#![allow(non_snake_case, mixed_script_confusables)]
#![feature(non_ascii_idents)]

use blind_sig_bench::{
    abe::Abe,
    common::FourMoveBlindSig,
    schnorr::BlindSchnorr,
    webserver::{make_client, start_server},
};

use std::{
    sync::{atomic::Ordering::SeqCst, Arc},
    thread::sleep,
    time::Duration,
};

use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use rand_distr::Distribution;

const SERVER_ADDR: &str = "localhost:14147";

const SESSION_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64];
const NUM_CLIENTS: usize = 100;

// 30ms mean latency between server and client. Let's say this is normally distributed with
// standard deviation of 5ms so that 95% of connections have latency between 20ms and 40ms.
const LATENCY_MEAN: f64 = 30f64;
const LATENCY_STD: f64 = 5f64;

// Average time between clients connecting. This is modeled as a Poisson point process, and so the
// time between arrivals is an exponential distribution with λ = 1 / mean_interarrival_time.
static MEAN_INTERARRIVAL_TIME: f64 = 30f64;

fn bench_scheme<S: FourMoveBlindSig>(
    bencher: &mut Criterion,
    group_name: &str,
    thread_pool_size: usize,
) {
    let mut group = bencher.benchmark_group(group_name);
    group.measurement_time(std::time::Duration::from_secs(300));

    let mut csprng = rand::thread_rng();

    let latency_distr = rand_distr::Normal::new(LATENCY_MEAN, LATENCY_STD).unwrap();
    let client_arrival_distr = rand_distr::Exp::new(1f64 / MEAN_INTERARRIVAL_TIME).unwrap();

    let my_global_state: Arc<DashMap<String, <S as FourMoveBlindSig>::ServerState>> =
        Arc::new(DashMap::new());

    // Run the Blind Schnorr server sequentially (that's the "1" below)
    let (_privkey, pubkey, stop_var) = start_server::<S, _>(
        SERVER_ADDR,
        thread_pool_size,
        my_global_state,
        latency_distr,
    );

    let bench_name = format!(
        "{} clients at {}ms EIAT",
        NUM_CLIENTS, MEAN_INTERARRIVAL_TIME
    );
    group.bench_function(bench_name, |b| {
        b.iter(|| {
            let mut threads = Vec::new();
            for _ in 0..NUM_CLIENTS {
                let client = make_client::<S>(SERVER_ADDR, pubkey.clone());
                threads.push(std::thread::spawn(client));

                let pause_time = std::cmp::max(0, client_arrival_distr.sample(&mut csprng) as i64);
                sleep(Duration::from_millis(pause_time as u64));
            }

            for thread in threads.into_iter() {
                thread.join().unwrap();
            }
        })
    });

    stop_var.store(true, SeqCst);
}

fn bench_schnorr(bencher: &mut Criterion) {
    bench_scheme::<BlindSchnorr>(bencher, "Sequential Blind Schnorr", 1);
}

fn bench_abe(bencher: &mut Criterion) {
    bench_scheme::<Abe>(bencher, "Parallel Abe", 8);
}

criterion_group!(benches, bench_abe, bench_schnorr);
criterion_main!(benches);
