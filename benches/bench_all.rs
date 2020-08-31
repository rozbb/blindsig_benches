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

// Number of threads we give to the server
const THREADPOOL_SIZES: &[usize] = &[1, 4, 16];

// Number of clients that connect to the server within a benchmark. Each client waits some
// interarrival time after the previous client before connecting
const NUM_CLIENTS: usize = 100;

// Average time between clients connecting. This is modeled as a Poisson point process, and so the
// time between arrivals is an exponential distribution with λ = 1 / mean_interarrival_time.
const INTERARRIVAL_TIMES: &[f64] = &[1f64, 10f64, 50f64, 90f64, 130f64];

// 30ms mean latency between server and client (this is roughly what I get on a WiFi network
// between NYC and msu.edu ). Let's say this is normally distributed with standard deviation of 5ms
// so that 95% of connections have latency between 20ms and 40ms.
const LATENCY_MEAN: f64 = 30f64;
const LATENCY_STD: f64 = 5f64;

fn bench_scheme<S: FourMoveBlindSig>(
    bencher: &mut Criterion,
    group_name: &str,
    server_thread_pool_size: usize,
) {
    let mut group = bencher.benchmark_group(group_name);
    //group.measurement_time(std::time::Duration::from_secs(300));

    let mut csprng = rand::thread_rng();

    // Network latency is a normal distribution if you squint
    let latency_distr = rand_distr::Normal::new(LATENCY_MEAN, LATENCY_STD).unwrap();

    // Thread-safe global state for the server
    let my_global_state: Arc<DashMap<String, <S as FourMoveBlindSig>::ServerState>> =
        Arc::new(DashMap::new());

    // Start the server. Setting stop_var to true will kill it.
    let (_privkey, pubkey, stop_var) = start_server::<S, _>(
        SERVER_ADDR,
        server_thread_pool_size,
        my_global_state,
        latency_distr,
    );

    for expected_iat in INTERARRIVAL_TIMES {
        // Interarrival distribution of a Poisson point process with rate λ is the exponential
        // distribution with parameter 1/λ
        let client_arrival_distr = rand_distr::Exp::new(1f64 / expected_iat).unwrap();

        let bench_name = format!(
            "{}-core server handling {} clients at {}ms EIAT",
            server_thread_pool_size, NUM_CLIENTS, expected_iat
        );

        // Bench how long it takes to spawn NUM_CLIENTS many clients, waiting expected_iat
        // milliseconds between each other, connecting to a server which is running on
        // server_thread_pool_size many cores.

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                let mut threads = Vec::new();
                for _ in 0..NUM_CLIENTS {
                    let client = make_client::<S>(SERVER_ADDR, pubkey.clone());
                    threads.push(std::thread::spawn(client));

                    let pause_time =
                        std::cmp::max(0, client_arrival_distr.sample(&mut csprng) as i64);
                    sleep(Duration::from_millis(pause_time as u64));
                }

                for thread in threads.into_iter() {
                    thread.join().unwrap();
                }
            })
        });
    }

    // Tell the server to stop
    stop_var.store(true, SeqCst);
    // Wait a second for the server to get the message
    sleep(Duration::from_secs(1));
}

fn bench_schnorr(bencher: &mut Criterion) {
    // Schnorr is sequential so the threadpool size is always 1
    bench_scheme::<BlindSchnorr>(bencher, "Sequential Blind Schnorr", 1);
}

fn bench_abe(bencher: &mut Criterion) {
    // Abe is parallel so we benchmark it for various threadpool sizes
    for &thread_pool_size in THREADPOOL_SIZES {
        bench_scheme::<Abe>(bencher, "Parallel Abe", thread_pool_size);
    }
}

criterion_group!(benches, bench_abe, bench_schnorr);
criterion_main!(benches);
