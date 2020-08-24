#![allow(non_snake_case, mixed_script_confusables)]
#![feature(non_ascii_idents)]
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, SeedableRng};

static SESSION_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

// 30ms mean latency between server and client. Let's say this is normally distributed with
// standard deviation of 5ms so that 95% of connections have latency between 20ms and 40ms.
static LATENCY_MEAN: f64 = 30;
static LATENCY_STD: f64 = 5;

// 100ms average time between clients connecting. This is modeled as a Poisson point process, and
// so the time between arrivals is an exponential distribution with λ = 1 / mean_interarrival_time.
static MEAN_INTERARRIVAL_TIME: f64 = 300;

pub fn blind_schnorr_steps(bencher: &mut Criterion) {
    use blind_sig_bench::schnorr::{client1, client2, keygen, server1, server2, verify};

    let mut group = bencher.benchmark_group("Sequential Blind Schnorr");
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";

    let latency_distr = rand_distr::Normal::new(LATENCY_MEAN, LATENCY_STD);
    let client_arrival_distr = rand_distr::Exp::new(1 / MEAN_INTERARRIVAL_TIME);

    group.bench_function("keygen", |b| b.iter(|| keygen(&mut csprng)));
    let (privkey, pubkey) = keygen(&mut csprng);

    for &num_sessions in SESSION_SIZES {
        let bench_name = format!("step 1[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for _ in 0..num_sessions {
                    server1(&mut csprng);
                }
            })
        });
        let (server_state, server_resp1) = server1(&mut csprng);

        let bench_name = format!("step 2[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for _ in 0..num_sessions {
                    client1(&mut csprng, &pubkey, m, &server_resp1);
                }
            })
        });
        let (client_state, client_resp) = client1(&mut csprng, &pubkey, m, &server_resp1);

        let bench_name = format!("step 3[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for _ in 0..num_sessions {
                    server2(&privkey, &server_state, &client_resp);
                }
            })
        });
        let server_resp2 = server2(&privkey, &server_state, &client_resp);

        let bench_name = format!("step 4[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for _ in 0..num_sessions {
                    client2(&pubkey, &client_state, &server_resp2).unwrap();
                }
            })
        });
        let sig = client2(&pubkey, &client_state, &server_resp2).unwrap();

        assert!(verify(&pubkey, m, &sig));
    }
}

/*
pub fn blind_schnorr_full(bencher: &mut Criterion) {
    use blind_sig_bench::schnorr::{client1, client2, keygen, server1, server2};

    let mut group = bencher.benchmark_group("Blind Schnorr");
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";

    group.bench_function("all steps", |b| {
        b.iter(|| {
            let (privkey, pubkey) = keygen(&mut csprng);
            let (server_state, server_resp1) = server1(&mut csprng);
            let (client_state, client_resp) = client1(&mut csprng, &pubkey, m, &server_resp1);
            let server_resp2 = server2(&privkey, &server_state, &client_resp);
            client2(&pubkey, &client_state, &server_resp2).unwrap()
        })
    });
}
*/

pub fn abe_steps(bencher: &mut Criterion) {
    use std::sync::{Arc, Barrier};

    use blind_sig_bench::abe::{client1, client2, keygen, server1, server2, verify};
    use threadpool::ThreadPool;

    let mut group = bencher.benchmark_group("Parallel Abe");

    let mut csprng = StdRng::from_entropy();
    let m = b"Hello world";

    group.bench_function("keygen", |b| b.iter(|| keygen(&mut csprng)));
    let (privkey, pubkey) = keygen(&mut csprng);

    for &num_sessions in SESSION_SIZES {
        let pool = ThreadPool::new(num_sessions);
        // A barrier that can wait for all sessions, plus the main thread
        let barrier = Arc::new(Barrier::new(num_sessions + 1));

        //
        // Bench server1
        //

        let inputs_to_server1 = vec![(StdRng::from_entropy(), pubkey.clone(),); num_sessions];
        let bench_name = format!("step 1[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for (mut csprng, pubkey) in inputs_to_server1.clone().into_iter() {
                    let barrier_copy = barrier.clone();

                    pool.execute(move || {
                        server1(&mut csprng, &pubkey);
                        barrier_copy.wait();
                    });
                }
                barrier.wait()
            })
        });
        let (server_state, server_resp1) = server1(&mut csprng, &pubkey);

        //
        // Bench client1
        //

        let inputs_to_client1 = vec![
            (
                StdRng::from_entropy(),
                pubkey.clone(),
                m.to_vec(),
                server_resp1
            );
            num_sessions
        ];
        let bench_name = format!("step 2[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for (mut csprng, pubkey, m, server_resp1) in inputs_to_client1.clone().into_iter() {
                    let barrier_copy = barrier.clone();

                    pool.execute(move || {
                        client1(&mut csprng, &pubkey, &m, &server_resp1);
                        barrier_copy.wait();
                    });
                }
                barrier.wait()
            })
        });
        let (client_state, client_resp) = client1(&mut csprng, &pubkey, m, &server_resp1);

        //
        // Bench server2
        //

        let inputs_to_server2 =
            vec![(privkey.clone(), server_state.clone(), client_resp.clone(),); num_sessions];
        let bench_name = format!("step 3[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for (privkey, server_state, client_resp) in inputs_to_server2.clone().into_iter() {
                    let barrier_copy = barrier.clone();

                    pool.execute(move || {
                        server2(&privkey, &server_state, &client_resp);
                        barrier_copy.wait();
                    });
                }
                barrier.wait()
            })
        });
        let server_resp2 = server2(&privkey, &server_state, &client_resp);

        //
        // Bench client2
        //

        let inputs_to_client2 = vec![
            (
                pubkey.clone(),
                client_state.clone(),
                m.clone(),
                server_resp2.clone()
            );
            num_sessions
        ];
        let bench_name = format!("step 4[s = {}]", num_sessions);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                for (pubkey, client_state, m, server_resp2) in inputs_to_client2.clone().into_iter()
                {
                    let barrier_copy = barrier.clone();

                    pool.execute(move || {
                        client2(&pubkey, &client_state, &m, &server_resp2);
                        barrier_copy.wait();
                    });
                }
                barrier.wait()
            })
        });
        let sig = client2(&pubkey, &client_state, m, &server_resp2).unwrap();

        assert!(verify(&pubkey, m, &sig));
    }
}

criterion_group!(benches, abe_steps, blind_schnorr_steps,);
criterion_main!(benches);
