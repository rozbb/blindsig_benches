use crate::common::FourMoveBlindSig;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

use dashmap::DashMap;
use rand::{distributions::Distribution, Rng};

// If a client gets an HTTP 409 from the server, it waits this many milliseconds before
// reconnecting
const CLIENT_BACKOFF_TIME: u64 = 75;

type ServerFunc = Box<dyn Fn(&rouille::Request) -> rouille::Response + Send + Sync + 'static>;
pub type ClientFunc = Box<dyn Fn() + Send>;

fn make_server_func<S, D>(
    global_state: Arc<DashMap<String, S::ServerState>>,
    latency_distr: D,
) -> (S::Privkey, S::Pubkey, ServerFunc)
where
    S: FourMoveBlindSig,
    D: Distribution<f64> + Send + Sync + 'static,
{
    use rouille::{input::json_input, try_or_400, Request, Response};

    let mut csprng = rand::thread_rng();
    let (privkey, pubkey) = S::keygen(&mut csprng);
    let (privkey_copy, pubkey_copy) = (privkey.clone(), pubkey.clone());

    let handler = move |req: &Request| {
        let mut csprng = rand::thread_rng();

        let client_id = req
            .header("client_id")
            .expect("no client_id provided")
            .to_string();

        // Only do as many parallels sessions as is permitted. If the global session is empty or
        // the given client ID matches, we can continue. Otherwise 400.
        // I know this is actually a race condition, and you might get more parallelism than you
        // intended, but:
        // 1. this is unlikely to happen,
        // 2. even if it does, it will not cascade into a big parallel mess, and
        // 3. this is just a benchmark so chill.
        if !(global_state.len() < S::MAX_PARALLEL_SESSIONS
            || global_state.get(&client_id).is_some())
        {
            return Response::text("").with_status_code(409);
        }

        let res = match req.url().as_ref() {
            "/sign1" => {
                let (server_state, server_resp1) = S::sign1(&mut csprng, &pubkey);

                global_state.insert(client_id, server_state);
                Response::json(&server_resp1)
            }
            "/sign2" => {
                let server_state = global_state
                    .get(&client_id)
                    .expect("missing server state for this client_id");
                let client_resp: S::ClientResp = try_or_400!(json_input(req));
                let server_resp2 = S::sign2(&privkey, &server_state, &client_resp);

                drop(server_state);
                global_state
                    .remove(&client_id)
                    .expect("couldn't remove from global state");

                Response::json(&server_resp2)
            }
            other => panic!("unexpected url {}", other),
        };

        // Simulate latency by sampling from the latency distribution and pausing for that time
        let pause_time = std::cmp::max(0, latency_distr.sample(&mut csprng) as i64);
        sleep(Duration::from_millis(pause_time as u64));

        res
    };

    (privkey_copy, pubkey_copy, Box::new(handler))
}

pub fn make_client<S: FourMoveBlindSig>(addr: &'static str, pubkey: S::Pubkey) -> ClientFunc {
    use reqwest::blocking::Client;

    let client = move || {
        let mut csprng = rand::thread_rng();
        let m = b"Hello world";
        let client_id: String = std::iter::repeat(())
            .map(|()| csprng.sample(rand::distributions::Alphanumeric))
            .take(7)
            .collect();

        // Do step 1. Loop until the request is accepted
        let server_resp1: S::ServerResp1 = loop {
            let res = Client::new()
                .get(&format!("http://{}/sign1", addr))
                .header("client_id", &client_id)
                .send()
                .expect("didn't get sign1 response");
            if res.status() == reqwest::StatusCode::from_u16(409).unwrap() {
                // Server's busy. Back off for some time before trying again
                sleep(Duration::from_millis(CLIENT_BACKOFF_TIME));
                continue;
            } else {
                let resp = res.json().expect("invalid ServerResp1");
                break resp;
            }
        };

        // Do step 2. Loop until the request is accepted
        let (client_state, client_resp) = S::user1(&mut csprng, &pubkey, m, &server_resp1);
        let server_resp2: S::ServerResp2 = loop {
            let res = Client::new()
                .get(&format!("http://{}/sign2", addr))
                .header("client_id", &client_id)
                .json(&client_resp)
                .send()
                .expect("didn't get sign2 response");
            if res.status() == reqwest::StatusCode::from_u16(409).unwrap() {
                // Server's busy. Back off for some time before trying again
                sleep(Duration::from_millis(CLIENT_BACKOFF_TIME));
                continue;
            } else {
                let resp = res.json().expect("invalid ServerResp2");
                break resp;
            }
        };
        let sig = S::user2(&pubkey, &client_state, m, &server_resp2).unwrap();

        assert!(S::verify(&pubkey, m, &sig));
    };

    Box::new(client)
}

pub fn start_server<S, D>(
    addr: &'static str,
    pool_size: usize,
    global_state: Arc<DashMap<String, S::ServerState>>,
    latency_distr: D,
) -> (S::Privkey, S::Pubkey, Arc<AtomicBool>)
where
    S: FourMoveBlindSig,
    D: Distribution<f64> + Send + Sync + 'static,
{
    let (privkey, pubkey, server_func) = make_server_func::<S, _>(global_state, latency_distr);

    let stop_var = Arc::new(AtomicBool::new(false));
    let stop_var_copy = stop_var.clone();

    std::thread::spawn(move || {
        let server = rouille::Server::new(addr, server_func)
            .expect("couldn't make server")
            .pool_size(pool_size);

        while !stop_var.load(SeqCst) {
            server.poll()
        }
    });

    (privkey, pubkey, stop_var_copy)
}

#[cfg(test)]
fn test_webserver<S: FourMoveBlindSig>() {
    let server_addr = "localhost:23489";
    // Make a global server state for all the cores to run with
    let my_global_state: Arc<DashMap<String, <S as FourMoveBlindSig>::ServerState>> =
        Arc::new(DashMap::new());

    // Make an arbitrary latency ditribution (this one is μ = 50ms, σ = 10ms), and start the server
    // with that latency distribution and 1 thread in the threadpool
    let latency_distr = rand_distr::Normal::new(50f64, 10f64).unwrap();
    let (_privkey, pubkey, stop_var) =
        start_server::<S, _>(server_addr, 1, my_global_state, latency_distr);

    // Let the server start up for a second
    sleep(Duration::from_secs(1));

    // Make 10 clients connect to the server
    let mut threads = Vec::new();
    for _ in 0..10 {
        let client = make_client::<S>(server_addr, pubkey.clone());
        threads.push(std::thread::spawn(client));
    }

    // Wait for all the clients finish
    for thread in threads.into_iter() {
        thread.join().unwrap();
    }

    // Kill the server
    stop_var.store(true, SeqCst);
}

#[test]
fn test_blind_schnorr() {
    test_webserver::<crate::schnorr::BlindSchnorr>();
}

#[test]
fn test_abe() {
    test_webserver::<crate::abe::Abe>();
}
