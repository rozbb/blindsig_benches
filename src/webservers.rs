use crate::{abe, schnorr};
use std::sync::{
    atomic::{AtomicBool, Ordering::SeqCst},
    Arc,
};

use dashmap::DashMap;
use rand::Rng;

const SERVER_ADDR: &str = "localhost:23489";

type ServerFunc = Box<dyn Fn(&rouille::Request) -> rouille::Response + Send + Sync + 'static>;
type ClientFunc = Box<dyn Fn() + Send>;

fn make_schnorr_server_func(
    global_state: Arc<DashMap<String, schnorr::ServerState>>,
) -> (schnorr::Privkey, schnorr::Pubkey, ServerFunc) {
    use rouille::{input::json_input, try_or_400, Request, Response};

    let mut csprng = rand::thread_rng();
    let (privkey, pubkey) = schnorr::keygen(&mut csprng);
    let (privkey_copy, pubkey_copy) = (privkey.clone(), pubkey.clone());

    let handler = move |req: &Request| {
        let mut csprng = rand::thread_rng();

        let client_id = req
            .header("client_id")
            .expect("no client_id provided")
            .to_string();

        // I can only do 1 session at a time. If the global session is empty or the given client ID
        // matches, we can continue. Otherwise 400.
        // I know this is actually a race condition, and you might get more parallelism than you
        // intended, but this is unlikely to happen and this is just a benchmark so chill.
        if !(global_state.len() < 1 || global_state.get(&client_id).is_some()) {
            return Response::text("").with_status_code(409);
        }

        match req.url().as_ref() {
            "/server1" => {
                let (server_state, server_resp1) = schnorr::server1(&mut csprng);

                global_state.insert(client_id, server_state);
                Response::json(&server_resp1)
            }
            "/server2" => {
                let server_state = global_state
                    .get(&client_id)
                    .expect("missing server state for this client_id");
                let client_resp: schnorr::ClientResp = try_or_400!(json_input(req));
                let server_resp2 = schnorr::server2(&privkey, &server_state, &client_resp);

                drop(server_state);
                global_state
                    .remove(&client_id)
                    .expect("couldn't remove from global state");

                Response::json(&server_resp2)
            }
            other => panic!("unexpected url {}", other),
        }
    };

    (privkey_copy, pubkey_copy, Box::new(handler))
}

fn make_schnorr_client(privkey: schnorr::Privkey, pubkey: schnorr::Pubkey) -> ClientFunc {
    use reqwest::blocking::Client;

    let client = move || {
        let mut csprng = rand::thread_rng();
        let m = b"Hello world";
        let client_id: String = std::iter::repeat(())
            .map(|()| csprng.sample(rand::distributions::Alphanumeric))
            .take(7)
            .collect();

        // Do step 1. Loop until the request is accepted
        let server_resp1: schnorr::ServerResp1 = loop {
            let res = Client::new()
                .get(&format!("http://{}/server1", SERVER_ADDR))
                .header("client_id", &client_id)
                .send()
                .expect("didn't get server1 response");
            if res.status() == reqwest::StatusCode::from_u16(409).unwrap() {
                continue;
            } else {
                let resp = res.json().expect("invalid ServerResp1");
                break resp;
            }
        };

        // Do step 2. Loop until the request is accepted
        let (client_state, client_resp) = schnorr::client1(&mut csprng, &pubkey, m, &server_resp1);
        let server_resp2: schnorr::ServerResp2 = loop {
            let res = Client::new()
                .get(&format!("http://{}/server2", SERVER_ADDR))
                .header("client_id", &client_id)
                .json(&client_resp)
                .send()
                .expect("didn't get server2 response");
            if res.status() == reqwest::StatusCode::from_u16(409).unwrap() {
                continue;
            } else {
                let resp = res.json().expect("invalid ServerResp2");
                break resp;
            }
        };
        let sig = schnorr::client2(&pubkey, &client_state, &server_resp2).unwrap();

        assert!(schnorr::verify(&pubkey, m, &sig));
    };

    Box::new(client)
}

fn start_schnorr_server(
    addr: &'static str,
    pool_size: usize,
    global_state: Arc<DashMap<String, schnorr::ServerState>>,
) -> (schnorr::Privkey, schnorr::Pubkey, Arc<AtomicBool>) {
    let (privkey, pubkey, server_func) = make_schnorr_server_func(global_state);

    let stop_var = Arc::new(AtomicBool::new(false));
    let stop_var_copy = stop_var.clone();

    std::thread::spawn(move || {
        let server = rouille::Server::new(addr, server_func)
            .expect("couldn't make server")
            .pool_size(1);

        while !stop_var.load(SeqCst) {
            server.poll()
        }

        println!("Server stopped");
    });

    (privkey, pubkey, stop_var_copy)
}

#[test]
fn test_schnorr_webserver() {
    let schnorr_global_state: Arc<DashMap<String, schnorr::ServerState>> = Arc::new(DashMap::new());

    let (privkey, pubkey, stop_var) = start_schnorr_server(SERVER_ADDR, 1, schnorr_global_state);

    let mut threads = Vec::new();
    for _ in 0..10 {
        let client = make_schnorr_client(privkey.clone(), pubkey.clone());
        threads.push(std::thread::spawn(client));
    }

    for (i, thread) in threads.into_iter().enumerate() {
        thread.join();
    }

    stop_var.store(false, SeqCst);
}
