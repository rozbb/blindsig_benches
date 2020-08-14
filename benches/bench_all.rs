#![allow(non_snake_case, mixed_script_confusables)]
#![feature(non_ascii_idents)]
use criterion::{criterion_group, criterion_main, Criterion};

/*
fn main() -> Result<(), std::io::Error> {
    let matches = App::new("Benchmark Blind Schnorr")
        .arg("<CSV_OUT> 'The file to write the benchmark data to, in CSV format'")
        .get_matches();

    let out_file = {
        let filename = matches
            .value_of_os("CSV_OUT")
            .expect("no CSV filename given");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(filename)?
    };

    let mut csprng = rand::thread_rng();
    let m = b"Hello world";

    let b = Bencher {
        bytes: 0,
        iterations: 0,
        dur: 0,
    };

    let (x, X) = keygen(&mut csprng);
    let (r, R, serialized_R) = server_com(&mut csprng);
    let (α, R_prime, c, serialized_c) = client_chal(&mut csprng, m, &X, &serialized_R);
    let serialized_s = server_resp(&x, &r, &serialized_c);
    let σ = client_unblind(&c, &α, &R, &R_prime, &X, &serialized_s);

    assert!(verify(&X, m, &σ));
}
*/

pub fn blind_schnorr_steps(bencher: &mut Criterion) {
    use blind_sig_bench::schnorr::{
        client_chal, client_unblind, keygen, server_com, server_resp, verify,
    };

    let mut group = bencher.benchmark_group("Blind Schnorr");
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";

    group.bench_function("keygen", |b| b.iter(|| keygen(&mut csprng)));
    let (x, X) = keygen(&mut csprng);

    group.bench_function("step 1", |b| b.iter(|| server_com(&mut csprng)));
    let (r, R, serialized_R) = server_com(&mut csprng);

    group.bench_function("step 2", |b| {
        b.iter(|| client_chal(&mut csprng, m, &X, &serialized_R))
    });
    let (α, R_prime, c, serialized_c) = client_chal(&mut csprng, m, &X, &serialized_R);

    group.bench_function("step 3", |b| b.iter(|| server_resp(&x, &r, &serialized_c)));
    let serialized_s = server_resp(&x, &r, &serialized_c);

    group.bench_function("step 4", |b| {
        b.iter(|| client_unblind(&c, &α, &R, &R_prime, &X, &serialized_s))
    });
    let σ = client_unblind(&c, &α, &R, &R_prime, &X, &serialized_s);

    assert!(verify(&X, m, &σ));
}

pub fn blind_schnorr_full(bencher: &mut Criterion) {
    use blind_sig_bench::schnorr::{
        client_chal, client_unblind, keygen, server_com, server_resp, verify,
    };

    let mut group = bencher.benchmark_group("Blind Schnorr");
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";

    group.bench_function("all steps", |b| {
        b.iter(|| {
            let (x, X) = keygen(&mut csprng);
            let (r, R, serialized_R) = server_com(&mut csprng);
            let (α, R_prime, c, serialized_c) = client_chal(&mut csprng, m, &X, &serialized_R);
            let serialized_s = server_resp(&x, &r, &serialized_c);
            let σ = client_unblind(&c, &α, &R, &R_prime, &X, &serialized_s);
        })
    });
}

criterion_group!(benches, blind_schnorr_steps, blind_schnorr_full);
criterion_main!(benches);
