# Blind Signature Scheme Benchmarks

## Run the benchmark

```
cargo +nightly bench
```

## Generate the plot on MY benchmark data

```
cargo +nightly run plot
```

This will generate `plots/server_runtime.svg`

## Generate the plot on YOUR benchmark data

In the file `src/plot.rs`, change the path `ec2_data/webserver_bench` to `target/criterion`. Then run

```
cargo +nightly run plot
```

This will generate `plots/server_runtime.svg`
