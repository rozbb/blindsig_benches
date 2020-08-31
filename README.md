# Blind Signature Scheme Benchmarks

## Run tests

```
cargo +nightly test -- --test-threads=1
```

The `--test-threads=1` part is so that the webserver tests don't step on each others' toes.

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

## If you're getting "Connection Refused" errors

I get these on my laptop, when the benchmarks tend to be slower. Try increasing the `CLIENT_BACKOFF_TIME` in `src/webserver.rs` to something larger. That normally fixes it for me.
