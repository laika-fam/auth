- use `cargo +nightly fmt` because nightly-only rustfmt features

database migrations:
```shell
cargo install diesel
diesel migration run --migration-dir db/src/migrations
# (or other diesel command)
```