set shell := ["bash", "-cu"]

default: check

# Full gate: format, lint, every test.
ready: fmt lint test
  @echo "Ready to commit"

alias r := ready
alias c := check
alias t := test

check:
  cargo check --workspace --all-targets --all-features

test:
  cargo test --workspace --all-features

# Clippy over every target with warnings denied.
lint:
  cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format check. `crates/ferrijs-std` is vendored and excluded by its own
# rustfmt.toml (`disable_all_formatting`), which is the guard that holds
# on the stable channel; the workspace `ignore` key only works on nightly.
fmt:
  cargo fmt --all -- --check

fmt-fix:
  cargo fmt --all

fix: fmt-fix
  cargo clippy --workspace --all-targets --all-features --fix --allow-dirty --allow-staged

# Run a target with the QuickJS leak dump on: every object still alive
# when the runtime is freed is listed, which is how a native closure
# that captured a JS value is found.
leak-check *args:
  cargo test -p ferrijs --features js-dump-leaks {{args}} -- --nocapture --test-threads=1
