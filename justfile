set shell := ["bash", "-cu"]

default: check

# Full gate: format, lint, every test, on the patched engine.
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

# Benchmarks against the engine a consumer actually gets. `--quick`
# stops each case as soon as it converges; drop it for a publishable
# number. Run `just patch` first only to measure the upstream bug.
bench *args:
  cargo bench --workspace {{args}}

# Rebuild the engine with the fixes in `patches/` applied. OFF by
# default, and deliberately not a prerequisite of anything: a cargo
# `paths` override is workspace-local, so nobody who depends on the
# published `ferrijs` gets it. Turning it on makes this checkout faster
# than the crate anyone can actually install, which is why the gate and
# the benchmarks do not use it.
#
# What it is for: reproducing and measuring an engine bug so it can be
# reported upstream, where fixing it would reach consumers.
#
# There is no `patch-package` for cargo (`cargo-patch` no longer
# compiles), so this is that idea by hand: copy the crate cargo already
# downloaded into `vendor/`, apply the committed diffs, and write the
# override. Only the diffs are committed. Re-runs are idempotent and
# `just unpatch` puts it back.
patch:
  #!/usr/bin/env bash
  set -euo pipefail
  crate=rquickjs-sys
  version=$(awk '/^name = "'"$crate"'"$/{f=1} f && /^version = /{gsub(/[",]/,"",$3); print $3; exit}' Cargo.lock)
  [ -n "$version" ] || { echo "$crate is not in Cargo.lock"; exit 1; }
  # The override has to be gone before cargo will run at all when the
  # directory it points at does not exist yet.
  rm -f .cargo/config.toml
  src=$(ls -d ~/.cargo/registry/src/*/"$crate-$version" 2>/dev/null | head -1 || true)
  if [ -z "$src" ]; then
    cargo fetch >/dev/null
    src=$(ls -d ~/.cargo/registry/src/*/"$crate-$version" | head -1)
  fi
  rm -rf "vendor/$crate"
  mkdir -p vendor
  cp -R "$src" "vendor/$crate"
  chmod -R u+w "vendor/$crate"
  # A version bump renames the patches out of the glob's reach. Failing
  # here is the point: a silent no-op would leave the engine quietly
  # unpatched and every benchmark quietly wrong.
  shopt -s nullglob
  found=(patches/"$crate-$version"-*.patch)
  if [ ${#found[@]} -eq 0 ]; then
    echo "no patches for $crate $version (have: $(ls patches/ 2>/dev/null | tr '\n' ' '))" >&2
    echo "rebase them onto the new version, or run 'just unpatch'" >&2
    exit 1
  fi
  for p in "${found[@]}"; do
    patch -p1 -s -d "vendor/$crate" < "$p"
    echo "applied $(basename "$p")"
  done
  mkdir -p .cargo
  printf 'paths = ["vendor/%s"]\n' "$crate" > .cargo/config.toml
  echo "engine patched: vendor/$crate ($version)"

# Drop the patched engine and build against the published crate again.
unpatch:
  rm -f .cargo/config.toml
  rm -rf vendor
  @echo "engine restored to the published crate"

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
