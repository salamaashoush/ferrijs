//! Shared scaffolding for the runtime benchmarks.
//!
//! The one thing that matters here is [`hosted`]. Criterion's
//! `to_async` drives a bench body with `Runtime::block_on`, and the
//! thread that calls `block_on` is not one of tokio's workers: every
//! await on it parks and unparks an OS thread, which on macOS costs
//! about 7 µs. A realm's VM loop is a spawned task, so a bench body
//! that awaits it from the `block_on` thread measures three context
//! switches and almost nothing else -- the same round trip from a
//! spawned task is 0.15 µs, forty times cheaper, and a spawned task is
//! what an embedding host actually is (a request handler, a test case).
//!
//! So every timed loop runs inside `tokio::spawn`, and the one
//! `block_on` handoff is amortised across the whole sample rather than
//! charged to each iteration.

// Benchmarks and the profiling driver are not API. The pedantic
// documentation and `must_use` lints have nothing to protect here, and
// a panic is how a broken measurement is meant to stop.
#![allow(
  // `support` is shared by four bench binaries, each using a subset.
  dead_code,
  clippy::cast_precision_loss,
  clippy::expect_used,
  clippy::unwrap_used,
  clippy::missing_panics_doc,
  clippy::must_use_candidate,
  clippy::semicolon_if_nothing_returned,
  clippy::too_many_lines,
  clippy::doc_markdown
)]

use std::future::Future;
use std::hint::black_box;
use std::time::{Duration, Instant};

use ferrijs::permissions::Permissions;
use ferrijs::{ModulePolicy, RealmOptions, Runtime};

/// The tokio runtime every async bench drives.
pub fn tokio_rt() -> tokio::runtime::Runtime {
  tokio::runtime::Builder::new_multi_thread()
    .worker_threads(4)
    .enable_all()
    .build()
    .expect("tokio runtime")
}

/// Time `iters` calls of `op` from inside a spawned task. Hand this to
/// `Bencher::iter_custom`.
pub async fn hosted<F, Fut, T>(iters: u64, mut op: F) -> Duration
where
  F: FnMut() -> Fut + Send + 'static,
  Fut: Future<Output = T> + Send,
  T: Send + 'static,
{
  tokio::spawn(async move {
    let started = Instant::now();
    for _ in 0..iters {
      black_box(op().await);
    }
    started.elapsed()
  })
  .await
  .expect("bench task")
}

/// The realm a host gets from `Runtime::builder().build()`: every
/// standard-library module, timers, fetch, no grants.
pub async fn plain() -> Runtime {
  Runtime::builder().build().await.expect("runtime")
}

/// A realm with everything granted, so the permission checks are on
/// their allow path rather than short-circuiting into a refusal.
pub async fn granted() -> Runtime {
  Runtime::builder()
    .permissions(Permissions::all())
    .build()
    .await
    .expect("runtime")
}

/// The smallest realm the builder can produce: no fetch, no timers, and
/// a module policy serving nothing.
pub async fn minimal() -> Runtime {
  Runtime::builder()
    .without_fetch()
    .timers(false)
    .modules(ModulePolicy::default().no_builtins().no_files())
    .build()
    .await
    .expect("runtime")
}

/// Unwrap a run, panicking with its error.
///
/// A bench body that only asked `is_ok()` would happily time a failure:
/// a poisoned realm answers in about a hundred nanoseconds, which looks
/// like a spectacular optimisation and is a broken measurement. Every
/// timed body goes through here.
pub fn ok<T>(run: ferrijs::Run<T>) -> T {
  match run.result {
    Ok(v) => v,
    Err(e) => panic!("benchmarked run failed: {e}"),
  }
}

/// A realm handed out as a shared reference so a criterion `FnMut`
/// closure can capture it: `Runtime` is not `Copy`, and a bench body
/// that moved it would only run once.
pub fn leak<T>(value: T) -> &'static T {
  Box::leak(Box::new(value))
}

pub fn realm_options_locked() -> RealmOptions {
  RealmOptions::default()
}

/// A JSON document with the shape a host actually hands a script:
/// nested objects, arrays, strings and numbers.
pub fn sample_json(width: usize, depth: usize) -> serde_json::Value {
  fn build(width: usize, depth: usize) -> serde_json::Value {
    if depth == 0 {
      return serde_json::json!({
        "id": 12_345,
        "name": "a moderately long identifier string",
        "ok": true,
        "ratio": 0.5,
        "tags": ["alpha", "beta", "gamma"],
      });
    }
    let mut map = serde_json::Map::new();
    for i in 0..width {
      map.insert(format!("key{i}"), build(width, depth - 1));
    }
    serde_json::Value::Object(map)
  }
  build(width, depth)
}
