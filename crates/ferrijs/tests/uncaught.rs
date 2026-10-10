#![allow(clippy::expect_used, clippy::unwrap_used)]
//! An exception nothing caught fails the run it happened in, as Node
//! exits on it, and reaches the host's hook when no run is there.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrijs::{RunOptions, Runtime, ScriptError, ScriptErrorKind};

async fn failure(source: &str) -> ScriptError {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm.eval_script(source, &[], RunOptions::default()).await;
  run.result.expect_err("the run should fail")
}

#[tokio::test]
async fn every_source_of_an_uncaught_throw_fails_the_run() {
  for (source, message) in [
    (
      "setTimeout(() => { throw new TypeError('timer') }, 0); await new Promise((r) => setTimeout(r, 20));",
      "timer",
    ),
    (
      "let n = 0; const id = setInterval(() => { if (++n === 2) throw new Error('interval') }, 1); await new Promise((r) => setTimeout(r, 50)); clearInterval(id);",
      "interval",
    ),
    (
      "queueMicrotask(() => { throw new Error('microtask') }); await null;",
      "microtask",
    ),
    (
      "process.nextTick(() => { throw new Error('tick') }); await null;",
      "tick",
    ),
    (
      "setImmediate(() => { throw new Error('immediate') }); await new Promise((r) => setTimeout(r, 10));",
      "immediate",
    ),
  ] {
    let error = failure(source).await;
    assert_eq!(error.kind, ScriptErrorKind::Runtime, "{source}");
    assert_eq!(error.message, message, "{source}");
  }
}

#[tokio::test]
async fn the_thrown_error_keeps_its_name() {
  let error =
    failure("setTimeout(() => { throw new TypeError('typed') }, 0); await new Promise((r) => setTimeout(r, 20));")
      .await;
  assert_eq!(error.name.as_deref(), Some("TypeError"));
}

/// Not yet: rquickjs reads a settled promise without marking it handled,
/// so a rejection Rust consumed would read as unhandled.
#[tokio::test]
async fn an_unhandled_rejection_does_not_fail_the_run() {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_script(
      "Promise.reject(new Error('a'));
       (async () => { throw new Error('b') })();
       await new Promise((r) => setTimeout(r, 10));
       return 'fine';",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result.unwrap(), serde_json::json!("fine"));
}

#[tokio::test]
async fn a_run_waiting_on_work_the_throw_cut_short_fails_at_once() {
  let realm = Runtime::builder().build().await.expect("runtime");
  let started = Instant::now();
  let run = realm
    .eval_script(
      "await new Promise((resolve) => setTimeout(() => { throw new Error('never resolves'); resolve(); }, 0));",
      &[],
      RunOptions {
        timeout: Some(Duration::from_secs(10)),
        ..RunOptions::default()
      },
    )
    .await;
  assert_eq!(run.result.unwrap_err().message, "never resolves");
  assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
  assert!(!run.poisoned);
  let next = realm.eval_script("return 1", &[], RunOptions::default()).await;
  assert_eq!(next.result.unwrap(), serde_json::json!(1));
}

#[tokio::test]
async fn a_timeout_inside_a_callback_is_reported_as_the_timeout() {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_script(
      "await new Promise((resolve) => setTimeout(() => { for (;;) {} }, 0));",
      &[],
      RunOptions {
        timeout: Some(Duration::from_millis(100)),
        ..RunOptions::default()
      },
    )
    .await;
  assert_eq!(run.result.unwrap_err().kind, ScriptErrorKind::Timeout);
}

#[tokio::test]
async fn outside_a_run_the_hook_hears_it() {
  let heard: Arc<Mutex<Vec<String>>> = Arc::default();
  let sink = Arc::clone(&heard);
  let realm = Runtime::builder()
    .on_uncaught(move |error| sink.lock().unwrap().push(error.message))
    .build()
    .await
    .expect("runtime");
  let run = realm
    .eval_script(
      "setTimeout(() => { throw new Error('after the run') }, 30);
       setTimeout(() => queueMicrotask(() => { throw new Error('queued after') }), 30);
       return 'done';",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result.unwrap(), serde_json::json!("done"));
  let deadline = Instant::now() + Duration::from_secs(5);
  while heard.lock().unwrap().len() < 2 && Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  let mut heard = heard.lock().unwrap().clone();
  heard.sort();
  assert_eq!(heard, ["after the run", "queued after"]);
}
