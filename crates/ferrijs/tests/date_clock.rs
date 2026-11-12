#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `Date` reads the same wall clock the host stamps its own times with,
//! to the millisecond, on every platform.

use ferrijs::{RunOptions, Runtime};

fn host_ms() -> f64 {
  let since = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("after the epoch");
  (since.as_secs_f64() * 1000.0).floor()
}

#[tokio::test]
async fn now_falls_between_two_host_readings() {
  let rt = Runtime::builder().build().await.expect("runtime");
  for _ in 0..50 {
    let before = host_ms();
    let run = rt
      .eval_script(
        "return [Date.now(), new Date().getTime(), new Date(0).getTime()]",
        &[],
        RunOptions::default(),
      )
      .await;
    let after = host_ms();
    let read = run.result.expect("clock read");
    let values = read.as_array().expect("an array");
    for value in &values[..2] {
      let ms = value.as_f64().expect("a number");
      assert!(before <= ms && ms <= after, "{before} <= {ms} <= {after}");
    }
    assert_eq!(values[2].as_f64(), Some(0.0));
  }
}

#[tokio::test]
async fn date_keeps_its_identity() {
  let rt = Runtime::builder().build().await.expect("runtime");
  let run = rt
    .eval_script(
      "class Stamp extends Date {}; const s = new Stamp(5); \
       return [Date.name, Date.length, Date.prototype.constructor === Date, new Date() instanceof Date, \
               s instanceof Date, s.getTime(), typeof Date.parse, typeof Date.UTC, Date.now.name]",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    run.result.expect("identity"),
    serde_json::json!(["Date", 7, true, true, true, 5, "function", "function", "now"])
  );
}
