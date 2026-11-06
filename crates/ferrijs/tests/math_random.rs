#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Every realm draws its own random numbers, however close together the
//! realms were made.

use std::sync::{Arc, Barrier};

use ferrijs::{RunOptions, Runtime};

const REALMS: usize = 32;

fn first_draws() -> Vec<f64> {
  let barrier = Arc::new(Barrier::new(REALMS));
  let threads: Vec<_> = (0..REALMS)
    .map(|_| {
      let barrier = Arc::clone(&barrier);
      std::thread::spawn(move || {
        let tokio = tokio::runtime::Builder::new_current_thread()
          .enable_all()
          .build()
          .expect("tokio");
        tokio.block_on(async {
          barrier.wait();
          let rt = Runtime::builder().build().await.expect("runtime");
          let run = rt.eval_script("return Math.random()", &[], RunOptions::default()).await;
          run.result.expect("draw").as_f64().expect("a number")
        })
      })
    })
    .collect();
  threads
    .into_iter()
    .map(|thread| thread.join().expect("thread"))
    .collect()
}

// Realms made at once, as a test runner's workers are when they start
// together, each draw a different sequence.
#[test]
fn realms_made_together_draw_different_numbers() {
  for _ in 0..10 {
    let draws = first_draws();
    let mut distinct = draws.clone();
    distinct.sort_by(f64::total_cmp);
    distinct.dedup();
    assert_eq!(distinct.len(), REALMS, "realms drew the same numbers: {draws:?}");
  }
}

#[tokio::test]
async fn math_random_keeps_its_shape() {
  let rt = Runtime::builder().build().await.expect("runtime");
  let run = rt
    .eval_script(
      r"
      const d = Object.getOwnPropertyDescriptor(Math, 'random');
      const draws = Array.from({ length: 1000 }, () => Math.random());
      return {
        name: Math.random.name,
        length: Math.random.length,
        writable: d.writable,
        enumerable: d.enumerable,
        configurable: d.configurable,
        inRange: draws.every((x) => typeof x === 'number' && x >= 0 && x < 1),
        distinct: new Set(draws).size,
      };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    run.result.expect("shape"),
    serde_json::json!({
      "name": "random",
      "length": 0,
      "writable": true,
      "enumerable": false,
      "configurable": true,
      "inRange": true,
      "distinct": 1000,
    })
  );
}
