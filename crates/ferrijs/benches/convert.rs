//! The Rust <-> JS value boundary on its own: the walkers in
//! `ferrijs::value` and `ferrijs-serde`, measured inside the VM but
//! without a script in the way.

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

mod support;

use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use ferrijs::value::{json_to_js, value_to_json};
use support::{hosted, leak, plain, sample_json, tokio_rt};

fn shapes() -> Vec<(&'static str, serde_json::Value)> {
  vec![
    ("scalar", serde_json::json!(42)),
    ("small_object", serde_json::json!({ "a": 1, "b": "two", "c": true })),
    ("wide_object", sample_json(16, 1)),
    ("deep_object", sample_json(3, 5)),
    (
      "number_array_5k",
      serde_json::Value::Array((0..5000).map(|i| serde_json::json!(i)).collect()),
    ),
    (
      "string_array_5k",
      serde_json::Value::Array((0..5000).map(|i| serde_json::json!(format!("item-{i}"))).collect()),
    ),
    (
      "record_array_1k",
      serde_json::Value::Array(
        (0..1000)
          .map(|i| serde_json::json!({ "id": i, "name": format!("row {i}"), "ok": i % 2 == 0, "score": 1.5 * f64::from(i) }))
          .collect(),
      ),
    ),
  ]
}

fn json_in(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("json_to_js");
  g.sample_size(50);

  for (name, doc) in shapes() {
    let doc = Arc::new(doc);
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        let doc = Arc::clone(&doc);
        hosted(iters, move || {
          let doc = Arc::clone(&doc);
          async move {
            realm
              .with(move |ctx| {
                Box::pin(async move {
                  let v = json_to_js(&ctx, &doc).expect("json_to_js");
                  v.type_of() as u8
                })
              })
              .await
              .ok()
          }
        })
      });
    });
  }
  g.finish();
}

fn json_out(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("value_to_json");
  g.sample_size(50);

  for (name, doc) in shapes() {
    let doc = Arc::new(doc);
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        let doc = Arc::clone(&doc);
        hosted(iters, move || {
          let doc = Arc::clone(&doc);
          async move {
            realm
              .with(move |ctx| {
                Box::pin(async move {
                  let v = json_to_js(&ctx, &doc).expect("json_to_js");
                  value_to_json(&ctx, v).is_some()
                })
              })
              .await
              .ok()
          }
        })
      });
    });
  }
  g.finish();
}

/// The dispatch itself: one empty job through the VM loop, so the
/// walker numbers above can be read net of it.
fn dispatch_floor(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm = leak(rt.block_on(plain()));
  c.bench_function("dispatch_floor", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        realm.with(|_ctx| Box::pin(async move { 1u8 })).await.ok()
      })
    });
  });
}

criterion_group!(benches, dispatch_floor, json_in, json_out);
criterion_main!(benches);
