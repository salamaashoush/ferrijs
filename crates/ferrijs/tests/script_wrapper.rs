#![allow(clippy::expect_used, clippy::unwrap_used)]
//! A script that never awaits runs in a plain arrow, one that does in an
//! async one. Each case here runs both ways, the second forced async by a
//! trailing `// await`, and the two must answer alike: value, error kind,
//! message and line.

use ferrijs::{RunOptions, Runtime};

const CASES: &[&str] = &[
  "return 1",
  "return args[0]",
  "return { a: [1, 2], b: 'x' }",
  "return undefined",
  "",
  "return Promise.resolve(5)",
  "return new Promise((resolve) => setTimeout(() => resolve('later'), 1))",
  "return Promise.reject(new TypeError('rejected'))",
  "return { then(resolve) { resolve('thenable'); } }",
  "return { then(_, reject) { reject(new RangeError('thenable rejected')); } }",
  "return { then: 'not a function', v: 1 }",
  "return { get then() { throw new Error('then getter'); } }",
  "throw new SyntaxError('thrown')",
  "\n\nnull.x",
  "return typeof this",
  "return [typeof globalThis.args, args.length]",
  "let n = 0; queueMicrotask(() => n++); return n",
];

async fn outcome(realm: &Runtime, source: &str) -> serde_json::Value {
  let run = realm
    .eval_script(source, &[serde_json::json!(7)], RunOptions::default())
    .await;
  match run.result {
    Ok(value) => serde_json::json!({ "ok": value }),
    Err(e) => serde_json::json!({ "err": [format!("{:?}", e.kind), e.name, e.message, e.line] }),
  }
}

#[tokio::test]
async fn both_wrappers_answer_alike() {
  let realm = Runtime::builder().build().await.expect("runtime");
  for source in CASES {
    let plain = outcome(&realm, source).await;
    let forced = outcome(&realm, &format!("{source}\n// await")).await;
    assert_eq!(plain, forced, "{source:?}");
  }
}

#[tokio::test]
async fn a_returned_promise_is_awaited() {
  let realm = Runtime::builder().build().await.expect("runtime");
  assert_eq!(
    outcome(&realm, "return Promise.resolve(5)").await,
    serde_json::json!({ "ok": 5 })
  );
  assert_eq!(
    outcome(&realm, "return { then(r) { r('thenable'); } }").await,
    serde_json::json!({ "ok": "thenable" })
  );
}
