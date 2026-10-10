#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `Buffer` held to what Node answers, case by case.
//!
//! Each fixture is a script body that runs every case and returns the
//! results; the `.node.json` beside it is that script's output under
//! Node 24, recorded with:
//!
//! ```sh
//! (echo 'console.log(JSON.stringify((() => {'; cat buffer_search_fill.js; echo '})()))') | node > buffer_search_fill.node.json
//! ```

use ferrijs::{RunOptions, Runtime};

async fn matches_node(script: &str, recorded: &str) {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm.eval_script(script, &[], RunOptions::default()).await;
  let ours = run.result.unwrap_or_else(|e| panic!("{e}"));
  let node: serde_json::Value = serde_json::from_str(recorded).unwrap();
  let (ours, node) = (ours.as_array().unwrap(), node.as_array().unwrap());
  assert_eq!(ours.len(), node.len());
  let differ: Vec<String> = ours
    .iter()
    .zip(node)
    .filter(|(a, b)| a != b)
    .take(10)
    .map(|(a, b)| format!("ours {a} node {b}"))
    .collect();
  assert!(differ.is_empty(), "{}", differ.join("\n"));
}

#[tokio::test]
async fn search_fill_compare_and_swap_match_node() {
  matches_node(
    include_str!("fixtures/buffer_search_fill.js"),
    include_str!("fixtures/buffer_search_fill.node.json"),
  )
  .await;
}

#[tokio::test]
async fn hex_and_base64_decode_as_node_does() {
  matches_node(
    include_str!("fixtures/buffer_decode.js"),
    include_str!("fixtures/buffer_decode.node.json"),
  )
  .await;
}

#[tokio::test]
async fn isatty_of_a_non_descriptor_is_false() {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_script(
      "const tty = require('node:tty');
       return [tty.isatty(undefined), tty.isatty('1'), tty.isatty(1.5), tty.isatty(-1)];",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result.unwrap(), serde_json::json!([false, false, false, false]));
}

#[tokio::test]
async fn global_is_the_global_object() {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_script(
      "const d = Object.getOwnPropertyDescriptor(globalThis, 'global');
       return [global === globalThis, d.writable, d.enumerable, d.configurable];",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result.unwrap(), serde_json::json!([true, true, true, true]));
}
