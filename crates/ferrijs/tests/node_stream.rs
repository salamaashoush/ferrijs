#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `node:stream`, held to Node: each scenario logs the events it sees, in
//! order, and the log must be what Node 24 logged for the same module.
//!
//! Recorded with:
//!
//! ```sh
//! node --input-type=module -e "import r from './stream_scenarios.mjs'; console.log(JSON.stringify(r))" > stream_scenarios.node.json
//! ```

use ferrijs::{RunOptions, Runtime};

async fn module(source: &str) -> serde_json::Value {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_module_source("entry.mjs", source, &[], RunOptions::default())
    .await;
  run.result.unwrap_or_else(|e| panic!("{e}\n{:?}", e.stack))
}

#[tokio::test]
async fn every_scenario_logs_what_node_logs() {
  let ours = module(include_str!("fixtures/stream_scenarios.mjs")).await;
  let node: serde_json::Value = serde_json::from_str(include_str!("fixtures/stream_scenarios.node.json")).unwrap();
  for (ours, node) in ours.as_array().unwrap().iter().zip(node.as_array().unwrap()) {
    assert_eq!(ours, node);
  }
}

#[tokio::test]
async fn import_and_require_share_one_instance() {
  let out = module(
    "import Stream, { Readable } from 'node:stream';
     import * as bare from 'stream';
     import { pipeline } from 'node:stream/promises';
     const required = require('stream');
     export default [
       required === Stream,
       bare.default === Stream,
       Stream.Readable === Readable,
       require('node:stream/promises').pipeline === pipeline,
       Stream.promises.pipeline === pipeline,
     ];",
  )
  .await;
  assert_eq!(out, serde_json::json!([true, true, true, true, true]));
}

#[tokio::test]
async fn the_classes_are_reached_through_the_module_not_globals() {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_script(
      "return [typeof Readable, typeof require('node:stream').Readable]",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result.unwrap(), serde_json::json!(["undefined", "function"]));
}
