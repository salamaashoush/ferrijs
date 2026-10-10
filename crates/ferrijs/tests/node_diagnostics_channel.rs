#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `node:diagnostics_channel`, held to Node: each scenario logs what it
//! sees, in order, and the log must be what Node 24 logged for the same
//! module.
//!
//! Recorded with:
//!
//! ```sh
//! node --input-type=module -e "import r from './diagnostics_channel.mjs'; console.log(JSON.stringify(r))" > diagnostics_channel.node.json
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
  let ours = module(include_str!("fixtures/diagnostics_channel.mjs")).await;
  let node: serde_json::Value = serde_json::from_str(include_str!("fixtures/diagnostics_channel.node.json")).unwrap();
  let (ours, node) = (ours.as_array().unwrap(), node.as_array().unwrap());
  assert_eq!(ours.len(), node.len());
  for (ours, node) in ours.iter().zip(node) {
    assert_eq!(ours, node);
  }
}

#[tokio::test]
async fn import_and_require_share_one_instance() {
  let out = module(
    "import dc, { channel } from 'node:diagnostics_channel';
     import * as bare from 'diagnostics_channel';
     const required = require('diagnostics_channel');
     const seen = [];
     required.subscribe('shared', (data) => seen.push(data));
     channel('shared').publish('through import');
     export default [
       required === dc,
       bare.default === dc,
       require('node:diagnostics_channel').channel === channel,
       seen,
     ];",
  )
  .await;
  assert_eq!(out, serde_json::json!([true, true, true, ["through import"]]));
}

#[tokio::test]
async fn a_throwing_subscriber_reaches_neither_the_publisher_nor_the_others() {
  let out = module(
    "import { channel } from 'node:diagnostics_channel';
     const seen = [];
     const ch = channel('throws');
     ch.subscribe(() => { throw new Error('subscriber'); });
     ch.subscribe((data) => seen.push(data));
     ch.publish('after the throw');
     export default seen;",
  )
  .await;
  assert_eq!(out, serde_json::json!(["after the throw"]));
}
