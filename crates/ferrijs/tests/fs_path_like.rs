#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `fs` takes a path as Node does: a string, a `Buffer`, or a `file:`
//! `URL`, so `readFileSync(new URL('./data.json', import.meta.url))`
//! reads the file beside the module.

use ferrijs::{Permissions, RunOptions, Runtime};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn a_path_may_be_a_string_a_buffer_or_a_file_url() {
  let dir = tempfile::tempdir().expect("temp dir");
  let file = dir.path().join("data.json");
  std::fs::write(&file, r#"{"ok":true}"#).expect("write");
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]))
    .build()
    .await
    .expect("runtime");
  let path = file.to_string_lossy().into_owned();
  let run = rt
    .eval_script(
      "const fs = require('node:fs');
       const url = require('node:url').pathToFileURL(args[0]).href;
       const asString = fs.readFileSync(args[0], 'utf8');
       const asBuffer = fs.readFileSync(Buffer.from(args[0]), 'utf8');
       const asUrl = fs.readFileSync(new URL(url), 'utf8');
       const exists = fs.existsSync(new URL(url));
       let scheme;
       try { fs.readFileSync(new URL('https://example.com/data.json')); } catch (e) { scheme = e.code; }
       return { same: asString === asBuffer && asBuffer === asUrl, exists, scheme };",
      &[json!(path)],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    run.result.expect("run"),
    json!({ "same": true, "exists": true, "scheme": "ERR_INVALID_URL_SCHEME" })
  );
}
