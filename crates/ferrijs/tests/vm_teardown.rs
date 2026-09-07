//! Runtime VM teardown must be clean: dropping a `Runtime` (LRU eviction,
//! poisoning rebuild, host shutdown) ends the VM event loop and frees
//! the `QuickJS` runtime without tripping its `JS_FreeRuntime` GC-list
//! assertion.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use ferrijs::{RunOptions, Runtime};

#[tokio::test(flavor = "multi_thread")]
async fn create_drop_is_clean() {
  let runtime = Runtime::builder().build().await.unwrap();
  drop(runtime);
  tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn create_execute_drop_is_clean() {
  let runtime = Runtime::builder().build().await.unwrap();
  let run = runtime.eval_script("return 1;", &[], RunOptions::default()).await;
  assert!(run.result.is_ok());
  drop(runtime);
  tokio::time::sleep(Duration::from_millis(200)).await;
}
