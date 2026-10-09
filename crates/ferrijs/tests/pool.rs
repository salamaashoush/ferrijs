#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `RealmPool`: realms built ahead, each handed out once.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrijs::{FnExtension, RealmPool, RunOptions, Runtime};

async fn until_ready(pool: &RealmPool, n: usize) {
  for _ in 0..500 {
    if pool.ready() >= n {
      return;
    }
    tokio::time::sleep(Duration::from_millis(2)).await;
  }
  panic!("pool never reached {n} ready realms, has {}", pool.ready());
}

#[tokio::test(flavor = "multi_thread")]
async fn fills_to_its_target_and_refills_after_a_take() {
  let pool = RealmPool::new(3, Runtime::builder);
  until_ready(&pool, 3).await;
  let realm = pool.acquire().await.expect("realm");
  let run = realm.eval_script("return 40 + 2", &[], RunOptions::default()).await;
  assert_eq!(run.result.expect("run"), serde_json::json!(42));
  until_ready(&pool, 3).await;
  assert_eq!(pool.ready(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_realm_is_fresh() {
  let pool = RealmPool::new(2, Runtime::builder);
  let first = pool.acquire().await.expect("realm");
  first
    .eval_script("globalThis.leak = 'first'", &[], RunOptions::default())
    .await
    .result
    .expect("run");
  let second = pool.acquire().await.expect("realm");
  let seen = second
    .eval_script("return typeof globalThis.leak", &[], RunOptions::default())
    .await;
  assert_eq!(seen.result.expect("run"), serde_json::json!("undefined"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_pool_builds_inline() {
  let builds = Arc::new(AtomicUsize::new(0));
  let counted = Arc::clone(&builds);
  let pool = RealmPool::new(0, move || {
    counted.fetch_add(1, Ordering::SeqCst);
    Runtime::builder()
  });
  let realm = pool.acquire().await.expect("realm");
  assert_eq!(builds.load(Ordering::SeqCst), 1);
  assert_eq!(pool.ready(), 0);
  drop(realm);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recipe_that_fails_reports_on_take() {
  let pool = RealmPool::new(1, || {
    Runtime::builder().extension(FnExtension::new("broken", |_ctx: &rquickjs::Ctx<'_>| {
      Err(rquickjs::Error::new_from_js("x", "y"))
    }))
  });
  let err = pool.acquire().await.expect_err("a broken recipe must fail");
  assert!(err.message.contains("broken"), "{err}");
  tokio::time::sleep(Duration::from_millis(20)).await;
  assert_eq!(pool.ready(), 0);
}
