#![cfg(feature = "intl")]
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `Intl` through the runtime: installed on first read, answering under
//! the defaults the host gave, and absent when the host asks for none.

use ferrijs::intl::IntlOptions;
use ferrijs::{RunOptions, Runtime};

async fn eval(rt: &Runtime, source: &str) -> serde_json::Value {
  let run = rt.eval_script(source, &[], RunOptions::default()).await;
  match run.result {
    Ok(value) => value,
    Err(error) => panic!("run failed: {error}\n{:?}", error.stack),
  }
}

fn arabic_cairo() -> IntlOptions {
  IntlOptions {
    default_locale: Some("ar-EG".to_owned()),
    default_time_zone: Some("Africa/Cairo".to_owned()),
  }
}

#[tokio::test]
async fn intl_answers_under_the_host_defaults() {
  let rt = Runtime::builder().intl(arabic_cairo()).build().await.expect("runtime");
  let seen = eval(
    &rt,
    "return JSON.stringify([
      new Intl.DateTimeFormat().resolvedOptions().timeZone,
      new Intl.NumberFormat().format(1234.5),
      new Date(Date.UTC(2024, 0, 1, 22)).toLocaleTimeString('en-US', { hour: 'numeric' }),
      ['b', 'a'].sort((x, y) => x.localeCompare(y)).join(),
    ])",
  )
  .await;
  assert_eq!(seen, serde_json::json!(r#"["Africa/Cairo","١٬٢٣٤٫٥","12 AM","a,b"]"#));
}

#[tokio::test]
async fn intl_installs_on_first_read() {
  let rt = Runtime::builder().build().await.expect("runtime");
  let seen = eval(
    &rt,
    "const before = Object.getOwnPropertyDescriptor(globalThis, 'Intl');
     const tag = Object.prototype.toString.call(Intl);
     const after = Object.getOwnPropertyDescriptor(globalThis, 'Intl');
     return JSON.stringify([typeof before.get, tag, typeof after.value]);",
  )
  .await;
  assert_eq!(seen, serde_json::json!(r#"["function","[object Intl]","object"]"#));
}

#[tokio::test]
async fn without_intl_there_is_none() {
  let rt = Runtime::builder().without_intl().build().await.expect("runtime");
  assert_eq!(eval(&rt, "return typeof Intl").await, serde_json::json!("undefined"));
}
