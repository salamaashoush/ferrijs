#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The host API an extension is written with: state found by its type,
//! script callbacks kept and called later, and a pump that delivers a
//! host's events into the realm from another task.

use std::time::Duration;

use ferrijs::host::{self, Callback, Pump};
use ferrijs::rquickjs::{Ctx, Function};
use ferrijs::{FnExtension, JsResultExt, RunOptions, Runtime, vm_try};

#[derive(Default)]
struct Counter(u32);

/// The listeners a script registered, and the pump that feeds them.
#[derive(Default)]
struct Listeners(Vec<Callback>);

#[derive(Clone)]
struct Events(Pump<String>);

// A native function rquickjs calls receives its context by value.
#[allow(clippy::needless_pass_by_value)]
fn on_event<'js>(ctx: Ctx<'js>, listener: Function<'js>) {
  let listener = Callback::save(&ctx, listener);
  host::with_or_default(&ctx, |listeners: &mut Listeners| listeners.0.push(listener));
}

fn install(ctx: &Ctx<'_>) -> ferrijs::rquickjs::Result<()> {
  ctx.globals().set(
    "bump",
    Function::new(ctx.clone(), |ctx: Ctx<'_>| {
      host::with_or_default(&ctx, |counter: &mut Counter| {
        counter.0 += 1;
        counter.0
      })
    })?,
  )?;
  ctx.globals().set("onEvent", Function::new(ctx.clone(), on_event)?)?;
  let pump = Pump::start(ctx, 16, |ctx, message: String| {
    let listeners = host::with(ctx, |listeners: &mut Listeners| listeners.0.clone()).unwrap_or_default();
    for listener in listeners {
      listener.call::<_, ()>(ctx, (message.clone(),))?;
    }
    Ok(())
  });
  host::set(ctx, Events(pump));
  Ok(())
}

async fn realm() -> Runtime {
  Runtime::builder()
    .extension(FnExtension::new("host", install))
    .build()
    .await
    .expect("runtime")
}

#[tokio::test]
async fn state_is_found_by_type_and_survives_between_runs() {
  let realm = realm().await;
  let first = realm
    .eval_script("return [bump(), bump()]", &[], RunOptions::default())
    .await;
  assert_eq!(first.result.unwrap(), serde_json::json!([1, 2]));
  let second = realm.eval_script("return bump()", &[], RunOptions::default()).await;
  assert_eq!(second.result.unwrap(), serde_json::json!(3));

  let vm = realm.handle();
  let taken = vm_try!(vm => |ctx| {
    let taken = host::take::<Counter>(&ctx).map(|counter| counter.0);
    let after = host::with(&ctx, |counter: &mut Counter| counter.0);
    host::set(&ctx, Counter(10));
    Ok::<_, ferrijs::ScriptError>((taken, after, host::with(&ctx, |counter: &mut Counter| counter.0)))
  })
  .await
  .unwrap();
  assert_eq!(taken, (Some(3), None, Some(10)));
}

#[tokio::test]
async fn a_callback_is_called_later_and_its_promise_awaited() {
  let realm = realm().await;
  let vm = realm.handle();
  let out = vm_try!(vm => |ctx| {
    let add: Function<'_> = ctx.eval("(a, b) => a + b").or_script_error(&ctx)?;
    let slow: Function<'_> = ctx.eval("async (x) => { await null; return x * 2 }").or_script_error(&ctx)?;
    let early: Function<'_> = ctx.eval("async () => { throw new Error('early') }").or_script_error(&ctx)?;
    let (add, slow, early) = (Callback::save(&ctx, add), Callback::save(&ctx, slow), Callback::save(&ctx, early));
    let sum: i32 = add.call(&ctx, (2, 3)).or_script_error(&ctx)?;
    let doubled = slow.call_async(&ctx, (21,)).await.or_script_error(&ctx)?;
    let failed = early.call_async(&ctx, ()).await.or_script_error(&ctx).unwrap_err();
    Ok::<_, ferrijs::ScriptError>((sum, doubled.as_int(), failed.message))
  })
  .await
  .unwrap();
  assert_eq!(out, (5, Some(42), "early".to_string()));
}

async fn events(realm: &Runtime) -> Pump<String> {
  let vm = realm.handle();
  vm_try!(vm => |ctx| {
    Ok::<_, ferrijs::ScriptError>(host::get::<Events>(&ctx).expect("installed").0)
  })
  .await
  .unwrap()
}

#[tokio::test]
async fn a_pump_delivers_during_a_run_and_between_runs() {
  let realm = realm().await;
  let pump = events(&realm).await;

  // During a run: the script parks until another task's events arrive.
  let sender = pump.clone();
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_millis(20)).await;
    sender.send("first".into()).await.unwrap();
    sender.send("second".into()).await.unwrap();
  });
  let run = realm
    .eval_script(
      "globalThis.seen = [];
       await new Promise((resolve) => onEvent((e) => { seen.push(e); if (seen.length === 2) resolve(); }));
       return seen;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result.unwrap(), serde_json::json!(["first", "second"]));

  // Between runs: delivered with no run in progress, seen by the next.
  pump.try_send("between".into()).unwrap();
  tokio::time::sleep(Duration::from_millis(50)).await;
  let run = realm.eval_script("return seen", &[], RunOptions::default()).await;
  assert_eq!(run.result.unwrap(), serde_json::json!(["first", "second", "between"]));
}

#[tokio::test]
async fn a_throwing_listener_fails_the_run_it_interrupts() {
  let realm = realm().await;
  let pump = events(&realm).await;
  let sender = pump.clone();
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_millis(20)).await;
    sender.send("boom".into()).await.unwrap();
  });
  let run = realm
    .eval_script(
      "onEvent((e) => { throw new Error('listener: ' + e) });
       await new Promise(() => {});",
      &[],
      RunOptions {
        timeout: Some(Duration::from_secs(5)),
        ..RunOptions::default()
      },
    )
    .await;
  assert_eq!(run.result.unwrap_err().message, "listener: boom");
}

#[tokio::test]
async fn a_full_pump_says_so() {
  let realm = Runtime::builder()
    .extension(FnExtension::new("tiny", |ctx: &Ctx<'_>| {
      let pump = Pump::start(ctx, 1, |_ctx, _message: u32| Ok(()));
      host::set(ctx, pump);
      Ok(())
    }))
    .build()
    .await
    .expect("runtime");
  let vm = realm.handle();
  let pump = vm_try!(vm => |ctx| {
    Ok::<_, ferrijs::ScriptError>(host::get::<Pump<u32>>(&ctx).expect("installed"))
  })
  .await
  .unwrap();
  // The loop only drains while it is polled; a burst outruns it.
  let results: Vec<_> = (0..64).map(|n| pump.try_send(n)).collect();
  assert!(results.contains(&Err(host::SendError::Full)), "{results:?}");
}
