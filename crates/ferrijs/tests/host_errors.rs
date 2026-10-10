#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The error API a host writes its bindings with: a failure from
//! rquickjs as a `ScriptError`, a promise from script awaited, and an
//! error thrown into script whole and of the right class.

use ferrijs::rquickjs::{Ctx, Function, Value};
use ferrijs::value::{range_error, serde_from_js, settle, type_error};
use ferrijs::{FnExtension, JsResultExt, RunOptions, Runtime, ScriptErrorKind, vm_try};

// A native function rquickjs calls receives its context by value.
#[allow(clippy::needless_pass_by_value)]
fn needs_bag<'js>(ctx: Ctx<'js>, bag: Value<'js>) -> ferrijs::rquickjs::Result<u32> {
  #[derive(serde::Deserialize)]
  struct Bag {
    count: u32,
  }
  Ok(serde_from_js::<Bag>(&ctx, bag)?.count)
}

async fn realm() -> Runtime {
  Runtime::builder()
    .extension(FnExtension::new("errors", |ctx: &Ctx<'_>| {
      let globals = ctx.globals();
      globals.set(
        "longTypeError",
        Function::new(ctx.clone(), |ctx: Ctx<'_>| -> ferrijs::rquickjs::Result<()> {
          Err(type_error(&ctx, "x".repeat(400)))
        })?,
      )?;
      globals.set(
        "outOfRange",
        Function::new(ctx.clone(), |ctx: Ctx<'_>| -> ferrijs::rquickjs::Result<()> {
          Err(range_error(&ctx, "too far"))
        })?,
      )?;
      globals.set("needsBag", Function::new(ctx.clone(), needs_bag)?)?;
      Ok(())
    }))
    .build()
    .await
    .expect("runtime")
}

#[tokio::test]
async fn a_thrown_error_reaches_script_whole_and_of_its_class() {
  let realm = realm().await;
  let run = realm
    .eval_script(
      "const seen = [];
       for (const f of [longTypeError, outOfRange, () => needsBag({ count: 'many' })]) {
         try { f(); } catch (e) { seen.push([e.constructor.name, e instanceof Error, e.message.length, e.message.slice(0, 16)]); }
       }
       return seen;",
      &[],
      RunOptions::default(),
    )
    .await;
  let seen = run.result.unwrap();
  assert_eq!(seen[0], serde_json::json!(["TypeError", true, 400, "xxxxxxxxxxxxxxxx"]));
  assert_eq!(seen[1], serde_json::json!(["RangeError", true, 7, "too far"]));
  assert_eq!(seen[2][0], "TypeError");
  assert_eq!(seen[2][3], "invalid argument");
}

#[tokio::test]
async fn a_failure_from_rquickjs_becomes_a_script_error() {
  let realm = realm().await;
  let vm = realm.handle();
  let value = vm_try!(vm => |ctx| {
    ctx.eval::<i32, _>("20 + 22").or_script_error(&ctx)
  })
  .await
  .unwrap();
  assert_eq!(value, 42);

  let vm = realm.handle();
  let error = vm_try!(vm => |ctx| {
    ctx.eval::<i32, _>("null.property").or_script_error(&ctx)
  })
  .await
  .unwrap_err();
  assert_eq!(error.kind, ScriptErrorKind::Runtime);
  assert_eq!(error.name.as_deref(), Some("TypeError"));
  assert!(error.message.contains("null"), "{}", error.message);
}

#[tokio::test]
async fn settle_awaits_a_promise_and_passes_a_value_through() {
  let realm = realm().await;
  let vm = realm.handle();
  let out = vm_try!(vm => |ctx| {
    let plain = settle(&ctx, ctx.eval::<Value<'_>, _>("7").or_script_error(&ctx)?).await?;
    let later = ctx.eval::<Function<'_>, _>("async () => { await null; return 8 }").or_script_error(&ctx)?;
    let later = settle(&ctx, later.call(()).or_script_error(&ctx)?).await?;
    let early = ctx
      .eval::<Function<'_>, _>("async () => { throw new RangeError('before any await') }")
      .or_script_error(&ctx)?;
    let early = settle(&ctx, early.call(()).or_script_error(&ctx)?).await.unwrap_err();
    Ok::<_, ferrijs::ScriptError>((plain.as_int(), later.as_int(), early.name, early.message))
  })
  .await
  .unwrap();
  assert_eq!(
    out,
    (
      Some(7),
      Some(8),
      Some("RangeError".to_string()),
      "before any await".to_string()
    )
  );
}

#[tokio::test]
async fn fetch_failures_are_the_classes_the_spec_names() {
  let realm = Runtime::builder()
    .permissions(ferrijs::Permissions::none().allow_all_net())
    .build()
    .await
    .expect("runtime");
  let run = realm
    .eval_script(
      "const c = new AbortController(); c.abort();
       const out = [];
       try { await fetch('http://127.0.0.1:1/', { signal: c.signal }); } catch (e) { out.push([e.name, e instanceof DOMException]); }
       try { await fetch('http://127.0.0.1:1/'); } catch (e) { out.push([e.name, e instanceof TypeError]); }
       try { await new Response('not json').json(); } catch (e) { out.push([e.name, e instanceof SyntaxError]); }
       return out;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    run.result.unwrap(),
    serde_json::json!([["AbortError", true], ["TypeError", true], ["SyntaxError", true]])
  );
}
