#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Lazy standard-library globals: a realm built lazily must end up as
//! the eager one once its globals are read, Rust that builds a lazy
//! group's objects before any script read the global must still get them
//! wired, and what a script did to a name before its group installed
//! must survive the install.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrijs::{FnExtension, Permissions, RealmOptions, RunOptions, Runtime};

async fn realm(lazy: bool) -> Runtime {
  Runtime::builder()
    .permissions(Permissions::all())
    .realm(RealmOptions {
      lazy_globals: lazy,
      ..RealmOptions::default()
    })
    .build()
    .await
    .expect("runtime")
}

async fn eval(rt: &Runtime, source: &str, args: &[serde_json::Value]) -> serde_json::Value {
  let run = rt.eval_script(source, args, RunOptions::default()).await;
  match run.result {
    Ok(value) => value,
    Err(error) => panic!("run failed: {error}\n{:?}", error.stack),
  }
}

fn lazy_names() -> Vec<&'static str> {
  ferrijs::std::LAZY_GROUPS
    .iter()
    .flat_map(|group| group.names.iter().copied())
    .collect()
}

/// Every own global with its type, attributes and, for a constructor, the
/// constructor names along its prototype chain.
const SHAPE: &str = r"
  for (const name of args[0]) void globalThis[name];
  const chain = (proto) => {
    const out = [];
    for (let p = proto; p; p = Object.getPrototypeOf(p)) {
      const c = Object.getOwnPropertyDescriptor(p, 'constructor');
      out.push(c && typeof c.value === 'function' ? c.value.name : '?');
    }
    return out;
  };
  return Reflect.ownKeys(globalThis)
    .filter((k) => typeof k === 'string' && k !== 'args')
    .sort()
    .map((k) => {
      const d = Object.getOwnPropertyDescriptor(globalThis, k);
      const v = d.value;
      return [k, 'value' in d, typeof v, d.writable, d.enumerable, d.configurable,
        typeof v === 'function' && v.prototype ? chain(v.prototype) : null];
    });
";

#[tokio::test]
async fn a_lazy_realm_once_read_matches_an_eager_one() {
  let names = serde_json::json!(lazy_names());
  let eager = eval(&realm(false).await, SHAPE, std::slice::from_ref(&names)).await;
  let lazy = eval(&realm(true).await, SHAPE, &[names]).await;
  assert_eq!(lazy, eager);
}

#[tokio::test]
async fn each_group_defines_exactly_its_names() {
  let rt = realm(true).await;
  for group in ferrijs::std::LAZY_GROUPS {
    let names = group.names;
    let out = eval(
      &rt,
      r"
        const [names, all] = args;
        const keys = () => new Set(Reflect.ownKeys(globalThis));
        const before = keys();
        void globalThis[names[0]];
        const added = [...keys()].filter((k) => !before.has(k)).map(String);
        const accessor = (n) => !('value' in (Object.getOwnPropertyDescriptor(globalThis, n) ?? { value: 0 }));
        return {
          added,
          stillLazy: names.filter(accessor),
          missing: names.filter((n) => !(n in globalThis)),
          othersInstalled: all.filter((n) => !names.includes(n) && !accessor(n)),
        };
      ",
      &[serde_json::json!(names), serde_json::json!(lazy_names())],
    )
    .await;
    let installed_before = out["othersInstalled"].as_array().unwrap().len();
    assert_eq!(
      out["added"],
      serde_json::json!([]),
      "{names:?} defined globals it does not list"
    );
    assert_eq!(out["stillLazy"], serde_json::json!([]), "{names:?}");
    assert_eq!(
      out["missing"],
      serde_json::json!([]),
      "{names:?} lists globals it does not define"
    );
    // Groups touched earlier in this loop are installed; nothing else is.
    let earlier: usize = ferrijs::std::LAZY_GROUPS
      .iter()
      .take_while(|g| g.names != names)
      .map(|g| g.names.len())
      .sum();
    assert_eq!(installed_before, earlier, "{names:?} installed another group");
  }
}

#[tokio::test]
async fn rust_built_objects_are_wired_before_any_global_is_read() {
  let dir = tempfile::tempdir().unwrap();
  let file = dir.path().join("data.txt");
  std::fs::write(&file, "hello").unwrap();
  let path = serde_json::json!(file.to_string_lossy());

  let cases: &[(&str, &str)] = &[
    (
      "fs Buffer",
      "const b = require('node:fs').readFileSync(args[0]); return [typeof b.equals, b.toString()]",
    ),
    (
      "zlib Buffer",
      "const z = require('node:zlib'); return z.inflateSync(z.deflateSync('abc')).toString()",
    ),
    (
      "crypto Buffer",
      "return require('node:crypto').createHash('sha256').update('a').digest().toString('hex').length",
    ),
    (
      "response body stream",
      "const r = new Response('body').body.getReader(); const { value } = await r.read(); return value.length",
    ),
    (
      "async iteration of a body",
      "let n = 0; for await (const c of new Response('abc').body) n += c.length; return n",
    ),
    (
      "multipart File",
      "const body = '--b\\r\\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\\r\\n\\r\\nhi\\r\\n--b--\\r\\n';
       const fd = await new Response(body, { headers: { 'content-type': 'multipart/form-data; boundary=b' } }).formData();
       const f = fd.get('f');
       return [f.name, typeof f.text, await f.text()]",
    ),
  ];
  let expected = [
    serde_json::json!(["function", "hello"]),
    serde_json::json!("abc"),
    serde_json::json!(64),
    serde_json::json!(4),
    serde_json::json!(3),
    serde_json::json!(["a.txt", "function", "hi"]),
  ];
  for ((what, source), want) in cases.iter().zip(expected) {
    let rt = realm(true).await;
    assert_eq!(eval(&rt, source, std::slice::from_ref(&path)).await, want, "{what}");
  }
}

#[tokio::test]
async fn what_a_script_did_before_an_install_survives_it() {
  let rt = realm(true).await;
  let out = eval(
    &rt,
    r"
      'use strict';
      URL = 1;
      delete globalThis.TextEncoder;
      Object.defineProperty(globalThis, 'Blob', { value: 5, writable: false, enumerable: false, configurable: true });
      globalThis.Buffer = 'mine';
      const params = new URLSearchParams('a=1').get('a');
      const decoder = typeof new TextDecoder().decode;
      const fromFs = typeof require('node:fs').readFileSync(args[0]).equals;
      const blob = Object.getOwnPropertyDescriptor(globalThis, 'Blob');
      return {
        url: URL, params, decoder, encoder: 'TextEncoder' in globalThis,
        blob: [blob.value, blob.writable, blob.enumerable], buffer: globalThis.Buffer, fromFs,
        file: typeof File,
      };
    ",
    &[serde_json::json!(file_in_tempdir())],
  )
  .await;
  assert_eq!(
    out,
    serde_json::json!({
      "url": 1, "params": "1", "decoder": "function", "encoder": false,
      "blob": [5, false, false], "buffer": "mine", "fromFs": "function", "file": "function",
    })
  );
}

fn file_in_tempdir() -> String {
  let dir = tempfile::tempdir().unwrap().keep();
  let file = dir.join("x.txt");
  std::fs::write(&file, "x").unwrap();
  file.to_string_lossy().into_owned()
}

#[tokio::test]
async fn the_lockdown_applies_to_lazy_names() {
  let rt = Runtime::builder()
    .realm(RealmOptions {
      remove_globals: vec!["URL".into()],
      freeze_intrinsics: true,
      ..RealmOptions::default()
    })
    .build()
    .await
    .expect("runtime");
  let out = eval(
    &rt,
    "return [typeof URL, new URLSearchParams('a=2').get('a'), 'URL' in globalThis, typeof new TextEncoder().encode]",
    &[],
  )
  .await;
  assert_eq!(out, serde_json::json!(["undefined", "2", false, "function"]));
}

fn counting_extension(
  installs: Arc<AtomicUsize>,
) -> FnExtension<impl for<'js> Fn(&rquickjs::Ctx<'js>) -> rquickjs::Result<()>> {
  FnExtension::new("lazy-host", move |ctx: &rquickjs::Ctx<'_>| {
    let installs = Arc::clone(&installs);
    ferrijs::lazy::define(ctx, &["hostThing", "hostOther"], move |ctx| {
      installs.fetch_add(1, Ordering::SeqCst);
      ctx.globals().set("hostThing", 41)?;
      ctx.globals().set("hostOther", "other")?;
      Ok(())
    })
  })
}

#[tokio::test]
async fn a_host_group_installs_once_on_first_read() {
  let installs = Arc::new(AtomicUsize::new(0));
  let rt = Runtime::builder()
    .extension(counting_extension(Arc::clone(&installs)))
    .build()
    .await
    .expect("runtime");
  assert_eq!(installs.load(Ordering::SeqCst), 0);
  let out = eval(&rt, "return [hostThing + 1, hostOther, hostThing]", &[]).await;
  assert_eq!(out, serde_json::json!([42, "other", 41]));
  eval(&rt, "return hostOther", &[]).await;
  assert_eq!(installs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_eager_realm_installs_host_groups_at_build() {
  let installs = Arc::new(AtomicUsize::new(0));
  let rt = Runtime::builder()
    .realm(RealmOptions {
      lazy_globals: false,
      ..RealmOptions::default()
    })
    .extension(counting_extension(Arc::clone(&installs)))
    .build()
    .await
    .expect("runtime");
  assert_eq!(installs.load(Ordering::SeqCst), 1);
  let out = eval(
    &rt,
    "return ['value' in Object.getOwnPropertyDescriptor(globalThis, 'hostThing'), 'value' in Object.getOwnPropertyDescriptor(globalThis, 'URL')]",
    &[],
  )
  .await;
  assert_eq!(out, serde_json::json!([true, true]));
}
