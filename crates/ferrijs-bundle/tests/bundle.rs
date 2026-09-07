#![allow(clippy::expect_used, clippy::unwrap_used)]
//! A TypeScript entry with relative and native imports bundles, compiles,
//! runs in a realm built over the same module table, and comes back from
//! the cache unchanged.

use std::path::PathBuf;
use std::sync::Arc;

use ferrijs::{ModuleRegistry, Permissions, RunOptions, Runtime, ScriptErrorKind};
use ferrijs_bundle::{Bundler, BundlerOptions, BytecodeCache};

fn project() -> tempfile::TempDir {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(
    dir.path().join("helper.ts"),
    "export const double = (n: number): number => n * 2;\nexport interface Shape { n: number }\n",
  )
  .expect("write");
  std::fs::write(
    dir.path().join("entry.ts"),
    r"
    import { double, type Shape } from './helper';
    import path from 'node:path';
    import { Buffer } from 'buffer';
    const shape: Shape = { n: 21 };
    export default {
      answer: double(shape.n),
      base: path.basename('/x/y.txt'),
      b64: Buffer.from('hi').toString('base64'),
      arg: (globalThis as any).args?.[0] ?? null,
    };
    ",
  )
  .expect("write");
  dir
}

fn bundler(cache: BytecodeCache) -> Bundler {
  Bundler::new(BundlerOptions::default(), Arc::new(ModuleRegistry::with_std()), cache)
}

#[tokio::test]
async fn a_typescript_entry_bundles_compiles_and_runs() {
  let dir = project();
  let entry = dir.path().join("entry.ts");
  let compiled = bundler(BytecodeCache::disabled())
    .compile(&[entry], dir.path(), "entry.js")
    .await
    .expect("compile");
  assert_eq!(compiled.module_name, "entry.js");
  assert!(compiled.source_map.is_some());

  let rt = Runtime::builder()
    .permissions(Permissions::none())
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_module(&compiled, &["from-args".into()], RunOptions::default())
    .await;
  assert_eq!(
    run.result.expect("run"),
    serde_json::json!({ "answer": 42, "base": "y.txt", "b64": "aGk=", "arg": "from-args" })
  );
}

#[tokio::test]
async fn the_cache_answers_the_second_compile_and_notices_an_edit() {
  let dir = project();
  let cache_dir = tempfile::tempdir().expect("cache dir");
  let cache = BytecodeCache::at(cache_dir.path());
  assert!(cache.is_enabled());
  let bundler = bundler(cache.clone());
  let entry = dir.path().join("entry.ts");
  let first = bundler
    .compile(std::slice::from_ref(&entry), dir.path(), "entry.js")
    .await
    .expect("compile");
  let key = bundler.cache_key("bundle:entry.js", std::slice::from_ref(&entry), dir.path());
  let hit = cache.load(key).expect("cache hit");
  assert_eq!(&*first.bytecode, hit.bytecode.as_slice());
  assert_eq!(hit.module_name, "entry.js");
  // The helper is a transitive input: editing it must miss.
  std::thread::sleep(std::time::Duration::from_millis(20));
  std::fs::write(
    dir.path().join("helper.ts"),
    "export const double = (n: number): number => n * 3;\n",
  )
  .expect("write");
  assert!(cache.load(key).is_none());
  let second = bundler
    .compile(&[entry], dir.path(), "entry.js")
    .await
    .expect("compile");
  let rt = Runtime::builder().build().await.expect("runtime");
  let run = rt.eval_module(&second, &[], RunOptions::default()).await;
  assert_eq!(run.result.expect("run")["answer"], 63);
}

#[tokio::test]
async fn a_bundle_error_names_the_file_and_line() {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(dir.path().join("bad.ts"), "const x: number = ;\n").expect("write");
  let err = bundler(BytecodeCache::disabled())
    .compile(&[dir.path().join("bad.ts")], dir.path(), "bad.js")
    .await
    .expect_err("bundle fails");
  assert_eq!(err.kind, ScriptErrorKind::Internal);
  assert!(err.message.contains("bad.ts"), "{}", err.message);
}

#[tokio::test]
async fn a_throw_in_bundled_code_maps_back_to_the_source() {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(
    dir.path().join("throws.ts"),
    "const label: string = 'x';\n\nfunction boom(): never {\n  throw new Error('from ts ' + label);\n}\nboom();\nexport default 1;\n",
  )
  .expect("write");
  let compiled = bundler(BytecodeCache::disabled())
    .compile(&[dir.path().join("throws.ts")], dir.path(), "throws.js")
    .await
    .expect("compile");
  let rt = Runtime::builder().build().await.expect("runtime");
  let run = rt.eval_module(&compiled, &[], RunOptions::default()).await;
  let err = run.err().expect("error");
  assert_eq!(err.message.split(" (at ").next(), Some("from ts x"));
  assert!(err.message.contains("throws.ts:4:"), "{}", err.message);
  let stack = err.stack.as_deref().unwrap_or_default();
  assert!(stack.contains("throws.ts:4:"), "{stack}");
}

#[tokio::test]
async fn several_entries_become_one_chunk() {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(
    dir.path().join("a.js"),
    "globalThis.seen = (globalThis.seen ?? []).concat('a');\n",
  )
  .expect("write");
  std::fs::write(
    dir.path().join("b.js"),
    "globalThis.seen = (globalThis.seen ?? []).concat('b');\n",
  )
  .expect("write");
  let entries: Vec<PathBuf> = vec![dir.path().join("a.js"), dir.path().join("b.js")];
  let compiled = bundler(BytecodeCache::disabled())
    .compile(&entries, dir.path(), "multi.js")
    .await
    .expect("compile");
  let rt = Runtime::builder().build().await.expect("runtime");
  rt.eval_module(&compiled, &[], RunOptions::default())
    .await
    .result
    .expect("run");
  let seen = rt
    .eval_script("return globalThis.seen", &[], RunOptions::default())
    .await;
  assert_eq!(seen.result.expect("run"), serde_json::json!(["a", "b"]));
}

#[test]
fn source_kind_heuristics() {
  assert!(ferrijs_bundle::is_typescript_path(std::path::Path::new("a.mts")));
  assert!(!ferrijs_bundle::is_typescript_path(std::path::Path::new("a.mjs")));
  assert!(ferrijs_bundle::source_is_es_module("import x from 'y';\n"));
  assert!(ferrijs_bundle::source_is_es_module("export const a = 1;"));
  assert!(!ferrijs_bundle::source_is_es_module(
    "const m = await import('y');\nreturn m;"
  ));
}
