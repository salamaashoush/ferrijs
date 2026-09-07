#![allow(clippy::expect_used, clippy::unwrap_used)]
//! One realm across many runs, the way a long-lived host drives it:
//! state that persists REPL-style, per-run deadlines and what they
//! poison, console capture, `args` binding, error shapes, module
//! loading from disk, and the runtime's timer / URL / text-codec /
//! console shims.

use std::time::Duration;

use ferrijs::{ConsoleLevel, ModulePolicy, Permissions, Run, RunOptions, Runtime, ScriptErrorKind};

async fn plain() -> Runtime {
  Runtime::builder().build().await.expect("runtime")
}

async fn with_root(root: &std::path::Path) -> Runtime {
  Runtime::builder()
    .modules(ModulePolicy::new(root))
    .build()
    .await
    .expect("runtime")
}

fn ok(run: &Run<serde_json::Value>) -> &serde_json::Value {
  match &run.result {
    Ok(value) => value,
    Err(error) => panic!("expected ok, got error: {error:?}"),
  }
}

// ── Deadlines: per-run overrides, and what a fired one leaves behind ──────

#[tokio::test(flavor = "multi_thread")]
async fn timeout_poisons_the_session() {
  let rt = plain().await;

  let timed = rt
    .eval_script(
      "while (true) { /* spin */ }",
      &[],
      RunOptions {
        timeout: Some(Duration::from_millis(150)),
        ..RunOptions::default()
      },
    )
    .await;
  match &timed.result {
    Err(error) => assert_eq!(error.kind, ScriptErrorKind::Timeout),
    Ok(_) => panic!("expected timeout"),
  }
  // A fired timeout interrupt halts the interpreter mid-run: the VM is
  // poisoned and the caller must discard it.
  assert!(timed.poisoned, "a timeout must poison the session");
}

#[tokio::test(flavor = "multi_thread")]
async fn native_await_park_hits_the_backstop_and_poisons() {
  let rt = plain().await;

  // The interrupt handler only runs while bytecode executes; a script
  // parked on a never-resolving native promise would otherwise hold the
  // session slot forever. The tokio-level backstop must fire instead.
  let timed = rt
    .eval_script(
      "await new Promise(() => {});",
      &[],
      RunOptions {
        timeout: Some(Duration::from_millis(150)),
        ..RunOptions::default()
      },
    )
    .await;
  match &timed.result {
    Err(error) => assert_eq!(error.kind, ScriptErrorKind::Timeout),
    Ok(_) => panic!("expected timeout"),
  }
  assert!(timed.poisoned, "a backstop fire must poison the session");
}

#[tokio::test(flavor = "multi_thread")]
async fn finished_call_deadline_does_not_halt_later_vm_entry() {
  let rt = plain().await;

  let quick = rt
    .eval_script(
      "return 1;",
      &[],
      RunOptions {
        timeout: Some(Duration::from_millis(100)),
        ..RunOptions::default()
      },
    )
    .await;
  assert!(quick.result.is_ok());
  assert!(!quick.poisoned);

  tokio::time::sleep(Duration::from_millis(250)).await;

  // A host dispatch re-enters the VM between calls via the realm's VM
  // event loop. An armed deadline left over from the finished call
  // would force-halt this entry.
  let vm = rt.handle();
  let entered = ferrijs::vm_with!(vm => |c| {
    c.eval::<f64, _>("let s = 0; for (let i = 0; i < 1e6; i++) s += i; s")
  })
  .await
  .expect("VM loop gone");
  assert!(
    entered.is_ok(),
    "between-call VM entry must not be halted by the previous call's deadline: {entered:?}"
  );
}

// ── Values in and out: args binding, return shapes, error shapes ─────────

#[tokio::test]
async fn args_are_bound_not_interpolated() {
  let rt = plain().await;
  // If args were interpolated, the quote/semicolon would break parsing.
  // With bound args, it's just a string value.
  let payload = serde_json::json!("'; drop table users; --");
  let result = rt
    .eval_script("return args[0]", std::slice::from_ref(&payload), RunOptions::default())
    .await;
  assert_eq!(ok(&result), &payload);
}

#[tokio::test]
async fn args_support_complex_types() {
  let rt = plain().await;
  let args = vec![
    serde_json::json!("plain string"),
    serde_json::json!({ "user": { "name": "alice", "tags": ["a", "b"] } }),
    serde_json::json!([1, 2, 3, null, false]),
  ];
  let result = rt
    .eval_script(
      "return { s: args[0], obj: args[1], arr: args[2] };",
      &args,
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&result),
    &serde_json::json!({
      "s": "plain string",
      "obj": { "user": { "name": "alice", "tags": ["a", "b"] } },
      "arr": [1, 2, 3, null, false]
    })
  );
}

#[tokio::test]
async fn returns_nested_object() {
  let rt = plain().await;
  let result = rt
    .eval_script(
      "return { a: 1, b: [2, 3, { c: 'nested', d: [true, null] }], unicode: 'héllo 🚀' };",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&result),
    &serde_json::json!({
      "a": 1,
      "b": [2, 3, { "c": "nested", "d": [true, null] }],
      "unicode": "héllo 🚀"
    })
  );
}

#[tokio::test]
async fn syntax_error_reports_structured_error() {
  let rt = plain().await;
  let result = rt
    .eval_script("this is not js at all", &[], RunOptions::default())
    .await;
  match &result.result {
    Ok(_) => panic!("expected syntax error"),
    Err(error) => {
      // The thrown `SyntaxError` is classified by name.
      assert_eq!(error.kind, ScriptErrorKind::Syntax);
      assert!(!error.message.is_empty());
    },
  }
}

#[tokio::test]
async fn thrown_error_includes_line_number() {
  let rt = plain().await;
  let result = rt
    .eval_script(
      r"
      let x = 1;
      let y = 2;
      throw new Error('deliberate');
      return x + y;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  match &result.result {
    Ok(_) => panic!("expected error"),
    Err(error) => {
      assert_eq!(error.kind, ScriptErrorKind::Runtime);
      assert!(error.message.contains("deliberate"), "got: {}", error.message);
      // Line numbers come from QuickJS's exception object; not guaranteed on
      // every variant, but when present the snippet is too.
      if error.line.is_some() {
        assert!(error.source_snippet.is_some());
      }
    },
  }
}

// ── Console capture ───────────────────────────────────────────────────────

#[tokio::test]
async fn console_levels_recorded_correctly() {
  let rt = plain().await;
  let result = rt
    .eval_script(
      r"
      console.log('log-msg');
      console.info('info-msg');
      console.warn('warn-msg');
      console.error('error-msg');
      console.debug('debug-msg');
      return null;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(result.result.is_ok(), "{result:?}");
  let levels: Vec<ConsoleLevel> = result.console.iter().map(|e| e.level).collect();
  assert_eq!(
    levels,
    vec![
      ConsoleLevel::Log,
      ConsoleLevel::Info,
      ConsoleLevel::Warn,
      ConsoleLevel::Error,
      ConsoleLevel::Debug,
    ]
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn console_uses_node_style_formatter_and_is_captured() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "console.log('n =', 42, { a: 1 }); console.warn(['x', 'y']); return null;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(r.result.is_ok(), "{:?}", r.result);
  let console = &r.console;
  assert_eq!(console.len(), 2, "two console entries: {console:?}");
  // Top-level string + number stay unquoted; object renders Node-style
  // (not JSON.stringify's {"a":1}).
  let line0 = &console[0].message;
  assert!(line0.starts_with("n = 42 "), "got: {line0}");
  assert!(line0.contains("a: 1"), "object Node-style, got: {line0}");
  // Arrays render structurally with strings quoted (`[ 'x', 'y' ]`,
  // Node's util.inspect shape) rather than via JSON.stringify
  // (`["x","y"]`).
  assert!(
    console[1].message.contains("[ 'x', 'y' ]"),
    "array rendered structurally, got: {}",
    console[1].message
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn console_printf_and_inspect_rendering() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "console.log('%s scored %d%%', 'amy', 97, 'extra');\n\
       console.log(['x', 1]);\n\
       console.log(new Map([['a', 1]]));\n\
       console.log(new Set([1, 2]));\n\
       console.log(/ab+c/gi);\n\
       return null;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(r.result.is_ok(), "{:?}", r.result);
  let console = &r.console;
  assert_eq!(console[0].message, "amy scored 97% extra", "{:?}", console[0]);
  assert_eq!(console[1].message, "[ 'x', 1 ]", "{:?}", console[1]);
  assert_eq!(console[2].message, "Map(1) { 'a' => 1 }", "{:?}", console[2]);
  assert_eq!(console[3].message, "Set(2) { 1, 2 }", "{:?}", console[3]);
  assert_eq!(console[4].message, "/ab+c/gi", "{:?}", console[4]);
}

// ── Module loading from disk ──────────────────────────────────────────────

#[tokio::test]
async fn imports_a_relative_module() {
  let tmp = tempfile::tempdir().expect("tempdir");
  std::fs::write(
    tmp.path().join("helper.js"),
    "export function greet(name) { return `hi ${name}`; }",
  )
  .unwrap();
  let rt = with_root(tmp.path()).await;
  let result = rt
    .eval_script(
      "const m = await import('./helper.js'); return m.greet('world');",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&result), &serde_json::json!("hi world"));
}

/// A relative import that climbs above the module root resolves: the
/// root is an anchor, not a boundary, unless the policy is jailed.
#[tokio::test]
async fn import_follows_a_parent_specifier() {
  let tmp = tempfile::tempdir().expect("tempdir");
  let parent = tmp.path().parent().expect("parent").to_path_buf();
  let helper = parent.join("ferrijs-session-shared.js");
  std::fs::write(&helper, "export const shared = 'from above';").expect("seed");

  let rt = with_root(tmp.path()).await;
  let result = rt
    .eval_script(
      "const m = await import('../ferrijs-session-shared.js'); return m.shared;",
      &[],
      RunOptions::default(),
    )
    .await;
  let _ = std::fs::remove_file(&helper);
  assert_eq!(ok(&result), &serde_json::json!("from above"));
}

#[tokio::test]
async fn imports_from_nested_subdirectory() {
  let tmp = tempfile::tempdir().expect("tempdir");
  std::fs::create_dir_all(tmp.path().join("lib/util")).unwrap();
  std::fs::write(
    tmp.path().join("lib/util/math.js"),
    "export const double = (n) => n * 2;",
  )
  .unwrap();

  let rt = with_root(tmp.path()).await;
  let result = rt
    .eval_script(
      "const m = await import('./lib/util/math.js'); return m.double(21);",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&result), &serde_json::json!(42));
}

#[tokio::test]
async fn rejects_bare_module_import() {
  let rt = plain().await;
  let result = rt
    .eval_script(
      "try { await import('lodash'); return 'no-error'; } catch (e) { return 'rejected: ' + String(e).slice(0, 30); }",
      &[],
      RunOptions::default(),
    )
    .await;
  let s = ok(&result).as_str().unwrap_or_default().to_string();
  assert!(s.starts_with("rejected"), "got: {s}");
}

// ── `fs` through the Node surface, under a read/write grant ───────────────

/// `fs` is Node's, so a script reads and writes the way Node does.
#[tokio::test]
async fn fs_reads_and_writes_through_the_node_surface() {
  let tmp = tempfile::tempdir().expect("tempdir");
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([tmp.path()]).allow_write([tmp.path()]))
    .build()
    .await
    .expect("runtime");
  let note = tmp.path().join("note.txt").to_string_lossy().into_owned();
  let result = rt
    .eval_script(
      &format!(
        r"
      const fs = require('node:fs');
      const note = {note:?};
      await fs.promises.writeFile(note, 'hello world');
      const viaPromise = await fs.promises.readFile(note, 'utf8');
      const viaSync = fs.readFileSync(note, 'utf8');
      const bytes = fs.readFileSync(note);
      return {{ viaPromise, viaSync, length: bytes.length }};
      "
      ),
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&result),
    &serde_json::json!({ "viaPromise": "hello world", "viaSync": "hello world", "length": 11 })
  );
}

/// A `..` component resolves; it is not a refusal. The grant, not the
/// spelling of the path, is the boundary.
#[tokio::test]
async fn fs_follows_a_parent_component() {
  let tmp = tempfile::tempdir().expect("tempdir");
  let outside = tmp.path().parent().expect("parent").join("ferrijs-session-outside.txt");
  std::fs::write(&outside, b"reachable").expect("seed");
  let nested = tmp.path().join("nested");
  std::fs::create_dir_all(&nested).expect("mkdir");
  let via_parent = nested
    .join("..")
    .join("..")
    .join("ferrijs-session-outside.txt")
    .to_string_lossy()
    .into_owned();

  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([tmp.path().parent().expect("parent")]))
    .build()
    .await
    .expect("runtime");
  let result = rt
    .eval_script(
      &format!("const fs = require('node:fs'); return fs.readFileSync({via_parent:?}, 'utf8');"),
      &[],
      RunOptions::default(),
    )
    .await;
  let _ = std::fs::remove_file(&outside);
  assert_eq!(ok(&result), &serde_json::json!("reachable"));
}

#[tokio::test]
async fn fs_readdir_lists_directory_contents() {
  let tmp = tempfile::tempdir().expect("tempdir");
  std::fs::write(tmp.path().join("a.txt"), b"x").unwrap();
  std::fs::write(tmp.path().join("b.txt"), b"y").unwrap();
  std::fs::create_dir_all(tmp.path().join("sub")).unwrap();

  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([tmp.path()]))
    .build()
    .await
    .expect("runtime");
  let dir = tmp.path().to_string_lossy().into_owned();
  let result = rt
    .eval_script(
      &format!(
        "const fs = require('node:fs'); const entries = await fs.promises.readdir({dir:?}); entries.sort(); return entries;"
      ),
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&result), &serde_json::json!(["a.txt", "b.txt", "sub"]));
}

#[tokio::test]
async fn fs_exists_reports_presence_and_absence() {
  let tmp = tempfile::tempdir().expect("tempdir");
  std::fs::write(tmp.path().join("present.txt"), b"x").unwrap();

  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([tmp.path()]))
    .build()
    .await
    .expect("runtime");
  let present = tmp.path().join("present.txt").to_string_lossy().into_owned();
  let absent = tmp.path().join("nothing.txt").to_string_lossy().into_owned();
  let result = rt
    .eval_script(
      &format!(
        r"
      const fs = require('node:fs');
      return {{ has: fs.existsSync({present:?}), missing: fs.existsSync({absent:?}) }};
      "
      ),
      &[],
      RunOptions::default(),
    )
    .await;
  // `false` means the file is not there, and nothing else — the answer
  // used to double as "the sandbox refused", which made a spec asking
  // whether its baseline had been written answer no for a file that was
  // sitting right there.
  assert_eq!(ok(&result), &serde_json::json!({ "has": true, "missing": false }));
}

// ── Realm isolation and longevity ─────────────────────────────────────────

/// A realm is the unit of isolation: what one leaks on `globalThis`, a
/// second one built from the same builder never sees.
#[tokio::test]
async fn fresh_context_isolates_state() {
  let first = plain().await;
  // First run leaks a global
  let _ = first
    .eval_script("globalThis.leak = 42; return 1", &[], RunOptions::default())
    .await;
  // A second realm should not see it
  let second = plain().await;
  let run = second
    .eval_script("return typeof globalThis.leak", &[], RunOptions::default())
    .await;
  assert_eq!(ok(&run), &serde_json::json!("undefined"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_lived_runtime_keeps_state_and_stays_healthy() {
  let rt = plain().await;

  // REPL counter seed.
  let seed = rt
    .eval_script("globalThis.c = 0; return true;", &[], RunOptions::default())
    .await;
  assert_eq!(ok(&seed), &serde_json::json!(true));

  // 40 sequential calls, each incrementing a `globalThis` counter. If
  // the VM ever rebuilt spuriously the counter would reset and the
  // final assert (== 40) would fail.
  for i in 1..=40u32 {
    let r = rt
      .eval_script(
        "globalThis.c += 1; return { c: globalThis.c };",
        &[],
        RunOptions::default(),
      )
      .await;
    let v = ok(&r);
    assert_eq!(
      v["c"],
      serde_json::json!(i),
      "REPL counter must advance with no rebuild"
    );
  }
  let r = rt
    .eval_script("return { c: globalThis.c };", &[], RunOptions::default())
    .await;
  assert_eq!(
    ok(&r)["c"],
    serde_json::json!(40),
    "globalThis survived all 41 executes"
  );

  // Heavy object churn: 250 executes each allocating/returning a sizable
  // structure. Stays under the 256 MiB quota and never poisons — proves
  // the cycle-GC threshold path frees memory and there is no leak across
  // a long-lived VM.
  for i in 0..250u32 {
    let r = rt
      .eval_script(
        "const a = Array.from({length: 5000}, (_, i) => ({ i, s: 'x'.repeat(32), nested: [i, i*2] })); \
         globalThis.churn = (globalThis.churn || 0) + 1; \
         return a.length + globalThis.churn;",
        &[],
        RunOptions::default(),
      )
      .await;
    if let Err(error) = &r.result {
      panic!("churn iter {i} failed (possible leak/OOM): {error:?}");
    }
    assert!(!r.poisoned, "churn iter {i} poisoned the realm");
  }
  let r = rt
    .eval_script("return globalThis.churn;", &[], RunOptions::default())
    .await;
  assert_eq!(ok(&r), &serde_json::json!(250), "all 250 churn executes ran in one VM");

  // A timeout poisons the VM; every later call on this realm is
  // refused, so the host knows to build a fresh one.
  let timed = rt
    .eval_script(
      "while (true) {}",
      &[],
      RunOptions {
        timeout: Some(Duration::from_millis(200)),
        ..Default::default()
      },
    )
    .await;
  assert!(timed.result.is_err(), "infinite loop must time out");
  assert!(timed.poisoned);
  let refused = rt.eval_script("return globalThis.c;", &[], RunOptions::default()).await;
  assert!(refused.poisoned, "a poisoned realm stays poisoned");
  assert!(refused.result.is_err(), "a poisoned realm runs nothing");
}

// ── Runtime shims: timers, URL, web polyfills, proper console ─────────────

#[tokio::test(flavor = "multi_thread")]
async fn set_timeout_resolves_inside_execute() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "return await new Promise((resolve) => setTimeout(() => resolve(7), 20));",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&r), &serde_json::json!(7));
  assert!(!r.poisoned);
}

#[tokio::test(flavor = "multi_thread")]
async fn timer_handle_persists_and_clears_across_calls() {
  let rt = plain().await;

  // Call 1: arm a long timeout, stash its handle on globalThis.
  let r1 = rt
    .eval_script(
      "globalThis.__t = setTimeout(() => { globalThis.__fired = true; }, 10000); \
       return typeof globalThis.__t;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(r1.result.is_ok(), "{:?}", r1.result);

  // Call 2: the handle survived REPL-style; clearTimeout accepts it.
  let r2 = rt
    .eval_script(
      "clearTimeout(globalThis.__t); return globalThis.__fired === true;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&r2), &serde_json::json!(false), "timer must not have fired");
}

#[tokio::test(flavor = "multi_thread")]
async fn set_timeout_passes_extra_args_and_clear_tolerates_garbage() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "clearTimeout(undefined); clearTimeout(null); clearTimeout(42); clearInterval();\n\
       return await new Promise((resolve) => setTimeout((a, b) => resolve(a + b), 10, 'x', 'y'));",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&r), &serde_json::json!("xy"));
}

#[tokio::test(flavor = "multi_thread")]
async fn url_and_search_params_work() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const p = new URLSearchParams('a=1&b=2'); p.append('b', '3'); \
       return [p.get('a'), p.getAll('b').join(',')];",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&r), &serde_json::json!(["1", "2,3"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn web_polyfills_text_codec_base64_microtask() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const enc = new TextEncoder().encode('hi€'); \
       const dec = new TextDecoder().decode(enc); \
       let mt = 0; queueMicrotask(() => { mt = 1; }); \
       await Promise.resolve(); \
       return { len: enc.length, dec, b64: btoa('hi'), round: atob(btoa('xy')), mt };",
      &[],
      RunOptions::default(),
    )
    .await;
  let value = ok(&r);
  assert_eq!(value["len"], serde_json::json!(5), "hi€ = 5 UTF-8 bytes: {value:?}");
  assert_eq!(value["dec"], serde_json::json!("hi€"));
  assert_eq!(value["b64"], serde_json::json!("aGk="));
  assert_eq!(value["round"], serde_json::json!("xy"));
  assert_eq!(value["mt"], serde_json::json!(1), "queueMicrotask must have run");
}

#[tokio::test(flavor = "multi_thread")]
async fn native_url_class_parses_and_exposes_search_params() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const u = new URL('https://ex.com:8443/a/b?x=1&y=2#frag'); \
       return { href: u.href, host: u.host, hostname: u.hostname, port: u.port, \
                proto: u.protocol, path: u.pathname, search: u.search, hash: u.hash, \
                origin: u.origin, sp: u.searchParams.get('y'), str: String(u) };",
      &[],
      RunOptions::default(),
    )
    .await;
  let v = ok(&r);
  assert_eq!(v["host"], serde_json::json!("ex.com:8443"), "{v}");
  assert_eq!(v["hostname"], serde_json::json!("ex.com"));
  assert_eq!(v["port"], serde_json::json!("8443"));
  assert_eq!(v["proto"], serde_json::json!("https:"));
  assert_eq!(v["path"], serde_json::json!("/a/b"));
  assert_eq!(v["search"], serde_json::json!("?x=1&y=2"));
  assert_eq!(v["hash"], serde_json::json!("#frag"));
  assert_eq!(v["origin"], serde_json::json!("https://ex.com:8443"));
  assert_eq!(v["sp"], serde_json::json!("2"), "searchParams via native URL: {v}");
  assert_eq!(v["str"], serde_json::json!("https://ex.com:8443/a/b?x=1&y=2#frag"));
}

#[tokio::test(flavor = "multi_thread")]
async fn url_search_params_binding_is_live_in_both_directions() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const u = new URL('https://ex.com/p?a=1');\n\
       const sp = u.searchParams;\n\
       sp.append('b', '2');\n\
       const afterAppend = [u.href, u.search];\n\
       u.search = '?c=3';\n\
       const afterSearchSet = [sp.get('c'), sp.has('a'), sp.size];\n\
       u.href = 'https://ex.com/q?d=4';\n\
       return { afterAppend, afterSearchSet, sameObject: u.searchParams === sp, afterHref: sp.get('d') };",
      &[],
      RunOptions::default(),
    )
    .await;
  let v = ok(&r);
  assert_eq!(
    v["afterAppend"],
    serde_json::json!(["https://ex.com/p?a=1&b=2", "?a=1&b=2"]),
    "params mutation must rewrite the URL: {v}"
  );
  assert_eq!(
    v["afterSearchSet"],
    serde_json::json!(["3", false, 1]),
    "setting search must be visible through the same params object: {v}"
  );
  assert_eq!(v["sameObject"], serde_json::json!(true));
  assert_eq!(
    v["afterHref"],
    serde_json::json!("4"),
    "href set must reach params: {v}"
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn text_codecs_cover_utf16_and_the_stream_forms() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const utf16 = new TextDecoder('utf-16le').decode(new Uint8Array([0x68, 0x00, 0x69, 0x00]));\n\
       const es = new TextEncoderStream();\n\
       const ds = new TextDecoderStream();\n\
       const out = es.readable.pipeThrough(ds).getReader();\n\
       const w = es.writable.getWriter();\n\
       await w.write('hi\\u20ac');\n\
       await w.close();\n\
       let text = '';\n\
       for (;;) { const { value, done } = await out.read(); if (done) break; text += value; }\n\
       return { utf16, text, encoding: ds.encoding };",
      &[],
      RunOptions::default(),
    )
    .await;
  let v = ok(&r);
  assert_eq!(v["utf16"], serde_json::json!("hi"), "utf-16le decode: {v}");
  assert_eq!(v["text"], serde_json::json!("hi\u{20ac}"), "stream round-trip: {v}");
  assert_eq!(v["encoding"], serde_json::json!("utf-8"));
}

#[tokio::test(flavor = "multi_thread")]
async fn node_url_module_serves_the_path_and_host_helpers() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const url = require('node:url');\n\
       const opts = url.urlToHttpOptions(new URL('https://ex.com:8443/a?b=1'));\n\
       return {\n\
         path: url.fileURLToPath('file:///tmp/a b.txt'),\n\
         href: url.pathToFileURL('/tmp/a b.txt').href,\n\
         ascii: url.domainToASCII('bücher.de'),\n\
         unicode: url.domainToUnicode('xn--bcher-kva.de'),\n\
         sameClass: url.URL === URL,\n\
         port: opts.port,\n\
         search: opts.search,\n\
       };",
      &[],
      RunOptions::default(),
    )
    .await;
  let v = ok(&r);
  assert_eq!(v["path"], serde_json::json!("/tmp/a b.txt"), "{v}");
  assert_eq!(v["href"], serde_json::json!("file:///tmp/a%20b.txt"), "{v}");
  assert_eq!(v["ascii"], serde_json::json!("xn--bcher-kva.de"), "{v}");
  assert_eq!(v["unicode"], serde_json::json!("bücher.de"), "{v}");
  assert_eq!(v["sameClass"], serde_json::json!(true), "one URL class per VM: {v}");
  assert_eq!(v["port"], serde_json::json!(8443), "{v}");
  assert_eq!(v["search"], serde_json::json!("?b=1"), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn url_search_params_node_semantics() {
  let rt = plain().await;
  let r = rt
    .eval_script(
      "const fromNull = new URLSearchParams(null).toString();\n\
       const enc = new URLSearchParams('a=1 2&b=%C3%A9');\n\
       const encoded = enc.toString();\n\
       const decoded = enc.get('b');\n\
       const live = new URLSearchParams('a=1&b=2&c=3');\n\
       for (const [k] of live) { live.delete(k); }\n\
       const empty = new URLSearchParams('').size;\n\
       const s = new URLSearchParams('b=2&a=1&a=0'); s.sort();\n\
       return [fromNull, encoded, decoded, live.size, empty, s.toString()];",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&r),
    // Live-iterator deletion skips every other entry (index-based,
    // exactly like Node/WHATWG): a and c deleted, b survives.
    &serde_json::json!(["null=", "a=1+2&b=%C3%A9", "\u{e9}", 1, 0, "a=1&a=0&b=2"]),
    "{:?}",
    r.result
  );
}
