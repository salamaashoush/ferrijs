#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The runtime end to end: a realm is built, scripts run under its
//! bracket, the sandbox refuses what was not granted, and a run that
//! must not continue poisons the realm.

use std::sync::Arc;
use std::time::Duration;

use ferrijs::{Limits, ModulePolicy, Permissions, RealmOptions, RunOptions, Runtime, ScriptErrorKind};

async fn plain() -> Runtime {
  Runtime::builder().build().await.expect("runtime")
}

fn ok(run: &ferrijs::Run<serde_json::Value>) -> &serde_json::Value {
  match &run.result {
    Ok(v) => v,
    Err(e) => panic!("run failed: {e}\n{:?}\nconsole: {:?}", e.stack, run.console),
  }
}

#[tokio::test]
async fn a_script_returns_its_value_and_sees_args() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      "return { sum: args[0] + args[1], name: args[2].name }",
      &[1.into(), 2.into(), serde_json::json!({ "name": "x" })],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&run), &serde_json::json!({ "sum": 3, "name": "x" }));
  assert!(!run.poisoned);
}

#[tokio::test]
async fn global_state_survives_between_runs() {
  let rt = plain().await;
  let first = rt
    .eval_script(
      "globalThis.counter = 1; let local = 'gone';",
      &[],
      RunOptions::default(),
    )
    .await;
  ok(&first);
  let second = rt
    .eval_script("return [globalThis.counter, typeof local]", &[], RunOptions::default())
    .await;
  assert_eq!(ok(&second), &serde_json::json!([1, "undefined"]));
}

#[tokio::test]
async fn console_is_captured_per_run() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      "console.log('a', 1, { b: 2 }); console.warn('w'); return 0",
      &[],
      RunOptions::default(),
    )
    .await;
  ok(&run);
  let messages: Vec<(ferrijs::ConsoleLevel, String)> =
    run.console.iter().map(|e| (e.level, e.message.clone())).collect();
  assert_eq!(
    messages,
    vec![
      (ferrijs::ConsoleLevel::Log, "a 1 { b: 2 }".to_string()),
      (ferrijs::ConsoleLevel::Warn, "w".to_string()),
    ]
  );
  let next = rt.eval_script("return 1", &[], RunOptions::default()).await;
  assert!(next.console.is_empty());
}

#[tokio::test]
async fn a_throw_is_reported_with_position_and_does_not_poison() {
  let rt = plain().await;
  let run = rt
    .eval_script("const x = 1;\nthrow new TypeError('boom');", &[], RunOptions::default())
    .await;
  let err = run.err().expect("error");
  assert_eq!(err.kind, ScriptErrorKind::Runtime);
  assert_eq!(err.name.as_deref(), Some("TypeError"));
  assert_eq!(err.message, "boom");
  assert_eq!(err.line, Some(2));
  assert!(
    err
      .source_snippet
      .as_deref()
      .is_some_and(|s| s.contains(">>>    2: throw")),
    "{:?}",
    err.source_snippet
  );
  assert!(!run.poisoned);
  assert!(!rt.poisoned());
  let again = rt.eval_script("return 2", &[], RunOptions::default()).await;
  assert_eq!(ok(&again), &serde_json::json!(2));
}

#[tokio::test]
async fn a_syntax_error_is_classified() {
  let rt = plain().await;
  let run = rt.eval_script("return {", &[], RunOptions::default()).await;
  assert_eq!(run.err().expect("error").kind, ScriptErrorKind::Syntax);
}

#[tokio::test]
async fn a_busy_loop_is_halted_and_poisons_the_realm() {
  let rt = Runtime::builder()
    .limits(Limits {
      timeout: Duration::from_millis(100),
      backstop_grace: Duration::from_millis(500),
      ..Limits::default()
    })
    .build()
    .await
    .expect("runtime");
  let run = rt.eval_script("while (true) {}", &[], RunOptions::default()).await;
  let err = run.err().expect("error");
  assert_eq!(err.kind, ScriptErrorKind::Timeout);
  assert!(run.poisoned);
  assert!(rt.poisoned());
  let refused = rt.eval_script("return 1", &[], RunOptions::default()).await;
  assert!(refused.poisoned);
  assert!(refused.err().is_some());
}

#[tokio::test]
async fn a_parked_await_is_freed_by_the_backstop() {
  let rt = Runtime::builder()
    .limits(Limits {
      timeout: Duration::from_millis(50),
      backstop_grace: Duration::from_millis(100),
      ..Limits::default()
    })
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script("await new Promise(() => {}); return 1", &[], RunOptions::default())
    .await;
  assert_eq!(run.err().expect("error").kind, ScriptErrorKind::Timeout);
  assert!(run.poisoned);
}

/// A host that gives each unit of work its own realm can read a
/// backstop fire as that unit's timeout instead of the realm's death,
/// and keep running. The caveat this trades for is stated on the flag:
/// a continuation that resumes later has no budget armed against it.
#[tokio::test]
async fn a_backstop_that_does_not_poison_leaves_the_realm_usable() {
  let rt = Runtime::builder()
    .limits(Limits {
      timeout: Duration::from_millis(50),
      backstop_grace: Duration::from_millis(100),
      backstop_poisons: false,
      ..Limits::default()
    })
    .build()
    .await
    .expect("runtime");

  let timed_out = rt
    .eval_script("await new Promise(() => {}); return 1", &[], RunOptions::default())
    .await;
  assert_eq!(timed_out.err().expect("error").kind, ScriptErrorKind::Timeout);
  assert!(!timed_out.poisoned);
  assert!(!rt.poisoned(), "the realm still takes work");

  let after = rt.eval_script("return 41 + 1", &[], RunOptions::default()).await;
  assert_eq!(ok(&after), &serde_json::json!(42));
}

#[tokio::test]
async fn the_memory_limit_poisons_on_exhaustion() {
  let rt = Runtime::builder()
    .limits(Limits {
      memory: 4 * 1024 * 1024,
      ..Limits::default()
    })
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      "const a = []; for (let i = 0; i < 1e7; i++) a.push('x'.repeat(1024)); return a.length",
      &[],
      RunOptions::default(),
    )
    .await;
  let err = run.err().expect("error");
  assert_eq!(err.kind, ScriptErrorKind::MemoryLimit, "{err}");
  assert!(run.poisoned);
}

#[tokio::test]
async fn timers_and_microtasks_work() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      r"
      const order = [];
      await new Promise((resolve) => {
        setTimeout(() => { order.push('timeout'); resolve(); }, 10);
        queueMicrotask(() => order.push('micro'));
        setImmediate(() => order.push('immediate'));
        order.push('sync');
      });
      const t = setInterval(() => {}, 5);
      clearInterval(t);
      return order;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&run), &serde_json::json!(["sync", "micro", "immediate", "timeout"]));
}

#[tokio::test]
async fn web_globals_and_node_modules_are_served() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      r"
      const path = require('node:path');
      const { Buffer } = require('buffer');
      const u = new URL('https://example.com/a?b=1');
      const enc = new TextEncoder().encode('hi');
      const hash = await crypto.subtle.digest('SHA-256', enc);
      return {
        joined: path.join('a', 'b'),
        b64: Buffer.from('hi').toString('base64'),
        host: u.host,
        q: u.searchParams.get('b'),
        hashLen: hash.byteLength,
        ab: atob(btoa('x')),
        clone: structuredClone({ a: [1] }),
        hasFetch: typeof fetch,
        hasHeaders: typeof Headers,
        version: process.version.startsWith('v'),
        release: process.release.name,
        ua: navigator.userAgent.startsWith('ferrijs/'),
      };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&run),
    &serde_json::json!({
      "joined": "a/b", "b64": "aGk=", "host": "example.com", "q": "1", "hashLen": 32,
      "ab": "x", "clone": { "a": [1] }, "hasFetch": "function", "hasHeaders": "function", "version": true,
      "release": "ferrijs", "ua": true,
    })
  );
}

#[tokio::test]
async fn es_modules_import_native_and_relative_modules() {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(dir.path().join("helper.mjs"), "export const double = (x) => x * 2;").expect("write");
  let rt = Runtime::builder()
    .modules(ModulePolicy::new(dir.path()))
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_module_source(
      "entry.mjs",
      r"
      import { double } from './helper.mjs';
      import path from 'node:path';
      import { EventEmitter } from 'events';
      const e = new EventEmitter();
      let seen = 0;
      e.on('x', (v) => { seen = v; });
      e.emit('x', 21);
      export default { d: double(seen), base: path.basename('/a/b.txt') };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&run), &serde_json::json!({ "d": 42, "base": "b.txt" }));
}

#[tokio::test]
async fn a_jailed_module_root_refuses_an_escape() {
  let dir = tempfile::tempdir().expect("tempdir");
  let inside = dir.path().join("inside");
  std::fs::create_dir_all(&inside).expect("mkdir");
  std::fs::write(dir.path().join("outside.mjs"), "export const x = 1;").expect("write");
  let rt = Runtime::builder()
    .modules(ModulePolicy::new(&inside).jailed())
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_module_source(
      "entry.mjs",
      "import { x } from '../outside.mjs'; export default x;",
      &[],
      RunOptions::default(),
    )
    .await;
  let err = run.err().expect("error");
  assert!(err.message.contains("outside the module root"), "{err}");
}

#[tokio::test]
async fn the_sandbox_denies_what_was_not_granted() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      r"
      const fs = require('node:fs');
      const os = require('node:os');
      const out = {};
      try { fs.readFileSync('/etc/hosts'); out.read = 'allowed'; } catch (e) { out.read = [e.name, e.code, e.permission]; }
      try { fs.writeFileSync('/tmp/ferrijs-denied', 'x'); out.write = 'allowed'; } catch (e) { out.write = [e.name, e.code, e.permission]; }
      try { os.hostname(); out.sys = 'allowed'; } catch (e) { out.sys = [e.name, e.code, e.permission]; }
      out.env = Object.keys(process.env).length;
      return out;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  let denied = serde_json::json!(["PermissionDeniedError", "ERR_ACCESS_DENIED", "read"]);
  let value = ok(&run);
  assert_eq!(value["read"], denied);
  assert_eq!(
    value["write"],
    serde_json::json!(["PermissionDeniedError", "ERR_ACCESS_DENIED", "write"])
  );
  assert_eq!(
    value["sys"],
    serde_json::json!(["PermissionDeniedError", "ERR_ACCESS_DENIED", "sys"])
  );
  assert_eq!(value["env"], 0);
}

#[tokio::test]
async fn a_read_grant_covers_its_root_and_nothing_else() {
  let dir = tempfile::tempdir().expect("tempdir");
  let root = dir.path().join("data");
  std::fs::create_dir_all(&root).expect("mkdir");
  std::fs::write(root.join("in.txt"), b"inside").expect("write");
  std::fs::write(dir.path().join("out.txt"), b"outside").expect("write");
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([&root]).allow_env(["PATH"]))
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      const fs = require('node:fs');
      const inside = fs.readFileSync(args[0], 'utf8');
      let outside;
      try { outside = fs.readFileSync(args[1], 'utf8'); } catch (e) { outside = e.code; }
      const listed = (await fs.promises.readdir(args[2])).length;
      return { inside, outside, listed, env: Object.keys(process.env) };
      ",
      &[
        root.join("in.txt").to_string_lossy().into_owned().into(),
        dir.path().join("out.txt").to_string_lossy().into_owned().into(),
        root.to_string_lossy().into_owned().into(),
      ],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&run),
    &serde_json::json!({ "inside": "inside", "outside": "ERR_ACCESS_DENIED", "listed": 1, "env": ["PATH"] })
  );
}

#[tokio::test]
async fn a_realm_only_narrows_and_scripts_can_query_and_drop() {
  let rt = Runtime::builder()
    .permissions(
      Permissions::none()
        .allow_env(["A", "B"])
        .allow_all_sys()
        .deny_sys([ferrijs::SysInfo::Username]),
    )
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      const os = require('node:os');
      const before = {
        envA: process.permission.has('env', 'A'),
        envAll: process.permission.has('env'),
        sysAll: process.permission.has('sys'),
        hostname: process.permission.has('sys', 'hostname'),
        username: process.permission.has('sys', 'username'),
      };
      let userInfo;
      try { os.userInfo(); userInfo = 'ok'; } catch (e) { userInfo = e.permission; }
      process.permission.drop('sys', 'hostname');
      let hostname;
      try { os.hostname(); hostname = 'ok'; } catch (e) { hostname = e.code; }
      process.permission.drop('env');
      const after = { envA: process.permission.has('env', 'A'), cpus: process.permission.has('sys', 'cpus') };
      let bad;
      try { process.permission.has('nope'); } catch (e) { bad = e.name; }
      return { before, userInfo, hostname, after, bad };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&run),
    &serde_json::json!({
      "before": { "envA": true, "envAll": false, "sysAll": false, "hostname": true, "username": false },
      "userInfo": "sys",
      "hostname": "ERR_ACCESS_DENIED",
      "after": { "envA": false, "cpus": true },
      "bad": "TypeError",
    })
  );
  // A drop is for the realm's life: the next run sees it too, and the
  // host's own handle agrees.
  let next = rt
    .eval_script(
      "return process.permission.has('sys', 'hostname')",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&next), &serde_json::json!(false));
  assert_eq!(
    rt.permissions().has(ferrijs::permissions::Kind::Env, Some("A")),
    Ok(false)
  );
  // The host can narrow from outside as well; a wider policy changes nothing.
  rt.permissions()
    .revoke(&Permissions::all().deny_sys([ferrijs::SysInfo::Cpus]));
  rt.permissions().revoke(&Permissions::all());
  let cpus = rt
    .eval_script(
      "const os = require('os'); try { os.cpus(); return 'ok' } catch (e) { return e.code }",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&cpus), &serde_json::json!("ERR_ACCESS_DENIED"));
}

#[tokio::test]
async fn a_timer_fires_under_the_realm_container() {
  // There is one container per realm; a drop made while a timer is
  // pending binds the callback too, because it is the same container.
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_all_sys())
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      const os = require('node:os');
      const armed = new Promise((resolve) => setTimeout(() => {
        try { os.hostname(); resolve('ok'); } catch (e) { resolve(e.code); }
      }, 5));
      process.permission.drop('sys');
      return await armed;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&run), &serde_json::json!("ERR_ACCESS_DENIED"));
}

#[tokio::test]
async fn an_unserved_builtin_is_absent_not_refusing() {
  let rt = Runtime::builder()
    .permissions(Permissions::all())
    .modules(ModulePolicy::default().builtins(["path", "buffer"]))
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      const out = { path: typeof require('node:path').join, buffer: typeof require('buffer').Buffer };
      try { require('node:fs'); out.fs = 'served'; } catch (e) { out.fs = e.message.includes('not available'); }
      try { require('os'); out.os = 'served'; } catch (e) { out.os = e.message.includes('not available'); }
      return out;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&run),
    &serde_json::json!({ "path": "function", "buffer": "function", "fs": true, "os": true })
  );
  let module = rt
    .eval_module_source(
      "m.mjs",
      "import fs from 'node:fs'; export default typeof fs;",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(
    module.err().is_some(),
    "an import of an unserved builtin must not resolve"
  );
  let none = Runtime::builder()
    .modules(ModulePolicy::default().no_builtins().no_files())
    .build()
    .await
    .expect("runtime");
  let refused = none
    .eval_script(
      "try { require('path'); return 'served' } catch (e) { return 'absent' }",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&refused), &serde_json::json!("absent"));
}

#[tokio::test]
async fn clocks_can_be_coarsened() {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(dir.path().join("f"), b"x").expect("write");
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]))
    .realm(RealmOptions {
      clock_resolution: Some(Duration::from_millis(100)),
      ..RealmOptions::default()
    })
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      const samples = [];
      for (let i = 0; i < 5; i++) samples.push(Date.now() % 100, new Date().getTime() % 100, performance.now() % 100);
      const [s, n] = process.hrtime();
      const big = process.hrtime.bigint();
      const fs = require('node:fs');
      const stats = fs.statSync(args[0]);
      return {
        samples,
        hrNs: n % 100000000,
        bigNs: Number(big % 100000000n),
        isDate: stats.mtime instanceof Date,
        ctor: stats.mtime.constructor === Date,
        name: Date.name,
        parse: Date.parse('2020-01-01T00:00:00Z'),
        typed: new Date(0).getTime(),
      };
      ",
      &[dir.path().join("f").to_string_lossy().into_owned().into()],
      RunOptions::default(),
    )
    .await;
  let value = ok(&run);
  assert!(value["samples"].as_array().unwrap().iter().all(|v| v == 0), "{value}");
  assert_eq!(value["hrNs"], 0);
  assert_eq!(value["bigNs"], 0);
  assert_eq!(value["isDate"], true);
  assert_eq!(value["ctor"], true);
  assert_eq!(value["name"], "Date");
  assert_eq!(value["parse"], 1_577_836_800_000_i64);
  assert_eq!(value["typed"], 0);
}

#[tokio::test]
async fn eval_can_be_switched_off() {
  let rt = Runtime::builder()
    .realm(RealmOptions {
      eval: false,
      ..RealmOptions::default()
    })
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      const attempts = {};
      const tryIt = (name, f) => { try { f(); attempts[name] = 'ran'; } catch (e) { attempts[name] = e.name; } };
      tryIt('eval', () => eval('1'));
      tryIt('indirect', () => (0, eval)('1'));
      tryIt('Function', () => new Function('return 1'));
      tryIt('proto', () => (function () {}).constructor('return 1'));
      tryIt('async', () => (async function () {}).constructor('return 1'));
      tryIt('gen', () => (function* () {}).constructor('return 1'));
      tryIt('asyncGen', () => (async function* () {}).constructor('return 1'));
      tryIt('reflect', () => Reflect.construct(Function, ['return 1']));
      return attempts;
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  let value = ok(&run);
  for key in [
    "eval", "indirect", "Function", "proto", "async", "gen", "asyncGen", "reflect",
  ] {
    assert_eq!(value[key], "EvalError", "{key}");
  }
}

#[tokio::test]
async fn frozen_intrinsics_resist_prototype_pollution() {
  let rt = Runtime::builder()
    .realm(RealmOptions {
      freeze_intrinsics: true,
      remove_globals: vec!["WeakRef".to_string()],
      ..RealmOptions::default()
    })
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      r"
      let polluted;
      try { Object.prototype.polluted = 1; polluted = 'ran'; } catch (e) { polluted = e.name; }
      let arr;
      try { Array.prototype.push = () => 0; arr = 'ran'; } catch (e) { arr = e.name; }
      return { polluted, arr, weakRef: typeof WeakRef, own: 'polluted' in {} };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(&run),
    &serde_json::json!({ "polluted": "TypeError", "arr": "TypeError", "weakRef": "undefined", "own": false })
  );
}

#[tokio::test]
async fn secrets_are_redacted_from_console_values_and_errors() {
  let rt = Runtime::builder()
    .redactor(Arc::new(ferrijs::Secrets::new([(
      "token".to_string(),
      "hunter2".to_string(),
    )])))
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      "console.log('t=hunter2'); return { k: 'hunter2' }",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.console[0].message, "t=<secret>token</secret>");
  assert_eq!(ok(&run), &serde_json::json!({ "k": "<secret>token</secret>" }));
  let failed = rt
    .eval_script("throw new Error('bad hunter2')", &[], RunOptions::default())
    .await;
  assert_eq!(failed.err().expect("error").message, "bad <secret>token</secret>");
}

#[tokio::test]
async fn an_extension_adds_a_module_and_a_global() {
  struct Acme;
  struct AcmeModule;
  impl rquickjs::module::ModuleDef for AcmeModule {
    fn declare(decl: &rquickjs::module::Declarations<'_>) -> rquickjs::Result<()> {
      decl.declare("answer")?;
      decl.declare("default")?;
      Ok(())
    }
    fn evaluate<'js>(ctx: &rquickjs::Ctx<'js>, exports: &rquickjs::module::Exports<'js>) -> rquickjs::Result<()> {
      let ns = acme_namespace(ctx)?;
      exports.export("answer", ns.get::<_, rquickjs::Value<'js>>("answer")?)?;
      exports.export("default", ns)?;
      Ok(())
    }
  }
  fn acme_namespace<'js>(ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Object<'js>> {
    let ns = rquickjs::Object::new(ctx.clone())?;
    ns.set("answer", 42)?;
    Ok(ns)
  }
  impl ferrijs::Extension for Acme {
    fn name(&self) -> &'static str {
      "acme"
    }
    fn modules(&self, registry: &mut ferrijs::ModuleRegistry) -> Result<(), String> {
      registry.register(ferrijs::NativeModule::new::<AcmeModule, _>(
        ["acme", "@acme/core"],
        acme_namespace,
      ))
    }
    fn install(&self, ctx: &rquickjs::Ctx<'_>) -> rquickjs::Result<()> {
      ctx.globals().set("acmeGlobal", "here")
    }
  }
  let rt = Runtime::builder().extension(Acme).build().await.expect("runtime");
  let script = rt
    .eval_script(
      "const a = require('acme'); const b = require('@acme/core'); return [a.answer, b.answer, acmeGlobal]",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&script), &serde_json::json!([42, 42, "here"]));
  let module = rt
    .eval_module_source(
      "m.mjs",
      "import acme, { answer } from '@acme/core'; export default [answer, acme.answer];",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&module), &serde_json::json!([42, 42]));
}

#[tokio::test]
async fn require_refuses_what_is_not_native() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      "try { require('lodash'); return 'ran' } catch (e) { return e.message }",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(
    ok(&run)
      .as_str()
      .is_some_and(|m| m.contains("require('lodash') is not available"))
  );
}

#[tokio::test]
async fn process_exit_does_not_kill_the_host() {
  let rt = plain().await;
  let run = rt
    .eval_script(
      "try { process.exit(3) } catch (e) { return e.message }",
      &[],
      RunOptions::default(),
    )
    .await;
  assert!(
    ok(&run)
      .as_str()
      .is_some_and(|m| m.contains("process.exit(3) is not available"))
  );
}

/// A configured sink keeps receiving across runs. The realm reuses its
/// own capture rather than installing a fresh console per run, so this
/// is the test that says the reuse did not cost a message.
#[tokio::test]
async fn a_console_sink_receives_every_run() {
  #[derive(Debug, Default)]
  struct Collect(std::sync::Mutex<Vec<String>>);

  impl ferrijs::ConsoleSink for Collect {
    fn emit(&self, entry: &ferrijs::ConsoleEntry) {
      self
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(entry.message.clone());
    }
  }

  let sink = Arc::new(Collect::default());
  let rt = Runtime::builder()
    .console(ferrijs::ConsoleOptions {
      sink: Some(Arc::clone(&sink) as Arc<dyn ferrijs::ConsoleSink>),
      ..ferrijs::ConsoleOptions::default()
    })
    .build()
    .await
    .expect("runtime");

  for n in 0..3 {
    let run = rt
      .eval_script(&format!("console.log('run {n}'); return 1"), &[], RunOptions::default())
      .await;
    ok(&run);
    // Streaming means the buffered form stays empty, which is what
    // `ConsoleOptions::sink` promises.
    assert!(run.console.is_empty(), "a streamed run buffers nothing");
  }

  let seen = sink.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(seen, vec!["run 0", "run 1", "run 2"]);
}

#[tokio::test]
async fn a_repeated_script_is_reused_without_changing_what_it_sees() {
  let rt = plain().await;
  // Same source three times: the second and third run the compiled
  // arrow the first left behind. Each must still get its own bindings
  // and the realm's current globals, which is what recompiling gave.
  for expected in 1..=3 {
    let run = rt
      .eval_script(
        "globalThis.n = (globalThis.n ?? 0) + 1; let local = 'fresh'; return [globalThis.n, local]",
        &[],
        RunOptions::default(),
      )
      .await;
    assert_eq!(ok(&run), &serde_json::json!([expected, "fresh"]));
  }
  // Args are rebound per run, not baked into the cached function.
  for i in 0..3 {
    let run = rt
      .eval_script("return args[0] * 2", &[serde_json::json!(i)], RunOptions::default())
      .await;
    assert_eq!(ok(&run), &serde_json::json!(i * 2));
  }
  // A different source is a different entry, not a stale hit.
  let other = rt.eval_script("return 'other'", &[], RunOptions::default()).await;
  assert_eq!(ok(&other), &serde_json::json!("other"));
}

#[tokio::test]
async fn a_syntax_error_is_not_cached_and_reports_every_time() {
  let rt = plain().await;
  for _ in 0..3 {
    let run = rt.eval_script("return (", &[], RunOptions::default()).await;
    let err = run.err().expect("syntax error");
    assert_eq!(err.kind, ScriptErrorKind::Syntax);
  }
  // The realm still works afterwards.
  let ok_run = rt.eval_script("return 42", &[], RunOptions::default()).await;
  assert_eq!(ok(&ok_run), &serde_json::json!(42));
}

#[tokio::test]
async fn the_script_cache_can_be_turned_off() {
  let rt = Runtime::builder().script_cache(0).build().await.expect("runtime");
  for expected in 1..=3 {
    let run = rt
      .eval_script(
        "globalThis.m = (globalThis.m ?? 0) + 1; return globalThis.m",
        &[],
        RunOptions::default(),
      )
      .await;
    assert_eq!(ok(&run), &serde_json::json!(expected));
  }
}

#[tokio::test]
async fn the_script_cache_stays_within_its_bound() {
  // Two slots, four distinct scripts: the table is emptied rather than
  // grown, and every script still answers correctly.
  let rt = Runtime::builder().script_cache(2).build().await.expect("runtime");
  for round in 0..3 {
    for i in 0..4 {
      let run = rt
        .eval_script(&format!("return {i} + 100"), &[], RunOptions::default())
        .await;
      assert_eq!(ok(&run), &serde_json::json!(i + 100), "round {round}, script {i}");
    }
  }
}
