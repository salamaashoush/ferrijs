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
async fn a_narrowed_scope_follows_a_timer_callback() {
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_env(["A", "B"]).allow_all_sys())
    .build()
    .await
    .expect("runtime");
  // A host dispatch narrows the realm to `sys: hostname` only, arms a
  // timer inside it, and the timer must still be narrowed when it
  // fires after the dispatch has restored the wider policy.
  let container = Arc::clone(rt.permissions());
  let narrow = container.narrow(&Permissions::none().allow_sys([ferrijs::SysInfo::Hostname]));
  let run = rt
    .run(
      RunOptions::default(),
      Box::new(move |ctx| {
        Box::pin(async move {
          let container = ferrijs::std::permissions::container(&ctx).expect("container");
          let armed: rquickjs::Promise<'_> = container.enter(Some(narrow), || {
            ctx.eval(
              r"
              new Promise((resolve) => setTimeout(() => {
                const os = require('node:os');
                const out = {};
                try { os.hostname(); out.hostname = 'ok'; } catch (e) { out.hostname = e.code; }
                try { os.cpus(); out.cpus = 'ok'; } catch (e) { out.cpus = e.code; }
                resolve(out);
              }, 5))
              ",
            )
          })?;
          let value: rquickjs::Value<'_> = armed
            .into_future()
            .await
            .map_err(|e| ferrijs::ScriptError::from_caught(&ctx, rquickjs::CaughtError::from_error(&ctx, e), ""))?;
          Ok(ferrijs::value::value_to_json(&ctx, value).unwrap_or_default())
        })
      }),
    )
    .await;
  assert_eq!(
    ok(&run),
    &serde_json::json!({ "hostname": "ok", "cpus": "ERR_ACCESS_DENIED" })
  );
  // Back outside the dispatch, the realm's own policy is in force.
  let after = rt
    .eval_script(
      "const os = require('os'); os.cpus(); return 'ok'",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&after), &serde_json::json!("ok"));
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
