#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The sandbox-safe `process` global: default-deny `env`, inert
//! identity, neutered `exit`. No browser.

use ferrijs::{ConsoleLevel, Permissions, Run, RunOptions, Runtime};

async fn run(src: &str, permissions: Permissions) -> Run<serde_json::Value> {
  Runtime::builder()
    .permissions(permissions)
    .build()
    .await
    .expect("runtime")
    .eval_script(src, &[], RunOptions::default())
    .await
}

fn val(o: &Run<serde_json::Value>) -> &serde_json::Value {
  match &o.result {
    Ok(value) => value,
    Err(error) => panic!("expected ok, got error: {error:?}"),
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn env_is_empty_by_default_and_inert_identity_is_present() {
  let o = run(
    "return { keys: Object.keys(process.env), os: typeof process.platform, \
       arch: typeof process.arch, ver: process.version, hasNode: 'node' in process.versions };",
    Permissions::none(),
  )
  .await;
  let v = val(&o);
  assert_eq!(v["keys"], serde_json::json!([]), "env default-deny");
  assert_eq!(v["os"], serde_json::json!("string"));
  assert_eq!(v["arch"], serde_json::json!("string"));
  assert!(v["ver"].as_str().unwrap_or("").starts_with('v'), "{v}");
  assert_eq!(
    v["hasNode"],
    serde_json::json!(false),
    "process.versions.node never present"
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn env_exposes_only_the_allow_list_intersected_with_real_env() {
  // Use the ambient PATH (always present) rather than mutating the
  // environment (set_var is `unsafe` in edition 2024 and racy).
  let caps = Permissions::none().allow_env(["PATH", "FERRI_DEFINITELY_ABSENT_VAR_xyz"]);
  let o = run(
    "return { allowed: typeof process.env.PATH, \
       allowedLen: (process.env.PATH ?? '').length > 0, \
       undeclared: process.env.HOME ?? null, \
       missing: process.env.FERRI_DEFINITELY_ABSENT_VAR_xyz ?? null };",
    caps,
  )
  .await;
  let v = val(&o);
  assert_eq!(v["allowed"], serde_json::json!("string"), "declared+present exposed");
  assert_eq!(v["allowedLen"], serde_json::json!(true));
  assert_eq!(v["undeclared"], serde_json::json!(null), "undeclared env not exposed");
  assert_eq!(
    v["missing"],
    serde_json::json!(null),
    "declared-but-absent not invented"
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_is_neutered() {
  let o = run(
    "try { process.exit(2); return 'no throw'; } catch (e) { return String(e); }",
    Permissions::none(),
  )
  .await;
  assert!(
    val(&o)
      .as_str()
      .unwrap_or("")
      .contains("process.exit(2) is not available"),
    "{:?}",
    val(&o)
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn env_object_is_frozen() {
  let o = run(
    "try { process.env.X = 'y'; } catch {} return process.env.X ?? 'still-unset';",
    Permissions::none(),
  )
  .await;
  assert_eq!(val(&o), &serde_json::json!("still-unset"), "env is frozen");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdout_stderr_write_route_into_console_capture() {
  let r = run(
    "const a = process.stdout.write('hello\\n'); \
     const b = process.stderr.write('boom'); \
     return { a, b, tty: process.stdout.isTTY };",
    Permissions::none(),
  )
  .await;
  let v = val(&r);
  assert_eq!(v["a"], serde_json::json!(true), "write returns true");
  assert_eq!(v["b"], serde_json::json!(true));
  assert_eq!(v["tty"], serde_json::json!(false), "not a TTY");
  let logged: Vec<_> = r.console.iter().map(|e| (&e.level, e.message.as_str())).collect();
  assert!(
    logged
      .iter()
      .any(|(l, m)| matches!(l, ConsoleLevel::Log) && *m == "hello"),
    "stdout.write -> console Log, trailing newline trimmed: {logged:?}"
  );
  assert!(
    logged
      .iter()
      .any(|(l, m)| matches!(l, ConsoleLevel::Error) && *m == "boom"),
    "stderr.write -> console Error: {logged:?}"
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn hrtime_bigint_and_diff() {
  let o = run(
    "const t0 = process.hrtime(); \
     for (let i = 0; i < 50000; i++) {} \
     const d = process.hrtime(t0); \
     const b0 = process.hrtime.bigint(); const b1 = process.hrtime.bigint(); \
     return { tuple: Array.isArray(t0) && t0.length === 2, \
       diffOk: d[0] >= 0 && d[1] >= 0, \
       bigintType: typeof process.hrtime.bigint(), \
       monotonic: b1 >= b0 };",
    Permissions::none(),
  )
  .await;
  let v = val(&o);
  assert_eq!(v["tuple"], serde_json::json!(true), "hrtime() -> [s, ns]");
  assert_eq!(v["diffOk"], serde_json::json!(true), "hrtime(prev) non-negative diff");
  assert_eq!(
    v["bigintType"],
    serde_json::json!("bigint"),
    "hrtime.bigint() -> BigInt"
  );
  assert_eq!(v["monotonic"], serde_json::json!(true), "bigint clock monotonic");
}

#[tokio::test(flavor = "multi_thread")]
async fn next_tick_runs_as_a_fifo_microtask() {
  // Documented behaviour: process.nextTick is a microtask (FIFO via
  // queueMicrotask), NOT Node's separate higher-priority queue. Order
  // therefore follows scheduling order.
  let o = run(
    "const order = []; \
     process.nextTick(() => order.push('nexttick')); \
     Promise.resolve().then(() => order.push('promise')); \
     await Promise.resolve(); await Promise.resolve(); \
     return order;",
    Permissions::none(),
  )
  .await;
  assert_eq!(
    val(&o),
    &serde_json::json!(["nexttick", "promise"]),
    "nextTick scheduled first runs first (FIFO microtask)"
  );
}
