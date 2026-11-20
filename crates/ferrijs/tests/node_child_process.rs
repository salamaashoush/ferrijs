#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `node:child_process` under the `run` grant: the sync forms, the
//! streaming `spawn` and the callback and promise forms over it, with
//! Node's results and error shapes, and refusal of a program the realm
//! was not granted.

use ferrijs::{Permissions, Run, RunOptions, Runtime};
use serde_json::json;

async fn run_with(permissions: Permissions, src: &str) -> Run<serde_json::Value> {
  let rt = Runtime::builder()
    .permissions(permissions)
    .build()
    .await
    .expect("runtime");
  rt.eval_script(src, &[], RunOptions::default()).await
}

async fn run(src: &str) -> serde_json::Value {
  let outcome = run_with(Permissions::none().allow_run(["sh", "cat", "sleep"]), src).await;
  match outcome.result {
    Ok(value) => value,
    Err(error) => panic!("run failed: {error:?}"),
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_program_outside_the_grant_is_refused() {
  let outcome = run_with(
    Permissions::none().allow_run(["cat"]),
    "const { execFileSync } = require('node:child_process');
     try { execFileSync('sh', ['-c', 'echo no']); return 'ran'; }
     catch (e) { return [e.name, e.code]; }",
  )
  .await;
  assert_eq!(
    outcome.result.expect("run"),
    json!(["PermissionDeniedError", "ERR_ACCESS_DENIED"])
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_file_sync_returns_stdout_and_throws_on_failure() {
  let seen = run(
    "const { execFileSync } = require('node:child_process');
     const out = execFileSync('sh', ['-c', 'printf hi'], { encoding: 'utf8' });
     let failure;
     try { execFileSync('sh', ['-c', 'echo bad >&2; exit 3'], { stdio: 'pipe' }); }
     catch (e) { failure = [e.message, e.status, e.stderr.toString()]; }
     const buffer = execFileSync('sh', ['-c', 'printf ab']);
     return { out, failure, isBuffer: Buffer.isBuffer(buffer), text: buffer.toString() };",
  )
  .await;
  assert_eq!(
    seen,
    json!({
      "out": "hi",
      "failure": ["Command failed: sh -c echo bad >&2; exit 3\nbad\n", 3, "bad\n"],
      "isBuffer": true,
      "text": "ab",
    })
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawn_sync_feeds_input_and_reports_status() {
  let seen = run(
    "const { spawnSync } = require('node:child_process');
     const echoed = spawnSync('cat', [], { input: 'piped in', encoding: 'utf8' });
     const env = spawnSync('sh', ['-c', 'printf \"$ONLY:$HOME\"'], { env: { ONLY: 'set' }, encoding: 'utf8' });
     return { echoed: [echoed.stdout, echoed.status, echoed.signal], env: env.stdout };",
  )
  .await;
  assert_eq!(seen, json!({ "echoed": ["piped in", 0, null], "env": "set:" }));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_program_is_enoent() {
  let outcome = run_with(
    Permissions::none().allow_all_run(),
    "const { spawnSync } = require('node:child_process');
     const r = spawnSync('no-such-program-anywhere', ['x']);
     return [r.error.code, r.error.syscall, r.error.path, r.status];",
  )
  .await;
  assert_eq!(
    outcome.result.expect("run"),
    json!([
      "ENOENT",
      "spawnSync no-such-program-anywhere",
      "no-such-program-anywhere",
      null
    ])
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_sync_runs_through_the_shell() {
  let seen = run(
    "const { execSync } = require('node:child_process');
     return execSync('echo $((40 + 2))').toString().trim();",
  )
  .await;
  assert_eq!(seen, json!("42"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_timeout_kills_the_child() {
  let seen = run(
    "const { execFileSync } = require('node:child_process');
     try { execFileSync('sleep', ['5'], { timeout: 50 }); return 'finished'; }
     catch (e) { return [e.code, e.signal]; }",
  )
  .await;
  assert_eq!(seen, json!(["ETIMEDOUT", "SIGTERM"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn spawn_streams_output_and_closes_with_the_exit_code() {
  let seen = run(
    "const { spawn } = require('node:child_process');
     const child = spawn('sh', ['-c', 'echo out; echo err >&2; exit 4']);
     const out = []; const err = []; const order = [];
     child.on('spawn', () => order.push('spawn'));
     child.stdout.on('data', (chunk) => out.push(chunk.toString()));
     child.stderr.on('data', (chunk) => err.push(chunk.toString()));
     child.on('exit', (code) => order.push(`exit ${code}`));
     const [code, signal] = await new Promise((resolve) => child.on('close', (c, s) => resolve([c, s])));
     order.push('close');
     return { pid: typeof child.pid, out: out.join(''), err: err.join(''), code, signal, order };",
  )
  .await;
  assert_eq!(
    seen,
    json!({ "pid": "number", "out": "out\n", "err": "err\n", "code": 4, "signal": null, "order": ["spawn", "exit 4", "close"] })
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawn_writes_stdin_and_kill_sends_a_signal() {
  let seen = run(
    "const { spawn } = require('node:child_process');
     const cat = spawn('cat');
     let echoed = '';
     cat.stdout.on('data', (chunk) => { echoed += chunk; });
     cat.stdin.write('to ');
     cat.stdin.end('cat');
     await new Promise((resolve) => cat.on('close', resolve));
     const sleeper = spawn('sleep', ['5']);
     const killed = sleeper.kill();
     const [code, signal] = await new Promise((resolve) => sleeper.on('close', (c, s) => resolve([c, s])));
     return { echoed, killed, code, signal, flag: sleeper.killed };",
  )
  .await;
  assert_eq!(
    seen,
    json!({ "echoed": "to cat", "killed": true, "code": null, "signal": "SIGTERM", "flag": true })
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_and_exec_file_call_back_and_promisify() {
  let seen = run(
    "const { exec, execFile } = require('node:child_process');
     const { promisify } = require('node:util');
     const viaCallback = await new Promise((resolve) =>
       execFile('sh', ['-c', 'printf back'], (error, stdout) => resolve([error, stdout])));
     const { stdout } = await promisify(exec)('printf promised');
     let failed;
     try { await promisify(execFile)('sh', ['-c', 'exit 2']); } catch (e) { failed = [e.code, e.cmd]; }
     return { viaCallback, stdout, failed };",
  )
  .await;
  assert_eq!(
    seen,
    json!({ "viaCallback": [null, "back"], "stdout": "promised", "failed": [2, "sh -c exit 2"] })
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawn_reports_a_missing_program_as_an_error_event() {
  let outcome = run_with(
    Permissions::none().allow_all_run(),
    "const { spawn } = require('node:child_process');
     const child = spawn('no-such-program-anywhere');
     const error = await new Promise((resolve) => child.on('error', resolve));
     return [error.code, child.pid];",
  )
  .await;
  assert_eq!(outcome.result.expect("run"), json!(["ENOENT", null]));
}

#[tokio::test(flavor = "multi_thread")]
async fn es_module_import_names_the_same_functions() {
  let seen = run(
    "const ns = require('node:child_process');
     return ['exec', 'execFile', 'execFileSync', 'execSync', 'spawn', 'spawnSync', 'ChildProcess']
       .map((name) => typeof ns[name]);",
  )
  .await;
  assert_eq!(
    seen,
    json!([
      "function", "function", "function", "function", "function", "function", "function"
    ])
  );
}
