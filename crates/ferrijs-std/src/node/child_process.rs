//! `node:child_process`.
//!
//! Two native primitives carry it: `spawnSync`, which runs a program to
//! completion on the calling thread, and `spawn`, which starts one and
//! reports its output and exit to a callback as they happen. Node's API
//! (`ChildProcess`, `exec`, `execFile`, the sync forms and their errors)
//! is written over them in `child_process.js`.
//!
//! Every start asks the realm's `run` grant for the program it will
//! execute (the shell, when `shell` is set), as Deno's `--allow-run`
//! does. A child runs outside the sandbox with the host's authority; the
//! grant is the whole of the control.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rquickjs::function::Opt;
use rquickjs::module::{Declarations, Exports, ModuleDef};
use rquickjs::{Array, Ctx, Function, JsLifetime, Object, Result, TypedArray, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::bundled::Bundled;

static CHILD_PROCESS: Bundled = Bundled::new("ferrijs:child_process", include_str!("child_process.js"));

pub(crate) const EXPORTS: &[&str] = &[
  "ChildProcess",
  "exec",
  "execFile",
  "execFileSync",
  "execSync",
  "spawn",
  "spawnSync",
];

#[derive(JsLifetime)]
struct Instance<'js>(Object<'js>);

/// `require('child_process')`: one instance per realm.
pub(crate) fn namespace<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  if let Some(instance) = ctx.userdata::<Instance<'js>>() {
    return Ok(instance.0.clone());
  }
  let factory: Function<'js> = CHILD_PROCESS.evaluate(ctx)?.get()?;
  let native = Object::new(ctx.clone())?;
  native.set("spawnSync", Function::new(ctx.clone(), spawn_sync)?)?;
  native.set("spawn", Function::new(ctx.clone(), spawn)?)?;
  let deps = Object::new(ctx.clone())?;
  deps.set("events", crate::modules::events_namespace(ctx)?)?;
  deps.set("stream", crate::node::stream::stream_namespace(ctx)?)?;
  deps.set("process", crate::node::process::process_object(ctx)?)?;
  crate::lazy::ensure(ctx, "Buffer")?;
  deps.set("Buffer", ctx.globals().get::<_, Value<'js>>("Buffer")?)?;
  let exports: Object<'js> = factory.call((native, deps))?;
  ctx
    .store_userdata(Instance(exports.clone()))
    .map_err(|_| rquickjs::Exception::throw_internal(ctx, "node:child_process loaded twice"))?;
  Ok(exports)
}

pub struct ChildProcessModule;

impl ModuleDef for ChildProcessModule {
  fn declare(declare: &Declarations<'_>) -> Result<()> {
    declare.declare("default")?;
    for name in EXPORTS {
      declare.declare(*name)?;
    }
    Ok(())
  }

  fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> Result<()> {
    let namespace = namespace(ctx)?;
    for name in EXPORTS {
      exports.export(*name, namespace.get::<_, Value<'js>>(*name)?)?;
    }
    exports.export("default", namespace)?;
    Ok(())
  }
}

/// What `child_process.js` hands the primitives, already defaulted.
struct Spec {
  file: String,
  args: Vec<String>,
  cwd: Option<String>,
  env: Option<Vec<(String, String)>>,
  stdio: [String; 3],
  argv0: Option<String>,
  /// Node's `windowsVerbatimArguments`: the arguments go onto the command
  /// line as written, which `cmd.exe` needs to parse a shell command.
  #[cfg(windows)]
  windows_verbatim: bool,
}

impl Spec {
  fn read<'js>(file: String, args: Array<'js>, options: &Object<'js>) -> Result<Self> {
    let args = args.iter::<String>().collect::<Result<Vec<_>>>()?;
    let env = match options.get::<_, Option<Array<'js>>>("env")? {
      Some(pairs) => Some(
        pairs
          .iter::<Array<'js>>()
          .map(|pair| {
            let pair = pair?;
            Ok((pair.get::<String>(0)?, pair.get::<String>(1)?))
          })
          .collect::<Result<Vec<_>>>()?,
      ),
      None => None,
    };
    let stdio: Array<'js> = options.get("stdio")?;
    Ok(Self {
      file,
      args,
      cwd: options.get("cwd")?,
      env,
      stdio: [stdio.get(0)?, stdio.get(1)?, stdio.get(2)?],
      argv0: options.get("argv0")?,
      #[cfg(windows)]
      windows_verbatim: options.get::<_, Option<bool>>("windowsVerbatimArguments")?.unwrap_or(false),
    })
  }

  fn command(&self) -> Command {
    let mut command = Command::new(&self.file);
    #[cfg(windows)]
    if self.windows_verbatim {
      for arg in &self.args {
        std::os::windows::process::CommandExt::raw_arg(&mut command, arg);
      }
    } else {
      command.args(&self.args);
    }
    #[cfg(not(windows))]
    command.args(&self.args);
    #[cfg(unix)]
    if let Some(argv0) = &self.argv0 {
      std::os::unix::process::CommandExt::arg0(&mut command, argv0);
    }
    if let Some(cwd) = &self.cwd {
      command.current_dir(cwd);
    }
    if let Some(env) = &self.env {
      command.env_clear();
      command.envs(env.iter().map(|(k, v)| (k, v)));
    }
    command.stdin(stdio(&self.stdio[0]));
    command.stdout(stdio(&self.stdio[1]));
    command.stderr(stdio(&self.stdio[2]));
    command
  }
}

fn stdio(mode: &str) -> Stdio {
  match mode {
    "inherit" => Stdio::inherit(),
    "ignore" => Stdio::null(),
    _ => Stdio::piped(),
  }
}

/// Node's `SystemError` fields for a spawn that never started.
fn spawn_error<'js>(ctx: &Ctx<'js>, error: &std::io::Error, spec: &Spec, syscall: &str) -> Result<Object<'js>> {
  let code = match error.kind() {
    std::io::ErrorKind::NotFound => "ENOENT",
    std::io::ErrorKind::PermissionDenied => "EACCES",
    _ => "EIO",
  };
  let object = Object::new(ctx.clone())?;
  object.set("code", code)?;
  object.set("errno", error.raw_os_error().map_or(-1, |n| -n))?;
  object.set("syscall", format!("{syscall} {}", spec.file))?;
  object.set("path", spec.file.as_str())?;
  object.set("message", format!("{syscall} {} {code}", spec.file))?;
  Ok(object)
}

#[cfg(unix)]
fn signal_name(status: ExitStatus) -> Option<&'static str> {
  use std::os::unix::process::ExitStatusExt;
  status.signal().map(signal_to_name)
}

/// Outside Unix a process ends with a code, never a signal.
#[cfg(not(unix))]
fn signal_name(_status: ExitStatus) -> Option<&'static str> {
  None
}

/// Outside Unix there are no signals to send: every kill terminates.
#[cfg(not(unix))]
fn signal_number(_signal: Option<&Value<'_>>) -> i32 {
  9
}

#[cfg(unix)]
const SIGNALS: &[(&str, i32)] = &[
  ("SIGHUP", libc::SIGHUP),
  ("SIGINT", libc::SIGINT),
  ("SIGQUIT", libc::SIGQUIT),
  ("SIGILL", libc::SIGILL),
  ("SIGTRAP", libc::SIGTRAP),
  ("SIGABRT", libc::SIGABRT),
  ("SIGBUS", libc::SIGBUS),
  ("SIGFPE", libc::SIGFPE),
  ("SIGKILL", libc::SIGKILL),
  ("SIGUSR1", libc::SIGUSR1),
  ("SIGSEGV", libc::SIGSEGV),
  ("SIGUSR2", libc::SIGUSR2),
  ("SIGPIPE", libc::SIGPIPE),
  ("SIGALRM", libc::SIGALRM),
  ("SIGTERM", libc::SIGTERM),
  ("SIGCHLD", libc::SIGCHLD),
  ("SIGCONT", libc::SIGCONT),
  ("SIGSTOP", libc::SIGSTOP),
  ("SIGTSTP", libc::SIGTSTP),
  ("SIGWINCH", libc::SIGWINCH),
];

#[cfg(unix)]
fn signal_to_name(number: i32) -> &'static str {
  SIGNALS.iter().find(|(_, n)| *n == number).map_or("SIGKILL", |(name, _)| name)
}

/// A signal as Node takes it, a name or a number; `SIGTERM` by default.
#[cfg(unix)]
fn signal_number(signal: Option<&Value<'_>>) -> i32 {
  match signal {
    Some(value) if value.is_number() => value.as_number().map_or(libc::SIGTERM, |n| n as i32),
    Some(value) => value
      .as_string()
      .and_then(|s| s.to_string().ok())
      .and_then(|name| SIGNALS.iter().find(|(n, _)| *n == name).map(|(_, number)| *number))
      .unwrap_or(libc::SIGTERM),
    None => libc::SIGTERM,
  }
}

/// Send `signal` to a child this process has not reaped, so its pid
/// cannot have been reused.
#[cfg(unix)]
fn send_signal(child: &mut std::process::Child, signal: i32) {
  // SAFETY: `kill` takes any pid and signal; the pid is a live child's.
  #[allow(unsafe_code)]
  unsafe {
    libc::kill(child.id() as i32, signal);
  }
}

#[cfg(not(unix))]
fn send_signal(child: &mut std::process::Child, _signal: i32) {
  if child.kill().is_err() {
    tracing::debug!("child_process: the child had already exited");
  }
}

#[cfg(unix)]
fn send_signal_async(child: &mut tokio::process::Child, signal: i32) {
  if let Some(pid) = child.id() {
    // SAFETY: as in `send_signal`; `id` is `None` once reaped.
    #[allow(unsafe_code)]
    unsafe {
      libc::kill(pid as i32, signal);
    }
  }
}

#[cfg(not(unix))]
fn send_signal_async(child: &mut tokio::process::Child, _signal: i32) {
  if child.start_kill().is_err() {
    tracing::debug!("child_process: the child had already exited");
  }
}

fn bytes<'js>(ctx: &Ctx<'js>, data: Vec<u8>) -> Result<Value<'js>> {
  Ok(TypedArray::<u8>::new(ctx.clone(), data)?.into_value())
}

/// `spawnSync(file, args, options)`: the program run to completion.
/// `options` carries `cwd`, `env` (as `[name, value]` pairs, or absent
/// for the host's), `stdio` (three of `pipe`, `inherit`, `ignore`),
/// `input`, `timeout`, `killSignal` and `maxBuffer`.
fn spawn_sync<'js>(ctx: Ctx<'js>, file: String, args: Array<'js>, options: Object<'js>) -> Result<Object<'js>> {
  crate::permissions::check_run(&ctx, &file)?;
  let spec = Spec::read(file, args, &options)?;
  let input = match options.get::<_, Value<'js>>("input")? {
    value if value.is_undefined() => None,
    value => Some(super::bytes::buffer_source_bytes(&ctx, &value)?),
  };
  let timeout: Option<f64> = options.get("timeout")?;
  let max_buffer: Option<f64> = options.get("maxBuffer")?;
  let max_buffer = max_buffer.filter(|n| n.is_finite() && *n > 0.0).map(|n| n as usize);
  let kill_signal = signal_number(options.get::<_, Option<Value<'js>>>("killSignal")?.as_ref());

  let result = Object::new(ctx.clone())?;
  let mut child = match spec.command().spawn() {
    Ok(child) => child,
    Err(error) => {
      result.set("error", spawn_error(&ctx, &error, &spec, "spawnSync")?)?;
      result.set("status", Value::new_null(ctx.clone()))?;
      result.set("signal", Value::new_null(ctx.clone()))?;
      return Ok(result);
    },
  };
  result.set("pid", child.id())?;

  // The input is written and both outputs drained on threads of their
  // own: a child that fills one pipe while the parent waits on another
  // would otherwise deadlock.
  let writer = child.stdin.take().map(|mut stdin| {
    let input = input.unwrap_or_default();
    std::thread::spawn(move || {
      // A child that exits or closes its stdin before reading all of it
      // gets what it read, as under Node; the broken pipe is not an error.
      stdin.write_all(&input).is_ok()
    })
  });
  let overflowed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let drain = |pipe: Option<Box<dyn Read + Send>>| {
    let overflowed = std::sync::Arc::clone(&overflowed);
    pipe.map(|mut pipe| {
      std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        while let Ok(n) = pipe.read(&mut chunk) {
          if n == 0 {
            break;
          }
          out.extend_from_slice(&chunk[..n]);
          if max_buffer.is_some_and(|max| out.len() > max) {
            out.truncate(max_buffer.unwrap_or(0));
            overflowed.store(true, std::sync::atomic::Ordering::Relaxed);
            break;
          }
        }
        out
      })
    })
  };
  let stdout = drain(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
  let stderr = drain(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));

  let deadline = timeout
    .filter(|t| t.is_finite() && *t > 0.0)
    .map(|t| Instant::now() + Duration::from_secs_f64(t / 1000.0));
  let mut timed_out = false;
  let status = loop {
    match child.try_wait() {
      Ok(Some(status)) => break Some(status),
      Ok(None) => {},
      Err(_) => break None,
    }
    let over = overflowed.load(std::sync::atomic::Ordering::Relaxed);
    if over || deadline.is_some_and(|d| Instant::now() >= d) {
      timed_out = !over;
      send_signal(&mut child, kill_signal);
      break child.wait().ok();
    }
    std::thread::sleep(Duration::from_millis(1));
  };
  // The writer ends once the child's stdin closes, which its exit did.
  if let Some(writer) = writer {
    if writer.join().is_err() {
      tracing::debug!("child_process: the stdin writer panicked");
    }
  }
  let collect = |handle: Option<std::thread::JoinHandle<Vec<u8>>>| handle.and_then(|h| h.join().ok());
  match collect(stdout) {
    Some(out) => result.set("stdout", bytes(&ctx, out)?)?,
    None => result.set("stdout", Value::new_null(ctx.clone()))?,
  }
  match collect(stderr) {
    Some(out) => result.set("stderr", bytes(&ctx, out)?)?,
    None => result.set("stderr", Value::new_null(ctx.clone()))?,
  }
  match status {
    Some(status) => {
      match status.code() {
        Some(code) => result.set("status", code)?,
        None => result.set("status", Value::new_null(ctx.clone()))?,
      }
      match signal_name(status) {
        Some(signal) => result.set("signal", signal)?,
        None => result.set("signal", Value::new_null(ctx.clone()))?,
      }
    },
    None => {
      result.set("status", Value::new_null(ctx.clone()))?;
      result.set("signal", Value::new_null(ctx.clone()))?;
    },
  }
  if timed_out || overflowed.load(std::sync::atomic::Ordering::Relaxed) {
    let error = Object::new(ctx.clone())?;
    let code = if timed_out { "ETIMEDOUT" } else { "ENOBUFS" };
    error.set("code", code)?;
    error.set("syscall", format!("spawnSync {}", spec.file))?;
    error.set("path", spec.file.as_str())?;
    error.set("message", format!("spawnSync {} {code}", spec.file))?;
    result.set("error", error)?;
  }
  Ok(result)
}

/// `spawn(file, args, options, onEvent)`: the program started, its
/// output and exit reported to `onEvent` as `('stdout' | 'stderr',
/// bytes)`, `('exit', code, signal)` and `('error', error)`, in the order
/// they happen. Answers the handle `child_process.js` drives: `pid`,
/// `write(bytes)`, `end()` and `kill(signal)`.
fn spawn<'js>(
  ctx: Ctx<'js>,
  file: String,
  args: Array<'js>,
  options: Object<'js>,
  on_event: Function<'js>,
) -> Result<Object<'js>> {
  crate::permissions::check_run(&ctx, &file)?;
  let spec = Spec::read(file, args, &options)?;
  let handle = Object::new(ctx.clone())?;
  let mut command = tokio::process::Command::from(spec.command());
  command.kill_on_drop(false);
  let mut child = match command.spawn() {
    Ok(child) => child,
    Err(error) => {
      // Node reports a spawn that failed as an `error` event on the next
      // turn, never as a throw from `spawn`.
      let error = spawn_error(&ctx, &error, &spec, "spawn")?;
      let callback = on_event.clone();
      ctx.spawn(async move {
        if let Err(error) = callback.call::<_, ()>(("error", error)) {
          crate::uncaught::report_error(callback.ctx(), &error);
        }
      });
      handle.set("write", Function::new(ctx.clone(), |_: Opt<Value<'_>>| false)?)?;
      handle.set("end", Function::new(ctx.clone(), || {})?)?;
      handle.set("kill", Function::new(ctx.clone(), |_: Opt<Value<'_>>| false)?)?;
      return Ok(handle);
    },
  };
  if let Some(pid) = child.id() {
    handle.set("pid", pid)?;
  }

  let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
  if let Some(mut stdin) = child.stdin.take() {
    ctx.spawn(async move {
      while let Some(chunk) = write_rx.recv().await {
        if stdin.write_all(&chunk).await.is_err() {
          break;
        }
      }
    });
  }
  let write_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(write_tx)));
  let writer = std::rc::Rc::clone(&write_tx);
  handle.set(
    "write",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, chunk: Value<'js>| -> Result<bool> {
      let bytes = super::bytes::buffer_source_bytes(&ctx, &chunk)?;
      Ok(writer.borrow().as_ref().is_some_and(|tx| tx.send(bytes).is_ok()))
    })?,
  )?;
  handle.set(
    "end",
    Function::new(ctx.clone(), move || {
      write_tx.borrow_mut().take();
    })?,
  )?;

  let (kill_tx, mut kill_rx) = mpsc::unbounded_channel::<i32>();
  handle.set(
    "kill",
    Function::new(ctx.clone(), move |signal: Opt<Value<'js>>| -> bool {
      kill_tx.send(signal_number(signal.0.as_ref())).is_ok()
    })?,
  )?;

  let pump = |pipe: Option<Box<dyn tokio::io::AsyncRead + Unpin>>, name: &'static str| {
    let callback = on_event.clone();
    async move {
      let Some(mut pipe) = pipe else {
        return;
      };
      let mut chunk = vec![0u8; 64 * 1024];
      while let Ok(n) = pipe.read(&mut chunk).await {
        if n == 0 {
          break;
        }
        let ctx = callback.ctx().clone();
        let delivered = bytes(&ctx, chunk[..n].to_vec()).and_then(|data| callback.call::<_, ()>((name, data)));
        if let Err(error) = delivered {
          crate::uncaught::report_error(&ctx, &error);
        }
      }
    }
  };
  let stdout = pump(child.stdout.take().map(|p| Box::new(p) as Box<dyn tokio::io::AsyncRead + Unpin>), "stdout");
  let stderr = pump(child.stderr.take().map(|p| Box::new(p) as Box<dyn tokio::io::AsyncRead + Unpin>), "stderr");
  let callback = on_event;
  ctx.spawn(async move {
    let wait = async {
      loop {
        tokio::select! {
          status = child.wait() => break status.ok(),
          Some(signal) = kill_rx.recv() => send_signal_async(&mut child, signal),
        }
      }
    };
    // Output is drained alongside the wait, so a child that writes more
    // than a pipe holds is not left blocked, and `exit` is reported only
    // once both pipes are drained.
    let (status, (), ()) = tokio::join!(wait, stdout, stderr);
    let ctx = callback.ctx().clone();
    let code = status.and_then(|s| s.code());
    let signal = status.and_then(signal_name);
    let reported = callback.call::<_, ()>(("exit", code, signal));
    if let Err(error) = reported {
      crate::uncaught::report_error(&ctx, &error);
    }
  });
  Ok(handle)
}
