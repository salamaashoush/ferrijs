//! One sandboxed realm: a `QuickJS` runtime, its context, the event loop
//! that owns them, and the policy they run under.
//!
//! A [`Runtime`] is built once and run many times. `globalThis` state
//! survives between runs REPL-style (a `globalThis.x =` persists; a
//! script's own top-level declarations are scoped to that run), while the
//! runtime's own globals (`console`, `args`) are refreshed every run so
//! they always reflect the current call. A run that is force-halted
//! (timeout) or hits an allocation fault leaves the heap untrustworthy;
//! the runtime reports it as [`Run::poisoned`] and the host discards
//! the realm and builds a fresh one.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ferrijs_permissions::{Container, Permissions};
use rquickjs::{AsyncContext, AsyncRuntime, CatchResultExt, Ctx, Module, Value};

use crate::console::{ConsoleCapture, ConsoleSink};
use crate::console_fmt::install_console;
use crate::error::{ScriptError, ScriptErrorKind};
use crate::extension::Extension;
use crate::limits::{AppliedLimits, Deadline, Limits, NeverParked, PauseClock, RunOptions, TimeoutState, run_within};
use crate::modules::{
  BoxLoader, BoxResolver, FileLoader, FileResolver, LoaderChain, ModulePolicy, ModuleRegistry, RequireHook,
  ResolverChain,
};
use crate::realm::RealmOptions;
use crate::redact::Redactor;
use crate::result::ConsoleEntry;
use crate::source_map::CompiledModule;
use crate::vm::{VmHandle, VmShutdown, spawn_vm_loop};
use crate::vm_with;

/// Default console-capture limits.
pub const DEFAULT_MAX_CONSOLE_ENTRIES: usize = 1_000;
pub const DEFAULT_MAX_CONSOLE_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_CONSOLE_ENTRY_BYTES: usize = 8_192;

/// How `console.*` output is kept.
#[derive(Clone)]
pub struct ConsoleOptions {
  pub max_entries: usize,
  pub max_bytes: usize,
  pub max_entry_bytes: usize,
  /// When set, `console.*` calls stream to this sink as they happen and
  /// [`Run::console`] stays empty. `None` (the default) keeps the
  /// buffered form every machine consumer reads.
  pub sink: Option<Arc<dyn ConsoleSink>>,
}

impl Default for ConsoleOptions {
  fn default() -> Self {
    Self {
      max_entries: DEFAULT_MAX_CONSOLE_ENTRIES,
      max_bytes: DEFAULT_MAX_CONSOLE_BYTES,
      max_entry_bytes: DEFAULT_MAX_CONSOLE_ENTRY_BYTES,
      sink: None,
    }
  }
}

impl std::fmt::Debug for ConsoleOptions {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ConsoleOptions")
      .field("max_entries", &self.max_entries)
      .field("max_bytes", &self.max_bytes)
      .field("max_entry_bytes", &self.max_entry_bytes)
      .field("sink", &self.sink.is_some())
      .finish()
  }
}

/// What `process` reports about itself.
#[derive(Debug, Clone, Default)]
pub struct ProcessOptions {
  /// What `process.cwd()` answers. Defaults to the module root.
  pub cwd: Option<String>,
  /// `process.argv[1..]`.
  pub argv: Vec<String>,
}

/// Everything a [`Runtime`] is built from. Assembled by [`Builder`].
pub struct Config {
  pub limits: Limits,
  pub console: ConsoleOptions,
  pub realm: RealmOptions,
  pub modules: ModulePolicy,
  pub process: ProcessOptions,
  pub identity: ferrijs_std::identity::Identity,
  pub permissions: Arc<Container>,
  pub redactor: Option<Arc<dyn Redactor>>,
  pub pause_clock: Arc<dyn PauseClock>,
  /// Install `globalThis.fs`, the way a scripting host does. Node has no
  /// such global, so it is off unless asked for.
  pub fs_global: bool,
  /// What `fetch` sends through. `None` installs no `fetch` at all; the
  /// default is the standalone [`crate::fetch::Client`].
  #[cfg(feature = "fetch")]
  pub fetch: Option<Arc<dyn crate::fetch::FetchBackend>>,
  pub extensions: Vec<Arc<dyn Extension>>,
}

impl std::fmt::Debug for Config {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Config")
      .field("limits", &self.limits)
      .field("console", &self.console)
      .field("realm", &self.realm)
      .field("modules", &self.modules)
      .field("process", &self.process)
      .field("identity", &self.identity)
      .field("permissions", &self.permissions)
      .field("fs_global", &self.fs_global)
      .field(
        "extensions",
        &self.extensions.iter().map(|e| e.name().to_string()).collect::<Vec<_>>(),
      )
      .finish_non_exhaustive()
  }
}

/// Builds a [`Runtime`]. Every setting has a default; the defaults
/// grant nothing.
pub struct Builder {
  config: Config,
}

impl Default for Builder {
  fn default() -> Self {
    Self {
      config: Config {
        limits: Limits::default(),
        console: ConsoleOptions::default(),
        realm: RealmOptions::default(),
        modules: ModulePolicy::default(),
        process: ProcessOptions::default(),
        identity: ferrijs_std::identity::Identity::default(),
        permissions: Arc::new(Container::new(Permissions::none())),
        redactor: None,
        pause_clock: Arc::new(NeverParked),
        fs_global: false,
        #[cfg(feature = "fetch")]
        fetch: Some(Arc::new(crate::fetch::Client::new())),
        extensions: Vec::new(),
      },
    }
  }
}

impl Builder {
  #[must_use]
  pub fn limits(mut self, limits: Limits) -> Self {
    self.config.limits = limits;
    self
  }

  #[must_use]
  pub fn console(mut self, console: ConsoleOptions) -> Self {
    self.config.console = console;
    self
  }

  #[must_use]
  pub fn realm(mut self, realm: RealmOptions) -> Self {
    self.config.realm = realm;
    self
  }

  #[must_use]
  pub fn modules(mut self, policy: ModulePolicy) -> Self {
    self.config.modules = policy;
    self
  }

  #[must_use]
  pub fn process(mut self, process: ProcessOptions) -> Self {
    self.config.process = process;
    self
  }

  #[must_use]
  pub fn identity(mut self, identity: ferrijs_std::identity::Identity) -> Self {
    self.config.identity = identity;
    self
  }

  /// The realm's policy. Replaces any container set before.
  #[must_use]
  pub fn permissions(mut self, permissions: Permissions) -> Self {
    self.config.permissions = Arc::new(Container::new(permissions));
    self
  }

  /// The realm's policy with a hook and/or audit attached.
  #[must_use]
  pub fn permission_container(mut self, container: Container) -> Self {
    self.config.permissions = Arc::new(container);
    self
  }

  #[must_use]
  pub fn redactor(mut self, redactor: Arc<dyn Redactor>) -> Self {
    self.config.redactor = Some(redactor);
    self
  }

  #[must_use]
  pub fn pause_clock(mut self, clock: Arc<dyn PauseClock>) -> Self {
    self.config.pause_clock = clock;
    self
  }

  #[must_use]
  pub fn fs_global(mut self, on: bool) -> Self {
    self.config.fs_global = on;
    self
  }

  /// What `fetch` sends through, replacing the default client. A host
  /// with its own HTTP stack installs it here; the realm's `net` grant
  /// applies to it unchanged.
  #[cfg(feature = "fetch")]
  #[must_use]
  pub fn fetch(mut self, backend: Arc<dyn crate::fetch::FetchBackend>) -> Self {
    self.config.fetch = Some(backend);
    self
  }

  /// No `fetch` global at all: for a realm that must have no network
  /// entry point whatever its grants say.
  #[cfg(feature = "fetch")]
  #[must_use]
  pub fn without_fetch(mut self) -> Self {
    self.config.fetch = None;
    self
  }

  #[must_use]
  pub fn extension(mut self, extension: impl Extension + 'static) -> Self {
    self.config.extensions.push(Arc::new(extension));
    self
  }

  #[must_use]
  pub fn extension_arc(mut self, extension: Arc<dyn Extension>) -> Self {
    self.config.extensions.push(extension);
    self
  }

  /// Build the realm: runtime, limits, loader, context, event loop, and
  /// the one-time install of the standard library and every extension.
  ///
  /// # Errors
  ///
  /// When the engine cannot be created, an extension's modules clash,
  /// or an install fails.
  pub async fn build(self) -> Result<Runtime, ScriptError> {
    Runtime::create(self.config).await
  }
}

/// The realm's event-loop handle, stashed as context userdata so a
/// binding that needs to dispatch back into the VM from another task
/// can find it.
struct VmHandleUd(VmHandle);

// SAFETY: holds only an owned channel handle (`'static`; no borrowed
// JS values), so re-stating the unused `'js` lifetime is sound.
#[allow(unsafe_code)]
unsafe impl rquickjs::JsLifetime<'_> for VmHandleUd {
  type Changed<'to> = VmHandleUd;
}

/// The realm's event-loop handle, from inside a binding.
#[must_use]
pub fn vm_handle(ctx: &Ctx<'_>) -> Option<VmHandle> {
  ctx.userdata::<VmHandleUd>().map(|ud| ud.0.clone())
}

/// The realm's module registry, from inside a binding.
struct RegistryUd(Arc<ModuleRegistry>);

// SAFETY: owned `Arc` only.
#[allow(unsafe_code)]
unsafe impl rquickjs::JsLifetime<'_> for RegistryUd {
  type Changed<'to> = RegistryUd;
}

/// The realm's module registry, from inside a binding.
#[must_use]
pub fn registry(ctx: &Ctx<'_>) -> Option<Arc<ModuleRegistry>> {
  ctx.userdata::<RegistryUd>().map(|ud| Arc::clone(&ud.0))
}

/// Outcome of one [`Runtime::run`]: the value or failure, what the run
/// logged, how long it took, and whether the realm must be discarded.
#[derive(Debug)]
pub struct Run<T> {
  pub result: Result<T, ScriptError>,
  pub duration_ms: u64,
  pub console: Vec<ConsoleEntry>,
  /// The interpreter was force-halted mid-run (timeout) or hit an
  /// allocation fault: the heap cannot be trusted, so the host must not
  /// run anything else on this realm. A plain JS `throw` is NOT
  /// poisoning.
  pub poisoned: bool,
}

impl<T> Run<T> {
  #[must_use]
  pub fn is_ok(&self) -> bool {
    self.result.is_ok()
  }

  /// The failure, if any.
  #[must_use]
  pub fn err(&self) -> Option<&ScriptError> {
    self.result.as_ref().err()
  }

  pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Run<U> {
    Run {
      result: self.result.map(f),
      duration_ms: self.duration_ms,
      console: self.console,
      poisoned: self.poisoned,
    }
  }
}

impl Run<serde_json::Value> {
  /// The run as the wire-shaped [`crate::result::ScriptResult`].
  #[must_use]
  pub fn into_result(self) -> crate::result::ScriptResult {
    match self.result {
      Ok(value) => crate::result::ScriptResult::ok(value, self.duration_ms, self.console),
      Err(error) => crate::result::ScriptResult::err(error, self.duration_ms, self.console),
    }
  }
}

/// A body handed to [`Runtime::run`]: runs on the VM loop with the
/// context in scope, and answers the run's value.
///
/// The future it returns is `!Send` (it holds JS values); the runtime
/// drives it only on the VM loop, under the engine lock.
pub type RunBody<T> =
  Box<dyn for<'js> FnOnce(Ctx<'js>) -> Pin<Box<dyn Future<Output = Result<T, ScriptError>> + 'js>> + Send>;

/// One sandboxed realm.
pub struct Runtime {
  engine: AsyncRuntime,
  /// Submission handle to the realm's single VM event loop (see
  /// [`crate::vm`]): one persistent `async_with` owns the runtime's
  /// scheduler for the realm's whole life; every run and every
  /// cross-task dispatch runs as a job `ctx.spawn`ed by that loop.
  /// Nothing else may create an `async_with` against this runtime -- a
  /// transient one steals the scheduler's single wake-queue slot and
  /// dies with it, silently losing every later external wake.
  vm: VmHandle,
  /// Dropping this with the runtime ends the VM event loop, which
  /// releases the engine on the loop's own task.
  _vm_shutdown: VmShutdown,
  config: Config,
  registry: Arc<ModuleRegistry>,
  applied: AppliedLimits,
  timeout: Arc<TimeoutState>,
  poisoned: AtomicBool,
}

impl std::fmt::Debug for Runtime {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Runtime")
      .field("config", &self.config)
      .field("poisoned", &self.poisoned())
      .finish_non_exhaustive()
  }
}

impl Runtime {
  #[must_use]
  pub fn builder() -> Builder {
    Builder::default()
  }

  async fn create(config: Config) -> Result<Self, ScriptError> {
    let runtime = AsyncRuntime::new().map_err(|e| ScriptError::internal(format!("rquickjs runtime init: {e}")))?;

    runtime.set_memory_limit(config.limits.memory).await;
    runtime.set_max_stack_size(config.limits.stack).await;
    runtime.set_gc_threshold(config.limits.gc_threshold).await;

    // One interrupt handler for the realm's lifetime, reading the shared
    // deadline cell. Installing per run and never disarming would let a
    // stale deadline force-halt a callback entering the interpreter
    // between runs.
    let timeout = Arc::new(TimeoutState::new(Arc::clone(&config.pause_clock)));
    {
      let state = Arc::clone(&timeout);
      runtime
        .set_interrupt_handler(Some(Box::new(move || {
          if state.expired() {
            state.timed_out.store(true, Ordering::Relaxed);
            true
          } else {
            false
          }
        })))
        .await;
    }

    // The module table: the standard library plus every extension's
    // modules, gathered BEFORE the loader is set, because `QuickJS`
    // resolves a module graph eagerly at declare time.
    let mut registry = ModuleRegistry::with_std();
    let mut resolvers: Vec<BoxResolver> = Vec::new();
    let mut loaders: Vec<BoxLoader> = Vec::new();
    let mut require_hooks: Vec<Arc<dyn RequireHook>> = Vec::new();
    for extension in &config.extensions {
      extension
        .modules(&mut registry)
        .map_err(|e| ScriptError::internal(format!("extension `{}`: {e}", extension.name())))?;
      for (resolver, loader) in extension.loaders() {
        resolvers.push(resolver);
        loaders.push(loader);
      }
      if let Some(hook) = extension.require_hook() {
        require_hooks.push(hook);
      }
    }
    let registry = Arc::new(registry);
    let (native_resolver, native_loader) = registry.loader();
    runtime
      .set_loader(
        (
          native_resolver,
          ResolverChain(resolvers),
          FileResolver::new(config.modules.clone()),
        ),
        (native_loader, LoaderChain(loaders), FileLoader::new(&config.modules)),
      )
      .await;

    let ctx = AsyncContext::full(&runtime)
      .await
      .map_err(|e| ScriptError::internal(format!("rquickjs context init: {e}")))?;

    let (vm, vm_shutdown) = spawn_vm_loop(&ctx);

    let base_console = Arc::new(Self::console_capture(&config));
    let install_registry = Arc::clone(&registry);
    let ud_vm = vm.clone();
    let permissions = Arc::clone(&config.permissions);
    let identity = config.identity.clone();
    let process = ferrijs_std::node::process::ProcessOptions {
      env: permissions.base().env_snapshot(),
      cwd: config
        .process
        .cwd
        .clone()
        .unwrap_or_else(|| config.modules.root.to_string_lossy().into_owned()),
      argv: config.process.argv.clone(),
    };
    let fs_global = config.fs_global;
    #[cfg(feature = "fetch")]
    let fetch_backend = config.fetch.clone();
    let realm = config.realm.clone();
    let extensions = config.extensions.clone();

    let installed: Result<Result<(), ScriptError>, ScriptError> = vm_with!(vm => |ctx| {
      let _ = ctx.store_userdata(VmHandleUd(ud_vm));
      let _ = ctx.store_userdata(RegistryUd(Arc::clone(&install_registry)));
      ferrijs_std::permissions::install(&ctx, permissions);
      ferrijs_std::identity::set(&ctx, identity);

      let fail = |what: &str, e: rquickjs::Error| ScriptError::internal(format!("failed to install {what}: {e}"));
      ferrijs_std::init(&ctx).map_err(|e| fail("the standard library", e))?;
      crate::timers::install(&ctx).map_err(|e| fail("timers", e))?;
      ferrijs_std::node::process::install(&ctx, &process).map_err(|e| fail("process", e))?;
      if fs_global {
        ferrijs_std::fs::init(&ctx).map_err(|e| fail("fs", e))?;
      }
      crate::modules::require::install(&ctx, install_registry, require_hooks).map_err(|e| fail("require", e))?;
      #[cfg(feature = "fetch")]
      if let Some(backend) = fetch_backend {
        crate::fetch::install(&ctx, backend).map_err(|e| fail("fetch", e))?;
      }
      // A console from the start, so an extension's top-level
      // `console.log` has somewhere to go; each run swaps in its own.
      install_console(&ctx, base_console).map_err(|e| fail("console", e))?;

      for extension in &extensions {
        extension
          .install_async(ctx.clone())
          .await
          .map_err(|e| ScriptError::internal(format!("extension `{}` failed to install: {e}", extension.name())))?;
      }

      crate::realm::lockdown(&ctx, &realm).map_err(|e| fail("the realm lockdown", e))?;
      Ok(())
    })
    .await;
    installed??;

    let applied = AppliedLimits::new(&config.limits);
    Ok(Self {
      engine: runtime,
      vm,
      _vm_shutdown: vm_shutdown,
      config,
      registry,
      applied,
      timeout,
      poisoned: AtomicBool::new(false),
    })
  }

  fn console_capture(config: &Config) -> ConsoleCapture {
    let capture = ConsoleCapture::new(
      config.console.max_entries,
      config.console.max_bytes,
      config.console.max_entry_bytes,
    );
    let capture = match &config.redactor {
      Some(redactor) => capture.with_redactor(Arc::clone(redactor)),
      None => capture,
    };
    match &config.console.sink {
      Some(sink) => capture.with_sink(Arc::clone(sink)),
      None => capture,
    }
  }

  /// The realm's event-loop handle. Cloneable; a host keeps one to
  /// dispatch into the VM from its own tasks.
  #[must_use]
  pub fn handle(&self) -> VmHandle {
    self.vm.clone()
  }

  #[must_use]
  pub fn config(&self) -> &Config {
    &self.config
  }

  #[must_use]
  pub fn registry(&self) -> &Arc<ModuleRegistry> {
    &self.registry
  }

  #[must_use]
  pub fn permissions(&self) -> &Arc<Container> {
    &self.config.permissions
  }

  /// Whether a run left the heap untrustworthy. Once set it stays set;
  /// the host discards the realm.
  #[must_use]
  pub fn poisoned(&self) -> bool {
    self.poisoned.load(Ordering::Relaxed)
  }

  /// A cloneable handle to the run deadline, for a host that re-arms it
  /// from somewhere the runtime itself cannot be held.
  #[must_use]
  pub fn deadline(&self) -> Deadline {
    Deadline(Arc::clone(&self.timeout))
  }

  /// Run `f` on the VM loop with the context in scope, outside any run
  /// bracket: no deadline, no console capture, no poison detection.
  /// For installs and lookups, not for user code.
  ///
  /// # Errors
  ///
  /// Only when the loop is gone (the realm was dropped).
  pub async fn with<R, F>(&self, f: F) -> Result<R, ScriptError>
  where
    R: Send + 'static,
    F: for<'js> FnOnce(Ctx<'js>) -> Pin<Box<dyn Future<Output = R> + Send + 'js>> + Send + 'static,
  {
    self.vm.with(f).await
  }

  /// Push resource limits to the engine, skipping any setter whose
  /// value is unchanged since the last run.
  async fn apply_limits(&self, memory: usize, stack: usize, gc: usize) {
    if self.applied.memory.swap(memory, Ordering::Relaxed) != memory {
      self.engine.set_memory_limit(memory).await;
    }
    if self.applied.stack.swap(stack, Ordering::Relaxed) != stack {
      self.engine.set_max_stack_size(stack).await;
    }
    if self.applied.gc.swap(gc, Ordering::Relaxed) != gc {
      self.engine.set_gc_threshold(gc).await;
    }
  }

  async fn apply_run_options(&self, options: &RunOptions) -> Duration {
    let limits = &self.config.limits;
    self
      .apply_limits(
        options.memory.unwrap_or(limits.memory),
        options.stack.unwrap_or(limits.stack),
        options.gc_threshold.unwrap_or(limits.gc_threshold),
      )
      .await;
    options.timeout.unwrap_or(limits.timeout)
  }

  /// Run `body` under the run bracket: limits applied, the deadline
  /// armed, a fresh `console` capture installed, the backstop watching,
  /// and the outcome classified (a force-halt or an allocation fault
  /// poisons the realm; a throw does not).
  ///
  /// The body sees the context with `console` already refreshed. Its
  /// value and failure are redacted before they are handed back.
  pub async fn run<T: Send + 'static>(&self, options: RunOptions, body: RunBody<T>) -> Run<T> {
    let started = Instant::now();
    let console = Arc::new(Self::console_capture(&self.config));
    if self.poisoned() {
      return Run {
        result: Err(ScriptError::internal(
          "this realm is poisoned by an earlier timeout or allocation fault; build a new one",
        )),
        duration_ms: 0,
        console: Vec::new(),
        poisoned: true,
      };
    }
    let timeout = self.apply_run_options(&options).await;
    self.timeout.arm(started + timeout);
    let run_console = Arc::clone(&console);

    let fut = vm_with!(self.vm => |ctx| {
      if let Err(e) = install_console(&ctx, run_console) {
        return Err(ScriptError::internal(format!("failed to install console: {e}")));
      }
      body(ctx).await
    });

    let backstop = timeout.saturating_add(self.config.limits.backstop_grace);
    let outcome = match run_within(self.timeout.clock(), backstop, fut).await {
      Ok(r) => r.and_then(|inner| inner),
      Err(_) => return self.finish_backstop(started, &console, timeout),
    };
    self.finish(outcome, started, &console, timeout)
  }

  /// Build the `Run` from an outcome, applying the poison rule.
  fn finish<T>(
    &self,
    outcome: Result<T, ScriptError>,
    started: Instant,
    console: &ConsoleCapture,
    timeout: Duration,
  ) -> Run<T> {
    self.timeout.disarm();
    let duration_ms = elapsed_ms(started);
    let drained = console.drain();
    match outcome {
      Ok(value) => Run {
        result: Ok(value),
        duration_ms,
        console: drained,
        poisoned: false,
      },
      Err(mut err) => {
        let timed_out = self.timeout.timed_out.load(Ordering::Relaxed);
        let oom = is_oom(&err);
        let poisoned = timed_out || oom;
        if timed_out {
          err = ScriptError::timeout(duration_ms, timeout.as_millis().try_into().unwrap_or(u64::MAX));
        } else if oom {
          err.kind = ScriptErrorKind::MemoryLimit;
        }
        if let Some(redactor) = &self.config.redactor {
          err.redact(redactor.as_ref());
        }
        if poisoned {
          self.poisoned.store(true, Ordering::Relaxed);
        }
        Run {
          result: Err(err),
          duration_ms,
          console: drained,
          poisoned,
        }
      },
    }
  }

  /// The `Run` for a backstop fire: the run was parked on a native
  /// await past the deadline, so the interrupt handler never got a
  /// chance to halt it. The future was dropped mid-flight -- half-driven
  /// promises may still reference VM state, so the run is always
  /// poisoned.
  fn finish_backstop<T>(&self, started: Instant, console: &ConsoleCapture, timeout: Duration) -> Run<T> {
    self.timeout.disarm();
    self.poisoned.store(true, Ordering::Relaxed);
    let duration_ms = elapsed_ms(started);
    Run {
      result: Err(ScriptError::timeout(
        duration_ms,
        timeout.as_millis().try_into().unwrap_or(u64::MAX),
      )),
      duration_ms,
      console: console.drain(),
      poisoned: true,
    }
  }

  /// Evaluate a script with `args` bound as the `args` global, and
  /// answer its top-level `return` value as JSON.
  ///
  /// The source is wrapped in an async IIFE, so `await` works at the top
  /// level and `return <value>` surfaces as the result. `args` is never
  /// interpolated into the source. For an ES module (`import` /
  /// `export`, TypeScript) bundle it and use [`Self::eval_module`].
  pub async fn eval_script(
    &self,
    source: &str,
    args: &[serde_json::Value],
    options: RunOptions,
  ) -> Run<serde_json::Value> {
    let source_owned = source.to_string();
    let args = args.to_vec();
    let redactor = self.config.redactor.clone();
    let run = self
      .run(
        options,
        Box::new(move |ctx| {
          Box::pin(async move {
            install_args(&ctx, &args)?;
            // One line of wrapper before the user's source, so a
            // reported position is offset by one.
            let wrapped = format!("(async () => {{\n{source_owned}\n}})()");
            let promise: rquickjs::Promise<'_> = ctx.eval(wrapped.as_bytes()).map_err(|e| {
              ScriptError::from_caught_offset(&ctx, rquickjs::CaughtError::from_error(&ctx, e), &source_owned, 1)
            })?;
            let value: Value<'_> = promise.into_future::<Value<'_>>().await.map_err(|e| {
              ScriptError::from_caught_offset(&ctx, rquickjs::CaughtError::from_error(&ctx, e), &source_owned, 1)
            })?;
            Ok(crate::value::value_to_json(&ctx, value).unwrap_or(serde_json::Value::Null))
          })
        }),
      )
      .await;
    redact_run(run, redactor.as_deref())
  }

  /// Evaluate a precompiled ES module with `args` bound as the `args`
  /// global. A module cannot use top-level `return`, so the run's value
  /// is the module's `default` export (`null` when it has none). Error
  /// positions are remapped through the module's source map.
  pub async fn eval_module(
    &self,
    module: &CompiledModule,
    args: &[serde_json::Value],
    options: RunOptions,
  ) -> Run<serde_json::Value> {
    let bytecode = Arc::clone(&module.bytecode);
    let label = module.module_name.clone();
    let mapper = module.mapper();
    let args = args.to_vec();
    let redactor = self.config.redactor.clone();
    let run = self
      .run(
        options,
        Box::new(move |ctx| {
          Box::pin(async move {
            crate::source_map::register_bundle(&ctx, mapper);
            install_args(&ctx, &args)?;
            // SAFETY: `bytecode` was produced by `Module::write` by this
            // exact rquickjs/QuickJS build with native endianness --
            // either in this process or restored from a bytecode cache
            // whose ABI tag guarantees an ABI-identical toolchain wrote
            // it. That contract is the bundle crate's to keep.
            #[allow(unsafe_code)]
            let declared = match (unsafe { Module::load(ctx.clone(), &bytecode) }).catch(&ctx) {
              Ok(m) => m,
              Err(e) => return Err(ScriptError::from_caught(&ctx, e, &label)),
            };
            let (evaluated, promise) = match declared.eval().catch(&ctx) {
              Ok(v) => v,
              Err(e) => return Err(ScriptError::from_caught(&ctx, e, &label)),
            };
            if let Err(e) = promise.into_future::<()>().await.catch(&ctx) {
              return Err(ScriptError::from_caught(&ctx, e, &label));
            }
            let default = evaluated
              .namespace()
              .and_then(|ns| ns.get::<_, Value<'_>>("default"))
              .unwrap_or_else(|_| Value::new_undefined(ctx.clone()));
            Ok(crate::value::value_to_json(&ctx, default).unwrap_or(serde_json::Value::Null))
          })
        }),
      )
      .await;
    let run = run.map_err_pos(|e| {
      if let Some(line) = e.line
        && let Some((src, sl, sc)) = module.remap(line, e.column.unwrap_or(1))
      {
        e.message = format!("{} (at {src}:{sl}:{sc})", e.message);
      }
    });
    redact_run(run, redactor.as_deref())
  }

  /// Declare and evaluate an ES module from source, under `name`, with
  /// `args` bound. For a host without a bundler, or a test.
  pub async fn eval_module_source(
    &self,
    name: &str,
    source: &str,
    args: &[serde_json::Value],
    options: RunOptions,
  ) -> Run<serde_json::Value> {
    let name = name.to_string();
    let source = source.to_string();
    let args = args.to_vec();
    let redactor = self.config.redactor.clone();
    let run = self
      .run(
        options,
        Box::new(move |ctx| {
          Box::pin(async move {
            install_args(&ctx, &args)?;
            let declared = match Module::declare(ctx.clone(), name.as_str(), source.as_bytes()).catch(&ctx) {
              Ok(m) => m,
              Err(e) => return Err(ScriptError::from_caught(&ctx, e, &source)),
            };
            let (evaluated, promise) = match declared.eval().catch(&ctx) {
              Ok(v) => v,
              Err(e) => return Err(ScriptError::from_caught(&ctx, e, &source)),
            };
            if let Err(e) = promise.into_future::<()>().await.catch(&ctx) {
              return Err(ScriptError::from_caught(&ctx, e, &source));
            }
            let default = evaluated
              .namespace()
              .and_then(|ns| ns.get::<_, Value<'_>>("default"))
              .unwrap_or_else(|_| Value::new_undefined(ctx.clone()));
            Ok(crate::value::value_to_json(&ctx, default).unwrap_or(serde_json::Value::Null))
          })
        }),
      )
      .await;
    redact_run(run, redactor.as_deref())
  }
}

impl<T> Run<T> {
  fn map_err_pos(mut self, f: impl FnOnce(&mut ScriptError)) -> Self {
    if let Err(e) = &mut self.result {
      f(e);
    }
    self
  }
}

fn redact_run(mut run: Run<serde_json::Value>, redactor: Option<&dyn Redactor>) -> Run<serde_json::Value> {
  if let Some(redactor) = redactor
    && let Ok(value) = &mut run.result
  {
    // Console entries were redacted as they were pushed and the error in
    // `finish`; the returned value has never been through a chokepoint
    // until now.
    crate::redact::redact_json(redactor, value);
  }
  run
}

/// Bind `args` as the `args` global: the JS array is built directly from
/// the serde values -- no JSON string, no JS-side `JSON.parse`, and
/// immune to a script reassigning `globalThis.JSON` in a persistent
/// realm.
///
/// # Errors
///
/// Propagates the conversion.
pub fn install_args(ctx: &Ctx<'_>, args: &[serde_json::Value]) -> Result<(), ScriptError> {
  let array = rquickjs::Array::new(ctx.clone()).map_err(|e| ScriptError::internal(format!("args: {e}")))?;
  for (i, a) in args.iter().enumerate() {
    let v = crate::value::json_to_js(ctx, a).map_err(|e| ScriptError::internal(format!("args[{i}]: {e}")))?;
    array
      .set(i, v)
      .map_err(|e| ScriptError::internal(format!("args[{i}]: {e}")))?;
  }
  ctx
    .globals()
    .set("args", array)
    .map_err(|e| ScriptError::internal(format!("args: {e}")))
}

/// `QuickJS` raises an `out of memory` error when an allocation fails
/// after the runtime memory limit is hit. The allocation site is
/// arbitrary, so the heap cannot be trusted afterwards.
fn is_oom(err: &ScriptError) -> bool {
  err.kind == ScriptErrorKind::MemoryLimit || err.message.to_ascii_lowercase().contains("out of memory")
}

fn elapsed_ms(started: Instant) -> u64 {
  u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
