//! rolldown bundle + tree-shake + TypeScript -> one ESM module ->
//! compiled to `QuickJS` bytecode once.
//!
//! rolldown (built on oxc) resolves the whole import graph including
//! `node_modules`, transpiles `.ts`/`.tsx`, tree-shakes, and emits a
//! single ESM chunk. That chunk is compiled to bytecode a single time;
//! every realm that runs it links the bytecode (one `Module::load`, no
//! parse, no resolver). A hidden source map is kept so a JS error in
//! the bundled output is reported at the original `.ts`/`.js` location.
//!
//! The native modules a realm serves stay EXTERNAL: the chunk keeps the
//! bare `import ... from 'node:fs'` and the written bytecode re-links by
//! name against whatever realm loads it. The [`Bundler`] reads which
//! specifiers those are from the same [`ModuleRegistry`] the runtime
//! was built with, so the two cannot disagree.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use ferrijs::ScriptError;
use ferrijs::modules::ModuleRegistry;
use ferrijs::source_map::{CompiledModule, LazyMap};
use rolldown::{
  Bundler as Rolldown, BundlerOptions as RolldownOptions, InputItem, OutputFormat, Platform, SourceMapType,
};
use rolldown_common::{CodeSplittingMode, ModuleType, Output, ResolveOptions, TsConfig};
use rolldown_plugin::{
  HookLoadArgs, HookLoadOutput, HookLoadReturn, HookResolveIdArgs, HookResolveIdOutput, HookResolveIdReturn, HookUsage,
  Plugin, PluginContext, SharedLoadPluginContext,
};
use rquickjs::{AsyncContext, AsyncRuntime, CatchResultExt, Module, WriteOptions, WriteOptionsEndianness};

use crate::cache::BytecodeCache;

/// Id prefix for host-declared virtual modules.
const VIRTUAL_USER_PREFIX: &str = "\0ferrijs-virtual:";

/// A bundle failure, rendered with the file and line it points at.
///
/// `BatchedBuildDiagnostic`'s `Debug` prints `BuildDiagnostic { kind:
/// "PARSE_ERROR", message: "Unexpected token", .. }` — and the `..` is
/// the label span, which is the only place the offending file appears.
/// Reporting that verbatim leaves the reader bisecting an import graph
/// by hand to find which of several hundred modules rolldown could not
/// parse. `to_diagnostic()` resolves the labels against the source it
/// read, so the file and line come back.
fn render_bundle_diagnostics(err: &rolldown_error::BatchedBuildDiagnostic) -> String {
  let rendered: Vec<String> = err
    .iter()
    .map(|d| {
      let diagnostic = d.to_diagnostic();
      let kind = diagnostic.kind();
      match diagnostic.get_primary_location() {
        Some((file, line, column, _)) => format!("{kind} at {file}:{line}:{column}: {d}"),
        None => format!("{kind}: {d}"),
      }
    })
    .collect();
  if rendered.is_empty() {
    return format!("rolldown bundle: {err}");
  }
  format!("rolldown bundle: {}", rendered.join("; "))
}

/// Extensions a JS parser must not be pointed at, mapped to the module
/// type that makes importing one a no-op.
///
/// A stylesheet import is a side effect of the bundler that built the
/// A stylesheet import is a side effect of the bundler that built the
/// package, not something the importing module reads. An analytics
/// package shipping `require("./styles/guides.scss")` inside its dist
/// is enough: with no rule for the extension rolldown hands the SCSS to
/// oxc and reports `PARSE_ERROR: Unexpected token` against a file that
/// is not JavaScript and was never going to be. There is no CSS in a
/// headless QuickJS runtime for the import to mean anything, so `Empty`
/// is the honest answer rather than a stub with a default export.
///
/// Images and fonts get `Empty` for the same reason; JSON and the text
/// formats keep a real value, because code that imports one reads it.
fn asset_module_types() -> rustc_hash::FxHashMap<String, ModuleType> {
  let mut m = rustc_hash::FxHashMap::default();
  for ext in ["css", "scss", "sass", "less", "styl", "stylus"] {
    m.insert(ext.to_string(), ModuleType::Empty);
  }
  for ext in [
    "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "woff", "woff2", "ttf", "eot", "mp4", "webm",
  ] {
    m.insert(ext.to_string(), ModuleType::Empty);
  }
  for ext in ["svg", "txt", "md", "graphql", "gql", "html"] {
    m.insert(ext.to_string(), ModuleType::Text);
  }
  m
}

/// How a bundle resolves: shim aliases, inline virtual modules, the
/// module resolution controls and the tsconfig selection.
#[derive(Debug, Clone)]
pub struct BundlerOptions {
  /// `specifier -> absolute shim file path`. The shim is bundled and
  /// transpiled like any other source (so `.ts` works) and lands in the
  /// source map, which keeps the disk-cache freshness check covering it.
  pub alias: Vec<(String, PathBuf)>,
  /// `specifier -> inline ES-module source` (never touches the fs).
  pub virtual_modules: Vec<(String, String)>,
  /// Extra `exports`/`imports` condition names. The resolver appends
  /// these to its own base set, so an empty list resolves exactly as it
  /// did before any were configured.
  pub conditions: Vec<String>,
  /// `package.json` fields consulted when no `exports` entry matches.
  /// rolldown's own default for a neutral platform is EMPTY, which
  /// leaves a plain `"main": "index.js"` package unresolvable; the
  /// default here is `["module", "main"]`.
  pub main_fields: Vec<String>,
  /// `package.json` field paths holding a legacy path-remapping object.
  pub alias_fields: Vec<Vec<String>>,
  /// The tsconfig whose `paths` / `baseUrl` govern resolution. `None`
  /// leaves rolldown's per-module upward discovery in place; a value
  /// pins one file for the whole graph, which is the only way to select
  /// a config discovery would not find (`tsconfig.test.json`).
  pub tsconfig: Option<PathBuf>,
  /// Specifiers to keep external beyond the registry's own: a host that
  /// serves modules of its own at load time (a package's bytecode
  /// already evaluated under a specifier) names them here so the chunk
  /// keeps the bare import instead of inlining a second copy.
  pub externals: Vec<String>,
}

impl Default for BundlerOptions {
  fn default() -> Self {
    Self {
      alias: Vec::new(),
      virtual_modules: Vec::new(),
      conditions: Vec::new(),
      main_fields: vec!["module".to_string(), "main".to_string()],
      alias_fields: Vec::new(),
      tsconfig: None,
      externals: Vec::new(),
    }
  }
}

impl BundlerOptions {
  /// Add a shim: `specifier` resolves to `target`, a file bundled and
  /// transpiled like any other source. A relative target is taken
  /// against `base`.
  #[must_use]
  pub fn alias(mut self, specifier: impl Into<String>, target: impl AsRef<Path>, base: &Path) -> Self {
    let p = target.as_ref();
    let abs = if p.is_absolute() { p.to_path_buf() } else { base.join(p) };
    self.alias.push((specifier.into(), abs));
    self
  }

  /// Add an inline ES module under `specifier`.
  #[must_use]
  pub fn virtual_module(mut self, specifier: impl Into<String>, source: impl Into<String>) -> Self {
    self.virtual_modules.push((specifier.into(), source.into()));
    self
  }

  /// Pin the tsconfig governing resolution, resolved against `base` when
  /// relative.
  #[must_use]
  pub fn with_tsconfig(mut self, tsconfig: Option<&str>, base: &Path) -> Self {
    self.tsconfig = tsconfig.map(|t| {
      let p = Path::new(t);
      if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
    });
    self
  }

  /// Stable content fingerprint, folded into every bundle cache key so
  /// editing an alias mapping, a virtual module's source or a resolution
  /// control invalidates cached bytecode. (Alias *target file* content is
  /// already covered by the transitive input set; this covers the
  /// mapping itself, the inline sources, and every knob that changes
  /// output without changing a source byte. The tsconfig's CONTENT is
  /// covered separately, through the bundle's input set.)
  #[must_use]
  pub fn fingerprint(&self) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (spec, path) in &self.alias {
      spec.hash(&mut h);
      path.hash(&mut h);
    }
    for (spec, src) in &self.virtual_modules {
      spec.hash(&mut h);
      src.hash(&mut h);
    }
    self.conditions.hash(&mut h);
    self.main_fields.hash(&mut h);
    self.alias_fields.hash(&mut h);
    self.tsconfig.hash(&mut h);
    self.externals.hash(&mut h);
    h.finish()
  }
}

/// Virtual id of the synthetic entry that fans out to every requested
/// entry file. rolldown emits ONE entry chunk per input; feeding it N
/// step/extension files as N inputs produces N entry chunks, of which
/// [`bundle_source`] can only return one — every other file's
/// registrations would be silently dropped. The synthetic entry
/// side-effect-imports each file instead, so one chunk carries them all.
const MULTI_ENTRY_ID: &str = "\0ferrijs-multi-entry.js";

#[derive(Debug)]
struct RuntimePlugin {
  env: Arc<BundlerOptions>,
  registry: Arc<ModuleRegistry>,
  /// Source of the synthetic multi-entry module, when the bundle has
  /// more than one entry file.
  multi_entry: Option<String>,
}

impl Plugin for RuntimePlugin {
  fn name(&self) -> Cow<'static, str> {
    "ferrijs-runtime".into()
  }

  // rolldown's `Plugin` declares these `async`; an impl that happens to
  // need no `.await` still cannot drop the keyword without failing to
  // satisfy the trait. `unknown_lints` rides along because the lint
  // itself only exists from 1.98, and this crate still compiles below it.
  #[allow(unknown_lints, clippy::unused_async_trait_impl)]
  async fn resolve_id(&self, _ctx: &PluginContext, args: &HookResolveIdArgs<'_>) -> HookResolveIdReturn {
    if args.specifier == MULTI_ENTRY_ID && self.multi_entry.is_some() {
      return Ok(Some(HookResolveIdOutput::from_id(MULTI_ENTRY_ID)));
    }
    // Native modules stay EXTERNAL: the emitted chunk keeps the bare
    // import and the bytecode re-links by name against the loading
    // realm's ModuleDefs. Checked first so a host alias can never
    // hijack the native surface. A specifier the host serves at load
    // time stays external too: inlining it would give every consumer
    // its own copy of the provider's state.
    if self.registry.serves(args.specifier) || self.env.externals.iter().any(|e| e == args.specifier) {
      return Ok(Some(HookResolveIdOutput {
        id: args.specifier.into(),
        external: Some(rolldown_common::ResolvedExternal::Bool(true)),
        ..Default::default()
      }));
    }
    if self.env.virtual_modules.iter().any(|(spec, _)| spec == args.specifier) {
      return Ok(Some(HookResolveIdOutput::from_id(format!(
        "{VIRTUAL_USER_PREFIX}{}",
        args.specifier
      ))));
    }
    if let Some((_, target)) = self.env.alias.iter().find(|(spec, _)| spec == args.specifier) {
      // Resolved to a concrete file: rolldown's default fs loader reads
      // it and transpiles by extension, so `.ts` shims work.
      return Ok(Some(HookResolveIdOutput::from_id(
        target.to_string_lossy().into_owned(),
      )));
    }
    Ok(None)
  }

  // rolldown's `Plugin` declares these `async`; an impl that happens to
  // need no `.await` still cannot drop the keyword without failing to
  // satisfy the trait. `unknown_lints` rides along because the lint
  // itself only exists from 1.98, and this crate still compiles below it.
  #[allow(unknown_lints, clippy::unused_async_trait_impl)]
  async fn load(&self, _ctx: SharedLoadPluginContext, args: &HookLoadArgs<'_>) -> HookLoadReturn {
    if args.id == MULTI_ENTRY_ID
      && let Some(src) = &self.multi_entry
    {
      return Ok(Some(HookLoadOutput {
        code: src.clone().into(),
        module_type: Some(ModuleType::Js),
        ..Default::default()
      }));
    }
    let code: Option<Cow<'_, str>> = args.id.strip_prefix(VIRTUAL_USER_PREFIX).and_then(|spec| {
      self
        .env
        .virtual_modules
        .iter()
        .find(|(s, _)| s == spec)
        .map(|(_, src)| Cow::Owned(src.clone()))
    });
    Ok(code.map(|code| HookLoadOutput {
      code: code.into_owned().into(),
      module_type: Some(ModuleType::Js),
      ..Default::default()
    }))
  }

  fn register_hook_usage(&self) -> HookUsage {
    HookUsage::ResolveId | HookUsage::Load
  }
}

/// The result of one rolldown bundle.
pub struct BundledSource {
  pub code: String,
  /// Hidden source map JSON, for translating bundled positions back to
  /// source in stack traces.
  pub source_map_json: Option<String>,
  /// Every module the entry chunk was built from, straight out of
  /// rolldown's module graph.
  ///
  /// NOT derived from the source map: a module whose every binding is
  /// inlined leaves no mapping tokens and vanishes from the map's
  /// `sources`, so a source-map-derived input set silently omitted
  /// exactly the small helper modules extensions are made of — and the
  /// bytecode caches then treated an edited helper as unchanged.
  pub modules: Vec<PathBuf>,
  /// Non-module files the resolver read that can change the output —
  /// the tsconfigs rolldown discovered or was pointed at. They are not
  /// in `modules` (nothing imports them) but editing a `paths` mapping
  /// changes what the same sources resolve to, so they belong in the
  /// cache's input set.
  pub config_inputs: Vec<PathBuf>,
}

/// The bundle front-end for one runtime configuration: its options,
/// the module table whose specifiers stay external, and the cache its
/// compiles land in.
#[derive(Debug, Clone)]
pub struct Bundler {
  options: Arc<BundlerOptions>,
  registry: Arc<ModuleRegistry>,
  cache: BytecodeCache,
}

impl Bundler {
  /// A bundler for realms built over `registry`.
  #[must_use]
  pub fn new(options: BundlerOptions, registry: Arc<ModuleRegistry>, cache: BytecodeCache) -> Self {
    Self {
      options: Arc::new(options),
      registry,
      cache,
    }
  }

  #[must_use]
  pub fn options(&self) -> &BundlerOptions {
    &self.options
  }

  #[must_use]
  pub fn registry(&self) -> &Arc<ModuleRegistry> {
    &self.registry
  }

  #[must_use]
  pub fn cache(&self) -> &BytecodeCache {
    &self.cache
  }

  /// Everything outside the entry files that can change a bundle's
  /// output for byte-identical sources: the options and the native
  /// module table. Every cache key folds this in.
  #[must_use]
  pub fn env_fingerprint(&self) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    self.options.fingerprint().hash(&mut h);
    self.registry.fingerprint().hash(&mut h);
    h.finish()
  }

  /// A cache key for `entry_paths` bundled from `cwd` under `kind`.
  #[must_use]
  pub fn cache_key(&self, kind: &str, entry_paths: &[PathBuf], cwd: &Path) -> u64 {
    crate::cache::entry_key(kind, entry_paths, cwd, self.env_fingerprint())
  }

  /// rolldown-bundle + tree-shake + transpile the entry files (and their
  /// `node_modules` / shared imports) into a single ESM module. Exposed
  /// for diagnostics and tests; [`Self::compile`] is the production path.
  ///
  /// # Errors
  ///
  /// A bundle failure, rendered with the file and line it points at.
  pub async fn bundle(&self, entry_paths: &[PathBuf], cwd: &Path) -> Result<BundledSource, ScriptError> {
    if entry_paths.is_empty() {
      return Err(ScriptError::internal("no entry files".to_string()));
    }

    let env = Arc::clone(&self.options);
    if let Some(ts) = &env.tsconfig
      && !ts.is_file()
    {
      return Err(ScriptError::internal(format!(
        "tsconfig points at {}, which is not a file",
        ts.display()
      )));
    }

    // ONE rolldown input, always. Each input produces its own entry
    // chunk and only one chunk's code can be returned, so multiple entry
    // files must be fanned out from a single synthetic entry module that
    // side-effect-imports each of them (top-level `Given`/`defineTool`
    // registrations are side effects, so nothing tree-shakes away).
    let multi_entry = (entry_paths.len() > 1).then(|| {
      use std::fmt::Write as _;
      entry_paths.iter().fold(String::new(), |mut acc, p| {
        let _ = writeln!(
          acc,
          "import {};",
          serde_json::to_string(&p.to_string_lossy()).unwrap_or_else(|_| String::from("\"\""))
        );
        acc
      })
    });
    let input: Vec<InputItem> = vec![InputItem {
      name: None,
      import: if multi_entry.is_some() {
        MULTI_ENTRY_ID.to_string()
      } else {
        entry_paths[0].to_string_lossy().into_owned()
      },
    }];

    let options = RolldownOptions {
      input: Some(input),
      cwd: Some(cwd.to_path_buf()),
      // Neutral: no Node builtins are injected (QuickJS has none); pure
      // ESM/CJS node_modules still resolve and bundle.
      platform: Some(Platform::Neutral),
      format: Some(OutputFormat::Esm),
      // Hidden: emit the map but no `//# sourceMappingURL` trailer in the
      // code we feed to QuickJS.
      sourcemap: Some(SourceMapType::Hidden),
      // Only `sources` paths and mappings are ever read back (`remap`);
      // `sourcesContent` would inline every spec's full text, tripling the
      // map and the cache blob it is stored in.
      sourcemap_exclude_sources: Some(true),
      // One chunk, always. Only the entry chunk is returned and compiled,
      // so a split chunk would be a reference to code nobody wrote — and
      // its modules would be missing from the cache's input set, making an
      // edit to them invalidate nothing. Legal because there is exactly
      // one input (MULTI_ENTRY fans the rest out).
      code_splitting: Some(CodeSplittingMode::Bool(false)),
      resolve: Some(ResolveOptions {
        // `None` and an empty list are NOT the same to rolldown for main
        // fields: `None` means "platform default", which is empty for
        // Platform::Neutral. Always pass ours.
        main_fields: Some(env.main_fields.clone()),
        condition_names: (!env.conditions.is_empty()).then(|| env.conditions.clone()),
        alias_fields: (!env.alias_fields.is_empty()).then(|| env.alias_fields.clone()),
        ..Default::default()
      }),
      // Unset leaves rolldown's per-module upward discovery (its default).
      tsconfig: env.tsconfig.clone().map(TsConfig::Manual),
      module_types: Some(asset_module_types()),
      ..Default::default()
    };

    let build_started = Instant::now();
    let mut bundler = Rolldown::with_plugins(
      options,
      vec![Arc::new(RuntimePlugin {
        env: Arc::clone(&env),
        registry: Arc::clone(&self.registry),
        multi_entry,
      })],
    )
    .map_err(|e| ScriptError::internal(format!("rolldown init: {e:?}")))?;
    // rolldown's generate future is large; box it so it doesn't bloat the
    // enclosing future.
    let ctor_ms = build_started.elapsed().as_secs_f64() * 1000.0;
    let gen_started = Instant::now();
    let out = Box::pin(bundler.generate())
      .await
      .map_err(|e| ScriptError::internal(render_bundle_diagnostics(&e)))?;
    tracing::debug!(
      target: "ferrijs::bundle",
      entries = entry_paths.len(),
      ctor_ms,
      generate_ms = gen_started.elapsed().as_secs_f64() * 1000.0,
      "rolldown build"
    );

    // Every tsconfig the resolver consulted, whether pinned or discovered
    // per module. rolldown reports them alongside the modules it read.
    let config_inputs: Vec<PathBuf> = bundler
      .watch_files()
      .iter()
      .map(|f| PathBuf::from(f.as_str()))
      .filter(|p| {
        let named_tsconfig = p
          .file_name()
          .and_then(|n| n.to_str())
          .is_some_and(|n| n.starts_with("tsconfig"));
        named_tsconfig && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("json"))
      })
      .collect();

    for asset in &out.assets {
      if let Output::Chunk(chunk) = asset
        && chunk.is_entry
      {
        let modules = chunk
          .module_ids
          .iter()
          .map(|id| PathBuf::from(id.to_string()))
          .filter(|p| p.is_file())
          .collect();
        // Assigned imperatively rather than through `Option::map`: the
        // map's type lives in a transitive crate this one does not depend on
        // directly, so it cannot be named for a method-path closure.
        let mut source_map_json = None;
        if let Some(m) = chunk.map.as_ref() {
          source_map_json = Some(m.to_json_string());
        }
        return Ok(BundledSource {
          code: chunk.code.clone(),
          source_map_json,
          modules,
          config_inputs,
        });
      }
    }
    Err(ScriptError::internal("rolldown produced no entry chunk".to_string()))
  }

  /// Bundle the entry files (TypeScript ok; `node_modules` and shared
  /// helpers resolved + tree-shaken) into one ESM module and compile it
  /// to bytecode under `module_name`, which is what error locations and
  /// stack frames are labelled with. Done once; every realm links the
  /// result.
  ///
  /// # Errors
  ///
  /// A bundle failure, or a module that fails to declare.
  pub async fn compile(
    &self,
    entry_paths: &[PathBuf],
    cwd: &Path,
    module_name: &str,
  ) -> Result<CompiledModule, ScriptError> {
    let module_name = module_name.to_string();

    // Disk cache: an unchanged source tree skips rolldown AND the QuickJS
    // compile. Validated against every transitive input's stamp. The
    // module name participates in the key: it is baked into the written
    // bytecode (QuickJS stores the module name), so two hosts bundling
    // the same files under different labels must not share an entry.
    let cache_key = self.cache_key(&format!("bundle:{module_name}"), entry_paths, cwd);
    let probe_started = Instant::now();
    let hit = self.cache.load(cache_key);
    let probe_elapsed = probe_started.elapsed();
    if let Some(hit) = hit {
      let map_bytes = hit.source_map_json.as_ref().map_or(0, String::len);
      let source_map = LazyMap::from_json(hit.source_map_json.as_deref());
      tracing::debug!(
        target: "ferrijs::bundle",
        module = %module_name,
        entries = entry_paths.len(),
        map_bytes,
        probe_ms = probe_elapsed.as_secs_f64() * 1000.0,
        "bundle warm path"
      );
      return Ok(CompiledModule {
        module_name,
        bytecode: Arc::from(hit.bytecode.into_boxed_slice()),
        source_map,
        cwd: Some(cwd.to_path_buf()),
      });
    }

    let bundle_started = Instant::now();
    let bundled = Box::pin(self.bundle(entry_paths, cwd)).await?;
    let bundle_elapsed = bundle_started.elapsed();
    let (code, map_json, mut modules) = (bundled.code, bundled.source_map_json, bundled.modules);
    modules.extend(bundled.config_inputs);

    let compile_started = Instant::now();
    let compiled = self.compile_source(&code, &module_name, map_json.as_deref()).await?;
    let compile_elapsed = compile_started.elapsed();

    let store_started = Instant::now();
    let inputs = crate::cache::input_set(entry_paths, &modules);
    self.cache.store(
      cache_key,
      &compiled.bytecode,
      &module_name,
      map_json.as_deref(),
      None,
      &inputs,
    );
    let store_elapsed = store_started.elapsed();

    tracing::debug!(
      target: "ferrijs::bundle",
      module = %module_name,
      entries = entry_paths.len(),
      modules = modules.len(),
      code_bytes = code.len(),
      map_bytes = map_json.as_ref().map_or(0, String::len),
      bytecode_bytes = compiled.bytecode.len(),
      probe_ms = probe_elapsed.as_secs_f64() * 1000.0,
      bundle_ms = bundle_elapsed.as_secs_f64() * 1000.0,
      compile_ms = compile_elapsed.as_secs_f64() * 1000.0,
      store_ms = store_elapsed.as_secs_f64() * 1000.0,
      "bundle cold path"
    );

    Ok(compiled)
  }

  /// Compile already-bundled ESM `code` to `QuickJS` bytecode.
  ///
  /// Split out of [`Self::compile`] because bundling and compiling can
  /// happen in different processes: a client bundles (its working
  /// directory is the one relative imports resolve against) and a host
  /// compiles (its `QuickJS` build is the one that will load the
  /// bytecode), so bytecode never crosses the wire between differently-
  /// built binaries.
  ///
  /// Does not touch the disk cache: the caller owns the key, because
  /// only it knows which inputs the code was built from.
  ///
  /// # Errors
  ///
  /// [`ScriptError`] if the module fails to declare (a syntax error, or
  /// an import the native loader cannot resolve) or to serialize.
  pub async fn compile_source(
    &self,
    code: &str,
    module_name: &str,
    source_map_json: Option<&str>,
  ) -> Result<CompiledModule, ScriptError> {
    let name = module_name.to_string();
    let code = code.to_string();
    let rt_started = Instant::now();
    let runtime = AsyncRuntime::new().map_err(|e| ScriptError::internal(format!("bytecode runtime: {e}")))?;
    // QuickJS resolves the module graph EAGERLY at declare, and the
    // bundle keeps native specifiers external — so even this throwaway
    // compile runtime needs the native resolver/loader. The written
    // bytecode stores the dependency by NAME and re-links against the
    // loading realm's own ModuleDefs. Externals the host serves at load
    // time are declared empty here: linking happens at eval, so an empty
    // module is enough to let a consumer's import resolve while it is
    // being compiled.
    let (resolver, loader) = self.registry.loader();
    let externals = ExternalStubs(self.options.externals.clone());
    runtime
      .set_loader((resolver, externals.clone()), (loader, externals))
      .await;
    let ctx = AsyncContext::full(&runtime)
      .await
      .map_err(|e| ScriptError::internal(format!("bytecode context: {e}")))?;
    let rt_elapsed = rt_started.elapsed();
    let bytecode: Vec<u8> = ctx
      .async_with(async |ctx| {
        // The bundle's only remaining imports are the external native
        // specifiers, resolved by the loader installed above.
        let declare_started = Instant::now();
        let module = Module::declare(ctx.clone(), name.into_bytes(), code.into_bytes())
          .catch(&ctx)
          .map_err(|e| ScriptError::from_caught_unmapped(e, "", 0))?;
        let declare_elapsed = declare_started.elapsed();
        let write_started = Instant::now();
        let out = module
          .write(WriteOptions {
            endianness: WriteOptionsEndianness::Native,
            ..Default::default()
          })
          .map_err(|e| ScriptError::internal(format!("module write: {e}")));
        tracing::debug!(
          target: "ferrijs::bundle",
          runtime_ms = rt_elapsed.as_secs_f64() * 1000.0,
          declare_ms = declare_elapsed.as_secs_f64() * 1000.0,
          write_ms = write_started.elapsed().as_secs_f64() * 1000.0,
          "bundle compile split"
        );
        out
      })
      .await?;

    Ok(CompiledModule {
      module_name: module_name.to_string(),
      bytecode: Arc::from(bytecode.into_boxed_slice()),
      source_map: LazyMap::from_json(source_map_json),
      // This path is handed code that was already bundled elsewhere, so
      // only the caller knows what its map's paths are relative to; it
      // sets `cwd` if the answer is not the process's.
      cwd: None,
    })
  }
}

/// Resolver/loader for the host-served externals in a throwaway compile
/// realm: each declares as an empty module so the entry links.
#[derive(Clone)]
struct ExternalStubs(Vec<String>);

impl rquickjs::loader::Resolver for ExternalStubs {
  fn resolve<'js>(
    &mut self,
    _ctx: &rquickjs::Ctx<'js>,
    base: &str,
    name: &str,
    _attributes: Option<rquickjs::loader::ImportAttributes<'js>>,
  ) -> rquickjs::Result<String> {
    if self.0.iter().any(|e| e == name) {
      Ok(name.to_string())
    } else {
      Err(rquickjs::Error::new_resolving(base, name))
    }
  }
}

impl rquickjs::loader::Loader for ExternalStubs {
  fn load<'js>(
    &mut self,
    ctx: &rquickjs::Ctx<'js>,
    name: &str,
    _attributes: Option<rquickjs::loader::ImportAttributes<'js>>,
  ) -> rquickjs::Result<Module<'js>> {
    if self.0.iter().any(|e| e == name) {
      Module::declare(ctx.clone(), name, "export {};\n")
    } else {
      Err(rquickjs::Error::new_loading(name))
    }
  }
}

/// True when a path's extension marks it as TypeScript (`.ts`/`.tsx`/
/// `.mts`/`.cts`) and so must be transpiled through the bundler.
#[must_use]
pub fn is_typescript_path(path: &Path) -> bool {
  matches!(
    path.extension().and_then(|e| e.to_str()),
    Some("ts" | "tsx" | "mts" | "cts")
  )
}

/// Heuristic: the source begins a line with a static `import`/`export`
/// and so must run as an ES module (bundled). Dynamic `import(...)` is
/// intentionally NOT matched — it is valid in a plain script, so such a
/// script keeps top-level `return`. A false positive only costs an
/// unnecessary bundle, never wrong output.
#[must_use]
pub fn source_is_es_module(source: &str) -> bool {
  source.lines().any(|line| {
    let t = line.trim_start();
    let static_import = t
      .strip_prefix("import")
      .is_some_and(|rest| matches!(rest.as_bytes().first(), Some(b' ' | b'\t' | b'{' | b'\'' | b'"')));
    static_import
      || t.starts_with("export ")
      || t.starts_with("export\t")
      || t.starts_with("export{")
      || t.starts_with("export*")
  })
}
