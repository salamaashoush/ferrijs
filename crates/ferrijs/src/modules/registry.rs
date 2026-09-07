//! The native modules a realm serves, and the one table they come from.
//!
//! A native module is a Rust [`ModuleDef`] the ES loader declares by
//! name -- no generated JS glue, no bundled source. A bundler marks
//! these specifiers external, so the emitted chunk keeps the bare
//! `import ... from 'node:fs'` and the written bytecode re-links by NAME
//! against whatever realm loads it. `QuickJS` resolves the module graph
//! EAGERLY at declare time, so a throwaway compile realm must register
//! the same names as the realm that will run the result; both read this
//! table.
//!
//! Every module is served twice from one definition: as an ES module,
//! and as the object `require('<specifier>')` hands back, so a host
//! cannot wire up the import form and forget the CommonJS one.

use std::sync::Arc;

use rquickjs::loader::{BuiltinResolver, ImportAttributes, Loader, Resolver};
use rquickjs::module::ModuleDef;
use rquickjs::{Ctx, Module, Object};

/// How a module is declared to the ES loader.
pub type DeclareFn = Arc<dyn for<'js> Fn(Ctx<'js>, Vec<u8>) -> rquickjs::Result<Module<'js>> + Send + Sync>;

/// How the object `require('<specifier>')` returns is built.
pub type NamespaceFn = Arc<dyn for<'js> Fn(&Ctx<'js>) -> rquickjs::Result<Object<'js>> + Send + Sync>;

/// One module, under every specifier it answers to.
#[derive(Clone)]
pub struct NativeModule {
  /// Every name this module is imported by. The first is canonical;
  /// the rest are the same module under other spellings (`fs` and
  /// `node:fs`), so an import of any of them links to one instance.
  pub specifiers: Vec<String>,
  pub declare: DeclareFn,
  pub namespace: NamespaceFn,
}

impl std::fmt::Debug for NativeModule {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("NativeModule")
      .field("specifiers", &self.specifiers)
      .finish_non_exhaustive()
  }
}

impl NativeModule {
  /// A module from a [`ModuleDef`] and a `require` namespace builder.
  pub fn new<D, N>(specifiers: impl IntoIterator<Item = impl Into<String>>, namespace: N) -> Self
  where
    D: ModuleDef,
    N: for<'js> Fn(&Ctx<'js>) -> rquickjs::Result<Object<'js>> + Send + Sync + 'static,
  {
    Self {
      specifiers: specifiers.into_iter().map(Into::into).collect(),
      declare: Arc::new(|ctx, name| Module::declare_def::<D, _>(ctx, name)),
      namespace: Arc::new(namespace),
    }
  }

  /// A module whose `require` form is the ES module's own namespace,
  /// evaluated on demand. For a module built entirely inside its
  /// `evaluate`, with no Rust-side object to borrow.
  pub fn from_def<D: ModuleDef>(specifiers: impl IntoIterator<Item = impl Into<String>>) -> Self {
    let specifiers: Vec<String> = specifiers.into_iter().map(Into::into).collect();
    let canonical = specifiers.first().cloned().unwrap_or_default();
    Self {
      specifiers,
      declare: Arc::new(|ctx, name| Module::declare_def::<D, _>(ctx, name)),
      namespace: Arc::new(move |ctx| module_default_object::<D>(ctx, &canonical)),
    }
  }

  #[must_use]
  pub fn canonical(&self) -> &str {
    self.specifiers.first().map_or("", String::as_str)
  }

  #[must_use]
  pub fn answers_to(&self, specifier: &str) -> bool {
    self.specifiers.iter().any(|s| s == specifier)
  }
}

impl From<ferrijs_std::modules::NodeModule> for NativeModule {
  fn from(m: ferrijs_std::modules::NodeModule) -> Self {
    Self {
      specifiers: m.specifiers.iter().map(|s| (*s).to_string()).collect(),
      declare: Arc::new(m.declare),
      namespace: Arc::new(m.namespace),
    }
  }
}

/// Evaluate a module and hand back its `default` export (or, failing
/// that, its whole namespace) as the `require()` object.
fn module_default_object<'js, D: ModuleDef>(ctx: &Ctx<'js>, name: &str) -> rquickjs::Result<Object<'js>> {
  let (module, _promise) = Module::evaluate_def::<D, _>(ctx.clone(), name)?;
  let namespace = module.namespace()?;
  if let Ok(default) = namespace.get::<_, Object<'js>>("default") {
    return Ok(default);
  }
  Ok(namespace)
}

/// Every native module a realm serves, plus the aliases and the names
/// nothing may claim.
///
/// A value, not a process global: two runtimes in one process may serve
/// different tables, and a bundler asked to mark externals reads the
/// table of the runtime that will run its output.
#[derive(Clone, Default)]
pub struct ModuleRegistry {
  modules: Vec<NativeModule>,
  /// `from -> to`: an extra specifier answered by the module `to` names.
  aliases: Vec<(String, String)>,
  /// Specifier prefixes and names reserved for the runtime, beyond the
  /// modules it serves.
  reserved_prefixes: Vec<String>,
  reserved_names: Vec<String>,
}

impl std::fmt::Debug for ModuleRegistry {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ModuleRegistry")
      .field("modules", &self.names())
      .field("aliases", &self.aliases)
      .finish_non_exhaustive()
  }
}

impl ModuleRegistry {
  /// An empty table.
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// The table with every Node / web module the standard library
  /// serves (`node:fs`, `node:path`, `node:buffer`, ...).
  #[must_use]
  pub fn with_std() -> Self {
    let mut registry = Self::new();
    for module in ferrijs_std::modules::modules() {
      registry.modules.push(module.into());
    }
    registry.reserved_prefixes.push("node:".to_string());
    registry
  }

  /// Add a module. A specifier already served is an error: the second
  /// registration would silently shadow the first, and which one won
  /// would depend on registration order.
  ///
  /// # Errors
  ///
  /// When one of the module's specifiers is already served or aliased.
  pub fn register(&mut self, module: NativeModule) -> Result<(), String> {
    for specifier in &module.specifiers {
      if self.serves(specifier) {
        return Err(format!("module `{specifier}` is already served by this runtime"));
      }
    }
    self.modules.push(module);
    Ok(())
  }

  /// [`Self::register`], panicking on a clash. For static tables built
  /// at startup, where a clash is a programming error.
  ///
  /// # Panics
  ///
  /// When a specifier is already served.
  #[must_use]
  pub fn with(mut self, module: NativeModule) -> Self {
    if let Err(e) = self.register(module) {
      panic!("{e}");
    }
    self
  }

  /// Answer `from` with the module `to` names.
  ///
  /// # Errors
  ///
  /// When `from` is already served (an alias may not redirect a native
  /// specifier) or `to` is not.
  pub fn alias(&mut self, from: impl Into<String>, to: impl Into<String>) -> Result<(), String> {
    let (from, to) = (from.into(), to.into());
    if self.modules.iter().any(|m| m.answers_to(&from)) {
      return Err(format!(
        "module alias `{from}`: cannot alias a specifier the runtime already serves natively"
      ));
    }
    if !self.modules.iter().any(|m| m.answers_to(&to)) {
      return Err(format!(
        "module alias `{from}` -> `{to}`: `{to}` is not a native module (expected one of {})",
        self.names().join(", ")
      ));
    }
    match self.aliases.iter_mut().find(|(f, _)| *f == from) {
      Some(entry) => entry.1 = to,
      None => self.aliases.push((from, to)),
    }
    Ok(())
  }

  /// Reserve a specifier prefix (`@acme/`) so nothing else may claim a
  /// name under it.
  pub fn reserve_prefix(&mut self, prefix: impl Into<String>) {
    self.reserved_prefixes.push(prefix.into());
  }

  /// Reserve one specifier.
  pub fn reserve_name(&mut self, name: impl Into<String>) {
    self.reserved_names.push(name.into());
  }

  /// Every specifier served natively, aliases included.
  #[must_use]
  pub fn names(&self) -> Vec<String> {
    let mut names: Vec<String> = self.modules.iter().flat_map(|m| m.specifiers.clone()).collect();
    names.extend(self.aliases.iter().map(|(from, _)| from.clone()));
    names
  }

  #[must_use]
  pub fn modules(&self) -> &[NativeModule] {
    &self.modules
  }

  #[must_use]
  pub fn aliases(&self) -> &[(String, String)] {
    &self.aliases
  }

  /// Whether `specifier` is served, directly or through an alias.
  #[must_use]
  pub fn serves(&self, specifier: &str) -> bool {
    self.canonical(specifier).is_some()
  }

  /// The canonical name of the module `specifier` resolves to: the
  /// module's first specifier, so two spellings of one module compare
  /// equal.
  #[must_use]
  pub fn canonical(&self, specifier: &str) -> Option<String> {
    let target = self
      .aliases
      .iter()
      .find(|(from, _)| from == specifier)
      .map_or(specifier, |(_, to)| to.as_str());
    self
      .modules
      .iter()
      .find(|m| m.answers_to(target))
      .map(|m| m.canonical().to_string())
  }

  /// Whether `specifier` is off-limits to anything outside the runtime:
  /// served, reserved by name, under a reserved prefix, or the bare twin
  /// of a served `node:` name (a claim on `fs` while the runtime serves
  /// `node:fs` is the same hijack spelled differently).
  #[must_use]
  pub fn is_reserved(&self, specifier: &str) -> bool {
    if self.serves(specifier) || self.reserved_names.iter().any(|n| n == specifier) {
      return true;
    }
    if self.reserved_prefixes.iter().any(|p| specifier.starts_with(p)) {
      return true;
    }
    self
      .names()
      .iter()
      .any(|name| name.strip_prefix("node:") == Some(specifier))
  }

  /// A stable fingerprint of the served names and aliases, for a cache
  /// key: adding or removing a native specifier flips it between
  /// "external bare import" and "resolved into the chunk", which
  /// changes a bundle's output for byte-identical inputs.
  #[must_use]
  pub fn fingerprint(&self) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut names = self.names();
    names.sort();
    let mut aliases = self.aliases.clone();
    aliases.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    names.hash(&mut h);
    aliases.hash(&mut h);
    h.finish()
  }

  fn module_for(&self, specifier: &str) -> Option<&NativeModule> {
    let canonical = self.canonical(specifier)?;
    self.modules.iter().find(|m| m.canonical() == canonical)
  }

  /// The object `require(specifier)` returns, or `None` for a specifier
  /// this table does not serve.
  ///
  /// # Errors
  ///
  /// Propagates the module's own namespace construction.
  pub fn namespace<'js>(&self, ctx: &Ctx<'js>, specifier: &str) -> rquickjs::Result<Option<Object<'js>>> {
    match self.module_for(specifier) {
      Some(module) => (module.namespace)(ctx).map(Some),
      None => Ok(None),
    }
  }

  /// The resolver / loader pair for this table, to chain ahead of a file
  /// loader in `AsyncRuntime::set_loader`.
  #[must_use]
  pub fn loader(self: &Arc<Self>) -> (NativeResolver, NativeLoader) {
    let mut builtin = BuiltinResolver::default();
    for name in self.names() {
      builtin.add_module(name);
    }
    (
      NativeResolver {
        builtin,
        registry: Arc::clone(self),
      },
      NativeLoader {
        registry: Arc::clone(self),
      },
    )
  }
}

/// Accepts exactly the served specifiers and aliases.
pub struct NativeResolver {
  builtin: BuiltinResolver,
  registry: Arc<ModuleRegistry>,
}

impl Resolver for NativeResolver {
  fn resolve<'js>(
    &mut self,
    ctx: &Ctx<'js>,
    base: &str,
    name: &str,
    attributes: Option<ImportAttributes<'js>>,
  ) -> rquickjs::Result<String> {
    // The resolver answers with the specifier as written (not the
    // canonical name): `QuickJS` keys module instances by the resolved
    // name, and the loader declares the same `ModuleDef` under each
    // spelling, so `import 'fs'` and `import 'node:fs'` each link to a
    // module whose exports are the same objects.
    let _ = &self.registry;
    self.builtin.resolve(ctx, base, name, attributes)
  }
}

/// Non-consuming native module loader. `rquickjs::loader::ModuleLoader`
/// REMOVES an entry on first load, which breaks the second context on a
/// shared runtime (and any re-link); `QuickJS` only calls the loader once
/// per name per context, but the loader itself should not be single-shot.
pub struct NativeLoader {
  registry: Arc<ModuleRegistry>,
}

impl Loader for NativeLoader {
  fn load<'js>(
    &mut self,
    ctx: &Ctx<'js>,
    path: &str,
    _attributes: Option<ImportAttributes<'js>>,
  ) -> rquickjs::Result<Module<'js>> {
    let module = self
      .registry
      .module_for(path)
      .ok_or_else(|| rquickjs::Error::new_loading(path))?;
    (module.declare)(ctx.clone(), Vec::from(path))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct Dummy;
  impl ModuleDef for Dummy {
    fn declare(decl: &rquickjs::module::Declarations<'_>) -> rquickjs::Result<()> {
      decl.declare("x")?;
      Ok(())
    }
    fn evaluate<'js>(_ctx: &Ctx<'js>, exports: &rquickjs::module::Exports<'js>) -> rquickjs::Result<()> {
      exports.export("x", 1)?;
      Ok(())
    }
  }

  #[test]
  fn std_table_serves_node_modules_under_both_spellings() {
    let r = ModuleRegistry::with_std();
    assert!(r.serves("fs"));
    assert!(r.serves("node:fs"));
    assert_eq!(r.canonical("node:fs").as_deref(), Some("fs"));
    assert!(r.is_reserved("node:anything"));
    assert!(!r.serves("lodash"));
  }

  #[test]
  fn register_refuses_a_clash_and_alias_refuses_a_redirect() {
    let mut r = ModuleRegistry::with_std();
    assert!(r.register(NativeModule::from_def::<Dummy>(["fs"])).is_err());
    r.register(NativeModule::from_def::<Dummy>(["acme"])).unwrap();
    assert!(r.alias("fs", "acme").is_err());
    assert!(r.alias("acme2", "nope").is_err());
    r.alias("acme2", "acme").unwrap();
    assert_eq!(r.canonical("acme2").as_deref(), Some("acme"));
    assert!(r.is_reserved("acme2"));
  }

  #[test]
  fn fingerprint_ignores_order() {
    let mut a = ModuleRegistry::new();
    a.register(NativeModule::from_def::<Dummy>(["one"])).unwrap();
    a.register(NativeModule::from_def::<Dummy>(["two"])).unwrap();
    let mut b = ModuleRegistry::new();
    b.register(NativeModule::from_def::<Dummy>(["two"])).unwrap();
    b.register(NativeModule::from_def::<Dummy>(["one"])).unwrap();
    assert_eq!(a.fingerprint(), b.fingerprint());
    b.alias("three", "one").unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
  }
}
