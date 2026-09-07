//! How a host adds its own API to a realm.
//!
//! An extension is a unit of host surface: the native modules it serves,
//! the globals it installs, and any module sources or `require` answers
//! it contributes. The runtime asks each extension in the order they
//! were added, so one that depends on another's globals is added after
//! it.
//!
//! Extensions install once, at realm creation. A host that must refresh
//! a global per run (a handle that changes between calls) does so in
//! the body it hands to [`crate::Runtime::run`], where it has the
//! context anyway.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rquickjs::Ctx;

use crate::modules::{BoxLoader, BoxResolver, ModuleRegistry, RequireHook};

/// A unit of host surface.
pub trait Extension: Send + Sync {
  /// For diagnostics.
  fn name(&self) -> &str;

  /// Native modules this extension serves. Registered before the realm
  /// exists, so a bundler and the loader see one table.
  ///
  /// # Errors
  ///
  /// A specifier already served (see [`ModuleRegistry::register`]).
  fn modules(&self, _registry: &mut ModuleRegistry) -> Result<(), String> {
    Ok(())
  }

  /// Resolver/loader pairs consulted after the native registry and
  /// before the file loader.
  fn loaders(&self) -> Vec<(BoxResolver, BoxLoader)> {
    Vec::new()
  }

  /// Something that answers `require()` ahead of the registry.
  fn require_hook(&self) -> Option<Arc<dyn RequireHook>> {
    None
  }

  /// Install globals, once per realm. The synchronous form; most
  /// extensions need nothing else.
  ///
  /// # Errors
  ///
  /// Propagates the installs.
  fn install(&self, _ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    Ok(())
  }

  /// [`Self::install`] for an extension whose install awaits (one that
  /// evaluates a module, say). Runs on the VM loop; the default calls
  /// the synchronous form.
  fn install_async<'js>(&self, ctx: Ctx<'js>) -> Pin<Box<dyn Future<Output = rquickjs::Result<()>> + 'js>> {
    let out = self.install(&ctx);
    Box::pin(async move { out })
  }
}

/// An extension made of closures, for a host with one global to add.
pub struct FnExtension<F> {
  name: String,
  install: F,
}

impl<F> FnExtension<F>
where
  F: for<'js> Fn(&Ctx<'js>) -> rquickjs::Result<()> + Send + Sync,
{
  pub fn new(name: impl Into<String>, install: F) -> Self {
    Self {
      name: name.into(),
      install,
    }
  }
}

impl<F> Extension for FnExtension<F>
where
  F: for<'js> Fn(&Ctx<'js>) -> rquickjs::Result<()> + Send + Sync,
{
  fn name(&self) -> &str {
    &self.name
  }

  fn install(&self, ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    (self.install)(ctx)
  }
}
