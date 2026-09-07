//! How a realm finds the modules a program imports.
//!
//! Three sources, consulted in order: the [`ModuleRegistry`] of native
//! modules (the standard library plus whatever extensions serve), any
//! resolver/loader pairs the host chained in, and finally files on disk
//! under a [`ModulePolicy`]. The same registry backs `require()`, so the
//! CommonJS and ES forms of a native module cannot drift.

pub mod file;
pub mod registry;
pub mod require;

pub use file::{FileLoader, FileResolver, ModulePolicy};
pub use registry::{DeclareFn, ModuleRegistry, NamespaceFn, NativeLoader, NativeModule, NativeResolver};
pub use require::RequireHook;

use rquickjs::loader::{ImportAttributes, Loader, Resolver};
use rquickjs::{Ctx, Module};

/// A resolver a host supplies at runtime, erased so the builder can
/// hold any number of them.
pub type BoxResolver = Box<dyn Resolver + Send>;
/// A loader a host supplies at runtime.
pub type BoxLoader = Box<dyn Loader + Send>;

/// A chain of host-supplied resolvers, tried in order.
pub struct ResolverChain(pub Vec<BoxResolver>);

impl Resolver for ResolverChain {
  fn resolve<'js>(
    &mut self,
    ctx: &Ctx<'js>,
    base: &str,
    name: &str,
    attributes: Option<ImportAttributes<'js>>,
  ) -> rquickjs::Result<String> {
    let mut last = rquickjs::Error::new_resolving(base, name);
    for resolver in &mut self.0 {
      match resolver.resolve(ctx, base, name, attributes.clone()) {
        Ok(resolved) => return Ok(resolved),
        Err(e) => last = e,
      }
    }
    Err(last)
  }
}

/// A chain of host-supplied loaders, tried in order.
pub struct LoaderChain(pub Vec<BoxLoader>);

impl Loader for LoaderChain {
  fn load<'js>(
    &mut self,
    ctx: &Ctx<'js>,
    name: &str,
    attributes: Option<ImportAttributes<'js>>,
  ) -> rquickjs::Result<Module<'js>> {
    let mut last = rquickjs::Error::new_loading(name);
    for loader in &mut self.0 {
      match loader.load(ctx, name, attributes.clone()) {
        Ok(module) => return Ok(module),
        Err(e) => last = e,
      }
    }
    Err(last)
  }
}
