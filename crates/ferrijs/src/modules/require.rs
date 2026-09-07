//! `globalThis.require`, for the native specifiers only.
//!
//! A CommonJS source (`const { x } = require('node:fs')`) is bundled
//! into an `__require("…")` call for any EXTERNAL specifier, and a
//! bundler's helper defers to a global `require` when one exists.
//! Without this the program dies at load with "in an environment that
//! doesn't expose the `require` function". Anything the realm does not
//! serve natively throws: this is a bridge for the native surface, not
//! a general CommonJS loader.
//!
//! `require.resolve(spec)` is Node's, answered relative to the file that
//! WROTE the call (through the source map, since bundling erased it).
//! The walk reads `package.json` files, so it runs under the `read`
//! grant.

use std::sync::Arc;

use rquickjs::{Ctx, Object};

use super::registry::ModuleRegistry;

/// Something that answers `require()` ahead of the registry: a host
/// serving modules of its own (a package's bytecode already evaluated
/// under a specifier).
pub trait RequireHook: Send + Sync {
  /// The object for `specifier`, or `None` to fall through.
  fn namespace<'js>(&self, ctx: &Ctx<'js>, specifier: &str) -> rquickjs::Result<Option<Object<'js>>>;

  /// Whether `require.resolve(specifier)` should answer the specifier
  /// itself, as Node does for a builtin.
  fn is_builtin(&self, _specifier: &str) -> bool {
    false
  }
}

/// Install `globalThis.require`.
///
/// # Errors
///
/// When the global cannot be installed.
pub fn install<'js>(
  ctx: &Ctx<'js>,
  registry: Arc<ModuleRegistry>,
  hooks: Vec<Arc<dyn RequireHook>>,
) -> rquickjs::Result<()> {
  let hooks = Arc::new(hooks);
  let names = registry.names();
  let (reg, hk) = (Arc::clone(&registry), Arc::clone(&hooks));
  let require = rquickjs::Function::new(
    ctx.clone(),
    move |ctx: Ctx<'js>, specifier: String| -> rquickjs::Result<Object<'js>> {
      for hook in hk.iter() {
        if let Some(ns) = hook.namespace(&ctx, &specifier)? {
          return Ok(ns);
        }
      }
      match reg.namespace(&ctx, &specifier)? {
        Some(ns) => Ok(ns),
        None => Err(rquickjs::Exception::throw_type(
          &ctx,
          &format!(
            "require('{specifier}') is not available: only the runtime's native modules ({}) can be require()d",
            names.join(", ")
          ),
        )),
      }
    },
  )?;
  let (reg, hk) = (registry, hooks);
  let resolve = rquickjs::Function::new(ctx.clone(), move |ctx: Ctx<'js>, specifier: String| {
    // Node answers a builtin with the specifier itself.
    if reg.serves(&specifier) || hk.iter().any(|h| h.is_builtin(&specifier)) {
      return Ok(specifier);
    }
    let base = crate::source_map::caller_source_file(&ctx)
      .and_then(|file| file.parent().map(std::path::Path::to_path_buf))
      .or_else(|| std::env::current_dir().ok())
      .unwrap_or_else(|| std::path::PathBuf::from("."));
    ferrijs_std::permissions::check_read(&ctx, &base)?;
    ferrijs_std::node::require_resolve::resolve(&base, &specifier)
      .map(|path| path.to_string_lossy().into_owned())
      .map_err(|message| rquickjs::Exception::throw_message(&ctx, &message))
  })?;
  require.set("resolve", resolve)?;
  ctx.globals().set("require", require)
}
