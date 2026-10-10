//! A module of our own JavaScript, compiled to bytecode once per process
//! and evaluated into a realm only when the realm first asks for it, so a
//! realm that never imports it pays nothing.

use std::sync::OnceLock;

use rquickjs::{Ctx, Module, Result, Value, WriteOptions, WriteOptionsEndianness};

pub(crate) struct Bundled {
  name: &'static str,
  source: &'static str,
  /// Loaded with `JS_READ_OBJ_ROM_DATA`, so the engine may point into
  /// these bytes for as long as a realm lives: the process, here.
  bytecode: OnceLock<Vec<u8>>,
}

impl Bundled {
  pub(crate) const fn new(name: &'static str, source: &'static str) -> Self {
    Self {
      name,
      source,
      bytecode: OnceLock::new(),
    }
  }

  fn bytecode(&'static self, ctx: &Ctx<'_>) -> Result<&'static [u8]> {
    if let Some(bytes) = self.bytecode.get() {
      return Ok(bytes);
    }
    let module = Module::declare(ctx.clone(), self.name, self.source)?;
    let bytes = module.write(WriteOptions {
      endianness: WriteOptionsEndianness::Native,
      ..WriteOptions::default()
    })?;
    Ok(self.bytecode.get_or_init(|| bytes))
  }

  /// The module's default export, from a fresh evaluation in `ctx`. The
  /// caller keeps it, since a second call evaluates the module again.
  pub(crate) fn evaluate<'js>(&'static self, ctx: &Ctx<'js>) -> Result<Value<'js>> {
    let bytes = self.bytecode(ctx)?;
    // SAFETY: the bytes were written by this process's own engine a moment
    // or a realm ago, so the bytecode ABI matches by construction, and they
    // live in a process-wide static, as ROM data must.
    #[allow(unsafe_code)]
    let declared = unsafe { Module::load(ctx.clone(), bytes) }?;
    let (module, _promise) = declared.eval()?;
    module.namespace()?.get("default")
  }
}
