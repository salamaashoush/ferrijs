//! `node:stream` and `node:stream/promises`, from the vendored
//! `readable-stream` (Node's own streams code, see
//! `js/readable-stream/VENDORED.md`).
//!
//! `build.rs` wraps the package into one module. It is compiled to
//! bytecode once per process and loaded into a realm the first time
//! the realm asks for a stream, so a realm that never imports one pays
//! nothing. Every specifier and `require` in a realm gets the same
//! instance, so `require('stream').Readable === (await
//! import('node:stream')).Readable`.

use rquickjs::module::{Declarations, Exports, ModuleDef};
use rquickjs::{Ctx, Function, JsLifetime, Object, Result, Value};

use super::bundled::Bundled;

static READABLE_STREAM: Bundled = Bundled::new(
  "ferrijs:readable-stream",
  include_str!(concat!(env!("OUT_DIR"), "/readable_stream.mjs")),
);

/// The members `node:stream` exports by name, besides `default`.
const STREAM_EXPORTS: &[&str] = &[
  "Readable",
  "Writable",
  "Duplex",
  "Transform",
  "PassThrough",
  "Stream",
  "pipeline",
  "finished",
  "addAbortSignal",
  "compose",
  "destroy",
  "isDestroyed",
  "isDisturbed",
  "isErrored",
  "isReadable",
  "isWritable",
  "setDefaultHighWaterMark",
  "getDefaultHighWaterMark",
  "promises",
  "_isUint8Array",
  "_uint8ArrayToBuffer",
];

const PROMISES_EXPORTS: &[&str] = &["pipeline", "finished"];

/// A realm's instance: the `stream` and `stream/promises` exports.
#[derive(JsLifetime)]
struct Instance<'js> {
  stream: Object<'js>,
  promises: Object<'js>,
}

/// What the package's `require` answers for a name outside it.
fn external<'js>(ctx: Ctx<'js>, name: String) -> Result<Value<'js>> {
  let globals = ctx.globals();
  Ok(match name.as_str() {
    "buffer" => crate::modules::buffer_namespace(&ctx)?.into_value(),
    "events" => crate::modules::events_namespace(&ctx)?.into_value(),
    "string_decoder" => crate::modules::string_decoder_namespace(&ctx)?.into_value(),
    "process" => globals.get("process")?,
    "abort-controller" => {
      let shim = Object::new(ctx.clone())?;
      shim.set("AbortController", globals.get::<_, Value<'js>>("AbortController")?)?;
      shim.set("AbortSignal", globals.get::<_, Value<'js>>("AbortSignal")?)?;
      shim.into_value()
    },
    other => {
      return Err(rquickjs::Exception::throw_message(
        &ctx,
        &format!("readable-stream asked for '{other}', which node:stream does not provide"),
      ));
    },
  })
}

fn instance<'js>(ctx: &Ctx<'js>) -> Result<(Object<'js>, Object<'js>)> {
  if let Some(instance) = ctx.userdata::<Instance<'js>>() {
    return Ok((instance.stream.clone(), instance.promises.clone()));
  }
  let load: Function<'js> = READABLE_STREAM.evaluate(ctx)?.get()?;
  let loaded: Object<'js> = load.call((Function::new(ctx.clone(), external)?,))?;
  let stream: Object<'js> = loaded.get("stream")?;
  let promises: Object<'js> = loaded.get("promises")?;
  // Node 22 raised the default byte-stream high-water mark to 64 KiB;
  // readable-stream 4.8 still starts at 16. Set through its own setter
  // rather than by editing the vendored source.
  let set_default: Function<'js> = stream.get("setDefaultHighWaterMark")?;
  set_default.call::<_, ()>((false, 65_536))?;
  let _ = ctx.store_userdata(Instance {
    stream: stream.clone(),
    promises: promises.clone(),
  });
  Ok((stream, promises))
}

/// `require('stream')`: the `Stream` constructor, as in Node.
pub(crate) fn stream_namespace<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  Ok(instance(ctx)?.0)
}

/// `require('stream/promises')`.
pub(crate) fn promises_namespace<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  Ok(instance(ctx)?.1)
}

fn export_members<'js>(exports: &Exports<'js>, from: &Object<'js>, names: &[&str]) -> Result<()> {
  exports.export("default", from.clone())?;
  for name in names {
    exports.export(*name, from.get::<_, Value<'js>>(*name)?)?;
  }
  Ok(())
}

pub struct StreamModule;

impl ModuleDef for StreamModule {
  fn declare(declare: &Declarations<'_>) -> Result<()> {
    declare.declare("default")?;
    for name in STREAM_EXPORTS {
      declare.declare(*name)?;
    }
    Ok(())
  }

  fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> Result<()> {
    export_members(exports, &stream_namespace(ctx)?, STREAM_EXPORTS)
  }
}

pub struct StreamPromisesModule;

impl ModuleDef for StreamPromisesModule {
  fn declare(declare: &Declarations<'_>) -> Result<()> {
    declare.declare("default")?;
    for name in PROMISES_EXPORTS {
      declare.declare(*name)?;
    }
    Ok(())
  }

  fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> Result<()> {
    export_members(exports, &promises_namespace(ctx)?, PROMISES_EXPORTS)
  }
}
