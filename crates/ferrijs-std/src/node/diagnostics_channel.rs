//! `node:diagnostics_channel`, from Node 24's own implementation adapted
//! to run without Node's internals (`diagnostics_channel.js`).
//!
//! Loggers and HTTP clients publish to it and APM agents subscribe, so a
//! library like pino imports it at load. Every specifier and `require`
//! in a realm share one instance: a channel subscribed to through one is
//! the channel published to through the other.

use rquickjs::module::{Declarations, Exports, ModuleDef};
use rquickjs::{Ctx, JsLifetime, Object, Result, Value};

use super::bundled::Bundled;

static DIAGNOSTICS_CHANNEL: Bundled =
  Bundled::new("ferrijs:diagnostics_channel", include_str!("diagnostics_channel.js"));

const EXPORTS: &[&str] = &["channel", "hasSubscribers", "subscribe", "tracingChannel", "unsubscribe", "Channel"];

#[derive(JsLifetime)]
struct Instance<'js>(Object<'js>);

/// `require('diagnostics_channel')`.
pub(crate) fn namespace<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  if let Some(instance) = ctx.userdata::<Instance<'js>>() {
    return Ok(instance.0.clone());
  }
  let exports: Object<'js> = DIAGNOSTICS_CHANNEL.evaluate(ctx)?.get()?;
  let _ = ctx.store_userdata(Instance(exports.clone()));
  Ok(exports)
}

pub struct DiagnosticsChannelModule;

impl ModuleDef for DiagnosticsChannelModule {
  fn declare(declare: &Declarations<'_>) -> Result<()> {
    declare.declare("default")?;
    for name in EXPORTS {
      declare.declare(*name)?;
    }
    Ok(())
  }

  fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> Result<()> {
    let from = namespace(ctx)?;
    exports.export("default", from.clone())?;
    for name in EXPORTS {
      exports.export(*name, from.get::<_, Value<'js>>(*name)?)?;
    }
    Ok(())
  }
}
