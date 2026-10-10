//! The max-listener API Node's `EventEmitter` has and the vendored one
//! does not: `setMaxListeners`, `getMaxListeners`, `defaultMaxListeners`
//! and their static forms, after Node's `lib/events.js`. Libraries call
//! `setMaxListeners` in a constructor (winston's console transport), so
//! its absence was a `not a function` at load.
//!
//! Only the bookkeeping: Node also prints a leak warning past the limit,
//! which needs a process warning channel this runtime does not have.

use rquickjs::function::{Opt, Rest, This};
use rquickjs::object::Accessor;
use rquickjs::{Ctx, Function, Object, Result, Value};

use super::coded;

const DEFAULT_MAX_LISTENERS: f64 = 10.0;

/// `validateNumber(n, name, 0)`.
fn non_negative(ctx: &Ctx<'_>, value: &Value<'_>, name: &str) -> Result<f64> {
  let Some(n) = value.as_number() else {
    return Err(coded(
      ctx,
      "TypeError",
      "ERR_INVALID_ARG_TYPE",
      &format!("The \"{name}\" argument must be of type number"),
    ));
  };
  if n.is_nan() || n < 0.0 {
    return Err(coded(
      ctx,
      "RangeError",
      "ERR_OUT_OF_RANGE",
      &format!("The value of \"{name}\" is out of range. It must be a non-negative number. Received {n}"),
    ));
  }
  Ok(n)
}

/// Add the API to `constructor` and its prototype.
///
/// # Errors
///
/// Propagates the property definitions.
pub fn install<'js>(ctx: &Ctx<'js>, constructor: &Object<'js>) -> Result<()> {
  let prototype: Object<'js> = constructor.get("prototype")?;
  let default_store = Object::new(ctx.clone())?;
  default_store.set("value", DEFAULT_MAX_LISTENERS)?;

  prototype.set(
    "setMaxListeners",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, this: This<Object<'js>>, n: Value<'js>| -> Result<Object<'js>> {
      let n = non_negative(&ctx, &n, "n")?;
      this.0.set("_maxListeners", n)?;
      Ok(this.0)
    })?,
  )?;
  let store = default_store.clone();
  prototype.set(
    "getMaxListeners",
    Function::new(ctx.clone(), move |this: This<Object<'js>>| -> Result<Value<'js>> {
      let own: Value<'js> = this.0.get("_maxListeners")?;
      if own.is_undefined() {
        return store.get("value");
      }
      Ok(own)
    })?,
  )?;

  let read = default_store.clone();
  let write = default_store.clone();
  constructor.prop(
    "defaultMaxListeners",
    Accessor::new(
      move || -> Result<Value<'js>> { read.get("value") },
      move |ctx: Ctx<'js>, n: Value<'js>| -> Result<()> {
        let n = non_negative(&ctx, &n, "defaultMaxListeners")?;
        write.set("value", n)
      },
    )
    .enumerable()
    .configurable(),
  )?;

  let store = default_store.clone();
  constructor.set(
    "setMaxListeners",
    Function::new(
      ctx.clone(),
      move |ctx: Ctx<'js>, n: Opt<Value<'js>>, targets: Rest<Value<'js>>| -> Result<()> {
        let n = match n.0 {
          Some(n) if !n.is_undefined() => non_negative(&ctx, &n, "n")?,
          _ => store.get::<_, f64>("value")?,
        };
        if targets.0.is_empty() {
          return store.set("value", n);
        }
        for target in targets.0 {
          let setter = target
            .as_object()
            .and_then(|t| t.get::<_, Function<'js>>("setMaxListeners").ok());
          let Some(setter) = setter else {
            return Err(coded(
              &ctx,
              "TypeError",
              "ERR_INVALID_ARG_TYPE",
              "The \"eventTargets\" argument must be an instance of EventEmitter or EventTarget",
            ));
          };
          setter.call::<_, Value<'js>>((rquickjs::function::This(target.clone()), n))?;
        }
        Ok(())
      },
    )?,
  )?;
  constructor.set(
    "getMaxListeners",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, target: Value<'js>| -> Result<Value<'js>> {
      let getter = target
        .as_object()
        .and_then(|t| t.get::<_, Function<'js>>("getMaxListeners").ok());
      match getter {
        Some(getter) => getter.call((rquickjs::function::This(target.clone()),)),
        None => Err(coded(
          &ctx,
          "TypeError",
          "ERR_INVALID_ARG_TYPE",
          "The \"emitter\" argument must be an instance of EventEmitter or EventTarget",
        )),
      }
    })?,
  )?;
  Ok(())
}
