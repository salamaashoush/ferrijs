//! The locale-sensitive methods of the language's own prototypes, which
//! ECMA-402 redefines over `Intl`.

use rquickjs::convert::Coerced;
use rquickjs::object::Property;
use rquickjs::{Ctx, Exception, Function, Object, Result, Value};

pub(crate) fn install(ctx: &Ctx<'_>) -> Result<()> {
  let string: Object<'_> = prototype(ctx, "String")?;
  method(ctx, &string, "localeCompare", 1, crate::collator::locale_compare)?;
  method(ctx, &string, "toLocaleUpperCase", 0, to_locale_upper_case)?;
  method(ctx, &string, "toLocaleLowerCase", 0, to_locale_lower_case)?;
  let number = prototype(ctx, "Number")?;
  method(
    ctx,
    &number,
    "toLocaleString",
    0,
    crate::number_format::number_to_locale_string,
  )?;
  let bigint = prototype(ctx, "BigInt")?;
  method(
    ctx,
    &bigint,
    "toLocaleString",
    0,
    crate::number_format::bigint_to_locale_string,
  )?;
  let date = prototype(ctx, "Date")?;
  method(
    ctx,
    &date,
    "toLocaleString",
    0,
    crate::date_time_format::to_locale_string,
  )?;
  method(
    ctx,
    &date,
    "toLocaleDateString",
    0,
    crate::date_time_format::to_locale_date_string,
  )?;
  method(
    ctx,
    &date,
    "toLocaleTimeString",
    0,
    crate::date_time_format::to_locale_time_string,
  )?;
  Ok(())
}

fn prototype<'js>(ctx: &Ctx<'js>, name: &str) -> Result<Object<'js>> {
  let constructor: Object<'js> = ctx.globals().get(name)?;
  constructor.get("prototype")
}

fn method<'js, P, F>(ctx: &Ctx<'js>, target: &Object<'js>, name: &str, length: u32, f: F) -> Result<()>
where
  F: rquickjs::function::IntoJsFunc<'js, P> + 'js,
{
  let function = Function::new(ctx.clone(), f)?
    .with_name(name)?
    .with_length(length as usize)?;
  target.prop(name, Property::from(function).writable().configurable())
}

/// `RequireObjectCoercible(this)` then `ToString(this)`.
pub(crate) fn this_string(ctx: &Ctx<'_>, this: &Value<'_>, method: &str) -> Result<String> {
  if this.is_undefined() || this.is_null() {
    return Err(Exception::throw_type(
      ctx,
      &format!("String.prototype.{method} called on null or undefined"),
    ));
  }
  Ok(this.get::<Coerced<String>>()?.0)
}

/// `thisNumberValue` / `thisBigIntValue`: the primitive, unwrapped from
/// its wrapper object.
pub(crate) fn this_primitive<'js>(ctx: &Ctx<'js>, this: &Value<'js>, kind: &str) -> Result<Value<'js>> {
  if this.is_object() {
    let value_of: Function<'js> = prototype(ctx, kind)?.get("valueOf")?;
    return value_of.call((rquickjs::function::This(this.clone()),));
  }
  Ok(this.clone())
}

/// `TransformCase(S, locales, upper)`: the first requested locale's
/// language picks the tailoring (Turkish dotted I, Lithuanian dots,
/// Greek accents), as ECMA-402 specifies.
fn transform_case<'js>(
  ctx: &Ctx<'js>,
  this: &Value<'js>,
  locales: Option<&Value<'js>>,
  upper: bool,
  method: &str,
) -> Result<String> {
  let text = this_string(ctx, this, method)?;
  let requested = crate::locale::canonicalize_list(ctx, locales)?;
  let language = match requested.first() {
    Some(locale) => locale.id.clone(),
    None => crate::state::state(ctx)?.default_locale.id.clone(),
  };
  let mapper = icu::casemap::CaseMapper::new();
  Ok(if upper {
    mapper.uppercase_to_string(&text, &language).into_owned()
  } else {
    mapper.lowercase_to_string(&text, &language).into_owned()
  })
}

fn to_locale_upper_case<'js>(
  ctx: Ctx<'js>,
  this: rquickjs::function::This<Value<'js>>,
  locales: rquickjs::function::Opt<Value<'js>>,
) -> Result<String> {
  transform_case(&ctx, &this.0, locales.0.as_ref(), true, "toLocaleUpperCase")
}

fn to_locale_lower_case<'js>(
  ctx: Ctx<'js>,
  this: rquickjs::function::This<Value<'js>>,
  locales: rquickjs::function::Opt<Value<'js>>,
) -> Result<String> {
  transform_case(&ctx, &this.0, locales.0.as_ref(), false, "toLocaleLowerCase")
}
