//! The option readers ECMA-402 shares between its constructors
//! (`GetOption`, `GetBooleanOrStringNumberFormatOption`,
//! `DefaultNumberOption`, `GetOptionsObject`, `CoerceOptionsToObject`).
//!
//! Each one reads the property once, in the order the caller asks for
//! it: a getter on the options bag sees the reads the spec makes, in the
//! spec's order, which test262 checks.

use rquickjs::convert::Coerced;
use rquickjs::{Ctx, Exception, Function, Object, Result, Value};

/// `GetOptionsObject`: `undefined` reads as an empty bag, an object as
/// itself, anything else is a `TypeError`.
pub(crate) fn options_object<'js>(ctx: &Ctx<'js>, value: Option<Value<'js>>) -> Result<Option<Object<'js>>> {
  match value {
    None => Ok(None),
    Some(value) if value.is_undefined() => Ok(None),
    Some(value) => match value.into_object() {
      Some(object) => Ok(Some(object)),
      None => Err(Exception::throw_type(ctx, "options must be an object")),
    },
  }
}

/// `CoerceOptionsToObject`: `ToObject`, which the older constructors
/// (`Collator`, `NumberFormat`, `DateTimeFormat`) use, so a primitive
/// reads its wrapper's prototype and `null` throws.
pub(crate) fn coerce_options<'js>(ctx: &Ctx<'js>, value: Option<Value<'js>>) -> Result<Option<Object<'js>>> {
  match value {
    None => Ok(None),
    Some(value) if value.is_undefined() => Ok(None),
    Some(value) if value.is_null() => Err(Exception::throw_type(ctx, "cannot convert null to object")),
    Some(value) => {
      if let Some(object) = value.clone().into_object() {
        Ok(Some(object))
      } else {
        let object: Function<'js> = crate::state::object_constructor(ctx)?;
        object.call((value,))
      }
    },
  }
}

/// `GetOption(options, name, string, values, fallback)`.
pub(crate) fn string<'js>(
  ctx: &Ctx<'js>,
  options: Option<&Object<'js>>,
  name: &str,
  values: &[&'static str],
) -> Result<Option<&'static str>> {
  let Some(raw) = string_any(options, name)? else {
    return Ok(None);
  };
  match values.iter().find(|v| **v == raw) {
    Some(v) => Ok(Some(v)),
    None => Err(Exception::throw_range(
      ctx,
      &format!("Value {raw} out of range for option {name}"),
    )),
  }
}

/// `GetOption(options, name, string, empty, undefined)`: any string.
pub(crate) fn string_any<'js>(options: Option<&Object<'js>>, name: &str) -> Result<Option<String>> {
  let Some(options) = options else {
    return Ok(None);
  };
  let value: Value<'js> = options.get(name)?;
  if value.is_undefined() {
    return Ok(None);
  }
  Ok(Some(value.get::<Coerced<String>>()?.0))
}

/// `GetOption(options, name, boolean, empty, undefined)`.
pub(crate) fn boolean<'js>(options: Option<&Object<'js>>, name: &str) -> Result<Option<bool>> {
  let Some(options) = options else {
    return Ok(None);
  };
  let value: Value<'js> = options.get(name)?;
  if value.is_undefined() {
    return Ok(None);
  }
  Ok(Some(value.get::<Coerced<bool>>()?.0))
}

/// `GetNumberOption(options, name, minimum, maximum, fallback)`.
pub(crate) fn number<'js>(
  ctx: &Ctx<'js>,
  options: Option<&Object<'js>>,
  name: &str,
  minimum: i32,
  maximum: i32,
) -> Result<Option<i32>> {
  let Some(options) = options else {
    return Ok(None);
  };
  let value: Value<'js> = options.get(name)?;
  default_number(ctx, &value, name, minimum, maximum)
}

/// `DefaultNumberOption(value, minimum, maximum, fallback)`.
pub(crate) fn default_number<'js>(
  ctx: &Ctx<'js>,
  value: &Value<'js>,
  name: &str,
  minimum: i32,
  maximum: i32,
) -> Result<Option<i32>> {
  if value.is_undefined() {
    return Ok(None);
  }
  let number = value.get::<Coerced<f64>>()?.0;
  if number.is_nan() || number < f64::from(minimum) || number > f64::from(maximum) {
    return Err(Exception::throw_range(ctx, &format!("{name} value is out of range.")));
  }
  Ok(Some(number.floor() as i32))
}

/// `GetOption(options, "localeMatcher", ...)`: read and validated, and
/// otherwise unused, since both matchers resolve the same way here.
pub(crate) fn locale_matcher<'js>(ctx: &Ctx<'js>, options: Option<&Object<'js>>) -> Result<()> {
  string(ctx, options, "localeMatcher", &["lookup", "best fit"]).map(|_| ())
}

/// A Unicode extension type value as an option gives it (`numberingSystem`,
/// `calendar`, `collation`): one or more 3-8 alphanumeric segments joined
/// by `-`, or a `RangeError`.
pub(crate) fn unicode_type<'js>(ctx: &Ctx<'js>, options: Option<&Object<'js>>, name: &str) -> Result<Option<String>> {
  let Some(value) = string_any(options, name)? else {
    return Ok(None);
  };
  let well_formed = !value.is_empty()
    && value
      .split('-')
      .all(|part| (3..=8).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric()));
  if well_formed {
    Ok(Some(value.to_ascii_lowercase()))
  } else {
    Err(Exception::throw_range(ctx, &format!("Invalid {name}: {value}")))
  }
}
