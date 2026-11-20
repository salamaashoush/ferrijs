//! The `Intl` namespace object.

use rquickjs::atom::PredefinedAtom;
use rquickjs::function::Opt;
use rquickjs::object::Property;
use rquickjs::{Array, Constructor, Ctx, Function, Object, Result, Value};

/// Build `Intl` and define it on `globalThis`, as the lazy group's
/// install does on first read.
pub(crate) fn install(ctx: &Ctx<'_>) -> Result<()> {
  let intl = Object::new(ctx.clone())?;
  intl.prop(PredefinedAtom::SymbolToStringTag, Property::from("Intl").configurable())?;
  let canonical = Function::new(ctx.clone(), get_canonical_locales)?
    .with_name("getCanonicalLocales")?
    .with_length(1)?;
  intl.prop(
    "getCanonicalLocales",
    Property::from(canonical).writable().configurable(),
  )?;

  crate::collator::define(ctx, &intl)?;
  crate::number_format::define(ctx, &intl)?;
  crate::date_time_format::define(ctx, &intl)?;
  crate::plural_rules::define(ctx, &intl)?;
  crate::relative_time_format::define(ctx, &intl)?;
  crate::list_format::define(ctx, &intl)?;
  crate::display_names::define(ctx, &intl)?;
  crate::segmenter::define(ctx, &intl)?;
  crate::locale_object::define(ctx, &intl)?;
  let supported = Function::new(ctx.clone(), supported_values_of)?
    .with_name("supportedValuesOf")?
    .with_length(1)?;
  intl.prop("supportedValuesOf", Property::from(supported).writable().configurable())?;

  ctx
    .globals()
    .prop("Intl", Property::from(intl).writable().configurable())
}

fn get_canonical_locales<'js>(ctx: rquickjs::Ctx<'js>, locales: Opt<Value<'js>>) -> Result<Array<'js>> {
  let list = crate::locale::canonicalize_list(&ctx, locales.0.as_ref())?;
  let array = Array::new(ctx)?;
  for (index, locale) in list.iter().enumerate() {
    array.set(index, locale.to_string())?;
  }
  Ok(array)
}

/// What every `Intl` constructor gets once made: its `length`, a
/// `supportedLocalesOf`, and its place on `Intl`.
pub(crate) fn finish_constructor<'js>(
  ctx: &Ctx<'js>,
  intl: &Object<'js>,
  constructor: &Constructor<'js>,
  name: &str,
  length: u32,
) -> Result<()> {
  constructor.prop("length", Property::from(length).configurable())?;
  let supported = Function::new(
    ctx.clone(),
    |ctx: Ctx<'js>, locales: Opt<Value<'js>>, options: Opt<Value<'js>>| {
      crate::locale::supported_locales_of(&ctx, locales.0.as_ref(), options.0)
    },
  )?
  .with_name("supportedLocalesOf")?
  .with_length(1)?;
  constructor.prop(
    "supportedLocalesOf",
    Property::from(supported).writable().configurable(),
  )?;
  intl.prop(name, Property::from(constructor.clone()).writable().configurable())
}

/// The newer constructors throw when called without `new`.
pub(crate) fn require_new(ctx: &Ctx<'_>, new_target: &Value<'_>, name: &str) -> Result<()> {
  if new_target.is_function() {
    Ok(())
  } else {
    Err(rquickjs::Exception::throw_type(
      ctx,
      &format!("Constructor Intl.{name} requires 'new'"),
    ))
  }
}

/// `Intl.supportedValuesOf(key)`.
fn supported_values_of<'js>(ctx: Ctx<'js>, key: Opt<Value<'js>>) -> Result<Array<'js>> {
  let key = match key.0 {
    Some(key) => key.get::<rquickjs::convert::Coerced<String>>()?.0,
    None => "undefined".to_owned(),
  };
  let mut values: Vec<String> = match key.as_str() {
    "calendar" => crate::date_time_format::supported_calendars()
      .iter()
      .map(|c| (*c).to_owned())
      .collect(),
    "collation" => [
      "compat", "dict", "emoji", "eor", "phonebk", "phonetic", "pinyin", "searchjl", "stroke", "trad", "unihan",
      "zhuyin",
    ]
    .iter()
    .map(|c| (*c).to_owned())
    .collect(),
    "currency" => crate::number_format::currencies(),
    "numberingSystem" => crate::number_format::numbering_systems(),
    "timeZone" => {
      let mut zones: Vec<String> = icu::time::zone::iana::IanaParserExtended::new()
        .iter()
        .map(|entry| entry.canonical.to_owned())
        .filter(|name| name.contains('/') && !name.starts_with("Etc/"))
        .collect();
      zones.push("UTC".to_owned());
      zones
    },
    "unit" => crate::units::sanctioned().iter().map(|u| (*u).to_owned()).collect(),
    _ => {
      return Err(rquickjs::Exception::throw_range(&ctx, &format!("Invalid key : {key}")));
    },
  };
  values.sort();
  values.dedup();
  let array = Array::new(ctx)?;
  for (index, value) in values.iter().enumerate() {
    array.set(index, value.as_str())?;
  }
  Ok(array)
}
