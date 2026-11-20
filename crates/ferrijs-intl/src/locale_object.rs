//! `Intl.Locale`.

use icu::locale::{Locale as IcuLocale, LocaleCanonicalizer, LocaleDirectionality, LocaleExpander};
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Array, Class, Ctx, Exception, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::options;

#[derive(Trace)]
#[rquickjs::class(rename = "Locale")]
pub struct Locale {
  #[qjs(skip_trace)]
  locale: IcuLocale,
}

// SAFETY: holds no JS value.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for Locale {
  type Changed<'to> = Locale;
}

/// The `[[Locale]]` of an `Intl.Locale` instance.
pub(crate) fn locale_of(value: &Value<'_>) -> Option<IcuLocale> {
  let class = Class::<Locale>::from_value(value).ok()?;
  let locale = class.borrow().locale.clone();
  Some(locale)
}

fn keyword_or_undefined<'js>(ctx: &Ctx<'js>, locale: &IcuLocale, key: &str) -> Result<Value<'js>> {
  match locale::keyword_value(locale, key) {
    Some(value) => Ok(rquickjs::String::from_str(ctx.clone(), &value)?.into_value()),
    None => Ok(Value::new_undefined(ctx.clone())),
  }
}

fn string_array<'js>(ctx: &Ctx<'js>, values: &[String]) -> Result<Array<'js>> {
  let array = Array::new(ctx.clone())?;
  for (index, value) in values.iter().enumerate() {
    array.set(index, value.as_str())?;
  }
  Ok(array)
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> Locale {
  pub fn maximize(&self, ctx: Ctx<'js>) -> Result<Class<'js, Locale>> {
    let mut locale = self.locale.clone();
    LocaleExpander::new_extended().maximize(&mut locale.id);
    Class::instance(ctx, Self { locale })
  }

  pub fn minimize(&self, ctx: Ctx<'js>) -> Result<Class<'js, Locale>> {
    let mut locale = self.locale.clone();
    LocaleExpander::new_extended().minimize(&mut locale.id);
    Class::instance(ctx, Self { locale })
  }

  #[qjs(rename = "toString")]
  pub fn to_string_js(&self) -> String {
    self.locale.to_string()
  }

  #[qjs(get)]
  pub fn base_name(&self) -> String {
    self.locale.id.to_string()
  }

  #[qjs(get)]
  pub fn language(&self) -> String {
    self.locale.id.language.to_string()
  }

  #[qjs(get)]
  pub fn script(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    match self.locale.id.script {
      Some(script) => Ok(rquickjs::String::from_str(ctx, script.as_str())?.into_value()),
      None => Ok(Value::new_undefined(ctx)),
    }
  }

  #[qjs(get)]
  pub fn region(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    match self.locale.id.region {
      Some(region) => Ok(rquickjs::String::from_str(ctx, region.as_str())?.into_value()),
      None => Ok(Value::new_undefined(ctx)),
    }
  }

  #[qjs(get)]
  pub fn calendar(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    keyword_or_undefined(&ctx, &self.locale, "ca")
  }

  #[qjs(get)]
  pub fn case_first(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    keyword_or_undefined(&ctx, &self.locale, "kf")
  }

  #[qjs(get)]
  pub fn collation(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    keyword_or_undefined(&ctx, &self.locale, "co")
  }

  #[qjs(get)]
  pub fn hour_cycle(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    keyword_or_undefined(&ctx, &self.locale, "hc")
  }

  #[qjs(get)]
  pub fn numbering_system(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    keyword_or_undefined(&ctx, &self.locale, "nu")
  }

  #[qjs(get)]
  pub fn numeric(&self) -> bool {
    locale::keyword_value(&self.locale, "kn").as_deref() == Some("true")
  }

  pub fn get_text_info(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    let rtl = LocaleDirectionality::new_extended().is_right_to_left(&self.locale.id);
    object.set("direction", if rtl { "rtl" } else { "ltr" })?;
    Ok(object)
  }

  pub fn get_week_info(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    use icu::calendar::week::WeekInformation;
    let info = WeekInformation::try_new((&self.locale).into())
      .map_err(|error| Exception::throw_range(&ctx, &format!("Intl.Locale: {error}")))?;
    let object = Object::new(ctx.clone())?;
    object.set("firstDay", info.first_weekday as u8)?;
    let mut days: Vec<u8> = info.weekend().map(|day| day as u8).collect();
    days.sort_unstable();
    let weekend = Array::new(ctx)?;
    for (index, day) in days.into_iter().enumerate() {
      weekend.set(index, day)?;
    }
    object.set("weekend", weekend)?;
    Ok(object)
  }

  pub fn get_calendars(&self, ctx: Ctx<'js>) -> Result<Array<'js>> {
    let calendar = locale::keyword_value(&self.locale, "ca")
      .unwrap_or_else(|| crate::date_time_format::preferred_calendar(&self.locale));
    string_array(&ctx, &[calendar])
  }

  pub fn get_numbering_systems(&self, ctx: Ctx<'js>) -> Result<Array<'js>> {
    let system = locale::keyword_value(&self.locale, "nu")
      .unwrap_or_else(|| crate::number_format::default_numbering_system(&self.locale));
    string_array(&ctx, &[system])
  }

  pub fn get_time_zones(&self, ctx: Ctx<'js>) -> Result<Value<'js>> {
    let Some(region) = self.locale.id.region else {
      return Ok(Value::new_undefined(ctx));
    };
    let prefix = region.as_str().to_ascii_lowercase();
    let mut zones: Vec<String> = icu::time::zone::iana::IanaParserExtended::new()
      .iter()
      .filter(|entry| entry.time_zone.0.as_str().starts_with(&prefix))
      .map(|entry| entry.canonical.to_owned())
      .collect();
    zones.sort();
    Ok(string_array(&ctx, &zones)?.into_value())
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.Locale"
  }
}

/// `ApplyOptionsToTag` and `ApplyUnicodeExtensionToTag`.
fn construct<'js>(ctx: &Ctx<'js>, tag: Option<Value<'js>>, options: Option<Value<'js>>) -> Result<Locale> {
  let Some(tag) = tag.filter(|tag| tag.is_string() || tag.is_object()) else {
    return Err(Exception::throw_type(
      ctx,
      "First argument to Intl.Locale constructor can't be empty or missing",
    ));
  };
  let mut locale = match locale_of(&tag) {
    Some(locale) => locale,
    None => locale::parse(ctx, &tag.get::<Coerced<String>>()?.0)?,
  };
  let options = options::coerce_options(ctx, options)?;
  let options = options.as_ref();
  let invalid = |name: &str| Exception::throw_range(ctx, &format!("Incorrect locale information provided: {name}"));
  if let Some(language) = options::string_any(options, "language")? {
    locale.id.language = language.parse().map_err(|_| invalid(&language))?;
  }
  if let Some(script) = options::string_any(options, "script")? {
    locale.id.script = Some(script.parse().map_err(|_| invalid(&script))?);
  }
  if let Some(region) = options::string_any(options, "region")? {
    locale.id.region = Some(region.parse().map_err(|_| invalid(&region))?);
  }
  let calendar = options::unicode_type(ctx, options, "calendar")?;
  let collation = options::unicode_type(ctx, options, "collation")?;
  let hour_cycle = options::string(ctx, options, "hourCycle", &["h11", "h12", "h23", "h24"])?;
  let case_first = options::string(ctx, options, "caseFirst", &["upper", "lower", "false"])?;
  let numeric = options::boolean(options, "numeric")?;
  let numbering_system = options::unicode_type(ctx, options, "numberingSystem")?;
  for (key, value) in [
    ("ca", calendar),
    ("co", collation),
    ("hc", hour_cycle.map(str::to_owned)),
    ("kf", case_first.map(str::to_owned)),
    ("kn", numeric.map(|n| n.to_string())),
    ("nu", numbering_system),
  ] {
    if let Some(value) = value {
      locale::set_keyword(&mut locale, key, &value);
    }
  }
  LocaleCanonicalizer::new_extended().canonicalize(&mut locale);
  Ok(Locale { locale })
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<Locale, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>, new_target: This<Value<'js>>, tag: Opt<Value<'js>>, options: Opt<Value<'js>>| -> Result<Locale> {
      crate::intl::require_new(&ctx, &new_target.0, "Locale")?;
      construct(&ctx, tag.0, options.0)
    },
  )?;
  constructor.prop("length", rquickjs::object::Property::from(1).configurable())?;
  intl.prop(
    "Locale",
    rquickjs::object::Property::from(constructor).writable().configurable(),
  )
}
