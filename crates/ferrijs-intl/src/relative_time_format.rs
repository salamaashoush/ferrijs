//! `Intl.RelativeTimeFormat`.

use std::cell::OnceCell;

use icu::experimental::relativetime::options::Numeric as IcuNumeric;
use icu::experimental::relativetime::{
  RelativeTimeFormatter, RelativeTimeFormatterOptions, RelativeTimeFormatterPreferences,
};
use icu::locale::Locale;
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Array, Ctx, Exception, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::number_format::{Digits, Numeric};
use crate::options;
use crate::parts::{self, JsPart, Recorder};

const UNITS: [&str; 8] = ["second", "minute", "hour", "day", "week", "month", "quarter", "year"];

#[derive(Trace)]
#[rquickjs::class(rename = "RelativeTimeFormat")]
pub struct RelativeTimeFormat {
  #[qjs(skip_trace)]
  locale: String,
  #[qjs(skip_trace)]
  data_locale: Locale,
  #[qjs(skip_trace)]
  numbering_system: String,
  #[qjs(skip_trace)]
  style: &'static str,
  #[qjs(skip_trace)]
  numeric: &'static str,
  #[qjs(skip_trace)]
  digits: Digits,
  /// One formatter per unit, made the first time the unit is asked for.
  #[qjs(skip_trace)]
  formatters: [OnceCell<Option<RelativeTimeFormatter>>; 8],
}

// SAFETY: holds no JS value.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for RelativeTimeFormat {
  type Changed<'to> = RelativeTimeFormat;
}

impl RelativeTimeFormat {
  fn formatter(&self, unit: usize) -> Option<&RelativeTimeFormatter> {
    self.formatters[unit]
      .get_or_init(|| {
        let prefs = RelativeTimeFormatterPreferences::from(&self.data_locale);
        let mut options = RelativeTimeFormatterOptions::default();
        options.numeric = Some(if self.numeric == "auto" {
          IcuNumeric::Auto
        } else {
          IcuNumeric::Always
        });
        let made = match (self.style, unit) {
          ("short", 0) => RelativeTimeFormatter::try_new_short_second(prefs, options),
          ("short", 1) => RelativeTimeFormatter::try_new_short_minute(prefs, options),
          ("short", 2) => RelativeTimeFormatter::try_new_short_hour(prefs, options),
          ("short", 3) => RelativeTimeFormatter::try_new_short_day(prefs, options),
          ("short", 4) => RelativeTimeFormatter::try_new_short_week(prefs, options),
          ("short", 5) => RelativeTimeFormatter::try_new_short_month(prefs, options),
          ("short", 6) => RelativeTimeFormatter::try_new_short_quarter(prefs, options),
          ("short", _) => RelativeTimeFormatter::try_new_short_year(prefs, options),
          ("narrow", 0) => RelativeTimeFormatter::try_new_narrow_second(prefs, options),
          ("narrow", 1) => RelativeTimeFormatter::try_new_narrow_minute(prefs, options),
          ("narrow", 2) => RelativeTimeFormatter::try_new_narrow_hour(prefs, options),
          ("narrow", 3) => RelativeTimeFormatter::try_new_narrow_day(prefs, options),
          ("narrow", 4) => RelativeTimeFormatter::try_new_narrow_week(prefs, options),
          ("narrow", 5) => RelativeTimeFormatter::try_new_narrow_month(prefs, options),
          ("narrow", 6) => RelativeTimeFormatter::try_new_narrow_quarter(prefs, options),
          ("narrow", _) => RelativeTimeFormatter::try_new_narrow_year(prefs, options),
          (_, 0) => RelativeTimeFormatter::try_new_long_second(prefs, options),
          (_, 1) => RelativeTimeFormatter::try_new_long_minute(prefs, options),
          (_, 2) => RelativeTimeFormatter::try_new_long_hour(prefs, options),
          (_, 3) => RelativeTimeFormatter::try_new_long_day(prefs, options),
          (_, 4) => RelativeTimeFormatter::try_new_long_week(prefs, options),
          (_, 5) => RelativeTimeFormatter::try_new_long_month(prefs, options),
          (_, 6) => RelativeTimeFormatter::try_new_long_quarter(prefs, options),
          (_, _) => RelativeTimeFormatter::try_new_long_year(prefs, options),
        };
        made.ok()
      })
      .as_ref()
  }

  /// `PartitionRelativeTimePattern(relativeTimeFormat, value, unit)`.
  fn parts<'js>(&self, ctx: &Ctx<'js>, value: Opt<Value<'js>>, unit: Opt<Value<'js>>) -> Result<Vec<JsPart>> {
    let value = match value.0 {
      Some(value) => value.get::<Coerced<f64>>()?.0,
      None => f64::NAN,
    };
    let unit = match unit.0 {
      Some(unit) => unit.get::<Coerced<String>>()?.0,
      None => "undefined".to_owned(),
    };
    if !value.is_finite() {
      return Err(Exception::throw_range(
        ctx,
        "Value need to be finite number for Intl.RelativeTimeFormat.prototype.format()",
      ));
    }
    let singular = unit.strip_suffix('s').unwrap_or(&unit);
    let Some(index) = UNITS.iter().position(|u| *u == singular) else {
      return Err(Exception::throw_range(
        ctx,
        &format!("Invalid unit argument for Intl.RelativeTimeFormat.prototype.format() '{unit}'"),
      ));
    };
    let Numeric::Finite(decimal) = Numeric::from_f64(value) else {
      return Err(Exception::throw_range(
        ctx,
        "Value need to be finite number for Intl.RelativeTimeFormat.prototype.format()",
      ));
    };
    let rounded = self.digits.round(&decimal);
    let Some(formatter) = self.formatter(index) else {
      return Err(Exception::throw_range(
        ctx,
        "Intl.RelativeTimeFormat has no data for this locale",
      ));
    };
    let mut out = Vec::new();
    for (part, text) in Recorder::record(&formatter.format(rounded)) {
      let kind = match part {
        Some(p) if p == icu::decimal::parts::INTEGER => "integer",
        Some(p) if p == icu::decimal::parts::FRACTION => "fraction",
        Some(p) if p == icu::decimal::parts::DECIMAL => "decimal",
        Some(p) if p == icu::decimal::parts::GROUP => "group",
        Some(p) if p == icu::decimal::parts::MINUS_SIGN => "minusSign",
        Some(p) if p == icu::decimal::parts::PLUS_SIGN => "plusSign",
        _ => "literal",
      };
      let mut part = JsPart::new(kind, text);
      if kind != "literal" {
        part.unit = Some(UNITS[index]);
      }
      parts::push(&mut out, part);
    }
    Ok(out)
  }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> RelativeTimeFormat {
  pub fn format(&self, ctx: Ctx<'js>, value: Opt<Value<'js>>, unit: Opt<Value<'js>>) -> Result<String> {
    Ok(parts::concat(&self.parts(&ctx, value, unit)?))
  }

  pub fn format_to_parts(&self, ctx: Ctx<'js>, value: Opt<Value<'js>>, unit: Opt<Value<'js>>) -> Result<Array<'js>> {
    let parts = self.parts(&ctx, value, unit)?;
    parts::to_array(&ctx, &parts)
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    object.set("locale", self.locale.as_str())?;
    object.set("style", self.style)?;
    object.set("numeric", self.numeric)?;
    object.set("numberingSystem", self.numbering_system.as_str())?;
    Ok(object)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.RelativeTimeFormat"
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<RelativeTimeFormat, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>,
     new_target: This<Value<'js>>,
     locales: Opt<Value<'js>>,
     options: Opt<Value<'js>>|
     -> Result<RelativeTimeFormat> {
      crate::intl::require_new(&ctx, &new_target.0, "RelativeTimeFormat")?;
      let requested = locale::canonicalize_list(&ctx, locales.0.as_ref())?;
      let options = options::options_object(&ctx, options.0)?;
      let options = options.as_ref();
      options::locale_matcher(&ctx, options)?;
      let numbering_system = options::unicode_type(&ctx, options, "numberingSystem")?;
      let style = options::string(&ctx, options, "style", &["long", "short", "narrow"])?.unwrap_or("long");
      let numeric = options::string(&ctx, options, "numeric", &["always", "auto"])?.unwrap_or("always");
      let found = locale::negotiate(&requested, &crate::state::state(&ctx)?.default_locale);
      let nu = locale::keyword(
        &found,
        "nu",
        numbering_system.as_deref(),
        crate::number_format::numbering_system_supported,
      );
      let resolved = locale::with_keywords(&found.id, &[&nu]);
      let mut data_locale = Locale::from(found.id.clone());
      if let Some(value) = &nu.value {
        locale::set_keyword(&mut data_locale, "nu", value);
      }
      let numbering_system = nu
        .value
        .clone()
        .unwrap_or_else(|| crate::number_format::default_numbering_system(&data_locale));
      Ok(RelativeTimeFormat {
        locale: resolved.to_string(),
        data_locale,
        numbering_system,
        style,
        numeric,
        digits: Digits::read(&ctx, None, (0, 3), false)?,
        formatters: Default::default(),
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "RelativeTimeFormat", 0)
}
