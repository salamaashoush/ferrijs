//! `Intl.DisplayNames`.
//!
//! ICU4X carries CLDR's names of languages, regions, scripts and
//! currencies. It has none for calendars or date-time fields; those
//! answer as `fallback` says (the code, or `undefined`), as they would
//! for any code without a name.

use icu::experimental::dimension::provider::currency::displayname::CurrencyDisplaynameV1;
use icu::experimental::displaynames::multi::{LocaleDisplayNamesFormatter, RegionDisplayNames, ScriptDisplayNames};
use icu::experimental::displaynames::{DisplayNamesOptions, DisplayNamesPreferences, Fallback, LanguageDisplay, Style};
use icu::locale::subtags::{Region, Script};
use icu::locale::{Locale, LocaleCanonicalizer};
use icu_provider::prelude::*;
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Ctx, Exception, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::options;

const FIELDS: &[&str] = &[
  "era",
  "year",
  "quarter",
  "month",
  "weekOfYear",
  "weekday",
  "day",
  "dayPeriod",
  "hour",
  "minute",
  "second",
  "timeZoneName",
];

enum Names {
  Language(Box<LocaleDisplayNamesFormatter>),
  Region(RegionDisplayNames),
  Script(ScriptDisplayNames),
  Currency(Locale),
  None,
}

#[derive(Trace)]
#[rquickjs::class(rename = "DisplayNames")]
pub struct DisplayNames {
  #[qjs(skip_trace)]
  locale: String,
  #[qjs(skip_trace)]
  style: &'static str,
  #[qjs(skip_trace)]
  kind: &'static str,
  #[qjs(skip_trace)]
  fallback: &'static str,
  #[qjs(skip_trace)]
  language_display: Option<&'static str>,
  #[qjs(skip_trace)]
  names: Names,
}

// SAFETY: holds no JS value.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for DisplayNames {
  type Changed<'to> = DisplayNames;
}

impl DisplayNames {
  /// `CanonicalCodeForDisplayNames(type, code)`, or a `RangeError`.
  fn canonical(&self, ctx: &Ctx<'_>, code: &str) -> Result<String> {
    let invalid = || Exception::throw_range(ctx, "invalid_argument");
    match self.kind {
      "language" => {
        let mut locale = Locale::try_from_str(code).map_err(|_| invalid())?;
        if !locale.extensions.is_empty() || code.contains('_') {
          return Err(invalid());
        }
        LocaleCanonicalizer::new_extended().canonicalize(&mut locale);
        Ok(locale.to_string())
      },
      "region" => {
        let region = Region::try_from_str(code).map_err(|_| invalid())?;
        Ok(region.to_string())
      },
      "script" => {
        let script = Script::try_from_str(code).map_err(|_| invalid())?;
        Ok(script.to_string())
      },
      "currency" => {
        if code.len() == 3 && code.bytes().all(|b| b.is_ascii_alphabetic()) {
          Ok(code.to_ascii_uppercase())
        } else {
          Err(invalid())
        }
      },
      "calendar" => {
        let well_formed = code
          .split('-')
          .all(|part| (3..=8).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric()));
        if well_formed {
          Ok(code.to_ascii_lowercase())
        } else {
          Err(invalid())
        }
      },
      _ => {
        if FIELDS.contains(&code) {
          Ok(code.to_owned())
        } else {
          Err(invalid())
        }
      },
    }
  }

  fn name(&self, code: &str) -> Option<String> {
    match &self.names {
      Names::Language(formatter) => {
        let locale = Locale::try_from_str(code).ok()?;
        let name = formatter.of(&locale).into_owned();
        (name != code).then_some(name)
      },
      Names::Region(names) => names.of(Region::try_from_str(code).ok()?).map(str::to_owned),
      Names::Script(names) => names.of(Script::try_from_str(code).ok()?).map(str::to_owned),
      Names::Currency(locale) => {
        let attributes = DataMarkerAttributes::try_from_str(code).ok()?;
        let data_locale = DataLocale::from(locale);
        let mut metadata = DataRequestMetadata::default();
        metadata.silent = true;
        DataProvider::<CurrencyDisplaynameV1>::load(
          &icu::experimental::provider::Baked,
          DataRequest {
            id: DataIdentifierBorrowed::for_marker_attributes_and_locale(attributes, &data_locale),
            metadata,
          },
        )
        .ok()
        .map(|response| response.payload.get().to_string())
      },
      Names::None => None,
    }
  }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> DisplayNames {
  pub fn of(&self, ctx: Ctx<'js>, code: Opt<Value<'js>>) -> Result<Value<'js>> {
    let code = match code.0 {
      Some(code) => code.get::<Coerced<String>>()?.0,
      None => "undefined".to_owned(),
    };
    let code = self.canonical(&ctx, &code)?;
    match self.name(&code) {
      Some(name) => Ok(rquickjs::String::from_str(ctx, &name)?.into_value()),
      None if self.fallback == "code" => Ok(rquickjs::String::from_str(ctx, &code)?.into_value()),
      None => Ok(Value::new_undefined(ctx)),
    }
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    object.set("locale", self.locale.as_str())?;
    object.set("style", self.style)?;
    object.set("type", self.kind)?;
    object.set("fallback", self.fallback)?;
    if let Some(display) = self.language_display {
      object.set("languageDisplay", display)?;
    }
    Ok(object)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.DisplayNames"
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<DisplayNames, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>,
     new_target: This<Value<'js>>,
     locales: Opt<Value<'js>>,
     options: Opt<Value<'js>>|
     -> Result<DisplayNames> {
      crate::intl::require_new(&ctx, &new_target.0, "DisplayNames")?;
      let requested = locale::canonicalize_list(&ctx, locales.0.as_ref())?;
      let Some(options) = options::options_object(&ctx, options.0)? else {
        return Err(Exception::throw_type(&ctx, "invalid_argument"));
      };
      let options = Some(&options);
      options::locale_matcher(&ctx, options)?;
      let style = options::string(&ctx, options, "style", &["narrow", "short", "long"])?.unwrap_or("long");
      let Some(kind) = options::string(
        &ctx,
        options,
        "type",
        &["language", "region", "script", "currency", "calendar", "dateTimeField"],
      )?
      else {
        return Err(Exception::throw_type(&ctx, "invalid_argument"));
      };
      let fallback = options::string(&ctx, options, "fallback", &["code", "none"])?.unwrap_or("code");
      let language_display = options::string(&ctx, options, "languageDisplay", &["dialect", "standard"])?;
      let found = locale::negotiate(&requested, &crate::state::state(&ctx)?.default_locale);
      let data_locale = Locale::from(found.id.clone());
      let prefs = DisplayNamesPreferences::from(&data_locale);
      let mut icu_options = DisplayNamesOptions::default();
      icu_options.style = Some(match style {
        "narrow" => Style::Narrow,
        "short" => Style::Short,
        _ => Style::Long,
      });
      icu_options.fallback = Fallback::None;
      icu_options.language_display = if language_display == Some("standard") {
        LanguageDisplay::Standard
      } else {
        LanguageDisplay::Dialect
      };
      let fail = |error: DataError| Exception::throw_range(&ctx, &format!("Intl.DisplayNames: {error}"));
      let names = match kind {
        "language" => Names::Language(Box::new(
          LocaleDisplayNamesFormatter::try_new(prefs, icu_options).map_err(fail)?,
        )),
        "region" => Names::Region(RegionDisplayNames::try_new(prefs, icu_options).map_err(fail)?),
        "script" => Names::Script(ScriptDisplayNames::try_new(prefs, icu_options).map_err(fail)?),
        "currency" => Names::Currency(data_locale.clone()),
        _ => Names::None,
      };
      Ok(DisplayNames {
        locale: data_locale.to_string(),
        style,
        kind,
        fallback,
        language_display: (kind == "language").then(|| language_display.unwrap_or("dialect")),
        names,
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "DisplayNames", 2)
}
