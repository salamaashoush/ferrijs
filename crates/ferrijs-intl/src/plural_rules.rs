//! `Intl.PluralRules`.

use icu::locale::Locale;
use icu::plurals::{PluralCategory, PluralRules as IcuPluralRules, PluralRulesPreferences, PluralRulesWithRanges};
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::function::Opt;
use rquickjs::{Array, Ctx, Exception, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::number_format::{Digits, Numeric};
use crate::options;

#[derive(Trace)]
#[rquickjs::class(rename = "PluralRules")]
pub struct PluralRules {
  #[qjs(skip_trace)]
  locale: String,
  #[qjs(skip_trace)]
  kind: &'static str,
  #[qjs(skip_trace)]
  digits: Digits,
  #[qjs(skip_trace)]
  rules: PluralRulesWithRanges<IcuPluralRules>,
}

// SAFETY: holds no JS value.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for PluralRules {
  type Changed<'to> = PluralRules;
}

fn category_name(category: PluralCategory) -> &'static str {
  match category {
    PluralCategory::Zero => "zero",
    PluralCategory::One => "one",
    PluralCategory::Two => "two",
    PluralCategory::Few => "few",
    PluralCategory::Many => "many",
    PluralCategory::Other => "other",
  }
}

impl PluralRules {
  fn new<'js>(ctx: &Ctx<'js>, locales: Option<&Value<'js>>, options: Option<Value<'js>>) -> Result<Self> {
    let requested = locale::canonicalize_list(ctx, locales)?;
    let options = options::options_object(ctx, options)?;
    let options = options.as_ref();
    options::locale_matcher(ctx, options)?;
    let kind = options::string(ctx, options, "type", &["cardinal", "ordinal"])?.unwrap_or("cardinal");
    let notation = options::string(
      ctx,
      options,
      "notation",
      &["standard", "scientific", "engineering", "compact"],
    )?
    .unwrap_or("standard");
    let digits = Digits::read(ctx, options, (0, 3), notation == "compact")?;
    let found = locale::negotiate(&requested, &crate::state::state(ctx)?.default_locale);
    let data_locale = Locale::from(found.id.clone());
    let prefs = PluralRulesPreferences::from(&data_locale);
    let rules = if kind == "ordinal" {
      PluralRulesWithRanges::try_new_ordinal(prefs)
    } else {
      PluralRulesWithRanges::try_new_cardinal(prefs)
    }
    .map_err(|error| Exception::throw_range(ctx, &format!("Intl.PluralRules: {error}")))?;
    Ok(Self {
      locale: data_locale.to_string(),
      kind,
      digits,
      rules,
    })
  }

  /// `ResolvePlural`: the category of the value as it would be
  /// formatted, rounding and all.
  fn category(&self, value: &Numeric) -> PluralCategory {
    match value {
      Numeric::Finite(decimal) => self.rules.rules().category_for(&self.digits.round(decimal)),
      _ => PluralCategory::Other,
    }
  }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> PluralRules {
  pub fn select(&self, ctx: Ctx<'js>, value: Opt<Value<'js>>) -> Result<&'static str> {
    let value = value.0.unwrap_or_else(|| Value::new_undefined(ctx.clone()));
    let number = value.get::<rquickjs::convert::Coerced<f64>>()?.0;
    Ok(category_name(self.category(&Numeric::from_f64(number))))
  }

  pub fn select_range(&self, ctx: Ctx<'js>, start: Opt<Value<'js>>, end: Opt<Value<'js>>) -> Result<&'static str> {
    let (Some(start), Some(end)) = (start.0, end.0) else {
      return Err(Exception::throw_type(&ctx, "start and end are required"));
    };
    if start.is_undefined() || end.is_undefined() {
      return Err(Exception::throw_type(&ctx, "start and end are required"));
    }
    let start = start.get::<rquickjs::convert::Coerced<f64>>()?.0;
    let end = end.get::<rquickjs::convert::Coerced<f64>>()?.0;
    if start.is_nan() || end.is_nan() {
      return Err(Exception::throw_range(&ctx, "start and end must not be NaN"));
    }
    let first = self.category(&Numeric::from_f64(start));
    let second = self.category(&Numeric::from_f64(end));
    Ok(category_name(self.rules.resolve_range(first, second)))
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx.clone())?;
    object.set("locale", self.locale.as_str())?;
    object.set("type", self.kind)?;
    self.digits.resolved(&object)?;
    let categories = Array::new(ctx)?;
    let present: Vec<PluralCategory> = self.rules.rules().categories().collect();
    let order = [
      PluralCategory::Zero,
      PluralCategory::One,
      PluralCategory::Two,
      PluralCategory::Few,
      PluralCategory::Many,
      PluralCategory::Other,
    ];
    for (index, category) in order.into_iter().filter(|c| present.contains(c)).enumerate() {
      categories.set(index, category_name(category))?;
    }
    object.set("pluralCategories", categories)?;
    self.digits.resolved_rounding(&object)?;
    Ok(object)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.PluralRules"
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<PluralRules, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>,
     new_target: rquickjs::function::This<Value<'js>>,
     locales: Opt<Value<'js>>,
     options: Opt<Value<'js>>|
     -> Result<PluralRules> {
      crate::intl::require_new(&ctx, &new_target.0, "PluralRules")?;
      PluralRules::new(&ctx, locales.0.as_ref(), options.0)
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "PluralRules", 0)
}
