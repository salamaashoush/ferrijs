//! `Intl.Collator` and `String.prototype.localeCompare`.

use std::cmp::Ordering;
use std::rc::Rc;

use icu::collator::options::{AlternateHandling, CaseLevel, CollatorOptions, Strength};
use icu::collator::provider::{Baked, CollationMetadataV1};
use icu::collator::{Collator as IcuCollator, CollatorBorrowed, CollatorPreferences};
use icu::locale::LanguageIdentifier;
use icu_provider::prelude::*;
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Class, Ctx, Exception, Function, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::options;

pub(crate) struct CollatorCore {
  collator: CollatorBorrowed<'static>,
  locale: String,
  usage: &'static str,
  sensitivity: &'static str,
  ignore_punctuation: bool,
  collation: String,
  numeric: bool,
  case_first: String,
}

impl CollatorCore {
  pub(crate) fn compare(&self, left: &str, right: &str) -> Ordering {
    self.collator.compare(left, right)
  }
}

/// `InitializeCollator` up to the formatter: every option read, in the
/// spec's order, and resolved to the core that compares under them.
pub(crate) fn resolve<'js>(
  ctx: &Ctx<'js>,
  locales: Option<&Value<'js>>,
  options: Option<Value<'js>>,
) -> Result<Rc<CollatorCore>> {
  let requested = locale::canonicalize_list(ctx, locales)?;
  let options = options::coerce_options(ctx, options)?;
  let options = options.as_ref();
  let usage = options::string(ctx, options, "usage", &["sort", "search"])?.unwrap_or("sort");
  options::locale_matcher(ctx, options)?;
  let collation = options::unicode_type(ctx, options, "collation")?;
  let numeric = options::boolean(options, "numeric")?.map(|n| if n { "true" } else { "false" });
  let case_first = options::string(ctx, options, "caseFirst", &["upper", "lower", "false"])?;
  let sensitivity = options::string(ctx, options, "sensitivity", &["base", "accent", "case", "variant"])?;
  let ignore_punctuation = options::boolean(options, "ignorePunctuation")?;

  let state = crate::state::state(ctx)?;
  let key = format!(
    "{}|{usage}|{collation:?}|{numeric:?}|{case_first:?}|{sensitivity:?}|{ignore_punctuation:?}",
    locale::list_key(&requested)
  );
  if let Some(core) = state.collators.get(&key) {
    return Ok(core);
  }
  let found = locale::negotiate(&requested, &state.default_locale);

  let language = found.id.clone();
  let co = locale::keyword(&found, "co", collation.as_deref(), |value| {
    collation_supported(&language, value)
  });
  let kn = locale::keyword(&found, "kn", numeric, |value| matches!(value, "true" | "false"));
  let kf = locale::keyword(&found, "kf", case_first, |value| {
    matches!(value, "upper" | "lower" | "false")
  });
  let resolved = locale::with_keywords(&found.id, &[&co, &kn, &kf]);

  // The collator itself also hears `usage`: a search collator is the
  // locale's `search` tailoring, which ECMA-402 never names in the
  // locale it reports.
  let mut data_locale = locale::with_keywords(&found.id, &[]);
  for keyword in [&co, &kn, &kf] {
    if let Some(value) = &keyword.value {
      locale::set_keyword(&mut data_locale, keyword.key, value);
    }
  }
  if usage == "search" {
    locale::set_keyword(&mut data_locale, "co", "search");
  }
  let prefs = CollatorPreferences::from(&data_locale);
  let sensitivity = sensitivity.unwrap_or("variant");
  let mut collator_options = CollatorOptions::default();
  match sensitivity {
    "base" => collator_options.strength = Some(Strength::Primary),
    "accent" => collator_options.strength = Some(Strength::Secondary),
    "case" => {
      collator_options.strength = Some(Strength::Primary);
      collator_options.case_level = Some(CaseLevel::On);
    },
    _ => collator_options.strength = Some(Strength::Tertiary),
  }
  // Thai is the one CLDR locale that ignores punctuation by default.
  let ignore_punctuation = ignore_punctuation.unwrap_or(found.id.language.as_str() == "th");
  if ignore_punctuation {
    collator_options.alternate_handling = Some(AlternateHandling::Shifted);
  }
  let collator = IcuCollator::try_new(prefs, collator_options)
    .map_err(|error| Exception::throw_range(ctx, &format!("Intl.Collator: {error}")))?;
  let core = Rc::new(CollatorCore {
    collator,
    locale: resolved.to_string(),
    usage,
    sensitivity,
    ignore_punctuation,
    collation: co.value.clone().unwrap_or_else(|| "default".to_owned()),
    numeric: kn.value.as_deref() == Some("true"),
    case_first: kf.value.clone().unwrap_or_else(|| "false".to_owned()),
  });
  state.collators.insert(key, Rc::clone(&core));
  Ok(core)
}

/// Whether `language` has the `co` tailoring `value`. `standard` and
/// `search` are chosen by `usage`, never by the locale.
fn collation_supported(language: &LanguageIdentifier, value: &str) -> bool {
  if matches!(value, "standard" | "search") {
    return false;
  }
  let Ok(attributes) = DataMarkerAttributes::try_from_str(value) else {
    return false;
  };
  let locale = DataLocale::from(language);
  let mut metadata = DataRequestMetadata::default();
  metadata.silent = true;
  let request = DataRequest {
    id: DataIdentifierBorrowed::for_marker_attributes_and_locale(attributes, &locale),
    metadata,
  };
  DataProvider::<CollationMetadataV1>::load(&Baked, request).is_ok()
}

#[derive(Trace)]
#[rquickjs::class(rename = "Collator")]
pub struct Collator<'js> {
  #[qjs(skip_trace)]
  core: Rc<CollatorCore>,
  bound_compare: Option<Function<'js>>,
}

// SAFETY: the only `'js` value is the bound `compare`, which belongs to
// the context the collator does.
#[allow(unsafe_code)]
unsafe impl<'js> JsLifetime<'js> for Collator<'js> {
  type Changed<'to> = Collator<'to>;
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> Collator<'js> {
  #[qjs(get)]
  pub fn compare(this: This<Class<'js, Self>>, ctx: Ctx<'js>) -> Result<Function<'js>> {
    if let Some(bound) = this.0.borrow().bound_compare.clone() {
      return Ok(bound);
    }
    let core = Rc::clone(&this.0.borrow().core);
    let bound = Function::new(ctx, move |left: Opt<Coerced<String>>, right: Opt<Coerced<String>>| {
      let left = left.0.map_or_else(|| "undefined".to_owned(), |s| s.0);
      let right = right.0.map_or_else(|| "undefined".to_owned(), |s| s.0);
      ordering(core.compare(&left, &right))
    })?
    .with_length(2)?
    .with_name("")?;
    this.0.borrow_mut().bound_compare = Some(bound.clone());
    Ok(bound)
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let core = &self.core;
    let object = Object::new(ctx)?;
    object.set("locale", core.locale.as_str())?;
    object.set("usage", core.usage)?;
    object.set("sensitivity", core.sensitivity)?;
    object.set("ignorePunctuation", core.ignore_punctuation)?;
    object.set("collation", core.collation.as_str())?;
    object.set("numeric", core.numeric)?;
    object.set("caseFirst", core.case_first.as_str())?;
    Ok(object)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.Collator"
  }
}

pub(crate) fn ordering(ordering: Ordering) -> i32 {
  match ordering {
    Ordering::Less => -1,
    Ordering::Equal => 0,
    Ordering::Greater => 1,
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<Collator<'js>, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>, locales: Opt<Value<'js>>, options: Opt<Value<'js>>| -> Result<Collator<'js>> {
      Ok(Collator {
        core: resolve(&ctx, locales.0.as_ref(), options.0)?,
        bound_compare: None,
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "Collator", 0)
}

/// `String.prototype.localeCompare(that, locales, options)`.
pub(crate) fn locale_compare<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  that: Opt<Value<'js>>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
) -> Result<i32> {
  let this = crate::prototypes::this_string(&ctx, &this.0, "localeCompare")?;
  let that = that.0.map_or_else(
    || Ok("undefined".to_owned()),
    |v| v.get::<Coerced<String>>().map(|s| s.0),
  )?;
  let defaults =
    locales.0.as_ref().is_none_or(Value::is_undefined) && options.0.as_ref().is_none_or(Value::is_undefined);
  let cached = defaults
    .then(|| crate::state::state(&ctx).ok()?.default_collator.borrow().clone())
    .flatten();
  let core = if let Some(core) = cached {
    core
  } else {
    let core = resolve(&ctx, locales.0.as_ref(), options.0)?;
    if defaults {
      *crate::state::state(&ctx)?.default_collator.borrow_mut() = Some(Rc::clone(&core));
    }
    core
  };
  Ok(ordering(core.compare(&this, &that)))
}
