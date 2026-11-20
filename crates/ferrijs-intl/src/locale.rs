//! Locale lists and locale negotiation: `CanonicalizeLocaleList`,
//! `ResolveLocale`, `FilterLocales` and the default locale.
//!
//! ECMA-402 negotiates against each service's available locales. ICU4X
//! with compiled data has no list of them to compare against; what it
//! has is fallback, and a baked provider reports the locale its fallback
//! landed on. A locale counts as available when its fallback lands on
//! data for its own language rather than on the root, which is the
//! language coverage the formatters actually have.

use icu::datetime::provider::names::DatetimeNamesWeekdayV1;
use icu::decimal::provider::{Baked, DecimalSymbolsV1};
use icu::locale::{LanguageIdentifier, Locale, LocaleCanonicalizer};
use icu_provider::prelude::*;
use rquickjs::convert::Coerced;
use rquickjs::{Array, Ctx, Exception, Object, Result, Value};

/// `IsStructurallyValidLanguageTag` then `CanonicalizeUnicodeLocaleId`.
pub(crate) fn parse(ctx: &Ctx<'_>, tag: &str) -> Result<Locale> {
  let invalid = || Exception::throw_range(ctx, &format!("Incorrect locale information provided: {tag}"));
  // ICU4X also takes `_` as a separator; a BCP 47 tag does not.
  if tag.is_empty() || tag.contains('_') || !tag.is_ascii() {
    return Err(invalid());
  }
  let mut locale = Locale::try_from_str(tag).map_err(|_| invalid())?;
  if !structurally_valid(&locale) {
    return Err(invalid());
  }
  LocaleCanonicalizer::new_extended().canonicalize(&mut locale);
  Ok(locale)
}

/// What ICU4X's parser accepts and a Unicode BCP 47 locale identifier
/// does not: a variant twice, and the same transformed-extension field
/// twice.
fn structurally_valid(locale: &Locale) -> bool {
  let variants = &locale.id.variants;
  let unique_variants = variants
    .iter()
    .enumerate()
    .all(|(i, v)| !variants.iter().skip(i + 1).any(|w| w == v));
  let tlang_variants = locale.extensions.transform.lang.as_ref().is_none_or(|lang| {
    lang
      .variants
      .iter()
      .enumerate()
      .all(|(i, v)| !lang.variants.iter().skip(i + 1).any(|w| w == v))
  });
  unique_variants && tlang_variants
}

/// `CanonicalizeLocaleList(locales)`.
pub(crate) fn canonicalize_list<'js>(ctx: &Ctx<'js>, locales: Option<&Value<'js>>) -> Result<Vec<Locale>> {
  let Some(locales) = locales.filter(|value| !value.is_undefined()) else {
    return Ok(Vec::new());
  };
  let mut seen: Vec<Locale> = Vec::new();
  let mut push = |locale: Locale| {
    if !seen.contains(&locale) {
      seen.push(locale);
    }
  };
  if let Some(tag) = locales.as_string() {
    push(parse(ctx, &tag.to_string()?)?);
    return Ok(seen);
  }
  if let Some(locale) = crate::locale_object::locale_of(locales) {
    push(locale);
    return Ok(seen);
  }
  if locales.is_null() {
    return Err(Exception::throw_type(ctx, "Cannot convert null to object"));
  }
  let object: Object<'js> = match locales.clone().into_object() {
    Some(object) => object,
    None => crate::state::object_constructor(ctx)?.call((locales.clone(),))?,
  };
  let length: Value<'js> = object.get("length")?;
  let length = to_length(length.get::<Coerced<f64>>()?.0);
  for index in 0..length {
    let key = index.to_string();
    if !object.contains_key(&*key)? {
      continue;
    }
    let element: Value<'js> = object.get(&*key)?;
    if let Some(locale) = crate::locale_object::locale_of(&element) {
      push(locale);
      continue;
    }
    if !(element.is_string() || element.is_object()) {
      return Err(Exception::throw_type(ctx, "Language ID should be string or object."));
    }
    let tag = element.get::<Coerced<String>>()?.0;
    push(parse(ctx, &tag)?);
  }
  Ok(seen)
}

fn to_length(number: f64) -> u64 {
  if number.is_nan() || number <= 0.0 {
    0
  } else {
    number.min(9_007_199_254_740_991.0) as u64
  }
}

/// Whether the formatters have data for `id`'s own language.
///
/// ICU4X drops a locale's data where it equals its parent's, so one
/// marker alone can send a well-covered language to the root: English
/// number symbols are the root's. Wide weekday names differ from the
/// root's in every language CLDR covers, and number symbols cover the
/// few without date names, so landing on the language in either counts.
pub(crate) fn is_available(id: &LanguageIdentifier) -> bool {
  if id.language.is_unknown() {
    return false;
  }
  let locale = DataLocale::from(id);
  let request = |attributes: &'static DataMarkerAttributes| {
    let mut metadata = DataRequestMetadata::default();
    metadata.silent = true;
    DataRequest {
      id: DataIdentifierBorrowed::for_marker_attributes_and_locale(attributes, &locale),
      metadata,
    }
  };
  let lands = |landed: Option<DataLocale>| landed.is_none_or(|landed| landed.language == id.language);
  let weekdays = DataProvider::<DatetimeNamesWeekdayV1>::load(
    &icu::datetime::provider::Baked,
    request(DataMarkerAttributes::from_str_or_panic("5")),
  );
  if weekdays.is_ok_and(|response| lands(response.metadata.locale)) {
    return true;
  }
  DataProvider::<DecimalSymbolsV1>::load(&Baked, request(DataMarkerAttributes::empty()))
    .is_ok_and(|response| lands(response.metadata.locale))
}

/// `ResolveLocale`'s matching step: the first requested locale the
/// formatters have data for, its Unicode extension kept for the caller
/// to read its keywords from and every other extension dropped, or the
/// default locale.
pub(crate) fn negotiate(requested: &[Locale], default: &Locale) -> Locale {
  for locale in requested {
    if is_available(&locale.id) {
      let mut found = Locale::from(locale.id.clone());
      found.extensions.unicode.keywords = locale.extensions.unicode.keywords.clone();
      return found;
    }
  }
  default.clone()
}

/// `FilterLocales(availableLocales, requestedLocales, options)`, the
/// body of every `supportedLocalesOf`.
pub(crate) fn supported_locales_of<'js>(
  ctx: &Ctx<'js>,
  locales: Option<&Value<'js>>,
  options: Option<Value<'js>>,
) -> Result<Array<'js>> {
  let requested = canonicalize_list(ctx, locales)?;
  let options = crate::options::coerce_options(ctx, options)?;
  crate::options::locale_matcher(ctx, options.as_ref())?;
  let array = Array::new(ctx.clone())?;
  let mut index = 0;
  for locale in requested {
    if is_available(&locale.id) {
      array.set(index, locale.to_string())?;
      index += 1;
    }
  }
  Ok(array)
}

/// The host's locale, from the POSIX locale variables as ICU reads them
/// (`LC_ALL`, then `LC_MESSAGES`, then `LANG`), or `en-US` when none
/// names one the formatters have.
pub(crate) fn host_default() -> Locale {
  let fallback = || icu::locale::locale!("en-US");
  let posix = ["LC_ALL", "LC_MESSAGES", "LANG"]
    .iter()
    .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
  let Some(posix) = posix else {
    return fallback();
  };
  let tag = posix.split(['.', '@']).next().unwrap_or_default().replace('_', "-");
  if tag == "C" || tag == "POSIX" {
    return fallback();
  }
  match Locale::try_from_str(&tag) {
    Ok(mut locale) if is_available(&locale.id) => {
      LocaleCanonicalizer::new_extended().canonicalize(&mut locale);
      locale
    },
    _ => fallback(),
  }
}

/// A requested default, as a host configured it, or the host's own.
pub(crate) fn configured_default(tag: Option<&str>) -> Locale {
  tag
    .and_then(|tag| Locale::try_from_str(tag).ok())
    .filter(|locale| is_available(&locale.id))
    .map_or_else(host_default, |mut locale| {
      LocaleCanonicalizer::new_extended().canonicalize(&mut locale);
      locale
    })
}

/// One Unicode extension keyword as `ResolveLocale` settles it: the
/// value the service uses, and whether that value came from the locale
/// (and so is reported in the resolved locale) or from an option.
pub(crate) struct Keyword {
  pub(crate) key: &'static str,
  pub(crate) value: Option<String>,
  pub(crate) in_locale: bool,
}

/// `ResolveLocale` for one relevant extension key: the locale's value if
/// the service supports it, overridden by a supported option value that
/// differs, which then drops the keyword from the reported locale.
pub(crate) fn keyword(
  found: &Locale,
  key: &'static str,
  option: Option<&str>,
  supported: impl Fn(&str) -> bool,
) -> Keyword {
  let mut resolved = Keyword {
    key,
    value: None,
    in_locale: false,
  };
  if let Some(value) = keyword_value(found, key)
    && supported(&value)
  {
    resolved.value = Some(value);
    resolved.in_locale = true;
  }
  if let Some(option) = option
    && supported(option)
    && resolved.value.as_deref() != Some(option)
  {
    resolved.value = Some(option.to_owned());
    resolved.in_locale = false;
  }
  resolved
}

/// The value of `key` in `locale`'s Unicode extension; a bare key reads
/// as `true`, as UTS 35 defines it.
pub(crate) fn keyword_value(locale: &Locale, key: &str) -> Option<String> {
  let key = icu::locale::extensions::unicode::Key::try_from_str(key).ok()?;
  let value = locale.extensions.unicode.keywords.get(&key)?;
  let value = value.to_string();
  Some(if value.is_empty() { "true".to_owned() } else { value })
}

/// `id` with the keywords that came from the requested locale.
pub(crate) fn with_keywords(id: &LanguageIdentifier, keywords: &[&Keyword]) -> Locale {
  let mut locale = Locale::from(id.clone());
  for keyword in keywords {
    if keyword.in_locale
      && let Some(value) = &keyword.value
    {
      set_keyword(&mut locale, keyword.key, value);
    }
  }
  locale
}

pub(crate) fn set_keyword(locale: &mut Locale, key: &str, value: &str) {
  use icu::locale::extensions::unicode::{Key, Value};
  if let (Ok(key), Ok(value)) = (Key::try_from_str(key), Value::try_from_str(value)) {
    locale.extensions.unicode.keywords.set(key, value);
  }
}

/// The cache key of a requested locale list, before negotiation.
pub(crate) fn list_key(requested: &[Locale]) -> String {
  let mut key = String::new();
  for locale in requested {
    key.push_str(&locale.to_string());
    key.push(',');
  }
  key
}
