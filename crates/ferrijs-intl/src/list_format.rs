//! `Intl.ListFormat`.

use icu::list::options::{ListFormatterOptions, ListLength};
use icu::list::{ListFormatter, ListFormatterPreferences};
use icu::locale::Locale;
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::function::{Opt, This};
use rquickjs::{Array, Ctx, Exception, Function, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::options;
use crate::parts::{self, JsPart, Recorder};

#[derive(Trace)]
#[rquickjs::class(rename = "ListFormat")]
pub struct ListFormat {
  #[qjs(skip_trace)]
  locale: String,
  #[qjs(skip_trace)]
  kind: &'static str,
  #[qjs(skip_trace)]
  style: &'static str,
  #[qjs(skip_trace)]
  formatter: ListFormatter,
}

// SAFETY: holds no JS value.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for ListFormat {
  type Changed<'to> = ListFormat;
}

/// `StringListFromIterable(iterable)`: every element must be a string.
fn strings<'js>(ctx: &Ctx<'js>, list: Option<Value<'js>>) -> Result<Vec<String>> {
  let Some(list) = list.filter(|value| !value.is_undefined()) else {
    return Ok(Vec::new());
  };
  let array_from: Function<'js> = ctx.globals().get::<_, Object<'js>>("Array")?.get("from")?;
  let array: Array<'js> = array_from.call((list,))?;
  let mut out = Vec::with_capacity(array.len());
  for element in array.iter::<Value<'js>>() {
    let element = element?;
    let Some(text) = element.as_string() else {
      let shown = element
        .get::<rquickjs::convert::Coerced<String>>()
        .map_or_else(|_| "value".to_owned(), |s| s.0);
      return Err(Exception::throw_type(
        ctx,
        &format!("Iterable yielded {shown} which is not a string"),
      ));
    };
    out.push(text.to_string()?);
  }
  Ok(out)
}

impl ListFormat {
  fn parts(&self, items: &[String]) -> Vec<JsPart> {
    let mut out = Vec::new();
    for (part, text) in Recorder::record(&self.formatter.format(items.iter())) {
      let kind = if part == Some(icu::list::parts::ELEMENT) {
        "element"
      } else {
        "literal"
      };
      out.push(JsPart::new(kind, text));
    }
    out
  }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> ListFormat {
  pub fn format(&self, ctx: Ctx<'js>, list: Opt<Value<'js>>) -> Result<String> {
    Ok(parts::concat(&self.parts(&strings(&ctx, list.0)?)))
  }

  pub fn format_to_parts(&self, ctx: Ctx<'js>, list: Opt<Value<'js>>) -> Result<Array<'js>> {
    let parts = self.parts(&strings(&ctx, list.0)?);
    parts::to_array(&ctx, &parts)
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    object.set("locale", self.locale.as_str())?;
    object.set("type", self.kind)?;
    object.set("style", self.style)?;
    Ok(object)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.ListFormat"
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<ListFormat, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>,
     new_target: This<Value<'js>>,
     locales: Opt<Value<'js>>,
     options: Opt<Value<'js>>|
     -> Result<ListFormat> {
      crate::intl::require_new(&ctx, &new_target.0, "ListFormat")?;
      let requested = locale::canonicalize_list(&ctx, locales.0.as_ref())?;
      let options = options::options_object(&ctx, options.0)?;
      let options = options.as_ref();
      options::locale_matcher(&ctx, options)?;
      let kind =
        options::string(&ctx, options, "type", &["conjunction", "disjunction", "unit"])?.unwrap_or("conjunction");
      let style = options::string(&ctx, options, "style", &["long", "short", "narrow"])?.unwrap_or("long");
      let found = locale::negotiate(&requested, &crate::state::state(&ctx)?.default_locale);
      let data_locale = Locale::from(found.id.clone());
      let prefs = ListFormatterPreferences::from(&data_locale);
      let length = match style {
        "short" => ListLength::Short,
        "narrow" => ListLength::Narrow,
        _ => ListLength::Wide,
      };
      let list_options = ListFormatterOptions::default().with_length(length);
      let formatter = match kind {
        "disjunction" => ListFormatter::try_new_or(prefs, list_options),
        "unit" => ListFormatter::try_new_unit(prefs, list_options),
        _ => ListFormatter::try_new_and(prefs, list_options),
      }
      .map_err(|error| Exception::throw_range(&ctx, &format!("Intl.ListFormat: {error}")))?;
      Ok(ListFormat {
        locale: data_locale.to_string(),
        kind,
        style,
        formatter,
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "ListFormat", 0)
}
