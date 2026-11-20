//! `Intl.Segmenter`, its `Segments` and their iterator.
//!
//! A string is segmented once, when `segment` is called: its UTF-16
//! code units and every boundary are kept, so `containing` and the
//! iterator only look up what was computed, and indices are the code
//! unit indices a script uses.

use std::rc::Rc;

use icu::segmenter::options::{SentenceBreakInvariantOptions, WordBreakInvariantOptions};
use icu::segmenter::{GraphemeClusterSegmenter, SentenceSegmenter, WordSegmenter};
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Class, Ctx, JsLifetime, Object, Result, Value};

use crate::locale;
use crate::options;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Granularity {
  Grapheme,
  Word,
  Sentence,
}

#[derive(Trace)]
#[rquickjs::class(rename = "Segmenter")]
pub struct Segmenter {
  #[qjs(skip_trace)]
  locale: String,
  #[qjs(skip_trace)]
  granularity: Granularity,
}

// SAFETY: holds no JS value.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for Segmenter {
  type Changed<'to> = Segmenter;
}

/// A segmented string: its code units, the boundaries between its
/// segments, and for words whether each segment is word-like.
struct Segmentation {
  units: Vec<u16>,
  breaks: Vec<usize>,
  word_like: Option<Vec<bool>>,
}

impl Segmentation {
  fn new(input: &str, granularity: Granularity) -> Self {
    let units: Vec<u16> = input.encode_utf16().collect();
    let mut word_like = None;
    let breaks = match granularity {
      Granularity::Grapheme => GraphemeClusterSegmenter::new().segment_utf16(&units).collect(),
      Granularity::Sentence => SentenceSegmenter::new(SentenceBreakInvariantOptions::default())
        .segment_utf16(&units)
        .collect(),
      Granularity::Word => {
        let mut breaks = Vec::new();
        let mut like = Vec::new();
        let mut iterator = WordSegmenter::new_auto(WordBreakInvariantOptions::default()).segment_utf16(&units);
        while let Some(index) = iterator.next() {
          if !breaks.is_empty() {
            like.push(iterator.is_word_like());
          }
          breaks.push(index);
        }
        word_like = Some(like);
        breaks
      },
    };
    Self {
      units,
      breaks,
      word_like,
    }
  }

  /// The segment containing code unit `index`, by its position among
  /// the segments.
  fn segment_at(&self, index: usize) -> Option<usize> {
    if index >= self.units.len() {
      return None;
    }
    let position = self.breaks.partition_point(|&b| b <= index);
    position.checked_sub(1)
  }

  /// `CreateSegmentDataObject` for the segment at `position`.
  fn data<'js>(&self, ctx: &Ctx<'js>, input: &rquickjs::String<'js>, position: usize) -> Result<Object<'js>> {
    let start = self.breaks[position];
    let end = self.breaks[position + 1];
    let object = Object::new(ctx.clone())?;
    object.set("segment", String::from_utf16_lossy(&self.units[start..end]))?;
    object.set("index", start)?;
    object.set("input", input.clone())?;
    if let Some(like) = &self.word_like {
      object.set("isWordLike", like[position])?;
    }
    Ok(object)
  }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> Segmenter {
  pub fn segment(&self, ctx: Ctx<'js>, input: Opt<Value<'js>>) -> Result<Class<'js, Segments<'js>>> {
    let text = input.0.map_or_else(
      || Ok("undefined".to_owned()),
      |v| v.get::<Coerced<String>>().map(|s| s.0),
    )?;
    let input = rquickjs::String::from_str(ctx.clone(), &text)?;
    Class::instance(
      ctx,
      Segments {
        segmentation: Rc::new(Segmentation::new(&text, self.granularity)),
        input,
      },
    )
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    object.set("locale", self.locale.as_str())?;
    object.set(
      "granularity",
      match self.granularity {
        Granularity::Grapheme => "grapheme",
        Granularity::Word => "word",
        Granularity::Sentence => "sentence",
      },
    )?;
    Ok(object)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.Segmenter"
  }
}

/// The string a segment reports as its `input` is kept as the one JS
/// string, not copied out for every segment.
#[derive(Trace)]
#[rquickjs::class(rename = "Segments")]
pub struct Segments<'js> {
  #[qjs(skip_trace)]
  segmentation: Rc<Segmentation>,
  input: rquickjs::String<'js>,
}

// SAFETY: the only `'js` value is the input string, which belongs to
// the context the segments do.
#[allow(unsafe_code)]
unsafe impl<'js> JsLifetime<'js> for Segments<'js> {
  type Changed<'to> = Segments<'to>;
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> Segments<'js> {
  pub fn containing(&self, ctx: Ctx<'js>, index: Opt<Value<'js>>) -> Result<Value<'js>> {
    let index = match index.0 {
      Some(value) => value.get::<Coerced<f64>>()?.0,
      None => 0.0,
    };
    let index = if index.is_nan() { 0.0 } else { index.trunc() };
    if index < 0.0 {
      return Ok(Value::new_undefined(ctx));
    }
    match self.segmentation.segment_at(index as usize) {
      Some(position) => Ok(self.segmentation.data(&ctx, &self.input, position)?.into_value()),
      None => Ok(Value::new_undefined(ctx)),
    }
  }

  #[qjs(rename = PredefinedAtom::SymbolIterator)]
  pub fn iterator(&self, ctx: Ctx<'js>) -> Result<Class<'js, SegmentIterator<'js>>> {
    Class::instance(
      ctx,
      SegmentIterator {
        segmentation: Rc::clone(&self.segmentation),
        input: self.input.clone(),
        position: 0,
      },
    )
  }
}

#[derive(Trace)]
#[rquickjs::class(rename = "Segment Iterator")]
pub struct SegmentIterator<'js> {
  #[qjs(skip_trace)]
  segmentation: Rc<Segmentation>,
  input: rquickjs::String<'js>,
  #[qjs(skip_trace)]
  position: usize,
}

// SAFETY: the only `'js` value is the input string, which belongs to
// the context the iterator does.
#[allow(unsafe_code)]
unsafe impl<'js> JsLifetime<'js> for SegmentIterator<'js> {
  type Changed<'to> = SegmentIterator<'to>;
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> SegmentIterator<'js> {
  pub fn next(&mut self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let result = Object::new(ctx.clone())?;
    if self.position + 1 >= self.segmentation.breaks.len() {
      result.set("value", Value::new_undefined(ctx))?;
      result.set("done", true)?;
      return Ok(result);
    }
    result.set("value", self.segmentation.data(&ctx, &self.input, self.position)?)?;
    result.set("done", false)?;
    self.position += 1;
    Ok(result)
  }

  #[qjs(rename = PredefinedAtom::SymbolIterator)]
  pub fn iterator(this: This<Class<'js, Self>>) -> Class<'js, Self> {
    this.0
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Segmenter String Iterator"
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<Segmenter, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>,
     new_target: This<Value<'js>>,
     locales: Opt<Value<'js>>,
     options: Opt<Value<'js>>|
     -> Result<Segmenter> {
      crate::intl::require_new(&ctx, &new_target.0, "Segmenter")?;
      let requested = locale::canonicalize_list(&ctx, locales.0.as_ref())?;
      let options = options::options_object(&ctx, options.0)?;
      let options = options.as_ref();
      options::locale_matcher(&ctx, options)?;
      let granularity = match options::string(&ctx, options, "granularity", &["grapheme", "word", "sentence"])? {
        Some("word") => Granularity::Word,
        Some("sentence") => Granularity::Sentence,
        _ => Granularity::Grapheme,
      };
      let found = locale::negotiate(&requested, &crate::state::state(&ctx)?.default_locale);
      Ok(Segmenter {
        locale: found.id.to_string(),
        granularity,
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "Segmenter", 0)
}
