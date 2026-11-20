//! ICU4X formatters annotate what they write with `writeable::Part`s;
//! `formatToParts` is those annotations under ECMA-402's names. A
//! [`Recorder`] keeps the text a formatter wrote, segment by segment,
//! with the innermost part each segment was written under.

use std::fmt;

use rquickjs::{Array, Ctx, Object, Result};
use writeable::{Part, PartsWrite, Writeable};

/// One run of text, with every part it was written under, outermost
/// first.
pub(crate) type Segment = (Vec<Part>, String);

#[derive(Default)]
pub(crate) struct Recorder {
  segments: Vec<Segment>,
  stack: Vec<Part>,
}

impl Recorder {
  /// Each segment under the innermost part it was written in: a digit
  /// a currency formatter wrote is an `integer`.
  pub(crate) fn record(writeable: &impl Writeable) -> Vec<(Option<Part>, String)> {
    Self::segments(writeable)
      .into_iter()
      .map(|(stack, text)| (stack.last().copied(), text))
      .fold(Vec::new(), |mut out, (part, text)| {
        match out.last_mut() {
          Some((last_part, last)) if *last_part == part => last.push_str(&text),
          _ => out.push((part, text)),
        }
        out
      })
  }

  /// Each segment under every part it was written in: a digit a date
  /// formatter wrote inside its year is the `year`, the fraction of its
  /// seconds is told from the whole seconds, and a range's two ends from
  /// what they share.
  pub(crate) fn segments(writeable: &impl Writeable) -> Vec<Segment> {
    let mut recorder = Self::default();
    match writeable.write_to_parts(&mut recorder) {
      Ok(()) => recorder.segments,
      Err(_) => Vec::new(),
    }
  }
}

impl fmt::Write for Recorder {
  fn write_str(&mut self, text: &str) -> fmt::Result {
    if text.is_empty() {
      return Ok(());
    }
    match self.segments.last_mut() {
      Some((stack, last)) if *stack == self.stack => last.push_str(text),
      _ => self.segments.push((self.stack.clone(), text.to_owned())),
    }
    Ok(())
  }
}

impl PartsWrite for Recorder {
  type SubPartsWrite = Self;

  fn with_part(&mut self, part: Part, mut f: impl FnMut(&mut Self) -> fmt::Result) -> fmt::Result {
    self.stack.push(part);
    let result = f(self);
    self.stack.pop();
    result
  }
}

/// One `{ type, value }` of a `formatToParts` result, under ECMA-402's
/// type name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsPart {
  pub(crate) kind: &'static str,
  pub(crate) value: String,
  pub(crate) source: Option<&'static str>,
  pub(crate) unit: Option<&'static str>,
}

impl JsPart {
  pub(crate) fn new(kind: &'static str, value: impl Into<String>) -> Self {
    Self {
      kind,
      value: value.into(),
      source: None,
      unit: None,
    }
  }
}

/// Append `part` to `parts`, joining it to the last one when both are
/// the same type, as adjacent literals are one part in ECMA-402.
pub(crate) fn push(parts: &mut Vec<JsPart>, part: JsPart) {
  if part.value.is_empty() {
    return;
  }
  if let Some(last) = parts.last_mut()
    && last.kind == part.kind
    && last.kind == "literal"
    && last.source == part.source
  {
    last.value.push_str(&part.value);
    return;
  }
  parts.push(part);
}

pub(crate) fn concat(parts: &[JsPart]) -> String {
  let mut text = String::with_capacity(parts.iter().map(|p| p.value.len()).sum());
  for part in parts {
    text.push_str(&part.value);
  }
  text
}

pub(crate) fn to_array<'js>(ctx: &Ctx<'js>, parts: &[JsPart]) -> Result<Array<'js>> {
  let array = Array::new(ctx.clone())?;
  for (index, part) in parts.iter().enumerate() {
    let object = Object::new(ctx.clone())?;
    object.set("type", part.kind)?;
    object.set("value", part.value.as_str())?;
    if let Some(source) = part.source {
      object.set("source", source)?;
    }
    if let Some(unit) = part.unit {
      object.set("unit", unit)?;
    }
    array.set(index, object)?;
  }
  Ok(array)
}
