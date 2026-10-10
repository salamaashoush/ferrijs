//! The `Buffer.prototype` methods Node defines over `Uint8Array`'s.
//!
//! `Buffer` inherits `indexOf`, `lastIndexOf`, `includes` and `fill` from
//! `Uint8Array`, which take byte values: `buf.indexOf(',')` coerces the
//! string to a number and answers `-1` without an error, where Node
//! searches for the text. These follow Node's `lib/buffer.js` and the
//! search in `node_buffer.cc` step for step: the offset coercion and
//! clamping, the empty needle, the 16-bit units of a UCS-2 search, the
//! repeated fill pattern and the error codes.

use rquickjs::function::{Constructor, Opt, This};
use rquickjs::{Coerced, Ctx, FromJs, Function, Object, Result, TypedArray, Value};

use crate::encoding::Encoder;

/// `kMaxLength`, the bound `validateOffset` checks an offset against.
const MAX_LENGTH: f64 = 9_007_199_254_740_991.0;

/// Define the methods on `prototype` and `Buffer.compare` on `buffer`.
///
/// # Errors
///
/// Propagates the property writes.
pub fn install<'js>(ctx: &Ctx<'js>, buffer: &Constructor<'js>, prototype: &Object<'js>) -> Result<()> {
  prototype.set("indexOf", Function::new(ctx.clone(), index_of)?.with_length(1)?)?;
  prototype.set("lastIndexOf", Function::new(ctx.clone(), last_index_of)?.with_length(1)?)?;
  prototype.set("includes", Function::new(ctx.clone(), includes)?.with_length(1)?)?;
  prototype.set("fill", Function::new(ctx.clone(), fill)?.with_length(1)?)?;
  prototype.set("compare", Function::new(ctx.clone(), compare)?.with_length(1)?)?;
  prototype.set("swap16", Function::new(ctx.clone(), |ctx, this| swap(ctx, this, 2))?)?;
  prototype.set("swap32", Function::new(ctx.clone(), |ctx, this| swap(ctx, this, 4))?)?;
  prototype.set("swap64", Function::new(ctx.clone(), |ctx, this| swap(ctx, this, 8))?)?;
  buffer.set("compare", Function::new(ctx.clone(), compare_static)?.with_length(2)?)?;
  Ok(())
}

/// Throw Node's coded error: a real `TypeError` or `RangeError` with
/// `code` set, as `internal/errors` makes them.
fn coded(ctx: &Ctx<'_>, kind: &str, code: &str, message: &str) -> rquickjs::Error {
  let built = (|| -> Result<Value<'_>> {
    let ctor: Constructor<'_> = ctx.globals().get(kind)?;
    let error: Object<'_> = ctor.construct((message,))?;
    error.set("code", code)?;
    Ok(error.into_value())
  })();
  match built {
    Ok(error) => ctx.throw(error),
    Err(error) => error,
  }
}

fn invalid_arg_type(ctx: &Ctx<'_>, name: &str, expected: &str) -> rquickjs::Error {
  coded(
    ctx,
    "TypeError",
    "ERR_INVALID_ARG_TYPE",
    &format!("The \"{name}\" argument must be {expected}"),
  )
}

/// `value` as a `Uint8Array`, if it is one.
fn as_view<'js>(value: &Value<'js>) -> Option<TypedArray<'js, u8>> {
  value
    .as_object()
    .and_then(|object| TypedArray::<u8>::from_object(object.clone()).ok())
}

/// The bytes of a `Uint8Array`, or Node's error for anything else.
fn view<'js>(ctx: &Ctx<'js>, value: &Value<'js>, name: &str) -> Result<TypedArray<'js, u8>> {
  as_view(value).ok_or_else(|| invalid_arg_type(ctx, name, "an instance of Buffer or Uint8Array"))
}

/// A copy of a view's bytes, so no JS can run while engine memory is
/// borrowed.
fn bytes_of(array: &TypedArray<'_, u8>) -> Vec<u8> {
  array.as_raw().map(|raw| {
    // SAFETY: read and copied at once, with no JS run in between.
    unsafe { raw.as_ref() }.to_vec()
  }).unwrap_or_default()
}

/// Node's `normalizeEncoding`, answering whether it is UCS-2 as well.
fn encoding(ctx: &Ctx<'_>, name: Option<&str>) -> Result<(Encoder, bool)> {
  let Some(name) = name else {
    return Ok((Encoder::Utf8, false));
  };
  let encoder = Encoder::from_str(name)
    .map_err(|_| coded(ctx, "TypeError", "ERR_UNKNOWN_ENCODING", &format!("Unknown encoding: {name}")))?;
  let ucs2 = matches!(encoder, Encoder::Utf16le);
  Ok((encoder, ucs2))
}

fn string_bytes(value: &Value<'_>, encoder: &Encoder) -> Result<Vec<u8>> {
  let text: String = value.get()?;
  Ok(encoder.decode_from_string(text).unwrap_or_default())
}

/// ECMAScript's ToUint32 of a number.
fn to_uint32(n: f64) -> u32 {
  if !n.is_finite() {
    return 0;
  }
  #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
  let wrapped = n.trunc().rem_euclid(4_294_967_296.0) as u32;
  wrapped
}

/// `IndexOfOffset` in `node_buffer.cc`.
fn index_of_offset(length: i64, offset: i64, needle: i64, forward: bool) -> i64 {
  if offset < 0 {
    if offset + length >= 0 {
      length + offset
    } else if forward || needle == 0 {
      0
    } else {
      -1
    }
  } else if offset + needle <= length {
    offset
  } else if needle == 0 {
    length
  } else if forward {
    -1
  } else {
    length - 1
  }
}

/// `SearchString` over units of `unit` bytes: the first match at or after
/// `start`, or the last at or before it.
fn search(haystack: &[u8], needle: &[u8], unit: usize, start: usize, forward: bool) -> Option<usize> {
  let units = haystack.len() / unit;
  let needle_units = needle.len() / unit;
  if units < needle_units {
    return None;
  }
  let needle = &needle[..needle_units * unit];
  let matches = |at: usize| haystack[at * unit..(at + needle_units) * unit] == *needle;
  let last = units - needle_units;
  if forward {
    (start..=last).find(|&at| matches(at)).map(|at| at * unit)
  } else {
    (0..=start.min(last)).rev().find(|&at| matches(at)).map(|at| at * unit)
  }
}

/// `bidirectionalIndexOf`.
fn bidirectional<'js>(
  ctx: &Ctx<'js>,
  this: &Value<'js>,
  value: &Value<'js>,
  offset: Option<Value<'js>>,
  encoding_arg: Option<Value<'js>>,
  forward: bool,
) -> Result<i64> {
  let haystack = bytes_of(&view(ctx, this, "buffer")?);
  let length = i64::try_from(haystack.len()).unwrap_or(i64::MAX);

  let (offset, encoding_arg) = match offset {
    Some(offset) if offset.is_string() => (None, Some(offset)),
    other => (other, encoding_arg),
  };
  let mut position = match offset {
    Some(offset) => Coerced::<f64>::from_js(ctx, offset)?.0,
    None => f64::NAN,
  };
  if position > f64::from(i32::MAX) {
    position = f64::from(i32::MAX);
  } else if position < f64::from(i32::MIN) {
    position = f64::from(i32::MIN);
  }
  #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
  let position = if position.is_nan() {
    if forward { 0 } else { length }
  } else {
    position.trunc() as i64
  };

  if let Some(number) = value.as_number() {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let byte = (to_uint32(number) & 0xFF) as u8;
    let start = index_of_offset(length, position, 1, forward);
    if start <= -1 || haystack.is_empty() {
      return Ok(-1);
    }
    let start = usize::try_from(start).unwrap_or(0);
    let found = if forward {
      haystack[start..].iter().position(|b| *b == byte).map(|at| at + start)
    } else {
      haystack[..=start.min(haystack.len() - 1)].iter().rposition(|b| *b == byte)
    };
    return Ok(found.map_or(-1, |at| i64::try_from(at).unwrap_or(-1)));
  }

  let encoding_name: Option<String> = match &encoding_arg {
    Some(name) if !name.is_undefined() => Some(name.get()?),
    _ => None,
  };
  let (needle, ucs2, needle_chars) = if value.is_string() {
    let (encoder, ucs2) = encoding(ctx, encoding_name.as_deref())?;
    let chars: usize = value.as_string().map_or(0, |s| s.to_string().map_or(0, |s| s.encode_utf16().count()));
    (string_bytes(value, &encoder)?, ucs2, Some(chars))
  } else if let Some(other) = as_view(value) {
    let ucs2 = encoding_name
      .as_deref()
      .and_then(|name| Encoder::from_str(name).ok())
      .is_some_and(|encoder| matches!(encoder, Encoder::Utf16le));
    (bytes_of(&other), ucs2, None)
  } else {
    return Err(invalid_arg_type(
      ctx,
      "value",
      "one of type number or string or an instance of Buffer or Uint8Array",
    ));
  };

  // A UCS-2 search runs over whole 16-bit units: an odd last byte is not
  // part of the haystack at all.
  let haystack = if ucs2 { &haystack[..haystack.len() & !1] } else { &haystack[..] };
  let length = i64::try_from(haystack.len()).unwrap_or(i64::MAX);
  let needle_length = i64::try_from(needle.len()).unwrap_or(i64::MAX);
  let start = index_of_offset(length, position, needle_length, forward);
  if needle.is_empty() {
    return Ok(start);
  }
  if haystack.is_empty() || start <= -1 {
    return Ok(-1);
  }
  let start = usize::try_from(start).unwrap_or(0);
  if (forward && needle.len() + start > haystack.len()) || needle.len() > haystack.len() {
    return Ok(-1);
  }
  let found = if ucs2 {
    let too_short = match needle_chars {
      Some(chars) => chars < 1,
      None => needle.len() < 2,
    };
    if haystack.len() < 2 || too_short {
      return Ok(-1);
    }
    search(haystack, &needle, 2, start / 2, forward)
  } else {
    search(haystack, &needle, 1, start, forward)
  };
  Ok(found.map_or(-1, |at| i64::try_from(at).unwrap_or(-1)))
}

fn index_of<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  value: Value<'js>,
  offset: Opt<Value<'js>>,
  encoding: Opt<Value<'js>>,
) -> Result<i64> {
  bidirectional(&ctx, &this.0, &value, offset.0, encoding.0, true)
}

fn last_index_of<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  value: Value<'js>,
  offset: Opt<Value<'js>>,
  encoding: Opt<Value<'js>>,
) -> Result<i64> {
  bidirectional(&ctx, &this.0, &value, offset.0, encoding.0, false)
}

fn includes<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  value: Value<'js>,
  offset: Opt<Value<'js>>,
  encoding: Opt<Value<'js>>,
) -> Result<bool> {
  Ok(bidirectional(&ctx, &this.0, &value, offset.0, encoding.0, true)? != -1)
}

/// `validateOffset(value, name, min, max)`.
fn offset_arg(ctx: &Ctx<'_>, value: &Value<'_>, name: &str, max: f64) -> Result<usize> {
  let Some(n) = value.as_number() else {
    return Err(invalid_arg_type(ctx, name, "of type number"));
  };
  if n.fract() != 0.0 || !n.is_finite() {
    return Err(coded(
      ctx,
      "RangeError",
      "ERR_OUT_OF_RANGE",
      &format!("The value of \"{name}\" is out of range. It must be an integer. Received {n}"),
    ));
  }
  if n < 0.0 || n > max {
    return Err(coded(
      ctx,
      "RangeError",
      "ERR_OUT_OF_RANGE",
      &format!("The value of \"{name}\" is out of range. It must be >= 0 && <= {max}. Received {n}"),
    ));
  }
  #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
  Ok(n as usize)
}

/// Write `pattern` over `bytes[start..end]` repeatedly.
fn fill_with(array: &TypedArray<'_, u8>, start: usize, end: usize, pattern: &[u8]) {
  if let Some(raw) = array.as_raw() {
    // SAFETY: written at once with no JS run in between; `end` was
    // checked against the view's length.
    let bytes = unsafe { &mut *raw.as_ptr() };
    let end = end.min(bytes.len());
    if start >= end || pattern.is_empty() {
      return;
    }
    for (slot, byte) in bytes[start..end].iter_mut().zip(pattern.iter().cycle()) {
      *slot = *byte;
    }
  }
}

/// `Buffer.prototype.fill` (`_fill` and the native `Fill`).
fn fill<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  value: Value<'js>,
  offset: Opt<Value<'js>>,
  end: Opt<Value<'js>>,
  encoding_arg: Opt<Value<'js>>,
) -> Result<Value<'js>> {
  let array = view(&ctx, &this.0, "buffer")?;
  let length = array.len();
  let (mut offset, mut end, mut encoding_arg) = (offset.0, end.0, encoding_arg.0);

  let mut pattern: Option<Vec<u8>> = None;
  let mut number: Option<f64> = value.as_number();
  if value.is_string() {
    if offset.as_ref().is_none_or(|o| o.is_undefined() || o.is_string()) {
      encoding_arg = offset.take().filter(|o| !o.is_undefined());
      offset = Some(Value::new_int(ctx.clone(), 0));
      end = Some(Value::new_number(ctx.clone(), length as f64));
    } else if end.as_ref().is_some_and(Value::is_string) {
      encoding_arg = end.take();
      end = Some(Value::new_number(ctx.clone(), length as f64));
    }
    let name: Option<String> = match &encoding_arg {
      Some(name) if !name.is_undefined() => {
        if !name.is_string() {
          return Err(invalid_arg_type(&ctx, "encoding", "of type string"));
        }
        Some(name.get()?)
      },
      _ => None,
    };
    let (encoder, _) = encoding(&ctx, name.as_deref())?;
    let text: String = value.get()?;
    let utf16: Vec<u16> = text.encode_utf16().collect();
    if utf16.is_empty() {
      number = Some(0.0);
    } else if utf16.len() == 1
      && (matches!(encoder, Encoder::Latin1) || (matches!(encoder, Encoder::Utf8) && utf16[0] < 128))
    {
      // Node's single-byte fast path, which also means a latin1 character
      // above 0xFF fills with its low byte.
      number = Some(f64::from(utf16[0]));
    } else {
      pattern = Some(encoder.decode_from_string(text).unwrap_or_default());
    }
  }

  let (start, stop) = match &offset {
    None => (0, length),
    Some(offset) if offset.is_undefined() => (0, length),
    Some(offset) => {
      let start = offset_arg(&ctx, offset, "offset", MAX_LENGTH)?;
      #[allow(clippy::cast_precision_loss)]
      let stop = match &end {
        Some(end) if !end.is_undefined() => offset_arg(&ctx, end, "end", length as f64)?,
        _ => length,
      };
      if start >= stop {
        return Ok(this.0);
      }
      (start, stop)
    },
  };

  if let Some(number) = number {
    if start > stop || stop > length {
      return Err(coded(&ctx, "RangeError", "ERR_BUFFER_OUT_OF_BOUNDS", "Attempt to access memory outside buffer bounds"));
    }
    // `TypedArray.prototype.fill`: ToUint8 of the number.
    let byte = Coerced::<i32>::from_js(&ctx, Value::new_number(ctx.clone(), number))?.0;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fill_with(&array, start, stop, &[byte as u8]);
    return Ok(this.0);
  }

  let pattern = match pattern {
    Some(pattern) => pattern,
    None => match as_view(&value) {
      Some(other) => bytes_of(&other),
      None => {
        let byte = to_uint32(Coerced::<f64>::from_js(&ctx, value.clone())?.0);
        vec![byte.to_le_bytes()[0]]
      },
    },
  };
  if stop > length {
    return Err(coded(&ctx, "RangeError", "ERR_BUFFER_OUT_OF_BOUNDS", "Attempt to access memory outside buffer bounds"));
  }
  if pattern.is_empty() {
    return Err(coded(
      &ctx,
      "TypeError",
      "ERR_INVALID_ARG_VALUE",
      "The argument 'value' is invalid.",
    ));
  }
  fill_with(&array, start, stop, &pattern);
  Ok(this.0)
}

/// `normalizeCompareVal` over the compared ranges.
fn ordering(a: &[u8], b: &[u8]) -> i32 {
  let shared = a.len().min(b.len());
  match a[..shared].cmp(&b[..shared]).then(a.len().cmp(&b.len())) {
    std::cmp::Ordering::Less => -1,
    std::cmp::Ordering::Equal => 0,
    std::cmp::Ordering::Greater => 1,
  }
}

fn compare_static<'js>(ctx: Ctx<'js>, a: Value<'js>, b: Value<'js>) -> Result<i32> {
  let a = bytes_of(&view(&ctx, &a, "buf1")?);
  let b = bytes_of(&view(&ctx, &b, "buf2")?);
  Ok(ordering(&a, &b))
}

fn compare<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  target: Value<'js>,
  target_start: Opt<Value<'js>>,
  target_end: Opt<Value<'js>>,
  source_start: Opt<Value<'js>>,
  source_end: Opt<Value<'js>>,
) -> Result<i32> {
  let source = bytes_of(&view(&ctx, &this.0, "buffer")?);
  let target = bytes_of(&view(&ctx, &target, "target")?);
  let given = |v: &Option<Value<'js>>| v.as_ref().filter(|v| !v.is_undefined()).cloned();
  #[allow(clippy::cast_precision_loss)]
  let (ts, te, ss, se) = (
    given(&target_start.0).map_or(Ok(0), |v| offset_arg(&ctx, &v, "targetStart", MAX_LENGTH))?,
    given(&target_end.0).map_or(Ok(target.len()), |v| offset_arg(&ctx, &v, "targetEnd", target.len() as f64))?,
    given(&source_start.0).map_or(Ok(0), |v| offset_arg(&ctx, &v, "sourceStart", MAX_LENGTH))?,
    given(&source_end.0).map_or(Ok(source.len()), |v| offset_arg(&ctx, &v, "sourceEnd", source.len() as f64))?,
  );
  if ss >= se {
    return Ok(if ts >= te { 0 } else { -1 });
  }
  if ts >= te {
    return Ok(1);
  }
  if ss > source.len() {
    return Err(coded(&ctx, "RangeError", "ERR_OUT_OF_RANGE", "The value of \"sourceStart\" is out of range."));
  }
  if ts > target.len() {
    return Err(coded(&ctx, "RangeError", "ERR_OUT_OF_RANGE", "The value of \"targetStart\" is out of range."));
  }
  Ok(ordering(&source[ss..se.min(source.len())], &target[ts..te.min(target.len())]))
}

fn swap<'js>(ctx: Ctx<'js>, this: This<Value<'js>>, width: usize) -> Result<Value<'js>> {
  let array = view(&ctx, &this.0, "buffer")?;
  if array.len() % width != 0 {
    return Err(coded(
      &ctx,
      "RangeError",
      "ERR_INVALID_BUFFER_SIZE",
      &format!("Buffer size must be a multiple of {}-bits", width * 8),
    ));
  }
  if let Some(raw) = array.as_raw() {
    // SAFETY: swapped in place at once with no JS run in between.
    let bytes = unsafe { &mut *raw.as_ptr() };
    for chunk in bytes.chunks_exact_mut(width) {
      chunk.reverse();
    }
  }
  Ok(this.0)
}
