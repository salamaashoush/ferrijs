//! Web-platform globals with no upstream in llrt: `atob` / `btoa`,
//! `structuredClone`, `performance`, `FormData`, the compression streams
//! and the timers.
//!
//! The timers are not installed by [`init`]: they carry host state across
//! a scheduled callback, so the host installs them with its own
//! [`timers::CallbackPolicy`].

pub mod blob_bytes;
pub mod compression;
pub mod form_data;
pub mod js_iterator;
pub mod performance;
pub mod timers;

use base64::Engine as _;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::GeneralPurposeConfig;
use rquickjs::function::{Constructor, Func, This};
use rquickjs::{Class, Ctx, Filter, Object, TypedArray, Value};

/// Install `atob`, `btoa`, `structuredClone`, `performance`, `FormData`
/// and `CompressionStream` / `DecompressionStream`.
///
/// # Errors
///
/// Propagates the global writes.
pub fn init(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
  let globals = ctx.globals();

  // btoa/atob over a Latin1 "binary string", per the WHATWG contract.
  globals.set(
    "btoa",
    Func::from(|s: String| -> rquickjs::Result<String> {
      let mut bytes = Vec::with_capacity(s.len());
      for ch in s.chars() {
        let c = ch as u32;
        if c > 0xFF {
          return Err(rquickjs::Error::new_from_js_message(
            "btoa",
            "InvalidCharacterError",
            "string contains characters outside the Latin1 range".to_string(),
          ));
        }
        bytes.push(c as u8);
      }
      Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }),
  )?;
  globals.set(
    "atob",
    Func::from(|s: String| -> rquickjs::Result<String> {
      let bytes = forgiving_base64_decode(&s)
        .map_err(|m| rquickjs::Error::new_from_js_message("atob", "InvalidCharacterError", m.to_string()))?;
      Ok(bytes.into_iter().map(|b| b as char).collect())
    }),
  )?;

  globals.set("structuredClone", Func::from(structured_clone))?;

  performance::init(ctx)?;

  rquickjs::Class::<form_data::FormDataJs>::define(&globals)?;
  compression::install(ctx)?;

  Ok(())
}

/// WHATWG "forgiving-base64 decode"
/// (<https://infra.spec.whatwg.org/#forgiving-base64-decode>): strip
/// ALL ASCII whitespace (not just the ends), reject a length ≡ 1 mod 4,
/// tolerate missing/partial `=` padding, and discard non-zero trailing
/// bits. `base64::STANDARD` does none of this (canonical padding only,
/// no whitespace), so a spec-conformant `atob` needs the explicit
/// algorithm here.
fn forgiving_base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
  let mut s: String = input
    .chars()
    .filter(|c| !matches!(c, '\t' | '\n' | '\u{0C}' | '\r' | ' '))
    .collect();
  // At most two trailing '=' are stripped; any remaining '=' (or one
  // that leaves length ≡ 1 mod 4) is invalid.
  if s.ends_with('=') {
    s.pop();
    if s.ends_with('=') {
      s.pop();
    }
  }
  if s.len() % 4 == 1 || s.contains('=') {
    return Err("invalid base64 length");
  }
  if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
    return Err("invalid base64 character");
  }
  // No-pad alphabet, padding indifferent (we stripped it), trailing
  // bits discarded — exactly the forgiving contract.
  let engine = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
      .with_encode_padding(false)
      .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
      .with_decode_allow_trailing_bits(true),
  );
  engine.decode(s.as_bytes()).map_err(|_| "invalid base64")
}

/// HTML `structuredClone(value)` — a deep clone by the structured-clone
/// algorithm.
///
/// Handles cycles and repeated references (the same object reached twice
/// stays the same object in the clone), `Array`, plain `Object`, `Map`,
/// `Set`, `Date`, `RegExp`, `ArrayBuffer` and typed arrays. Functions,
/// symbols and class instances are not cloneable and raise a
/// `DataCloneError` `DOMException`, per spec — never a silent
/// pass-through, which would alias the original.
fn structured_clone<'js>(ctx: Ctx<'js>, value: Value<'js>) -> rquickjs::Result<Value<'js>> {
  let mut seen: Vec<(Value<'js>, Value<'js>)> = Vec::new();
  let realm = Realm::read(&ctx)?;
  clone_value(&ctx, &realm, &value, &mut seen)
}

/// The constructors and the prototype the clone walk compares against.
///
/// Read once per `structuredClone`, not once per object: deciding what
/// an object is used to cost four global lookups and four `instanceof`
/// prototype walks EVERY time the walk descended, which on a document
/// of small objects is most of the work.
struct Realm<'js> {
  date: Value<'js>,
  regexp: Value<'js>,
  map: Value<'js>,
  set: Value<'js>,
  object_proto: Option<Object<'js>>,
}

impl<'js> Realm<'js> {
  fn read(ctx: &Ctx<'js>) -> rquickjs::Result<Self> {
    let globals = ctx.globals();
    let object: Value<'js> = globals.get("Object")?;
    Ok(Self {
      date: globals.get("Date")?,
      regexp: globals.get("RegExp")?,
      map: globals.get("Map")?,
      set: globals.get("Set")?,
      object_proto: object
        .as_object()
        .and_then(|o| o.get::<_, Value<'js>>("prototype").ok())
        .and_then(|v| v.as_object().cloned()),
    })
  }
}

fn data_clone_error(ctx: &Ctx<'_>, what: &str) -> rquickjs::Error {
  let ex = crate::exceptions::DOMException::new_with_name(
    ctx,
    crate::exceptions::DOMExceptionName::DataCloneError,
    format!("{what} could not be cloned"),
  );
  match ex.and_then(|ex| Class::instance(ctx.clone(), ex)) {
    Ok(ex) => ctx.throw(ex.into_value()),
    Err(e) => e,
  }
}

fn clone_value<'js>(
  ctx: &Ctx<'js>,
  realm: &Realm<'js>,
  value: &Value<'js>,
  seen: &mut Vec<(Value<'js>, Value<'js>)>,
) -> rquickjs::Result<Value<'js>> {
  if value.is_function() {
    return Err(data_clone_error(ctx, "a function"));
  }
  if value.type_of() == rquickjs::Type::Symbol {
    return Err(data_clone_error(ctx, "a symbol"));
  }
  let Some(obj) = value.as_object() else {
    // Primitives are immutable: cloning is identity.
    return Ok(value.clone());
  };
  if let Some((_, clone)) = seen.iter().find(|(orig, _)| orig.as_object() == Some(obj)) {
    return Ok(clone.clone());
  }

  // Arrays and plain objects first, and both answer from the object
  // itself: an array is a native type test, and a plain object is the
  // one whose prototype IS `Object.prototype`. Between them they are
  // almost everything a document contains, and neither now costs a
  // single `instanceof` walk.
  if let Some(arr) = value.as_array() {
    let out = rquickjs::Array::new(ctx.clone())?;
    seen.push((value.clone(), out.clone().into_value()));
    for i in 0..arr.len() {
      let item: Value<'js> = arr.get(i)?;
      out.set(i, clone_value(ctx, realm, &item, seen)?)?;
    }
    return Ok(out.into_value());
  }

  let proto = obj.get_prototype();
  // `Object.create(null)` has no prototype and is still plain.
  if proto.is_none() || proto == realm.object_proto {
    let out = Object::new(ctx.clone())?;
    seen.push((value.clone(), out.clone().into_value()));
    // Own enumerable string keys, as `Value` pairs: taking them as
    // `String` allocated and UTF-8-converted every key twice, once to
    // read it and once to write it back.
    for entry in obj.own_props::<Value<'js>, Value<'js>>(Filter::new().enum_only().string()) {
      let (key, v) = entry?;
      out.set(key, clone_value(ctx, realm, &v, seen)?)?;
    }
    return Ok(out.into_value());
  }

  // Dates and RegExps round-trip through their own constructors.
  if obj.is_instance_of(&realm.date) {
    let ctor = Constructor::from_value(realm.date.clone())?;
    let time: f64 = obj
      .get::<_, rquickjs::Function<'js>>("getTime")?
      .call((This(obj.clone()),))?;
    return ctor.construct::<_, Value<'js>>((time,));
  }
  if obj.is_instance_of(&realm.regexp) {
    let ctor = Constructor::from_value(realm.regexp.clone())?;
    let source: String = obj.get("source")?;
    let flags: String = obj.get("flags")?;
    return ctor.construct::<_, Value<'js>>((source, flags));
  }
  if let Some(buf) = rquickjs::ArrayBuffer::from_object(obj.clone()) {
    // SAFETY: copied out immediately.
    let bytes = unsafe { buf.as_bytes() }.unwrap_or_default().to_vec();
    return Ok(rquickjs::ArrayBuffer::new(ctx.clone(), bytes)?.into_value());
  }
  if let Ok(ta) = TypedArray::<u8>::from_value(value.clone()) {
    // SAFETY: copied out immediately.
    let bytes = unsafe { ta.as_bytes() }.unwrap_or_default().to_vec();
    return Ok(TypedArray::new(ctx.clone(), bytes)?.into_value());
  }

  if obj.is_instance_of(&realm.map) {
    let ctor = Constructor::from_value(realm.map.clone())?;
    let out: Value<'js> = ctor.construct(())?;
    seen.push((value.clone(), out.clone()));
    let out_obj = out.as_object().cloned().unwrap_or_else(|| obj.clone());
    let set: rquickjs::Function<'js> = out_obj.get("set")?;
    for entry in iterate_entries(ctx, obj)? {
      let (k, v) = entry?;
      set.call::<_, ()>((
        This(out_obj.clone()),
        clone_value(ctx, realm, &k, seen)?,
        clone_value(ctx, realm, &v, seen)?,
      ))?;
    }
    return Ok(out);
  }
  if obj.is_instance_of(&realm.set) {
    let ctor = Constructor::from_value(realm.set.clone())?;
    let out: Value<'js> = ctor.construct(())?;
    seen.push((value.clone(), out.clone()));
    let out_obj = out.as_object().cloned().unwrap_or_else(|| obj.clone());
    let add: rquickjs::Function<'js> = out_obj.get("add")?;
    for entry in iterate_entries(ctx, obj)? {
      let (k, _) = entry?;
      add.call::<_, ()>((This(out_obj.clone()), clone_value(ctx, realm, &k, seen)?))?;
    }
    return Ok(out);
  }

  // Anything left has a prototype of its own that is none of the
  // cloneable exotics: a class instance, including the native web
  // classes.
  Err(data_clone_error(ctx, "an object that is not a plain object"))
}

/// `[...target.entries()]` as `(key, value)` pairs — how a `Map`'s
/// contents (and, with the value ignored, a `Set`'s) are read without
/// assuming an internal representation.
#[allow(clippy::type_complexity)]
fn iterate_entries<'js>(
  ctx: &Ctx<'js>,
  target: &Object<'js>,
) -> rquickjs::Result<Vec<rquickjs::Result<(Value<'js>, Value<'js>)>>> {
  let entries: rquickjs::Function<'js> = target.get("entries")?;
  let iter: Value<'js> = entries.call((This(target.clone()),))?;
  let array_ctor: Value<'js> = ctx.globals().get("Array")?;
  let from: rquickjs::Function<'js> = array_ctor
    .as_object()
    .ok_or_else(|| rquickjs::Exception::throw_type(ctx, "Array is not an object"))?
    .get("from")?;
  let list: rquickjs::Array<'js> = from.call((This(array_ctor), iter))?;
  Ok(
    (0..list.len())
      .map(|i| {
        let pair: rquickjs::Array<'js> = list.get(i)?;
        Ok((pair.get(0)?, pair.get(1)?))
      })
      .collect(),
  )
}
