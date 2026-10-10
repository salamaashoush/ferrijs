//! A script's value as `serde_json::Value`, walked over the raw engine.
//!
//! The answer is exactly what `ferrijs-serde` driving the
//! `value::JsonValue` visitor gives, step for step: the same property
//! reads in the same order, the same `toJSON` / `valueOf` / `toString`
//! calls with the same arguments, the same skips, the same cycle check
//! and the same exceptions left pending on a failure. One difference is
//! deliberate: it never looks a method up on `null` or `undefined`, which
//! left a stray `TypeError` pending after a successful conversion. A test
//! runs both over a corpus and requires the same result otherwise.
//!
//! What it saves is everything around that: every `rquickjs::Value`
//! re-counts its context on the way in and out, and serde's visitor
//! layering costs more than the work at each node. Here a value is a
//! bare `JSValue`, owned ones freed by [`Owned`].

#![allow(unsafe_code)]

use std::ffi::c_char;

use rquickjs::atom::PredefinedAtom;
use rquickjs::{Ctx, Value, qjs};
use rustc_hash::FxHashMap;

/// The class ids `ferrijs-serde` asks about.
const CLASS_NUMBER: u32 = 4;
const CLASS_STRING: u32 = 5;
const CLASS_BOOL: u32 = 6;
const CLASS_BIG_INT: u32 = 35;

#[allow(clippy::cast_precision_loss)]
const MAX_SAFE_INTEGER: f64 = ((1u64 << 53) - 1) as f64;

/// Every failure has already done what the walker it mirrors did to the
/// context (an exception pending, or not); the caller only needs to know
/// there was one.
struct Failed;

type Walked<T> = Result<T, Failed>;

/// The JSON for `value`, or `None` where `ferrijs-serde` would fail.
pub(crate) fn convert(ctx: &Ctx<'_>, value: &Value<'_>) -> Option<serde_json::Value> {
  let mut walker = Walker {
    ctx: ctx.as_raw().as_ptr(),
    stack: Vec::new(),
    keys: FxHashMap::default(),
  };
  // SAFETY: `value` is a live value of `ctx`, borrowed for the walk, and
  // the walk runs on the thread holding `ctx`.
  unsafe { walker.any(value.as_raw()) }.ok()
}

/// A value this walk owns a reference to.
struct Owned {
  ctx: *mut qjs::JSContext,
  value: qjs::JSValue,
}

impl Drop for Owned {
  fn drop(&mut self) {
    // SAFETY: `value` is a reference this walk took and has not freed.
    unsafe { qjs::JS_FreeValue(self.ctx, self.value) }
  }
}

struct Walker {
  ctx: *mut qjs::JSContext,
  /// The arrays and objects being walked, for the cycle check. Each one
  /// is held alive by the frame walking it.
  stack: Vec<qjs::JSValue>,
  /// Each key converted once per walk: rows of one shape share their
  /// keys. The walker holds a reference on every atom here, so none is
  /// freed and its number reused for a different name mid-walk.
  keys: FxHashMap<qjs::JSAtom, String>,
}

impl Drop for Walker {
  fn drop(&mut self) {
    for atom in self.keys.keys() {
      // SAFETY: each cached atom was duplicated when it was cached.
      unsafe { qjs::JS_FreeAtom(self.ctx, *atom) }
    }
  }
}

fn tag(value: qjs::JSValue) -> i32 {
  // SAFETY: reading a value's tag touches nothing it points at.
  unsafe { qjs::JS_VALUE_GET_NORM_TAG(value) }
}

fn same(a: qjs::JSValue, b: qjs::JSValue) -> bool {
  // SAFETY: as `rquickjs::Value`'s `PartialEq`: tag and payload bits only.
  unsafe {
    qjs::JS_VALUE_GET_TAG(a) == qjs::JS_VALUE_GET_TAG(b)
      && qjs::JS_VALUE_GET_FLOAT64(a).to_bits() == qjs::JS_VALUE_GET_FLOAT64(b).to_bits()
  }
}

fn is_string(value: qjs::JSValue) -> bool {
  // SAFETY: tag read only.
  let tag = unsafe { qjs::JS_VALUE_GET_TAG(value) };
  tag == qjs::JS_TAG_STRING || tag == qjs::JS_TAG_STRING_ROPE
}

fn null() -> qjs::JSValue {
  qjs::JSValue {
    u: qjs::JSValueUnion { int32: 0 },
    tag: i64::from(qjs::JS_TAG_NULL),
  }
}

impl Walker {
  fn own(&self, value: qjs::JSValue) -> Walked<Owned> {
    let owned = Owned { ctx: self.ctx, value };
    if tag(value) == qjs::JS_TAG_EXCEPTION {
      return Err(Failed);
    }
    Ok(owned)
  }

  unsafe fn dup(&self, value: qjs::JSValue) -> Owned {
    Owned {
      ctx: self.ctx,
      value: unsafe { qjs::JS_DupValue(self.ctx, value) },
    }
  }

  unsafe fn throw_type(&self, message: &'static std::ffi::CStr) -> Failed {
    unsafe {
      qjs::JS_ThrowTypeError(self.ctx, c"%s".as_ptr(), message.as_ptr());
    }
    Failed
  }

  /// `value[atom]` when it is a function; anything else, a throw
  /// included, is no method (the throw stays pending, as it did).
  ///
  /// `null` and `undefined` have no properties to look up. `ferrijs-serde`
  /// looked anyway and left the engine's `TypeError` pending in the
  /// context after a conversion that succeeded; this walk does not.
  unsafe fn method(&self, value: qjs::JSValue, atom: PredefinedAtom) -> Option<Owned> {
    if matches!(tag(value), qjs::JS_TAG_NULL | qjs::JS_TAG_UNDEFINED) {
      return None;
    }
    let found = Owned {
      ctx: self.ctx,
      value: unsafe { qjs::JS_GetProperty(self.ctx, value, atom as qjs::JSAtom) },
    };
    unsafe { qjs::JS_IsFunction(self.ctx, found.value) }.then_some(found)
  }

  unsafe fn call(&self, function: &Owned, this: qjs::JSValue, args: &mut [qjs::JSValue]) -> Walked<Owned> {
    let count = i32::try_from(args.len()).unwrap_or(i32::MAX);
    self.own(unsafe { qjs::JS_Call(self.ctx, function.value, this, count, args.as_mut_ptr()) })
  }

  /// `ensure_supported`: `Ok(false)` for what JSON drops, a throw for a
  /// boxed `BigInt`.
  unsafe fn supported(&self, value: qjs::JSValue) -> Walked<bool> {
    let class = unsafe { qjs::JS_GetClassID(value) };
    if class == CLASS_BOOL || class == CLASS_NUMBER {
      return Ok(true);
    }
    if class == CLASS_BIG_INT {
      return Err(unsafe { self.throw_type(c"BigInt not supported") });
    }
    let dropped = match tag(value) {
      qjs::JS_TAG_UNDEFINED | qjs::JS_TAG_SYMBOL | qjs::JS_TAG_UNINITIALIZED => true,
      qjs::JS_TAG_OBJECT => unsafe { qjs::JS_IsFunction(self.ctx, value) },
      _ => false,
    };
    Ok(!dropped)
  }

  unsafe fn check_cycles(&self, value: qjs::JSValue) -> Walked<()> {
    if self.stack.iter().rev().any(|seen| same(*seen, value)) {
      return Err(unsafe { self.throw_type(c"circular dependency") });
    }
    Ok(())
  }

  unsafe fn number(&self, value: qjs::JSValue) -> Walked<serde_json::Value> {
    if unsafe { qjs::JS_VALUE_GET_TAG(value) } == qjs::JS_TAG_INT {
      return Ok(serde_json::Value::from(i64::from(unsafe {
        qjs::JS_VALUE_GET_INT(value)
      })));
    }
    if tag(value) == qjs::JS_TAG_FLOAT64 {
      let n = unsafe { qjs::JS_VALUE_GET_FLOAT64(value) };
      let whole = (n % 1.0) == 0.0;
      if whole && n.is_sign_positive() && n <= f64::from(u32::MAX) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        return Ok(serde_json::Value::from(u64::from(n as u32)));
      }
      if whole && (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) {
        #[allow(clippy::cast_possible_truncation)]
        return Ok(serde_json::Value::from(n as i64));
      }
      return Ok(serde_json::Number::from_f64(n).map_or(serde_json::Value::Null, serde_json::Value::Number));
    }
    Err(unsafe { self.throw_type(c"Unsupported number type") })
  }

  unsafe fn string(&self, value: qjs::JSValue) -> Walked<String> {
    let mut len: qjs::size_t = 0;
    let ptr = unsafe { qjs::JS_ToCStringLen2(self.ctx, &raw mut len, value, false) };
    if ptr.is_null() {
      return Err(Failed);
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), usize::try_from(len).unwrap_or(0)) };
    let text = match std::str::from_utf8(bytes) {
      Ok(text) => text.to_owned(),
      Err(error) => lossy(bytes, error),
    };
    unsafe { qjs::JS_FreeCString(self.ctx, ptr.cast::<c_char>()) };
    Ok(text)
  }

  /// The key string for `atom`, as `ferrijs-serde` makes it from the
  /// atom's string value.
  unsafe fn key(&mut self, atom: qjs::JSAtom) -> Walked<String> {
    if let Some(key) = self.keys.get(&atom) {
      return Ok(key.clone());
    }
    let mut len: qjs::size_t = 0;
    let ptr = unsafe { qjs::JS_AtomToCStringLen(self.ctx, &raw mut len, atom) };
    if ptr.is_null() {
      return Err(Failed);
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), usize::try_from(len).unwrap_or(0)) };
    let key = match std::str::from_utf8(bytes) {
      Ok(text) => text.to_owned(),
      Err(error) => lossy(bytes, error),
    };
    unsafe { qjs::JS_FreeCString(self.ctx, ptr) };
    self
      .keys
      .insert(unsafe { qjs::JS_DupAtom(self.ctx, atom) }, key.clone());
    Ok(key)
  }

  /// `deserialize_any`, for a value borrowed from the caller.
  unsafe fn any(&mut self, value: qjs::JSValue) -> Walked<serde_json::Value> {
    let t = tag(value);
    if t == qjs::JS_TAG_INT || t == qjs::JS_TAG_FLOAT64 {
      return unsafe { self.number(value) };
    }
    let class = unsafe { qjs::JS_GetClassID(value) };
    if class == CLASS_NUMBER
      && let Some(value_of) = unsafe { self.method(value, PredefinedAtom::ValueOf) }
    {
      let unboxed = unsafe { self.call(&value_of, value, &mut []) }?;
      return unsafe { self.number(unboxed.value) };
    }
    if unsafe { qjs::JS_VALUE_GET_TAG(value) } == qjs::JS_TAG_BOOL {
      return Ok(serde_json::Value::Bool(unsafe { qjs::JS_VALUE_GET_BOOL(value) }));
    }
    if class == CLASS_BOOL
      && let Some(value_of) = unsafe { self.method(value, PredefinedAtom::ValueOf) }
    {
      let unboxed = unsafe { self.call(&value_of, value, &mut []) }?;
      if unsafe { qjs::JS_VALUE_GET_TAG(unboxed.value) } != qjs::JS_TAG_BOOL {
        return Err(Failed);
      }
      return Ok(serde_json::Value::Bool(unsafe {
        qjs::JS_VALUE_GET_BOOL(unboxed.value)
      }));
    }
    if t == qjs::JS_TAG_NULL || t == qjs::JS_TAG_UNDEFINED {
      return Ok(serde_json::Value::Null);
    }

    let mut current = unsafe { self.dup(value) };
    if class == CLASS_STRING
      && let Some(to_string) = unsafe { self.method(value, PredefinedAtom::ToString) }
    {
      current = unsafe { self.call(&to_string, value, &mut []) }?;
    }
    let value = current.value;

    if is_string(value) {
      return unsafe { self.string(value) }.map(serde_json::Value::String);
    }
    if tag(value) == qjs::JS_TAG_OBJECT && unsafe { self.array_like(value) } {
      return unsafe { self.seq(value) };
    }
    if tag(value) == qjs::JS_TAG_OBJECT {
      unsafe { self.supported(value) }?;
      if let Some(to_json) = unsafe { self.method(value, PredefinedAtom::ToJSON) } {
        let replaced = unsafe { self.call(&to_json, value, &mut []) }?;
        return unsafe { self.any(replaced.value) };
      }
      return unsafe { self.map(value) };
    }
    let class = unsafe { qjs::JS_GetClassID(value) };
    let t = tag(value);
    if class == CLASS_BIG_INT || t == qjs::JS_TAG_BIG_INT || t == qjs::JS_TAG_SHORT_BIG_INT {
      if let Some(to_json) = unsafe { self.method(value, PredefinedAtom::ToJSON) } {
        let replaced = unsafe { self.call(&to_json, value, &mut []) }?;
        return unsafe { self.any(replaced.value) };
      }
      if let Some(to_string) = unsafe { self.method(value, PredefinedAtom::ToString) } {
        let replaced = unsafe { self.call(&to_string, value, &mut []) }?;
        return unsafe { self.any(replaced.value) };
      }
    }
    Err(unsafe { self.throw_type(c"Unsupported type") })
  }

  /// An array, or a proxy whose target (through any chain of proxies) is.
  unsafe fn array_like(&self, value: qjs::JSValue) -> bool {
    if unsafe { qjs::JS_IsArray(value) } {
      return true;
    }
    let mut current = unsafe { self.dup(value) };
    loop {
      if !unsafe { qjs::JS_IsProxy(current.value) } {
        return false;
      }
      let Ok(target) = self.own(unsafe { qjs::JS_GetProxyTarget(self.ctx, current.value) }) else {
        return false;
      };
      if unsafe { qjs::JS_IsArray(target.value) } {
        return true;
      }
      current = target;
    }
  }

  unsafe fn seq(&mut self, array: qjs::JSValue) -> Walked<serde_json::Value> {
    self.stack.push(array);
    let out = unsafe { self.seq_items(array) };
    self.stack.pop();
    out
  }

  unsafe fn seq_items(&mut self, array: qjs::JSValue) -> Walked<serde_json::Value> {
    let length = self.own(unsafe { qjs::JS_GetProperty(self.ctx, array, PredefinedAtom::Length as qjs::JSAtom) })?;
    let length = match tag(length.value) {
      qjs::JS_TAG_INT => f64::from(unsafe { qjs::JS_VALUE_GET_INT(length.value) }),
      qjs::JS_TAG_FLOAT64 => unsafe { qjs::JS_VALUE_GET_FLOAT64(length.value) },
      _ => {
        let mut n = 0.0;
        if unsafe { qjs::JS_ToFloat64(self.ctx, &raw mut n, length.value) } < 0 {
          return Err(Failed);
        }
        n
      },
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // A NaN length clamps to NaN, which the cast takes to zero.
    let length = length.clamp(0.0, MAX_SAFE_INTEGER) as usize;
    let mut items = Vec::with_capacity(length.min(1 << 16));
    for index in 0..length {
      #[allow(clippy::cast_possible_truncation)]
      let element = self.own(unsafe { qjs::JS_GetPropertyUint32(self.ctx, array, index as u32) })?;
      let item = if let Some(to_json) = unsafe { self.method(element.value, PredefinedAtom::ToJSON) } {
        let key = index.to_string();
        let key = self.own(unsafe { qjs::JS_NewStringLen(self.ctx, key.as_ptr().cast::<c_char>(), key.len() as _) })?;
        let mut args = [key.value];
        unsafe { self.call(&to_json, element.value, &mut args) }?
      } else if unsafe { self.supported(element.value) }? {
        element
      } else {
        Owned {
          ctx: self.ctx,
          value: null(),
        }
      };
      unsafe { self.check_cycles(item.value) }?;
      items.push(unsafe { self.any(item.value) }?);
    }
    Ok(serde_json::Value::Array(items))
  }

  unsafe fn map(&mut self, object: qjs::JSValue) -> Walked<serde_json::Value> {
    self.stack.push(object);
    let out = unsafe { self.map_entries(object) };
    self.stack.pop();
    out
  }

  unsafe fn map_entries(&mut self, object: qjs::JSValue) -> Walked<serde_json::Value> {
    let mut table: *mut qjs::JSPropertyEnum = std::ptr::null_mut();
    let mut count: u32 = 0;
    let flags = (qjs::JS_GPN_STRING_MASK | qjs::JS_GPN_ENUM_ONLY).cast_signed();
    if unsafe { qjs::JS_GetOwnPropertyNames(self.ctx, &raw mut table, &raw mut count, object, flags) } < 0 {
      return Err(Failed);
    }
    let names = Names {
      ctx: self.ctx,
      table,
      count,
    };
    let mut entries = Vec::with_capacity(count as usize);
    for name in names.atoms() {
      let value = self.own(unsafe { qjs::JS_GetProperty(self.ctx, object, name) })?;
      let value = if let Some(to_json) = unsafe { self.method(value.value, PredefinedAtom::ToJSON) } {
        // The key's JS string only exists to be `toJSON`'s argument.
        let key = self.own(unsafe { qjs::JS_AtomToValue(self.ctx, name) })?;
        let mut args = [key.value];
        unsafe { self.call(&to_json, value.value, &mut args) }?
      } else {
        value
      };
      // String-masked enumeration answers no symbol, so `ferrijs-serde`'s
      // symbol-key skip never fires.
      if !unsafe { self.supported(value.value) }? {
        continue;
      }
      let class = unsafe { qjs::JS_GetClassID(value.value) };
      let unboxer = match class {
        CLASS_BOOL | CLASS_NUMBER => unsafe { self.method(value.value, PredefinedAtom::ValueOf) },
        CLASS_STRING => unsafe { self.method(value.value, PredefinedAtom::ToString) },
        _ => None,
      };
      let value = match unboxer {
        Some(unbox) => unsafe { self.call(&unbox, value.value, &mut []) }?,
        None => value,
      };
      let key = unsafe { self.key(name) }?;
      unsafe { self.check_cycles(value.value) }?;
      entries.push((key, unsafe { self.any(value.value) }?));
    }
    Ok(serde_json::Value::Object(entries.into_iter().collect()))
  }
}

/// A property-name table from `JS_GetOwnPropertyNames`, freed on drop.
struct Names {
  ctx: *mut qjs::JSContext,
  table: *mut qjs::JSPropertyEnum,
  count: u32,
}

impl Names {
  fn atoms(&self) -> impl Iterator<Item = qjs::JSAtom> + '_ {
    (0..self.count as usize).map(|i| {
      // SAFETY: `i` is within the `count` entries the engine wrote.
      unsafe { (*self.table.add(i)).atom }
    })
  }
}

impl Drop for Names {
  fn drop(&mut self) {
    if !self.table.is_null() {
      // SAFETY: the table and its atoms came from `JS_GetOwnPropertyNames`.
      unsafe { qjs::JS_FreePropertyEnum(self.ctx, self.table, self.count) }
    }
  }
}

/// `ferrijs-serde`'s `to_string_lossy`: one U+FFFD per invalid sequence,
/// a 3-byte lone surrogate counting as one.
fn lossy(mut bytes: &[u8], mut error: std::str::Utf8Error) -> String {
  let mut out = String::with_capacity(bytes.len());
  loop {
    let (valid, after) = bytes.split_at(error.valid_up_to());
    // SAFETY: `valid_up_to` bytes are valid UTF-8 by definition.
    out.push_str(unsafe { std::str::from_utf8_unchecked(valid) });
    out.push(char::REPLACEMENT_CHARACTER);
    let lone_surrogate = matches!(after, [0xED, 0xA0..=0xBF, 0x80..=0xBF, ..]);
    let skip = if lone_surrogate {
      3
    } else {
      error.error_len().unwrap_or(after.len())
    };
    bytes = &after[skip.min(after.len())..];
    match std::str::from_utf8(bytes) {
      Ok(rest) => {
        out.push_str(rest);
        return out;
      },
      Err(next) => error = next,
    }
  }
}

#[cfg(test)]
mod tests {
  use rquickjs::{CatchResultExt, Context, Runtime};

  /// Each expression is evaluated twice into the same fresh context, once
  /// for each walker. `globalThis.log` collects what hooks observed, so
  /// the order of `toJSON` / getter / trap calls is compared as well.
  const CASES: &[&str] = &[
    "1",
    "-1",
    "0",
    "-0",
    "1.5",
    "2 ** 31",
    "-(2 ** 31) - 1",
    "4294967295",
    "4294967296",
    "2 ** 53 - 1",
    "2 ** 53",
    "-(2 ** 53) + 1",
    "-(2 ** 53)",
    "2 ** 60",
    "1e300",
    "5e-324",
    "1e21",
    "NaN",
    "Infinity",
    "-Infinity",
    "true",
    "false",
    "null",
    "undefined",
    "'plain'",
    "'\\u00e9\\u4e2d\\ud83d\\ude00'",
    "'\\ud800'",
    "'a\\ud800b\\udc00c'",
    "'a\\u0000b'",
    "[]",
    "[1, , 3]",
    "[1, 'two', null, undefined, () => 1, Symbol('s'), NaN, [3]]",
    "({})",
    "({ a: 1, b: 'two', c: [1, 2, 3], d: { e: null } })",
    "({ u: undefined, f() {}, s: Symbol('x'), n: NaN, i: -Infinity })",
    "({ [Symbol('k')]: 1, k: 2 })",
    "({ 2: 'two', 1: 'one', b: 1, a: 2 })",
    "({ '\\ud800': 1, 'é': 2 })",
    "({ toJSON() { return { replaced: true }; } })",
    "({ toJSON() { return undefined; } })",
    "({ toJSON(key) { log.push(['top', key]); return 1; } })",
    "({ a: { toJSON(key) { log.push(['a', key]); return 'A'; } }, b: [ { toJSON(k) { log.push(['b0', k]); return 'B'; } } ] })",
    "({ toJSON: 5, x: 1 })",
    "({ x: { toJSON() { throw new Error('boom'); } } })",
    "({ get a() { log.push('a'); return 1; }, get b() { log.push('b'); return 2; } })",
    "({ get a() { throw new RangeError('getter'); } })",
    "new Date(0)",
    "new Date(NaN)",
    "({ d: new Date(86400000) })",
    "new Number(5)",
    "new Number(1.5)",
    "new String('boxed')",
    "new Boolean(false)",
    "({ a: new Number(1.5), b: new String('x'), c: new Boolean(true) })",
    "Object.assign(new Number(3), { extra: 1 })",
    "Object.assign(new String('s'), { extra: 1 })",
    "(() => { const n = new Number(1); n.valueOf = () => 'nope'; return n; })()",
    "(() => { const n = new Number(1); n.valueOf = () => { throw new Error('vo'); }; return { n }; })()",
    "(() => { const b = new Boolean(true); b.valueOf = () => 1; return b; })()",
    "(() => { const s = new String('x'); s.toString = () => 42; return s; })()",
    "(() => { const s = new String('x'); s.toString = () => ({ obj: true }); return { s }; })()",
    "new Map([[1, 2]])",
    "new Set([1])",
    "/re/g",
    "new Uint8Array([1, 2, 3])",
    "new ArrayBuffer(2)",
    "new Error('boom')",
    "Object.create({ inherited: 1 }, { own: { value: 2, enumerable: true }, hidden: { value: 3 } })",
    "new (class P { constructor() { this.x = 1; } get y() { return 2; } })()",
    "Object.assign(() => 1, { a: 1 })",
    "Object.assign([1, 2], { extra: 'x' })",
    "new Proxy({ a: 1 }, {})",
    "new Proxy([1, 2], {})",
    "new Proxy(new Proxy([7], {}), {})",
    "new Proxy({ a: 1, b: 2 }, { ownKeys(t) { log.push('ownKeys'); return Reflect.ownKeys(t); }, get(t, k) { log.push(['get', String(k)]); return t[k]; } })",
    "new Proxy([1, 2, 3], { get(t, k) { log.push(['get', String(k)]); return t[k]; } })",
    "Object.assign(Object.create(null), { z: 1 })",
    "(() => { const o = { a: 1 }; o.self = o; return o; })()",
    "(() => { const a = [1]; a.push(a); return a; })()",
    "(() => { const shared = { s: 1 }; return [shared, shared, { shared }]; })()",
    "10n",
    "({ big: 10n })",
    "[10n]",
    "Object(10n)",
    "({ b: Object(10n) })",
    "() => 1",
    "Symbol('top')",
    "({ length: 2, 0: 'a', 1: 'b' })",
    "(() => { const p = new Proxy([], { get(t, k) { return k === 'length' ? '2' : 'v' + String(k); } }); return p; })()",
    "(() => { const p = new Proxy([], { get(t, k) { return k === 'length' ? -5 : 0; } }); return p; })()",
    "(() => { const p = new Proxy([], { get(t, k) { return k === 'length' ? { valueOf() { log.push('len'); return 1; } } : 'x'; } }); return p; })()",
    "(function () { return arguments; })(1, 2)",
    "Array.from({ length: 5 }, (_, i) => ({ i, s: String(i), f: i / 3 }))",
    "(() => { let seed = 7; const r = () => (seed = (seed * 48271) % 2147483647) / 2147483647;\n const gen = (d) => { const k = r(); if (d > 4 || k < 0.2) return [r() * 1e6 | 0, r(), 'str' + (r() * 100 | 0), r() < 0.5, null][r() * 5 | 0];\n if (k < 0.6) { const o = {}; for (let i = 0; i < (r() * 6 | 0); i++) o['k' + (r() * 20 | 0)] = gen(d + 1); return o; }\n return Array.from({ length: r() * 6 | 0 }, () => gen(d + 1)); };\n return Array.from({ length: 50 }, () => gen(0)); })()",
  ];

  fn outcome(ctx: &rquickjs::Ctx<'_>, expression: &str, fast: bool) -> serde_json::Value {
    ctx
      .globals()
      .set("log", rquickjs::Array::new(ctx.clone()).unwrap())
      .unwrap();
    let value: rquickjs::Value<'_> = ctx.eval(format!("({expression})")).catch(ctx).unwrap();
    let json = if fast {
      super::convert(ctx, &value)
    } else {
      crate::value::value_to_json_via_serde(value)
    };
    let pending = ctx
      .catch()
      .as_exception()
      .map(|e| {
        format!(
          "{}: {}",
          e.get::<_, String>("name").unwrap_or_default(),
          e.message().unwrap_or_default()
        )
      })
      // The reference's stray throw from looking `toJSON` up on
      // `undefined` or `null`, which the direct walk no longer makes.
      .filter(|message| !message.starts_with("TypeError: cannot read property 'toJSON' of "));
    let log: rquickjs::Value<'_> = ctx.globals().get("log").unwrap();
    let log = crate::value::value_to_json_via_serde(log);
    // Converting the log can itself leave a TypeError pending (both
    // walks look `toJSON` up on an `undefined` element); it belongs to
    // neither case.
    let _ = ctx.catch();
    serde_json::json!({ "json": json, "pending": pending, "log": log })
  }

  #[test]
  fn a_successful_conversion_leaves_nothing_pending() {
    let runtime = Runtime::new().unwrap();
    let context = Context::full(&runtime).unwrap();
    context.with(|ctx| {
      for expression in ["[undefined, null]", "({ a: [undefined], b: null })", "[1, , 3]"] {
        let value: rquickjs::Value<'_> = ctx.eval(format!("({expression})")).unwrap();
        assert!(super::convert(&ctx, &value).is_some(), "{expression}");
        assert!(!ctx.catch().is_exception(), "{expression} left an exception pending");
      }
    });
  }

  #[test]
  fn the_direct_walk_answers_what_the_serde_walk_does() {
    let runtime = Runtime::new().unwrap();
    let context = Context::full(&runtime).unwrap();
    context.with(|ctx| {
      for expression in CASES {
        let fast = outcome(&ctx, expression, true);
        let reference = outcome(&ctx, expression, false);
        assert_eq!(fast, reference, "{expression}");
      }
    });
  }
}
