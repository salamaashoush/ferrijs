//! A `serde_json::Value` built into the engine directly.
//!
//! It makes exactly what `value::json_to_js` made through rquickjs: ints
//! for exact `i32`s and floats otherwise, own enumerable, writable,
//! configurable data properties in map order, and array elements stored
//! with an ordinary indexed set. The difference is cost: each key is
//! interned once per conversion rather than hashed again for every object
//! that carries it, and no value re-counts its context on the way.

#![allow(unsafe_code)]

use std::ffi::c_char;

use rquickjs::{Ctx, Value, qjs};
use rustc_hash::FxHashMap;

/// The value for `json`, or the error the engine raised building it.
pub(crate) fn convert<'js>(ctx: &Ctx<'js>, json: &serde_json::Value) -> rquickjs::Result<Value<'js>> {
  let mut builder = Builder {
    ctx: ctx.as_raw().as_ptr(),
    atoms: FxHashMap::default(),
    objects: 0,
  };
  // SAFETY: the build runs on the thread holding `ctx`, and the value it
  // answers is a fresh reference handed to rquickjs to own.
  match unsafe { builder.value(json) } {
    Some(value) => Ok(unsafe { Value::from_raw(ctx.clone(), value) }),
    None => Err(rquickjs::Error::Exception),
  }
}

struct Builder<'a> {
  ctx: *mut qjs::JSContext,
  /// Each key interned once per conversion; freed with the builder.
  /// Filled from the second object on: a payload with one object has no
  /// key to repeat, and the map would cost it more than it saves.
  atoms: FxHashMap<&'a str, qjs::JSAtom>,
  objects: usize,
}

impl Drop for Builder<'_> {
  fn drop(&mut self) {
    for atom in self.atoms.values() {
      // SAFETY: each atom here was created by this builder.
      unsafe { qjs::JS_FreeAtom(self.ctx, *atom) }
    }
  }
}

fn exception(value: qjs::JSValue) -> bool {
  // SAFETY: a tag read.
  unsafe { qjs::JS_VALUE_GET_NORM_TAG(value) == qjs::JS_TAG_EXCEPTION }
}

impl<'a> Builder<'a> {
  /// A new reference to the value for `json`; `None` with an exception
  /// pending when the engine could not allocate.
  unsafe fn value(&mut self, json: &'a serde_json::Value) -> Option<qjs::JSValue> {
    let value = match json {
      serde_json::Value::Null => qjs::JS_MKVAL(qjs::JS_TAG_NULL, 0),
      serde_json::Value::Bool(b) => qjs::JS_MKVAL(qjs::JS_TAG_BOOL, i32::from(*b)),
      serde_json::Value::Number(n) => {
        let f = n.as_f64().unwrap_or(f64::NAN);
        match crate::value::f64_as_exact_i32(f) {
          Some(i) => qjs::JS_MKVAL(qjs::JS_TAG_INT, i),
          None => qjs::JS_NewFloat64(f),
        }
      },
      serde_json::Value::String(s) => unsafe {
        qjs::JS_NewStringLen(self.ctx, s.as_ptr().cast::<c_char>(), s.len() as _)
      },
      serde_json::Value::Array(items) => {
        let array = unsafe { qjs::JS_NewArray(self.ctx) };
        if exception(array) {
          return None;
        }
        for (index, item) in items.iter().enumerate() {
          let Some(element) = (unsafe { self.value(item) }) else {
            unsafe { qjs::JS_FreeValue(self.ctx, array) };
            return None;
          };
          #[allow(clippy::cast_possible_truncation)]
          if unsafe { qjs::JS_SetPropertyUint32(self.ctx, array, index as u32, element) } < 0 {
            unsafe { qjs::JS_FreeValue(self.ctx, array) };
            return None;
          }
        }
        array
      },
      serde_json::Value::Object(map) => {
        let object = unsafe { qjs::JS_NewObject(self.ctx) };
        if exception(object) {
          return None;
        }
        self.objects += 1;
        let cache = self.objects > 1;
        for (key, item) in map {
          let cached = if cache {
            self.atoms.get(key.as_str()).copied()
          } else {
            None
          };
          let atom = if let Some(atom) = cached {
            atom
          } else {
            let atom = unsafe { qjs::JS_NewAtomLen(self.ctx, key.as_ptr().cast::<c_char>(), key.len() as _) };
            if atom == qjs::JS_ATOM_NULL {
              unsafe { qjs::JS_FreeValue(self.ctx, object) };
              return None;
            }
            if cache {
              self.atoms.insert(key.as_str(), atom);
            }
            atom
          };
          let field = unsafe { self.value(item) };
          let defined = field.is_some_and(|field| {
            let flags = (qjs::JS_PROP_C_W_E | qjs::JS_PROP_THROW).cast_signed();
            unsafe { qjs::JS_DefinePropertyValue(self.ctx, object, atom, field, flags) >= 0 }
          });
          if !cache {
            unsafe { qjs::JS_FreeAtom(self.ctx, atom) };
          }
          if !defined {
            unsafe { qjs::JS_FreeValue(self.ctx, object) };
            return None;
          }
        }
        object
      },
    };
    (!exception(value)).then_some(value)
  }
}

#[cfg(test)]
mod tests {
  use rquickjs::{Context, Runtime};

  /// What a script can observe of a built value: its JSON, its own key
  /// order and every property's attributes, walked recursively.
  const OBSERVE: &str = r"(v) => {
    const seen = [];
    const walk = (x) => {
      if (x === null || typeof x !== 'object') { seen.push([typeof x, Object.is(x, -0) ? '-0' : String(x)]); return; }
      seen.push([Array.isArray(x) ? 'array' : 'object', Object.getPrototypeOf(x) === (Array.isArray(x) ? Array.prototype : Object.prototype)]);
      for (const k of Reflect.ownKeys(x)) {
        const d = Object.getOwnPropertyDescriptor(x, k);
        seen.push([String(k), d.writable, d.enumerable, d.configurable, 'value' in d]);
        if ('value' in d) walk(d.value);
      }
    };
    walk(v);
    return JSON.stringify(seen);
  }";

  #[test]
  fn the_direct_build_makes_what_rquickjs_made() {
    let docs = [
      serde_json::json!(null),
      serde_json::json!(true),
      serde_json::json!(0),
      serde_json::json!(-1),
      serde_json::json!(2_147_483_647),
      serde_json::json!(2_147_483_648_u64),
      serde_json::json!(-2_147_483_649_i64),
      serde_json::json!(1.5),
      serde_json::json!(-0.0),
      serde_json::json!(9_007_199_254_740_993_u64),
      serde_json::json!(1e300),
      serde_json::json!("plain"),
      serde_json::json!("é中😀\u{0}"),
      serde_json::json!([]),
      serde_json::json!({}),
      serde_json::json!([1, [2, [3, { "a": [] }]], null, "x"]),
      serde_json::json!({ "b": 1, "a": 2, "2": "two", "1": "one", "": "empty" }),
      serde_json::json!({ "__proto__": { "polluted": true }, "constructor": 1, "toString": "s" }),
      serde_json::json!({ "rows": [{ "id": 1, "name": "x" }, { "id": 2, "name": "y" }, { "name": "z", "id": 3 }] }),
      serde_json::json!({ "length": 3, "0": "a" }),
    ];
    let runtime = Runtime::new().unwrap();
    let context = Context::full(&runtime).unwrap();
    context.with(|ctx| {
      let observe: rquickjs::Function<'_> = ctx.eval(OBSERVE).unwrap();
      for doc in &docs {
        let fast = super::convert(&ctx, doc).unwrap();
        let reference = crate::value::json_to_js_via_rquickjs(&ctx, doc).unwrap();
        let fast: String = observe.call((fast,)).unwrap();
        let reference: String = observe.call((reference,)).unwrap();
        assert_eq!(fast, reference, "{doc}");
      }
    });
  }
}
