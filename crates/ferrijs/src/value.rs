//! Conversions between Rust values and `rquickjs` values.

use rquickjs::object::Property;
use rquickjs::{Ctx, Object, Value};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Throw a real JS `Error` with `name` set explicitly, so a script's
/// `e.name === 'TimeoutError'` holds. `Error::new_from_js_message`
/// cannot do this: it surfaces in scripts as a `TypeError` with a
/// mangled "Error converting from js ..." message and a fixed name.
pub use ferrijs_std::node::throw_named;

/// [`throw_named`] with the `stack` the thrower decided on, rather than
/// the one the engine captured at the `Error` construction site: for a
/// host that re-attributes a failure to the frame that asked for the
/// work.
pub fn throw_named_with_stack(ctx: &Ctx<'_>, name: &str, message: String, stack: Option<String>) -> rquickjs::Error {
  let Some(stack) = stack else {
    return throw_named(ctx, name, message);
  };
  let built: rquickjs::Result<Value<'_>> = (|| {
    let ctor: rquickjs::function::Constructor<'_> = ctx.globals().get("Error")?;
    let err: Object<'_> = ctor.construct((message.as_str(),))?;
    err.set("name", name)?;
    err.set("stack", stack)?;
    Ok(err.into_value())
  })();
  match built {
    Ok(v) => ctx.throw(v),
    Err(_) => throw_named(ctx, name, message),
  }
}

/// Convert a JS millisecond value (`f64`) into a `u64`, clamping
/// negatives to `0`. Single home for the otherwise-repeated f64->u64
/// timeout cast so call sites stay lint-clean.
#[must_use]
pub fn ms_f64_to_u64(ms: f64) -> u64 {
  if ms <= 0.0 {
    return 0;
  }
  // `ms` is now strictly positive and finite-or-inf; `f64::min` against
  // `u64::MAX` keeps the cast in range, and the fractional part is
  // truncated (sub-millisecond precision is irrelevant for timeouts).
  #[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
  )]
  {
    ms.min(u64::MAX as f64) as u64
  }
}

/// Parse a trailing timeout argument: a bare millisecond number or a
/// `{ timeout }` options bag. Returns `None` when omitted so callers
/// apply their own default.
pub fn parse_timeout_number_or_bag<'js>(
  ctx: &Ctx<'js>,
  options: rquickjs::function::Opt<rquickjs::Value<'js>>,
) -> rquickjs::Result<Option<u64>> {
  match options.0 {
    Some(v) if v.is_number() => Ok(v.as_number().map(ms_f64_to_u64)),
    Some(v) if v.is_object() => {
      #[derive(serde::Deserialize, Default)]
      #[serde(rename_all = "camelCase", default)]
      struct JsTimeoutBag {
        timeout: Option<f64>,
      }
      let parsed: JsTimeoutBag = serde_from_js(ctx, v)?;
      Ok(parsed.timeout.map(ms_f64_to_u64))
    },
    _ => Ok(None),
  }
}

/// Convert any `serde::Serialize` value into a JS value via
/// `ferrijs-serde` — direct `T` -> `rquickjs::Value`, no JSON string
/// and no `serde_json::Value` middle allocation. Used for binding
/// returns (cookies, storage state, parsed JSON bodies).
pub fn serde_to_js<'js, T: Serialize>(ctx: &Ctx<'js>, value: &T) -> rquickjs::Result<Value<'js>> {
  ferrijs_serde::to_value(ctx.clone(), value)
    .map_err(|e| rquickjs::Error::new_from_js_message("serde", "serialize", e.to_string()))
}

/// Build a JS `Array<{ name, value }>` straight from name/value pairs
/// via `ferrijs-serde` — no `serde_json::json!` / `serde_json::Value`
/// middle allocation. Used by `request`/`response`/`apiResponse`
/// `headersArray()`.
pub fn name_value_array_to_js<'js, S: AsRef<str>>(ctx: &Ctx<'js>, pairs: &[(S, S)]) -> rquickjs::Result<Value<'js>> {
  #[derive(Serialize)]
  struct NameValue<'a> {
    name: &'a str,
    value: &'a str,
  }
  let view: Vec<NameValue<'_>> = pairs
    .iter()
    .map(|(n, v)| NameValue {
      name: n.as_ref(),
      value: v.as_ref(),
    })
    .collect();
  serde_to_js(ctx, &view)
}

/// Inverse of [`serde_to_js`] — deserialize a JS value into a Rust type
/// via `ferrijs-serde` (direct `Value` -> `T`). Integral-float ->
/// integer coercion, `undefined`/function-property drop, Proxy and
/// cycle handling all hold (covered by the ferrijs-serde test suite),
/// so the option-bag call sites keep their prior semantics without our
/// own hand-rolled walker.
pub fn serde_from_js<'js, T: DeserializeOwned>(_ctx: &Ctx<'js>, value: Value<'js>) -> rquickjs::Result<T> {
  ferrijs_serde::from_value(value)
    .map_err(|e| rquickjs::Error::new_from_js_message("serde", "deserialize", e.to_string()))
}

/// Deserialize an optional JS option bag straight into an options
/// struct — `None` / `undefined` / `null` → `Ok(None)`. The struct
/// carries the wire shape itself (serde camelCase + defaults), so there
/// is no binding-side mirror to drift.
pub fn parse_opt_bag<'js, T: DeserializeOwned>(
  ctx: &Ctx<'js>,
  value: rquickjs::function::Opt<Value<'js>>,
) -> rquickjs::Result<Option<T>> {
  match value.0 {
    Some(v) if !v.is_undefined() && !v.is_null() => Ok(Some(serde_from_js(ctx, v)?)),
    _ => Ok(None),
  }
}

/// Define `key` as an own data property (writable/enumerable/
/// configurable, like a normal JS literal field) on `obj`.
///
/// Untrusted input — page-controlled `evaluate` results, script args —
/// can contain a `__proto__` (or other accessor) key. `Object::set`
/// routes through `[[Set]]`, so such a key would invoke the
/// `__proto__` setter (retargeting the object's prototype) or any
/// inherited setter. `Object::prop` lowers to `JS_DefineProperty`,
/// which always creates an own data property and never triggers a
/// setter — the value lands exactly where a JSON consumer expects.
fn define_own<'js, V: rquickjs::IntoJs<'js>>(obj: &Object<'js>, key: &str, value: V) -> rquickjs::Result<()> {
  obj.prop(key, Property::from(value).writable().enumerable().configurable())
}

/// An absent value as a TS declaration spells it: `T | null`.
///
/// rquickjs lowers a bare `Option::None` to `undefined`, which is a
/// different value in JS — `=== null` and `toBeNull()` both fail on it,
/// while a signature that can answer "nothing" usually says `null`. A
/// binding whose declaration is `T | null` returns `Null<T>` instead of
/// `Option<T>`.
pub struct Null<T>(pub Option<T>);

impl<'js, T: rquickjs::IntoJs<'js>> rquickjs::IntoJs<'js> for Null<T> {
  fn into_js(self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    match self.0 {
      Some(v) => v.into_js(ctx),
      None => Ok(Value::new_null(ctx.clone())),
    }
  }
}

/// Build an `rquickjs::Value` from a `serde_json::Value`.
///
/// Walked explicitly rather than through [`serde_to_js`]: a host that
/// enables `serde_json/arbitrary_precision` (rolldown does, workspace-
/// wide) makes `Number`'s `Serialize` emit a private one-key map, which
/// would land in JS as `{"$serde_json::private::Number": "..."}`. The
/// `as_*` accessors are immune. Object keys are defined as own data
/// properties, so a `__proto__` key in untrusted input cannot retarget
/// the prototype.
pub fn json_to_js<'js>(ctx: &Ctx<'js>, v: &serde_json::Value) -> rquickjs::Result<Value<'js>> {
  match v {
    serde_json::Value::Null => Ok(Value::new_null(ctx.clone())),
    serde_json::Value::Bool(b) => Ok(Value::new_bool(ctx.clone(), *b)),
    serde_json::Value::Number(n) => {
      let f = n.as_f64().unwrap_or(f64::NAN);
      if let Some(i) = f64_as_exact_i32(f) {
        Ok(Value::new_int(ctx.clone(), i))
      } else {
        Ok(Value::new_number(ctx.clone(), f))
      }
    },
    serde_json::Value::String(s) => Ok(rquickjs::String::from_str(ctx.clone(), s)?.into_value()),
    serde_json::Value::Array(items) => {
      let arr = rquickjs::Array::new(ctx.clone())?;
      for (i, item) in items.iter().enumerate() {
        arr.set(i, json_to_js(ctx, item)?)?;
      }
      Ok(arr.into_value())
    },
    serde_json::Value::Object(map) => {
      let obj = Object::new(ctx.clone())?;
      for (k, val) in map {
        define_own(&obj, k.as_str(), json_to_js(ctx, val)?)?;
      }
      Ok(obj.into_value())
    },
  }
}

fn f64_as_exact_i32(n: f64) -> Option<i32> {
  if n.is_finite() && n.fract() == 0.0 && n >= f64::from(i32::MIN) && n <= f64::from(i32::MAX) {
    // SAFETY: bounds-checked above. Direct cast preserves value for integers in i32 range.
    let trunc = n.trunc();
    i32::try_from(trunc as i64).ok()
  } else {
    None
  }
}

/// Convert a script's value to `serde_json::Value`.
///
/// `ferrijs-serde` drives the deserializer: it invokes `toJSON()` /
/// `valueOf()` (a returned `Date` still serialises as its ISO string),
/// coerces whole f64 in the safe-integer range to `i64`, drops
/// `undefined` / function / symbol, and renders non-finite as null.
/// The private `JsonValue` is what receives it, and says there why
/// `serde_json::Value`'s own `Deserialize` cannot.
#[must_use]
pub fn value_to_json<'js>(_ctx: &Ctx<'js>, value: Value<'js>) -> Option<serde_json::Value> {
  ferrijs_serde::from_value::<JsonValue>(value).ok().map(|v| v.0)
}

/// A `serde_json::Value` built through explicit constructors.
///
/// `serde_json::Value`'s own `Deserialize` cannot be used: under
/// `serde_json/arbitrary_precision` (which a host's bundler may enable
/// workspace-wide -- rolldown does) it demands a private number
/// representation that a non-`serde_json` deserializer cannot provide,
/// and every numeric or array result would collapse to `null`. So the
/// visitor below builds the same value out of `Number::from` and
/// `Map`, which are immune.
///
/// It builds the final value directly rather than an intermediate
/// mirror: filling a `Vec<(String, _)>` per object and a `Vec<_>` per
/// array only to walk them again cost an allocation and a move per
/// container for no gain.
struct JsonValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for JsonValue {
  fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
      type Value = JsonValue;
      fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
      }
      fn visit_unit<E>(self) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::Null))
      }
      fn visit_none<E>(self) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::Null))
      }
      fn visit_bool<E>(self, v: bool) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::Bool(v)))
      }
      fn visit_i64<E>(self, v: i64) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::Number(v.into())))
      }
      fn visit_u64<E>(self, v: u64) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::Number(v.into())))
      }
      fn visit_f64<E>(self, v: f64) -> Result<JsonValue, E> {
        Ok(JsonValue(
          serde_json::Number::from_f64(v).map_or(serde_json::Value::Null, serde_json::Value::Number),
        ))
      }
      fn visit_str<E>(self, v: &str) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::String(v.to_owned())))
      }
      fn visit_string<E>(self, v: String) -> Result<JsonValue, E> {
        Ok(JsonValue(serde_json::Value::String(v)))
      }
      fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<JsonValue, A::Error> {
        let mut out = Vec::with_capacity(a.size_hint().unwrap_or(0));
        while let Some(JsonValue(e)) = a.next_element()? {
          out.push(e);
        }
        Ok(JsonValue(serde_json::Value::Array(out)))
      }
      fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<JsonValue, A::Error> {
        // Collected then built in bulk, not inserted one at a time:
        // `serde_json::Map` is a `BTreeMap`, and building one from an
        // iterator sorts once and fills the nodes directly, where N
        // inserts each pay a tree descent.
        let mut pairs: Vec<(String, serde_json::Value)> = Vec::with_capacity(m.size_hint().unwrap_or(0));
        while let Some((k, JsonValue(v))) = m.next_entry::<String, JsonValue>()? {
          pairs.push((k, v));
        }
        Ok(JsonValue(serde_json::Value::Object(pairs.into_iter().collect())))
      }
    }
    d.deserialize_any(V)
  }
}
