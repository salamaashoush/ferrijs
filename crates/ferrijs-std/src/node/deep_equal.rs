//! Structural equality, in Node's two flavours.
//!
//! One implementation, shared by `util.isDeepStrictEqual` and by
//! `assert.deepEqual` / `assert.deepStrictEqual`.

use rquickjs::{Atom, Function, Object, Type, Value, atom::PredefinedAtom, function::This};

/// How leaf values compare.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
  /// `assert.deepEqual`: `==` on primitives, prototypes ignored.
  Loose,
  /// `assert.deepStrictEqual`: `Object.is` on primitives, prototypes must
  /// match.
  Strict,
}

/// Recursion ceiling. A cyclic graph would otherwise never terminate;
/// Node tracks visited pairs instead, which needs identity keys QuickJS
/// does not hand out cheaply.
const MAX_DEPTH: usize = 64;

/// Compare two values the way `assert.deepEqual` / `deepStrictEqual` do.
///
/// # Errors
///
/// Propagates JS-side property reads.
pub fn deep_equal<'js>(a: &Value<'js>, b: &Value<'js>, mode: Mode) -> rquickjs::Result<bool> {
  equal_at(a, b, mode, 0)
}

/// `===`: `Object.is` on primitives (so `NaN` matches itself and `0` does
/// not match `-0`), identity on everything else.
#[must_use]
pub fn strict_equal<'js>(a: &Value<'js>, b: &Value<'js>) -> bool {
  if a.type_of() != b.type_of() {
    return false;
  }
  match a.type_of() {
    Type::Int | Type::Float => number_eq(a, b, Mode::Strict),
    Type::String => a
      .as_string()
      .and_then(|s| s.to_string().ok())
      .eq(&b.as_string().and_then(|s| s.to_string().ok())),
    Type::Bool => a.as_bool() == b.as_bool(),
    Type::Undefined | Type::Null | Type::Uninitialized => true,
    _ => a == b,
  }
}

/// `==`: strict equality, plus the primitive coercions.
#[must_use]
pub fn loose_equal<'js>(a: &Value<'js>, b: &Value<'js>) -> bool {
  if a.type_of() == b.type_of() {
    // `==` and `===` differ only across types, except that `NaN` is equal
    // to nothing under either.
    return match a.type_of() {
      Type::Int | Type::Float => number_eq(a, b, Mode::Loose),
      _ => strict_equal(a, b),
    };
  }
  loose_primitive_eq(a, b)
}

fn equal_at<'js>(a: &Value<'js>, b: &Value<'js>, mode: Mode, depth: usize) -> rquickjs::Result<bool> {
  if depth > MAX_DEPTH {
    return Ok(false);
  }
  if a.type_of() != b.type_of() {
    // `1 == '1'` under the loose flavour; nothing else crosses types.
    return Ok(mode == Mode::Loose && loose_primitive_eq(a, b));
  }

  match a.type_of() {
    Type::Undefined | Type::Null | Type::Uninitialized => Ok(true),
    Type::Bool => Ok(a.as_bool() == b.as_bool()),
    Type::Int | Type::Float => Ok(number_eq(a, b, mode)),
    Type::String => Ok(js_string(a)? == js_string(b)?),
    Type::Symbol => Ok(a.as_symbol() == b.as_symbol()),
    Type::Array => array_eq(a, b, mode, depth),
    Type::Object | Type::Exception => object_eq(a, b, mode, depth),
    // Functions, constructors and everything else compare by identity.
    _ => Ok(a == b),
  }
}

fn js_string(value: &Value<'_>) -> rquickjs::Result<String> {
  value.as_string().map_or_else(|| Ok(String::new()), rquickjs::String::to_string)
}

/// `Object.is` semantics under Strict (so `NaN` equals itself and `0` does
/// not equal `-0`), `==` semantics under Loose.
fn number_eq(a: &Value<'_>, b: &Value<'_>, mode: Mode) -> bool {
  let (Some(x), Some(y)) = (a.as_number(), b.as_number()) else {
    return false;
  };
  match mode {
    Mode::Strict => {
      if x.is_nan() && y.is_nan() {
        true
      } else {
        x == y && x.is_sign_negative() == y.is_sign_negative()
      }
    },
    Mode::Loose => x == y,
  }
}

/// `==` across types: the numeric coercion JS performs for
/// number/string/boolean pairs, plus `null == undefined`. Objects are NOT
/// coerced through `valueOf` / `toString` — Node's `assert.equal` on an
/// object against a primitive is a comparison nobody writes on purpose.
fn loose_primitive_eq(a: &Value<'_>, b: &Value<'_>) -> bool {
  let nullish = |v: &Value<'_>| v.is_null() || v.is_undefined();
  if nullish(a) || nullish(b) {
    return nullish(a) && nullish(b);
  }
  match (coerce_number(a), coerce_number(b)) {
    (Some(x), Some(y)) => x == y,
    _ => false,
  }
}

/// `ToNumber` for the primitive types `==` coerces.
fn coerce_number(value: &Value<'_>) -> Option<f64> {
  match value.type_of() {
    Type::Int | Type::Float => value.as_number(),
    Type::Bool => value.as_bool().map(|b| if b { 1.0 } else { 0.0 }),
    Type::String => {
      let text = value.as_string()?.to_string().ok()?;
      let trimmed = text.trim();
      if trimmed.is_empty() {
        return Some(0.0);
      }
      trimmed.parse::<f64>().ok()
    },
    _ => None,
  }
}

fn array_eq<'js>(a: &Value<'js>, b: &Value<'js>, mode: Mode, depth: usize) -> rquickjs::Result<bool> {
  let (Some(x), Some(y)) = (a.as_array(), b.as_array()) else {
    return Ok(false);
  };
  if x.len() != y.len() {
    return Ok(false);
  }
  for i in 0..x.len() {
    let (lhs, rhs): (Value<'_>, Value<'_>) = (x.get(i)?, y.get(i)?);
    if !equal_at(&lhs, &rhs, mode, depth + 1)? {
      return Ok(false);
    }
  }
  Ok(true)
}

fn object_eq<'js>(a: &Value<'js>, b: &Value<'js>, mode: Mode, depth: usize) -> rquickjs::Result<bool> {
  let (Some(x), Some(y)) = (a.as_object(), b.as_object()) else {
    return Ok(false);
  };

  // Each side's constructor name, once. It used to be recomputed six
  // times per comparison -- here, and again inside the `Date` and
  // `RegExp` probes for both operands -- and each call interned two
  // atoms and allocated a String.
  let (xc, yc) = (constructor_name(x)?, constructor_name(y)?);
  if mode == Mode::Strict && xc != yc {
    return Ok(false);
  }

  // Dates and RegExps carry their state outside their own properties.
  if xc.as_deref() == Some("Date") && yc.as_deref() == Some("Date") {
    let (lhs, rhs) = (value_of_number(x)?, value_of_number(y)?);
    return Ok(lhs == rhs || (lhs.is_nan() && rhs.is_nan()));
  }
  if xc.as_deref() == Some("RegExp") && yc.as_deref() == Some("RegExp") {
    return Ok(regexp_source(x)? == regexp_source(y)?);
  }

  // Keys as atoms, not as `String`s. A property name that arrives as a
  // Rust string has to be interned again for every lookup it is used
  // in -- and this loop used it in three -- on top of the C-string
  // round trip that built it.
  let keys: Vec<Atom<'js>> = x.keys::<Atom<'js>>().collect::<rquickjs::Result<Vec<_>>>()?;
  let other: Vec<Atom<'js>> = y.keys::<Atom<'js>>().collect::<rquickjs::Result<Vec<_>>>()?;
  if keys.len() != other.len() {
    return Ok(false);
  }
  for key in keys {
    if !y.contains_key(key.clone())? {
      return Ok(false);
    }
    let (lhs, rhs): (Value<'js>, Value<'js>) = (x.get(key.clone())?, y.get(key)?);
    if !equal_at(&lhs, &rhs, mode, depth + 1)? {
      return Ok(false);
    }
  }
  Ok(true)
}

fn constructor_name(object: &Object<'_>) -> rquickjs::Result<Option<String>> {
  let ctor: Option<Object<'_>> = object.get(PredefinedAtom::Constructor).ok();
  match ctor {
    Some(c) => Ok(c.get::<_, String>(PredefinedAtom::Name).ok()),
    None => Ok(None),
  }
}

/// `valueOf()` for a `Date`, whose identity is a number rather than its
/// own properties. The caller has already established the constructor.
fn value_of_number(object: &Object<'_>) -> rquickjs::Result<f64> {
  let value_of: Function<'_> = object.get(PredefinedAtom::ValueOf)?;
  value_of.call((This(object.clone()),))
}

/// A `RegExp`'s pattern and flags, which is its whole identity. The
/// caller has already established the constructor.
fn regexp_source(object: &Object<'_>) -> rquickjs::Result<String> {
  let source: String = object.get(PredefinedAtom::Source)?;
  let flags: String = object.get(PredefinedAtom::Flags).unwrap_or_default();
  Ok(format!("/{source}/{flags}"))
}
