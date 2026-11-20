//! What a realm's `Intl` keeps between calls: the defaults it resolved
//! at install, and the formatters the locale-sensitive built-ins
//! (`localeCompare`, `toLocaleString`, ...) made.
//!
//! Each of those built-ins is specified as constructing a fresh
//! `Intl` object per call. Built literally, `array.sort((a, b) =>
//! a.localeCompare(b))` would load collation data once per comparison,
//! so every formatter a built-in makes is kept here under the options it
//! was resolved from, and the next call with the same options reuses it.

use std::cell::RefCell;
use std::hash::Hash;
use std::rc::Rc;

use icu::locale::Locale;
use rquickjs::{Ctx, Exception, JsLifetime, Result};
use rustc_hash::FxHashMap;

use crate::collator::CollatorCore;
use crate::date_time_format::DateTimeFormatCore;
use crate::number_format::NumberFormatCore;

/// How many formatters of one kind a realm keeps. Past this the cache
/// starts over: a program that cycles through more distinct option sets
/// than this is not one a cache would save.
const CACHE_LIMIT: usize = 64;

pub(crate) struct Cache<K, V> {
  map: RefCell<FxHashMap<K, Rc<V>>>,
}

impl<K: Eq + Hash, V> Default for Cache<K, V> {
  fn default() -> Self {
    Self {
      map: RefCell::new(FxHashMap::default()),
    }
  }
}

impl<K: Eq + Hash, V> Cache<K, V> {
  pub(crate) fn get(&self, key: &K) -> Option<Rc<V>> {
    self.map.borrow().get(key).cloned()
  }

  pub(crate) fn insert(&self, key: K, value: Rc<V>) {
    let mut map = self.map.borrow_mut();
    if map.len() >= CACHE_LIMIT {
      map.clear();
    }
    map.insert(key, value);
  }
}

pub(crate) struct State {
  /// What `localeCompare` and `toLocaleString` resolve to when called
  /// with no locales and no options, which is most calls, kept apart so
  /// those calls skip building a cache key.
  pub(crate) default_collator: RefCell<Option<Rc<CollatorCore>>>,
  pub(crate) default_number_format: RefCell<Option<Rc<NumberFormatCore>>>,
  pub(crate) default_locale: Locale,
  pub(crate) default_time_zone: String,
  pub(crate) collators: Cache<String, CollatorCore>,
  pub(crate) number_formats: Cache<String, NumberFormatCore>,
  pub(crate) date_time_formats: Cache<String, DateTimeFormatCore>,
}

// SAFETY: `State` holds no JS value, so renaming its lifetime is a no-op.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for State {
  type Changed<'to> = State;
}

impl State {
  pub(crate) fn new(default_locale: Locale, default_time_zone: String) -> Self {
    Self {
      default_collator: RefCell::new(None),
      default_number_format: RefCell::new(None),
      default_locale,
      default_time_zone,
      collators: Cache::default(),
      number_formats: Cache::default(),
      date_time_formats: Cache::default(),
    }
  }
}

pub(crate) fn state<'a>(ctx: &'a Ctx<'_>) -> Result<rquickjs::runtime::UserDataGuard<'a, State>> {
  ctx
    .userdata::<State>()
    .ok_or_else(|| Exception::throw_internal(ctx, "Intl is not installed on this realm"))
}

/// The realm's own `Object` constructor, as the realm was built, not
/// whatever a script has since put at `globalThis.Object`.
pub(crate) fn object_constructor<'js>(ctx: &Ctx<'js>) -> Result<rquickjs::Function<'js>> {
  use ferrijs_std::utils::primordials::{BasePrimordials, Primordial as _};
  BasePrimordials::init(ctx)?;
  Ok(BasePrimordials::get(ctx)?.constructor_object.clone().into_inner())
}

/// `ToPrimitive(value, number)` for an object: `valueOf`, then
/// `toString`, as the realm's `Number` would read it, without converting
/// a BigInt or a string it yields.
pub(crate) fn to_primitive_number<'js>(ctx: &Ctx<'js>, value: &rquickjs::Value<'js>) -> Result<rquickjs::Value<'js>> {
  let Some(object) = value.as_object() else {
    return Ok(value.clone());
  };
  for method in ["valueOf", "toString"] {
    let function: rquickjs::Value<'js> = object.get(method)?;
    if let Some(function) = function.as_function() {
      let result: rquickjs::Value<'js> = function.call((rquickjs::function::This(value.clone()),))?;
      if !result.is_object() {
        return Ok(result);
      }
    }
  }
  Err(Exception::throw_type(ctx, "Cannot convert object to primitive value"))
}
