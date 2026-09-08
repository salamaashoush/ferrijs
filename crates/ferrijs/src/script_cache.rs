//! Compiled scripts, kept for the realm's life.
//!
//! [`crate::Runtime::eval_script`] wraps the source in an async arrow and
//! hands it to `QuickJS`, which parses it every time. For a trivial
//! script that parse is about two thirds of the whole call, and for a
//! real one it scales with the source: a host that runs the same script
//! repeatedly (a poll, a page `evaluate`, a test body) pays for the same
//! parse over and over.
//!
//! So the compiled arrow is kept and called again. What is cached is the
//! function object, not its result, so each call still runs a fresh
//! invocation with fresh bindings and sees the realm's current
//! `globalThis` -- the observable behaviour is exactly what recompiling
//! gave, minus the parse.
//!
//! # Why this lives in the realm's userdata
//!
//! A [`Persistent`] is a GC root the collector cannot see, and rquickjs
//! aborts the process if one outlives its runtime. Userdata is the one
//! place with the right teardown order: `Opaque::clear` drops it
//! *before* `JS_FreeRuntime`, so the root is always released in time.
//! That is also why there is no public `CompiledScript` type -- handing
//! a host something it must remember to drop before the realm would be
//! an abort waiting to happen.

use std::cell::RefCell;
use std::hash::{Hash, Hasher};

use rquickjs::{Ctx, Function, Persistent};
use rustc_hash::FxHashMap;

/// How many compiled scripts a realm keeps by default.
///
/// A host running one script in a loop needs one slot; the rest are for
/// a handful of distinct bodies (a poll, a predicate, a serializer).
/// Past the limit the table is emptied rather than evicted one at a
/// time: a workload that rotates through more scripts than this has no
/// working set to protect, and clearing keeps the bound exact and the
/// code honest.
pub const DEFAULT_SCRIPT_CACHE: usize = 32;

struct Entry {
  /// The source this was compiled from. A 64-bit hash collision would
  /// otherwise run one script in place of another, which is not a
  /// trade-off worth making for a pointer's worth of memory.
  source: Box<str>,
  function: Persistent<Function<'static>>,
}

/// The realm's compiled-script table.
pub struct ScriptCache {
  limit: usize,
  entries: FxHashMap<u64, Entry>,
}

/// The table as realm userdata.
pub struct ScriptCacheUd(RefCell<ScriptCache>);

// SAFETY: holds `Persistent` values, which `Persistent::save` has
// already detached from any context lifetime, plus plain data. Nothing
// here borrows from `'js`, so restating the lifetime is sound.
#[allow(unsafe_code)]
unsafe impl rquickjs::JsLifetime<'_> for ScriptCacheUd {
  type Changed<'to> = ScriptCacheUd;
}

fn hash_of(source: &str) -> u64 {
  let mut h = rustc_hash::FxHasher::default();
  source.hash(&mut h);
  h.finish()
}

/// Install a compiled-script table on `ctx`. `limit` of zero installs
/// nothing, which is how a host turns the cache off.
pub fn install(ctx: &Ctx<'_>, limit: usize) {
  if limit == 0 {
    return;
  }
  let _ = ctx.store_userdata(ScriptCacheUd(RefCell::new(ScriptCache {
    limit,
    entries: FxHashMap::default(),
  })));
}

/// The compiled arrow for `source`, if this realm has one.
pub fn get<'js>(ctx: &Ctx<'js>, source: &str) -> Option<Function<'js>> {
  let ud = ctx.userdata::<ScriptCacheUd>()?;
  let cache = ud.0.borrow();
  let entry = cache.entries.get(&hash_of(source))?;
  if &*entry.source != source {
    return None;
  }
  entry.function.clone().restore(ctx).ok()
}

/// Keep `function` as the compiled form of `source`.
pub fn put<'js>(ctx: &Ctx<'js>, source: &str, function: &Function<'js>) {
  let Some(ud) = ctx.userdata::<ScriptCacheUd>() else {
    return;
  };
  let Ok(mut cache) = ud.0.try_borrow_mut() else {
    return;
  };
  if cache.entries.len() >= cache.limit {
    cache.entries.clear();
  }
  cache.entries.insert(
    hash_of(source),
    Entry {
      source: source.into(),
      function: Persistent::save(ctx, function.clone()),
    },
  );
}
