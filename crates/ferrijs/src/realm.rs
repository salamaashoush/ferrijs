//! What a realm looks like before any script runs: which globals exist,
//! and whether the language's own escape hatches are open.
//!
//! `QuickJS` picks its intrinsics at context creation, but the one that
//! matters most for a sandbox -- `eval` -- cannot be dropped there
//! without also losing the host's ability to evaluate source (every
//! `ctx.eval` and every module declaration goes through the same
//! internal). So the lockdown happens after the realm is built: the
//! constructors that compile source at runtime are replaced with ones
//! that throw, and the replacement covers every path to them, since
//! `Function.prototype.constructor` is reachable from any function and
//! the async and generator constructors are separate objects.

use rquickjs::{Ctx, Object, Value};

/// How the realm is shaped after the extensions install.
#[derive(Debug, Clone)]
pub struct RealmOptions {
  /// Whether `eval`, `new Function` and the async / generator function
  /// constructors compile source. Off, each throws an `EvalError`;
  /// modules and the host's own evaluation are unaffected.
  pub eval: bool,
  /// Freeze the standard intrinsics (`Object.prototype`,
  /// `Array.prototype`, ...) so a script cannot change what another
  /// script in the same realm sees. Off by default: it breaks code that
  /// patches a prototype, which some libraries do on load.
  pub freeze_intrinsics: bool,
  /// Globals to delete after everything installed, by name: a host that
  /// wants no `fetch`, or no `WeakRef`, names it here rather than
  /// re-implementing the install that added it.
  pub remove_globals: Vec<String>,
  /// Quantise every clock a script can read (`Date.now()`, `new Date()`,
  /// `performance.now()`, `process.hrtime()`) to this resolution. A
  /// high-resolution clock is the instrument of a timing side channel;
  /// coarsening it is what browsers and workerd do for code they do not
  /// trust. `None` leaves the clocks precise.
  pub clock_resolution: Option<std::time::Duration>,
}

impl Default for RealmOptions {
  fn default() -> Self {
    Self {
      eval: true,
      freeze_intrinsics: false,
      remove_globals: Vec::new(),
      clock_resolution: None,
    }
  }
}

/// Apply the lockdown. Runs last at realm creation, after every
/// extension, so nothing installed afterwards can undo it.
///
/// # Errors
///
/// Propagates the property writes.
pub fn lockdown(ctx: &Ctx<'_>, options: &RealmOptions) -> rquickjs::Result<()> {
  if let Some(resolution) = options.clock_resolution {
    let ms = resolution.as_secs_f64() * 1000.0;
    ctx.eval::<(), _>(TAME_CLOCKS.replace("__RESOLUTION_MS__", &format!("{ms}")))?;
  }
  if !options.eval {
    ctx.eval::<(), _>(NO_EVAL)?;
  }
  for name in &options.remove_globals {
    let globals = ctx.globals();
    if globals.contains_key(name.as_str())? {
      globals.remove(name.as_str())?;
    }
  }
  if options.freeze_intrinsics {
    ctx.eval::<(), _>(FREEZE_INTRINSICS)?;
  }
  Ok(())
}

/// Replace every runtime compiler with a thrower. `Function` itself is
/// replaced on the global and as `Function.prototype.constructor` (the
/// route from any existing function), and the three constructors that
/// are only reachable through a prototype get the same treatment.
const NO_EVAL: &str = r#"
(() => {
  const refuse = (what) => function () {
    throw new EvalError(what + " is not available: this realm was created without eval");
  };
  const replace = (proto, name) => {
    const thrower = refuse(name);
    Object.defineProperty(thrower, "name", { value: name });
    thrower.prototype = proto;
    Object.defineProperty(proto, "constructor", { value: thrower, writable: true, configurable: true });
    return thrower;
  };
  const F = replace(Function.prototype, "Function");
  Object.defineProperty(globalThis, "Function", { value: F, writable: true, configurable: true });
  replace(Object.getPrototypeOf(async function () {}), "AsyncFunction");
  replace(Object.getPrototypeOf(function* () {}), "GeneratorFunction");
  replace(Object.getPrototypeOf(async function* () {}), "AsyncGeneratorFunction");
  Object.defineProperty(globalThis, "eval", { value: refuse("eval"), writable: true, configurable: true });
})();
"#;

/// Replace every clock with one that answers in multiples of the
/// resolution. `Date` is replaced by a constructor that shares the real
/// prototype, so a `Date` the host creates natively (a file's `mtime`)
/// is still `instanceof Date`; `performance.now` and `process.hrtime`
/// are wrapped in place.
const TAME_CLOCKS: &str = r#"
(() => {
  const q = __RESOLUTION_MS__;
  const floorMs = (ms) => Math.floor(ms / q) * q;
  const RealDate = Date;
  const realNow = RealDate.now.bind(RealDate);
  function TamedDate(...args) {
    if (!new.target) return new RealDate(floorMs(realNow())).toString();
    return Reflect.construct(RealDate, args.length === 0 ? [floorMs(realNow())] : args, new.target);
  }
  TamedDate.prototype = RealDate.prototype;
  Object.defineProperty(RealDate.prototype, "constructor", { value: TamedDate, writable: true, configurable: true });
  Object.defineProperty(TamedDate, "name", { value: "Date" });
  Object.defineProperty(TamedDate, "length", { value: 7 });
  TamedDate.now = () => floorMs(realNow());
  TamedDate.parse = RealDate.parse;
  TamedDate.UTC = RealDate.UTC;
  Object.defineProperty(globalThis, "Date", { value: TamedDate, writable: true, configurable: true });
  if (typeof performance === "object" && typeof performance.now === "function") {
    const realPerfNow = performance.now.bind(performance);
    Object.defineProperty(performance, "now", { value: () => floorMs(realPerfNow()), writable: true, configurable: true });
  }
  if (typeof process === "object" && typeof process.hrtime === "function") {
    const qNs = BigInt(Math.round(q * 1e6));
    const realHr = process.hrtime;
    const realBig = realHr.bigint;
    const quantised = () => {
      const ns = realBig();
      return ns - (ns % qNs);
    };
    const hrtime = (prev) => {
      const ns = quantised();
      let s = Number(ns / 1000000000n), n = Number(ns % 1000000000n);
      if (Array.isArray(prev)) {
        s -= prev[0]; n -= prev[1];
        if (n < 0) { s -= 1; n += 1e9; }
      }
      return [s, n];
    };
    hrtime.bigint = quantised;
    Object.defineProperty(process, "hrtime", { value: hrtime, writable: true, configurable: true });
  }
})();
"#;

/// Deep-freeze the intrinsics a program can reach from `globalThis`
/// without naming a host global. The walk is by value, not by name, so
/// it covers the prototypes behind the constructors too.
const FREEZE_INTRINSICS: &str = r#"
(() => {
  const roots = [
    Object, Function, Array, Number, Boolean, String, Symbol, Date, Promise, RegExp,
    Error, EvalError, RangeError, ReferenceError, SyntaxError, TypeError, URIError,
    JSON, Math, Reflect, Map, Set, WeakMap, WeakSet, ArrayBuffer, DataView,
    Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array,
    Uint32Array, Float32Array, Float64Array, BigInt, BigInt64Array, BigUint64Array,
    Object.getPrototypeOf(async function () {}),
    Object.getPrototypeOf(function* () {}),
    Object.getPrototypeOf(async function* () {}),
    Object.getPrototypeOf([][Symbol.iterator]()),
  ];
  const seen = new Set();
  const freeze = (value) => {
    if ((typeof value !== "object" && typeof value !== "function") || value === null || seen.has(value)) return;
    seen.add(value);
    Object.freeze(value);
    for (const key of Reflect.ownKeys(value)) {
      const desc = Object.getOwnPropertyDescriptor(value, key);
      if (!desc) continue;
      if ("value" in desc) freeze(desc.value);
      if (desc.get) freeze(desc.get);
      if (desc.set) freeze(desc.set);
    }
    freeze(Object.getPrototypeOf(value));
  };
  for (const root of roots) freeze(root);
})();
"#;

/// Whether `globalThis` has a property called `name`.
pub fn has_global(ctx: &Ctx<'_>, name: &str) -> bool {
  ctx.globals().get::<_, Value<'_>>(name).is_ok_and(|v| !v.is_undefined())
}

/// `globalThis` as an object, for callers that want to inspect it.
#[must_use]
pub fn globals<'js>(ctx: &Ctx<'js>) -> Object<'js> {
  ctx.globals()
}
