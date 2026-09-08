//! `setTimeout` / `setInterval` / `clearTimeout` / `clearInterval` /
//! `setImmediate` / `queueMicrotask` — native, `ctx.spawn`-backed (the
//! timer future lives on the host's VM executor, so callbacks fire
//! between executes and while a script is parked on a host await;
//! dropping the runtime aborts every armed timer).
//!
//! The timer handle is a [`Timeout`] class instance (not a numeric id):
//! it survives REPL-style across evaluations via `globalThis` and
//! `clearTimeout(handle)` cancels through its `Notify`. Holding the JS
//! callback inside the spawned future is the sanctioned
//! executor-owned-future shape (same as `AbortSignal.timeout`) — the
//! future is dropped with the runtime, never stored in a traced JS field.
//!
//! The delay follows the HTML spec rather than Node. A `setTimeout(fn,
//! 0)` runs on the next turn of the event loop, after the microtask
//! checkpoint, instead of waiting out Node's unconditional one
//! millisecond -- for a script that polls with `await sleep(0)` that is
//! the difference between microseconds and milliseconds per turn. What
//! keeps that from starving the loop is the spec's own guard, the timer
//! NESTING LEVEL: a timeout armed from inside a timer callback is one
//! level deeper than the callback's own, and past level five a delay
//! under 4ms is raised to 4ms. `setInterval` deepens a level per
//! repeat, so a zero-delay interval free-runs a few times and then
//! settles at 4ms, which is what a browser does.
//!
//! A host with ambient per-callback state (a capability grant, a request
//! scope) supplies it as a [`CallbackPolicy`]: it is captured when the
//! timer is armed and re-entered when the callback fires, so a callback
//! registered under a restriction keeps it instead of falling back to
//! whatever the resting state happens to be. Hosts without such state
//! install [`NoPolicy`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rquickjs::function::{Func, Rest};
use rquickjs::{Class, Ctx, Function, JsLifetime, Value, class::Trace};
use tokio::sync::Notify;

/// Past this nesting depth the HTML spec raises a sub-4ms delay to 4ms.
/// It is what stops `setTimeout(f, 0)` recursion from spinning the loop
/// now that the first level really does fire on the next turn.
const MAX_FREE_NESTING: u32 = 5;

/// The HTML timer nesting level currently in force: zero outside any
/// timer callback, and the firing timer's own level inside one.
///
/// Kept as realm userdata rather than captured by the arming closures,
/// because `setTimeout` has to be a named generic function: an inline
/// closure gives `Ctx`, the callback and the returned handle three
/// separate `'js` lifetimes, and the handle is invariant over its own.
#[derive(Clone)]
struct Nesting(Arc<AtomicU32>);

// SAFETY: owns only an `Arc<AtomicU32>`; no borrowed JS values, so
// restating the unused `'js` lifetime is sound.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for Nesting {
  type Changed<'to> = Nesting;
}

/// The realm's nesting counter, or a detached one for a realm whose
/// host installed timers without it (the level then never deepens,
/// which is the pre-existing behaviour rather than a new hazard).
fn nesting_of(ctx: &Ctx<'_>) -> Arc<AtomicU32> {
  ctx
    .userdata::<Nesting>()
    .map_or_else(|| Arc::new(AtomicU32::new(0)), |n| Arc::clone(&n.0))
}

/// Ambient host state that a scheduled callback must run under.
pub trait CallbackPolicy: Clone + 'static {
  /// The state in force right now, if any.
  fn capture(ctx: &Ctx<'_>) -> Option<Self>
  where
    Self: Sized;

  /// Run `f` with `policy` in force, restoring the caller's state after.
  fn enter<R>(ctx: &Ctx<'_>, policy: Option<&Self>, f: impl FnOnce() -> R) -> R
  where
    Self: Sized;
}

/// For hosts with no ambient callback state: callbacks run as they are.
#[derive(Clone, Copy)]
pub struct NoPolicy;

impl CallbackPolicy for NoPolicy {
  fn capture(_ctx: &Ctx<'_>) -> Option<Self> {
    None
  }

  fn enter<R>(_ctx: &Ctx<'_>, _policy: Option<&Self>, f: impl FnOnce() -> R) -> R {
    f()
  }
}

/// Opaque timer handle returned by `setTimeout` / `setInterval`.
#[derive(Trace, JsLifetime)]
#[rquickjs::class]
pub struct Timeout {
  #[qjs(skip_trace)]
  abort: Arc<Notify>,
}

/// `clearTimeout(handle?)` / `clearInterval(handle?)`. Node ignores
/// `undefined`, `null`, numbers, foreign objects — anything that is not
/// a live timer handle — so the argument is taken as a raw `Value` and
/// only acted on when it is actually a [`Timeout`].
fn clear_timeout(value: Rest<Value<'_>>) {
  if let Some(v) = value.0.first() {
    if let Ok(timeout) = Class::<Timeout>::from_value(v) {
      timeout.borrow().abort.notify_one();
    }
  }
}

/// The delay a script asked for, in whole milliseconds. A negative,
/// NaN or out-of-range value is zero, which the spec treats as "as soon
/// as the loop gets to it".
fn requested_ms(msec: Option<f64>) -> u64 {
  match msec {
    Some(ms) if ms.is_finite() && ms >= 1.0 && ms < f64::from(i32::MAX) => ms as u64,
    _ => 0,
  }
}

/// The spec's clamp: past [`MAX_FREE_NESTING`], anything under 4ms
/// becomes 4ms.
fn clamped(requested: u64, level: u32) -> Duration {
  if level > MAX_FREE_NESTING && requested < 4 {
    Duration::from_millis(4)
  } else {
    Duration::from_millis(requested)
  }
}

/// Wait out `delay`. A zero delay is not a timer at all: yielding hands
/// the loop back so the microtask checkpoint runs first (a `setTimeout`
/// is a task, and a task never precedes a promise continuation already
/// queued), and the callback fires on the next pass. Going through
/// tokio's wheel instead would cost the millisecond this whole change
/// exists to remove.
async fn wait(delay: Duration) {
  if delay.is_zero() {
    tokio::task::yield_now().await;
  } else {
    tokio::time::sleep(delay).await;
  }
}

fn set_timeout_interval<'js, P: CallbackPolicy>(
  ctx: Ctx<'js>,
  cb: Function<'js>,
  msec: Option<f64>,
  args: Vec<Value<'js>>,
  is_interval: bool,
) -> rquickjs::Result<Class<'js, Timeout>> {
  let requested = requested_ms(msec);
  let nesting = nesting_of(&ctx);
  // A timer armed inside a callback is one level below it.
  let level = nesting.load(Ordering::Relaxed).saturating_add(1);

  let abort = Arc::new(Notify::new());
  let abort_ref = abort.clone();
  let policy = P::capture(&ctx);

  ctx.spawn(async move {
    // Node passes `setTimeout(cb, ms, ...args)` extras through to every
    // invocation. Answers whether the timer should keep running. The
    // nesting level is published for the duration of the call, so a
    // timer the callback arms sees itself as one level deeper, and is
    // restored afterwards even when the callback throws.
    let fire = |level: u32| {
      let mut call_args = rquickjs::function::Args::new(cb.ctx().clone(), args.len());
      if call_args.push_args(args.iter().cloned()).is_err() {
        return false;
      }
      let outer = nesting.swap(level, Ordering::Relaxed);
      let res: rquickjs::Result<()> = P::enter(cb.ctx(), policy.as_ref(), || cb.call_arg(call_args));
      nesting.store(outer, Ordering::Relaxed);
      res
        .inspect_err(|err| tracing::warn!(target: "ferrijs::timers", "timer callback threw: {err}"))
        .is_ok()
    };

    if !is_interval {
      tokio::select! {
        () = abort_ref.notified() => {},
        () = wait(clamped(requested, level)) => { fire(level); },
      }
      return;
    }

    // An interval deepens a level per repeat, so its delay is recomputed
    // each time round rather than fixed at arm time. The deadline is
    // carried forward instead of restarted after the callback, so the
    // period does not drift by however long the callback took; a
    // callback that overruns its own period skips the ticks it missed
    // rather than firing them back to back.
    let mut level = level;
    let mut next = tokio::time::Instant::now() + clamped(requested, level);
    loop {
      let delay = next.saturating_duration_since(tokio::time::Instant::now());
      let aborted = tokio::select! {
        () = abort_ref.notified() => true,
        () = wait(delay) => false,
      };
      if aborted || !fire(level) {
        break;
      }
      level = level.saturating_add(1);
      let period = clamped(requested, level);
      next += period;
      let now = tokio::time::Instant::now();
      if next <= now {
        next = now + period;
      }
    }
  });

  Class::instance(ctx, Timeout { abort })
}

fn set_timeout<'js, P: CallbackPolicy>(
  ctx: Ctx<'js>,
  cb: Function<'js>,
  rest: Rest<Value<'js>>,
) -> rquickjs::Result<Class<'js, Timeout>> {
  let (msec, args) = split_delay_args(rest.0);
  set_timeout_interval::<P>(ctx, cb, msec, args, false)
}

fn set_interval<'js, P: CallbackPolicy>(
  ctx: Ctx<'js>,
  cb: Function<'js>,
  rest: Rest<Value<'js>>,
) -> rquickjs::Result<Class<'js, Timeout>> {
  let (msec, args) = split_delay_args(rest.0);
  set_timeout_interval::<P>(ctx, cb, msec, args, true)
}

/// Split `(delay?, ...args)` off the rest parameters, coercing the
/// delay to a number the way JS timers do (`undefined`/non-numeric ⇒ 0).
fn split_delay_args(mut rest: Vec<Value<'_>>) -> (Option<f64>, Vec<Value<'_>>) {
  if rest.is_empty() {
    return (None, rest);
  }
  let delay = rest.remove(0);
  (delay.as_number(), rest)
}

/// `setImmediate(cb, ...args)` — deferred to the microtask-adjacent job
/// queue, args passed through like Node. With a captured policy the
/// callback is wrapped in a native bracket so the deferred job runs
/// under it (same rule as `setTimeout`).
fn set_immediate<'js, P: CallbackPolicy>(
  ctx: Ctx<'js>,
  cb: Function<'js>,
  rest: Rest<Value<'js>>,
) -> rquickjs::Result<()> {
  match P::capture(&ctx) {
    None => {
      let mut args = rquickjs::function::Args::new(ctx, rest.0.len());
      args.push_args(rest.0)?;
      cb.defer_arg(args)
    },
    Some(policy) => {
      // The wrapper captures only the policy (plain data); the real
      // callback rides the deferred args (a native closure must never
      // capture a JS value or a `Persistent` — untraceable GC cycle at
      // teardown). A `Rest`-only signature keeps every JS value on one
      // `'js`.
      let policy = Some(policy);
      let wrapper = Function::new(ctx.clone(), move |args: Rest<Value<'_>>| {
        deferred_call::<P>(policy.as_ref(), &args.0)
      })?;
      let mut args = rquickjs::function::Args::new(ctx, rest.0.len() + 1);
      args.push_arg(cb)?;
      args.push_args(rest.0)?;
      wrapper.defer_arg(args)
    },
  }
}

/// Call the deferred callback (args[0]) with the rest of the args, under
/// `policy`.
fn deferred_call<P: CallbackPolicy>(policy: Option<&P>, args: &[Value<'_>]) -> rquickjs::Result<()> {
  let inner = args.first().and_then(|v| v.as_function().cloned()).ok_or_else(|| {
    rquickjs::Error::new_from_js_message("setImmediate", "Error", "deferred callback missing".to_string())
  })?;
  let ctx = inner.ctx().clone();
  let mut call_args = rquickjs::function::Args::new(ctx.clone(), args.len().saturating_sub(1));
  call_args.push_args(args.iter().skip(1).cloned())?;
  P::enter(&ctx, policy, || inner.call_arg(call_args))
}

/// WHATWG `queueMicrotask(cb)`. A named generic fn so `Ctx`, the
/// callback, and the wrapper share one `'js` (an inline closure would
/// give each its own lifetime).
fn queue_microtask<'js, P: CallbackPolicy>(ctx: Ctx<'js>, cb: Function<'js>) -> rquickjs::Result<()> {
  match P::capture(&ctx) {
    None => cb.defer::<()>(()),
    Some(policy) => {
      let policy = Some(policy);
      let wrapper = Function::new(ctx.clone(), move |args: Rest<Value<'_>>| {
        deferred_call::<P>(policy.as_ref(), &args.0)
      })?;
      wrapper.defer((cb,))
    },
  }
}

/// Install the timer globals, carrying `P` from registration to callback.
///
/// # Errors
///
/// Propagates the global writes.
pub fn install<P: CallbackPolicy>(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
  let globals = ctx.globals();
  // One nesting counter per realm, shared by both arming functions:
  // a `setInterval` armed inside a `setTimeout` callback is nested too.
  let _ = ctx.store_userdata(Nesting(Arc::new(AtomicU32::new(0))));
  globals.set("setTimeout", Func::from(set_timeout::<P>))?;
  globals.set("clearTimeout", Func::from(clear_timeout))?;
  globals.set("setInterval", Func::from(set_interval::<P>))?;
  globals.set("clearInterval", Func::from(clear_timeout))?;
  globals.set("setImmediate", Func::from(set_immediate::<P>))?;
  // The job queue drains outside whatever bracket the registrar ran in,
  // so a microtask it queued must carry the policy with it (same rule as
  // `setTimeout` / `setImmediate`).
  globals.set("queueMicrotask", Func::from(queue_microtask::<P>))?;
  Ok(())
}
