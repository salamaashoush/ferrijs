//! Exceptions nothing caught: a throw from a timer callback or from a
//! queued one (`queueMicrotask`, `process.nextTick`, `setImmediate`).
//!
//! The engine drops both: a timer's throw ends in the timer's own future
//! and a failed job is discarded by the job loop. Each is reported here
//! to the handler the host set for the realm; without one it is logged.
//!
//! Queued callbacks go through `QuickJS`'s own job queue with a C job
//! function rather than through a JS or rquickjs function, so a
//! microtask costs what `Function::defer` did.
//!
//! Unhandled rejections are not tracked. rquickjs reads a settled
//! promise without marking its rejection handled, so every Rust caller
//! that awaits an already-rejected promise would read as having left it
//! unhandled.

#![allow(unsafe_code)]

use std::ptr::NonNull;
use std::rc::Rc;

use rquickjs::{Ctx, Function, JsLifetime, Value, qjs};

/// What a realm does with an exception nothing caught.
pub type Handler = Box<dyn for<'js> Fn(&Ctx<'js>, Value<'js>)>;

struct HandlerUd(Rc<Handler>);

// SAFETY: holds a boxed closure and no JS value, so the unused `'js`
// lifetime can be restated freely.
unsafe impl JsLifetime<'_> for HandlerUd {
  type Changed<'to> = HandlerUd;
}

/// Set the realm's handler, replacing any earlier one.
pub fn set_handler(ctx: &Ctx<'_>, handler: Handler) {
  let _ = ctx.store_userdata(HandlerUd(Rc::new(handler)));
}

/// Report `value` as uncaught.
pub fn report<'js>(ctx: &Ctx<'js>, value: Value<'js>) {
  // Cloned out of the userdata guard first: the handler may run script,
  // and no userdata can be stored while a guard is held.
  let handler = ctx.userdata::<HandlerUd>().map(|handler| Rc::clone(&handler.0));
  match handler {
    Some(handler) => handler(ctx, value),
    None => tracing::warn!(target: "ferrijs::uncaught", "uncaught exception: {value:?}"),
  }
}

/// Report the exception a failed call left pending. Any other failure
/// is not a script's throw and is only logged.
pub fn report_error(ctx: &Ctx<'_>, error: &rquickjs::Error) {
  if error.is_exception() {
    report(ctx, ctx.catch());
  } else {
    tracing::warn!(target: "ferrijs::uncaught", "queued callback failed: {error}");
  }
}

/// Report the exception pending on `ctx`, unless it is the interpreter
/// being halted, which must keep unwinding. Answers the job's result.
///
/// # Safety
///
/// `ctx` is the live context running the job, with an exception pending.
unsafe fn report_pending(ctx: *mut qjs::JSContext) -> qjs::JSValue {
  unsafe {
    let exception = qjs::JS_GetException(ctx);
    if qjs::JS_IsUncatchableError(exception) {
      return qjs::JS_Throw(ctx, exception);
    }
    let reported = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let ctx = Ctx::from_raw(NonNull::new_unchecked(ctx));
      let value = Value::from_raw(ctx.clone(), exception);
      report(&ctx, value);
    }));
    if reported.is_err() {
      tracing::error!(target: "ferrijs::uncaught", "the uncaught handler panicked");
    }
    qjs::JS_UNDEFINED
  }
}

/// `argv[0](...argv[1..])`, reporting a throw.
unsafe extern "C" fn call_job(ctx: *mut qjs::JSContext, argc: qjs::c_int, argv: *mut qjs::JSValue) -> qjs::JSValue {
  unsafe {
    let result = qjs::JS_Call(ctx, *argv, qjs::JS_UNDEFINED, argc - 1, argv.add(1));
    if qjs::JS_IsException(result) {
      return report_pending(ctx);
    }
    qjs::JS_FreeValue(ctx, result);
    qjs::JS_UNDEFINED
  }
}

/// Queue `callback(...args)` as a microtask whose throw is reported.
///
/// # Errors
///
/// When the engine cannot allocate the job.
pub fn queue<'js>(ctx: &Ctx<'js>, callback: &Function<'js>, args: &[Value<'js>]) -> rquickjs::Result<()> {
  let mut argv = Vec::with_capacity(args.len() + 1);
  argv.push(callback.as_raw());
  argv.extend(args.iter().map(Value::as_raw));
  let count = qjs::c_int::try_from(argv.len()).map_err(|_| rquickjs::Error::Unknown)?;
  // SAFETY: the job queue duplicates every argument it is handed, so the
  // borrowed values outlive nothing here.
  if unsafe { qjs::JS_EnqueueJob(ctx.as_raw().as_ptr(), Some(call_job), count, argv.as_mut_ptr()) } < 0 {
    return Err(rquickjs::Error::Exception);
  }
  Ok(())
}
