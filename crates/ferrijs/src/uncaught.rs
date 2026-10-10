//! What a realm does with an exception nothing caught: a throw from a
//! timer callback or a queued one. Unhandled rejections are not tracked;
//! see [`ferrijs_std::uncaught`].
//!
//! During a run the first one fails the run, the way Node exits on it,
//! even when the body itself finishes. A run waiting on work the throw
//! cut short fails at once rather than at its deadline. Outside a run
//! (a host listener firing between calls, say) the host's
//! [`crate::Builder::on_uncaught`] hook hears it, and without one it is
//! logged.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use rquickjs::{CaughtError, Ctx, Exception, Value};

use crate::error::ScriptError;
use crate::limits::TimeoutState;
use crate::redact::Redactor;

/// Hears what a realm could not report to a run.
pub type UncaughtHook = Arc<dyn Fn(ScriptError) + Send + Sync>;

/// The run in progress, as the handler sees it. The handler writes it on
/// the VM thread and the run reads it from the caller's; the locks are
/// taken only once an exception or a parked run needs them.
#[derive(Default)]
pub(crate) struct Watch {
  active: AtomicBool,
  failed: AtomicBool,
  error: Mutex<Option<ScriptError>>,
  waker: Mutex<Option<Waker>>,
}

impl Watch {
  pub(crate) fn take(&self) -> Option<ScriptError> {
    if !self.failed.load(Ordering::Relaxed) {
      return None;
    }
    self.failed.store(false, Ordering::Relaxed);
    self.error.lock().ok().and_then(|mut error| error.take())
  }
}

fn to_error<'js>(ctx: &Ctx<'js>, value: Value<'js>) -> ScriptError {
  let caught = match value
    .as_object()
    .and_then(|object| Exception::from_object(object.clone()))
  {
    Some(exception) => CaughtError::Exception(exception),
    None => CaughtError::Value(value),
  };
  ScriptError::from_caught(ctx, caught, "")
}

/// Take over the realm's uncaught reports.
pub(crate) fn install(
  ctx: &Ctx<'_>,
  watch: Arc<Watch>,
  timeout: Arc<TimeoutState>,
  hook: Option<UncaughtHook>,
  redactor: Option<Arc<dyn Redactor>>,
) {
  ferrijs_std::uncaught::set_handler(
    ctx,
    Box::new(move |ctx, value| {
      // A halted interpreter unwinds through whatever callback it was in;
      // that is the run's timeout, which the run reports itself.
      if timeout.timed_out.load(Ordering::Relaxed) {
        return;
      }
      let mut error = to_error(ctx, value);
      if watch.active.load(Ordering::Relaxed) && !watch.failed.load(Ordering::Relaxed) {
        if let Ok(mut slot) = watch.error.lock() {
          *slot = Some(error);
          watch.failed.store(true, Ordering::Relaxed);
        }
        if let Some(waker) = watch.waker.lock().ok().and_then(|mut waker| waker.take()) {
          waker.wake();
        }
        return;
      }
      if let Some(redactor) = &redactor {
        error.redact(redactor.as_ref());
      }
      if let Some(hook) = &hook {
        hook(error);
      } else {
        tracing::warn!(target: "ferrijs::uncaught", "uncaught {}: {}", error.kind, error.message);
      }
    }),
  );
}

/// Mark a run in flight, before its job is submitted.
pub(crate) fn begin(watch: &Watch) {
  watch.active.store(true, Ordering::Relaxed);
}

/// The run is over. Whether an exception arrived that its body did not
/// already return; [`Watch::take`] has it.
pub(crate) fn end(watch: &Watch) -> bool {
  watch.active.store(false, Ordering::Relaxed);
  watch.failed.load(Ordering::Relaxed)
}

/// The VM side of a run: `body`, ended early by an uncaught exception
/// once it parks. A body that finishes in one poll never touches the
/// lock; [`end`] catches what it threw on the way.
pub(crate) fn guard<F>(watch: Arc<Watch>, body: F) -> Guarded<F> {
  Guarded {
    watch,
    body,
    registered: false,
  }
}

pub(crate) struct Guarded<F> {
  watch: Arc<Watch>,
  body: F,
  registered: bool,
}

impl<T, F: Future<Output = Result<T, ScriptError>> + Unpin> Future for Guarded<F> {
  type Output = Result<T, ScriptError>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    if let Poll::Ready(outcome) = Pin::new(&mut self.body).poll(cx) {
      return Poll::Ready(outcome);
    }
    if let Some(error) = self.watch.take() {
      return Poll::Ready(Err(error));
    }
    if let Ok(mut waker) = self.watch.waker.lock()
      && !waker.as_ref().is_some_and(|known| known.will_wake(cx.waker()))
    {
      *waker = Some(cx.waker().clone());
    }
    self.registered = true;
    // An exception reported between the check above and the waker being
    // stored would otherwise wait for the body's next wake.
    match self.watch.take() {
      Some(error) => Poll::Ready(Err(error)),
      None => Poll::Pending,
    }
  }
}

impl<F> Drop for Guarded<F> {
  fn drop(&mut self) {
    if self.registered
      && let Ok(mut waker) = self.watch.waker.lock()
    {
      waker.take();
    }
  }
}
