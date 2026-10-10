//! What a host keeps in a realm, and how it calls back into script.
//!
//! - State: any `'static` Rust value, found again from any binding by its
//!   type ([`set`], [`with`], [`with_or_default`], [`get`], [`take`]). A
//!   host needs no `unsafe impl JsLifetime` of its own.
//! - [`Callback`]: a script function kept past the call that handed it
//!   over, and called later.
//! - [`Pump`]: a channel from any thread into the realm's event loop, for
//!   events the host raises on its own tasks (a page event, a socket
//!   frame). Its handler runs on the loop, between runs as well as during
//!   one, so a listener fires while a script is parked on an await.
//!
//! Nothing here may be touched from another thread with the realm's
//! context: a host task reaches the realm through [`crate::VmHandle`]
//! (`vm_with!`, `vm_try!`) or by sending into a [`Pump`].

use std::cell::RefCell;

use rquickjs::function::IntoArgs;
use rquickjs::{Ctx, FromJs, Function, JsLifetime, Persistent, Value};

/// One host value in a realm's userdata.
struct Slot<T>(RefCell<T>);

// SAFETY: `T: 'static` holds no `'js` value, so the context lifetime it
// is stored under can be restated to any other.
#[allow(unsafe_code)]
unsafe impl<T: 'static> JsLifetime<'_> for Slot<T> {
  type Changed<'to> = Slot<T>;
}

/// Store `value`, replacing the one of its type already there.
pub fn set<T: 'static>(ctx: &Ctx<'_>, value: T) {
  if let Some(slot) = ctx.userdata::<Slot<T>>() {
    *slot.0.borrow_mut() = value;
    return;
  }
  let _ = ctx.store_userdata(Slot(RefCell::new(value)));
}

/// Run `f` with the stored `T`, or answer `None` when there is none.
///
/// `f` must not run script: script may call a binding that reaches the
/// same `T`, which is borrowed. Take what a call needs out first, with
/// [`get`] or inside `f`.
pub fn with<T: 'static, R>(ctx: &Ctx<'_>, f: impl FnOnce(&mut T) -> R) -> Option<R> {
  let slot = ctx.userdata::<Slot<T>>()?;
  let mut value = slot.0.borrow_mut();
  Some(f(&mut value))
}

/// [`with`], storing `T::default()` first when there is none.
pub fn with_or_default<T: Default + 'static, R>(ctx: &Ctx<'_>, f: impl FnOnce(&mut T) -> R) -> R {
  if ctx.userdata::<Slot<T>>().is_none() {
    let _ = ctx.store_userdata(Slot(RefCell::new(T::default())));
  }
  match ctx.userdata::<Slot<T>>() {
    Some(slot) => f(&mut slot.0.borrow_mut()),
    // Storing fails only while another userdata guard is held; `f` then
    // sees a default that is not kept.
    None => f(&mut T::default()),
  }
}

/// A clone of the stored `T`: the way to reach host state from code that
/// then runs script (an `Arc` handle, a channel sender).
pub fn get<T: Clone + 'static>(ctx: &Ctx<'_>) -> Option<T> {
  with(ctx, |value: &mut T| value.clone())
}

/// Remove the stored `T` and hand it back.
pub fn take<T: 'static>(ctx: &Ctx<'_>) -> Option<T> {
  ctx
    .remove_userdata::<Slot<T>>()
    .ok()
    .flatten()
    .map(|slot| slot.0.into_inner())
}

/// A script function kept for later, by the host or in host state.
///
/// Cloning is cheap; every clone calls the same function. Keep it in the
/// realm it came from: restoring it into another is an error.
#[derive(Clone)]
pub struct Callback(Persistent<Function<'static>>);

impl Callback {
  /// Keep `function`.
  #[must_use]
  pub fn save<'js>(ctx: &Ctx<'js>, function: Function<'js>) -> Self {
    Self(Persistent::save(ctx, function))
  }

  /// The function itself, for an identity comparison or a call of the
  /// host's own.
  ///
  /// # Errors
  ///
  /// When the callback belongs to another realm.
  pub fn restore<'js>(&self, ctx: &Ctx<'js>) -> rquickjs::Result<Function<'js>> {
    self.0.clone().restore(ctx)
  }

  /// Call it and convert what it returns.
  ///
  /// # Errors
  ///
  /// What it threw, or a failed conversion.
  pub fn call<'js, A, R>(&self, ctx: &Ctx<'js>, args: A) -> rquickjs::Result<R>
  where
    A: IntoArgs<'js>,
    R: FromJs<'js>,
  {
    self.restore(ctx)?.call(args)
  }

  /// Call it and await what it returns when that is a promise, as script
  /// awaits an async listener.
  ///
  /// # Errors
  ///
  /// What it threw or rejected with.
  pub async fn call_async<'js, A>(&self, ctx: &Ctx<'js>, args: A) -> rquickjs::Result<Value<'js>>
  where
    A: IntoArgs<'js>,
  {
    let value: Value<'js> = self.call(ctx, args)?;
    crate::value::await_value(ctx, value).await
  }
}

/// Why a [`Pump::try_send`] did not deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
  /// The pump is at capacity: the handler is behind.
  Full,
  /// The realm is gone.
  Closed,
}

impl std::fmt::Display for SendError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Full => write!(f, "the pump is full"),
      Self::Closed => write!(f, "the realm is gone"),
    }
  }
}

impl std::error::Error for SendError {}

/// The sending end of a pump: cloneable, `Send`, usable from any thread.
pub struct Pump<T> {
  sender: tokio::sync::mpsc::Sender<T>,
}

impl<T> Clone for Pump<T> {
  fn clone(&self) -> Self {
    Self {
      sender: self.sender.clone(),
    }
  }
}

impl<T: Send + 'static> Pump<T> {
  /// Start a pump on the realm's event loop. Up to `capacity` messages
  /// wait for the handler; each is handled in the order sent.
  ///
  /// A handler's failure is reported as uncaught (it fails the run in
  /// progress, as a throwing listener ends a Node process); a handler
  /// that means to swallow a listener's throw catches it itself.
  pub fn start(
    ctx: &Ctx<'_>,
    capacity: usize,
    handle: impl for<'js> Fn(&Ctx<'js>, T) -> rquickjs::Result<()> + 'static,
  ) -> Self {
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<T>(capacity.max(1));
    let pump_ctx = ctx.clone();
    ctx.spawn(async move {
      while let Some(message) = receiver.recv().await {
        if let Err(error) = handle(&pump_ctx, message) {
          ferrijs_std::uncaught::report_error(&pump_ctx, &error);
        }
      }
    });
    Self { sender }
  }

  /// Deliver `message` without waiting.
  ///
  /// # Errors
  ///
  /// [`SendError::Full`] when the handler is `capacity` messages behind,
  /// [`SendError::Closed`] when the realm is gone.
  pub fn try_send(&self, message: T) -> Result<(), SendError> {
    self.sender.try_send(message).map_err(|error| match error {
      tokio::sync::mpsc::error::TrySendError::Full(_) => SendError::Full,
      tokio::sync::mpsc::error::TrySendError::Closed(_) => SendError::Closed,
    })
  }

  /// Deliver `message`, waiting for room.
  ///
  /// # Errors
  ///
  /// [`SendError::Closed`] when the realm is gone.
  pub async fn send(&self, message: T) -> Result<(), SendError> {
    self.sender.send(message).await.map_err(|_| SendError::Closed)
  }
}
