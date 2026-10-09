//! Realms built ahead of need.
//!
//! A host that gives every request or every test a realm of its own pays
//! the realm's build on that request's clock. A pool builds them in the
//! background instead, so taking one is a queue pop, and refills itself
//! after every take. It moves the build off the latency path; it does not
//! make it cheaper, and a pool kept full spends that CPU whether or not a
//! request arrives to use it.
//!
//! A realm leaves the pool for good. There is no way to hand one back:
//! whatever ran in it is still in its heap, and a realm another request
//! could inherit is the isolation the pool exists to keep.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use crate::error::ScriptError;
use crate::runtime::{Builder, Runtime};

type Factory = dyn Fn() -> Builder + Send + Sync;

struct Inner {
  factory: Box<Factory>,
  target: usize,
  state: Mutex<State>,
}

#[derive(Default)]
struct State {
  ready: VecDeque<Runtime>,
  /// Builds in flight, counted against `target` so concurrent takes do
  /// not each start a full refill.
  building: usize,
}

/// A queue of prebuilt realms, all from one [`Builder`] recipe.
#[derive(Clone)]
pub struct RealmPool {
  inner: Arc<Inner>,
}

impl std::fmt::Debug for RealmPool {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("RealmPool")
      .field("target", &self.inner.target)
      .field("ready", &self.ready())
      .finish_non_exhaustive()
  }
}

impl RealmPool {
  /// A pool that keeps `target` realms ready, each built by `factory`,
  /// and starts filling at once. Must be called inside a Tokio runtime:
  /// the builds run as spawned tasks.
  pub fn new(target: usize, factory: impl Fn() -> Builder + Send + Sync + 'static) -> Self {
    let pool = Self {
      inner: Arc::new(Inner {
        factory: Box::new(factory),
        target,
        state: Mutex::new(State::default()),
      }),
    };
    pool.refill();
    pool
  }

  /// A realm no one has used: a ready one when there is one, otherwise
  /// one built now. Either way the pool starts topping itself back up.
  ///
  /// # Errors
  ///
  /// Only from an inline build, the same failure [`Builder::build`]
  /// reports. A background build that fails is logged and not retried
  /// until the next take, so a broken recipe surfaces here rather than
  /// spinning.
  pub async fn acquire(&self) -> Result<Runtime, ScriptError> {
    let taken = self.lock().ready.pop_front();
    self.refill();
    match taken {
      Some(realm) => Ok(realm),
      None => (self.inner.factory)().build().await,
    }
  }

  /// How many realms are ready to hand out right now.
  #[must_use]
  pub fn ready(&self) -> usize {
    self.lock().ready.len()
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, State> {
    self.inner.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn refill(&self) {
    let missing = {
      let mut state = self.lock();
      let missing = self.inner.target.saturating_sub(state.ready.len() + state.building);
      state.building += missing;
      missing
    };
    for _ in 0..missing {
      let weak = Arc::downgrade(&self.inner);
      let builder = (self.inner.factory)();
      tokio::spawn(fill(weak, builder));
    }
  }
}

async fn fill(pool: Weak<Inner>, builder: Builder) {
  let built = builder.build().await;
  let Some(pool) = pool.upgrade() else {
    return;
  };
  let mut state = pool.state.lock().unwrap_or_else(PoisonError::into_inner);
  state.building -= 1;
  match built {
    Ok(realm) => state.ready.push_back(realm),
    Err(error) => tracing::warn!(target: "ferrijs::pool", "a pooled realm failed to build: {error}"),
  }
}
