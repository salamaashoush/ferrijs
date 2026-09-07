//! Resource ceilings, and the deadline the interrupt handler reads.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Default per-run wall-clock timeout (5 minutes).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_mins(5);

/// Extra slack past the run deadline before the tokio-level backstop
/// fires. The interrupt handler is the preferred kill (it halts the
/// interpreter cleanly with the run's console output intact), but it
/// only runs while bytecode executes -- a script parked on a native
/// `await` (`await new Promise(() => {})`) never re-enters the
/// interpreter, so the backstop is the only thing that frees the realm.
/// The grace keeps the two mechanisms from racing.
pub const DEFAULT_BACKSTOP_GRACE: Duration = Duration::from_secs(1);

/// Default heap quota (256 MiB).
pub const DEFAULT_MEMORY_LIMIT: usize = 256 * 1024 * 1024;

/// Default JS stack size (1 MiB).
pub const DEFAULT_STACK_SIZE: usize = 1024 * 1024;

/// Default GC trigger threshold (64 MiB). `QuickJS` is reference-counted;
/// the cycle GC otherwise fires adaptively at ~1.5x live size, so an
/// object-churny program pays recurring mark-sweep stalls mid-run.
/// Raising the floor lets a typical short-lived run finish with few or
/// zero cycle-GC passes -- the same lever LLRT exposes
/// (`LLRT_GC_THRESHOLD_MB`, 20 MiB default). The memory limit remains
/// the hard backstop, and acyclic garbage is still freed immediately by
/// refcounting, so this only defers *cycle* collection.
pub const DEFAULT_GC_THRESHOLD: usize = 64 * 1024 * 1024;

/// What one realm may consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
  /// Heap ceiling in bytes. An allocation past it fails with `out of
  /// memory`, which poisons the realm.
  pub memory: usize,
  /// JS stack ceiling in bytes. Past it a `RangeError` is thrown, which
  /// is recoverable.
  pub stack: usize,
  /// Cycle-GC trigger threshold in bytes. See [`DEFAULT_GC_THRESHOLD`].
  pub gc_threshold: usize,
  /// Wall-clock budget for one run. The interrupt handler force-halts
  /// the interpreter past it; the backstop frees a run parked on a
  /// native await.
  pub timeout: Duration,
  /// See [`DEFAULT_BACKSTOP_GRACE`].
  pub backstop_grace: Duration,
}

impl Default for Limits {
  fn default() -> Self {
    Self {
      memory: DEFAULT_MEMORY_LIMIT,
      stack: DEFAULT_STACK_SIZE,
      gc_threshold: DEFAULT_GC_THRESHOLD,
      timeout: DEFAULT_TIMEOUT,
      backstop_grace: DEFAULT_BACKSTOP_GRACE,
    }
  }
}

/// Per-run overrides of the realm's [`Limits`].
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
  pub timeout: Option<Duration>,
  pub memory: Option<usize>,
  pub stack: Option<usize>,
  pub gc_threshold: Option<usize>,
}

/// Time a host held the process stopped (a debugger, a pause at a
/// breakpoint), which a deadline must not count. The default counts
/// nothing.
pub trait PauseClock: Send + Sync {
  /// Total parked time so far, including a park still open.
  fn parked_now(&self) -> Duration;
}

/// The clock of a host that never parks.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverParked;

impl PauseClock for NeverParked {
  fn parked_now(&self) -> Duration {
    Duration::ZERO
  }
}

/// Currently-applied runtime limits, so a run can skip redundant
/// `AsyncRuntime` setter calls (each takes the runtime's async lock;
/// re-pushing identical values every run is pure overhead on a warm
/// realm running many small scripts).
pub(crate) struct AppliedLimits {
  pub memory: AtomicUsize,
  pub stack: AtomicUsize,
  pub gc: AtomicUsize,
}

impl AppliedLimits {
  pub fn new(limits: &Limits) -> Self {
    Self {
      memory: AtomicUsize::new(limits.memory),
      stack: AtomicUsize::new(limits.stack),
      gc: AtomicUsize::new(limits.gc_threshold),
    }
  }
}

/// Deadline state consulted by the realm's single interrupt handler,
/// installed once at creation. Between runs the deadline rests at
/// [`TimeoutState::DISARMED`], so a late VM entry (a callback arriving
/// after a run finished) is never force-halted by a stale deadline
/// from the previous run.
pub(crate) struct TimeoutState {
  epoch: Instant,
  /// Deadline as milliseconds since `epoch`; `DISARMED` between runs.
  deadline_ms: AtomicU64,
  /// Time the process had spent parked when the current deadline was
  /// armed. Whatever it gains after that is time this run was held
  /// rather than running, and is added back in [`Self::expired`].
  parked_at_arm_ms: AtomicU64,
  /// Set by the interrupt handler when it force-halted the interpreter.
  pub timed_out: AtomicBool,
  clock: Arc<dyn PauseClock>,
}

impl TimeoutState {
  pub const DISARMED: u64 = u64::MAX;

  pub fn new(clock: Arc<dyn PauseClock>) -> Self {
    Self {
      epoch: Instant::now(),
      deadline_ms: AtomicU64::new(Self::DISARMED),
      parked_at_arm_ms: AtomicU64::new(0),
      timed_out: AtomicBool::new(false),
      clock,
    }
  }

  pub fn arm(&self, deadline: Instant) {
    let ms = u64::try_from(deadline.saturating_duration_since(self.epoch).as_millis())
      .unwrap_or(Self::DISARMED - 1)
      .min(Self::DISARMED - 1);
    self.timed_out.store(false, Ordering::Relaxed);
    self.parked_at_arm_ms.store(self.parked_ms(), Ordering::Relaxed);
    self.deadline_ms.store(ms, Ordering::Relaxed);
  }

  pub fn disarm(&self) {
    self.deadline_ms.store(Self::DISARMED, Ordering::Relaxed);
  }

  fn parked_ms(&self) -> u64 {
    u64::try_from(self.clock.parked_now().as_millis()).unwrap_or(u64::MAX)
  }

  pub fn expired(&self) -> bool {
    let deadline = self.deadline_ms.load(Ordering::Relaxed);
    if deadline == Self::DISARMED {
      return false;
    }
    // A run held at a debugger is not a run that is running away: give
    // back every millisecond spent parked since this deadline was armed.
    let parked = self
      .parked_ms()
      .saturating_sub(self.parked_at_arm_ms.load(Ordering::Relaxed));
    let elapsed = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
    elapsed >= deadline.saturating_add(parked)
  }

  pub fn clock(&self) -> &Arc<dyn PauseClock> {
    &self.clock
  }
}

/// Cloneable handle to a realm's interrupt deadline, for a host that
/// re-arms it from outside the run (a test runner extending a budget).
#[derive(Clone)]
pub struct Deadline(pub(crate) Arc<TimeoutState>);

impl Deadline {
  /// Arm the deadline `timeout` from now.
  pub fn arm(&self, timeout: Duration) {
    self.0.arm(Instant::now() + timeout);
  }

  /// Clear the deadline.
  pub fn disarm(&self) {
    self.0.disarm();
  }

  /// Whether the interrupt handler force-halted the interpreter for
  /// this deadline.
  ///
  /// A force-halt stops the VM wherever it happened to be -- mid-await,
  /// mid-property-write -- so the realm is not trustworthy afterwards
  /// even though its state still LOOKS intact. A plain JS throw is not
  /// a force-halt and leaves the realm usable.
  #[must_use]
  pub fn force_halted(&self) -> bool {
    self.0.timed_out.load(Ordering::Relaxed)
  }
}

/// The error [`run_within`] answers when `limit` elapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timedout;

/// Drive `fut` for at most `limit` of un-parked time.
///
/// # Errors
///
/// [`Timedout`] when `limit` elapses without the future finishing, not
/// counting time the [`PauseClock`] reports as parked.
pub async fn run_within<F: std::future::Future>(
  clock: &Arc<dyn PauseClock>,
  limit: Duration,
  fut: F,
) -> Result<F::Output, Timedout> {
  let started = Instant::now();
  // The clock counts the whole process, so only what it gains from here
  // on belongs to this call -- otherwise work that runs after a long
  // stop would inherit that stop's grace and never time out.
  let parked_before = clock.parked_now();
  let deadline_now = || started + limit + clock.parked_now().saturating_sub(parked_before);
  let mut fut = std::pin::pin!(fut);
  loop {
    let deadline = deadline_now();
    tokio::select! {
      out = &mut fut => return Ok(out),
      () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
        // The deadline may have moved while we slept (a park opened
        // and closed); only give up when it is really behind us.
        if Instant::now() >= deadline_now() {
          return Err(Timedout);
        }
      },
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn run_within_lets_a_quick_future_through() {
    let clock: Arc<dyn PauseClock> = Arc::new(NeverParked);
    let out = run_within(&clock, Duration::from_secs(5), async { 7 }).await;
    assert_eq!(out, Ok(7));
  }

  #[tokio::test]
  async fn run_within_times_out_a_parked_future() {
    let clock: Arc<dyn PauseClock> = Arc::new(NeverParked);
    let out = run_within(&clock, Duration::from_millis(20), std::future::pending::<()>()).await;
    assert_eq!(out, Err(Timedout));
  }

  #[test]
  fn disarmed_deadline_never_expires() {
    let state = TimeoutState::new(Arc::new(NeverParked));
    assert!(!state.expired());
    state.arm(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    assert!(state.expired());
    state.disarm();
    assert!(!state.expired());
  }
}
