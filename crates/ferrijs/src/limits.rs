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
/// installed once at creation.
///
/// Runs may overlap: a host dispatching several handlers into one realm
/// has several budgets in flight, and the interrupt must fire at the
/// EARLIEST of them. Each armed budget is a token; the handler reads a
/// cached minimum. Between runs nothing is armed and the minimum rests
/// at [`TimeoutState::DISARMED`], so a late VM entry (a callback
/// arriving after a run finished) is never force-halted by a stale
/// deadline from the previous run.
pub(crate) struct TimeoutState {
  epoch: Instant,
  /// The earliest armed deadline as milliseconds since `epoch`;
  /// `DISARMED` when nothing is armed.
  earliest_ms: AtomicU64,
  /// Every armed budget: `(token, deadline_ms, parked_at_arm_ms)`.
  armed: std::sync::Mutex<Vec<(u64, u64, u64)>>,
  next_token: AtomicU64,
  /// Set by the interrupt handler when it force-halted the interpreter.
  /// Never cleared: the realm is poisoned from then on.
  pub timed_out: AtomicBool,
  clock: Arc<dyn PauseClock>,
}

/// The token an armed budget answers to; disarm with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmToken(u64);

/// The token of the host's own slot ([`Deadline::arm`]), which a host
/// re-arms and disarms without holding a token.
const HOST_TOKEN: u64 = 0;

impl TimeoutState {
  pub const DISARMED: u64 = u64::MAX;

  pub fn new(clock: Arc<dyn PauseClock>) -> Self {
    Self {
      epoch: Instant::now(),
      earliest_ms: AtomicU64::new(Self::DISARMED),
      armed: std::sync::Mutex::new(Vec::new()),
      next_token: AtomicU64::new(1),
      timed_out: AtomicBool::new(false),
      clock,
    }
  }

  fn deadline_ms(&self, deadline: Instant) -> u64 {
    u64::try_from(deadline.saturating_duration_since(self.epoch).as_millis())
      .unwrap_or(Self::DISARMED - 1)
      .min(Self::DISARMED - 1)
  }

  fn armed(&self) -> std::sync::MutexGuard<'_, Vec<(u64, u64, u64)>> {
    self.armed.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn recompute(&self, armed: &[(u64, u64, u64)]) {
    let earliest = armed.iter().map(|(_, d, _)| *d).min().unwrap_or(Self::DISARMED);
    self.earliest_ms.store(earliest, Ordering::Relaxed);
  }

  /// Arm a budget ending at `deadline`; the returned token disarms it.
  pub fn arm(&self, deadline: Instant) -> ArmToken {
    let token = self.next_token.fetch_add(1, Ordering::Relaxed);
    let mut armed = self.armed();
    armed.push((token, self.deadline_ms(deadline), self.parked_ms()));
    self.recompute(&armed);
    ArmToken(token)
  }

  pub fn disarm(&self, token: ArmToken) {
    let mut armed = self.armed();
    armed.retain(|(t, _, _)| *t != token.0);
    self.recompute(&armed);
  }

  /// Arm (or re-arm) the host's slot.
  pub fn arm_host(&self, deadline: Instant) {
    let mut armed = self.armed();
    armed.retain(|(t, _, _)| *t != HOST_TOKEN);
    armed.push((HOST_TOKEN, self.deadline_ms(deadline), self.parked_ms()));
    self.recompute(&armed);
  }

  pub fn disarm_host(&self) {
    self.disarm(ArmToken(HOST_TOKEN));
  }

  fn parked_ms(&self) -> u64 {
    u64::try_from(self.clock.parked_now().as_millis()).unwrap_or(u64::MAX)
  }

  /// Whether the earliest armed budget has run out. Cheap on the common
  /// path (one atomic load); the parked-time correction only runs when a
  /// deadline looks due.
  pub fn expired(&self) -> bool {
    let earliest = self.earliest_ms.load(Ordering::Relaxed);
    if earliest == Self::DISARMED {
      return false;
    }
    let elapsed = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
    if elapsed < earliest {
      return false;
    }
    // A run held at a debugger is not a run that is running away: give
    // each armed budget back every millisecond spent parked since it
    // was armed, and ask again.
    let parked_now = self.parked_ms();
    let armed = self.armed();
    armed.iter().any(|(_, deadline, parked_at_arm)| {
      let parked = parked_now.saturating_sub(*parked_at_arm);
      elapsed >= deadline.saturating_add(parked)
    })
  }

  pub fn clock(&self) -> &Arc<dyn PauseClock> {
    &self.clock
  }
}

/// Cloneable handle to a realm's interrupt deadline, for a host that
/// arms a budget of its own around work it drives through
/// [`crate::Runtime::with`] (a test runner extending a per-test budget).
/// One slot: arming again replaces the previous host budget.
#[derive(Clone)]
pub struct Deadline(pub(crate) Arc<TimeoutState>);

impl Deadline {
  /// Arm the host slot `timeout` from now.
  pub fn arm(&self, timeout: Duration) {
    self.0.arm_host(Instant::now() + timeout);
  }

  /// Clear the host slot.
  pub fn disarm(&self) {
    self.0.disarm_host();
  }

  /// Whether the interrupt handler force-halted the interpreter.
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
    let token = state.arm(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    assert!(state.expired());
    state.disarm(token);
    assert!(!state.expired());
  }

  #[test]
  fn the_earliest_of_several_budgets_wins_and_survives_the_others_ending() {
    let state = TimeoutState::new(Arc::new(NeverParked));
    let far = state.arm(Instant::now() + Duration::from_secs(60));
    let near = state.arm(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    assert!(state.expired());
    // The far budget ending does not unarm the near one.
    state.disarm(far);
    assert!(state.expired());
    state.disarm(near);
    assert!(!state.expired());
    // The host slot re-arms in place.
    state.arm_host(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    state.arm_host(Instant::now() + Duration::from_secs(60));
    assert!(!state.expired());
    state.disarm_host();
  }
}
