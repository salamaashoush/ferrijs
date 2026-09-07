//! The timer globals, carrying the permission scope from registration to
//! callback.
//!
//! The timers themselves are [`ferrijs_std::web::timers`]; what the
//! runtime adds is the ambient state they carry. Capability follows the
//! registrar: a timer armed (or a microtask queued) by a narrowed host
//! handler keeps that handler's grants when it later fires from the
//! executor or the job queue, where the resting policy would otherwise
//! be the realm's wider one.

use rquickjs::Ctx;

/// Install `setTimeout` / `setInterval` / `setImmediate` /
/// `queueMicrotask` and their `clear*` twins.
///
/// # Errors
///
/// Propagates the global writes.
pub fn install(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
  ferrijs_std::web::timers::install::<ferrijs_std::permissions::Scope>(ctx)
}
