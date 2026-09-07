//! The timer globals.
//!
//! The timers themselves are [`ferrijs_std::web::timers`]. They carry no
//! ambient state: a callback fires under the same realm container it
//! was armed under, because a realm has exactly one. A host that needs
//! a timer to run under different authority than the code that armed it
//! has two trust domains, and two trust domains are two realms.

use rquickjs::Ctx;

/// Install `setTimeout` / `setInterval` / `setImmediate` /
/// `queueMicrotask` and their `clear*` twins.
///
/// # Errors
///
/// Propagates the global writes.
pub fn install(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
  ferrijs_std::web::timers::install::<ferrijs_std::web::timers::NoPolicy>(ctx)
}
