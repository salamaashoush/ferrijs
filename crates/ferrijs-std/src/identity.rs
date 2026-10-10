//! Which runtime a script believes it is running in.
//!
//! `process.release.name`, `process.argv0`, `process.versions` and
//! `navigator.userAgent` name the runtime. The values here default to
//! this crate's, and a host that ships its own binary sets its own before
//! installing the globals, so a user-agent sniffer or a `process.release`
//! check sees the binary the user is actually running.
//!
//! `process.version` is the exception: libraries gate features with
//! `semver.satisfies(process.version, ...)`, and the runtime's own
//! version read as an ancient Node turned those features off (jsonwebtoken
//! dropped PS256). It is [`NODE_VERSION`], the Node release whose API this
//! runtime follows. `process.versions.node` stays absent, so a library
//! that tests for Node itself does not take a path that needs Node's
//! internals.

use rquickjs::{Ctx, JsLifetime};

/// The Node release whose API the standard library follows, without the
/// leading `v`. What `process.version` reports.
pub const NODE_VERSION: &str = "24.0.0";

/// The runtime's name and version as scripts see them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
  /// The binary's name (`process.release.name`, `process.argv0`, the
  /// `navigator.userAgent` product token).
  pub name: String,
  /// Its version, without a leading `v`.
  pub version: String,
}

impl Default for Identity {
  fn default() -> Self {
    Self {
      name: "ferrijs".to_string(),
      version: env!("CARGO_PKG_VERSION").to_string(),
    }
  }
}

impl Identity {
  #[must_use]
  pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
    Self {
      name: name.into(),
      version: version.into(),
    }
  }

  /// `name/version`, the shape Node 21+ reports as `navigator.userAgent`.
  #[must_use]
  pub fn user_agent(&self) -> String {
    format!("{}/{}", self.name, self.version)
  }
}

/// The QuickJS engine version, as the engine itself reports it.
#[must_use]
pub fn quickjs_version() -> &'static str {
  // SAFETY: `JS_GetVersion` returns a pointer to a static NUL-terminated
  // string owned by the engine; it is never freed.
  #[allow(unsafe_code)]
  unsafe {
    std::ffi::CStr::from_ptr(rquickjs::qjs::JS_GetVersion())
  }
  .to_str()
  .unwrap_or("unknown")
}

struct IdentityUd(Identity);

// SAFETY: owned strings only; no borrowed JS values, so re-stating the
// unused `'js` lifetime is sound.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for IdentityUd {
  type Changed<'to> = IdentityUd;
}

/// Record the identity every later `install` reads. Call before
/// [`crate::init`] or [`crate::node::process::install`]; a second call
/// replaces the first.
pub fn set(ctx: &Ctx<'_>, identity: Identity) {
  let _ = ctx.store_userdata(IdentityUd(identity));
}

/// The realm's identity, or the crate default when the host set none.
#[must_use]
pub fn get(ctx: &Ctx<'_>) -> Identity {
  ctx.userdata::<IdentityUd>().map_or_else(Identity::default, |ud| ud.0.clone())
}
