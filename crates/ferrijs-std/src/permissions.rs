//! The realm's permission container, and the checks every module makes.
//!
//! The policy itself is `ferrijs_permissions`; this module is where it
//! meets `QuickJS`: the [`Container`] is stored as context userdata, each
//! `fs` / `os` / network entry point calls one of the `check_*` helpers,
//! and a refusal is thrown into JS as a `PermissionDeniedError` carrying
//! Node's `ERR_ACCESS_DENIED` code plus the `permission` and `resource`
//! Node attaches.
//!
//! A realm with no container installed is unrestricted. The `ferrijs`
//! runtime always installs one (deny-all unless the host grants more);
//! a host embedding this crate without the runtime calls [`install`]
//! itself, or gets a standard library with no sandbox.

use std::path::Path;
use std::sync::Arc;

use ferrijs_permissions::{Container, Denied, Permissions, SysInfo};
use rquickjs::{Ctx, JsLifetime, Object, Value};

struct ContainerUd(Arc<Container>);

// SAFETY: holds an owned `Arc` to `'static` data; no borrowed JS values.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for ContainerUd {
  type Changed<'to> = ContainerUd;
}

/// Install the realm's container. A second call replaces the first.
pub fn install(ctx: &Ctx<'_>, container: Arc<Container>) {
  let _ = ctx.store_userdata(ContainerUd(container));
}

/// The realm's container, if a host installed one.
#[must_use]
pub fn container(ctx: &Ctx<'_>) -> Option<Arc<Container>> {
  ctx.userdata::<ContainerUd>().map(|ud| Arc::clone(&ud.0))
}

/// Throw `denied` into JS as a `PermissionDeniedError`.
///
/// Shape: `name` is `PermissionDeniedError`, `code` is
/// `ERR_ACCESS_DENIED`, `permission` is the kind (`read`, `net`, ...)
/// and `resource` is what was asked for, so a script can catch and
/// report it the way it would Node's.
#[must_use]
pub fn throw_denied(ctx: &Ctx<'_>, denied: &Denied) -> rquickjs::Error {
  let built: rquickjs::Result<Value<'_>> = (|| {
    let ctor: rquickjs::function::Constructor<'_> = ctx.globals().get("Error")?;
    let err: Object<'_> = ctor.construct((denied.to_string(),))?;
    err.set("name", Denied::NAME)?;
    err.set("code", Denied::CODE)?;
    err.set("permission", denied.kind.as_str())?;
    err.set("resource", denied.resource.as_str())?;
    Ok(err.into_value())
  })();
  match built {
    Ok(v) => ctx.throw(v),
    Err(_) => rquickjs::Exception::throw_message(ctx, &denied.to_string()),
  }
}

fn checked(ctx: &Ctx<'_>, result: Result<(), Denied>) -> rquickjs::Result<()> {
  result.map_err(|denied| throw_denied(ctx, &denied))
}

/// # Errors
///
/// A `PermissionDeniedError` when the realm's `read` grant does not
/// cover `path`.
pub fn check_read(ctx: &Ctx<'_>, path: &Path) -> rquickjs::Result<()> {
  match container(ctx) {
    Some(c) => checked(ctx, c.check_read(path)),
    None => Ok(()),
  }
}

/// # Errors
///
/// A `PermissionDeniedError` when the realm's `write` grant does not
/// cover `path`.
pub fn check_write(ctx: &Ctx<'_>, path: &Path) -> rquickjs::Result<()> {
  match container(ctx) {
    Some(c) => checked(ctx, c.check_write(path)),
    None => Ok(()),
  }
}

/// # Errors
///
/// A `PermissionDeniedError` when the realm's `net` grant does not
/// cover `host:port`.
pub fn check_net(ctx: &Ctx<'_>, host: &str, port: Option<u16>) -> rquickjs::Result<()> {
  match container(ctx) {
    Some(c) => checked(ctx, c.check_net(host, port)),
    None => Ok(()),
  }
}

/// # Errors
///
/// A `PermissionDeniedError` when the realm's `env` grant does not
/// cover `name`.
pub fn check_env(ctx: &Ctx<'_>, name: &str) -> rquickjs::Result<()> {
  match container(ctx) {
    Some(c) => checked(ctx, c.check_env(name)),
    None => Ok(()),
  }
}

/// # Errors
///
/// A `PermissionDeniedError` when the realm's `sys` grant does not
/// cover `item`.
pub fn check_sys(ctx: &Ctx<'_>, item: SysInfo) -> rquickjs::Result<()> {
  match container(ctx) {
    Some(c) => checked(ctx, c.check_sys(item)),
    None => Ok(()),
  }
}

/// The policy in force right now: the realm's, or the narrowing a host
/// dispatch installed. `None` when no container is installed.
#[must_use]
pub fn effective(ctx: &Ctx<'_>) -> Option<Arc<Permissions>> {
  container(ctx).map(|c| c.effective())
}

/// The narrowing a scheduled callback must run under, captured when a
/// timer or microtask is registered and re-entered when it fires. This
/// is the [`crate::web::timers::CallbackPolicy`] the runtime installs
/// its timers with: a callback armed by a narrowed handler keeps that
/// handler's grants instead of falling back to the realm's.
#[derive(Clone)]
pub struct Scope(Option<Arc<Permissions>>);

impl crate::web::timers::CallbackPolicy for Scope {
  fn capture(ctx: &Ctx<'_>) -> Option<Self> {
    container(ctx).and_then(|c| c.active()).map(|p| Self(Some(p)))
  }

  fn enter<R>(ctx: &Ctx<'_>, policy: Option<&Self>, f: impl FnOnce() -> R) -> R {
    match (container(ctx), policy) {
      (Some(c), Some(scope)) => c.enter(scope.0.clone(), f),
      _ => f(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn a_refusal_is_a_node_shaped_error() {
    let rt = rquickjs::Runtime::new().unwrap();
    let cx = rquickjs::Context::full(&rt).unwrap();
    cx.with(|ctx| {
      install(&ctx, Arc::new(Container::new(Permissions::none())));
      let err = check_read(&ctx, Path::new("/etc/passwd")).unwrap_err();
      assert!(matches!(err, rquickjs::Error::Exception));
      let ex = ctx.catch();
      let obj = ex.as_object().unwrap();
      assert_eq!(obj.get::<_, String>("name").unwrap(), "PermissionDeniedError");
      assert_eq!(obj.get::<_, String>("code").unwrap(), "ERR_ACCESS_DENIED");
      assert_eq!(obj.get::<_, String>("permission").unwrap(), "read");
      assert_eq!(obj.get::<_, String>("resource").unwrap(), "/etc/passwd");
    });
  }

  #[test]
  fn no_container_means_no_restriction() {
    let rt = rquickjs::Runtime::new().unwrap();
    let cx = rquickjs::Context::full(&rt).unwrap();
    cx.with(|ctx| {
      assert!(check_write(&ctx, Path::new("/anything")).is_ok());
      assert!(check_net(&ctx, "example.com", Some(443)).is_ok());
    });
  }
}
