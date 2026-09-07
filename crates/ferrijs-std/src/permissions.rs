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
//!
//! The container is the realm's for its whole life and only narrows.
//! Nothing here carries a policy across a callback: a timer fires under
//! the same container it was armed under, because there is only one.

use std::path::Path;
use std::sync::Arc;

use ferrijs_permissions::{Container, Denied, SysInfo};
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

/// Whether `kind` covers `resource` right now, for a `has()`-style
/// query. Unrestricted when no container is installed.
///
/// # Errors
///
/// A `net` rule or `sys` name that does not parse, thrown as a
/// `TypeError`.
pub fn has(ctx: &Ctx<'_>, kind: &str, resource: Option<&str>) -> rquickjs::Result<bool> {
  let kind: ferrijs_permissions::Kind = kind
    .parse()
    .map_err(|m: String| rquickjs::Exception::throw_type(ctx, &m))?;
  match container(ctx) {
    Some(c) => c
      .has(kind, resource)
      .map_err(|m| rquickjs::Exception::throw_type(ctx, &m)),
    None => Ok(true),
  }
}

/// Give up `resource` under `kind` (or the whole kind) for good: Node's
/// `process.permission.drop`. Nothing when no container is installed.
///
/// # Errors
///
/// A kind, rule or name that does not parse, thrown as a `TypeError`.
pub fn drop(ctx: &Ctx<'_>, kind: &str, resource: Option<&str>) -> rquickjs::Result<()> {
  let kind: ferrijs_permissions::Kind = kind
    .parse()
    .map_err(|m: String| rquickjs::Exception::throw_type(ctx, &m))?;
  let Some(c) = container(ctx) else {
    return Ok(());
  };
  match resource {
    Some(r) => c.deny(kind, r).map_err(|m| rquickjs::Exception::throw_type(ctx, &m)),
    None => {
      let mut remaining = (*c.permissions()).clone();
      match kind {
        ferrijs_permissions::Kind::Read => remaining.read = ferrijs_permissions::Allow::None,
        ferrijs_permissions::Kind::Write => remaining.write = ferrijs_permissions::Allow::None,
        ferrijs_permissions::Kind::Net => remaining.net = ferrijs_permissions::Allow::None,
        ferrijs_permissions::Kind::Env => remaining.env = ferrijs_permissions::Allow::None,
        ferrijs_permissions::Kind::Sys => remaining.sys = ferrijs_permissions::Allow::None,
      }
      c.revoke(&remaining);
      Ok(())
    },
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ferrijs_permissions::Permissions;

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
