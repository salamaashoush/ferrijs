use std::io;

use rquickjs::{Ctx, Exception, Result};

pub fn throw(ctx: &Ctx<'_>, error: &io::Error, syscall: &str, path: &str) -> rquickjs::Error {
  let code = match error.raw_os_error() {
    Some(libc::ENOENT) => "ENOENT",
    _ if error.kind() == io::ErrorKind::AlreadyExists => "EEXIST",
    Some(libc::ENOTDIR) => "ENOTDIR",
    Some(libc::EISDIR) => "EISDIR",
    Some(libc::EACCES) => "EACCES",
    Some(libc::EPERM) => "EPERM",
    Some(libc::ELOOP) => "ELOOP",
    Some(libc::ENAMETOOLONG) => "ENAMETOOLONG",
    Some(libc::EIO) => "EIO",
    Some(libc::ENOMEM) => "ENOMEM",
    _ => "UNKNOWN",
  };
  let message = format!("{code}: {error}, {syscall} '{path}'");
  let built: Result<Exception<'_>> = (|| {
    let exception = Exception::from_message(ctx.clone(), &message)?;
    exception.set("code", code)?;
    if let Some(errno) = error.raw_os_error() {
      exception.set("errno", -errno.abs())?;
    }
    exception.set("syscall", syscall)?;
    exception.set("path", path)?;
    Ok(exception)
  })();
  match built {
    Ok(exception) => ctx.throw(exception.into_value()),
    Err(error) => error,
  }
}
