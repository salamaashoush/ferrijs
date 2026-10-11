//! LOCAL DELTA: `realpath` and `realpathSync`, which upstream lacks.
//!
//! The path is resolved the way the operating system resolves it, every
//! symlink followed and every `.` and `..` folded, which is also how the
//! read grant in front of it is decided: the answer names nothing the
//! caller could not already have read through the path it gave. A failure
//! keeps Node's `code`, `errno`, `syscall` and `path` through
//! `node::system_error`; the syscall is `lstat` for the synchronous form
//! and `realpath` for the promise, as it is in Node, whose synchronous
//! form walks the path itself. The answer is always a string: Node's
//! `encoding: 'buffer'` is refused rather than ignored.

use std::path::Path;

use rquickjs::{function::Opt, Ctx, Exception, Result, Value};

use crate::node::system_error;

pub async fn realpath<'js>(ctx: Ctx<'js>, path: String, options: Opt<Value<'js>>) -> Result<String> {
    refuse_buffer(&ctx, options.0.as_ref())?;
    tokio::fs::canonicalize(&path)
        .await
        .map(|resolved| displayed(&resolved))
        .map_err(|error| system_error::throw(&ctx, &error, "realpath", &path))
}

pub fn realpath_sync<'js>(ctx: Ctx<'js>, path: String, options: Opt<Value<'js>>) -> Result<String> {
    refuse_buffer(&ctx, options.0.as_ref())?;
    std::fs::canonicalize(&path)
        .map(|resolved| displayed(&resolved))
        .map_err(|error| system_error::throw(&ctx, &error, "lstat", &path))
}

/// The resolved path as Node prints it. Windows answers a canonical path
/// in its `\\?\` form, which names the same file as the plain one.
fn displayed(resolved: &Path) -> String {
    dunce::simplified(resolved).to_string_lossy().into_owned()
}

fn refuse_buffer<'js>(ctx: &Ctx<'js>, options: Option<&Value<'js>>) -> Result<()> {
    let encoding = match options {
        Some(value) if value.is_string() => value.get::<String>().ok(),
        Some(value) => value
            .as_object()
            .and_then(|bag| bag.get::<_, Option<String>>("encoding").ok().flatten()),
        None => None,
    };
    if encoding.as_deref() == Some("buffer") {
        return Err(Exception::throw_type(
            ctx,
            "realpath: the 'buffer' encoding is not supported, the path is returned as a string",
        ));
    }
    Ok(())
}
