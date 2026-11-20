//! LOCAL DELTA: the permission checks in front of every `fs` entry point.
//!
//! The vendored functions stay byte-close to upstream; each is wrapped
//! here by a function of the same shape that asks the realm's container
//! first. `fill_fs` and `export_promises` register the wrappers, so a
//! namespace built any way at all is guarded. An `open()` is checked for
//! the access its flags ask for; operations on the `FileHandle` it
//! returns are not re-checked, since the grant was given at open time,
//! which is how a capability works.

use std::path::Path;

use either::Either;
use rquickjs::{function::Opt, Ctx, Object, Result, Value};

use super::access::{access, access_sync};
use super::append_file::{append_file, append_file_sync};
use super::chmod::{chmod, chmod_sync};
use super::file_handle::FileHandle;
use super::mkdir::{mkdir, mkdir_sync, mkdtemp, mkdtemp_sync};
use super::open::open;
use super::read_dir::{read_dir, read_dir_sync, ReadDir};
use super::read_file::{read_file, read_file_sync, ReadFileOptions};
use super::realpath::{realpath, realpath_sync};
use super::rename::{rename, rename_sync};
use super::rm::{rmdir, rmdir_sync, rmfile, rmfile_sync};
use super::stats::{lstat_fn, lstat_fn_sync, stat_fn, stat_fn_sync, Stats};
use super::symlink::{symlink, symlink_sync};
use super::write_file::{write_file, write_file_sync, WriteFileOptions};
use crate::permissions::{check_read, check_write};

/// A path as Node's `fs` takes one: a string, a `Buffer` or other byte
/// view of one (UTF-8), or a `file:` `URL`, which `fileURLToPath`
/// turns into the path it names. Any other `URL` is
/// `ERR_INVALID_URL_SCHEME`, anything else `ERR_INVALID_ARG_TYPE`.
pub(super) struct PathLike(pub(super) String);

impl<'js> rquickjs::FromJs<'js> for PathLike {
    fn from_js(ctx: &Ctx<'js>, value: Value<'js>) -> Result<Self> {
        if let Some(text) = value.as_string() {
            return Ok(Self(text.to_string()?));
        }
        if let Some(object) = value.as_object() {
            if rquickjs::TypedArray::<u8>::from_value(value.clone()).is_ok() {
                let bytes = ObjectBytes::from(ctx, &value)?;
                return Ok(Self(String::from_utf8_lossy(bytes.as_bytes(ctx)?).into_owned()));
            }
            // Node's `isURL`: an object with an `href` and a `protocol`.
            let href: Option<String> = object.get("href").ok();
            let protocol: Option<String> = object.get("protocol").ok();
            if let (Some(href), Some(protocol)) = (href, protocol) {
                if protocol != "file:" {
                    return Err(crate::node::throw_error(
                        ctx,
                        "TypeError",
                        Some("ERR_INVALID_URL_SCHEME"),
                        "The URL must be of scheme file",
                    ));
                }
                return file_url_path(ctx, &href).map(Self);
            }
        }
        Err(crate::node::throw_error(
            ctx,
            "TypeError",
            Some("ERR_INVALID_ARG_TYPE"),
            "The \"path\" argument must be of type string or an instance of Buffer or URL.",
        ))
    }
}

/// `url.fileURLToPath(href)` for a `file:` URL.
fn file_url_path(ctx: &Ctx<'_>, href: &str) -> Result<String> {
    let url = url::Url::parse(href).map_err(|_| {
        crate::node::throw_error(ctx, "TypeError", Some("ERR_INVALID_URL"), "Invalid URL")
    })?;
    url.to_file_path()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|()| {
            crate::node::throw_error(
                ctx,
                "TypeError",
                Some("ERR_INVALID_FILE_URL_HOST"),
                "File URL host must be \"localhost\" or empty",
            )
        })
}
use crate::utils::bytes::ObjectBytes;

pub(super) async fn access_guarded(ctx: Ctx<'_>, path: PathLike, mode: Opt<u32>) -> Result<()> {
    let path = path.0;
    check_access_mode(&ctx, &path, mode.0)?;
    access(ctx, path, mode).await
}

pub(super) fn access_sync_guarded(ctx: Ctx<'_>, path: PathLike, mode: Opt<u32>) -> Result<()> {
    let path = path.0;
    check_access_mode(&ctx, &path, mode.0)?;
    access_sync(ctx, path, mode)
}

fn check_access_mode(ctx: &Ctx<'_>, path: &str, mode: Option<u32>) -> Result<()> {
    let path = Path::new(path);
    let mode = mode.unwrap_or(super::CONSTANT_F_OK);
    if mode & super::CONSTANT_W_OK != 0 {
        check_write(ctx, path)?;
    }
    if mode & (super::CONSTANT_R_OK | super::CONSTANT_X_OK) != 0 || mode & super::CONSTANT_W_OK == 0 {
        check_read(ctx, path)?;
    }
    Ok(())
}

pub(super) async fn append_file_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    data: Value<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    append_file(ctx, path, data, options).await
}

pub(super) fn append_file_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    bytes: ObjectBytes<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    append_file_sync(ctx, path, bytes, options)
}

pub(super) async fn realpath_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Value<'js>>,
) -> Result<String> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    realpath(ctx, path, options).await
}

pub(super) fn realpath_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Value<'js>>,
) -> Result<String> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    realpath_sync(ctx, path, options)
}

pub(super) async fn chmod_guarded(ctx: Ctx<'_>, path: PathLike, mode: u32) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    chmod(ctx, path, mode).await
}

pub(super) fn chmod_sync_guarded(ctx: Ctx<'_>, path: PathLike, mode: u32) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    chmod_sync(ctx, path, mode)
}

pub(super) async fn mkdir_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Object<'js>>,
) -> Result<String> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    mkdir(ctx, path, options).await
}

pub(super) fn mkdir_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Object<'js>>,
) -> Result<String> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    mkdir_sync(ctx, path, options)
}

pub(super) async fn mkdtemp_guarded(ctx: Ctx<'_>, prefix: String) -> Result<String> {
    check_write(&ctx, Path::new(&prefix))?;
    mkdtemp(ctx, prefix).await
}

pub(super) fn mkdtemp_sync_guarded(ctx: Ctx<'_>, prefix: String) -> Result<String> {
    check_write(&ctx, Path::new(&prefix))?;
    mkdtemp_sync(ctx, prefix)
}

pub(super) async fn open_guarded(
    ctx: Ctx<'_>,
    path: PathLike,
    flags: Opt<String>,
    mode: Opt<u32>,
) -> Result<FileHandle> {
    let path = path.0;
    check_open_flags(&ctx, &path, flags.0.as_deref())?;
    open(ctx, path, flags, mode).await
}

/// Every read/write flag needs both grants before a handle can escape.
/// A flag the vendored `open` will reject is checked as a
/// write, so the refusal (if any) is the sandbox's rather than a
/// filesystem error that reveals the file exists.
fn check_open_flags(ctx: &Ctx<'_>, path: &str, flags: Option<&str>) -> Result<()> {
    let path = Path::new(path);
    match flags.unwrap_or("r") {
        "r" | "rs" | "sr" => check_read(ctx, path),
        "r+" | "rs+" | "sr+" | "w+" | "wx+" | "xw+" | "a+" | "ax+" | "xa+" | "as+" | "sa+" => {
            check_read(ctx, path)?;
            check_write(ctx, path)
        }
        _ => check_write(ctx, path),
    }
}

pub(super) async fn read_dir_guarded(
    ctx: Ctx<'_>,
    path: PathLike,
    options: Opt<Object<'_>>,
) -> Result<ReadDir> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    read_dir(path, options).await
}

pub(super) fn read_dir_sync_guarded(
    ctx: Ctx<'_>,
    path: PathLike,
    options: Opt<Object<'_>>,
) -> Result<ReadDir> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    read_dir_sync(path, options)
}

pub(super) async fn read_file_guarded(
    ctx: Ctx<'_>,
    path: PathLike,
    options: Opt<Either<String, ReadFileOptions>>,
) -> Result<Value<'_>> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    read_file(ctx, path, options).await
}

pub(super) fn read_file_sync_guarded(
    ctx: Ctx<'_>,
    path: PathLike,
    options: Opt<Either<String, ReadFileOptions>>,
) -> Result<Value<'_>> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    read_file_sync(ctx, path, options)
}

pub(super) fn exists_sync_guarded(ctx: Ctx<'_>, path: PathLike) -> Result<bool> {
    let path = path.0;
    // Whether a file exists is a fact about the filesystem; without a
    // read grant the answer is the same `false` a missing file gives,
    // never an error that confirms the path.
    if check_read(&ctx, Path::new(&path)).is_err() {
        // Clear the exception the check threw: this is a soft refusal.
        let _ = ctx.catch();
        return Ok(false);
    }
    Ok(Path::new(&path).exists())
}

pub(super) async fn rename_guarded(ctx: Ctx<'_>, old_path: PathLike, new_path: PathLike) -> Result<()> {
    let old_path = old_path.0;
    let new_path = new_path.0;
    check_write(&ctx, Path::new(&old_path))?;
    check_write(&ctx, Path::new(&new_path))?;
    rename(ctx, old_path, new_path).await
}

pub(super) fn rename_sync_guarded(ctx: Ctx<'_>, old_path: PathLike, new_path: PathLike) -> Result<()> {
    let old_path = old_path.0;
    let new_path = new_path.0;
    check_write(&ctx, Path::new(&old_path))?;
    check_write(&ctx, Path::new(&new_path))?;
    rename_sync(ctx, old_path, new_path)
}

pub(super) async fn rmdir_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Object<'js>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    rmdir(ctx, path, options).await
}

pub(super) fn rmdir_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Object<'js>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    rmdir_sync(ctx, path, options)
}

pub(super) async fn rmfile_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    options: Opt<Object<'js>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    rmfile(ctx, path, options).await
}

pub(super) fn rmfile_sync_guarded(ctx: Ctx<'_>, path: PathLike, options: Opt<Object<'_>>) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    rmfile_sync(path, options)
}

pub(super) async fn stat_guarded(ctx: Ctx<'_>, path: PathLike) -> Result<Stats> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    stat_fn(ctx, path).await
}

pub(super) fn stat_sync_guarded(ctx: Ctx<'_>, path: PathLike) -> Result<Stats> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    stat_fn_sync(ctx, path)
}

pub(super) async fn lstat_guarded(ctx: Ctx<'_>, path: PathLike) -> Result<Stats> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    lstat_fn(ctx, path).await
}

pub(super) fn lstat_sync_guarded(ctx: Ctx<'_>, path: PathLike) -> Result<Stats> {
    let path = path.0;
    check_read(&ctx, Path::new(&path))?;
    lstat_fn_sync(ctx, path)
}

pub(super) async fn symlink_guarded<'js>(
    ctx: Ctx<'js>,
    target: PathLike,
    path: PathLike,
    type_value: Opt<String>,
) -> Result<()> {
    let path = path.0;
    let target = target.0;
    check_write(&ctx, Path::new(&path))?;
    symlink(ctx, target, path, type_value).await
}

pub(super) fn symlink_sync_guarded<'js>(
    ctx: Ctx<'js>,
    target: PathLike,
    path: PathLike,
    type_value: Opt<String>,
) -> Result<()> {
    let path = path.0;
    let target = target.0;
    check_write(&ctx, Path::new(&path))?;
    symlink_sync(ctx, target, path, type_value)
}

pub(super) async fn write_file_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    data: Value<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    write_file(ctx, path, data, options).await
}

pub(super) fn write_file_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: PathLike,
    bytes: ObjectBytes<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    let path = path.0;
    check_write(&ctx, Path::new(&path))?;
    write_file_sync(ctx, path, bytes, options)
}
