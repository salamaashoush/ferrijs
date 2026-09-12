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
use super::chmod::{chmod, chmod_sync};
use super::file_handle::FileHandle;
use super::mkdir::{mkdir, mkdir_sync, mkdtemp, mkdtemp_sync};
use super::open::open;
use super::read_dir::{read_dir, read_dir_sync, ReadDir};
use super::read_file::{read_file, read_file_sync, ReadFileOptions};
use super::rename::{rename, rename_sync};
use super::rm::{rmdir, rmdir_sync, rmfile, rmfile_sync};
use super::stats::{lstat_fn, lstat_fn_sync, stat_fn, stat_fn_sync, Stats};
use super::symlink::{symlink, symlink_sync};
use super::write_file::{write_file, write_file_sync, WriteFileOptions};
use crate::permissions::{check_read, check_write};
use crate::utils::bytes::ObjectBytes;

pub(super) async fn access_guarded(ctx: Ctx<'_>, path: String, mode: Opt<u32>) -> Result<()> {
    check_access_mode(&ctx, &path, mode.0)?;
    access(ctx, path, mode).await
}

pub(super) fn access_sync_guarded(ctx: Ctx<'_>, path: String, mode: Opt<u32>) -> Result<()> {
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

pub(super) async fn chmod_guarded(ctx: Ctx<'_>, path: String, mode: u32) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    chmod(ctx, path, mode).await
}

pub(super) fn chmod_sync_guarded(ctx: Ctx<'_>, path: String, mode: u32) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    chmod_sync(ctx, path, mode)
}

pub(super) async fn mkdir_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    options: Opt<Object<'js>>,
) -> Result<String> {
    check_write(&ctx, Path::new(&path))?;
    mkdir(ctx, path, options).await
}

pub(super) fn mkdir_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    options: Opt<Object<'js>>,
) -> Result<String> {
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
    path: String,
    flags: Opt<String>,
    mode: Opt<u32>,
) -> Result<FileHandle> {
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
    path: String,
    options: Opt<Object<'_>>,
) -> Result<ReadDir> {
    check_read(&ctx, Path::new(&path))?;
    read_dir(path, options).await
}

pub(super) fn read_dir_sync_guarded(
    ctx: Ctx<'_>,
    path: String,
    options: Opt<Object<'_>>,
) -> Result<ReadDir> {
    check_read(&ctx, Path::new(&path))?;
    read_dir_sync(path, options)
}

pub(super) async fn read_file_guarded(
    ctx: Ctx<'_>,
    path: String,
    options: Opt<Either<String, ReadFileOptions>>,
) -> Result<Value<'_>> {
    check_read(&ctx, Path::new(&path))?;
    read_file(ctx, path, options).await
}

pub(super) fn read_file_sync_guarded(
    ctx: Ctx<'_>,
    path: String,
    options: Opt<Either<String, ReadFileOptions>>,
) -> Result<Value<'_>> {
    check_read(&ctx, Path::new(&path))?;
    read_file_sync(ctx, path, options)
}

pub(super) fn exists_sync_guarded(ctx: Ctx<'_>, path: String) -> Result<bool> {
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

pub(super) async fn rename_guarded(ctx: Ctx<'_>, old_path: String, new_path: String) -> Result<()> {
    check_write(&ctx, Path::new(&old_path))?;
    check_write(&ctx, Path::new(&new_path))?;
    rename(ctx, old_path, new_path).await
}

pub(super) fn rename_sync_guarded(ctx: Ctx<'_>, old_path: String, new_path: String) -> Result<()> {
    check_write(&ctx, Path::new(&old_path))?;
    check_write(&ctx, Path::new(&new_path))?;
    rename_sync(ctx, old_path, new_path)
}

pub(super) async fn rmdir_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    options: Opt<Object<'js>>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    rmdir(ctx, path, options).await
}

pub(super) fn rmdir_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    options: Opt<Object<'js>>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    rmdir_sync(ctx, path, options)
}

pub(super) async fn rmfile_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    options: Opt<Object<'js>>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    rmfile(ctx, path, options).await
}

pub(super) fn rmfile_sync_guarded(ctx: Ctx<'_>, path: String, options: Opt<Object<'_>>) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    rmfile_sync(path, options)
}

pub(super) async fn stat_guarded(ctx: Ctx<'_>, path: String) -> Result<Stats> {
    check_read(&ctx, Path::new(&path))?;
    stat_fn(ctx, path).await
}

pub(super) fn stat_sync_guarded(ctx: Ctx<'_>, path: String) -> Result<Stats> {
    check_read(&ctx, Path::new(&path))?;
    stat_fn_sync(ctx, path)
}

pub(super) async fn lstat_guarded(ctx: Ctx<'_>, path: String) -> Result<Stats> {
    check_read(&ctx, Path::new(&path))?;
    lstat_fn(ctx, path).await
}

pub(super) fn lstat_sync_guarded(ctx: Ctx<'_>, path: String) -> Result<Stats> {
    check_read(&ctx, Path::new(&path))?;
    lstat_fn_sync(ctx, path)
}

pub(super) async fn symlink_guarded<'js>(
    ctx: Ctx<'js>,
    target: String,
    path: String,
    type_value: Opt<String>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    symlink(ctx, target, path, type_value).await
}

pub(super) fn symlink_sync_guarded<'js>(
    ctx: Ctx<'js>,
    target: String,
    path: String,
    type_value: Opt<String>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    symlink_sync(ctx, target, path, type_value)
}

pub(super) async fn write_file_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    data: Value<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    write_file(ctx, path, data, options).await
}

pub(super) fn write_file_sync_guarded<'js>(
    ctx: Ctx<'js>,
    path: String,
    bytes: ObjectBytes<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    check_write(&ctx, Path::new(&path))?;
    write_file_sync(ctx, path, bytes, options)
}
