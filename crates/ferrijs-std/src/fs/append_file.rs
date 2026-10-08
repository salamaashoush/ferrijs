//! LOCAL DELTA: `appendFile` and `appendFileSync`, which upstream lacks.
//!
//! The file is opened with `O_APPEND | O_CREAT`, so each write lands at
//! the end even when another writer has moved it, and `mode` applies only
//! when the call creates the file, as in Node. Options are read the way
//! `writeFile` reads them here. Failures keep Node's `code`, `errno`,
//! `syscall` and `path` through `node::system_error`.

use either::Either;
use rquickjs::{function::Opt, Ctx, Result, Value};
use tokio::io::AsyncWriteExt;

use super::write_file::WriteFileOptions;
use crate::node::system_error;
use crate::utils::bytes::ObjectBytes;

pub async fn append_file<'js>(
    ctx: Ctx<'js>,
    path: String,
    data: Value<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    let bytes = ObjectBytes::from(&ctx, &data)?;
    let mut file = tokio::fs::OpenOptions::from(open_options(&options))
        .open(&path)
        .await
        .map_err(|error| system_error::throw(&ctx, &error, "open", &path))?;
    file.write_all(bytes.as_bytes(&ctx)?)
        .await
        .map_err(|error| system_error::throw(&ctx, &error, "write", &path))?;
    file.flush()
        .await
        .map_err(|error| system_error::throw(&ctx, &error, "write", &path))
}

pub fn append_file_sync<'js>(
    ctx: Ctx<'js>,
    path: String,
    bytes: ObjectBytes<'js>,
    options: Opt<Either<String, WriteFileOptions>>,
) -> Result<()> {
    use std::io::Write;

    let mut file = open_options(&options)
        .open(&path)
        .map_err(|error| system_error::throw(&ctx, &error, "open", &path))?;
    file.write_all(bytes.as_bytes(&ctx)?)
        .map_err(|error| system_error::throw(&ctx, &error, "write", &path))
}

fn open_options(options: &Opt<Either<String, WriteFileOptions>>) -> std::fs::OpenOptions {
    let mut open = std::fs::OpenOptions::new();
    open.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mode = match &options.0 {
            Some(Either::Right(opts)) => opts.mode.unwrap_or(0o666),
            _ => 0o666,
        };
        open.mode(mode);
    }
    #[cfg(not(unix))]
    {
        _ = options;
    }
    open
}
