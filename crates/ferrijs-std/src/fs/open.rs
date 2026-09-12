// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::node::system_error;
use rquickjs::{function::Opt, Ctx, Exception, Result};
use tokio::fs::OpenOptions;

use super::file_handle::FileHandle;

pub async fn open(
    ctx: Ctx<'_>,
    path: String,
    flags: Opt<String>,
    mode: Opt<u32>,
) -> Result<FileHandle> {
    let mut options = OpenOptions::new();
    match flags.0.as_deref().unwrap_or("r") {
        // We are not supporting the sync modes
        "a" => options.append(true).create(true),
        "ax" | "xa" => options.append(true).create_new(true),
        "a+" => options.append(true).read(true).create(true),
        "ax+" | "xa+" => options.append(true).read(true).create_new(true),
        "r" => options.read(true),
        "r+" => options.read(true).write(true),
        "w" => options.write(true).create(true).truncate(true),
        "wx" | "xw" => options.write(true).create_new(true),
        "w+" => options.write(true).read(true).create(true).truncate(true),
        "wx+" | "xw+" => options.write(true).read(true).create_new(true),
        flags => {
            return Err(Exception::throw_message(
                &ctx,
                &["Invalid flags '", flags, "'"].concat(),
            ))
        },
    };
    #[cfg(unix)]
    {
        let mode = mode.0.unwrap_or(0o666);
        options.mode(mode);
    }
    #[cfg(not(unix))]
    {
        _ = mode;
    }

    let file = options
        .open(&path)
        .await
        .map_err(|error| system_error::throw(&ctx, &error, "open", &path))?;

    Ok(FileHandle::new(file, PathBuf::from(path)))
}
