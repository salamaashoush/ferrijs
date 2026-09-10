// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fs::Metadata;

use crate::node::system_error;
use rquickjs::{prelude::Opt, Ctx, Exception, Result};
use tokio::fs;

#[allow(dead_code, unused_imports)]
use super::{CONSTANT_F_OK, CONSTANT_R_OK, CONSTANT_W_OK, CONSTANT_X_OK};

pub async fn access(ctx: Ctx<'_>, path: String, mode: Opt<u32>) -> Result<()> {
    let metadata = fs::metadata(&path)
        .await
        .map_err(|error| system_error::throw(&ctx, &error, "access", &path))?;

    verify_metadata(&ctx, mode, metadata)
}

pub fn access_sync(ctx: Ctx<'_>, path: String, mode: Opt<u32>) -> Result<()> {
    let metadata = std::fs::metadata(&path)
        .map_err(|error| system_error::throw(&ctx, &error, "access", &path))?;

    verify_metadata(&ctx, mode, metadata)
}

fn verify_metadata(ctx: &Ctx, mode: Opt<u32>, metadata: Metadata) -> Result<()> {
    let permissions = metadata.permissions();

    let mode = mode.unwrap_or(CONSTANT_F_OK);

    if mode & CONSTANT_W_OK != 0 && permissions.readonly() {
        return Err(Exception::throw_message(
            ctx,
            "Permission denied. File not writable",
        ));
    }

    if mode & CONSTANT_X_OK != 0 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if permissions.mode() & 0o100 == 0 {
                return Err(Exception::throw_message(
                    ctx,
                    "Permission denied. File not executable",
                ));
            }
        }
        // On Windows, X_OK behaves like F_OK (file exists check only)
    }

    Ok(())
}
