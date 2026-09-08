// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use rquickjs::{
    prelude::{Opt, Rest},
    Ctx, IntoJs, Null, Object, Result, Value,
};
use sysinfo::System;

use crate::os::get_home_dir;

pub static EOL: &str = "\r\n";
pub static DEV_NULL: &str = "\\\\.\\nul";

// Node reports `Windows_NT` here on every Windows release, matching
// `uname -s` under MSYS rather than the marketing name.
pub fn get_type() -> &'static str {
    "Windows_NT"
}

pub fn get_release() -> &'static str {
    static RELEASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    RELEASE.get_or_init(|| System::kernel_version().unwrap_or_default())
}

pub fn get_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| System::long_os_version().unwrap_or_default())
}

// Windows scheduling priorities are per-process classes, not the nice
// values `getpriority` returns. Node answers 0 (`PRIORITY_NORMAL`) for a
// process it has not been asked to change, which is what a caller that
// never calls `setPriority` always sees.
pub fn get_priority(_who: Opt<u32>) -> i32 {
    0
}

pub fn set_priority(_ctx: Ctx<'_>, _args: Rest<Value<'_>>) -> Result<()> {
    Ok(())
}

// There is no uid/gid on Windows; Node reports -1 for both and leaves
// `shell` null.
pub fn get_user_info<'js>(ctx: Ctx<'js>, _options: Opt<Value<'js>>) -> Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("uid", -1)?;
    obj.set("gid", -1)?;
    obj.set(
        "username",
        std::env::var("USERNAME").unwrap_or_default().into_js(&ctx)?,
    )?;
    obj.set("shell", Null.into_js(&ctx)?)?;
    obj.set("homedir", get_home_dir())?;
    Ok(obj)
}
