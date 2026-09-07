// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use rquickjs::{Ctx, Object, Result};

// LOCAL DELTA: upstream hardcodes `llrt <version>`; the runtime's own
// name comes from `crate::identity`, which the host sets.
pub fn init(ctx: &Ctx<'_>) -> Result<()> {
    let globals = ctx.globals();

    let navigator = Object::new(ctx.clone())?;

    navigator.set("userAgent", crate::identity::get(ctx).user_agent())?;

    globals.set("navigator", navigator)?;

    Ok(())
}
