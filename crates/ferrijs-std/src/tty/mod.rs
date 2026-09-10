// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use crate::utils::module::{export_default, ModuleInfo};
use rquickjs::{
    module::{Declarations, Exports, ModuleDef},
    prelude::Func,
    Ctx, Result,
};

// Windows' CRT `_isatty` answers for any character device, so a pipe to NUL
// counts and the result disagrees with what Node reports through
// `uv_guess_handle`. `IsTerminal` asks the console directly, which is the same
// question, so the three standard descriptors go through it. Anything else
// still has to be asked of the C library, and Windows has no descriptor table
// to ask about.
fn isatty(fd: i32) -> bool {
    use std::io::IsTerminal;

    match fd {
        0 => std::io::stdin().is_terminal(),
        1 => std::io::stdout().is_terminal(),
        2 => std::io::stderr().is_terminal(),
        #[cfg(unix)]
        other => unsafe { libc::isatty(other) != 0 },
        #[cfg(not(unix))]
        _ => false,
    }
}

pub struct TtyModule;

impl ModuleDef for TtyModule {
    fn declare(declare: &Declarations<'_>) -> Result<()> {
        declare.declare("isatty")?;
        declare.declare("default")?;
        Ok(())
    }

    fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> Result<()> {
        export_default(ctx, exports, |default| {
            default.set("isatty", Func::from(isatty))?;
            Ok(())
        })
    }
}

impl From<TtyModule> for ModuleInfo<TtyModule> {
    fn from(val: TtyModule) -> Self {
        ModuleInfo {
            name: "tty",
            module: val,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tty::TtyModule;
    use crate::test::{call_test, test_async_with, ModuleEvaluator};
    use std::io::{stderr, stdin, stdout, IsTerminal};

    #[tokio::test]
    async fn test_isatty() {
        test_async_with(|ctx| {
            Box::pin(async move {
                ModuleEvaluator::eval_rust::<TtyModule>(ctx.clone(), "tty")
                    .await
                    .unwrap();

                let module = ModuleEvaluator::eval_js(
                    ctx.clone(),
                    "test",
                    r#"
                        import { isatty } from 'tty';

                        export async function test() {
                            return new Array(3).fill(0).map((_, i) => +isatty(i)).join('')
                        }
                    "#,
                )
                .await
                .unwrap();
                let expect = [
                    stdin().is_terminal(),
                    stdout().is_terminal(),
                    stderr().is_terminal(),
                ]
                .map(|i| (i as u8).to_string())
                .join("");
                let result = call_test::<String, _>(&ctx, &module, ()).await;
                assert_eq!(result, expect);
            })
        })
        .await;
    }
}
