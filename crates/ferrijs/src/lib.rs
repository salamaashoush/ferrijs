//! ferrijs: an embeddable JavaScript runtime on `QuickJS`.
//!
//! A [`Runtime`] is one sandboxed realm: the engine, its context, the
//! single event loop that owns them, and the policy they run under.
//! Build one with [`Runtime::builder`], granting what the program may
//! reach through [`Permissions`] and bounding what it may consume
//! through [`Limits`]; add host API as [`Extension`]s; then
//! [`Runtime::eval_script`] a script, [`Runtime::eval_module`] a
//! compiled module, or [`Runtime::run`] a body of your own under the
//! same bracket.
//!
//! What every realm has: the web-standard globals (`URL`, `fetch`,
//! Streams, `crypto`, `TextEncoder`, `AbortController`, `Blob`,
//! `structuredClone`, ...), the timer globals, `console`, `process`
//! and `require`, and the Node modules (`node:fs`, `node:path`,
//! `node:buffer`, `node:crypto`, `node:events`, `node:util`,
//! `node:zlib`, ...) under the same names Node serves them. Every one of
//! them answers to the realm's permissions.

#![allow(
  clippy::missing_errors_doc,
  clippy::missing_panics_doc,
  clippy::must_use_candidate,
  clippy::module_name_repetitions,
  clippy::cast_possible_truncation,
  clippy::cast_precision_loss,
  clippy::cast_sign_loss,
  clippy::too_many_lines,
  clippy::uninlined_format_args,
  clippy::needless_pass_by_value,
  clippy::doc_markdown,
  clippy::return_self_not_must_use,
  // Some web-API classes are legitimately stateless per their WHATWG
  // spec, but `#[rquickjs::methods]` instance methods must still take
  // `&self` to be callable on an instance.
  clippy::unused_self
)]

pub mod console;
pub mod console_fmt;
pub mod error;
pub mod extension;
#[cfg(feature = "fetch")]
pub mod fetch;
pub mod limits;
pub mod modules;
pub mod realm;
pub mod redact;
pub mod result;
pub mod runtime;
pub mod source_map;
pub mod timers;
pub mod value;
pub mod vm;

pub use console::{ConsoleCapture, ConsoleSink};
pub use error::{ScriptError, ScriptErrorKind};
pub use extension::{Extension, FnExtension};
pub use ferrijs_permissions::{self as permissions, Container, Denied, Permissions, SysInfo};
pub use ferrijs_std as std;
pub use ferrijs_std::identity::Identity;
pub use limits::{Deadline, Limits, PauseClock, RunOptions};
pub use modules::{ModulePolicy, ModuleRegistry, NativeModule, RequireHook};
pub use realm::RealmOptions;
pub use redact::{Redactor, Secrets};
pub use result::{ConsoleEntry, ConsoleLevel, Outcome, ScriptResult, ScriptSuccess};
pub use rquickjs;
pub use runtime::{Builder, Config, ConsoleOptions, ProcessOptions, Run, RunBody, Runtime, vm_handle};
pub use source_map::{CompiledModule, LazyMap, SourceMapper};
pub use vm::VmHandle;
