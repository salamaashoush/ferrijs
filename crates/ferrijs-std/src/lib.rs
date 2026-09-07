//! Vendored subset of [awslabs/llrt](https://github.com/awslabs/llrt)
//! (Apache-2.0): the WHATWG Streams implementation plus the pieces it
//! needs (`llrt_utils`, `llrt_events`, `llrt_exceptions`, `llrt_abort`).
//!
//! Upstream crate -> module here:
//!
//! | upstream            | module        |
//! |---------------------|---------------|
//! | `llrt_utils`        | [`utils`]     |
//! | `llrt_context`      | [`context`]   |
//! | `llrt_exceptions`   | [`exceptions`]|
//! | `llrt_events`       | [`events`]    |
//! | `llrt_abort`        | [`abort`]     |
//! | `llrt_os`           | [`os`]        |
//! | `llrt_fs`           | [`fs`]        |
//! | `llrt_path` (helpers)| [`pathutil`] |
//! | `llrt_encoding`     | [`encoding`]  |
//! | `llrt_buffer`       | [`buffer`]    |
//! | `llrt_json`         | [`json`]      |
//! | `llrt_crypto`       | [`crypto`]    |
//! | `llrt_stream_web`   | [`stream_web`]|
//! | `llrt_zlib`         | [`zlib`]      |
//! | `llrt_compression`  | [`compression`]|
//! | `llrt_string_decoder`| [`string_decoder`]|
//! | `llrt_perf_hooks`   | [`perf_hooks`]|
//! | `llrt_tty`          | [`tty`]       |
//! | `llrt_navigator`    | [`navigator`] |
//! | `llrt_url`          | [`url`]       |
//! | `llrt_util` (codecs)| [`text`]      |
//! | `llrt_test`         | `test` (dev)  |
//!
//! Sources are kept byte-close to upstream — only `crate::` / `llrt_*`
//! path prefixes are rewritten — so a re-sync stays a mechanical diff.
//! Host-specific behaviour belongs in the embedding runtime, not here.

pub mod abort;
pub mod context;
pub mod buffer;
/// Codec back-ends behind `zlib` (upstream `llrt_compression`).
pub mod compression;
pub mod crypto;
pub mod encoding;
pub mod events;
pub mod exceptions;
pub mod fs;
pub mod identity;
pub mod json;
pub mod modules;
pub mod navigator;
/// Node modules this crate implements itself, because upstream llrt has
/// none or only a stub. Written to the repo's style, but compiled under
/// this crate's relaxed lints: pedantic's `needless_pass_by_value` is
/// unsatisfiable for rquickjs callback signatures, which must take owned
/// JS values.
pub mod node;
pub mod os;
pub mod perf_hooks;
pub mod permissions;
/// Path helpers the vendored `fs` needs (upstream `llrt_path`). The
/// `path` MODULE is this crate's own; only these Rust helpers come from
/// upstream, so `fs` stays byte-close to it.
pub mod pathutil;
pub mod stream_web;
pub mod string_decoder;
pub mod text;
pub mod tty;
pub mod url;
pub mod utils;
pub mod zlib;
/// Web-platform globals with no upstream in llrt, written here so the
/// runtime has exactly one implementation of each.
pub mod web;

#[cfg(test)]
mod test;

use rquickjs::{Ctx, Result};

/// Install every web-standard global on `ctx`: `DOMException`, `Event` /
/// `EventTarget`, `AbortController` / `AbortSignal`, the full Streams
/// surface, `Buffer` / `Blob` / `File`, `crypto`, the text codecs,
/// `URL` / `URLSearchParams`, `atob` / `btoa`, `structuredClone`,
/// `performance`, `FormData`, the compression streams and `navigator`.
///
/// One entry point, so a host cannot install half the crate. What is
/// deliberately NOT here: the timers (they carry host state, see
/// [`web::timers`]), `process` (its `env` and `cwd` are the host's to
/// supply, see [`node::process`]), the Node modules (served through
/// [`modules::modules`] by the host's loader) and an `fs` global (Node
/// has none; [`fs::init`] is the opt-in).
pub fn init(ctx: &Ctx<'_>) -> Result<()> {
  exceptions::init(ctx)?;
  events::init(ctx)?;
  abort::init(ctx)?;
  stream_web::init(ctx)?;
  buffer::init(ctx)?;
  crypto::init(ctx)?;
  text::init(ctx)?;
  url::init(ctx)?;
  web::init(ctx)?;
  navigator::init(ctx)?;
  Ok(())
}
