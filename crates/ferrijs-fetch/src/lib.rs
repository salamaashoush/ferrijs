//! A spec-faithful WHATWG Fetch model and the single send engine over
//! reqwest. A JS `fetch` global and a host's own HTTP client API both
//! marshal into the same [`Request`], go through the same [`send`] path,
//! and read back the same [`Response`] — there is no second code path.
//!
//! Layout:
//! - [`headers`] — the WHATWG header list.
//! - [`body`] — request/response body (`Empty` / `Bytes` / stream).
//! - [`model`] — [`Request`] / [`Response`] + the `RedirectMode` /
//!   `Credentials` / `ResponseType` enums and `RemoteAddr`.
//! - [`error`] — the typed [`FetchError`].
//! - [`engine`] — the client pool and the one manual-redirect send loop.
//! - [`net_guard`] — SSRF policy (allow-list, metadata/private blocking).
//! - [`cookie`] — RFC 6265 parsing/matching for the context-bound path.
//! - [`multipart`] — `multipart/form-data` serialization and parsing.
//! - [`bridge`] — the two-way cookie/defaults bridge to a host-owned jar
//!   (a browser context, a session store).
//! - [`cookie`] also carries the [`Cookie`] record that bridge speaks.

pub mod body;
pub mod bridge;
pub mod cookie;
pub mod engine;
pub mod error;
pub mod headers;
pub mod model;
pub mod multipart;
pub mod net_guard;

pub use body::{Body, ByteStream, channel_stream};
pub use bridge::{BridgeFuture, ContextBridge, ContextDefaults};
pub use cookie::{Cookie, SameSite};
pub use error::FetchError;
pub use headers::Headers;
pub use model::{Credentials, RedirectMode, RemoteAddr, Request, Response, ResponseType};
pub use multipart::{
  MultipartField, MultipartValue, multipart_boundary, multipart_boundary_of, parse_multipart, serialize_multipart,
};
pub use net_guard::{NetGuard, check_url, preflight};

pub use engine::{ClientPool, send};
