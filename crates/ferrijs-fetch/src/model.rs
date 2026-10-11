//! The WHATWG request/response model the engine sends and returns.
//!
//! [`Request`] is fully resolved before it reaches the engine (absolute
//! URL, params appended, headers assembled, body materialized): the
//! engine is format-agnostic. [`Response`] carries the metadata plus a
//! single-use [`Body`].

use std::time::Duration;

use super::body::Body;
use super::headers::Headers;
use super::net_guard::NetGuard;

/// How a redirect response is handled, mirroring WHATWG Fetch's
/// `RequestInit.redirect` (`follow` | `manual` | `error`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RedirectMode {
  /// Follow up to the redirect cap ([`Request::max_redirects`]), then
  /// error (the default).
  #[default]
  Follow,
  /// Do not follow: the 3xx response is returned as-is (the JS layer
  /// turns this into an opaque-redirect `Response`).
  Manual,
  /// Treat any redirect as a network error.
  Error,
}

/// WHATWG `RequestCredentials` — whether stored cookies ride the request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Credentials {
  /// Never send credentials (cookies).
  Omit,
  /// Send credentials (the default for this engine, and what Playwright's
  /// `request` always does — the browser context is the jar).
  #[default]
  SameOrigin,
  /// Send credentials on cross-origin requests too. Same behaviour as
  /// `SameOrigin` here since the engine has a single origin scope.
  Include,
}

/// WHATWG `Response.type`: how the response was filtered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResponseType {
  /// A same-origin (unfiltered) response.
  #[default]
  Basic,
  /// A CORS-filtered response.
  Cors,
  /// An opaque cross-origin `no-cors` response.
  Opaque,
  /// An opaque `redirect: manual` 3xx.
  OpaqueRedirect,
  /// A network-error response (`Response.error()`).
  Error,
  /// A constructed response with no filtering applied.
  Default,
}

impl ResponseType {
  #[must_use]
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Basic => "basic",
      Self::Cors => "cors",
      Self::Opaque => "opaque",
      Self::OpaqueRedirect => "opaqueredirect",
      Self::Error => "error",
      Self::Default => "default",
    }
  }
}

/// Resolved peer address of a response. Mirrors Playwright's
/// `RemoteAddr` (`{ ipAddress, port }`) returned by
/// `apiResponse.serverAddr()` / `response.serverAddr()`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteAddr {
  #[serde(rename = "ipAddress")]
  pub ip_address: String,
  pub port: u16,
}

/// When the phases of one hop ended, as offsets from its start. A phase
/// that did not happen is `None`: no lookup for an address literal, no
/// connect on a connection the pool already had.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Timing {
  /// Wall-clock start of the hop that produced the response. A redirect
  /// starts a new hop, as it does in Playwright's `_sendRequest`.
  pub start_time: std::time::SystemTime,
  /// The host name was resolved.
  pub dns_end: Option<Duration>,
  /// The connection was established, TLS handshake included.
  pub connect_end: Option<Duration>,
  /// The response head arrived.
  pub response_start: Duration,
}

impl Default for Timing {
  fn default() -> Self {
    Self {
      start_time: std::time::SystemTime::UNIX_EPOCH,
      dns_end: None,
      connect_end: None,
      response_start: Duration::ZERO,
    }
  }
}

/// Answers a `401` Basic challenge from the hop at a URL with the
/// `Authorization` value to send it again with, or `None` to leave the
/// challenge to the caller. Asked per hop, so a redirect to another
/// origin is answered with that origin's credentials and never with the
/// first one's (Playwright's `_sendRequest`, `server/fetch.ts`).
#[derive(Clone)]
pub struct ChallengeAnswer(std::sync::Arc<AnswerFn>);

type AnswerFn = dyn Fn(&reqwest::Url) -> Option<String> + Send + Sync;

impl ChallengeAnswer {
  pub fn new(answer: impl Fn(&reqwest::Url) -> Option<String> + Send + Sync + 'static) -> Self {
    Self(std::sync::Arc::new(answer))
  }

  pub(crate) fn answer(&self, url: &reqwest::Url) -> Option<String> {
    (self.0)(url)
  }
}

impl std::fmt::Debug for ChallengeAnswer {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("ChallengeAnswer")
  }
}

/// A fully-resolved request the engine can send as-is.
#[derive(Debug)]
pub struct Request {
  pub method: reqwest::Method,
  /// Absolute URL with query params already appended.
  pub url: reqwest::Url,
  /// Assembled request headers (content-type already set for bodies).
  pub headers: Headers,
  pub body: Body,
  pub redirect: RedirectMode,
  pub credentials: Credentials,
  /// Redirect cap for `redirect: follow`: `Some(0)` = don't follow,
  /// `Some(n)` = follow up to `n`, `None` = the engine default (20).
  pub max_redirects: Option<u32>,
  /// Retry the request on a connection reset up to this many times.
  pub max_retries: u32,
  pub timeout: Duration,
  /// Resolved TLS posture for this request.
  pub ignore_https_errors: bool,
  /// Sandbox network policy, enforced on the initial URL, every redirect
  /// hop, and every resolved address when active.
  pub net_guard: Option<NetGuard>,
  /// What answers a Basic challenge, hop by hop.
  pub challenge: Option<ChallengeAnswer>,
}

/// The engine's response: metadata plus a single-use body.
#[derive(Debug)]
pub struct Response {
  pub status: u16,
  pub status_text: String,
  /// Final URL after any followed redirects.
  pub url: String,
  pub headers: Headers,
  pub body: Body,
  /// Whether at least one redirect hop was followed.
  pub redirected: bool,
  /// Whether a 3xx was returned unfollowed because `redirect: manual`.
  pub unfollowed_redirect: bool,
  pub server_addr: Option<RemoteAddr>,
  pub type_: ResponseType,
  /// Phase timings of the hop that produced this response.
  pub timing: Timing,
  /// The server's leaf certificate, DER-encoded, on a TLS connection.
  pub peer_certificate: Option<Vec<u8>>,
}

impl Response {
  #[must_use]
  pub fn ok(&self) -> bool {
    (200..300).contains(&self.status)
  }
}
