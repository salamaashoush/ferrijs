//! What the `fetch` global sends through.
//!
//! The JS layer assembles a [`FetchRequest`] (the WHATWG "extract a
//! body" step already done, headers decided) and hands it to whichever
//! [`FetchBackend`] the realm was built with. The default is
//! [`Client`], a standalone client over the `ferrijs-fetch` engine with
//! its own cookie jar; a host with an HTTP stack of its own (one bound
//! to a browser context, say) implements the trait and installs that
//! instead, and the permission check, the SSRF guard and the abort
//! plumbing apply to it unchanged.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ferrijs_fetch::{Body, ClientPool, Credentials, FetchError, Headers, NetGuard, NetPolicy, RedirectMode, Response};

/// A request as the `fetch` global assembled it.
#[derive(Debug)]
pub struct FetchRequest {
  /// Absolute, or relative to the backend's base URL if it has one.
  pub url: String,
  pub method: String,
  /// Fully assembled request headers, applied over the backend's
  /// defaults.
  pub headers: Vec<(String, String)>,
  pub body: Body,
  pub redirect: RedirectMode,
  pub credentials: Credentials,
  /// The realm's `net` policy, snapshotted at call time, plus the
  /// address-range blocks. Enforced on the initial URL and every
  /// redirect hop.
  pub net_guard: Option<NetGuard>,
  /// `None` uses the backend default.
  pub timeout: Option<Duration>,
}

/// A future a backend answers with.
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Response, FetchError>> + Send + 'a>>;

/// Sends what the `fetch` global assembled.
pub trait FetchBackend: Send + Sync {
  fn fetch(&self, request: FetchRequest) -> FetchFuture<'_>;

  /// The policy a request is checked against, given the realm's own.
  /// Called synchronously inside the `fetch()` call, before any I/O.
  /// The default is the realm's policy as is; a host with a narrower
  /// policy of its own for some requests composes it here. It can only
  /// add refusals: the realm's container is always consulted.
  fn net_policy(&self, realm: Arc<dyn NetPolicy>) -> Arc<dyn NetPolicy> {
    realm
  }
}

/// The default backend: a standalone client with its own cookie jar,
/// optional base URL and default headers.
pub struct Client {
  pool: ClientPool,
  base_url: Option<String>,
  default_headers: Vec<(String, String)>,
  timeout: Duration,
}

impl std::fmt::Debug for Client {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Client")
      .field("base_url", &self.base_url)
      .field("default_headers", &self.default_headers)
      .field("timeout", &self.timeout)
      .finish_non_exhaustive()
  }
}

impl Default for Client {
  fn default() -> Self {
    Self::new()
  }
}

impl Client {
  #[must_use]
  pub fn new() -> Self {
    Self {
      pool: ClientPool::standalone(false),
      base_url: None,
      default_headers: Vec::new(),
      timeout: Duration::from_secs(30),
    }
  }

  /// Accept any TLS certificate. For a client pointed at a local
  /// server with a self-signed certificate; never for anything else.
  #[must_use]
  pub fn ignore_https_errors(mut self) -> Self {
    self.pool = ClientPool::standalone(true);
    self
  }

  /// Resolve a relative request URL against this.
  #[must_use]
  pub fn base_url(mut self, base: impl Into<String>) -> Self {
    self.base_url = Some(base.into());
    self
  }

  /// Headers every request starts from, before its own.
  #[must_use]
  pub fn default_headers(mut self, headers: Vec<(String, String)>) -> Self {
    self.default_headers = headers;
    self
  }

  /// The per-request timeout when a request names none.
  #[must_use]
  pub fn timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }
}

impl FetchBackend for Client {
  fn fetch(&self, request: FetchRequest) -> FetchFuture<'_> {
    Box::pin(async move {
      let url = match (&self.base_url, ferrijs_fetch::reqwest::Url::parse(&request.url)) {
        (_, Ok(url)) => url,
        (Some(base), Err(_)) => ferrijs_fetch::reqwest::Url::parse(base)
          .and_then(|b| b.join(&request.url))
          .map_err(|e| FetchError::InvalidUrl(format!("cannot resolve {}: {e}", request.url)))?,
        (None, Err(e)) => return Err(FetchError::InvalidUrl(format!("invalid URL {}: {e}", request.url))),
      };
      let method: ferrijs_fetch::reqwest::Method = request
        .method
        .parse()
        .map_err(|_| FetchError::InvalidUrl(format!("invalid HTTP method: {}", request.method)))?;
      let mut headers = Headers::new();
      for (name, value) in &self.default_headers {
        headers.set(name, value.clone());
      }
      for (name, value) in request.headers {
        headers.set(&name, value);
      }
      ferrijs_fetch::send(
        &self.pool,
        None,
        ferrijs_fetch::Request {
          method,
          url,
          headers,
          body: request.body,
          redirect: request.redirect,
          credentials: request.credentials,
          max_redirects: None,
          max_retries: 0,
          timeout: request.timeout.unwrap_or(self.timeout),
          ignore_https_errors: false,
          net_guard: request.net_guard,
        },
      )
      .await
    })
  }
}
