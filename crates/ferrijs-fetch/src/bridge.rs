//! Two-way bridge between the engine and a host-owned cookie jar.
//!
//! The shape is Playwright's `BrowserContextAPIRequestContext`
//! (`server/fetch.ts:649`), which shares the browser context's cookie
//! jar in both directions: the outgoing `Cookie` header is assembled
//! from the host's cookies before every hop, and every hop's
//! `Set-Cookie` headers are written back through the host. reqwest's own
//! jar can't do that (the cookies live in the HOST, and each hop needs a
//! fresh read), so the bridged path follows redirects manually and
//! reads/writes cookies through this trait.

/// Boxed future used by [`ContextBridge`] (`async fn` in traits is not
/// dyn-compatible).
pub type BridgeFuture<'a, T> =
  std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, crate::FetchError>> + Send + 'a>>;

/// Live per-request defaults sourced from the owning context. Mirrors
/// the subset of Playwright's `_defaultOptions()` (fetch.ts:666) a
/// browser context carries.
#[derive(Debug, Clone, Default)]
pub struct ContextDefaults {
  pub base_url: Option<String>,
  pub extra_http_headers: Vec<(String, String)>,
  pub user_agent: Option<String>,
  pub ignore_https_errors: bool,
}

/// Two-way bridge between the engine and a host-owned context. Read
/// live on every request so option mutations and host-side cookie
/// changes are always visible, matching Playwright's live
/// `_defaultOptions()` read.
pub trait ContextBridge: Send + Sync {
  fn defaults(&self) -> BridgeFuture<'_, ContextDefaults>;
  fn cookies(&self) -> BridgeFuture<'_, Vec<crate::Cookie>>;
  fn add_cookies(&self, cookies: Vec<crate::Cookie>) -> BridgeFuture<'_, ()>;
}
