//! Sandbox network guard (SSRF defense).
//!
//! The permission model decides which hosts a script may name; this
//! guard makes that decision hold on the wire. It is enforced inside
//! the send engine so a JS `fetch`, a host's own HTTP client and every
//! narrowed handler share one implementation:
//!
//!  * the effective `net` grant — checked on the initial URL AND on
//!    every redirect target, so an allowed host cannot 302 a restricted
//!    caller into an internal address;
//!  * a DNS filter that drops cloud-metadata / (optionally) private
//!    resolved addresses, which also defeats DNS rebinding (a public
//!    hostname that resolves to 169.254.169.254);
//!  * scheme pinning (http/https only).
//!
//! The recommended sandbox posture blocks the cloud-metadata endpoints
//! for every request (no legitimate script targets them) while
//! loopback/private stays reachable so local servers keep working
//! unless the host opts in to blocking them.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use ferrijs_permissions::{Container, Denied, Permissions, is_metadata_ip, is_private_ip};

/// Boxed error for the custom DNS resolver (`reqwest::dns::Resolving`
/// resolves to `Result<Addrs, BoxError>`).
type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Who decides whether a host may be reached. A bare [`Permissions`]
/// answers from its `net` grant; a [`Container`] answers from whatever
/// is in force and runs its hook and audit too.
pub trait NetPolicy: Send + Sync + std::fmt::Debug {
  /// # Errors
  ///
  /// [`Denied`] naming `host:port`.
  fn check(&self, host: &str, port: Option<u16>) -> Result<(), Denied>;
}

impl NetPolicy for Permissions {
  fn check(&self, host: &str, port: Option<u16>) -> Result<(), Denied> {
    self.check_net(host, port)
  }
}

impl NetPolicy for Container {
  fn check(&self, host: &str, port: Option<u16>) -> Result<(), Denied> {
    self.check_net(host, port)
  }
}

/// Why a URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
  /// Not http or https, or no host, or unparsable.
  Invalid(String),
  /// A literal or resolved address in a blocked range.
  Blocked(String),
  /// The policy refused the host.
  Denied(Denied),
}

impl std::fmt::Display for GuardError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Invalid(m) | Self::Blocked(m) => f.write_str(m),
      Self::Denied(d) => d.fmt(f),
    }
  }
}

impl std::error::Error for GuardError {}

/// Per-request network policy. `Default` (no policy, all-false) is
/// inert — a caller that sets nothing keeps the cached-client fast path.
#[derive(Debug, Clone, Default)]
pub struct NetGuard {
  /// The `net` grant in force. `None` ⇒ any host; `Some` ⇒ its check
  /// must pass for the initial URL and every redirect hop.
  pub policy: Option<Arc<dyn NetPolicy>>,
  /// Block the cloud instance-metadata endpoints (169.254.169.254 /
  /// `fd00:ec2::254`) at both the URL and the resolved-address layer.
  pub block_metadata: bool,
  /// Also block loopback / RFC1918 / link-local / ULA / CGNAT. Off by
  /// default so local servers on `127.0.0.1` still work; a host opts in.
  pub block_private: bool,
}

impl NetGuard {
  /// Whether this guard changes behaviour at all. When `false` the
  /// caller uses the unguarded cached-client path (zero overhead).
  #[must_use]
  pub fn is_active(&self) -> bool {
    self.policy.is_some() || self.block_metadata || self.block_private
  }

  /// The address-family filter this guard needs at the DNS layer, or
  /// `None` when no address filtering applies (host policy only).
  #[must_use]
  pub(crate) fn dns_filter(&self) -> Option<(bool, bool)> {
    (self.block_metadata || self.block_private).then_some((self.block_metadata, self.block_private))
  }
}

/// `true` if the address must not be connected to under this guard.
fn ip_blocked(ip: IpAddr, block_metadata: bool, block_private: bool) -> bool {
  (block_metadata && is_metadata_ip(ip)) || (block_private && is_private_ip(ip))
}

/// Validate one concrete URL (initial or a redirect target) against the
/// guard: scheme must be http/https, a literal-IP host is range-checked,
/// and the host must satisfy the policy.
///
/// # Errors
///
/// [`GuardError`] with the reason.
pub fn check_url(url: &reqwest::Url, g: &NetGuard) -> Result<(), GuardError> {
  let scheme = url.scheme();
  if scheme != "http" && scheme != "https" {
    return Err(GuardError::Invalid(format!(
      "scheme \"{scheme}\" is not permitted by the sandbox network policy"
    )));
  }
  let host = url
    .host_str()
    .ok_or_else(|| GuardError::Invalid("request to a URL with no host is not permitted".to_string()))?;
  if let Ok(ip) = host.parse::<IpAddr>()
    && ip_blocked(ip, g.block_metadata, g.block_private)
  {
    return Err(GuardError::Blocked(format!(
      "request to blocked address {ip} (sandbox network policy)"
    )));
  }
  if let Some(policy) = &g.policy {
    policy
      .check(
        host.trim_start_matches('[').trim_end_matches(']'),
        url.port_or_known_default(),
      )
      .map_err(GuardError::Denied)?;
  }
  Ok(())
}

/// Pre-flight the initial (already base-resolved) request URL. A
/// parse failure under an active guard is a denial (fail closed).
///
/// # Errors
///
/// [`GuardError`] with the reason.
pub fn preflight(resolved_url: &str, g: &NetGuard) -> Result<(), GuardError> {
  match reqwest::Url::parse(resolved_url) {
    Ok(u) => check_url(&u, g),
    Err(_) => Err(GuardError::Invalid(format!(
      "request to invalid/relative URL \"{resolved_url}\" is not permitted by the sandbox network policy"
    ))),
  }
}

/// Custom reqwest DNS resolver that resolves the host normally, then
/// drops any address the guard forbids. Empty after filtering ⇒ the
/// connection is refused. This is what defeats DNS rebinding: a public
/// hostname resolving to a metadata/private address never connects.
pub(crate) struct GuardedResolver {
  pub block_metadata: bool,
  pub block_private: bool,
}

impl reqwest::dns::Resolve for GuardedResolver {
  fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
    let host = name.as_str().to_string();
    let (bm, bp) = (self.block_metadata, self.block_private);
    Box::pin(async move {
      let lookup = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<SocketAddr>> {
        Ok((host.as_str(), 0u16).to_socket_addrs()?.collect())
      })
      .await;
      let addrs = match lookup {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => return Err(Box::new(e) as BoxErr),
        Err(e) => return Err(Box::new(e) as BoxErr),
      };
      let kept: Vec<SocketAddr> = addrs.into_iter().filter(|sa| !ip_blocked(sa.ip(), bm, bp)).collect();
      if kept.is_empty() {
        return Err("all resolved addresses blocked by sandbox network policy".into());
      }
      Ok(Box::new(kept.into_iter()) as reqwest::dns::Addrs)
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn only(hosts: &[&str]) -> Arc<dyn NetPolicy> {
    Arc::new(Permissions::none().allow_net(hosts.iter().copied()).unwrap())
  }

  #[test]
  fn check_url_blocks_metadata_by_default_keeps_loopback() {
    let g = NetGuard {
      policy: None,
      block_metadata: true,
      block_private: false,
    };
    assert!(check_url(&reqwest::Url::parse("http://169.254.169.254/").unwrap(), &g).is_err());
    // Loopback stays reachable so local servers work.
    assert!(check_url(&reqwest::Url::parse("http://127.0.0.1:9/").unwrap(), &g).is_ok());
    // Non-http(s) scheme rejected.
    assert!(check_url(&reqwest::Url::parse("file:///etc/passwd").unwrap(), &g).is_err());
  }

  #[test]
  fn check_url_enforces_policy_on_any_url() {
    let g = NetGuard {
      policy: Some(only(&["allowed.com"])),
      block_metadata: true,
      block_private: false,
    };
    assert!(check_url(&reqwest::Url::parse("https://allowed.com/x").unwrap(), &g).is_ok());
    // This is the per-hop check that closes the redirect SSRF bypass:
    // the same function the manual redirect loop calls on every hop.
    assert!(matches!(
      check_url(&reqwest::Url::parse("https://evil.com/x").unwrap(), &g),
      Err(GuardError::Denied(_))
    ));
    // The userinfo trick does not spoof the host.
    assert!(check_url(&reqwest::Url::parse("https://allowed.com@evil.com/x").unwrap(), &g).is_err());
  }

  #[test]
  fn check_url_applies_the_scheme_default_port() {
    let g = NetGuard {
      policy: Some(only(&["allowed.com:443"])),
      ..Default::default()
    };
    assert!(check_url(&reqwest::Url::parse("https://allowed.com/").unwrap(), &g).is_ok());
    assert!(check_url(&reqwest::Url::parse("http://allowed.com/").unwrap(), &g).is_err());
    assert!(check_url(&reqwest::Url::parse("https://allowed.com:8443/").unwrap(), &g).is_err());
  }

  #[test]
  fn preflight_fails_closed_on_unparsable_url() {
    let g = NetGuard {
      policy: Some(only(&["allowed.com"])),
      block_metadata: true,
      block_private: false,
    };
    assert!(preflight("not a url", &g).is_err());
  }

  #[test]
  fn inert_guard_is_not_active() {
    assert!(!NetGuard::default().is_active());
    assert!(
      NetGuard {
        block_metadata: true,
        ..Default::default()
      }
      .is_active()
    );
  }
}
