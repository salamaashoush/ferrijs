//! The proxy a pool's requests leave through.
//!
//! The shape is Playwright's `ProxySettings` (`server`, `bypass`, `username`,
//! `password`), so a host can hand one value to a browser context and to the
//! client that shares its cookies.

use crate::error::FetchError;

/// A proxy every request of a [`crate::ClientPool`] goes through.
///
/// `server` is `scheme://host:port`, `http` when the scheme is left out.
/// `http`/`https` proxies are spoken to with `CONNECT` for `https` targets and
/// absolute-form requests for `http` ones, and answered with `username` and
/// `password` as `Proxy-Authorization: Basic`. `socks5` resolves names on the
/// proxy, as `socks5h` does and as browsers do for either spelling, so a target
/// only the proxy's network knows by name is still reachable; `socks5`
/// authenticates with the username/password method (RFC 1929). `socks4` has
/// no authentication and resolves names on the proxy (`socks4a`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proxy {
  pub server: String,
  /// Comma-separated hosts reached directly. Each entry matches the host
  /// itself and every subdomain of it (`example.com` and `.example.com` both
  /// cover `api.example.com`); a leading `*` is ignored.
  pub bypass: Option<String>,
  pub username: Option<String>,
  pub password: Option<String>,
}

impl Proxy {
  /// The proxy as the transport speaks to it.
  ///
  /// # Errors
  ///
  /// [`FetchError::InvalidUrl`] for a server that is not a URL, a scheme no
  /// proxy speaks, or credentials on a `socks4` proxy, which has no way to
  /// send them.
  pub fn to_transport(&self) -> Result<reqwest::Proxy, FetchError> {
    let url = self.url()?;
    let bypass = Bypass::parse(self.bypass.as_deref());
    let route = move |target: &reqwest::Url| (!bypass.covers(target)).then(|| url.clone());
    Ok(reqwest::Proxy::custom(route))
  }

  /// Check the settings without building anything, so a host can refuse them
  /// where they were given rather than on the first request.
  ///
  /// # Errors
  ///
  /// As [`Self::to_transport`].
  pub fn validate(&self) -> Result<(), FetchError> {
    self.url().map(drop)
  }

  fn url(&self) -> Result<reqwest::Url, FetchError> {
    let server = self.server.trim();
    let written = if server.contains("://") {
      server.to_string()
    } else {
      format!("http://{server}")
    };
    let mut url = reqwest::Url::parse(&written)
      .map_err(|e| FetchError::InvalidUrl(format!("invalid proxy server {server:?}: {e}")))?;
    if url.host_str().is_none_or(str::is_empty) {
      return Err(FetchError::InvalidUrl(format!("proxy server {server:?} names no host")));
    }
    let scheme = match url.scheme() {
      "http" | "https" | "socks5h" | "socks4a" => url.scheme().to_string(),
      "socks5" => "socks5h".to_string(),
      "socks4" => "socks4a".to_string(),
      other => {
        return Err(FetchError::InvalidUrl(format!(
          "proxy server {server:?} has scheme {other:?}; expected http, https, socks5 or socks4"
        )));
      },
    };
    let has_credentials = self.username.as_deref().is_some_and(|u| !u.is_empty());
    if has_credentials && scheme == "socks4a" {
      return Err(FetchError::InvalidUrl(
        "a socks4 proxy cannot authenticate; use socks5 for a proxy that needs credentials".into(),
      ));
    }
    // `set_scheme` refuses a change between a special scheme (http) and a
    // non-special one (socks5h), so the URL is rebuilt rather than edited.
    if url.scheme() != scheme {
      let rest = &written[written.find("://").map_or(0, |i| i + 3)..];
      url = reqwest::Url::parse(&format!("{scheme}://{rest}"))
        .map_err(|e| FetchError::InvalidUrl(format!("invalid proxy server {server:?}: {e}")))?;
    }
    if has_credentials {
      let username = self.username.as_deref().unwrap_or_default();
      let password = self.password.as_deref().unwrap_or_default();
      url
        .set_username(username)
        .and_then(|()| url.set_password(Some(password)))
        .map_err(|()| FetchError::InvalidUrl(format!("proxy server {server:?} cannot carry credentials")))?;
    }
    Ok(url)
  }
}

/// Playwright's `shouldBypassProxy` for the request client: a suffix match on
/// the host with a leading dot, so `example.com` covers `api.example.com` but
/// not `badexample.com`.
#[derive(Debug, Clone)]
struct Bypass(Vec<String>);

impl Bypass {
  fn parse(list: Option<&str>) -> Self {
    let entries = list
      .unwrap_or_default()
      .split(',')
      .map(|entry| normalized_host(entry.trim().trim_start_matches('*')))
      .filter(|entry| entry.len() > 1)
      .collect();
    Self(entries)
  }

  fn covers(&self, target: &reqwest::Url) -> bool {
    let Some(host) = target.host_str() else {
      return false;
    };
    let host = normalized_host(host);
    self.0.iter().any(|entry| host.ends_with(entry.as_str()))
  }
}

/// A host as a dot-led, lower-case suffix, IPv6 brackets removed, so `[::1]`
/// in a bypass list matches the `[::1]` a URL reports.
fn normalized_host(host: &str) -> String {
  let bare = host
    .trim_start_matches('.')
    .trim_start_matches('[')
    .trim_end_matches(']');
  format!(".{}", bare.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
  use super::{Bypass, Proxy};

  fn proxy(server: &str) -> Proxy {
    Proxy {
      server: server.into(),
      ..Proxy::default()
    }
  }

  #[test]
  fn a_server_without_a_scheme_is_an_http_proxy() {
    assert_eq!(
      proxy("127.0.0.1:3128").url().unwrap().as_str(),
      "http://127.0.0.1:3128/"
    );
  }

  #[test]
  fn socks5_resolves_names_on_the_proxy_whichever_way_it_is_spelled() {
    for server in ["socks5://127.0.0.1:1080", "socks5h://127.0.0.1:1080"] {
      assert_eq!(proxy(server).url().unwrap().scheme(), "socks5h", "{server}");
    }
    assert_eq!(proxy("socks4://127.0.0.1:1080").url().unwrap().scheme(), "socks4a");
  }

  #[test]
  fn credentials_travel_in_the_url_the_transport_reads_them_from() {
    let url = Proxy {
      username: Some("user@example.com".into()),
      password: Some("p:ss w/rd".into()),
      ..proxy("socks5://127.0.0.1:1080")
    }
    .url()
    .unwrap();
    assert_eq!(url.username(), "user%40example.com");
    assert_eq!(url.password(), Some("p%3Ass%20w%2Frd"));
  }

  #[test]
  fn socks4_cannot_carry_credentials() {
    let refused = Proxy {
      username: Some("user".into()),
      password: Some("secret".into()),
      ..proxy("socks4://127.0.0.1:1080")
    }
    .validate();
    assert!(refused.is_err());
  }

  #[test]
  fn an_unknown_scheme_or_a_missing_host_is_refused() {
    assert!(proxy("ftp://127.0.0.1:21").validate().is_err());
    assert!(proxy("http://").validate().is_err());
  }

  #[test]
  fn bypass_matches_a_host_and_its_subdomains_only() {
    let bypass = Bypass::parse(Some("example.com, .internal.test, *.wild.test, [::1]"));
    let covers = |url: &str| bypass.covers(&reqwest::Url::parse(url).unwrap());
    assert!(covers("https://example.com/"));
    assert!(covers("https://api.example.com/"));
    assert!(!covers("https://badexample.com/"));
    assert!(covers("http://a.internal.test/"));
    assert!(covers("http://x.wild.test/"));
    assert!(covers("http://[::1]:8080/"));
    assert!(!covers("http://127.0.0.1/"));
    assert!(!Bypass::parse(None).covers(&reqwest::Url::parse("http://example.com/").unwrap()));
  }
}
