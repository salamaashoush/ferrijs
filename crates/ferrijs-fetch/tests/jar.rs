// The test helpers below fail a test by panicking, which the lint's
// in-test exemption does not reach outside a `#[test]` function.
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The standalone pool's cookie jar, over a real socket: what a response
//! sets rides the next request, a redirect hop included, and a host can
//! read, fill and empty the jar.

use std::time::Duration;

use ferrijs_fetch::{Body, ClientPool, Cookie, Credentials, Headers, RedirectMode, Request, SameSite, send};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A server answering each request from its path:
/// - `/set` sets `sid=one` and `scoped=x; Path=/only`,
/// - `/hop` sets `hop=1` and redirects to `/echo`,
/// - `/drop` expires `sid`,
/// - anything else echoes the `Cookie` header it was sent.
async fn serve() -> String {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
  let origin = format!("http://{}", listener.local_addr().expect("addr"));
  tokio::spawn(async move {
    loop {
      let Ok((mut socket, _)) = listener.accept().await else {
        return;
      };
      tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        let mut read = 0;
        while !buffer[..read].windows(4).any(|w| w == b"\r\n\r\n") {
          match socket.read(&mut buffer[read..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => read += n,
          }
        }
        let head = String::from_utf8_lossy(&buffer[..read]).into_owned();
        let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
        let cookie = head
          .lines()
          .find_map(|line| line.strip_prefix("cookie: ").or_else(|| line.strip_prefix("Cookie: ")))
          .unwrap_or("")
          .to_string();
        let (status, extra, body) = match path.as_str() {
          "/set" => (
            "200 OK",
            "Set-Cookie: sid=one\r\nSet-Cookie: scoped=x; Path=/only\r\n".to_string(),
            String::new(),
          ),
          "/hop" => (
            "302 Found",
            "Set-Cookie: hop=1\r\nLocation: /echo\r\n".to_string(),
            String::new(),
          ),
          "/drop" => ("200 OK", "Set-Cookie: sid=; Max-Age=0\r\n".to_string(), String::new()),
          _ => ("200 OK", String::new(), cookie),
        };
        let response = format!(
          "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
          body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
      });
    }
  });
  origin
}

fn request(url: &str) -> Request {
  Request {
    method: reqwest::Method::GET,
    url: reqwest::Url::parse(url).expect("url"),
    headers: Headers::default(),
    body: Body::empty(),
    redirect: RedirectMode::Follow,
    credentials: Credentials::SameOrigin,
    max_redirects: None,
    max_retries: 0,
    timeout: Duration::from_secs(10),
    ignore_https_errors: false,
    net_guard: None,
    challenge: None,
  }
}

async fn text(pool: &ClientPool, request: Request) -> String {
  let response = send(pool, None, request).await.expect("send");
  String::from_utf8(response.body.collect().await.expect("body").to_vec()).expect("utf8")
}

fn stored(pool: &ClientPool) -> Vec<String> {
  let jar = pool.jar().expect("a standalone pool has a jar");
  jar
    .all()
    .into_iter()
    .map(|c| format!("{}={} {}{}", c.name, c.value, c.domain, c.path))
    .collect()
}

#[tokio::test]
async fn a_response_cookie_rides_the_next_request_where_it_applies() {
  let origin = serve().await;
  let pool = ClientPool::standalone(false);
  assert_eq!(text(&pool, request(&format!("{origin}/echo"))).await, "");
  text(&pool, request(&format!("{origin}/set"))).await;
  assert_eq!(stored(&pool), ["sid=one 127.0.0.1/", "scoped=x 127.0.0.1/only"]);
  assert_eq!(text(&pool, request(&format!("{origin}/echo"))).await, "sid=one");
  assert_eq!(
    text(&pool, request(&format!("{origin}/only/echo"))).await,
    "sid=one; scoped=x"
  );

  // An expired `Set-Cookie` deletes.
  text(&pool, request(&format!("{origin}/drop"))).await;
  assert_eq!(text(&pool, request(&format!("{origin}/echo"))).await, "");
}

#[tokio::test]
async fn a_cookie_set_on_a_redirect_reaches_its_target() {
  let origin = serve().await;
  let pool = ClientPool::standalone(false);
  assert_eq!(text(&pool, request(&format!("{origin}/hop"))).await, "hop=1");
}

#[tokio::test]
async fn omitted_credentials_neither_send_nor_store() {
  let origin = serve().await;
  let pool = ClientPool::standalone(false);
  text(&pool, request(&format!("{origin}/set"))).await;

  let mut omitted = request(&format!("{origin}/echo"));
  omitted.credentials = Credentials::Omit;
  assert_eq!(text(&pool, omitted).await, "");

  let mut omitted = request(&format!("{origin}/hop"));
  omitted.credentials = Credentials::Omit;
  assert_eq!(text(&pool, omitted).await, "");
  assert_eq!(stored(&pool), ["sid=one 127.0.0.1/", "scoped=x 127.0.0.1/only"]);
}

#[tokio::test]
async fn an_explicit_cookie_header_replaces_the_jar_for_the_first_hop_only() {
  let origin = serve().await;
  let pool = ClientPool::standalone(false);
  text(&pool, request(&format!("{origin}/set"))).await;

  let mut explicit = request(&format!("{origin}/echo"));
  explicit.headers.set("cookie", "mine=1");
  assert_eq!(text(&pool, explicit).await, "mine=1");

  let mut explicit = request(&format!("{origin}/hop"));
  explicit.headers.set("cookie", "mine=1");
  assert_eq!(text(&pool, explicit).await, "sid=one; hop=1");
}

#[tokio::test]
async fn a_host_reads_fills_and_empties_the_jar() {
  let origin = serve().await;
  let pool = ClientPool::standalone(false);
  let jar = pool.jar().expect("jar");
  jar.add([Cookie {
    name: "token".into(),
    value: "abc".into(),
    domain: "127.0.0.1".into(),
    path: "/".into(),
    secure: false,
    http_only: true,
    expires: None,
    same_site: Some(SameSite::Lax),
    url: None,
  }]);
  assert_eq!(text(&pool, request(&format!("{origin}/echo"))).await, "token=abc");
  jar.remove(|cookie| cookie.name == "token");
  assert_eq!(text(&pool, request(&format!("{origin}/echo"))).await, "");
  assert!(ClientPool::bridged().jar().is_none());
}
