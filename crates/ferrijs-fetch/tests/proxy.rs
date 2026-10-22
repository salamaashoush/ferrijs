// The test helpers below fail a test by panicking, which the lint's
// in-test exemption does not reach outside a `#[test]` function.
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Requests leaving through an HTTP proxy and a SOCKS5 proxy, both of which
//! want credentials, to a host only the proxy can resolve.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrijs_fetch::{Body, ClientPool, Credentials, FetchError, Headers, Proxy, RedirectMode, Request, send};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The name the proxies resolve to loopback. It resolves nowhere else, so a
/// response proves the proxy, not this process, looked it up.
const HIDDEN_HOST: &str = "origin.invalid";

async fn read_head(socket: &mut TcpStream) -> Option<String> {
  let mut buffer = Vec::new();
  let mut byte = [0u8; 1];
  while !buffer.ends_with(b"\r\n\r\n") {
    if socket.read(&mut byte).await.ok()? == 0 {
      return None;
    }
    buffer.push(byte[0]);
  }
  Some(String::from_utf8_lossy(&buffer).into_owned())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
  head.lines().find_map(|line| {
    let (key, value) = line.split_once(": ")?;
    key.eq_ignore_ascii_case(name).then_some(value)
  })
}

/// Answers every request with the `Host` it was sent.
async fn origin() -> u16 {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();
  tokio::spawn(async move {
    while let Ok((mut socket, _)) = listener.accept().await {
      tokio::spawn(async move {
        let Some(head) = read_head(&mut socket).await else {
          return;
        };
        let body = format!("host={}", header(&head, "host").unwrap_or_default());
        let response = format!(
          "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
          body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
      });
    }
  });
  port
}

fn resolve(host: &str) -> &str {
  if host == HIDDEN_HOST { "127.0.0.1" } else { host }
}

/// An HTTP proxy wanting `Proxy-Authorization: Basic user:secret`, speaking
/// absolute-form requests. Records the targets it forwarded.
async fn http_proxy(seen: Arc<Mutex<Vec<String>>>) -> u16 {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();
  tokio::spawn(async move {
    while let Ok((mut socket, _)) = listener.accept().await {
      let seen = seen.clone();
      tokio::spawn(async move {
        let Some(head) = read_head(&mut socket).await else {
          return;
        };
        if header(&head, "proxy-authorization") != Some("Basic dXNlcjpzZWNyZXQ=") {
          let _ = socket
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
          return;
        }
        let target = head.split_whitespace().nth(1).unwrap_or_default().to_string();
        seen.lock().unwrap().push(target.clone());
        let url = reqwest::Url::parse(&target).unwrap();
        let address = format!("{}:{}", resolve(url.host_str().unwrap()), url.port().unwrap());
        let mut upstream = TcpStream::connect(address).await.unwrap();
        let request_line = head.lines().next().unwrap().replace(&target, url.path());
        let rest = head.split_once("\r\n").unwrap().1;
        upstream
          .write_all(format!("{request_line}\r\n{rest}").as_bytes())
          .await
          .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
      });
    }
  });
  port
}

/// A SOCKS5 proxy accepting only username/password `user`/`secret`.
/// Records the host names it was asked to connect to.
async fn socks5_proxy(seen: Arc<Mutex<Vec<String>>>) -> u16 {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();
  tokio::spawn(async move {
    while let Ok((mut socket, _)) = listener.accept().await {
      let seen = seen.clone();
      tokio::spawn(async move {
        let mut greeting = [0u8; 2];
        socket.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0u8; usize::from(greeting[1])];
        socket.read_exact(&mut methods).await.unwrap();
        if !methods.contains(&0x02) {
          let _ = socket.write_all(&[0x05, 0xff]).await;
          return;
        }
        socket.write_all(&[0x05, 0x02]).await.unwrap();
        let mut version_and_length = [0u8; 2];
        socket.read_exact(&mut version_and_length).await.unwrap();
        let mut username = vec![0u8; usize::from(version_and_length[1])];
        socket.read_exact(&mut username).await.unwrap();
        let mut password_length = [0u8; 1];
        socket.read_exact(&mut password_length).await.unwrap();
        let mut password = vec![0u8; usize::from(password_length[0])];
        socket.read_exact(&mut password).await.unwrap();
        if username != b"user" || password != b"secret" {
          let _ = socket.write_all(&[0x01, 0x01]).await;
          return;
        }
        socket.write_all(&[0x01, 0x00]).await.unwrap();
        let mut request = [0u8; 4];
        socket.read_exact(&mut request).await.unwrap();
        let host = match request[3] {
          0x03 => {
            let mut length = [0u8; 1];
            socket.read_exact(&mut length).await.unwrap();
            let mut name = vec![0u8; usize::from(length[0])];
            socket.read_exact(&mut name).await.unwrap();
            String::from_utf8(name).unwrap()
          },
          0x01 => {
            let mut octets = [0u8; 4];
            socket.read_exact(&mut octets).await.unwrap();
            std::net::Ipv4Addr::from(octets).to_string()
          },
          _ => return,
        };
        let mut port = [0u8; 2];
        socket.read_exact(&mut port).await.unwrap();
        seen.lock().unwrap().push(host.clone());
        let mut upstream = TcpStream::connect((resolve(&host), u16::from_be_bytes(port)))
          .await
          .unwrap();
        socket
          .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
          .await
          .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
      });
    }
  });
  port
}

fn request(url: &str) -> Request {
  Request {
    method: reqwest::Method::GET,
    url: reqwest::Url::parse(url).unwrap(),
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

fn proxy(server: String, password: &str) -> Proxy {
  Proxy {
    server,
    bypass: None,
    username: Some("user".into()),
    password: Some(password.into()),
  }
}

async fn body_of(pool: &ClientPool, url: &str) -> Result<(u16, String), FetchError> {
  let response = send(pool, None, request(url)).await?;
  let status = response.status;
  let body = response.body.collect().await?;
  Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
async fn an_http_proxy_is_sent_its_credentials_and_resolves_the_target() {
  let origin = origin().await;
  let seen = Arc::new(Mutex::new(Vec::new()));
  let proxy_port = http_proxy(seen.clone()).await;
  let pool = ClientPool::standalone(false).with_proxy(Some(proxy(format!("127.0.0.1:{proxy_port}"), "secret")));

  let (status, body) = body_of(&pool, &format!("http://{HIDDEN_HOST}:{origin}/page"))
    .await
    .unwrap();

  assert_eq!(status, 200);
  assert_eq!(body, format!("host={HIDDEN_HOST}:{origin}"));
  assert_eq!(*seen.lock().unwrap(), [format!("http://{HIDDEN_HOST}:{origin}/page")]);
}

#[tokio::test]
async fn an_http_proxy_refusing_the_credentials_is_the_response() {
  let origin = origin().await;
  let proxy_port = http_proxy(Arc::default()).await;
  let pool = ClientPool::standalone(false).with_proxy(Some(proxy(format!("http://127.0.0.1:{proxy_port}"), "wrong")));

  let (status, _) = body_of(&pool, &format!("http://{HIDDEN_HOST}:{origin}/"))
    .await
    .unwrap();

  assert_eq!(status, 407);
}

#[tokio::test]
async fn socks5_authenticates_and_hands_the_name_to_the_proxy() {
  let origin = origin().await;
  for scheme in ["socks5", "socks5h"] {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let proxy_port = socks5_proxy(seen.clone()).await;
    let pool =
      ClientPool::standalone(false).with_proxy(Some(proxy(format!("{scheme}://127.0.0.1:{proxy_port}"), "secret")));

    let (status, body) = body_of(&pool, &format!("http://{HIDDEN_HOST}:{origin}/"))
      .await
      .unwrap();

    assert_eq!(
      (status, body),
      (200, format!("host={HIDDEN_HOST}:{origin}")),
      "{scheme}"
    );
    assert_eq!(*seen.lock().unwrap(), [HIDDEN_HOST], "{scheme}");
  }
}

#[tokio::test]
async fn socks5_refusing_the_credentials_fails_the_request() {
  let origin = origin().await;
  let proxy_port = socks5_proxy(Arc::default()).await;
  let pool = ClientPool::standalone(false).with_proxy(Some(proxy(format!("socks5://127.0.0.1:{proxy_port}"), "wrong")));

  let failed = body_of(&pool, &format!("http://{HIDDEN_HOST}:{origin}/")).await;

  assert!(matches!(failed, Err(FetchError::Network(_))), "{failed:?}");
}

#[tokio::test]
async fn a_bypassed_host_is_reached_directly() {
  let origin = origin().await;
  let seen = Arc::new(Mutex::new(Vec::new()));
  let proxy_port = http_proxy(seen.clone()).await;
  let pool = ClientPool::standalone(false).with_proxy(Some(Proxy {
    bypass: Some("localhost, 127.0.0.1".into()),
    ..proxy(format!("127.0.0.1:{proxy_port}"), "secret")
  }));

  let (status, body) = body_of(&pool, &format!("http://127.0.0.1:{origin}/")).await.unwrap();

  assert_eq!((status, body), (200, format!("host=127.0.0.1:{origin}")));
  assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn settings_that_name_no_proxy_fail_the_request() {
  let pool = ClientPool::standalone(false).with_proxy(Some(Proxy {
    server: "ftp://127.0.0.1:21".into(),
    ..Proxy::default()
  }));

  let failed = body_of(&pool, "http://127.0.0.1:9/").await;

  assert!(matches!(failed, Err(FetchError::InvalidUrl(_))), "{failed:?}");
}
