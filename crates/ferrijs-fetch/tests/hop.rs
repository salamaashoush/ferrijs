// The test helpers below fail a test by panicking, which the lint's
// in-test exemption does not reach outside a `#[test]` function.
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! What the engine learns and decides per hop, over a real socket: the
//! phase timings of the hop that produced the response, and a Basic
//! challenge answered with the credentials of the URL that raised it.

use std::time::Duration;

use ferrijs_fetch::{Body, ChallengeAnswer, ClientPool, Credentials, Headers, RedirectMode, Request, Response, send};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A server that keeps its connections open and answers by path:
/// - `/auth` wants `Authorization: Basic <host of the request>`,
/// - `/digest` challenges with a scheme the engine does not answer,
/// - `/to?<url>` redirects to `<url>`,
/// - anything else echoes the `Authorization` header it was sent.
async fn serve() -> u16 {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
  let port = listener.local_addr().expect("addr").port();
  tokio::spawn(async move {
    loop {
      let Ok((mut socket, _)) = listener.accept().await else {
        return;
      };
      tokio::spawn(async move {
        let mut buffer = Vec::new();
        loop {
          let mut chunk = [0u8; 4096];
          while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            match socket.read(&mut chunk).await {
              Ok(0) | Err(_) => return,
              Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
          }
          let end = buffer.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
          let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
          buffer.drain(..end);
          let header = |name: &str| {
            head
              .lines()
              .find_map(|line| {
                let (key, value) = line.split_once(": ")?;
                key.eq_ignore_ascii_case(name).then(|| value.to_string())
              })
              .unwrap_or_default()
          };
          let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
          let (path, query) = target.split_once('?').unwrap_or((&target, ""));
          let host = header("host");
          let authorization = header("authorization");
          let (status, extra, body) = match path {
            "/auth" if authorization == format!("Basic {}", host.split(':').next().unwrap_or("")) => {
              ("200 OK", String::new(), format!("in as {authorization}"))
            },
            "/auth" => (
              "401 Unauthorized",
              "WWW-Authenticate: Basic realm=\"test\"\r\n".to_string(),
              String::from("challenged"),
            ),
            "/digest" => (
              "401 Unauthorized",
              "WWW-Authenticate: Digest realm=\"test\"\r\n".to_string(),
              String::from("challenged"),
            ),
            "/to" => ("302 Found", format!("Location: {query}\r\n"), String::new()),
            _ => ("200 OK", String::new(), authorization),
          };
          let response = format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
          );
          if socket.write_all(response.as_bytes()).await.is_err() {
            return;
          }
        }
      });
    }
  });
  port
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

/// Answers with the host of the URL that challenged, which is what the
/// test server accepts: an answer meant for another origin is refused.
fn by_host() -> ChallengeAnswer {
  ChallengeAnswer::new(|url| Some(format!("Basic {}", url.host_str()?)))
}

async fn outcome(response: Response) -> (u16, String) {
  let status = response.status;
  let body = String::from_utf8(response.body.collect().await.expect("body").to_vec()).expect("utf8");
  (status, body)
}

#[tokio::test]
async fn a_new_connection_reports_its_lookup_and_connect() {
  let port = serve().await;
  let pool = ClientPool::standalone(false);
  let before = std::time::SystemTime::now();

  let named = send(&pool, None, request(&format!("http://localhost:{port}/")))
    .await
    .expect("send");
  let timing = named.timing;
  assert!(timing.start_time >= before);
  let (dns, connect) = (
    timing.dns_end.expect("a name is looked up"),
    timing.connect_end.expect("connected"),
  );
  assert!(dns <= connect, "{timing:?}");
  assert!(connect <= timing.response_start, "{timing:?}");
  assert_eq!(named.peer_certificate, None);
  drop(outcome(named).await);

  // An address literal is not looked up.
  let literal = send(&pool, None, request(&format!("http://127.0.0.1:{port}/")))
    .await
    .expect("send");
  assert_eq!(literal.timing.dns_end, None);
  assert!(literal.timing.connect_end.is_some());
  drop(outcome(literal).await);

  // The pool kept both connections: neither phase happens again.
  for host in ["localhost", "127.0.0.1"] {
    let reused = send(&pool, None, request(&format!("http://{host}:{port}/")))
      .await
      .expect("send");
    assert_eq!(
      (reused.timing.dns_end, reused.timing.connect_end),
      (None, None),
      "{host}"
    );
    assert!(reused.timing.response_start > Duration::ZERO);
    drop(outcome(reused).await);
  }
}

#[tokio::test]
async fn a_basic_challenge_is_answered_once_with_the_credentials_of_its_url() {
  let port = serve().await;
  let pool = ClientPool::standalone(false);

  // Unanswered, the challenge is the response.
  let response = send(&pool, None, request(&format!("http://127.0.0.1:{port}/auth")))
    .await
    .expect("send");
  assert_eq!(outcome(response).await, (401, "challenged".to_string()));

  let mut answered = request(&format!("http://127.0.0.1:{port}/auth"));
  answered.challenge = Some(by_host());
  let response = send(&pool, None, answered).await.expect("send");
  assert_eq!(outcome(response).await, (200, "in as Basic 127.0.0.1".to_string()));

  // A wrong answer is not tried twice.
  let mut wrong = request(&format!("http://127.0.0.1:{port}/auth"));
  wrong.challenge = Some(ChallengeAnswer::new(|_| Some("Basic nope".to_string())));
  let response = send(&pool, None, wrong).await.expect("send");
  assert_eq!(outcome(response).await, (401, "challenged".to_string()));
}

#[tokio::test]
async fn a_challenge_after_a_cross_origin_redirect_gets_that_origins_credentials() {
  let port = serve().await;
  let pool = ClientPool::standalone(false);

  let mut redirected = request(&format!("http://127.0.0.1:{port}/to?http://localhost:{port}/auth"));
  redirected.challenge = Some(by_host());
  let response = send(&pool, None, redirected).await.expect("send");
  assert_eq!(response.url, format!("http://localhost:{port}/auth"));
  assert_eq!(outcome(response).await, (200, "in as Basic localhost".to_string()));

  // The answer given to the first origin does not follow the redirect
  // to another one, and does follow one within its own.
  let mut first = request(&format!(
    "http://127.0.0.1:{port}/to?http://127.0.0.1:{port}/to?http://localhost:{port}/echo"
  ));
  first.headers.set("authorization", "Basic mine");
  let response = send(&pool, None, first).await.expect("send");
  assert_eq!(outcome(response).await, (200, String::new()));

  let mut same = request(&format!("http://127.0.0.1:{port}/to?http://127.0.0.1:{port}/echo"));
  same.headers.set("authorization", "Basic mine");
  let response = send(&pool, None, same).await.expect("send");
  assert_eq!(outcome(response).await, (200, "Basic mine".to_string()));
}

#[tokio::test]
async fn a_challenge_is_left_alone_when_the_caller_authorized_or_the_scheme_is_not_basic() {
  let port = serve().await;
  let pool = ClientPool::standalone(false);

  let mut explicit = request(&format!("http://127.0.0.1:{port}/auth"));
  explicit.headers.set("authorization", "Basic mine");
  explicit.challenge = Some(by_host());
  let response = send(&pool, None, explicit).await.expect("send");
  assert_eq!(outcome(response).await, (401, "challenged".to_string()));

  let mut digest = request(&format!("http://127.0.0.1:{port}/digest"));
  digest.challenge = Some(by_host());
  let response = send(&pool, None, digest).await.expect("send");
  assert_eq!(outcome(response).await, (401, "challenged".to_string()));
}
