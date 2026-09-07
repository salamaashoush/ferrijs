#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The `net` grant is what `fetch` answers to: the realm's container on
//! every hop, composed with whatever the backend adds, refusing with the
//! permission error rather than a network one.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use ferrijs::fetch::{Client, FetchBackend, FetchFuture, FetchRequest};
use ferrijs::{Permissions, RunOptions, Runtime};
use ferrijs_fetch::NetPolicy;

/// Replies 200 to anything; a redirect target when the path says so.
fn spawn_server() -> (String, std::thread::JoinHandle<()>) {
  let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
  let addr = listener.local_addr().expect("addr");
  let url = format!("http://{addr}");
  let h = std::thread::spawn(move || {
    for stream in listener.incoming().take(8) {
      let Ok(mut s) = stream else { break };
      let mut buf = [0u8; 4096];
      let n = s.read(&mut buf).unwrap_or(0);
      let req = String::from_utf8_lossy(&buf[..n]);
      let path = req
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
      let resp = if path == "/redirect-out" {
        "HTTP/1.1 302 Found\r\nLocation: http://evil.invalid/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          .to_string()
      } else {
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
      };
      let _ = s.write_all(resp.as_bytes());
    }
  });
  (url, h)
}

const SCRIPT: &str = r"
  try {
    const r = await fetch(args[0]);
    return { ok: r.status, body: await r.text() };
  } catch (e) {
    return { name: e.name, code: e.code, permission: e.permission, resource: e.resource, message: e.message };
  }
";

fn ok(run: &ferrijs::Run<serde_json::Value>) -> &serde_json::Value {
  run.result.as_ref().expect("run")
}

#[tokio::test(flavor = "multi_thread")]
async fn no_net_grant_means_fetch_is_refused_before_any_io() {
  let (url, _h) = spawn_server();
  let rt = Runtime::builder().build().await.expect("runtime");
  let run = rt
    .eval_script(SCRIPT, &[url.clone().into()], RunOptions::default())
    .await;
  let value = ok(&run);
  assert_eq!(value["name"], "PermissionDeniedError");
  assert_eq!(value["code"], "ERR_ACCESS_DENIED");
  assert_eq!(value["permission"], "net");
  let port = url.rsplit(':').next().unwrap();
  assert_eq!(value["resource"], format!("127.0.0.1:{port}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_grant_covers_its_host_and_every_redirect_hop() {
  let (url, _h) = spawn_server();
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_net(["127.0.0.1"]).unwrap())
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(SCRIPT, &[url.clone().into()], RunOptions::default())
    .await;
  assert_eq!(ok(&run), &serde_json::json!({ "ok": 200, "body": "ok" }));
  // The first hop is granted; the redirect target is not.
  let hop = rt
    .eval_script(SCRIPT, &[format!("{url}/redirect-out").into()], RunOptions::default())
    .await;
  let value = ok(&hop);
  assert_eq!(value["name"], "PermissionDeniedError", "{value}");
  assert_eq!(value["resource"], "evil.invalid:80");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_grant_binds_the_next_fetch() {
  let (url, _h) = spawn_server();
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_all_net())
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      &format!("const first = await fetch(args[0]); process.permission.drop('net'); {SCRIPT}"),
      &[url.into()],
      RunOptions::default(),
    )
    .await;
  assert_eq!(ok(&run)["name"], "PermissionDeniedError");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cloud_metadata_endpoint_is_blocked_whatever_the_grant() {
  let rt = Runtime::builder()
    .permissions(Permissions::all())
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script(
      SCRIPT,
      &["http://169.254.169.254/latest/meta-data/".into()],
      RunOptions::default(),
    )
    .await;
  let value = ok(&run);
  assert_eq!(value["name"], "TypeError", "{value}");
  assert!(
    value["message"].as_str().unwrap().contains("blocked address"),
    "{value}"
  );
}

/// A backend that refuses one host of its own on top of the realm's
/// policy: what a host with a per-request rule composes.
struct Composed {
  inner: Client,
  refused: String,
}

#[derive(Debug)]
struct Both {
  realm: Arc<dyn NetPolicy>,
  refused: String,
}

impl NetPolicy for Both {
  fn check(&self, host: &str, port: Option<u16>) -> Result<(), ferrijs::Denied> {
    self.realm.check(host, port)?;
    if host == self.refused {
      return Err(ferrijs::Denied::new(
        ferrijs::permissions::Kind::Net,
        format!("{host}:{}", port.unwrap_or(0)),
      ));
    }
    Ok(())
  }
}

impl FetchBackend for Composed {
  fn fetch(&self, request: FetchRequest) -> FetchFuture<'_> {
    self.inner.fetch(request)
  }

  fn net_policy(&self, _ctx: &rquickjs::Ctx<'_>, realm: Arc<dyn NetPolicy>) -> Arc<dyn NetPolicy> {
    Arc::new(Both {
      realm,
      refused: self.refused.clone(),
    })
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_backend_composes_its_own_refusals_over_the_realms() {
  let (url, _h) = spawn_server();
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_all_net())
    .fetch(Arc::new(Composed {
      inner: Client::new(),
      refused: "127.0.0.1".to_string(),
    }))
    .build()
    .await
    .expect("runtime");
  let run = rt.eval_script(SCRIPT, &[url.into()], RunOptions::default()).await;
  assert_eq!(ok(&run)["name"], "PermissionDeniedError");
}

#[tokio::test]
async fn a_realm_can_have_no_fetch_at_all() {
  let rt = Runtime::builder()
    .permissions(Permissions::all())
    .without_fetch()
    .build()
    .await
    .expect("runtime");
  let run = rt
    .eval_script("return [typeof fetch, typeof Headers]", &[], RunOptions::default())
    .await;
  assert_eq!(ok(&run), &serde_json::json!(["undefined", "undefined"]));
}
