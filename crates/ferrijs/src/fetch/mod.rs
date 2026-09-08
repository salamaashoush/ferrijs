//! A WHATWG `fetch` + `Headers` + `Request` + `Response`, so code that
//! expects `fetch` works. It is a thin surface over the `ferrijs-fetch`
//! engine, reached through a [`FetchBackend`] the host chooses — one
//! HTTP stack, one place the net policy applies.
//!
//! Web-standard names: `Headers`, `Request`, `Response` are the WHATWG
//! classes. `Headers` is spec (lowercase + RFC7230 validate, value
//! normalize, `, ` combine, separate `set-cookie` + `getSetCookie`,
//! sorted real iterators, `forEach`). `Response` / `Request` are
//! constructible with the spec accessors (`status`/`ok`/`redirected`/
//! `type`/`bodyUsed`/`headers`/...), single-use bodies
//! (`text`/`json`/`arrayBuffer`), `clone()`, and static
//! `Response.json`/`error`/`redirect`. `fetch(url, { signal })` is wired
//! to `AbortController`/`AbortSignal` (see [`abort`]): an already-aborted
//! signal rejects before I/O and an in-flight abort drops the request
//! future. `Response.body` is a WHATWG `ReadableStream` that pulls
//! chunks live off the socket (the body is NOT buffered) — the same
//! stream object on every access, drained by `text()`/`json()`/
//! `arrayBuffer()`, and pipeable through a `TransformStream` into a
//! `WritableStream`. `clone()` tees it, so both responses read the full
//! payload off one socket even when nothing has been buffered yet. See
//! [`streams`].
//!
//! Bodies: `fetch(url, { body })`, `new Request(input, { body })` and
//! `new Response(body)` all take the same `BodyInit` union, so all three
//! go through the one "extract a body" step in [`body_init`] — never
//! their own subset of the union. `Headers` is likewise a view over the
//! engine's [`ferrijs_fetch::Headers`] list, so the JS class and the
//! Rust client share one set of header semantics.
//!
//! Net policy: `fetch` hands the realm's container to the engine as the
//! request's [`NetGuard`], which checks the initial URL and every
//! redirect hop against it. The container only ever narrows, so a check
//! made later in the request is never looser than one made at the call.
//! A refusal is thrown as the `PermissionDeniedError` it is.

pub mod abort;
pub mod backend;
pub mod body_init;
pub mod multipart;
pub mod streams;

pub use backend::{Client, FetchBackend, FetchFuture, FetchRequest};
/// The engine underneath, for a host implementing its own backend.
pub use ferrijs_fetch as engine;

use std::sync::Arc;
use std::time::Duration;

use ferrijs_fetch::Headers as CoreHeaders;
use ferrijs_fetch::{Credentials, NetGuard, RedirectMode};
use ferrijs_std::abort::AbortSignal;
use ferrijs_std::stream_web::ReadableStream;
use rquickjs::atom::PredefinedAtom;
use rquickjs::function::{Opt, This};
use rquickjs::{Coerced, Ctx, IntoJs, Object, Value, class::Class, class::Trace};

use ferrijs_std::web::js_iterator::live_iterator;

use self::body_init::{BodySource, ExtractedBody, extract_body};
use crate::value::json_to_js;
use ferrijs_std::buffer::Blob;
use ferrijs_std::web::form_data::FormDataJs;

/// Hard cap on a single buffered `fetch` body (`text`/`json`/
/// `arrayBuffer`). QuickJS's `memory_limit` only bounds the JS heap;
/// the drained body is a Rust allocation, so without this a script
/// reading an unbounded/huge response could exhaust host memory well
/// past the JS quota. Streaming via `Response.body` is unaffected.
const MAX_FETCH_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Wall-clock bound on draining one streamed body, so a slow-loris /
/// never-ending response cannot pin a session forever (the per-script
/// interrupt-handler timeout does not fire during a native await).
const FETCH_BODY_DRAIN_TIMEOUT: Duration = Duration::from_mins(2);

/// WHATWG `Headers`, a view over the core [`ferrijs_fetch::Headers`]
/// list: names
/// are lowercased and RFC7230-validated, values are HTTP-whitespace
/// normalized and validated, `append` combines same-name values with
/// `, ` while `set-cookie` is kept as separate entries,
/// `getSetCookie()` returns them all, and iteration is sorted by name.
/// The list semantics live in core (`fetch::headers`) so this class and
/// the Rust HTTP client cannot drift; only the JS surface is here.
/// `keys`/`values`/`entries`/`[Symbol.iterator]` return real iterator
/// objects.
#[derive(Trace)]
#[rquickjs::class(rename = "Headers")]
pub struct HeadersJs {
  #[qjs(skip_trace)]
  list: CoreHeaders,
}

/// Project the sorted-by-name entry at `index` for the JS iterators.
/// The list is re-read per step, so a header appended mid-iteration is
/// observed — WHATWG iteration is over the live "sorted and combined"
/// view, not a snapshot.
fn header_entry<'js>(
  ctx: &Ctx<'js>,
  parent: &Class<'js, HeadersJs>,
  index: usize,
) -> rquickjs::Result<Option<Value<'js>>> {
  let Some((name, value)) = parent.borrow().list.sorted_entries().into_iter().nth(index) else {
    return Ok(None);
  };
  let pair = rquickjs::Array::new(ctx.clone())?;
  pair.set(0, name)?;
  pair.set(1, value)?;
  Ok(Some(pair.into_value()))
}

fn header_key<'js>(
  ctx: &Ctx<'js>,
  parent: &Class<'js, HeadersJs>,
  index: usize,
) -> rquickjs::Result<Option<Value<'js>>> {
  parent
    .borrow()
    .list
    .sorted_entries()
    .into_iter()
    .nth(index)
    .map(|(name, _)| name.into_js(ctx))
    .transpose()
}

fn header_val<'js>(
  ctx: &Ctx<'js>,
  parent: &Class<'js, HeadersJs>,
  index: usize,
) -> rquickjs::Result<Option<Value<'js>>> {
  parent
    .borrow()
    .list
    .sorted_entries()
    .into_iter()
    .nth(index)
    .map(|(_, value)| value.into_js(ctx))
    .transpose()
}

/// WHATWG `Response` (spec subset). Constructible (`new Response(body?,
/// init?)`), with `status`/`ok`/`statusText`/`url`/`redirected`/`type`/
/// `bodyUsed`/`headers` accessors, `text`/`json`/`arrayBuffer` body
/// readers (single-use: a second read throws, per spec), `clone()`
/// (throws once the body is used), and static `Response.json`,
/// `Response.error`, `Response.redirect`. This is the global `Response`
/// (the Playwright page-network `Response` is no longer a global — it is
/// only ever a return value, matching Playwright itself).
#[derive(Trace)]
#[rquickjs::class(rename = "Response")]
pub struct FetchResponseJs<'js> {
  #[qjs(skip_trace)]
  status: u16,
  #[qjs(skip_trace)]
  status_text: String,
  #[qjs(skip_trace)]
  url: String,
  #[qjs(skip_trace)]
  headers: CoreHeaders,
  #[qjs(skip_trace)]
  body: Vec<u8>,
  #[qjs(skip_trace)]
  redirected: bool,
  #[qjs(skip_trace)]
  type_: &'static str,
  #[qjs(skip_trace)]
  body_used: bool,
  /// `Some` for a `fetch()` result: the live, not-yet-buffered
  /// response. `text`/`json`/`arrayBuffer` drain it; `body` hands it to
  /// a `ReadableStream`. `None` for a constructed/`Response.json/error/
  /// redirect` (the bytes are in `body`).
  #[qjs(skip_trace)]
  net: Option<self::streams::NetBody>,
  /// The `Response.body` stream, created on first access (or by
  /// `clone()`, which tees it). Once present it is the authoritative
  /// body: `text()`/`json()`/`arrayBuffer()` drain it rather than the
  /// raw source, so a tee'd branch reads its own copy.
  body_stream: Option<Class<'js, ReadableStream<'js>>>,
}

/// WHATWG `Request` (spec subset). Constructible (`new Request(input,
/// init?)` where `input` is a URL string or another `Request`), with
/// `url`/`method`/`headers`/`redirect`/`credentials`/`bodyUsed`
/// accessors and `text`/`json`/`arrayBuffer`/`clone`. A `signal` passed
/// in `init` is carried (as the native abort channel) and forwarded by
/// `fetch(request)`; `fetch` reads `url`/`method`/`headers`/`body`/
/// `redirect`/`credentials`/`signal` off a `Request` argument.
#[derive(Trace)]
#[rquickjs::class(rename = "Request")]
pub struct FetchRequestJs<'js> {
  #[qjs(skip_trace)]
  url: String,
  #[qjs(skip_trace)]
  method: String,
  #[qjs(skip_trace)]
  headers: CoreHeaders,
  #[qjs(skip_trace)]
  body: Vec<u8>,
  #[qjs(skip_trace)]
  redirect: String,
  #[qjs(skip_trace)]
  credentials: String,
  #[qjs(skip_trace)]
  body_used: bool,
  /// Spec attributes the runtime does not act on but must round-trip:
  /// reading them back off a `Request` (or a `clone()`) has to return
  /// what the caller passed in `init`.
  #[qjs(skip_trace)]
  cache: String,
  #[qjs(skip_trace)]
  mode: String,
  #[qjs(skip_trace)]
  referrer: String,
  #[qjs(skip_trace)]
  referrer_policy: String,
  #[qjs(skip_trace)]
  integrity: String,
  #[qjs(skip_trace)]
  keepalive: bool,
  #[qjs(skip_trace)]
  destination: String,
  /// Spec: `duplex` must be `"half"` when the body is a stream. Stored
  /// so it round-trips off the `Request` and through `clone()`.
  #[qjs(skip_trace)]
  duplex: Option<String>,
  /// The native abort channel of a `signal` passed in `init`, kept so
  /// `fetch(request)` can drop the in-flight future on abort. Native
  /// (`Arc<AbortInner>`), never a captured JS value — GC-safe.
  #[qjs(skip_trace)]
  signal_inner: Option<Arc<self::abort::AbortInner>>,
  /// The `signal` exactly as handed to the constructor, so the `signal`
  /// getter returns the caller's own `AbortSignal` object rather than a
  /// fresh one built from the native channel.
  signal: Option<Class<'js, AbortSignal<'js>>>,
  /// The `Request.body` stream, created on first access. Once present it
  /// is the authoritative body and the body readers drain it, mirroring
  /// `Response.body`.
  body_stream: Option<Class<'js, ReadableStream<'js>>>,
}

// SAFETY: only owned `'static` data.
#[allow(unsafe_code)]
unsafe impl rquickjs::JsLifetime<'_> for HeadersJs {
  type Changed<'to> = HeadersJs;
}
#[allow(unsafe_code)]
unsafe impl<'js> rquickjs::JsLifetime<'js> for FetchResponseJs<'js> {
  type Changed<'to> = FetchResponseJs<'to>;
}
#[allow(unsafe_code)]
unsafe impl<'js> rquickjs::JsLifetime<'js> for FetchRequestJs<'js> {
  type Changed<'to> = FetchRequestJs<'to>;
}

/// Parse a `Response`/`Request` `init` bag's `headers` into raw pairs
/// and apply the body's implied `content-type`.
///
/// A `FormData` body's type carries the multipart boundary the bytes
/// were written with, so it REPLACES a caller-supplied `content-type`
/// (`forced`) — the same rule core applies to the Playwright `multipart`
/// option. Every other body type only fills an absent header.
fn init_headers(init: Option<&Object<'_>>, body: Option<&ExtractedBody<'_>>) -> CoreHeaders {
  let mut list = init
    .and_then(|o| o.get::<_, Value<'_>>("headers").ok())
    .map(|v| header_list_from(&v))
    .unwrap_or_default();
  apply_body_content_type(&mut list, body);
  list
}

/// Merge a body's implied `content-type` into an assembled header list.
fn apply_body_content_type(list: &mut CoreHeaders, body: Option<&ExtractedBody<'_>>) {
  let Some(body) = body else { return };
  let Some(ct) = &body.content_type else { return };
  if body.forced {
    list.set("content-type", ct.clone());
  } else {
    list.set_if_absent("content-type", ct.clone());
  }
}

/// Infallible best-effort extraction of `(name,value)` pairs from a JS
/// value for the outbound request `headers` — invalid entries are
/// skipped rather than thrown (the throwing path is the `Headers`
/// constructor).
fn header_list_from(v: &Value<'_>) -> CoreHeaders {
  let mut list = CoreHeaders::new();
  // Lenient mode cannot fail; the `Err` arm is unreachable.
  let _ = fill_header_list(None, &mut list, v);
  list
}

/// The ONE reader of a WHATWG `HeadersInit` — a `Headers` instance, a
/// `[[name, value], ...]` sequence, or a record. `ctx: Some` is the
/// spec's throwing mode (the `Headers` constructor, `fill`); `None` is
/// the lenient mode used when assembling an outgoing request, where a
/// malformed entry is dropped instead of failing the whole call.
fn fill_header_list(ctx: Option<&Ctx<'_>>, list: &mut CoreHeaders, v: &Value<'_>) -> rquickjs::Result<()> {
  if let Ok(other) = Class::<HeadersJs>::from_value(v) {
    for (name, value) in other.borrow().list.iter() {
      list.append_combined(name.clone(), value.clone());
    }
    return Ok(());
  }

  let mut push = |raw_name: &str, raw_value: &str| -> rquickjs::Result<()> {
    let valid_name = ferrijs_fetch::headers::is_valid_name(raw_name);
    let value = ferrijs_fetch::headers::normalize_value(raw_value);
    let valid_value = ferrijs_fetch::headers::is_valid_value(&value);
    match ctx {
      Some(ctx) if !valid_name => Err(rquickjs::Exception::throw_type(
        ctx,
        &format!("Invalid header name: {raw_name:?}"),
      )),
      Some(ctx) if !valid_value => Err(rquickjs::Exception::throw_type(ctx, "Invalid header value")),
      _ => {
        if valid_name && valid_value {
          list.append_combined(raw_name.to_ascii_lowercase(), value);
        }
        Ok(())
      },
    }
  };

  if let Some(arr) = v.as_array() {
    for i in 0..arr.len() {
      let Ok(entry) = arr.get::<Value<'_>>(i) else { continue };
      let pair = entry.as_array().filter(|p| p.len() == 2);
      let Some(pair) = pair else {
        match ctx {
          Some(ctx) => {
            return Err(rquickjs::Exception::throw_type(
              ctx,
              "Header init entry must be a [name, value] pair",
            ));
          },
          None => continue,
        }
      };
      match (pair.get::<Coerced<String>>(0), pair.get::<Coerced<String>>(1)) {
        (Ok(name), Ok(value)) => push(&name.0, &value.0)?,
        _ if ctx.is_none() => {},
        (name, value) => {
          name?;
          value?;
        },
      }
    }
    return Ok(());
  }

  if let Some(obj) = v.as_object() {
    let keys = obj.keys::<String>().collect::<rquickjs::Result<Vec<_>>>();
    let keys = match (keys, ctx) {
      (Ok(keys), _) => keys,
      (Err(e), Some(_)) => return Err(e),
      (Err(_), None) => return Ok(()),
    };
    for name in keys {
      match obj.get::<_, Coerced<String>>(name.as_str()) {
        Ok(value) => push(&name, &value.0)?,
        Err(_) if ctx.is_none() => {},
        Err(e) => return Err(e),
      }
    }
  }
  Ok(())
}

impl HeadersJs {
  /// Build from known server/response pairs (lowercase + normalize +
  /// spec-combine). Used by `FetchResponseJs::headers`.
  pub(crate) fn from_pairs<I: IntoIterator<Item = (String, String)>>(it: I) -> Self {
    let mut list = CoreHeaders::new();
    for (name, value) in it {
      list.append_combined(
        name.to_ascii_lowercase(),
        ferrijs_fetch::headers::normalize_value(&value),
      );
    }
    Self { list }
  }

  fn check_name(ctx: &Ctx<'_>, name: &str) -> rquickjs::Result<String> {
    if ferrijs_fetch::headers::is_valid_name(name) {
      Ok(name.to_ascii_lowercase())
    } else {
      Err(rquickjs::Exception::throw_type(
        ctx,
        &format!("Invalid header name: {name:?}"),
      ))
    }
  }

  fn check_value(ctx: &Ctx<'_>, raw: &str) -> rquickjs::Result<String> {
    let value = ferrijs_fetch::headers::normalize_value(raw);
    if ferrijs_fetch::headers::is_valid_value(&value) {
      Ok(value)
    } else {
      Err(rquickjs::Exception::throw_type(ctx, "Invalid header value"))
    }
  }
}

#[rquickjs::methods]
impl HeadersJs {
  /// Spec: every platform object carries `Symbol.toStringTag`, so
  /// `Object.prototype.toString.call(x)` reads `[object Headers]`.
  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Headers"
  }

  #[qjs(constructor)]
  pub fn new<'js>(ctx: Ctx<'js>, init: Opt<Value<'js>>) -> rquickjs::Result<Self> {
    let mut list = CoreHeaders::new();
    if let Some(v) = init.0 {
      if v.is_null() || v.is_number() {
        return Err(rquickjs::Exception::throw_type(
          &ctx,
          "Failed to construct 'Headers': invalid init",
        ));
      }
      if !v.is_undefined() {
        fill_header_list(Some(&ctx), &mut list, &v)?;
      }
    }
    Ok(Self { list })
  }

  #[qjs(rename = "append")]
  pub fn append(&mut self, ctx: Ctx<'_>, name: String, value: Coerced<String>) -> rquickjs::Result<()> {
    let name = Self::check_name(&ctx, &name)?;
    let value = Self::check_value(&ctx, &value.0)?;
    self.list.append_combined(name, value);
    Ok(())
  }

  #[qjs(rename = "set")]
  pub fn set(&mut self, ctx: Ctx<'_>, name: String, value: Coerced<String>) -> rquickjs::Result<()> {
    let name = Self::check_name(&ctx, &name)?;
    let value = Self::check_value(&ctx, &value.0)?;
    self.list.set(&name, value);
    Ok(())
  }

  #[qjs(rename = "get")]
  pub fn get<'js>(&self, ctx: Ctx<'js>, name: String) -> rquickjs::Result<Value<'js>> {
    let name = Self::check_name(&ctx, &name)?;
    match self.list.get_joined(&name) {
      Some(joined) => joined.into_js(&ctx),
      None => Ok(Value::new_null(ctx)),
    }
  }

  #[qjs(rename = "getSetCookie")]
  pub fn get_set_cookie(&self) -> Vec<String> {
    self
      .list
      .get_set_cookie()
      .into_iter()
      .map(ToString::to_string)
      .collect()
  }

  #[qjs(rename = "has")]
  pub fn has(&self, ctx: Ctx<'_>, name: String) -> rquickjs::Result<bool> {
    let name = Self::check_name(&ctx, &name)?;
    Ok(self.list.contains(&name))
  }

  #[qjs(rename = "delete")]
  pub fn delete(&mut self, ctx: Ctx<'_>, name: String) -> rquickjs::Result<()> {
    let name = Self::check_name(&ctx, &name)?;
    self.list.remove(&name);
    Ok(())
  }

  #[qjs(rename = "entries")]
  pub fn entries<'js>(ctx: Ctx<'js>, this: This<Class<'js, Self>>) -> rquickjs::Result<Object<'js>> {
    live_iterator(&ctx, this.0, header_entry)
  }

  #[qjs(rename = "keys")]
  pub fn keys<'js>(ctx: Ctx<'js>, this: This<Class<'js, Self>>) -> rquickjs::Result<Object<'js>> {
    live_iterator(&ctx, this.0, header_key)
  }

  #[qjs(rename = "values")]
  pub fn values<'js>(ctx: Ctx<'js>, this: This<Class<'js, Self>>) -> rquickjs::Result<Object<'js>> {
    live_iterator(&ctx, this.0, header_val)
  }

  #[qjs(rename = PredefinedAtom::SymbolIterator)]
  pub fn js_iterator<'js>(ctx: Ctx<'js>, this: This<Class<'js, Self>>) -> rquickjs::Result<Object<'js>> {
    live_iterator(&ctx, this.0, header_entry)
  }

  #[qjs(rename = "forEach")]
  pub fn for_each(&self, cb: rquickjs::Function<'_>) -> rquickjs::Result<()> {
    for (name, value) in self.list.sorted_entries() {
      cb.call::<_, ()>((value, name))?;
    }
    Ok(())
  }
}

impl<'js> FetchResponseJs<'js> {
  /// The `Response` a `fetch()` resolves to: status/headers are known,
  /// the body streams from `stream` (not buffered).
  fn from_stream(
    status: u16,
    status_text: String,
    url: String,
    headers: Vec<(String, String)>,
    redirected: bool,
    type_: &'static str,
    stream: ferrijs_fetch::ByteStream,
  ) -> Self {
    Self {
      status,
      status_text,
      url,
      headers: CoreHeaders::from_pairs(headers),
      body: Vec::new(),
      redirected,
      type_,
      body_used: false,
      net: Some(Arc::new(tokio::sync::Mutex::new(Some(stream)))),
      body_stream: None,
    }
  }

  /// A WHATWG opaque-redirect filtered response (`redirect: manual` on a
  /// 3xx): type "opaqueredirect", status 0, empty headers, null body.
  fn opaque_redirect() -> Self {
    Self {
      status: 0,
      status_text: String::new(),
      url: String::new(),
      headers: CoreHeaders::new(),
      body: Vec::new(),
      redirected: false,
      type_: "opaqueredirect",
      body_used: false,
      net: None,
      body_stream: None,
    }
  }

  /// The `Response.body` stream, created on first access.
  ///
  /// A streamed `fetch` result shares the live response with the stream
  /// (so neither buffers it); anything else streams the in-memory bytes.
  fn ensure_body_stream(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Class<'js, ReadableStream<'js>>> {
    if let Some(s) = &self.body_stream {
      return Ok(s.clone());
    }
    let stream = match self.net.take() {
      Some(net) => self::streams::from_net(ctx, net)?,
      None => self::streams::from_bytes(ctx, std::mem::take(&mut self.body))?,
    };
    self.body_stream = Some(stream.clone());
    Ok(stream)
  }

  /// Read a `ReadableStream` to completion through its public JS reader,
  /// so a tee'd branch, a user-constructed stream and a live socket all
  /// drain the same way.
  async fn drain_stream(ctx: &Ctx<'js>, stream: Class<'js, ReadableStream<'js>>) -> rquickjs::Result<Vec<u8>> {
    let obj = stream
      .into_value()
      .into_object()
      .ok_or_else(|| rquickjs::Error::new_from_js_message("Response", "TypeError", "body is not a ReadableStream"))?;
    let reader: Object<'js> = obj.get::<_, rquickjs::Function<'js>>("getReader")?.call((This(obj),))?;
    let read: rquickjs::Function<'js> = reader.get("read")?;
    let mut out = Vec::new();
    loop {
      let step: rquickjs::Promise<'js> = read.call((This(reader.clone()),))?;
      let res: Object<'js> = step.into_future().await?;
      if res.get::<_, bool>("done").unwrap_or(false) {
        return Ok(out);
      }
      let chunk = chunk_bytes(&res.get::<_, Value<'js>>("value")?);
      if out.len() + chunk.len() > MAX_FETCH_BODY_BYTES {
        return Err(rquickjs::Exception::throw_type(
          ctx,
          &format!("response body exceeded {MAX_FETCH_BODY_BYTES} bytes"),
        ));
      }
      out.extend_from_slice(&chunk);
    }
  }

  /// WHATWG "consume body": a second read is a `TypeError`. Drains the
  /// body stream when one has been vended (`.body`, or a `clone()` tee),
  /// else the live response, else the in-memory bytes.
  async fn consume(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Vec<u8>> {
    if self.body_used {
      return Err(rquickjs::Exception::throw_type(ctx, "Body has already been consumed"));
    }
    if let Some(stream) = self.body_stream.clone() {
      if stream.borrow().is_readable_stream_locked() {
        return Err(rquickjs::Exception::throw_type(ctx, "Body is locked to a reader"));
      }
      self.body_used = true;
      return match tokio::time::timeout(FETCH_BODY_DRAIN_TIMEOUT, Self::drain_stream(ctx, stream)).await {
        Ok(r) => r,
        Err(_) => Err(rquickjs::Exception::throw_type(ctx, "response body read timed out")),
      };
    }
    self.body_used = true;
    if let Some(net) = &self.net {
      let mut guard = net.lock().await;
      let mut out = Vec::new();
      if let Some(body) = guard.as_mut() {
        use futures::StreamExt as _;
        let drained = tokio::time::timeout(FETCH_BODY_DRAIN_TIMEOUT, async {
          while let Some(chunk) = body.next().await.transpose().map_err(|e| e.to_string())? {
            if out.len() + chunk.len() > MAX_FETCH_BODY_BYTES {
              return Err(format!("response body exceeded {MAX_FETCH_BODY_BYTES} bytes"));
            }
            out.extend_from_slice(&chunk);
          }
          Ok::<(), String>(())
        })
        .await;
        // Free the socket regardless of outcome so a rejected read does
        // not leave the connection (and its buffers) pinned.
        *guard = None;
        match drained {
          Ok(Ok(())) => {},
          Ok(Err(msg)) => return Err(rquickjs::Exception::throw_type(ctx, &msg)),
          Err(_) => {
            return Err(rquickjs::Exception::throw_type(ctx, "response body read timed out"));
          },
        }
        return Ok(out);
      }
      *guard = None;
      return Ok(out);
    }
    Ok(std::mem::take(&mut self.body))
  }
}

impl<'js> BodyMixin<'js> for FetchResponseJs<'js> {
  async fn consume_body(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Vec<u8>> {
    self.consume(ctx).await
  }

  fn content_type(&self) -> Option<String> {
    self.headers.get_first("content-type").map(ToString::to_string)
  }
}

impl<'js> BodyMixin<'js> for FetchRequestJs<'js> {
  async fn consume_body(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Vec<u8>> {
    self.consume(ctx).await
  }

  fn content_type(&self) -> Option<String> {
    self.headers.get_first("content-type").map(ToString::to_string)
  }
}

/// The WHATWG `Body` mixin, shared verbatim by `Request` and
/// `Response` (spec: both objects expose the same readers over the same
/// "consume body" step). Implementors supply only how to take the bytes
/// and what content type describes them; every reader below is defined
/// once here.
///
/// `#[rquickjs::methods]` cannot see methods that come from a trait (or
/// a macro), so each class still registers six one-line delegators — but
/// no reader logic is duplicated.
pub(crate) trait BodyMixin<'js> {
  /// WHATWG "consume body": yields the bytes, marks the body used, and
  /// fails on a second read.
  fn consume_body(&mut self, ctx: &Ctx<'js>) -> impl Future<Output = rquickjs::Result<Vec<u8>>>;

  /// The `content-type` header value, which types the `Blob` from
  /// `blob()` and selects the `formData()` parser.
  fn content_type(&self) -> Option<String>;

  async fn mixin_text(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<String> {
    let b = self.consume_body(ctx).await?;
    Ok(String::from_utf8_lossy(&b).into_owned())
  }

  async fn mixin_json(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    let b = self.consume_body(ctx).await?;
    let v: serde_json::Value =
      serde_json::from_slice(&b).map_err(|e| rquickjs::Error::new_from_js_message("json", "Error", e.to_string()))?;
    json_to_js(ctx, &v)
  }

  async fn mixin_array_buffer(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    let b = self.consume_body(ctx).await?;
    rquickjs::ArrayBuffer::new(ctx.clone(), b).map(rquickjs::ArrayBuffer::into_value)
  }

  /// Spec: `bytes()` resolves with a `Uint8Array` (not an `ArrayBuffer`).
  async fn mixin_bytes(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    let b = self.consume_body(ctx).await?;
    Ok(rquickjs::TypedArray::new(ctx.clone(), b)?.into_value())
  }

  /// Spec: the blob's `type` is the body's content type, or `""`.
  async fn mixin_blob(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    let mime = self.content_type().unwrap_or_default();
    let b = self.consume_body(ctx).await?;
    Ok(Class::instance(ctx.clone(), Blob::from_bytes(ctx, b, Some(mime))?)?.into_value())
  }

  /// Spec: parses `multipart/form-data` and
  /// `application/x-www-form-urlencoded`; any other type is a
  /// `TypeError`.
  async fn mixin_form_data(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    let content_type = self.content_type().unwrap_or_default();
    let boundary = ferrijs_fetch::multipart_boundary_of(&content_type);
    let urlencoded = content_type
      .split(';')
      .next()
      .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"));
    if boundary.is_none() && !urlencoded {
      return Err(rquickjs::Exception::throw_type(
        ctx,
        &format!("Could not parse content as FormData: unsupported content type {content_type:?}"),
      ));
    }

    let bytes = self.consume_body(ctx).await?;
    let form = match boundary {
      Some(boundary) => self::multipart::form_data_from_fields(&ferrijs_fetch::parse_multipart(&bytes, &boundary)),
      None => FormDataJs::from_urlencoded(&String::from_utf8_lossy(&bytes)),
    };
    Ok(Class::instance(ctx.clone(), form)?.into_value())
  }
}

/// Bytes behind a stream chunk (`Uint8Array`/`ArrayBuffer`/string).
// Reading a JS buffer's bytes is `unsafe` from rquickjs 0.13: the slice
// aliases engine memory and no JavaScript may run while it is alive.
// Every read here is copied out on the following line, so the borrow
// never spans a call back into script.
#[allow(unsafe_code)]
fn chunk_bytes(v: &Value<'_>) -> Vec<u8> {
  if let Some(s) = v.as_string().and_then(|s| s.to_string().ok()) {
    return s.into_bytes();
  }
  if let Ok(ta) = rquickjs::TypedArray::<u8>::from_value(v.clone()) {
    // SAFETY: copied out on the next line; nothing between runs JS.
    let b: &[u8] = unsafe { ta.as_bytes() }.unwrap_or_default();
    return b.to_vec();
  }
  if let Some(ab) = rquickjs::ArrayBuffer::from_value(v.clone())
    // SAFETY: copied out in the body below; nothing between runs JS.
    && let Some(b) = unsafe { ab.as_bytes() }
  {
    return b.to_vec();
  }
  Vec::new()
}

#[rquickjs::methods]
impl<'js> FetchResponseJs<'js> {
  /// Spec: every platform object carries `Symbol.toStringTag`, so
  /// `Object.prototype.toString.call(x)` reads `[object Response]`.
  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Response"
  }

  /// `new Response(body?, init?)` — `init`: `{ status?, statusText?,
  /// headers? }`. `status` outside 200..=599 is a `RangeError`.
  #[qjs(constructor)]
  pub fn new(ctx: Ctx<'js>, body: Opt<Value<'js>>, init: Opt<Object<'js>>) -> rquickjs::Result<Self> {
    let init = init.0;
    let status = match init.as_ref().and_then(|o| o.get::<_, i64>("status").ok()) {
      Some(s) if !(200..=599).contains(&s) => {
        return Err(rquickjs::Exception::throw_range(
          &ctx,
          "Failed to construct 'Response': status is outside the range [200, 599]",
        ));
      },
      Some(s) => s as u16,
      None => 200,
    };
    let status_text = init
      .as_ref()
      .and_then(|o| o.get::<_, String>("statusText").ok())
      .unwrap_or_default();
    // WHATWG: a null-body status (204/205/304) with a non-null body is
    // a `TypeError`.
    let has_body = body.0.as_ref().is_some_and(|v| !v.is_null() && !v.is_undefined());
    if has_body && matches!(status, 204 | 205 | 304) {
      return Err(rquickjs::Exception::throw_type(
        &ctx,
        "Failed to construct 'Response': Response with null body status cannot have body",
      ));
    }
    let extracted = match &body.0 {
      Some(v) => extract_body(&ctx, v)?,
      None => None,
    };
    let headers = init_headers(init.as_ref(), extracted.as_ref());
    // A `ReadableStream` body is kept as the body stream, not drained:
    // the spec only pulls it when a consumer asks.
    let (bytes, body_stream) = match extracted.map(|e| e.source) {
      Some(BodySource::Bytes(b)) => (b, None),
      Some(BodySource::Stream(s)) => (Vec::new(), Some(s)),
      None => (Vec::new(), None),
    };
    Ok(Self {
      status,
      status_text,
      url: String::new(),
      headers,
      body: bytes,
      redirected: false,
      type_: "default",
      body_used: false,
      net: None,
      body_stream,
    })
  }

  /// `Response.json(data, init?)` — JSON body + `application/json`.
  #[qjs(static, rename = "json")]
  pub fn json_static(ctx: Ctx<'js>, data: Value<'js>, init: Opt<Object<'js>>) -> rquickjs::Result<Self> {
    let init = init.0;
    let json: serde_json::Value = crate::value::serde_from_js(&ctx, data)?;
    let status = init
      .as_ref()
      .and_then(|o| o.get::<_, i64>("status").ok())
      .unwrap_or(200) as u16;
    let status_text = init
      .as_ref()
      .and_then(|o| o.get::<_, String>("statusText").ok())
      .unwrap_or_default();
    Ok(Self {
      status,
      status_text,
      url: String::new(),
      headers: init_headers(
        init.as_ref(),
        Some(&ExtractedBody {
          source: BodySource::Bytes(Vec::new()),
          content_type: Some("application/json".to_string()),
          forced: false,
        }),
      ),
      body: json.to_string().into_bytes(),
      redirected: false,
      type_: "default",
      body_used: false,
      net: None,
      body_stream: None,
    })
  }

  /// `Response.error()` — a network-error response (status 0).
  #[qjs(static, rename = "error")]
  pub fn error() -> Self {
    Self {
      status: 0,
      status_text: String::new(),
      url: String::new(),
      headers: CoreHeaders::new(),
      body: Vec::new(),
      redirected: false,
      type_: "error",
      body_used: false,
      net: None,
      body_stream: None,
    }
  }

  /// `Response.redirect(url, status=302)` — status must be a redirect
  /// code (301/302/303/307/308) or it is a `RangeError`.
  #[qjs(static, rename = "redirect")]
  pub fn redirect(ctx: Ctx<'_>, url: String, status: Opt<i64>) -> rquickjs::Result<Self> {
    let status = status.0.unwrap_or(302);
    if ![301, 302, 303, 307, 308].contains(&status) {
      return Err(rquickjs::Exception::throw_range(&ctx, "Invalid redirect status code"));
    }
    Ok(Self {
      status: status as u16,
      status_text: String::new(),
      url: String::new(),
      headers: CoreHeaders::from_pairs(vec![("location".to_string(), url)]),
      body: Vec::new(),
      redirected: false,
      type_: "default",
      body_used: false,
      net: None,
      body_stream: None,
    })
  }

  #[qjs(get, rename = "status")]
  pub fn status(&self) -> u16 {
    self.status
  }
  #[qjs(get, rename = "ok")]
  pub fn ok(&self) -> bool {
    (200..300).contains(&self.status)
  }
  #[qjs(get, rename = "statusText")]
  pub fn status_text(&self) -> String {
    self.status_text.clone()
  }
  #[qjs(get, rename = "url")]
  pub fn url(&self) -> String {
    self.url.clone()
  }
  #[qjs(get, rename = "redirected")]
  pub fn redirected(&self) -> bool {
    self.redirected
  }
  #[qjs(get, rename = "type")]
  pub fn type_(&self) -> String {
    self.type_.to_string()
  }
  #[qjs(get, rename = "bodyUsed")]
  pub fn body_used(&self) -> bool {
    self.body_used
  }

  #[qjs(get, rename = "headers")]
  pub fn headers(&self, ctx: Ctx<'js>) -> rquickjs::Result<Class<'js, HeadersJs>> {
    Class::instance(ctx, HeadersJs::from_pairs(self.headers.iter().cloned()))
  }

  /// `Response.body` — the body `ReadableStream`. For a streamed
  /// `fetch` result each pull takes the next chunk off the socket (the
  /// body is NOT buffered); for a constructed `Response` it streams the
  /// in-memory bytes. The same stream object is returned every time, and
  /// `text()`/`json()`/`arrayBuffer()` drain it.
  #[qjs(get, rename = "body")]
  pub fn body(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Class<'js, ReadableStream<'js>>> {
    self.ensure_body_stream(&ctx)
  }

  #[qjs(rename = "text")]
  pub async fn text(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<String> {
    self.mixin_text(&ctx).await
  }

  #[qjs(rename = "json")]
  pub async fn json(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_json(&ctx).await
  }

  #[qjs(rename = "arrayBuffer")]
  pub async fn array_buffer(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_array_buffer(&ctx).await
  }

  #[qjs(rename = "bytes")]
  pub async fn bytes(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_bytes(&ctx).await
  }

  #[qjs(rename = "blob")]
  pub async fn blob(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_blob(&ctx).await
  }

  #[qjs(rename = "formData")]
  pub async fn form_data(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_form_data(&ctx).await
  }

  /// `Response.clone()` — WHATWG "clone a response": the body stream is
  /// tee'd, so BOTH responses can be read independently, including an
  /// unread streamed `fetch` body (neither branch buffers ahead of its
  /// own consumer).
  #[qjs(rename = "clone")]
  pub fn clone_(this: This<Class<'js, Self>>, ctx: Ctx<'js>) -> rquickjs::Result<Self> {
    let (branch1, branch2) = {
      let mut me = this.borrow_mut();
      if me.body_used {
        return Err(rquickjs::Exception::throw_type(&ctx, "Cannot clone a used Response"));
      }
      let stream = me.ensure_body_stream(&ctx)?;
      drop(me);
      ferrijs_std::stream_web::tee_readable_stream(ctx.clone(), stream)?
    };
    let mut me = this.borrow_mut();
    me.body_stream = Some(branch1);
    Ok(Self {
      status: me.status,
      status_text: me.status_text.clone(),
      url: me.url.clone(),
      headers: me.headers.clone(),
      body: Vec::new(),
      redirected: me.redirected,
      type_: me.type_,
      body_used: false,
      net: None,
      body_stream: Some(branch2),
    })
  }
}

impl<'js> FetchRequestJs<'js> {
  /// The `Request.body` stream, created on first access — over the
  /// in-memory bytes, since a `Request` is never backed by a live
  /// socket.
  ///
  /// Unlike `Response`, the bytes are COPIED rather than moved into the
  /// stream: `fetch(request)` reads them straight off the `Request`, so
  /// moving them would make merely touching `.body` send an empty body.
  /// Single-use semantics are unaffected — `consume()` prefers the
  /// stream once one exists, and `fetch()` refuses a disturbed body.
  fn ensure_body_stream(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Class<'js, ReadableStream<'js>>> {
    if let Some(s) = &self.body_stream {
      return Ok(s.clone());
    }
    let stream = self::streams::from_bytes(ctx, self.body.clone())?;
    self.body_stream = Some(stream.clone());
    Ok(stream)
  }

  /// Whether the body has been read — consumed through a reader, or
  /// drained/locked through the `.body` stream. Spec: fetching a
  /// Request with a disturbed body is a `TypeError`.
  fn body_is_disturbed(&self) -> bool {
    if self.body_used {
      return true;
    }
    self.body_stream.as_ref().is_some_and(|s| {
      let s = s.borrow();
      s.disturbed || s.is_readable_stream_locked()
    })
  }

  /// WHATWG "consume body": a second read is a `TypeError`. Drains the
  /// body stream when one has been vended (`.body`), else the bytes.
  async fn consume(&mut self, ctx: &Ctx<'js>) -> rquickjs::Result<Vec<u8>> {
    if self.body_used {
      return Err(rquickjs::Exception::throw_type(ctx, "Body has already been consumed"));
    }
    if let Some(stream) = self.body_stream.clone() {
      if stream.borrow().is_readable_stream_locked() {
        return Err(rquickjs::Exception::throw_type(ctx, "Body is locked to a reader"));
      }
      self.body_used = true;
      return match tokio::time::timeout(FETCH_BODY_DRAIN_TIMEOUT, FetchResponseJs::drain_stream(ctx, stream)).await {
        Ok(r) => r,
        Err(_) => Err(rquickjs::Exception::throw_type(ctx, "request body read timed out")),
      };
    }
    self.body_used = true;
    Ok(std::mem::take(&mut self.body))
  }
}

#[rquickjs::methods]
impl<'js> FetchRequestJs<'js> {
  /// Spec: every platform object carries `Symbol.toStringTag`, so
  /// `Object.prototype.toString.call(x)` reads `[object Request]`.
  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Request"
  }

  /// `new Request(input, init?)` — `input` is a URL string or another
  /// `Request`; `init`: `{ method?, headers?, body?, redirect?,
  /// credentials?, signal?, cache?, mode?, referrer?, referrerPolicy?,
  /// integrity?, keepalive? }`.
  #[qjs(constructor)]
  pub fn new(ctx: Ctx<'js>, input: Value<'js>, init: Opt<Object<'js>>) -> rquickjs::Result<Self> {
    let init = init.0;
    let mut req = if let Ok(other) = Class::<FetchRequestJs<'js>>::from_value(&input) {
      let o = other.borrow();
      Self {
        url: o.url.clone(),
        method: o.method.clone(),
        headers: o.headers.clone(),
        body: o.body.clone(),
        redirect: o.redirect.clone(),
        credentials: o.credentials.clone(),
        body_used: false,
        cache: o.cache.clone(),
        mode: o.mode.clone(),
        referrer: o.referrer.clone(),
        referrer_policy: o.referrer_policy.clone(),
        integrity: o.integrity.clone(),
        keepalive: o.keepalive,
        destination: o.destination.clone(),
        duplex: o.duplex.clone(),
        signal_inner: o.signal_inner.clone(),
        signal: o.signal.clone(),
        body_stream: None,
      }
    } else {
      Self {
        url: input.as_string().and_then(|s| s.to_string().ok()).unwrap_or_default(),
        method: "GET".to_string(),
        headers: CoreHeaders::new(),
        body: Vec::new(),
        redirect: "follow".to_string(),
        credentials: "same-origin".to_string(),
        body_used: false,
        cache: "default".to_string(),
        mode: "cors".to_string(),
        referrer: "about:client".to_string(),
        referrer_policy: String::new(),
        integrity: String::new(),
        keepalive: false,
        // Spec: a Request built by script has an empty destination;
        // only the fetch a browser initiates for a specific consumer
        // (script/image/...) carries one.
        destination: String::new(),
        duplex: None,
        signal_inner: None,
        signal: None,
        body_stream: None,
      }
    };
    if let Some(o) = init.as_ref() {
      if let Ok(m) = o.get::<_, String>("method") {
        req.method = m.to_ascii_uppercase();
      }
      if let Ok(r) = o.get::<_, String>("redirect") {
        req.redirect = r;
      }
      if let Ok(c) = o.get::<_, String>("credentials") {
        req.credentials = c;
      }
      if let Ok(v) = o.get::<_, String>("cache") {
        req.cache = v;
      }
      if let Ok(v) = o.get::<_, String>("mode") {
        req.mode = v;
      }
      if let Ok(v) = o.get::<_, String>("referrer") {
        req.referrer = v;
      }
      if let Ok(v) = o.get::<_, String>("referrerPolicy") {
        req.referrer_policy = v;
      }
      if let Ok(v) = o.get::<_, String>("integrity") {
        req.integrity = v;
      }
      if let Ok(v) = o.get::<_, bool>("keepalive") {
        req.keepalive = v;
      }
      if let Ok(v) = o.get::<_, String>("duplex") {
        req.duplex = Some(v);
      }
      if let Ok(sig) = o.get::<_, Value<'js>>("signal")
        && let Ok(s) = Class::<AbortSignal<'js>>::from_value(&sig)
      {
        req.signal_inner = Some(self::abort::native_channel(&ctx, &s)?);
        req.signal = Some(s);
      }
      let extracted = match o.get::<_, Value<'_>>("body").ok() {
        Some(v) => extract_body(&ctx, &v)?,
        None => None,
      };
      // Spec: a GET/HEAD request cannot carry a body. Silently dropping
      // one hides the caller's mistake until the server sees a bodyless
      // request.
      if extracted.is_some() && matches!(req.method.as_str(), "GET" | "HEAD") {
        return Err(rquickjs::Exception::throw_type(
          &ctx,
          "Failed to construct 'Request': Request with GET/HEAD method cannot have body.",
        ));
      }
      match extracted.as_ref().map(|e| &e.source) {
        Some(BodySource::Bytes(bytes)) if !bytes.is_empty() => req.body.clone_from(bytes),
        // A stream body is kept unread; `Request.body` hands out this
        // very stream and the body readers drain it.
        Some(BodySource::Stream(stream)) => {
          req.body = Vec::new();
          req.body_stream = Some(stream.clone());
        },
        _ => {},
      }
      req.headers = {
        let mut h = init_headers(init.as_ref(), extracted.as_ref());
        if h.is_empty() {
          std::mem::take(&mut req.headers)
        } else {
          if let Ok(existing) = Class::<FetchRequestJs<'js>>::from_value(&input) {
            for (name, value) in existing.borrow().headers.iter() {
              h.set_if_absent(name, value.clone());
            }
          }
          h
        }
      };
    }
    Ok(req)
  }

  #[qjs(get, rename = "url")]
  pub fn url(&self) -> String {
    self.url.clone()
  }
  #[qjs(get, rename = "method")]
  pub fn method(&self) -> String {
    self.method.clone()
  }
  #[qjs(get, rename = "redirect")]
  pub fn redirect(&self) -> String {
    self.redirect.clone()
  }
  #[qjs(get, rename = "credentials")]
  pub fn credentials(&self) -> String {
    self.credentials.clone()
  }
  #[qjs(get, rename = "bodyUsed")]
  pub fn body_used(&self) -> bool {
    self.body_used
  }
  #[qjs(get, rename = "cache")]
  pub fn cache(&self) -> String {
    self.cache.clone()
  }
  #[qjs(get, rename = "mode")]
  pub fn mode(&self) -> String {
    self.mode.clone()
  }
  #[qjs(get, rename = "referrer")]
  pub fn referrer(&self) -> String {
    self.referrer.clone()
  }
  #[qjs(get, rename = "referrerPolicy")]
  pub fn referrer_policy(&self) -> String {
    self.referrer_policy.clone()
  }
  #[qjs(get, rename = "integrity")]
  pub fn integrity(&self) -> String {
    self.integrity.clone()
  }
  #[qjs(get, rename = "keepalive")]
  pub fn keepalive(&self) -> bool {
    self.keepalive
  }
  #[qjs(get, rename = "destination")]
  pub fn destination(&self) -> String {
    self.destination.clone()
  }

  /// Spec: `"half"` when a stream body was declared as such, else
  /// `undefined`.
  #[qjs(get, rename = "duplex")]
  pub fn duplex(&self) -> Option<String> {
    self.duplex.clone()
  }

  /// Spec: always `false` for a `Request` built by script — only a
  /// browser-initiated navigation sets these.
  #[qjs(get, rename = "isHistoryNavigation")]
  pub fn is_history_navigation(&self) -> bool {
    false
  }

  #[qjs(get, rename = "isReloadNavigation")]
  pub fn is_reload_navigation(&self) -> bool {
    false
  }
  #[qjs(get, rename = "headers")]
  pub fn headers(&self, ctx: Ctx<'js>) -> rquickjs::Result<Class<'js, HeadersJs>> {
    Class::instance(ctx, HeadersJs::from_pairs(self.headers.iter().cloned()))
  }

  /// `Request.signal` — the `AbortSignal` passed in `init`. Spec always
  /// exposes one, so a request built without a signal reports a fresh,
  /// never-aborted instance.
  #[qjs(get, rename = "signal")]
  pub fn signal(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Class<'js, AbortSignal<'js>>> {
    if let Some(s) = &self.signal {
      return Ok(s.clone());
    }
    let fresh = self::abort::fresh_instance(&ctx)?;
    self.signal = Some(fresh.clone());
    Ok(fresh)
  }

  /// `Request.body` — the body `ReadableStream`, same object on every
  /// access, drained by the body readers.
  #[qjs(get, rename = "body")]
  pub fn body(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Class<'js, ReadableStream<'js>>> {
    self.ensure_body_stream(&ctx)
  }

  #[qjs(rename = "text")]
  pub async fn text(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<String> {
    self.mixin_text(&ctx).await
  }

  #[qjs(rename = "json")]
  pub async fn json(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_json(&ctx).await
  }

  #[qjs(rename = "arrayBuffer")]
  pub async fn array_buffer(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_array_buffer(&ctx).await
  }

  #[qjs(rename = "bytes")]
  pub async fn bytes(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_bytes(&ctx).await
  }

  #[qjs(rename = "blob")]
  pub async fn blob(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_blob(&ctx).await
  }

  #[qjs(rename = "formData")]
  pub async fn form_data(&mut self, ctx: Ctx<'js>) -> rquickjs::Result<Value<'js>> {
    self.mixin_form_data(&ctx).await
  }

  /// WHATWG "clone a request". When a body stream has already been
  /// vended the bytes live in it, so the stream is tee'd exactly as
  /// `Response.clone()` does — otherwise the clone would come out with
  /// an empty body.
  #[qjs(rename = "clone")]
  pub fn clone_(this: This<Class<'js, Self>>, ctx: Ctx<'js>) -> rquickjs::Result<Self> {
    {
      let me = this.borrow();
      if me.body_used {
        return Err(rquickjs::Exception::throw_type(&ctx, "Cannot clone a used Request"));
      }
    }
    let branch2 = if this.borrow().body_stream.is_some() {
      let stream = this.borrow_mut().ensure_body_stream(&ctx)?;
      let (branch1, branch2) = ferrijs_std::stream_web::tee_readable_stream(ctx.clone(), stream)?;
      this.borrow_mut().body_stream = Some(branch1);
      Some(branch2)
    } else {
      None
    };
    let me = this.borrow();
    Ok(Self {
      url: me.url.clone(),
      method: me.method.clone(),
      headers: me.headers.clone(),
      body: me.body.clone(),
      redirect: me.redirect.clone(),
      credentials: me.credentials.clone(),
      body_used: false,
      cache: me.cache.clone(),
      mode: me.mode.clone(),
      referrer: me.referrer.clone(),
      referrer_policy: me.referrer_policy.clone(),
      integrity: me.integrity.clone(),
      keepalive: me.keepalive,
      destination: me.destination.clone(),
      duplex: me.duplex.clone(),
      signal_inner: me.signal_inner.clone(),
      signal: me.signal.clone(),
      body_stream: branch2,
    })
  }
}

/// Define the `Headers` / `Request` / `Response` classes on
/// `globalThis`. Idempotent per realm; [`install`] calls it.
///
/// # Errors
///
/// Propagates the class definitions.
pub fn define_classes<'js>(ctx: &Ctx<'js>) -> rquickjs::Result<()> {
  let g = ctx.globals();
  Class::<HeadersJs>::define(&g)?;
  Class::<FetchResponseJs<'js>>::define(&g)?;
  Class::<FetchRequestJs<'js>>::define(&g)?;
  Ok(())
}

/// Install `globalThis.fetch` over `backend`, with the classes it
/// speaks. A realm's `net` grant applies to every request it sends.
///
/// # Errors
///
/// Propagates the global writes.
pub fn install(ctx: &Ctx<'_>, backend: Arc<dyn FetchBackend>) -> rquickjs::Result<()> {
  define_classes(ctx)?;
  let f = function(ctx, backend)?;
  ctx.globals().set("fetch", f)?;
  Ok(())
}

/// A `fetch` function over `backend`, not installed anywhere: for a
/// host handing a caller an attenuated capability rather than the
/// global.
///
/// # Errors
///
/// Propagates the function creation.
pub fn function<'js>(ctx: &Ctx<'js>, backend: Arc<dyn FetchBackend>) -> rquickjs::Result<rquickjs::Function<'js>> {
  // Forward into a generic fn so `Ctx`/`Value`/return share one `'js`
  // (an inline closure gives each arg its own lifetime and the returned
  // promise Value cannot be proven to outlive them).
  rquickjs::Function::new(ctx.clone(), move |ctx, input, init| {
    do_fetch(ctx, input, init, backend.clone())
  })
}

/// The realm's `fetch` as an [`crate::Extension`], over `backend`.
pub struct FetchExtension {
  backend: Arc<dyn FetchBackend>,
}

impl FetchExtension {
  #[must_use]
  pub fn new(backend: Arc<dyn FetchBackend>) -> Self {
    Self { backend }
  }
}

impl Default for FetchExtension {
  fn default() -> Self {
    Self::new(Arc::new(Client::new()))
  }
}

impl crate::extension::Extension for FetchExtension {
  fn name(&self) -> &'static str {
    "fetch"
  }

  fn install(&self, ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    install(ctx, Arc::clone(&self.backend))
  }
}

fn do_fetch<'js>(
  ctx: Ctx<'js>,
  input: Value<'js>,
  init: Opt<Object<'js>>,
  backend: Arc<dyn FetchBackend>,
) -> rquickjs::Result<Value<'js>> {
  {
    // `input` may be a URL string, a `Request` instance, or an object
    // with a `url`. A `Request` seeds method/headers/body/redirect; the
    // `init` bag overrides each.
    let req = Class::<FetchRequestJs<'js>>::from_value(&input).ok();
    // Spec: fetching a Request whose body was already read is a
    // TypeError, rather than silently sending nothing.
    if let Some(r) = req.as_ref()
      && r.borrow().body_is_disturbed()
    {
      return Err(rquickjs::Exception::throw_type(
        &ctx,
        "Cannot fetch a Request whose body has already been read",
      ));
    }
    let url = req
      .as_ref()
      .map(|r| r.borrow().url.clone())
      .or_else(|| input.as_string().and_then(|s| s.to_string().ok()))
      .or_else(|| input.as_object().and_then(|o| o.get::<_, String>("url").ok()))
      .unwrap_or_default();
    // The realm's container, composed with whatever the backend adds,
    // taken synchronously inside the call so the backend sees the
    // caller's context. The cloud metadata endpoints are blocked for
    // every script `fetch` regardless of grant (closes the default-open
    // SSRF); loopback stays reachable so local servers work.
    let net_guard = ferrijs_std::permissions::container(&ctx).map(|container| NetGuard {
      policy: Some(backend.net_policy(&ctx, container)),
      block_metadata: true,
      block_private: false,
    });
    let init = init.0;
    let method = init
      .as_ref()
      .and_then(|o| o.get::<_, String>("method").ok())
      .or_else(|| req.as_ref().map(|r| r.borrow().method.clone()));
    let mut header_list: CoreHeaders = init
      .as_ref()
      .and_then(|o| o.get::<_, Value<'_>>("headers").ok())
      .map(|v| header_list_from(&v))
      .or_else(|| req.as_ref().map(|r| r.borrow().headers.clone()))
      .unwrap_or_default();
    // The body goes through the ONE "extract a body" step
    // ([`super::body_init`]) that the `Request` / `Response`
    // constructors use, so every `BodyInit` type reaches the wire the
    // same way from every entry point.
    let extracted = match init.as_ref().and_then(|o| o.get::<_, Value<'_>>("body").ok()) {
      Some(v) => extract_body(&ctx, &v)?,
      None => None,
    };
    apply_body_content_type(&mut header_list, extracted.as_ref());
    // A stream body is drained inside the request future (the engine
    // sends buffered request bodies); anything else is already bytes.
    // With no `init.body`, a `Request` argument supplies its own bytes —
    // which its `.body` stream only ever holds a copy of, and a
    // disturbed one was already rejected above.
    let body_source = match extracted.map(|e| e.source) {
      Some(source) => Some(source),
      None => match req.as_ref().map(|r| r.borrow().body.clone()) {
        Some(b) if !b.is_empty() => Some(BodySource::Bytes(b)),
        _ => None,
      },
    };
    let headers = header_list.into_pairs();
    // A stream body is handed to the engine as a live byte stream — it is
    // pumped chunk-by-chunk onto the socket rather than buffered first,
    // so an unbounded source does not have to fit in memory. Built HERE,
    // synchronously, because the pump must be spawned on the QuickJS
    // thread that owns the stream.
    let body = match body_source {
      None => ferrijs_fetch::Body::empty(),
      Some(BodySource::Bytes(bytes)) => ferrijs_fetch::Body::from_bytes(bytes),
      Some(BodySource::Stream(stream)) => {
        ferrijs_fetch::Body::from_stream(self::streams::to_byte_stream(&ctx, stream)?)
      },
    };
    // `init.redirect` (or the Request's) maps onto the WHATWG redirect
    // mode: "follow" (default) follows up to the engine cap; "manual"
    // returns an opaque-redirect Response for a 3xx; "error" rejects.
    let redirect = init
      .as_ref()
      .and_then(|o| o.get::<_, String>("redirect").ok())
      .or_else(|| req.as_ref().map(|r| r.borrow().redirect.clone()));
    let redirect = match redirect.as_deref() {
      Some("manual") => RedirectMode::Manual,
      Some("error") => RedirectMode::Error,
      _ => RedirectMode::Follow,
    };
    // `init.credentials` (or the Request's): "omit" sends no cookies;
    // "same-origin" (default) / "include" send them.
    let credentials = init
      .as_ref()
      .and_then(|o| o.get::<_, String>("credentials").ok())
      .or_else(|| req.as_ref().map(|r| r.borrow().credentials.clone()));
    let credentials = match credentials.as_deref() {
      Some("omit") => Credentials::Omit,
      Some("include") => Credentials::Include,
      _ => Credentials::SameOrigin,
    };
    // `signal`: an `AbortSignal` from `init`, else the one carried on the
    // `Request` argument. Grab its native channel so the request future
    // can be dropped when it aborts.
    let signal = init
      .as_ref()
      .and_then(|o| o.get::<_, Value<'_>>("signal").ok())
      .and_then(|v| Class::<AbortSignal<'js>>::from_value(&v).ok())
      .and_then(|s| self::abort::native_channel(&ctx, &s).ok())
      .or_else(|| req.as_ref().and_then(|r| r.borrow().signal_inner.clone()));
    let failure_ctx = ctx.clone();
    let promised = rquickjs::promise::Promised::from(async move {
      let fail = |e: ferrijs_fetch::FetchError| fetch_failure(&failure_ctx, e);
      let request = FetchRequest {
        url: url.clone(),
        method: method.unwrap_or_else(|| "GET".to_string()),
        headers,
        body,
        redirect,
        credentials,
        net_guard,
        timeout: None,
      };
      if let Some(sig) = &signal
        && sig.is_aborted()
      {
        return Err(rquickjs::Error::new_from_js_message(
          "fetch",
          "AbortError",
          sig.reason_message(),
        ));
      }
      // Streamed: status/headers resolve here, the body is pulled
      // incrementally later (via Response.body / text() / json()).
      // A network failure is a WHATWG `TypeError`.
      let fut = backend.fetch(request);
      let resp = match &signal {
        Some(sig) => {
          tokio::select! {
            r = fut => r.map_err(fail)?,
            () = sig.aborted() => {
              return Err(fail(ferrijs_fetch::FetchError::Abort(sig.reason_message())));
            }
          }
        },
        None => fut.await.map_err(fail)?,
      };
      // `redirect: manual` on a 3xx yields an opaque-redirect filtered
      // response: type "opaqueredirect", status 0, empty headers, null
      // body, url "" (WHATWG). The unread 3xx is dropped here.
      if resp.unfollowed_redirect {
        return Ok(FetchResponseJs::opaque_redirect());
      }
      let ferrijs_fetch::Response {
        status,
        status_text,
        url,
        headers,
        body,
        redirected,
        type_,
        ..
      } = resp;
      let out = FetchResponseJs::from_stream(
        status,
        status_text,
        url,
        headers.entries().to_vec(),
        redirected,
        type_.as_str(),
        body.into_stream(),
      );
      Ok::<_, rquickjs::Error>(out)
    });
    promised.into_js(&ctx)
  }
}

/// An engine failure on its way to JS: a permission refusal stays the
/// `PermissionDeniedError` it is, an abort is an `AbortError`, and
/// anything else is the WHATWG `TypeError`.
fn fetch_failure(ctx: &Ctx<'_>, error: ferrijs_fetch::FetchError) -> rquickjs::Error {
  match error {
    ferrijs_fetch::FetchError::Denied(denied) => ferrijs_std::permissions::throw_denied(ctx, &denied),
    ferrijs_fetch::FetchError::Abort(reason) => rquickjs::Error::new_from_js_message("fetch", "AbortError", reason),
    other => rquickjs::Error::new_from_js_message("fetch", "TypeError", other.to_string()),
  }
}
