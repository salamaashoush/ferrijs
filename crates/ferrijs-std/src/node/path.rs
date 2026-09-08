//! `node:path` — POSIX-style pure string operations.
//!
//! `join`, `resolve`, `dirname`, `basename`, `extname`, `normalize`,
//! `relative`, `isAbsolute`, `parse`, `format`, `toNamespacedPath`,
//! `sep`, `delimiter`, and `posix` pointing back at the module.
//! `resolve` roots at `process.cwd()` — the sandbox root this runtime
//! reports, not the real process directory. No win32 flavour: this
//! runtime's path model is POSIX, and a `path.win32` that answered
//! POSIX would be worse than an absent one.
//!
//! Every entry point normalises in a single pass into one `String`: a
//! path helper is called in a loop by the code above it (a bundler
//! resolving a graph, a test runner naming fixtures), so an
//! intermediate `Vec<&str>` and a `join` per call are not free.

use std::sync::Arc;

use rquickjs::function::{Func, Opt, Rest};
use rquickjs::{Ctx, JsLifetime, Object};

/// What `process.cwd()` answers, kept where `resolve` can read it
/// without calling into JS.
///
/// `resolve` and `relative` need the working directory on every call,
/// and reaching it through `globalThis.process.cwd()` is a global
/// lookup, a property lookup and a JS call each time. The realm's cwd
/// is fixed at build time (there is no `chdir` in this sandbox), so the
/// process shim stores it here and the path module reads it directly.
#[derive(Clone)]
pub struct Cwd(pub Arc<str>);

// SAFETY: owns only an `Arc<str>`; no borrowed JS values, so restating
// the unused `'js` lifetime is sound.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for Cwd {
  type Changed<'to> = Cwd;
}

/// Record what `process.cwd()` answers for this realm.
pub fn set_cwd(ctx: &Ctx<'_>, cwd: &str) {
  let _ = ctx.store_userdata(Cwd(Arc::from(cwd)));
}

/// The realm's working directory, falling back to the JS `process.cwd()`
/// for a realm whose host installed a `process` of its own, and to `/`
/// for one with no `process` at all.
fn cwd(ctx: &Ctx<'_>) -> Arc<str> {
  if let Some(c) = ctx.userdata::<Cwd>() {
    return Arc::clone(&c.0);
  }
  let from_js: rquickjs::Result<String> = (|| {
    let process: Object<'_> = ctx.globals().get("process")?;
    let cwd_fn: rquickjs::Function<'_> = process.get("cwd")?;
    cwd_fn.call(())
  })();
  Arc::from(from_js.unwrap_or_else(|_| "/".to_string()))
}

/// Normalise `parts` (each a path fragment, split on `/` by the caller)
/// into `out`, resolving `.` and `..` as POSIX does.
///
/// `absolute` and `trailing` come from the whole path the parts were
/// taken from, because a fragment cannot know whether it is first or
/// last.
fn normalize_into<'a>(parts: impl Iterator<Item = &'a str>, absolute: bool, trailing: bool, out: &mut String) {
  let root = out.len();
  if absolute {
    out.push('/');
  }
  let body = out.len();
  // Where each kept segment begins, separator included, so a `..` drops
  // the one before it by truncating rather than by a second pass.
  let mut starts: Vec<usize> = Vec::new();
  for seg in parts {
    match seg {
      "" | "." => {},
      ".." => {
        if let Some(start) = starts.pop() {
          out.truncate(start);
        } else if !absolute {
          // A relative path keeps a `..` it cannot resolve, and nothing
          // later may pop it: `../..` is two levels, not zero.
          if out.len() > body {
            out.push('/');
          }
          out.push_str("..");
        }
      },
      s => {
        let start = out.len();
        if out.len() > body {
          out.push('/');
        }
        starts.push(start);
        out.push_str(s);
      },
    }
  }
  if out.len() == body {
    if !absolute {
      out.truncate(root);
      out.push('.');
    }
    return;
  }
  if trailing {
    out.push('/');
  }
}

fn normalize_str(path: &str) -> String {
  let mut out = String::with_capacity(path.len() + 1);
  normalize_into(
    path.split('/'),
    path.starts_with('/'),
    path.len() > 1 && path.ends_with('/'),
    &mut out,
  );
  out
}

fn join_segments(segments: &[String]) -> String {
  let Some(first) = segments.iter().find(|s| !s.is_empty()) else {
    return ".".to_string();
  };
  let last = segments.iter().rev().find(|s| !s.is_empty()).unwrap_or(first);
  let capacity = segments.iter().map(|s| s.len() + 1).sum::<usize>() + 1;
  let mut out = String::with_capacity(capacity);
  normalize_into(
    segments.iter().filter(|s| !s.is_empty()).flat_map(|s| s.split('/')),
    first.starts_with('/'),
    last.len() > 1 && last.ends_with('/'),
    &mut out,
  );
  out
}

fn dirname_str(path: &str) -> String {
  let trimmed = path.trim_end_matches('/');
  match trimmed.rfind('/') {
    Some(0) => "/".to_string(),
    Some(i) => trimmed[..i].to_string(),
    None => {
      if path.starts_with('/') {
        "/".to_string()
      } else {
        ".".to_string()
      }
    },
  }
}

fn basename_of(path: &str) -> &str {
  let trimmed = path.trim_end_matches('/');
  trimmed.rsplit('/').next().unwrap_or(trimmed)
}

fn basename_str(path: &str, ext: Option<&str>) -> String {
  let base = basename_of(path);
  match ext {
    Some(e) if base.len() > e.len() && base.ends_with(e) => base[..base.len() - e.len()].to_string(),
    _ => base.to_string(),
  }
}

/// The extension of `base`, dot included, or `""`. A leading dot
/// (`.gitignore`) is the name, not an extension.
fn extname_of(base: &str) -> &str {
  match base.rfind('.') {
    Some(i) if i > 0 => &base[i..],
    _ => "",
  }
}

fn extname_str(path: &str) -> String {
  extname_of(basename_of(path)).to_string()
}

/// Node's `resolve`: walk the arguments right to left, prepending, until
/// one is absolute; fall back to the working directory. Building from
/// the right means a segment that a later absolute path would have
/// discarded is never copied at all.
fn resolve_segments(cwd: &str, segments: &[String]) -> String {
  let mut parts: Vec<&str> = Vec::new();
  let mut absolute = false;
  for seg in segments.iter().rev() {
    if seg.is_empty() {
      continue;
    }
    parts.push(seg.as_str());
    if seg.starts_with('/') {
      absolute = true;
      break;
    }
  }
  if !absolute {
    parts.push(cwd);
    absolute = cwd.starts_with('/');
  }
  parts.reverse();
  let capacity = parts.iter().map(|s| s.len() + 1).sum::<usize>() + 1;
  let mut out = String::with_capacity(capacity);
  // `resolve` never answers a trailing slash, except for the root.
  normalize_into(parts.iter().flat_map(|s| s.split('/')), absolute, false, &mut out);
  out
}

fn relative_str(from: &str, to: &str) -> String {
  let f = normalize_str(from);
  let t = normalize_str(to);
  let fp: Vec<&str> = f.split('/').filter(|s| !s.is_empty()).collect();
  let tp: Vec<&str> = t.split('/').filter(|s| !s.is_empty()).collect();
  let common = fp.iter().zip(tp.iter()).take_while(|(a, b)| a == b).count();
  let mut out: Vec<&str> = vec![".."; fp.len() - common];
  out.extend(&tp[common..]);
  out.join("/")
}

/// `path.parse`, as a named function so `Ctx` and the object it builds
/// share one `'js` (an inline closure would give each its own).
fn parse_fn<'js>(ctx: Ctx<'js>, path: String) -> rquickjs::Result<Object<'js>> {
  parse_object(&ctx, &path)
}

/// `path.parse`: the root, directory, base name, extension and stem, the
/// five fields `path.format` reads back.
fn parse_object<'js>(ctx: &Ctx<'js>, path: &str) -> rquickjs::Result<Object<'js>> {
  let o = Object::new(ctx.clone())?;
  let root = if path.starts_with('/') { "/" } else { "" };
  let base = basename_of(path);
  let ext = extname_of(base);
  let name = &base[..base.len() - ext.len()];
  let dir = {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
      Some(0) => "/",
      Some(i) => &trimmed[..i],
      None => "",
    }
  };
  o.set("root", root)?;
  o.set("dir", dir)?;
  o.set("base", base)?;
  o.set("ext", ext)?;
  o.set("name", name)?;
  Ok(o)
}

/// `path.format`: `dir` wins over `root`, and `base` over `name`+`ext`,
/// which is Node's precedence.
fn format_str(root: &str, dir: &str, base: &str, name: &str, ext: &str) -> String {
  let base = if base.is_empty() {
    let mut b = String::with_capacity(name.len() + ext.len() + 1);
    b.push_str(name);
    if !ext.is_empty() && !ext.starts_with('.') {
      b.push('.');
    }
    b.push_str(ext);
    b
  } else {
    base.to_string()
  };
  if dir.is_empty() {
    return format!("{root}{base}");
  }
  if dir == "/" {
    return format!("/{base}");
  }
  format!("{dir}/{base}")
}

/// Build the `path` module object (fresh per call; only built once per
/// session by the module loader).
pub fn path_object<'js>(ctx: &Ctx<'js>) -> rquickjs::Result<Object<'js>> {
  let o = Object::new(ctx.clone())?;
  o.set("sep", "/")?;
  o.set("delimiter", ":")?;
  o.set("join", Func::from(|segs: Rest<String>| join_segments(&segs.0)))?;
  o.set(
    "resolve",
    Func::from(|ctx: Ctx<'_>, segs: Rest<String>| -> String { resolve_segments(&cwd(&ctx), &segs.0) }),
  )?;
  o.set("normalize", Func::from(|p: String| normalize_str(&p)))?;
  o.set("dirname", Func::from(|p: String| dirname_str(&p)))?;
  o.set(
    "basename",
    Func::from(|p: String, ext: Opt<String>| basename_str(&p, ext.0.as_deref())),
  )?;
  o.set("extname", Func::from(|p: String| extname_str(&p)))?;
  o.set(
    "relative",
    Func::from(|ctx: Ctx<'_>, from: String, to: String| -> String {
      let cwd = cwd(&ctx);
      relative_str(&resolve_segments(&cwd, &[from]), &resolve_segments(&cwd, &[to]))
    }),
  )?;
  o.set("isAbsolute", Func::from(|p: String| p.starts_with('/')))?;
  o.set("parse", Func::from(parse_fn))?;
  o.set(
    "format",
    Func::from(|bag: Object<'_>| -> rquickjs::Result<String> {
      let field = |k: &str| -> String { bag.get::<_, Option<String>>(k).ok().flatten().unwrap_or_default() };
      Ok(format_str(
        &field("root"),
        &field("dir"),
        &field("base"),
        &field("name"),
        &field("ext"),
      ))
    }),
  )?;
  // POSIX has no namespaced paths; Node's own posix flavour is the
  // identity here too.
  o.set("toNamespacedPath", Func::from(|p: String| p))?;
  // `path.posix` is this module: code that picks a flavour explicitly
  // gets the one flavour this runtime has.
  o.set("posix", o.clone())?;
  Ok(o)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn normalize_matches_node() {
    for (input, want) in [
      ("/a/b/../c", "/a/c"),
      ("/foo/bar//baz/asdf/quux/..", "/foo/bar/baz/asdf"),
      ("a/b/..", "a"),
      ("a/..", "."),
      ("", "."),
      ("/", "/"),
      ("/..", "/"),
      ("../..", "../.."),
      ("./a/", "a/"),
      ("/a/b/", "/a/b/"),
      ("//a", "/a"),
      ("../a/../b", "../b"),
    ] {
      assert_eq!(normalize_str(input), want, "normalize({input:?})");
    }
  }

  #[test]
  fn join_matches_node() {
    let j = |parts: &[&str]| join_segments(&parts.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
    assert_eq!(j(&["/foo", "bar", "baz/asdf", "quux", ".."]), "/foo/bar/baz/asdf");
    assert_eq!(j(&["a", "", "b"]), "a/b");
    assert_eq!(j(&[]), ".");
    assert_eq!(j(&["", ""]), ".");
    assert_eq!(j(&["a/", "b"]), "a/b");
    assert_eq!(j(&["/"]), "/");
    assert_eq!(j(&["a", "b/"]), "a/b/");
  }

  #[test]
  fn resolve_matches_node() {
    let r = |parts: &[&str]| resolve_segments("/base", &parts.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
    assert_eq!(r(&["/foo/bar", "./baz"]), "/foo/bar/baz");
    assert_eq!(r(&["/foo/bar", "/tmp/file/"]), "/tmp/file");
    assert_eq!(r(&["a", "b"]), "/base/a/b");
    assert_eq!(r(&[]), "/base");
    assert_eq!(r(&["/"]), "/");
    assert_eq!(r(&["..", ".."]), "/");
  }

  #[test]
  fn parse_and_format_round_trip() {
    assert_eq!(extname_of(basename_of("/home/user/file.txt")), ".txt");
    assert_eq!(extname_of(basename_of("/home/.gitignore")), "");
    assert_eq!(basename_of("/home/user/file.txt"), "file.txt");
    assert_eq!(format_str("/", "/home/user", "file.txt", "", ""), "/home/user/file.txt");
    assert_eq!(format_str("/", "", "", "file", ".txt"), "/file.txt");
    assert_eq!(format_str("", "/", "index.js", "", ""), "/index.js");
  }

  #[test]
  fn relative_matches_node() {
    assert_eq!(relative_str("/a/b/c", "/a/b/c/d"), "d");
    assert_eq!(relative_str("/a/b/c", "/a/x"), "../../x");
    assert_eq!(relative_str("/a", "/a"), "");
  }
}
