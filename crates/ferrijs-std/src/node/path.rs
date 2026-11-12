//! `node:path` — pure string operations, in both of Node's flavours.
//!
//! `join`, `resolve`, `dirname`, `basename`, `extname`, `normalize`,
//! `relative`, `isAbsolute`, `parse`, `format`, `toNamespacedPath`,
//! `sep`, `delimiter`, and `posix` / `win32` reaching either flavour from
//! the other. The module itself is the host's flavour, as in Node: a path
//! the runtime hands to JS on Windows is a Windows path, and code that
//! takes it apart has to read it as one. `resolve` roots at
//! `process.cwd()` — the sandbox root this runtime reports, not the real
//! process directory.
//!
//! Both flavours are ports of Node's `lib/path.js` (`posix.rs`,
//! `win32.rs`), checked against Node's own `test/parallel/test-path*.js`;
//! the helpers the two share sit here. Every entry point validates its
//! arguments as Node does, so a non-string throws `ERR_INVALID_ARG_TYPE`.

use std::sync::Arc;

use rquickjs::function::{Opt, Rest};
use rquickjs::{Ctx, Function, JsLifetime, Object, Value};

mod posix;
mod win32;

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

/// Node's `normalizeString`: resolve `.` and `..` in a path with its root
/// removed, joining what is kept with `separator`. Lengths here are bytes
/// where Node's are UTF-16 units; every length is only ever used to cut
/// `res` at a separator, so the two agree.
fn normalize_string(path: &str, allow_above_root: bool, separator: char, is_sep: fn(u8) -> bool) -> String {
  let bytes = path.as_bytes();
  let mut res = String::with_capacity(path.len());
  let mut last_segment_length = 0usize;
  let mut last_slash: Option<usize> = None;
  let mut dots = 0i32;
  let mut code = 0u8;
  for index in 0..=bytes.len() {
    if index < bytes.len() {
      code = bytes[index];
    } else if is_sep(code) {
      break;
    } else {
      code = b'/';
    }
    if is_sep(code) {
      if last_slash.map_or(index == 0, |slash| slash + 1 == index) || dots == 1 {
        // A doubled separator or a `.` segment adds nothing.
      } else if dots == 2 {
        if !res.ends_with("..") || last_segment_length != 2 {
          if res.len() > 2 {
            // The last segment is everything after the separator before it.
            if last_segment_length >= res.len() {
              res.clear();
              last_segment_length = 0;
            } else {
              res.truncate(res.len() - last_segment_length - 1);
              last_segment_length = res.len() - res.rfind(separator).map_or(0, |at| at + separator.len_utf8());
            }
            last_slash = Some(index);
            dots = 0;
            continue;
          } else if !res.is_empty() {
            res.clear();
            last_segment_length = 0;
            last_slash = Some(index);
            dots = 0;
            continue;
          }
        }
        if allow_above_root {
          if !res.is_empty() {
            res.push(separator);
          }
          res.push_str("..");
          last_segment_length = 2;
        }
      } else {
        let segment = &path[last_slash.map_or(0, |slash| slash + 1)..index];
        if !res.is_empty() {
          res.push(separator);
        }
        res.push_str(segment);
        last_segment_length = segment.len();
      }
      last_slash = Some(index);
      dots = 0;
    } else if code == b'.' && dots != -1 {
      dots += 1;
    } else {
      dots = -1;
    }
  }
  res
}

/// What `extname` and `parse` both find in the last component, scanning
/// down to `lower`: where the component starts (`start_part` when no
/// separator stops the scan), where its trailing separators begin, and
/// the dot its extension starts at, if it has one.
struct LastComponent {
  start: usize,
  end: Option<usize>,
  dot: Option<usize>,
}

fn last_component(bytes: &[u8], lower: usize, start_part: usize, is_sep: fn(u8) -> bool) -> LastComponent {
  let mut start = start_part;
  let mut start_dot: Option<usize> = None;
  let mut end: Option<usize> = None;
  let mut matched_slash = true;
  // 0: nothing seen before the dot; 1: only dots; -1: a name.
  let mut pre_dot_state = 0i8;
  for i in (lower..bytes.len()).rev() {
    let byte = bytes[i];
    if is_sep(byte) {
      if !matched_slash {
        start = i + 1;
        break;
      }
      continue;
    }
    if end.is_none() {
      matched_slash = false;
      end = Some(i + 1);
    }
    if byte == b'.' {
      if start_dot.is_none() {
        start_dot = Some(i);
      } else if pre_dot_state != 1 {
        pre_dot_state = 1;
      }
    } else if start_dot.is_some() {
      pre_dot_state = -1;
    }
  }
  // No extension when nothing names the component before its dot, or when
  // the component is exactly `..`.
  let dot = match (start_dot, end) {
    (Some(dot), Some(end)) if pre_dot_state != 0 && !(pre_dot_state == 1 && dot + 1 == end && dot == start + 1) => {
      Some(dot)
    },
    _ => None,
  };
  LastComponent { start, end, dot }
}

fn utf16(text: &str) -> Vec<u16> {
  text.encode_utf16().collect()
}

/// `units[start..end]` as a string, empty where JS `slice` would be.
fn from_utf16(units: &[u16], start: usize, end: usize) -> String {
  let end = end.min(units.len());
  if start >= end {
    return String::new();
  }
  String::from_utf16_lossy(&units[start..end])
}

/// Node's `basename`, from `start` (past a drive on win32). It compares
/// the suffix in UTF-16 units, as Node does.
fn basename_with(path: &str, suffix: Option<&str>, start: usize, is_sep: fn(u8) -> bool) -> String {
  let units = utf16(path);
  let is_sep16 = |unit: u16| u8::try_from(unit).is_ok_and(is_sep);
  let mut start = start;
  let mut end: Option<usize> = None;
  let mut matched_slash = true;

  if let Some(suffix) = suffix
    .map(utf16)
    .filter(|suffix| !suffix.is_empty() && suffix.len() <= units.len())
  {
    if suffix == units {
      return String::new();
    }
    let mut ext_index = Some(suffix.len() - 1);
    let mut first_non_slash_end: Option<usize> = None;
    for i in (start..units.len()).rev() {
      let unit = units[i];
      if is_sep16(unit) {
        if !matched_slash {
          start = i + 1;
          break;
        }
      } else {
        if first_non_slash_end.is_none() {
          matched_slash = false;
          first_non_slash_end = Some(i + 1);
        }
        if let Some(ext) = ext_index {
          if unit == suffix[ext] {
            if ext == 0 {
              end = Some(i);
            }
            ext_index = ext.checked_sub(1);
          } else {
            ext_index = None;
            end = first_non_slash_end;
          }
        }
      }
    }
    let end = if end == Some(start) { first_non_slash_end } else { end };
    return from_utf16(&units, start, end.unwrap_or(units.len()));
  }

  for i in (start..units.len()).rev() {
    if is_sep16(units[i]) {
      if !matched_slash {
        start = i + 1;
        break;
      }
    } else if end.is_none() {
      matched_slash = false;
      end = Some(i + 1);
    }
  }
  end.map_or_else(String::new, |end| from_utf16(&units, start, end))
}

/// `path.parse`'s five fields.
#[derive(Debug, Default, PartialEq, Eq)]
struct Parsed {
  root: String,
  dir: String,
  base: String,
  ext: String,
  name: String,
}

/// Node's `_format`: `dir` wins over `root`, and `base` over
/// `name`+`ext`; a `dir` that is only the root takes no separator.
fn format_str(sep: char, root: &str, dir: &str, base: &str, name: &str, ext: &str) -> String {
  let dir = if dir.is_empty() { root } else { dir };
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
    base
  } else if dir == root {
    format!("{dir}{base}")
  } else {
    format!("{dir}{sep}{base}")
  }
}

/// What Node's `determineSpecificType` says a rejected argument was.
fn received(ctx: &Ctx<'_>, value: &Value<'_>) -> String {
  if value.is_null() {
    return "null".into();
  }
  if value.is_undefined() {
    return "undefined".into();
  }
  if let Some(flag) = value.as_bool() {
    return format!("type boolean ({flag})");
  }
  if let Some(number) = value.as_number() {
    if number == 0.0 && number.is_sign_negative() {
      return "type number (-0)".into();
    }
    let text = value.get::<rquickjs::convert::Coerced<String>>().map_or_else(|_| number.to_string(), |c| c.0);
    return format!("type number ({text})");
  }
  if value.is_big_int() {
    let text = value.get::<rquickjs::convert::Coerced<String>>().map(|c| c.0).unwrap_or_default();
    return format!("type bigint ({text}n)");
  }
  if let Some(text) = value.as_string().and_then(|text| text.to_string().ok()) {
    let units = utf16(&text);
    let shown = if units.len() > 28 { format!("{}...", from_utf16(&units, 0, 25)) } else { text };
    return if shown.contains('\'') {
      format!(
        "type string ({})",
        ctx
          .json_stringify(shown.as_str())
          .ok()
          .flatten()
          .and_then(|json| json.to_string().ok())
          .unwrap_or(shown)
      )
    } else {
      format!("type string ('{shown}')")
    };
  }
  if let Some(function) = value.as_function() {
    let name: String = function.get("name").unwrap_or_default();
    return format!("function {name}");
  }
  if let Some(object) = value.as_object() {
    let constructor = object
      .get::<_, Option<Object<'_>>>("constructor")
      .ok()
      .flatten()
      .and_then(|constructor| constructor.get::<_, Option<String>>("name").ok().flatten());
    if let Some(name) = constructor {
      return format!("an instance of {name}");
    }
    let mut out = String::new();
    if crate::node::inspect::Inspector::new(false).with_depth(0).value(&mut out, value, 0).is_ok() {
      return out;
    }
  }
  if value.is_symbol() {
    let text = value
      .as_symbol()
      .and_then(|symbol| symbol.description().ok())
      .and_then(|description| description.as_string().and_then(|text| text.to_string().ok()))
      .unwrap_or_default();
    return format!("type symbol (Symbol({text}))");
  }
  "an unknown value".into()
}

fn invalid_arg_type(ctx: &Ctx<'_>, name: &str, expected: &str, value: &Value<'_>) -> rquickjs::Error {
  crate::node::coded(
    ctx,
    "TypeError",
    "ERR_INVALID_ARG_TYPE",
    &format!("The \"{name}\" argument must be of type {expected}. Received {}", received(ctx, value)),
  )
}

/// Node's `validateString`; a missing argument is `undefined`.
fn string_arg(ctx: &Ctx<'_>, value: &Option<Value<'_>>, name: &str) -> rquickjs::Result<String> {
  match value {
    Some(value) => match value.as_string() {
      Some(text) => text.to_string(),
      None => Err(invalid_arg_type(ctx, name, "string", value)),
    },
    None => Err(invalid_arg_type(ctx, name, "string", &Value::new_undefined(ctx.clone()))),
  }
}

fn string_args(ctx: &Ctx<'_>, values: &[Value<'_>], name: impl Fn(usize) -> String) -> rquickjs::Result<Vec<String>> {
  values
    .iter()
    .enumerate()
    .map(|(index, value)| string_arg(ctx, &Some(value.clone()), &name(index)))
    .collect()
}

/// What `path.posix` resolves against: on Windows, Node's `posixCwd`, the
/// working directory with its separators turned and its drive dropped.
fn posix_cwd(cwd: &str) -> String {
  if !cfg!(windows) {
    return cwd.to_string();
  }
  let turned = cwd.replace('\\', "/");
  match turned.find('/') {
    Some(at) => turned[at..].to_string(),
    // `slice(indexOf('/'))` with no `/` keeps the last character.
    None => turned.chars().last().map(String::from).unwrap_or_default(),
  }
}

/// Windows' per-drive working directory, `process.env['=C:']`, which
/// `cmd.exe` keeps and Node consults for a drive-relative path.
fn drive_cwd(ctx: &Ctx<'_>, drive: &str) -> Option<String> {
  let process: Object<'_> = ctx.globals().get("process").ok()?;
  let env: Object<'_> = process.get("env").ok()?;
  env
    .get::<_, Option<String>>(format!("={drive}"))
    .ok()
    .flatten()
    .filter(|dir| !dir.is_empty())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavour {
  Posix,
  Win32,
}

impl Flavour {
  fn resolve(self, ctx: &Ctx<'_>, args: &[String]) -> String {
    let cwd = cwd(ctx);
    match self {
      Self::Posix => posix::resolve(&posix_cwd(&cwd), args),
      Self::Win32 => win32::resolve(&cwd, &mut |drive| drive_cwd(ctx, drive), args),
    }
  }

  fn relative(self, ctx: &Ctx<'_>, from: &str, to: &str) -> String {
    let cwd = cwd(ctx);
    match self {
      Self::Posix => posix::relative(&posix_cwd(&cwd), from, to),
      Self::Win32 => win32::relative(&cwd, &mut |drive| drive_cwd(ctx, drive), from, to),
    }
  }

  fn parse(self, path: &str) -> Parsed {
    match self {
      Self::Posix => posix::parse(path),
      Self::Win32 => win32::parse(path),
    }
  }

  fn sep(self) -> char {
    match self {
      Self::Posix => '/',
      Self::Win32 => '\\',
    }
  }
}

/// One flavour's functions on a fresh object.
fn flavour_object<'js>(ctx: &Ctx<'js>, flavour: Flavour) -> rquickjs::Result<Object<'js>> {
  let o = Object::new(ctx.clone())?;
  o.set("sep", flavour.sep().to_string())?;
  o.set("delimiter", if flavour == Flavour::Win32 { ";" } else { ":" })?;

  o.set(
    "join",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, args: Rest<Value<'js>>| -> rquickjs::Result<String> {
      let args = string_args(&ctx, &args.0, |_| "path".to_string())?;
      Ok(match flavour {
        Flavour::Posix => posix::join(&args),
        Flavour::Win32 => win32::join(&args),
      })
    })?
    .with_name("join")?,
  )?;
  o.set(
    "resolve",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, args: Rest<Value<'js>>| -> rquickjs::Result<String> {
      let args = string_args(&ctx, &args.0, |index| format!("paths[{index}]"))?;
      Ok(flavour.resolve(&ctx, &args))
    })?
    .with_name("resolve")?,
  )?;
  o.set(
    "normalize",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, path: Opt<Value<'js>>| -> rquickjs::Result<String> {
      let path = string_arg(&ctx, &path.0, "path")?;
      Ok(match flavour {
        Flavour::Posix => posix::normalize(&path),
        Flavour::Win32 => win32::normalize(&path),
      })
    })?
    .with_name("normalize")?,
  )?;
  o.set(
    "isAbsolute",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, path: Opt<Value<'js>>| -> rquickjs::Result<bool> {
      let path = string_arg(&ctx, &path.0, "path")?;
      Ok(match flavour {
        Flavour::Posix => posix::is_absolute(&path),
        Flavour::Win32 => win32::is_absolute(&path),
      })
    })?
    .with_name("isAbsolute")?,
  )?;
  o.set(
    "relative",
    Function::new(
      ctx.clone(),
      move |ctx: Ctx<'js>, from: Opt<Value<'js>>, to: Opt<Value<'js>>| -> rquickjs::Result<String> {
        let from = string_arg(&ctx, &from.0, "from")?;
        let to = string_arg(&ctx, &to.0, "to")?;
        Ok(flavour.relative(&ctx, &from, &to))
      },
    )?
    .with_name("relative")?,
  )?;
  o.set(
    "dirname",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, path: Opt<Value<'js>>| -> rquickjs::Result<String> {
      let path = string_arg(&ctx, &path.0, "path")?;
      Ok(match flavour {
        Flavour::Posix => posix::dirname(&path),
        Flavour::Win32 => win32::dirname(&path),
      })
    })?
    .with_name("dirname")?,
  )?;
  o.set(
    "basename",
    Function::new(
      ctx.clone(),
      move |ctx: Ctx<'js>, path: Opt<Value<'js>>, suffix: Opt<Value<'js>>| -> rquickjs::Result<String> {
        let suffix = match suffix.0.filter(|suffix| !suffix.is_undefined()) {
          Some(suffix) => Some(string_arg(&ctx, &Some(suffix), "suffix")?),
          None => None,
        };
        let path = string_arg(&ctx, &path.0, "path")?;
        Ok(match flavour {
          Flavour::Posix => posix::basename(&path, suffix.as_deref()),
          Flavour::Win32 => win32::basename(&path, suffix.as_deref()),
        })
      },
    )?
    .with_name("basename")?,
  )?;
  o.set(
    "extname",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, path: Opt<Value<'js>>| -> rquickjs::Result<String> {
      let path = string_arg(&ctx, &path.0, "path")?;
      Ok(match flavour {
        Flavour::Posix => posix::extname(&path),
        Flavour::Win32 => win32::extname(&path),
      })
    })?
    .with_name("extname")?,
  )?;
  o.set(
    "parse",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, path: Opt<Value<'js>>| -> rquickjs::Result<Object<'js>> {
      let parsed = flavour.parse(&string_arg(&ctx, &path.0, "path")?);
      let o = Object::new(ctx)?;
      o.set("root", parsed.root)?;
      o.set("dir", parsed.dir)?;
      o.set("base", parsed.base)?;
      o.set("ext", parsed.ext)?;
      o.set("name", parsed.name)?;
      Ok(o)
    })?
    .with_name("parse")?,
  )?;
  o.set(
    "format",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, bag: Opt<Value<'js>>| -> rquickjs::Result<String> {
      // Node's `validateObject`: an object, not null, not an array.
      let bag = bag.0.unwrap_or_else(|| Value::new_undefined(ctx.clone()));
      let object = bag
        .as_object()
        .filter(|object| !object.is_array() && !bag.is_function())
        .cloned()
        .ok_or_else(|| invalid_arg_type(&ctx, "pathObject", "object", &bag))?;
      let field = |k: &str| -> String { object.get::<_, Option<String>>(k).ok().flatten().unwrap_or_default() };
      Ok(format_str(
        flavour.sep(),
        &field("root"),
        &field("dir"),
        &field("base"),
        &field("name"),
        &field("ext"),
      ))
    })?
    .with_name("format")?,
  )?;
  o.set(
    "toNamespacedPath",
    Function::new(ctx.clone(), move |ctx: Ctx<'js>, path: Opt<Value<'js>>| -> rquickjs::Result<Value<'js>> {
      let path = path.0.unwrap_or_else(|| Value::new_undefined(ctx.clone()));
      // Anything but a non-empty string comes back as it went in.
      let Some(text) = path.as_string().map(rquickjs::String::to_string).transpose()? else {
        return Ok(path);
      };
      if flavour == Flavour::Posix || text.is_empty() {
        return Ok(path);
      }
      let cwd = cwd(&ctx);
      let long = win32::to_namespaced_path(&cwd, &mut |drive| drive_cwd(&ctx, drive), &text);
      Ok(rquickjs::String::from_str(ctx.clone(), &long)?.into_value())
    })?
    .with_name("toNamespacedPath")?,
  )?;
  Ok(o)
}

/// The realm's one `path` object, so every `require('path')`, the ES
/// module and `path/posix` / `path/win32` hand out the same objects, as
/// Node's do.
struct PathNamespace(rquickjs::Persistent<Object<'static>>);

// SAFETY: holds only a `Persistent`, which is lifetime-erased by
// construction.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for PathNamespace {
  type Changed<'to> = PathNamespace;
}

/// The `path` module object: the host's flavour, each flavour reaching
/// the other as Node's do. Built once per realm.
pub fn path_object<'js>(ctx: &Ctx<'js>) -> rquickjs::Result<Object<'js>> {
  if let Some(held) = ctx.userdata::<PathNamespace>() {
    if let Ok(path) = held.0.clone().restore(ctx) {
      return Ok(path);
    }
  }
  let posix = flavour_object(ctx, Flavour::Posix)?;
  let win32 = flavour_object(ctx, Flavour::Win32)?;
  for flavour in [&posix, &win32] {
    flavour.set("posix", posix.clone())?;
    flavour.set("win32", win32.clone())?;
    // Node's legacy alias (DEP0080).
    flavour.set("_makeLong", flavour.get::<_, Value<'_>>("toNamespacedPath")?)?;
  }
  let path = if cfg!(windows) { win32 } else { posix };
  let _ = ctx.store_userdata(PathNamespace(rquickjs::Persistent::save(ctx, path.clone())));
  Ok(path)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn format_follows_node_precedence() {
    assert_eq!(format_str('/', "/", "/home/user", "file.txt", "", ""), "/home/user/file.txt");
    assert_eq!(format_str('/', "/", "", "", "file", ".txt"), "/file.txt");
    // Node joins a `dir` that is not the `root` with a separator, even `/`.
    assert_eq!(format_str('/', "", "/", "index.js", "", ""), "//index.js");
    assert_eq!(format_str('/', "", "", "", "x", "png"), "x.png");
    assert_eq!(
      format_str('\\', "C:\\", "C:\\path\\dir", "file.txt", "", ""),
      "C:\\path\\dir\\file.txt"
    );
  }

  #[test]
  fn posix_resolves_against_a_windows_cwd_without_its_drive() {
    if cfg!(windows) {
      assert_eq!(posix_cwd("C:\\fd\\ferridriver"), "/fd/ferridriver");
    } else {
      assert_eq!(posix_cwd("/fd/ferridriver"), "/fd/ferridriver");
    }
  }
}
