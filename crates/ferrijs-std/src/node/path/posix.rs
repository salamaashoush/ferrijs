//! `path.posix`: the posix half of Node's `lib/path.js`, function by
//! function. Only `/` separates, so the algorithms walk bytes and slice at
//! `/` or at the ends of a common prefix, both character boundaries.

use super::{basename_with, last_component, normalize_string, Parsed};

fn is_sep(byte: u8) -> bool {
  byte == b'/'
}

/// `path.posix.resolve`.
pub fn resolve(cwd: &str, args: &[String]) -> String {
  if (args.is_empty() || (args.len() == 1 && (args[0].is_empty() || args[0] == "."))) && cwd.starts_with('/') {
    return cwd.to_string();
  }
  // Right to left until one is absolute, as Node prepends `${path}/`.
  let mut kept: Vec<&str> = Vec::new();
  let mut absolute = false;
  for arg in args.iter().rev() {
    if arg.is_empty() {
      continue;
    }
    kept.push(arg);
    if arg.starts_with('/') {
      absolute = true;
      break;
    }
  }
  if !absolute {
    kept.push(cwd);
    absolute = cwd.starts_with('/');
  }
  let mut joined = String::with_capacity(kept.iter().map(|part| part.len() + 1).sum());
  for part in kept.iter().rev() {
    joined.push_str(part);
    joined.push('/');
  }
  let tail = normalize_string(&joined, !absolute, '/', is_sep);
  if absolute {
    format!("/{tail}")
  } else if tail.is_empty() {
    ".".to_string()
  } else {
    tail
  }
}

/// `path.posix.normalize`.
pub fn normalize(path: &str) -> String {
  if path.is_empty() {
    return ".".to_string();
  }
  let absolute = path.starts_with('/');
  let trailing = path.ends_with('/');
  let mut tail = normalize_string(path, !absolute, '/', is_sep);
  if tail.is_empty() {
    return if absolute {
      "/"
    } else if trailing {
      "./"
    } else {
      "."
    }
    .to_string();
  }
  if trailing {
    tail.push('/');
  }
  if absolute {
    format!("/{tail}")
  } else {
    tail
  }
}

/// `path.posix.isAbsolute`.
pub fn is_absolute(path: &str) -> bool {
  path.starts_with('/')
}

/// `path.posix.join`.
pub fn join(args: &[String]) -> String {
  let parts: Vec<&str> = args.iter().map(String::as_str).filter(|arg| !arg.is_empty()).collect();
  if parts.is_empty() {
    return ".".to_string();
  }
  normalize(&parts.join("/"))
}

/// `path.posix.relative`.
pub fn relative(cwd: &str, from: &str, to: &str) -> String {
  if from == to {
    return String::new();
  }
  let from = resolve(cwd, &[from.to_string()]);
  let to = resolve(cwd, &[to.to_string()]);
  if from == to {
    return String::new();
  }
  let (from_bytes, to_bytes) = (from.as_bytes(), to.as_bytes());
  let from_start = 1;
  let from_end = from_bytes.len();
  let from_len = from_end - from_start;
  let to_start = 1;
  let to_len = to_bytes.len() - to_start;

  let length = from_len.min(to_len);
  // Offsets past the leading `/`; `None` before any common separator.
  let mut last_common_sep: Option<usize> = None;
  let mut i = 0;
  while i < length {
    let byte = from_bytes[from_start + i];
    if byte != to_bytes[to_start + i] {
      break;
    }
    if byte == b'/' {
      last_common_sep = Some(i);
    }
    i += 1;
  }
  if i == length {
    if to_len > length {
      if to_bytes[to_start + i] == b'/' {
        // `from` is the exact base of `to`: `/foo/bar` to `/foo/bar/baz`.
        return to[to_start + i + 1..].to_string();
      }
      if i == 0 {
        // `from` is the root: `/` to `/foo`.
        return to[to_start..].to_string();
      }
    } else if from_len > length {
      if from_bytes[from_start + i] == b'/' {
        // `to` is the exact base of `from`: `/foo/bar/baz` to `/foo/bar`.
        last_common_sep = Some(i);
      } else if i == 0 {
        // `to` is the root: `/foo/bar` to `/`.
        last_common_sep = Some(0);
      }
    }
  }

  // One `..` per separator left in `from` past the common part, and one
  // for its end.
  let first = from_start + last_common_sep.map_or(0, |sep| sep + 1);
  let parents = from_bytes[first.min(from_end)..from_end].iter().filter(|byte| **byte == b'/').count()
    + usize::from(first <= from_end);
  let mut out = vec![".."; parents].join("/");
  // With no common separator Node slices from `toStart - 1`, the root.
  out.push_str(&to[last_common_sep.map_or(0, |sep| to_start + sep)..]);
  out
}

/// `path.posix.dirname`.
pub fn dirname(path: &str) -> String {
  let bytes = path.as_bytes();
  if bytes.is_empty() {
    return ".".to_string();
  }
  let has_root = bytes[0] == b'/';
  let mut end = None;
  let mut matched_slash = true;
  for i in (1..bytes.len()).rev() {
    if bytes[i] == b'/' {
      if !matched_slash {
        end = Some(i);
        break;
      }
    } else {
      matched_slash = false;
    }
  }
  match end {
    None if has_root => "/".to_string(),
    None => ".".to_string(),
    Some(1) if has_root => "//".to_string(),
    Some(end) => path[..end].to_string(),
  }
}

/// `path.posix.basename`.
pub fn basename(path: &str, suffix: Option<&str>) -> String {
  basename_with(path, suffix, 0, is_sep)
}

/// `path.posix.extname`.
pub fn extname(path: &str) -> String {
  let component = last_component(path.as_bytes(), 0, 0, is_sep);
  match (component.dot, component.end) {
    (Some(dot), Some(end)) => path[dot..end].to_string(),
    _ => String::new(),
  }
}

/// `path.posix.parse`.
pub fn parse(path: &str) -> Parsed {
  let mut parsed = Parsed::default();
  if path.is_empty() {
    return parsed;
  }
  let absolute = path.starts_with('/');
  if absolute {
    parsed.root.push('/');
  }
  // The scan stops above the root, but the `..` test counts from 0.
  let component = last_component(path.as_bytes(), usize::from(absolute), 0, is_sep);
  if let Some(end) = component.end {
    let start = if component.start == 0 && absolute { 1 } else { component.start };
    parsed.base = path[start..end].to_string();
    match component.dot {
      Some(dot) => {
        parsed.name = path[start..dot].to_string();
        parsed.ext = path[dot..end].to_string();
      },
      None => parsed.name.clone_from(&parsed.base),
    }
  }
  if component.start > 0 {
    parsed.dir = path[..component.start - 1].to_string();
  } else if absolute {
    parsed.dir.push('/');
  }
  parsed
}

#[cfg(test)]
mod tests {
  use super::*;

  fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
  }

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
      ("./", "./"),
    ] {
      assert_eq!(normalize(input), want, "normalize({input:?})");
    }
  }

  #[test]
  fn join_matches_node() {
    let join = |parts: &[&str]| super::join(&args(parts));
    assert_eq!(join(&["/foo", "bar", "baz/asdf", "quux", ".."]), "/foo/bar/baz/asdf");
    assert_eq!(join(&["a", "", "b"]), "a/b");
    assert_eq!(join(&[]), ".");
    assert_eq!(join(&["", ""]), ".");
    assert_eq!(join(&["a/", "b"]), "a/b");
    assert_eq!(join(&["/"]), "/");
    assert_eq!(join(&["a", "b/"]), "a/b/");
    assert_eq!(join(&[".", "./"]), "./");
  }

  #[test]
  fn resolve_matches_node() {
    let resolve = |parts: &[&str]| super::resolve("/base", &args(parts));
    assert_eq!(resolve(&["/foo/bar", "./baz"]), "/foo/bar/baz");
    assert_eq!(resolve(&["/foo/bar", "/tmp/file/"]), "/tmp/file");
    assert_eq!(resolve(&["a", "b"]), "/base/a/b");
    assert_eq!(resolve(&[]), "/base");
    assert_eq!(resolve(&["/"]), "/");
    assert_eq!(resolve(&["..", ".."]), "/");
  }

  #[test]
  fn relative_matches_node() {
    assert_eq!(relative("/base", "/a/b/c", "/a/b/c/d"), "d");
    assert_eq!(relative("/base", "/a/b/c", "/a/x"), "../../x");
    assert_eq!(relative("/base", "/a", "/a"), "");
    assert_eq!(relative("/base", "/a", "/b"), "../b");
    assert_eq!(relative("/base", "/", "/foo"), "foo");
    assert_eq!(relative("/base", "/foo/bar", "/"), "../..");
  }

  #[test]
  fn dirname_basename_extname_parse_match_node() {
    assert_eq!(dirname("//a"), "//");
    assert_eq!(dirname("/a/b/"), "/a");
    assert_eq!(basename(".js", Some(".js")), "");
    assert_eq!(basename("/home/user/file.txt", None), "file.txt");
    assert_eq!(extname(".."), "");
    assert_eq!(extname("/home/.gitignore"), "");
    assert_eq!(extname("/home/user/file.txt"), ".txt");
    assert_eq!(
      parse("/home/user/dir/file.txt"),
      Parsed {
        root: "/".into(),
        dir: "/home/user/dir".into(),
        base: "file.txt".into(),
        ext: ".txt".into(),
        name: "file".into(),
      }
    );
  }
}
