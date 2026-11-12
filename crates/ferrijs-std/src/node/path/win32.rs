//! `path.win32`: the win32 half of Node's `lib/path.js`, function by
//! function, so a Windows path answers here what it answers in Node.
//!
//! Every character the algorithms branch on is ASCII (`\`, `/`, `:`, `.`,
//! `?`, a drive letter), and UTF-8 never puts an ASCII byte inside a
//! multi-byte character, so they walk bytes and slice at byte offsets.
//! The two places Node compares lengths in UTF-16 units (`relative`'s
//! case-folding check, `basename`'s suffix) and the one where it measures
//! a result (`toNamespacedPath`) work in UTF-16 too.

const RESERVED_NAMES: [&str; 28] = [
  "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
  "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM\u{b9}", "COM\u{b2}", "COM\u{b3}", "LPT\u{b9}",
  "LPT\u{b2}", "LPT\u{b3}",
];

use super::{basename_with, from_utf16, last_component, normalize_string, utf16, Parsed};

const BACKSLASH: u16 = b'\\' as u16;

fn is_sep(byte: u8) -> bool {
  byte == b'/' || byte == b'\\'
}

fn is_device_root(byte: u8) -> bool {
  byte.is_ascii_alphabetic()
}

fn at(bytes: &[u8], index: usize) -> Option<u8> {
  bytes.get(index).copied()
}

fn sep_at(bytes: &[u8], index: usize) -> bool {
  at(bytes, index).is_some_and(is_sep)
}

fn drive_at_start(bytes: &[u8]) -> bool {
  at(bytes, 0).is_some_and(is_device_root) && at(bytes, 1) == Some(b':')
}

/// Node's `isWindowsReservedName(path, colonIndex)`: the text before the
/// colon, upper-cased, is a DOS device. Node calls it with `indexOf(':')`
/// unchecked, so a path with no colon tests all but its last UTF-16 unit
/// (`slice(0, -1)`); a last character outside the BMP leaves half a
/// surrogate pair behind, which no device name matches.
fn is_reserved_name(path: &str, colon: Option<usize>) -> bool {
  let device = match colon {
    Some(colon) => &path[..colon],
    None => {
      let mut chars = path.chars();
      match chars.next_back() {
        Some(last) if last.len_utf16() == 2 => return false,
        _ => chars.as_str(),
      }
    },
  };
  RESERVED_NAMES.contains(&device.to_uppercase().as_str())
}

/// The UNC prefix both `resolve` and `normalize` look for at the start of
/// a path that opens with two separators: `\\server\share`. Answers the
/// server part and the byte range of the share, or `None` when the path
/// stops short of a share.
fn unc_parts(path: &str) -> Option<(&str, usize, usize)> {
  let bytes = path.as_bytes();
  let len = bytes.len();
  let mut j = 2;
  let mut last = j;
  while j < len && !is_sep(bytes[j]) {
    j += 1;
  }
  if j >= len || j == last {
    return None;
  }
  let first_part = &path[last..j];
  last = j;
  while j < len && is_sep(bytes[j]) {
    j += 1;
  }
  if j >= len || j == last {
    return None;
  }
  last = j;
  while j < len && !is_sep(bytes[j]) {
    j += 1;
  }
  Some((first_part, last, j))
}

/// `path.win32.resolve`. `drive_cwd` answers Windows' per-drive working
/// directory (`process.env['=C:']`) for a drive-relative argument.
pub fn resolve(cwd: &str, drive_cwd: &mut dyn FnMut(&str) -> Option<String>, args: &[String]) -> String {
  let mut resolved_device = String::new();
  let mut resolved_tail = String::new();
  let mut resolved_absolute = false;

  let mut index = args.len() as isize - 1;
  while index >= -1 {
    let fallback: String;
    let path: &str = if index >= 0 {
      let arg = &args[index as usize];
      if arg.is_empty() {
        index -= 1;
        continue;
      }
      arg
    } else if resolved_device.is_empty() {
      let only_here = args.len() == 1 && (args[0].is_empty() || args[0] == ".");
      if args.is_empty() || (only_here && sep_at(cwd.as_bytes(), 0)) {
        return if cfg!(windows) {
          cwd.to_string()
        } else {
          cwd.replace('/', "\\")
        };
      }
      cwd
    } else {
      let drive = drive_cwd(&resolved_device).unwrap_or_else(|| cwd.to_string());
      let other_drive = drive
        .get(..2)
        .is_none_or(|prefix| prefix.to_lowercase() != resolved_device.to_lowercase());
      fallback = if other_drive && at(drive.as_bytes(), 2) == Some(b'\\') {
        format!("{resolved_device}\\")
      } else {
        drive
      };
      &fallback
    };

    let bytes = path.as_bytes();
    let len = bytes.len();
    let mut root_end = 0;
    let mut device = String::new();
    let mut is_absolute = false;
    if len == 1 {
      if is_sep(bytes[0]) {
        root_end = 1;
        is_absolute = true;
      }
    } else if sep_at(bytes, 0) {
      is_absolute = true;
      if sep_at(bytes, 1) {
        if let Some((first_part, share_start, share_end)) = unc_parts(path) {
          if first_part != "." && first_part != "?" {
            device = format!("\\\\{first_part}\\{}", &path[share_start..share_end]);
            root_end = share_end;
          } else {
            device = format!("\\\\{first_part}");
            root_end = 4;
          }
        }
      } else {
        root_end = 1;
      }
    } else if drive_at_start(bytes) {
      device = path[..2].to_string();
      root_end = 2;
      if len > 2 && is_sep(bytes[2]) {
        is_absolute = true;
        root_end = 3;
      }
    }

    if !device.is_empty() {
      if resolved_device.is_empty() {
        resolved_device = device;
      } else if device.to_lowercase() != resolved_device.to_lowercase() {
        index -= 1;
        continue;
      }
    }

    if resolved_absolute {
      if !resolved_device.is_empty() {
        break;
      }
    } else {
      resolved_tail = format!("{}\\{resolved_tail}", &path[root_end..]);
      resolved_absolute = is_absolute;
      if is_absolute && !resolved_device.is_empty() {
        break;
      }
    }
    index -= 1;
  }

  let tail = normalize_string(&resolved_tail, !resolved_absolute, '\\', is_sep);
  if resolved_absolute {
    format!("{resolved_device}\\{tail}")
  } else {
    let relative = format!("{resolved_device}{tail}");
    if relative.is_empty() { ".".to_string() } else { relative }
  }
}

/// `path.win32.normalize`.
pub fn normalize(path: &str) -> String {
  let bytes = path.as_bytes();
  let len = bytes.len();
  if len == 0 {
    return ".".to_string();
  }
  if len == 1 {
    return if bytes[0] == b'/' {
      "\\".to_string()
    } else {
      path.to_string()
    };
  }
  let mut root_end = 0;
  let mut device: Option<String> = None;
  let mut is_absolute = false;
  if is_sep(bytes[0]) {
    is_absolute = true;
    if is_sep(bytes[1]) {
      if let Some((first_part, share_start, share_end)) = unc_parts(path) {
        if first_part == "." || first_part == "?" {
          let mut root = format!("\\\\{first_part}");
          root_end = 4;
          // `\\?\COM1:`: a reserved device right after the prefix.
          let possible = match path.find(':') {
            Some(colon) if colon >= 4 => &path[4..=colon],
            _ => "",
          };
          if !possible.is_empty() && is_reserved_name(possible, Some(possible.len() - 1)) {
            root = format!("\\\\?\\{possible}");
            root_end = 4 + possible.len();
          }
          device = Some(root);
        } else if share_end == len {
          return format!("\\\\{first_part}\\{}\\", &path[share_start..]);
        } else {
          device = Some(format!("\\\\{first_part}\\{}", &path[share_start..share_end]));
          root_end = share_end;
        }
      }
    } else {
      root_end = 1;
    }
  } else if let Some(colon) = path.find(':').filter(|colon| *colon > 0) {
    if is_device_root(bytes[0]) && colon == 1 {
      device = Some(path[..2].to_string());
      root_end = 2;
      if len > 2 && is_sep(bytes[2]) {
        is_absolute = true;
        root_end = 3;
      }
    } else if is_reserved_name(path, Some(colon)) {
      device = Some(path[..=colon].to_string());
      root_end = colon + 1;
    }
  }

  let mut tail = if root_end < len {
    normalize_string(&path[root_end..], !is_absolute, '\\', is_sep)
  } else {
    String::new()
  };
  if tail.is_empty() && !is_absolute {
    tail.push('.');
  }
  if !tail.is_empty() && is_sep(bytes[len - 1]) {
    tail.push('\\');
  }
  if !is_absolute && device.is_none() && path.contains(':') {
    // A relative path must not normalise into one Windows reads as
    // rooted on a drive or a stream (CVE-2024-36139).
    if drive_at_start(tail.as_bytes()) {
      return format!(".\\{tail}");
    }
    let mut colon = path.find(':');
    while let Some(at) = colon {
      if at == len - 1 || is_sep(bytes[at + 1]) {
        return format!(".\\{tail}");
      }
      colon = path[at + 1..].find(':').map(|next| next + at + 1);
    }
  }
  if is_reserved_name(path, path.find(':')) {
    return format!(".\\{}{tail}", device.as_deref().unwrap_or_default());
  }
  match device {
    None if is_absolute => format!("\\{tail}"),
    None => tail,
    Some(device) if is_absolute => format!("{device}\\{tail}"),
    Some(device) => format!("{device}{tail}"),
  }
}

/// `path.win32.isAbsolute`.
pub fn is_absolute(path: &str) -> bool {
  let bytes = path.as_bytes();
  sep_at(bytes, 0) || (bytes.len() > 2 && drive_at_start(bytes) && is_sep(bytes[2]))
}

/// `path.win32.join`.
pub fn join(args: &[String]) -> String {
  let parts: Vec<&str> = args.iter().map(String::as_str).filter(|arg| !arg.is_empty()).collect();
  let Some(first) = parts.first().map(|first| first.as_bytes()) else {
    return ".".to_string();
  };
  let mut joined = parts.join("\\");

  // Two leading separators read as a UNC root, which is only meant when
  // the first argument itself starts with exactly two and a name.
  let mut needs_replace = true;
  let mut slash_count = 0;
  if is_sep(first[0]) {
    slash_count += 1;
    if sep_at(first, 1) {
      slash_count += 1;
      if first.len() > 2 {
        if is_sep(first[2]) {
          slash_count += 1;
        } else {
          needs_replace = false;
        }
      }
    }
  }
  if needs_replace {
    let bytes = joined.as_bytes();
    while slash_count < bytes.len() && is_sep(bytes[slash_count]) {
      slash_count += 1;
    }
    if slash_count >= 2 {
      joined = format!("\\{}", &joined[slash_count..]);
    }
  }

  // A segment naming a DOS device is left as written, separators aside.
  let reserved = joined
    .split('\\')
    .filter(|part| !part.is_empty())
    .any(|part| part.find(':').is_some_and(|colon| is_reserved_name(part, Some(colon))));
  if reserved {
    return joined.replace('/', "\\");
  }
  normalize(&joined)
}

/// `path.win32.relative`. Windows paths compare case-insensitively.
pub fn relative(cwd: &str, drive_cwd: &mut dyn FnMut(&str) -> Option<String>, from: &str, to: &str) -> String {
  if from == to {
    return String::new();
  }
  let from_orig = resolve(cwd, drive_cwd, &[from.to_string()]);
  let to_orig = resolve(cwd, drive_cwd, &[to.to_string()]);
  if from_orig == to_orig {
    return String::new();
  }
  let from_lower = from_orig.to_lowercase();
  let to_lower = to_orig.to_lowercase();
  if from_lower == to_lower {
    return String::new();
  }

  let from_units = utf16(&from_lower);
  let to_units = utf16(&to_lower);
  let to_orig_units = utf16(&to_orig);
  if utf16(&from_orig).len() != from_units.len() || to_orig_units.len() != to_units.len() {
    // Lower-casing changed a length, so the two cannot be walked in step:
    // compare component by component instead.
    let mut from_split: Vec<&str> = from_orig.split('\\').collect();
    let mut to_split: Vec<&str> = to_orig.split('\\').collect();
    if from_split.last() == Some(&"") {
      from_split.pop();
    }
    if to_split.last() == Some(&"") {
      to_split.pop();
    }
    let length = from_split.len().min(to_split.len());
    let common = (0..length)
      .find(|&i| from_split[i].to_lowercase() != to_split[i].to_lowercase())
      .unwrap_or(length);
    if common == 0 {
      return to_orig;
    }
    if common == length {
      if to_split.len() > length {
        return to_split[common..].join("\\");
      }
      if from_split.len() > length {
        return format!("{}..", "..\\".repeat(from_split.len() - 1 - common));
      }
      return String::new();
    }
    return format!("{}{}", "..\\".repeat(from_split.len() - common), to_split[common..].join("\\"));
  }

  let (from, to) = (&from_units, &to_units);
  let mut from_start = 0;
  while from_start < from.len() && from[from_start] == BACKSLASH {
    from_start += 1;
  }
  let mut from_end = from.len();
  while from_end > from_start + 1 && from[from_end - 1] == BACKSLASH {
    from_end -= 1;
  }
  let from_len = from_end - from_start;
  let mut to_start = 0;
  while to_start < to.len() && to[to_start] == BACKSLASH {
    to_start += 1;
  }
  let mut to_end = to.len();
  while to_end > to_start + 1 && to[to_end - 1] == BACKSLASH {
    to_end -= 1;
  }
  let to_len = to_end - to_start;

  let length = from_len.min(to_len);
  let mut last_common_sep: Option<usize> = None;
  let mut i = 0;
  while i < length {
    let unit = from[from_start + i];
    if unit != to[to_start + i] {
      break;
    }
    if unit == BACKSLASH {
      last_common_sep = Some(i);
    }
    i += 1;
  }

  let last_common_sep = if i == length {
    if to_len > length {
      if to[to_start + i] == BACKSLASH {
        // `from` is the exact base of `to`: `C:\foo\bar` to `C:\foo\bar\baz`.
        return from_utf16(&to_orig_units, to_start + i + 1, to_orig_units.len());
      }
      if i == 2 {
        // `from` is the device root: `C:\` to `C:\foo`.
        return from_utf16(&to_orig_units, to_start + i, to_orig_units.len());
      }
    }
    let mut common = last_common_sep;
    if from_len > length {
      if from[from_start + i] == BACKSLASH {
        common = Some(i);
      } else if i == 2 {
        common = Some(3);
      }
    }
    common.unwrap_or(0)
  } else {
    match last_common_sep {
      Some(common) => common,
      None => return to_orig,
    }
  };

  // One `..` per separator left in `from` past the common part, and one
  // for its end.
  let first = from_start + last_common_sep + 1;
  let parents = from[first.min(from_end)..from_end].iter().filter(|unit| **unit == BACKSLASH).count()
    + usize::from(first <= from_end);
  let mut out = vec![".."; parents].join("\\");
  let mut to_start = to_start + last_common_sep;
  if !out.is_empty() {
    out.push_str(&from_utf16(&to_orig_units, to_start, to_end));
    return out;
  }
  if to_orig_units.get(to_start) == Some(&BACKSLASH) {
    to_start += 1;
  }
  from_utf16(&to_orig_units, to_start, to_end)
}

/// `path.win32.toNamespacedPath`: the `\\?\` long form of an absolute
/// drive or UNC path.
pub fn to_namespaced_path(cwd: &str, drive_cwd: &mut dyn FnMut(&str) -> Option<String>, path: &str) -> String {
  let resolved = resolve(cwd, drive_cwd, &[path.to_string()]);
  if resolved.encode_utf16().count() <= 2 {
    return path.to_string();
  }
  let bytes = resolved.as_bytes();
  if bytes[0] == b'\\' {
    if bytes[1] == b'\\' && bytes[2] != b'?' && bytes[2] != b'.' {
      return format!("\\\\?\\UNC\\{}", &resolved[2..]);
    }
  } else if drive_at_start(bytes) && bytes[2] == b'\\' {
    return format!("\\\\?\\{resolved}");
  }
  resolved
}

/// `path.win32.dirname`.
pub fn dirname(path: &str) -> String {
  let bytes = path.as_bytes();
  let len = bytes.len();
  if len == 0 {
    return ".".to_string();
  }
  if len == 1 {
    return if is_sep(bytes[0]) {
      path.to_string()
    } else {
      ".".to_string()
    };
  }
  let mut root_end: Option<usize> = None;
  let mut offset = 0;
  if is_sep(bytes[0]) {
    root_end = Some(1);
    offset = 1;
    if let Some((_, share_start, share_end)) = unc_parts(path).filter(|_| is_sep(bytes[1])) {
      if share_end == len {
        return path.to_string();
      }
      if share_end != share_start {
        // The separator after `\\server\share` belongs to the root.
        root_end = Some(share_end + 1);
        offset = share_end + 1;
      }
    }
  } else if drive_at_start(bytes) {
    let end = if len > 2 && is_sep(bytes[2]) { 3 } else { 2 };
    root_end = Some(end);
    offset = end;
  }

  let mut end = None;
  let mut matched_slash = true;
  for i in (offset..len).rev() {
    if is_sep(bytes[i]) {
      if !matched_slash {
        end = Some(i);
        break;
      }
    } else {
      matched_slash = false;
    }
  }
  match end.or(root_end) {
    Some(end) => path[..end].to_string(),
    None => ".".to_string(),
  }
}

/// `path.win32.basename`.
pub fn basename(path: &str, suffix: Option<&str>) -> String {
  let start = if drive_at_start(path.as_bytes()) { 2 } else { 0 };
  basename_with(path, suffix, start, is_sep)
}

/// `path.win32.extname`.
pub fn extname(path: &str) -> String {
  let bytes = path.as_bytes();
  let start = if drive_at_start(bytes) { 2 } else { 0 };
  let component = last_component(bytes, start, start, is_sep);
  match (component.dot, component.end) {
    (Some(dot), Some(end)) => path[dot..end].to_string(),
    _ => String::new(),
  }
}

/// `path.win32.parse`.
pub fn parse(path: &str) -> Parsed {
  let mut parsed = Parsed::default();
  let bytes = path.as_bytes();
  let len = bytes.len();
  if len == 0 {
    return parsed;
  }
  if len == 1 {
    if is_sep(bytes[0]) {
      parsed.root = path.to_string();
      parsed.dir = path.to_string();
    } else {
      parsed.base = path.to_string();
      parsed.name = path.to_string();
    }
    return parsed;
  }
  let mut root_end = 0;
  if is_sep(bytes[0]) {
    root_end = 1;
    if let Some((_, share_start, share_end)) = unc_parts(path).filter(|_| is_sep(bytes[1])) {
      if share_end == len {
        root_end = share_end;
      } else if share_end != share_start {
        root_end = share_end + 1;
      }
    }
  } else if drive_at_start(bytes) {
    if len <= 2 || (len == 3 && is_sep(bytes[2])) {
      parsed.root = path.to_string();
      parsed.dir = path.to_string();
      return parsed;
    }
    root_end = if is_sep(bytes[2]) { 3 } else { 2 };
  }
  if root_end > 0 {
    parsed.root = path[..root_end].to_string();
  }

  let component = last_component(bytes, root_end, root_end, is_sep);
  if let Some(end) = component.end {
    let base = &path[component.start..end];
    parsed.base = base.to_string();
    match component.dot {
      Some(dot) => {
        parsed.name = path[component.start..dot].to_string();
        parsed.ext = path[dot..end].to_string();
      },
      None => parsed.name = base.to_string(),
    }
  }
  parsed.dir = if component.start > 0 && component.start != root_end {
    path[..component.start - 1].to_string()
  } else {
    parsed.root.clone()
  };
  parsed
}

#[cfg(test)]
mod tests {
  use super::*;

  fn no_drive_cwd(_: &str) -> Option<String> {
    None
  }

  fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
  }

  #[test]
  fn resolve_matches_node() {
    let resolve = |cwd: &str, parts: &[&str]| super::resolve(cwd, &mut no_drive_cwd, &args(parts));
    assert_eq!(resolve("C:\\cwd", &["c:/blah\\blah", "d:/games", "c:../a"]), "c:\\blah\\a");
    assert_eq!(resolve("C:\\cwd", &["c:/ignore", "d:\\a/b\\c/d", "\\e.exe"]), "d:\\e.exe");
    assert_eq!(resolve("C:\\cwd", &["c:/ignore", "c:/some/file"]), "c:\\some\\file");
    assert_eq!(resolve("C:\\cwd", &["d:/ignore", "d:some/dir//"]), "d:\\ignore\\some\\dir");
    assert_eq!(resolve("C:\\cwd", &["//server/share", "..", "relative\\"]), "\\\\server\\share\\relative");
    assert_eq!(resolve("C:\\cwd", &["c:/", "//"]), "c:\\");
    assert_eq!(resolve("C:\\cwd", &["c:/", "//dir"]), "c:\\dir");
    assert_eq!(resolve("C:\\cwd", &["c:/", "//server/share"]), "\\\\server\\share\\");
    assert_eq!(resolve("C:\\cwd", &["c:/", "///some//dir"]), "c:\\some\\dir");
    assert_eq!(
      resolve("C:\\cwd", &["C:\\foo\\tmp.3\\", "..\\tmp.3\\cycles\\root.js"]),
      "C:\\foo\\tmp.3\\cycles\\root.js"
    );
    assert_eq!(resolve("C:\\cwd", &["a", "b"]), "C:\\cwd\\a\\b");
    assert_eq!(resolve("C:\\cwd", &[]), "C:\\cwd");
  }

  #[test]
  fn a_drive_relative_path_takes_that_drive_s_directory() {
    let mut drives = |drive: &str| (drive == "D:").then(|| "D:\\work".to_string());
    assert_eq!(super::resolve("C:\\cwd", &mut drives, &args(&["D:src"])), "D:\\work\\src");
    assert_eq!(super::resolve("C:\\cwd", &mut no_drive_cwd, &args(&["E:src"])), "E:\\src");
  }

  #[test]
  fn normalize_matches_node() {
    for (input, want) in [
      ("./fixtures///b/../b/c.js", "fixtures\\b\\c.js"),
      ("/foo/../../../bar", "\\bar"),
      ("a//b//../b", "a\\b"),
      ("a//b//./c", "a\\b\\c"),
      ("//server/share/dir/file.ext", "\\\\server\\share\\dir\\file.ext"),
      ("/a/b/c/../../../x/y/z", "\\x\\y\\z"),
      ("C:", "C:."),
      ("C:..\\abc", "C:..\\abc"),
      ("c:/ignore", "c:\\ignore"),
      ("..\\foo..\\..\\..\\bar", "..\\..\\bar"),
      ("\\\\server\\share", "\\\\server\\share\\"),
      ("bar\\foo..\\..\\", "bar\\"),
      ("test/../C:/Windows", ".\\C:\\Windows"),
      ("test/../C:Windows", ".\\C:Windows"),
      ("./upload/../C:/Windows", ".\\C:\\Windows"),
      ("\\\\?\\COM1:\\foo", "\\\\?\\COM1:\\foo"),
      ("CON:foo", ".\\CON:foo"),
    ] {
      assert_eq!(normalize(input), want, "normalize({input:?})");
    }
  }

  #[test]
  fn join_matches_node() {
    let join = |parts: &[&str]| super::join(&args(parts));
    assert_eq!(join(&["//foo", "bar"]), "\\\\foo\\bar\\");
    assert_eq!(join(&["\\/foo", "bar"]), "\\\\foo\\bar\\");
    assert_eq!(join(&["//", "foo", "bar"]), "\\foo\\bar");
    assert_eq!(join(&["c:", "file"]), "c:\\file");
    assert_eq!(join(&["C:\\fd", "test-results", "x.har"]), "C:\\fd\\test-results\\x.har");
    assert_eq!(join(&[]), ".");
    assert_eq!(join(&["", ""]), ".");
  }

  #[test]
  fn relative_matches_node() {
    let relative = |from: &str, to: &str| super::relative("C:\\cwd", &mut no_drive_cwd, from, to);
    assert_eq!(relative("c:/blah\\blah", "d:/games"), "d:\\games");
    assert_eq!(relative("c:/aaaa/bbbb", "c:/aaaa"), "..");
    assert_eq!(relative("c:/aaaa/bbbb", "c:/cccc"), "..\\..\\cccc");
    assert_eq!(relative("c:/aaaa/bbbb", "C:/aaaa/bbbb"), "");
    assert_eq!(relative("c:/aaaa/", "c:/aaaa/cccc"), "cccc");
    assert_eq!(relative("c:/", "c:\\aaaa\\bbbb"), "aaaa\\bbbb");
    assert_eq!(relative("c:/aaaa/bbbb", "d:\\"), "d:\\");
    assert_eq!(relative("\\\\foo\\bar", "\\\\foo\\bar\\baz"), "baz");
    assert_eq!(relative("C:\\baz-quux", "C:\\baz"), "..\\baz");
  }

  #[test]
  fn dirname_basename_extname_match_node() {
    assert_eq!(dirname("c:\\foo\\bar"), "c:\\foo");
    assert_eq!(dirname("c:\\"), "c:\\");
    assert_eq!(dirname("c:foo"), "c:");
    assert_eq!(dirname("\\\\unc\\share\\foo"), "\\\\unc\\share\\");
    assert_eq!(dirname("\\\\unc\\share"), "\\\\unc\\share");
    assert_eq!(dirname("C:\\fd\\x.har"), "C:\\fd");
    assert_eq!(basename("C:\\foo.html", Some(".html")), "foo");
    assert_eq!(basename("C:", None), "");
    assert_eq!(basename("C:basename.ext\\\\", None), "basename.ext");
    assert_eq!(basename("aaa\\bbb", Some("bbb")), "bbb");
    assert_eq!(extname("C:\\a\\b.c.d"), ".d");
    assert_eq!(extname("file\\\\"), "");
    assert_eq!(extname("C:.."), "");
  }

  #[test]
  fn parse_matches_node() {
    assert_eq!(
      parse("C:\\path\\dir\\index.html"),
      Parsed {
        root: "C:\\".into(),
        dir: "C:\\path\\dir".into(),
        base: "index.html".into(),
        ext: ".html".into(),
        name: "index".into(),
      }
    );
    assert_eq!(
      parse("\\\\server\\share\\file_path"),
      Parsed {
        root: "\\\\server\\share\\".into(),
        dir: "\\\\server\\share\\".into(),
        base: "file_path".into(),
        ext: String::new(),
        name: "file_path".into(),
      }
    );
  }

  #[test]
  fn namespaced_paths_take_the_long_form() {
    let long = |path: &str| to_namespaced_path("C:\\cwd", &mut no_drive_cwd, path);
    assert_eq!(long("C:\\foo"), "\\\\?\\C:\\foo");
    assert_eq!(long("\\\\server\\share\\x"), "\\\\?\\UNC\\server\\share\\x");
    assert_eq!(long("\\\\?\\C:\\foo"), "\\\\?\\C:\\foo");
  }
}
