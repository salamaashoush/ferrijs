//! Where in the user's source a position in a bundle came from.
//!
//! A bundler rewrites the code `QuickJS` runs, so every position the
//! engine reports (a stack frame, a thrown error's line) is in bundled
//! coordinates. Each loaded bundle registers its [`SourceMapper`] on the
//! realm; [`remap_stack`] and [`caller_source_file`] translate through
//! whichever map the frame's module name selects, so a realm holding
//! several bundles (an entry plus the extensions installed beside it)
//! never maps one bundle's lines through another's map.

use std::cell::RefCell;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};

use rquickjs::{Ctx, JsLifetime};

/// A bundle's source map, parsed the first time something asks to remap.
///
/// Parsing it costs more than reading the whole cache record, and a run
/// that never reports a position -- anything that simply executes and
/// succeeds -- would otherwise pay it on every start.
#[derive(Clone, Default)]
pub struct LazyMap(Option<Arc<LazyMapInner>>);

struct LazyMapInner {
  json: Box<str>,
  parsed: OnceLock<Option<Arc<sourcemap::SourceMap>>>,
}

impl LazyMap {
  #[must_use]
  pub fn from_json(json: Option<&str>) -> Self {
    Self(json.map(|j| {
      Arc::new(LazyMapInner {
        json: j.into(),
        parsed: OnceLock::new(),
      })
    }))
  }

  /// The map's JSON as it was given, for a cache that persists it.
  #[must_use]
  pub fn json(&self) -> Option<&str> {
    self.0.as_ref().map(|inner| &*inner.json)
  }

  #[must_use]
  pub fn is_some(&self) -> bool {
    self.0.is_some()
  }

  fn get(&self) -> Option<&Arc<sourcemap::SourceMap>> {
    let inner = self.0.as_ref()?;
    inner
      .parsed
      .get_or_init(|| {
        sourcemap::SourceMap::from_slice(inner.json.as_bytes())
          .ok()
          .map(Arc::new)
      })
      .as_ref()
  }

  /// The `sources` the map names, for a cache that fingerprints them.
  #[must_use]
  pub fn sources(&self) -> Vec<String> {
    self
      .get()
      .map(|sm| sm.sources().map(ToString::to_string).collect())
      .unwrap_or_default()
  }
}

/// A bundle's position mapping on its own.
///
/// A realm has to keep translating positions for as long as the module
/// it loaded can run -- long after the compiled bundle that produced the
/// bytecode has been dropped by whoever compiled it.
#[derive(Clone)]
pub struct SourceMapper {
  /// Module name `QuickJS` knows the bundle by, which is what its stack
  /// frames are labelled with.
  pub module_name: String,
  map: LazyMap,
  /// Directory the bundle's own source-map paths are relative to. A
  /// process cwd is not it: a bundler is handed a root, and a host that
  /// bundles a suite and then runs it from somewhere else would report
  /// every frame against a directory the sources are not under.
  cwd: Option<PathBuf>,
}

impl std::fmt::Debug for SourceMapper {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("SourceMapper")
      .field("module_name", &self.module_name)
      .field("mapped", &self.map.is_some())
      .field("cwd", &self.cwd)
      .finish()
  }
}

impl SourceMapper {
  #[must_use]
  pub fn new(module_name: impl Into<String>, map: LazyMap) -> Self {
    Self {
      module_name: module_name.into(),
      map,
      cwd: None,
    }
  }

  /// Resolve this bundle's sources against `cwd` rather than the
  /// process's. What a bundler sets, since it is the one that knows.
  #[must_use]
  pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
    self.cwd = Some(cwd.into());
    self
  }

  /// The absolute path of an original source this bundle names.
  #[must_use]
  pub fn absolute(&self, source: &str) -> String {
    match &self.cwd {
      Some(cwd) => resolve_source(cwd, source).to_string_lossy().into_owned(),
      None => absolute(source),
    }
  }

  /// Map a bundled-output `line:col` (1-based, as `QuickJS` reports) back
  /// to the original source location.
  #[must_use]
  pub fn remap(&self, line: u32, col: u32) -> Option<(String, u32, u32)> {
    let sm = self.map.get()?;
    let token = sm.lookup_token(line.saturating_sub(1), col.saturating_sub(1))?;
    let src = token.get_source().unwrap_or("<unknown>").to_string();
    Some((src, token.get_src_line() + 1, token.get_src_col() + 1))
  }
}

/// A module compiled to `QuickJS` bytecode, plus the source map to
/// translate bundled positions back to source. What a bundler produces
/// and [`crate::Runtime::eval_module`] runs.
pub struct CompiledModule {
  pub module_name: String,
  pub bytecode: Arc<[u8]>,
  pub source_map: LazyMap,
  /// The root the bundler resolved this module's imports against, which
  /// is what its source-map paths are relative to.
  pub cwd: Option<PathBuf>,
}

impl CompiledModule {
  #[must_use]
  pub fn mapper(&self) -> SourceMapper {
    let mapper = SourceMapper::new(self.module_name.clone(), self.source_map.clone());
    match &self.cwd {
      Some(cwd) => mapper.with_cwd(cwd.clone()),
      None => mapper,
    }
  }

  /// Map a bundled-output position back to the original source.
  #[must_use]
  pub fn remap(&self, line: u32, col: u32) -> Option<(String, u32, u32)> {
    self.mapper().remap(line, col)
  }
}

impl std::fmt::Debug for CompiledModule {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CompiledModule")
      .field("module_name", &self.module_name)
      .field("bytecode_len", &self.bytecode.len())
      .field("mapped", &self.source_map.is_some())
      .field("cwd", &self.cwd)
      .finish()
  }
}

/// Collapse `.` and `..` without touching the filesystem.
#[must_use]
pub fn normalize_path(path: &Path) -> PathBuf {
  let mut out = PathBuf::new();
  for component in path.components() {
    match component {
      Component::CurDir => {},
      Component::ParentDir => {
        if !matches!(
          out.components().next_back(),
          Some(Component::RootDir | Component::Prefix(_)) | None
        ) {
          out.pop();
        }
      },
      other => out.push(other.as_os_str()),
    }
  }
  out
}

/// Resolve a source-map `sources` entry to a real file.
///
/// The entries are relative to the bundle chunk's virtual location (a
/// level below the bundling cwd), so a literal join produces paths like
/// `<cwd>/../tests/a.test.ts` -- peel leading `../` segments until the
/// candidate exists under `cwd`.
#[must_use]
pub fn resolve_source(cwd: &Path, src: &str) -> PathBuf {
  let p = Path::new(src);
  if p.is_absolute() {
    return p.to_path_buf();
  }
  // Normalized, because the joined form keeps every `../` verbatim: a
  // file outside the working directory would then be reported as
  // `<cwd>/../../../tmp/specs/a.ts`, which names the right file but is
  // not under `cwd`.
  let mut rest = src;
  loop {
    let candidate = normalize_path(&cwd.join(rest));
    if candidate.exists() {
      return candidate;
    }
    match rest.strip_prefix("../") {
      Some(stripped) => rest = stripped,
      None => return normalize_path(&cwd.join(src)),
    }
  }
}

/// The maps registered on this realm, one per loaded bundle.
struct SourceMapsUd(RefCell<Vec<SourceMapper>>);

// SAFETY: holds only `'static` data (strings and parsed maps), no JS
// values, so re-stating the unused `'js` lifetime is sound.
#[allow(unsafe_code)]
unsafe impl JsLifetime<'_> for SourceMapsUd {
  type Changed<'to> = SourceMapsUd;
}

/// Record a bundle's source map so positions taken while it runs report
/// the file the user wrote.
///
/// Called wherever a bundle is loaded into a realm. Loading the same
/// bundle twice is not an error -- a realm re-running a module keeps
/// one entry.
pub fn register_bundle(ctx: &Ctx<'_>, mapper: SourceMapper) {
  if ctx.userdata::<SourceMapsUd>().is_none() {
    let _ = ctx.store_userdata(SourceMapsUd(RefCell::new(Vec::new())));
  }
  let Some(ud) = ctx.userdata::<SourceMapsUd>() else {
    return;
  };
  let mut maps = ud.0.borrow_mut();
  if maps.iter().any(|m| m.module_name == mapper.module_name) {
    return;
  }
  maps.push(mapper);
}

/// Rewrite every `<module>:LINE:COL` frame in a JS stack through the map
/// registered for THAT module. Frames whose module has no registered map
/// are left exactly as `QuickJS` wrote them.
#[must_use]
pub fn remap_stack(ctx: &Ctx<'_>, stack: &str) -> String {
  let Some(maps) = ctx.userdata::<SourceMapsUd>() else {
    return stack.to_string();
  };
  let maps = maps.0.borrow();
  if maps.is_empty() {
    return stack.to_string();
  }
  let mut out = String::with_capacity(stack.len());
  for (i, line) in stack.split('\n').enumerate() {
    if i > 0 {
      out.push('\n');
    }
    match parse_frame(line) {
      Some((start, end, file, l, c)) => {
        let hit = maps
          .iter()
          .find(|m| m.module_name == file)
          .and_then(|m| m.remap(l, c).map(|r| (m, r)));
        match hit {
          Some((mapper, (src, sl, sc))) => {
            use std::fmt::Write as _;
            out.push_str(&line[..start]);
            let _ = write!(out, "{}:{sl}:{sc}", mapper.absolute(&src));
            out.push_str(&line[end..]);
          },
          None => out.push_str(line),
        }
      },
      None => out.push_str(line),
    }
  }
  out
}

/// A position in the bundle the frame names, answered as the file the
/// author wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
  pub file: String,
  pub line: u32,
  pub column: u32,
}

/// Translate a bundled `line:col` back to the original source through
/// the map of the bundle the frame names.
#[must_use]
pub fn remap(ctx: &Ctx<'_>, file: &str, line: u32, column: u32) -> Option<Position> {
  let maps = ctx.userdata::<SourceMapsUd>()?;
  let maps = maps.0.borrow();
  // With one bundle in the realm the frame's label is that bundle's by
  // construction, and a plain run labels its module after the entry
  // file. With more than one the label is the only thing that says
  // which map a frame belongs to, and guessing maps one bundle's line
  // numbers through another's.
  let mapper = match maps.as_slice() {
    [only] if only.module_name == file || file.is_empty() => Some(only),
    many => many.iter().find(|m| m.module_name == file),
  }?;
  let (src, src_line, src_col) = mapper.remap(line, column)?;
  Some(Position {
    file: mapper.absolute(&src),
    line: src_line,
    column: src_col,
  })
}

/// Source-map sources are relative to the bundle's virtual location;
/// anything that reads the file off disk wants the real path.
fn absolute(source: &str) -> String {
  static CWD: OnceLock<Option<PathBuf>> = OnceLock::new();
  match CWD.get_or_init(|| std::env::current_dir().ok()) {
    Some(cwd) => resolve_source(cwd, source).to_string_lossy().into_owned(),
    None => source.to_string(),
  }
}

/// The calling JS frame, mapped back to the original source.
#[must_use]
pub fn caller_position(ctx: &Ctx<'_>) -> Option<Position> {
  let (file, line, column) = capture_frame(ctx)?;
  remap(ctx, &file, line, column)
}

/// The ORIGINAL source file the calling JS frame was written in.
///
/// `require.resolve('./x')` has to answer relative to the file that
/// wrote it, the way Node does. Bundling erases that: `QuickJS` only
/// knows the bundle it ran. The source map puts it back.
///
/// `None` when there is no JS frame or no map covers it: an inline
/// eval, or a plain script that was never bundled. The caller decides
/// what to anchor on then (the working directory).
#[must_use]
pub fn caller_source_file(ctx: &Ctx<'_>) -> Option<PathBuf> {
  caller_position(ctx).map(|p| PathBuf::from(p.file))
}

/// `file`, `line`, `col` of the innermost JS frame in a fresh stack
/// trace -- the caller's own position, in bundled coordinates.
///
/// Synthetic frames (`<eval>`, `native`) are skipped: the capture itself
/// runs through `ctx.eval`, whose frame sits below the native binding
/// frame, and the caller's frame is the first that names a module.
#[must_use]
pub fn capture_frame(ctx: &Ctx<'_>) -> Option<(String, u32, u32)> {
  capture_frames(ctx).into_iter().next()
}

/// Every JS frame of a fresh stack trace, innermost first.
#[must_use]
pub fn capture_frames(ctx: &Ctx<'_>) -> Vec<(String, u32, u32)> {
  let Ok(stack) = ctx.eval::<String, _>("new Error().stack") else {
    return Vec::new();
  };
  parse_js_frames(&stack)
}

/// The `file:line:col` frames of a `QuickJS` stack, innermost first.
/// Only frames naming a module file count; `<eval>` and `native` are
/// skipped.
#[must_use]
pub fn parse_js_frames(stack: &str) -> Vec<(String, u32, u32)> {
  stack
    .lines()
    .filter_map(|line| {
      let (_, _, file, l, c) = parse_frame(line)?;
      let is_module = Path::new(file)
        .extension()
        .is_some_and(|e| ["js", "mjs", "cjs", "ts"].iter().any(|x| e.eq_ignore_ascii_case(x)));
      is_module.then(|| (file.to_string(), l, c))
    })
    .collect()
}

/// The innermost frame of a stack that is the program's own: for a
/// position when the exception object carries none. Frames inside the
/// runtime's snippets (a thrower installed by the realm lockdown) are
/// skipped, since a user is looking for the line that called them.
#[must_use]
pub fn innermost_frame(stack: &str) -> Option<(String, u32, u32)> {
  stack.lines().find_map(|line| {
    let (_, _, file, l, c) = parse_frame(line)?;
    (!file.starts_with('<')).then(|| (file.to_string(), l, c))
  })
}

/// Find the last `<file>:<line>:<col>` in a stack line: byte range of
/// the whole match, the file, and the two numbers.
fn parse_frame(line: &str) -> Option<(usize, usize, &str, u32, u32)> {
  // Walk from the end: `col` is the trailing digits, `line` the digits
  // before the previous colon, `file` everything back to whitespace or
  // an opening paren.
  let trimmed_end = line.trim_end_matches(|c: char| c == ')' || c.is_whitespace());
  let end = trimmed_end.len();
  let (rest, col) = trimmed_end.rsplit_once(':')?;
  let col: u32 = col.parse().ok()?;
  let (rest, ln) = rest.rsplit_once(':')?;
  let ln: u32 = ln.parse().ok()?;
  let start = rest
    .rfind(|c: char| c.is_whitespace() || c == '(')
    .map_or(0, |i| i + c_len(rest, i));
  let file = &rest[start..];
  if file.is_empty() {
    return None;
  }
  Some((start, end, file, ln, col))
}

fn c_len(s: &str, i: usize) -> usize {
  s[i..].chars().next().map_or(1, char::len_utf8)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_quickjs_frames_innermost_first() {
    let stack = "    at f (bundle.js:12:5)\n    at <eval> (eval_script:3:1)\n    at g (helpers.mjs:7:9)\n    at native";
    assert_eq!(
      parse_js_frames(stack),
      vec![("bundle.js".to_string(), 12, 5), ("helpers.mjs".to_string(), 7, 9)]
    );
  }

  #[test]
  fn remap_stack_leaves_unmapped_frames_alone() {
    let rt = rquickjs::Runtime::new().unwrap();
    let cx = rquickjs::Context::full(&rt).unwrap();
    cx.with(|ctx| {
      let stack = "    at f (bundle.js:1:2)";
      assert_eq!(remap_stack(&ctx, stack), stack);
      register_bundle(&ctx, SourceMapper::new("bundle.js", LazyMap::default()));
      assert_eq!(remap_stack(&ctx, stack), stack);
    });
  }

  #[test]
  fn normalize_collapses_dots() {
    assert_eq!(normalize_path(Path::new("/a/b/../c/./d")), PathBuf::from("/a/c/d"));
    assert_eq!(normalize_path(Path::new("/../x")), PathBuf::from("/x"));
  }

  #[test]
  fn a_bundle_resolves_its_sources_against_its_own_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("suite");
    std::fs::create_dir_all(root.join("specs")).expect("mkdir");
    std::fs::write(root.join("specs/a.ts"), "").expect("write");

    let mapper = SourceMapper::new("bundle.js", LazyMap::default()).with_cwd(&root);
    // `join` keeps an embedded `/` verbatim, so the expected value is built a
    // component at a time; `absolute` normalises and would not match it on a
    // platform whose separator is not `/`.
    assert_eq!(
      mapper.absolute("specs/a.ts"),
      root.join("specs").join("a.ts").to_string_lossy()
    );
    // Without one, the process cwd answers instead, which is the bug:
    // the file it names is not the one the bundler read.
    assert_ne!(
      SourceMapper::new("bundle.js", LazyMap::default()).absolute("specs/a.ts"),
      mapper.absolute("specs/a.ts")
    );
  }
}
