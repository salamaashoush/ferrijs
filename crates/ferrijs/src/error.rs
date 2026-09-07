//! Script execution errors with source-level diagnostics.

use std::fmt;

/// Kind of failure a script can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ScriptErrorKind {
  /// Source failed to parse.
  Syntax,
  /// Script threw an exception during execution.
  Runtime,
  /// Wall-clock timeout was exceeded.
  Timeout,
  /// `QuickJS` memory quota was exceeded.
  MemoryLimit,
  /// Engine-level failure unrelated to user script (binding setup, module loader, etc.).
  Internal,
}

impl fmt::Display for ScriptErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Syntax => write!(f, "syntax_error"),
      Self::Runtime => write!(f, "runtime_error"),
      Self::Timeout => write!(f, "timeout"),
      Self::MemoryLimit => write!(f, "memory_limit"),
      Self::Internal => write!(f, "internal_error"),
    }
  }
}

/// Structured error returned when a script fails.
///
/// `line`, `column`, and `source_snippet` are filled in whenever the `QuickJS`
/// runtime exposes them (syntax and runtime errors); they are `None` for
/// engine-level failures like timeouts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ScriptError {
  pub kind: ScriptErrorKind,
  /// The thrown value's JS constructor name (`TypeError`, ...) when the
  /// failure came from a JS exception. Hosts render `name: message` the way
  /// every JS runtime does; `None` for engine-level failures.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  pub message: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub stack: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub line: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub column: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub source_snippet: Option<String>,
}

impl ScriptError {
  /// Replace redacted values everywhere this error carries text.
  ///
  /// `source_snippet` is the reason this cannot be left to the caller: it
  /// quotes the script's own source around the throwing line, so a failure
  /// inside `login('admin', 'hunter2')` prints the credential back even
  /// when neither the message nor the stack mentions it.
  pub fn redact(&mut self, redactor: &dyn crate::redact::Redactor) {
    if redactor.is_empty() {
      return;
    }
    crate::redact::redact_in_place(redactor, &mut self.message);
    for field in [&mut self.name, &mut self.stack, &mut self.source_snippet] {
      if let Some(text) = field.as_mut() {
        crate::redact::redact_in_place(redactor, text);
      }
    }
  }

  #[must_use]
  pub fn internal(message: impl Into<String>) -> Self {
    Self {
      kind: ScriptErrorKind::Internal,
      name: None,
      message: message.into(),
      stack: None,
      line: None,
      column: None,
      source_snippet: None,
    }
  }

  /// A failure carrying a specific JS-visible `name`, for a host that
  /// distinguishes its own refusals by name.
  #[must_use]
  pub fn named(name: impl Into<String>, message: impl Into<String>) -> Self {
    Self {
      name: Some(name.into()),
      ..Self::internal(message)
    }
  }

  #[must_use]
  pub fn timeout(elapsed_ms: u64, limit_ms: u64) -> Self {
    Self {
      kind: ScriptErrorKind::Timeout,
      name: None,
      message: format!("script exceeded timeout: {elapsed_ms}ms > {limit_ms}ms"),
      stack: None,
      line: None,
      column: None,
      source_snippet: None,
    }
  }

  #[must_use]
  pub fn memory_limit(limit_bytes: usize) -> Self {
    Self {
      kind: ScriptErrorKind::MemoryLimit,
      name: None,
      message: format!("script exceeded memory limit of {limit_bytes} bytes"),
      stack: None,
      line: None,
      column: None,
      source_snippet: None,
    }
  }
}

impl ScriptError {
  /// A caught JS failure as a `ScriptError`, with every frame of its
  /// stack mapped through whichever bundle registered it in this realm,
  /// and a source snippet around the throwing line when `source` is the
  /// text that ran.
  #[must_use]
  pub fn from_caught(ctx: &rquickjs::Ctx<'_>, caught: rquickjs::CaughtError<'_>, source: &str) -> Self {
    Self::from_caught_offset(ctx, caught, source, 0)
  }

  /// [`Self::from_caught`] for source the runtime wrapped: `line_offset`
  /// is how many lines the wrapper put before the user's first line, so
  /// the reported position and snippet name the user's line.
  #[must_use]
  pub fn from_caught_offset(
    ctx: &rquickjs::Ctx<'_>,
    caught: rquickjs::CaughtError<'_>,
    source: &str,
    line_offset: u32,
  ) -> Self {
    let mut err = Self::from_caught_unmapped(caught, source, line_offset);
    if let Some(stack) = err.stack.take() {
      err.stack = Some(crate::source_map::remap_stack(ctx, &stack));
    }
    err
  }

  /// [`Self::from_caught`] without the stack remap, for a realm with no
  /// bundle registered.
  #[must_use]
  pub fn from_caught_unmapped(caught: rquickjs::CaughtError<'_>, source: &str, line_offset: u32) -> Self {
    let (name, message, stack, line, column) = match caught {
      rquickjs::CaughtError::Exception(ex) => {
        let message = ex.message().unwrap_or_else(|| "exception".to_string());
        let stack = ex.stack();
        // `lineNumber` / `columnNumber` are present on most QuickJS
        // exceptions; `name` is what every JS runtime prints ahead of
        // the message.
        let obj = ex.as_object();
        let name = obj.get::<_, String>("name").ok().filter(|n| !n.is_empty());
        let mut line = obj.get::<_, u32>("lineNumber").ok();
        let mut column = obj.get::<_, u32>("columnNumber").ok();
        // A thrown `Error` carries no `lineNumber`; the position is in
        // the stack's innermost frame.
        if line.is_none()
          && let Some((_, l, c)) = stack.as_deref().and_then(crate::source_map::innermost_frame)
        {
          line = Some(l);
          column = Some(c);
        }
        (name, message, stack, line, column)
      },
      // A heap that cannot allocate even the error object throws a bare
      // `null` (QuickJS's `JS_ThrowError2` falls back to it rather than
      // recurse), so a null exception IS the out-of-memory signal. A
      // deliberate `throw null` reports the same way; nothing else does,
      // since `Promise.reject()` and `throw undefined` carry `undefined`.
      rquickjs::CaughtError::Value(v) if v.is_null() => {
        return Self {
          kind: ScriptErrorKind::MemoryLimit,
          name: None,
          message: "out of memory: the engine could not allocate an error object".to_string(),
          stack: None,
          line: None,
          column: None,
          source_snippet: None,
        };
      },
      rquickjs::CaughtError::Value(v) => (None, format!("{v:?}"), None, None, None),
      rquickjs::CaughtError::Error(e) => (None, format!("{e}"), None, None, None),
    };
    let kind = if name.as_deref() == Some("SyntaxError") {
      ScriptErrorKind::Syntax
    } else if name.as_deref() == Some("InternalError") && message.contains("out of memory") {
      ScriptErrorKind::MemoryLimit
    } else {
      ScriptErrorKind::Runtime
    };
    // A position inside the wrapper (before the user's first line) is
    // not the user's, so it is reported as none rather than as line 0.
    let line = line.and_then(|l| l.checked_sub(line_offset).filter(|l| *l >= 1));
    Self {
      kind,
      name,
      message,
      stack,
      line,
      column,
      source_snippet: line.and_then(|l| snippet_around_line(source, l, 2)),
    }
  }
}

/// Build a 1-indexed source snippet with `context_lines` around the
/// target line, so a reader sees where the script failed.
fn snippet_around_line(source: &str, line_1based: u32, context_lines: u32) -> Option<String> {
  use std::fmt::Write as _;
  let lines: Vec<&str> = source.lines().collect();
  if lines.is_empty() {
    return None;
  }
  let target = line_1based.saturating_sub(1) as usize;
  let start = target.saturating_sub(context_lines as usize);
  let end = (target + context_lines as usize + 1).min(lines.len());
  let mut out = String::new();
  for (i, text) in lines[start..end].iter().enumerate() {
    let ln = start + i + 1;
    let marker = if ln == line_1based as usize { ">>>" } else { "   " };
    let _ = writeln!(out, "{marker} {ln:>4}: {text}");
  }
  Some(out)
}

impl fmt::Display for ScriptError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "[{}] {}", self.kind, self.message)?;
    if let (Some(l), Some(c)) = (self.line, self.column) {
      write!(f, " (at {l}:{c})")?;
    }
    Ok(())
  }
}

impl std::error::Error for ScriptError {}

/// An engine error outside any catch (a failed global write, a loader
/// refusal) is an internal failure: it has no JS exception behind it to
/// name.
impl From<rquickjs::Error> for ScriptError {
  fn from(e: rquickjs::Error) -> Self {
    Self::internal(e.to_string())
  }
}
