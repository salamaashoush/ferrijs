//! Values that must not reach a caller verbatim.
//!
//! A host that knows a credential the script will handle (an API token
//! it injected, a password a test logs in with) registers it here, and
//! the runtime replaces it in everything it hands back: console entries,
//! the returned value, the failure and its source snippet. Doing it at
//! the runtime means a host cannot forget one of the three paths.
//!
//! A convenience, not a security boundary: it replaces known strings on
//! the way out. A value the host never declared, or one the script
//! reshapes (base64, a substring, a re-encoding), still passes through.

use std::borrow::Cow;

/// Something that rewrites text before it leaves the runtime.
pub trait Redactor: Send + Sync + std::fmt::Debug {
  /// `Borrowed` when nothing changed.
  fn redact<'a>(&self, text: &'a str) -> Cow<'a, str>;

  /// Whether a call can ever change anything. A host with nothing to
  /// hide answers `true` and the runtime skips the walk.
  fn is_empty(&self) -> bool {
    false
  }
}

/// Named secret values, replaced by `<secret>NAME</secret>`.
///
/// Entries are ordered longest-value-first so that when one secret
/// contains another, the longer one is replaced before its substring
/// can be.
#[derive(Debug, Clone, Default)]
pub struct Secrets {
  entries: Vec<(String, String)>,
}

impl Secrets {
  /// Build from `name -> value` pairs. Empty values are dropped: an unset
  /// credential would otherwise match the empty string everywhere.
  #[must_use]
  pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
    let mut entries: Vec<(String, String)> = pairs.into_iter().filter(|(_, value)| !value.is_empty()).collect();
    entries.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    Self { entries }
  }

  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  /// The declared name of an exactly-matching secret value.
  #[must_use]
  pub fn name_for(&self, value: &str) -> Option<&str> {
    self
      .entries
      .iter()
      .find(|(_, secret)| secret == value)
      .map(|(name, _)| name.as_str())
  }

  /// Replace every occurrence of a secret value with `<secret>NAME</secret>`.
  #[must_use]
  pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
    if self.entries.is_empty() {
      return Cow::Borrowed(text);
    }
    let mut out = Cow::Borrowed(text);
    for (name, value) in &self.entries {
      if out.contains(value.as_str()) {
        out = Cow::Owned(out.replace(value.as_str(), &format!("<secret>{name}</secret>")));
      }
    }
    out
  }
}

impl Redactor for Secrets {
  fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
    Self::redact(self, text)
  }

  fn is_empty(&self) -> bool {
    Self::is_empty(self)
  }
}

/// [`Redactor::redact`] over every string in a JSON document, keys
/// included: a credential used as an object key leaks exactly as readily
/// as one used as a value.
pub fn redact_json(redactor: &dyn Redactor, value: &mut serde_json::Value) {
  if redactor.is_empty() {
    return;
  }
  match value {
    serde_json::Value::String(s) => {
      if let Cow::Owned(redacted) = redactor.redact(s) {
        *s = redacted;
      }
    },
    serde_json::Value::Array(items) => {
      for item in items {
        redact_json(redactor, item);
      }
    },
    serde_json::Value::Object(map) => {
      let needs_key_rewrite = map.keys().any(|k| matches!(redactor.redact(k), Cow::Owned(_)));
      if needs_key_rewrite {
        let rewritten: serde_json::Map<String, serde_json::Value> = std::mem::take(map)
          .into_iter()
          .map(|(k, v)| (redactor.redact(&k).into_owned(), v))
          .collect();
        *map = rewritten;
      }
      for item in map.values_mut() {
        redact_json(redactor, item);
      }
    },
    _ => {},
  }
}

/// Replace `text` in place when the redactor changes it.
pub fn redact_in_place(redactor: &dyn Redactor, text: &mut String) {
  if let Cow::Owned(redacted) = redactor.redact(text) {
    *text = redacted;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn longest_secret_wins() {
    let s = Secrets::new([
      ("short".to_string(), "abc".to_string()),
      ("long".to_string(), "abcdef".to_string()),
    ]);
    assert_eq!(
      s.redact("xx abcdef yy abc"),
      "xx <secret>long</secret> yy <secret>short</secret>"
    );
  }

  #[test]
  fn json_keys_and_values_are_redacted() {
    let s = Secrets::new([("token".to_string(), "hunter2".to_string())]);
    let mut v = serde_json::json!({ "hunter2": ["hunter2", 1], "ok": "fine" });
    redact_json(&s, &mut v);
    assert_eq!(
      v,
      serde_json::json!({ "<secret>token</secret>": ["<secret>token</secret>", 1], "ok": "fine" })
    );
  }

  #[test]
  fn empty_values_are_ignored() {
    let s = Secrets::new([("unset".to_string(), String::new())]);
    assert!(s.is_empty());
    assert_eq!(s.redact("anything"), "anything");
  }
}
