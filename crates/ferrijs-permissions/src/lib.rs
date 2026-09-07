//! What a script is allowed to do, decided in one place.
//!
//! `QuickJS` itself has no ambient authority: a fresh realm can compute
//! and nothing else. Everything a script can reach beyond that — a file,
//! a socket, an environment variable, a fact about the host — is a
//! capability the embedding runtime installed, and every one of those
//! installs asks this crate before acting. Deny is the default for each
//! kind; a host grants the least it can.
//!
//! The model is Deno's and Node's, which are the two that survived:
//!
//! - [`Permissions`] is the policy: five kinds ([`Kind`]), each a
//!   [`Allow`] of none, everything, or a list, plus a [`Deny`] list per
//!   kind that overrides the allow (`read: all, deny read: /etc`).
//! - [`Container`] holds the policy for ONE realm for the realm's whole
//!   life. It can only ever narrow ([`Container::revoke`], irreversible,
//!   like Node's `process.permission.drop` and Deno's `revoke`). It also
//!   carries a [`Hook`] the host may install to grant on demand (a
//!   prompt) and an [`Audit`] that sees every decision.
//!
//! What the model deliberately does NOT have is a dynamic scope: no
//! "narrow the policy around this call and carry it into the callbacks
//! it registers". That is Java's stack-inspection Security Manager,
//! removed by JEP 411 as brittle, slow, and impossible to keep complete
//! across an API surface. A host with two trust levels runs them in two
//! realms, each with its own container, the way workerd gives each
//! isolate its own bindings.
//!
//! Paths are checked twice: as written, after lexical normalisation, and
//! as the filesystem will actually resolve them, after following every
//! symlink in the longest existing prefix. Both must fall under a
//! granted root, so a link planted inside an allowed directory cannot
//! point out of it. Node documents the opposite (links are followed out)
//! as a hazard the operator must avoid; this does not leave it to them.

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// One capability kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Kind {
  /// Reading a file or directory, including `stat` and `readdir`.
  Read,
  /// Creating, writing, renaming, removing or changing the mode of a
  /// file or directory.
  Write,
  /// Opening a connection to a host.
  Net,
  /// Reading an environment variable.
  Env,
  /// Learning something about the host: its name, addresses, users,
  /// load, memory.
  Sys,
}

impl Kind {
  #[must_use]
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Read => "read",
      Self::Write => "write",
      Self::Net => "net",
      Self::Env => "env",
      Self::Sys => "sys",
    }
  }
}

impl fmt::Display for Kind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

/// A grant for one kind: nothing, everything, or exactly these.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Allow<T> {
  /// Every request of this kind is refused.
  #[default]
  None,
  /// Every request of this kind is granted.
  All,
  /// A request is granted when one entry matches it.
  Only(Vec<T>),
}

impl<T> Allow<T> {
  #[must_use]
  pub fn is_all(&self) -> bool {
    matches!(self, Self::All)
  }

  #[must_use]
  pub fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }

  /// The entries of an `Only`, empty for the other two.
  #[must_use]
  pub fn entries(&self) -> &[T] {
    match self {
      Self::Only(list) => list,
      _ => &[],
    }
  }

  fn map<U>(self, f: impl FnMut(T) -> U) -> Allow<U> {
    match self {
      Self::None => Allow::None,
      Self::All => Allow::All,
      Self::Only(list) => Allow::Only(list.into_iter().map(f).collect()),
    }
  }

  /// A grant no wider than either side.
  ///
  /// Two lists intersect by keeping, from each side, the entries the
  /// other side covers in full; `subsumes(a, b)` says whether `a` grants
  /// everything `b` grants.
  fn intersect_with(&self, other: &Self, subsumes: impl Fn(&T, &T) -> bool) -> Self
  where
    T: Clone + PartialEq,
  {
    match (self, other) {
      (Self::None, _) | (_, Self::None) => Self::None,
      (Self::All, o) => o.clone(),
      (s, Self::All) => s.clone(),
      (Self::Only(mine), Self::Only(theirs)) => {
        let mut kept: Vec<T> = mine
          .iter()
          .filter(|e| theirs.iter().any(|t| subsumes(t, e)))
          .cloned()
          .collect();
        for e in theirs {
          if mine.iter().any(|m| subsumes(m, e)) && !kept.contains(e) {
            kept.push(e.clone());
          }
        }
        Self::Only(kept)
      },
    }
  }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for Allow<T> {
  fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
    match self {
      Self::None => s.serialize_bool(false),
      Self::All => s.serialize_bool(true),
      Self::Only(list) => list.serialize(s),
    }
  }
}

#[cfg(feature = "serde")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Allow<T> {
  fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Repr<T> {
      Flag(bool),
      List(Vec<T>),
    }
    Ok(match Repr::<T>::deserialize(d)? {
      Repr::Flag(true) => Self::All,
      Repr::Flag(false) => Self::None,
      Repr::List(list) => Self::Only(list),
    })
  }
}

/// A directory (or file) a `read` / `write` grant covers, with
/// everything under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
  /// The root as the host wrote it, made absolute and normalised.
  lexical: PathBuf,
  /// The root as the filesystem resolves it. Equal to `lexical` when no
  /// symlink is involved or the root does not exist yet.
  resolved: PathBuf,
}

impl PathRule {
  /// Anchor a root. A relative path is taken against the current
  /// directory at construction time, so a policy read from a config
  /// file means the same thing for the process's whole life.
  #[must_use]
  pub fn new(root: impl AsRef<Path>) -> Self {
    let lexical = normalize(&absolute(root.as_ref()));
    let resolved = resolve_existing(&lexical);
    Self { lexical, resolved }
  }

  #[must_use]
  pub fn root(&self) -> &Path {
    &self.lexical
  }

  fn covers(&self, candidate: &CheckedPath) -> bool {
    candidate.lexical.starts_with(&self.lexical) && candidate.resolved.starts_with(&self.resolved)
  }
}

impl<P: AsRef<Path>> From<P> for PathRule {
  fn from(p: P) -> Self {
    Self::new(p)
  }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PathRule {
  fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
    self.lexical.serialize(s)
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PathRule {
  fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    PathBuf::deserialize(d).map(Self::new)
  }
}

/// A path as a check sees it: both spellings a rule must cover.
struct CheckedPath {
  lexical: PathBuf,
  resolved: PathBuf,
}

impl CheckedPath {
  fn new(path: &Path) -> Self {
    let lexical = normalize(&absolute(path));
    let resolved = resolve_existing(&lexical);
    Self { lexical, resolved }
  }
}

fn absolute(path: &Path) -> PathBuf {
  if path.is_absolute() {
    path.to_path_buf()
  } else {
    std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
  }
}

/// Collapse `.` and `..` without touching the filesystem. A `..` that
/// would climb above the root stays at the root, which is what the OS
/// does too.
fn normalize(path: &Path) -> PathBuf {
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

/// Canonicalise the longest prefix that exists and re-append the rest,
/// so a path that does not exist yet (a file about to be written) is
/// still judged by where its directory really is.
fn resolve_existing(path: &Path) -> PathBuf {
  let mut existing = path.to_path_buf();
  let mut rest: Vec<std::ffi::OsString> = Vec::new();
  loop {
    if let Ok(canonical) = std::fs::canonicalize(&existing) {
      let mut out = canonical;
      for part in rest.iter().rev() {
        out.push(part);
      }
      return out;
    }
    match existing.file_name() {
      Some(name) => {
        rest.push(name.to_os_string());
        if !existing.pop() {
          break;
        }
      },
      None => break,
    }
  }
  path.to_path_buf()
}

/// A host (and optionally a port) a `net` grant covers.
///
/// Spelled the way an allow-list entry is written: `api.example.com`,
/// `*.example.com` (which also covers the bare `example.com`),
/// `127.0.0.1:8080`, `[::1]:443`. No port means any port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRule {
  host: String,
  port: Option<u16>,
}

impl NetRule {
  /// Parse an allow-list entry.
  ///
  /// # Errors
  ///
  /// An empty host, a port that is not a number, or a wildcard with no
  /// suffix.
  pub fn parse(entry: &str) -> Result<Self, String> {
    let entry = entry.trim();
    if entry.is_empty() {
      return Err("empty network rule".to_string());
    }
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
      // Bracketed IPv6, optionally followed by `:port`.
      let (addr, after) = rest
        .split_once(']')
        .ok_or_else(|| format!("network rule `{entry}`: unterminated IPv6 literal"))?;
      let port = match after.strip_prefix(':') {
        Some(p) => Some(parse_port(entry, p)?),
        None if after.is_empty() => None,
        None => return Err(format!("network rule `{entry}`: unexpected `{after}` after address")),
      };
      (addr.to_string(), port)
    } else if entry.matches(':').count() > 1 {
      // Bare IPv6 with no port.
      (entry.to_string(), None)
    } else if let Some((host, port)) = entry.rsplit_once(':') {
      (host.to_string(), Some(parse_port(entry, port)?))
    } else {
      (entry.to_string(), None)
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host == "*." {
      return Err(format!("network rule `{entry}`: empty host"));
    }
    Ok(Self { host, port })
  }

  #[must_use]
  pub fn host(&self) -> &str {
    &self.host
  }

  #[must_use]
  pub fn port(&self) -> Option<u16> {
    self.port
  }

  fn covers(&self, host: &str, port: Option<u16>) -> bool {
    let host_ok = if self.host == host {
      true
    } else if let Some(suffix) = self.host.strip_prefix("*.") {
      host == suffix || host.strip_suffix(suffix).is_some_and(|prefix| prefix.ends_with('.'))
    } else {
      false
    };
    host_ok && self.port.is_none_or(|p| port == Some(p))
  }

  /// Whether `other` would be granted by this rule in full, which is
  /// what makes it a subset when intersecting two lists.
  fn subsumes(&self, other: &Self) -> bool {
    let host_ok = if self.host == other.host {
      true
    } else if let Some(suffix) = self.host.strip_prefix("*.") {
      other.host == suffix
        || other
          .host
          .strip_suffix(suffix)
          .is_some_and(|prefix| prefix.ends_with('.'))
        || other.host.strip_prefix("*.").is_some_and(|other_suffix| {
          other_suffix == suffix
            || other_suffix
              .strip_suffix(suffix)
              .is_some_and(|prefix| prefix.ends_with('.'))
        })
    } else {
      false
    };
    host_ok && (self.port.is_none() || self.port == other.port)
  }
}

fn parse_port(entry: &str, port: &str) -> Result<u16, String> {
  port
    .parse::<u16>()
    .map_err(|_| format!("network rule `{entry}`: `{port}` is not a port"))
}

impl fmt::Display for NetRule {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let bracket = self.host.contains(':');
    match (bracket, self.port) {
      (true, Some(p)) => write!(f, "[{}]:{p}", self.host),
      (true, None) => write!(f, "{}", self.host),
      (false, Some(p)) => write!(f, "{}:{p}", self.host),
      (false, None) => f.write_str(&self.host),
    }
  }
}

impl std::str::FromStr for NetRule {
  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::parse(s)
  }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NetRule {
  fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(self)
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NetRule {
  fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    let s = String::deserialize(d)?;
    Self::parse(&s).map_err(serde::de::Error::custom)
  }
}

/// One fact about the host a `sys` grant can cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum SysInfo {
  Hostname,
  OsRelease,
  OsUptime,
  LoadAvg,
  NetworkInterfaces,
  SystemMemory,
  Uid,
  Gid,
  Username,
  Cpus,
  HomeDir,
  /// Reading or changing scheduling priority.
  Priority,
}

impl SysInfo {
  #[must_use]
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Hostname => "hostname",
      Self::OsRelease => "osRelease",
      Self::OsUptime => "osUptime",
      Self::LoadAvg => "loadavg",
      Self::NetworkInterfaces => "networkInterfaces",
      Self::SystemMemory => "systemMemoryInfo",
      Self::Uid => "uid",
      Self::Gid => "gid",
      Self::Username => "username",
      Self::Cpus => "cpus",
      Self::HomeDir => "homedir",
      Self::Priority => "priority",
    }
  }
}

impl fmt::Display for SysInfo {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

/// What a grant carves out. A denial wins over any allow of the same
/// kind, so a broad grant can exclude its sensitive corners:
/// `read: All` with `deny.read: ["/etc"]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "camelCase"))]
pub struct Deny {
  pub read: Vec<PathRule>,
  pub write: Vec<PathRule>,
  pub net: Vec<NetRule>,
  pub env: Vec<String>,
  pub sys: Vec<SysInfo>,
}

impl Deny {
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.read.is_empty() && self.write.is_empty() && self.net.is_empty() && self.env.is_empty() && self.sys.is_empty()
  }

  fn merged(&self, other: &Self) -> Self {
    fn union<T: Clone + PartialEq>(a: &[T], b: &[T]) -> Vec<T> {
      let mut out = a.to_vec();
      for item in b {
        if !out.contains(item) {
          out.push(item.clone());
        }
      }
      out
    }
    Self {
      read: union(&self.read, &other.read),
      write: union(&self.write, &other.write),
      net: union(&self.net, &other.net),
      env: union(&self.env, &other.env),
      sys: union(&self.sys, &other.sys),
    }
  }
}

/// The policy for one realm.
///
/// `Default` grants nothing. [`Permissions::all`] grants everything, for
/// a host whose scripts are as trusted as the host itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "camelCase"))]
pub struct Permissions {
  pub read: Allow<PathRule>,
  pub write: Allow<PathRule>,
  pub net: Allow<NetRule>,
  pub env: Allow<String>,
  pub sys: Allow<SysInfo>,
  #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Deny::is_empty"))]
  pub deny: Deny,
}

impl Permissions {
  /// Nothing granted.
  #[must_use]
  pub fn none() -> Self {
    Self::default()
  }

  /// Everything granted.
  #[must_use]
  pub fn all() -> Self {
    Self {
      read: Allow::All,
      write: Allow::All,
      net: Allow::All,
      env: Allow::All,
      sys: Allow::All,
      deny: Deny::default(),
    }
  }

  #[must_use]
  pub fn allow_read<I, P>(mut self, roots: I) -> Self
  where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
  {
    self.read = Allow::Only(roots.into_iter().map(PathRule::new).collect());
    self
  }

  #[must_use]
  pub fn allow_write<I, P>(mut self, roots: I) -> Self
  where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
  {
    self.write = Allow::Only(roots.into_iter().map(PathRule::new).collect());
    self
  }

  /// Grant these hosts. An entry that does not parse is reported rather
  /// than dropped: a typo in an allow-list must not widen or narrow it
  /// silently.
  ///
  /// # Errors
  ///
  /// The first entry [`NetRule::parse`] refuses.
  pub fn allow_net<I, S>(mut self, hosts: I) -> Result<Self, String>
  where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
  {
    let rules = hosts
      .into_iter()
      .map(|h| NetRule::parse(h.as_ref()))
      .collect::<Result<Vec<_>, _>>()?;
    self.net = Allow::Only(rules);
    Ok(self)
  }

  #[must_use]
  pub fn allow_env<I, S>(mut self, names: I) -> Self
  where
    I: IntoIterator<Item = S>,
    S: Into<String>,
  {
    self.env = Allow::Only(names.into_iter().map(Into::into).collect());
    self
  }

  #[must_use]
  pub fn allow_sys<I>(mut self, items: I) -> Self
  where
    I: IntoIterator<Item = SysInfo>,
  {
    self.sys = Allow::Only(items.into_iter().collect());
    self
  }

  #[must_use]
  pub fn allow_all_read(mut self) -> Self {
    self.read = Allow::All;
    self
  }

  #[must_use]
  pub fn allow_all_write(mut self) -> Self {
    self.write = Allow::All;
    self
  }

  #[must_use]
  pub fn allow_all_net(mut self) -> Self {
    self.net = Allow::All;
    self
  }

  #[must_use]
  pub fn allow_all_env(mut self) -> Self {
    self.env = Allow::All;
    self
  }

  #[must_use]
  pub fn allow_all_sys(mut self) -> Self {
    self.sys = Allow::All;
    self
  }

  #[must_use]
  pub fn deny_read<I, P>(mut self, roots: I) -> Self
  where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
  {
    self.deny.read.extend(roots.into_iter().map(PathRule::new));
    self
  }

  #[must_use]
  pub fn deny_write<I, P>(mut self, roots: I) -> Self
  where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
  {
    self.deny.write.extend(roots.into_iter().map(PathRule::new));
    self
  }

  /// # Errors
  ///
  /// The first entry [`NetRule::parse`] refuses.
  pub fn deny_net<I, S>(mut self, hosts: I) -> Result<Self, String>
  where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
  {
    for host in hosts {
      self.deny.net.push(NetRule::parse(host.as_ref())?);
    }
    Ok(self)
  }

  #[must_use]
  pub fn deny_env<I, S>(mut self, names: I) -> Self
  where
    I: IntoIterator<Item = S>,
    S: Into<String>,
  {
    self.deny.env.extend(names.into_iter().map(Into::into));
    self
  }

  #[must_use]
  pub fn deny_sys<I>(mut self, items: I) -> Self
  where
    I: IntoIterator<Item = SysInfo>,
  {
    self.deny.sys.extend(items);
    self
  }

  /// The grant for one kind, as an untyped view for reporting.
  #[must_use]
  pub fn describe(&self, kind: Kind) -> String {
    fn render<T: fmt::Display>(allow: &Allow<T>) -> String {
      match allow {
        Allow::None => "none".to_string(),
        Allow::All => "all".to_string(),
        Allow::Only(list) => list.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
      }
    }
    match kind {
      Kind::Read => render(&self.read.clone().map(|r| r.lexical.display().to_string())),
      Kind::Write => render(&self.write.clone().map(|r| r.lexical.display().to_string())),
      Kind::Net => render(&self.net),
      Kind::Env => render(&self.env),
      Kind::Sys => render(&self.sys),
    }
  }

  /// A policy no wider than either side, kind by kind.
  #[must_use]
  pub fn intersect(&self, other: &Self) -> Self {
    let path_subsumes =
      |a: &PathRule, b: &PathRule| b.lexical.starts_with(&a.lexical) && b.resolved.starts_with(&a.resolved);
    Self {
      read: self.read.intersect_with(&other.read, path_subsumes),
      write: self.write.intersect_with(&other.write, path_subsumes),
      net: self.net.intersect_with(&other.net, NetRule::subsumes),
      env: self.env.intersect_with(&other.env, |a, b| a == b),
      sys: self.sys.intersect_with(&other.sys, |a, b| a == b),
      deny: self.deny.merged(&other.deny),
    }
  }

  /// # Errors
  ///
  /// [`Denied`] naming the path.
  pub fn check_read(&self, path: &Path) -> Result<(), Denied> {
    check_path(Kind::Read, &self.read, &self.deny.read, path)
  }

  /// # Errors
  ///
  /// [`Denied`] naming the path.
  pub fn check_write(&self, path: &Path) -> Result<(), Denied> {
    check_path(Kind::Write, &self.write, &self.deny.write, path)
  }

  /// `port` is the port the connection will use, so a caller passes the
  /// scheme default when the URL names none.
  ///
  /// # Errors
  ///
  /// [`Denied`] naming `host:port`.
  pub fn check_net(&self, host: &str, port: Option<u16>) -> Result<(), Denied> {
    let host = host.to_ascii_lowercase();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let denied = self.deny.net.iter().any(|r| r.covers(host, port));
    let granted = !denied
      && match &self.net {
        Allow::None => false,
        Allow::All => true,
        Allow::Only(rules) => rules.iter().any(|r| r.covers(host, port)),
      };
    if granted {
      Ok(())
    } else {
      let resource = match port {
        Some(p) if host.contains(':') => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
      };
      Err(Denied::new(Kind::Net, resource))
    }
  }

  /// # Errors
  ///
  /// [`Denied`] naming the variable.
  pub fn check_env(&self, name: &str) -> Result<(), Denied> {
    let granted = !self.deny.env.iter().any(|n| n == name)
      && match &self.env {
        Allow::None => false,
        Allow::All => true,
        Allow::Only(names) => names.iter().any(|n| n == name),
      };
    if granted {
      Ok(())
    } else {
      Err(Denied::new(Kind::Env, name))
    }
  }

  /// # Errors
  ///
  /// [`Denied`] naming the item.
  pub fn check_sys(&self, item: SysInfo) -> Result<(), Denied> {
    let granted = !self.deny.sys.contains(&item)
      && match &self.sys {
        Allow::None => false,
        Allow::All => true,
        Allow::Only(items) => items.contains(&item),
      };
    if granted {
      Ok(())
    } else {
      Err(Denied::new(Kind::Sys, item.as_str()))
    }
  }

  /// The process environment reduced to this policy's `env` grant, in
  /// name order. What a host hands to `process.env`.
  #[must_use]
  pub fn env_snapshot(&self) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = match &self.env {
      Allow::None => Vec::new(),
      Allow::All => std::env::vars().collect(),
      Allow::Only(names) => names
        .iter()
        .filter_map(|n| std::env::var(n).ok().map(|v| (n.clone(), v)))
        .collect(),
    };
    out.retain(|(name, _)| !self.deny.env.contains(name));
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out
  }
}

fn check_path(kind: Kind, allow: &Allow<PathRule>, deny: &[PathRule], path: &Path) -> Result<(), Denied> {
  let granted = match allow {
    Allow::None => false,
    Allow::All if deny.is_empty() => true,
    _ => {
      let candidate = CheckedPath::new(path);
      let denied = deny.iter().any(|r| r.covers(&candidate));
      !denied
        && match allow {
          Allow::All => true,
          Allow::Only(rules) => rules.iter().any(|r| r.covers(&candidate)),
          Allow::None => false,
        }
    },
  };
  if granted {
    Ok(())
  } else {
    Err(Denied::new(kind, path.display().to_string()))
  }
}

/// A refused request. Carries what Node's `ERR_ACCESS_DENIED` carries:
/// the kind and the resource, so a host can render either its own
/// message or Node's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
  pub kind: Kind,
  pub resource: String,
}

impl Denied {
  #[must_use]
  pub fn new(kind: Kind, resource: impl Into<String>) -> Self {
    Self {
      kind,
      resource: resource.into(),
    }
  }

  /// Node's error code for a permission-model refusal.
  pub const CODE: &'static str = "ERR_ACCESS_DENIED";

  /// The name the thrown JS error carries.
  pub const NAME: &'static str = "PermissionDeniedError";
}

impl fmt::Display for Denied {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let what = match self.kind {
      Kind::Read => "read access to",
      Kind::Write => "write access to",
      Kind::Net => "network access to",
      Kind::Env => "access to environment variable",
      Kind::Sys => "access to host information",
    };
    write!(
      f,
      "permission denied: {what} \"{}\" (grant `{}` to allow it)",
      self.resource, self.kind
    )
  }
}

impl std::error::Error for Denied {}

/// A request the policy refused, offered to the [`Hook`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
  pub kind: Kind,
  pub resource: Cow<'a, str>,
}

/// What a [`Hook`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
  Allow,
  Deny,
}

/// A host's say in a request the static policy refused: a prompt, a
/// policy computed at call time, a one-shot grant. Called on the VM
/// thread, synchronously, inside the operation that asked, so it must
/// answer quickly.
pub trait Hook: Send + Sync {
  fn decide(&self, request: &Request<'_>) -> Decision;
}

impl<F> Hook for F
where
  F: Fn(&Request<'_>) -> Decision + Send + Sync,
{
  fn decide(&self, request: &Request<'_>) -> Decision {
    self(request)
  }
}

/// Sees every decision, granted or not.
pub trait Audit: Send + Sync {
  fn record(&self, request: &Request<'_>, granted: bool);
}

impl<F> Audit for F
where
  F: Fn(&Request<'_>, bool) + Send + Sync,
{
  fn record(&self, request: &Request<'_>, granted: bool) {
    self(request, granted);
  }
}

/// The policy for one realm, plus the hook and audit the host attached.
///
/// Every check goes through here. The policy can only ever get
/// narrower: [`Container::revoke`] intersects it with what remains,
/// and nothing widens it except the [`Hook`], case by case.
pub struct Container {
  policy: std::sync::RwLock<Arc<Permissions>>,
  hook: Option<Arc<dyn Hook>>,
  audit: Option<Arc<dyn Audit>>,
}

impl fmt::Debug for Container {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Container")
      .field("policy", &self.permissions())
      .field("hook", &self.hook.as_ref().map(|_| "..."))
      .field("audit", &self.audit.as_ref().map(|_| "..."))
      .finish()
  }
}

impl Container {
  #[must_use]
  pub fn new(policy: Permissions) -> Self {
    Self {
      policy: std::sync::RwLock::new(Arc::new(policy)),
      hook: None,
      audit: None,
    }
  }

  #[must_use]
  pub fn with_hook(mut self, hook: Arc<dyn Hook>) -> Self {
    self.hook = Some(hook);
    self
  }

  #[must_use]
  pub fn with_audit(mut self, audit: Arc<dyn Audit>) -> Self {
    self.audit = Some(audit);
    self
  }

  /// The policy in force. A snapshot: a later [`Self::revoke`] does not
  /// change the `Arc` handed out.
  #[must_use]
  pub fn permissions(&self) -> Arc<Permissions> {
    Arc::clone(&self.policy.read().unwrap_or_else(std::sync::PoisonError::into_inner))
  }

  /// Narrow the policy to what it and `remaining` both grant.
  /// Irreversible: there is no call that widens.
  pub fn revoke(&self, remaining: &Permissions) {
    let mut guard = self.policy.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Arc::new(guard.intersect(remaining));
  }

  /// Carve `resource` out of `kind` for good. `resource` is a path for
  /// `read` / `write`, a host rule for `net`, a name for `env`, a
  /// [`SysInfo`] name for `sys`.
  ///
  /// # Errors
  ///
  /// A `net` rule or `sys` name that does not parse.
  pub fn deny(&self, kind: Kind, resource: &str) -> Result<(), String> {
    let mut guard = self.policy.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut next = (**guard).clone();
    match kind {
      Kind::Read => next.deny.read.push(PathRule::new(resource)),
      Kind::Write => next.deny.write.push(PathRule::new(resource)),
      Kind::Net => next.deny.net.push(NetRule::parse(resource)?),
      Kind::Env => next.deny.env.push(resource.to_string()),
      Kind::Sys => next.deny.sys.push(sys_info_from_str(resource)?),
    }
    *guard = Arc::new(next);
    Ok(())
  }

  fn decide(&self, kind: Kind, resource: &str, statically: Result<(), Denied>) -> Result<(), Denied> {
    let request = Request {
      kind,
      resource: Cow::Borrowed(resource),
    };
    let outcome = match statically {
      Ok(()) => Ok(()),
      Err(denied) => match &self.hook {
        Some(hook) if hook.decide(&request) == Decision::Allow => Ok(()),
        _ => Err(denied),
      },
    };
    if let Some(audit) = &self.audit {
      audit.record(&request, outcome.is_ok());
    }
    outcome
  }

  /// # Errors
  ///
  /// [`Denied`] when neither the policy nor the hook grants it.
  pub fn check_read(&self, path: &Path) -> Result<(), Denied> {
    let result = self.permissions().check_read(path);
    self.decide(Kind::Read, &path.to_string_lossy(), result)
  }

  /// # Errors
  ///
  /// [`Denied`] when neither the policy nor the hook grants it.
  pub fn check_write(&self, path: &Path) -> Result<(), Denied> {
    let result = self.permissions().check_write(path);
    self.decide(Kind::Write, &path.to_string_lossy(), result)
  }

  /// # Errors
  ///
  /// [`Denied`] when neither the policy nor the hook grants it.
  pub fn check_net(&self, host: &str, port: Option<u16>) -> Result<(), Denied> {
    let result = self.permissions().check_net(host, port);
    let resource = match port {
      Some(p) => format!("{host}:{p}"),
      None => host.to_string(),
    };
    self.decide(Kind::Net, &resource, result)
  }

  /// # Errors
  ///
  /// [`Denied`] when neither the policy nor the hook grants it.
  pub fn check_env(&self, name: &str) -> Result<(), Denied> {
    let result = self.permissions().check_env(name);
    self.decide(Kind::Env, name, result)
  }

  /// # Errors
  ///
  /// [`Denied`] when neither the policy nor the hook grants it.
  pub fn check_sys(&self, item: SysInfo) -> Result<(), Denied> {
    let result = self.permissions().check_sys(item);
    self.decide(Kind::Sys, item.as_str(), result)
  }

  /// Whether `kind` covers `resource` right now, without consulting the
  /// hook or the audit: what a `has()`-style query answers. `None`
  /// asks about the kind as a whole (granted in full).
  ///
  /// # Errors
  ///
  /// A `net` rule or `sys` name that does not parse.
  pub fn has(&self, kind: Kind, resource: Option<&str>) -> Result<bool, String> {
    let policy = self.permissions();
    Ok(match (kind, resource) {
      (Kind::Read, None) => policy.read.is_all() && policy.deny.read.is_empty(),
      (Kind::Write, None) => policy.write.is_all() && policy.deny.write.is_empty(),
      (Kind::Net, None) => policy.net.is_all() && policy.deny.net.is_empty(),
      (Kind::Env, None) => policy.env.is_all() && policy.deny.env.is_empty(),
      (Kind::Sys, None) => policy.sys.is_all() && policy.deny.sys.is_empty(),
      (Kind::Read, Some(r)) => policy.check_read(Path::new(r)).is_ok(),
      (Kind::Write, Some(r)) => policy.check_write(Path::new(r)).is_ok(),
      (Kind::Net, Some(r)) => {
        let rule = NetRule::parse(r)?;
        policy.check_net(rule.host(), rule.port()).is_ok()
      },
      (Kind::Env, Some(r)) => policy.check_env(r).is_ok(),
      (Kind::Sys, Some(r)) => policy.check_sys(sys_info_from_str(r)?).is_ok(),
    })
  }
}

fn sys_info_from_str(name: &str) -> Result<SysInfo, String> {
  [
    SysInfo::Hostname,
    SysInfo::OsRelease,
    SysInfo::OsUptime,
    SysInfo::LoadAvg,
    SysInfo::NetworkInterfaces,
    SysInfo::SystemMemory,
    SysInfo::Uid,
    SysInfo::Gid,
    SysInfo::Username,
    SysInfo::Cpus,
    SysInfo::HomeDir,
    SysInfo::Priority,
  ]
  .into_iter()
  .find(|item| item.as_str() == name)
  .ok_or_else(|| format!("`{name}` is not a sys permission"))
}

impl std::str::FromStr for Kind {
  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "read" => Ok(Self::Read),
      "write" => Ok(Self::Write),
      "net" => Ok(Self::Net),
      "env" => Ok(Self::Env),
      "sys" => Ok(Self::Sys),
      other => Err(format!(
        "`{other}` is not a permission kind (read, write, net, env, sys)"
      )),
    }
  }
}

impl std::str::FromStr for SysInfo {
  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    sys_info_from_str(s)
  }
}

/// Whether an address is one of the cloud instance-metadata endpoints
/// (AWS/GCP/Azure/OpenStack IMDS on IPv4, the AWS IPv6 IMDS). They have
/// no legitimate use from a script and are the canonical SSRF target.
#[must_use]
pub fn is_metadata_ip(ip: IpAddr) -> bool {
  match canon_ip(ip) {
    IpAddr::V4(v4) => v4 == std::net::Ipv4Addr::new(169, 254, 169, 254),
    IpAddr::V6(v6) => v6 == std::net::Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
  }
}

/// Loopback, private, link-local, unique-local, carrier-grade NAT and
/// unspecified: the "internal network" set a host may choose to keep a
/// script away from.
#[must_use]
pub fn is_private_ip(ip: IpAddr) -> bool {
  match canon_ip(ip) {
    IpAddr::V4(v4) => {
      v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.octets()[0] == 0
        || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
    },
    IpAddr::V6(v6) => {
      v6.is_loopback()
        || v6.is_unspecified()
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        || (v6.segments()[0] & 0xffc0) == 0xfe80
    },
  }
}

/// An IPv4-mapped IPv6 address down to its IPv4 form, so range checks
/// see the real address.
fn canon_ip(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
    v4 @ IpAddr::V4(_) => v4,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_denies_everything() {
    let p = Permissions::none();
    assert!(p.check_read(Path::new("/etc/hosts")).is_err());
    assert!(p.check_write(Path::new("/tmp/x")).is_err());
    assert!(p.check_net("example.com", Some(443)).is_err());
    assert!(p.check_env("HOME").is_err());
    assert!(p.check_sys(SysInfo::Hostname).is_err());
  }

  #[test]
  fn all_grants_everything() {
    let p = Permissions::all();
    assert!(p.check_read(Path::new("/etc/hosts")).is_ok());
    assert!(p.check_net("example.com", None).is_ok());
    assert!(p.check_env("HOME").is_ok());
    assert!(p.check_sys(SysInfo::Uid).is_ok());
  }

  #[test]
  fn read_is_scoped_to_the_granted_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    let p = Permissions::none().allow_read([&root]);
    assert!(p.check_read(&root.join("a.txt")).is_ok());
    assert!(p.check_read(&root.join("sub/deep/b.txt")).is_ok());
    assert!(p.check_read(&root.join("../escape.txt")).is_err());
    assert!(p.check_read(dir.path()).is_err());
    // A sibling whose name merely starts with the root's name is not under it.
    assert!(p.check_read(&dir.path().join("data-other/x")).is_err());
  }

  #[test]
  fn a_relative_path_resolves_against_cwd() {
    let cwd = std::env::current_dir().unwrap();
    let p = Permissions::none().allow_read([&cwd]);
    assert!(p.check_read(Path::new("Cargo.toml")).is_ok());
    assert!(p.check_read(Path::new("../../../../../../etc/passwd")).is_err());
  }

  #[cfg(unix)]
  #[test]
  fn a_symlink_inside_the_root_cannot_point_out_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret"), b"x").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let p = Permissions::none().allow_read([&root]);
    // Lexically inside, physically outside.
    assert!(p.check_read(&root.join("link/secret")).is_err());
    // A file that does not exist yet is judged by its real directory.
    assert!(p.check_read(&root.join("link/new-file")).is_err());
    assert!(p.check_read(&root.join("plain")).is_ok());
  }

  #[cfg(unix)]
  #[test]
  fn a_root_that_is_itself_a_symlink_grants_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let p = Permissions::none().allow_read([&link]);
    assert!(p.check_read(&link.join("f")).is_ok());
  }

  #[test]
  fn net_rules_match_host_wildcard_and_port() {
    let p = Permissions::none()
      .allow_net(["api.acme.com", "*.cdn.com", "127.0.0.1:8080", "[::1]:9"])
      .unwrap();
    assert!(p.check_net("api.acme.com", Some(443)).is_ok());
    assert!(p.check_net("API.ACME.COM", None).is_ok());
    assert!(p.check_net("cdn.com", Some(80)).is_ok());
    assert!(p.check_net("a.b.cdn.com", Some(80)).is_ok());
    assert!(p.check_net("evilcdn.com", Some(80)).is_err());
    assert!(p.check_net("acme.com", Some(443)).is_err());
    assert!(p.check_net("127.0.0.1", Some(8080)).is_ok());
    assert!(p.check_net("127.0.0.1", Some(8081)).is_err());
    assert!(p.check_net("::1", Some(9)).is_ok());
    assert!(p.check_net("[::1]", Some(9)).is_ok());
    assert!(p.check_net("::1", Some(10)).is_err());
  }

  #[test]
  fn net_rule_parse_rejects_garbage() {
    assert!(NetRule::parse("").is_err());
    assert!(NetRule::parse("host:notaport").is_err());
    assert!(NetRule::parse("*.").is_err());
    assert!(NetRule::parse("[::1").is_err());
    assert_eq!(NetRule::parse("[::1]:80").unwrap().to_string(), "[::1]:80");
    assert_eq!(NetRule::parse("Example.COM").unwrap().to_string(), "example.com");
  }

  #[test]
  fn intersect_never_widens() {
    let base = Permissions::none()
      .allow_net(["*.acme.com", "cdn.com:443"])
      .unwrap()
      .allow_env(["HOME", "USER"])
      .allow_all_read();
    let declared = Permissions::none()
      .allow_net(["api.acme.com", "evil.com", "cdn.com"])
      .unwrap()
      .allow_env(["USER", "SECRET"])
      .allow_read(["/srv"]);
    let narrowed = base.intersect(&declared);
    assert!(narrowed.check_net("api.acme.com", Some(443)).is_ok());
    assert!(narrowed.check_net("evil.com", Some(443)).is_err());
    // `cdn.com` on any port, against `cdn.com:443`: the one port both grant.
    assert!(narrowed.check_net("cdn.com", Some(443)).is_ok());
    assert!(narrowed.check_net("cdn.com", Some(80)).is_err());
    assert!(narrowed.check_env("USER").is_ok());
    assert!(narrowed.check_env("HOME").is_err());
    assert!(narrowed.check_env("SECRET").is_err());
    assert!(narrowed.check_read(Path::new("/srv/x")).is_ok());
    assert!(narrowed.check_read(Path::new("/etc/x")).is_err());
    // All ∩ All stays All; None ∩ anything is None.
    assert!(Permissions::all().intersect(&Permissions::all()).write.is_all());
    assert!(Permissions::all().intersect(&Permissions::none()).write.is_none());
  }

  #[test]
  fn deny_overrides_allow() {
    let p = Permissions::all()
      .deny_read(["/etc"])
      .deny_net(["*.internal"])
      .unwrap()
      .deny_env(["SECRET"])
      .deny_sys([SysInfo::Username]);
    assert!(p.check_read(Path::new("/etc/passwd")).is_err());
    assert!(p.check_read(Path::new("/var/log")).is_ok());
    assert!(p.check_net("db.internal", Some(5432)).is_err());
    assert!(p.check_net("example.com", Some(443)).is_ok());
    assert!(p.check_env("SECRET").is_err());
    assert!(p.check_env("HOME").is_ok());
    assert!(p.check_sys(SysInfo::Username).is_err());
    assert!(p.check_sys(SysInfo::Hostname).is_ok());
    assert!(!p.env_snapshot().iter().any(|(k, _)| k == "SECRET"));
  }

  #[test]
  fn a_container_only_narrows() {
    let c = Container::new(Permissions::all());
    assert!(c.check_env("ANY").is_ok());
    assert_eq!(c.has(Kind::Env, None), Ok(true));
    c.revoke(&Permissions::all().allow_env(["ONLY"]));
    assert!(c.check_env("ONLY").is_ok());
    assert!(c.check_env("ANY").is_err());
    assert_eq!(c.has(Kind::Env, None), Ok(false));
    assert_eq!(c.has(Kind::Env, Some("ONLY")), Ok(true));
    // Revoking with a wider policy changes nothing.
    c.revoke(&Permissions::all());
    assert!(c.check_env("ANY").is_err());
    c.deny(Kind::Env, "ONLY").unwrap();
    assert!(c.check_env("ONLY").is_err());
    c.deny(Kind::Net, "*.internal").unwrap();
    assert!(c.check_net("x.internal", Some(80)).is_err());
    assert!(c.check_net("example.com", Some(80)).is_ok());
    assert_eq!(c.has(Kind::Net, Some("example.com:80")), Ok(true));
    assert!(c.deny(Kind::Sys, "nope").is_err());
  }

  #[test]
  fn hook_can_grant_and_audit_sees_both() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = Arc::clone(&seen);
    let c = Container::new(Permissions::none())
      .with_hook(Arc::new(|req: &Request<'_>| {
        if req.kind == Kind::Env && req.resource == "PROMPTED" {
          Decision::Allow
        } else {
          Decision::Deny
        }
      }))
      .with_audit(Arc::new(move |_req: &Request<'_>, _granted: bool| {
        seen2.fetch_add(1, Ordering::Relaxed);
      }));
    assert!(c.check_env("PROMPTED").is_ok());
    assert!(c.check_env("OTHER").is_err());
    assert_eq!(seen.load(Ordering::Relaxed), 2);
  }

  #[test]
  fn denied_renders_kind_and_resource() {
    let d = Denied::new(Kind::Net, "evil.com:443");
    assert_eq!(
      d.to_string(),
      "permission denied: network access to \"evil.com:443\" (grant `net` to allow it)"
    );
  }

  #[test]
  fn metadata_and_private_ranges() {
    assert!(is_metadata_ip("169.254.169.254".parse().unwrap()));
    assert!(is_metadata_ip("::ffff:169.254.169.254".parse().unwrap()));
    assert!(is_metadata_ip("fd00:ec2::254".parse().unwrap()));
    assert!(!is_metadata_ip("93.184.216.34".parse().unwrap()));
    for ip in [
      "127.0.0.1",
      "10.0.0.1",
      "192.168.1.1",
      "172.16.0.1",
      "100.64.0.1",
      "::1",
      "fe80::1",
      "fc00::1",
    ] {
      assert!(is_private_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
  }

  #[test]
  fn env_snapshot_filters_to_the_grant() {
    let p = Permissions::none().allow_env(["PATH", "FERRIJS_SURELY_UNSET_VAR"]);
    let snap = p.env_snapshot();
    assert!(snap.iter().any(|(k, _)| k == "PATH"));
    assert!(!snap.iter().any(|(k, _)| k == "FERRIJS_SURELY_UNSET_VAR"));
    assert!(Permissions::none().env_snapshot().is_empty());
  }

  #[cfg(feature = "serde")]
  #[test]
  fn serde_shape_is_bool_or_list() {
    let doc = r#"{"read": true, "write": ["/srv/out"], "net": ["*.acme.com:443"], "env": false, "sys": ["hostname"], "deny": {"read": ["/etc"]}}"#;
    let p: Permissions = serde_json::from_str(doc).unwrap();
    assert!(p.read.is_all());
    assert_eq!(p.write.entries().len(), 1);
    assert!(p.env.is_none());
    assert_eq!(p.sys.entries(), &[SysInfo::Hostname]);
    assert_eq!(p.deny.read.len(), 1);
    assert!(p.check_read(Path::new("/etc/hosts")).is_err());
    let back = serde_json::to_value(&p).unwrap();
    assert_eq!(back["read"], serde_json::Value::Bool(true));
    assert_eq!(back["net"][0], "*.acme.com:443");
    assert_eq!(back["deny"]["read"][0], "/etc");
    let plain: Permissions = serde_json::from_str(r#"{"read": true}"#).unwrap();
    assert!(serde_json::to_value(&plain).unwrap().get("deny").is_none());
  }
}
