//! Module loading from disk, under a policy.
//!
//! Scripts import other files via ES module syntax:
//!
//! ```js
//! import { helper } from './helpers.js';
//! import data from './fixtures/users.js';
//! ```
//!
//! An import path is resolved relative to the importing module's
//! directory, or to the policy's root for an inline script with no base,
//! and read from disk. Bare specifiers (`import lodash from 'lodash'`)
//! are refused: there is no node_modules resolution here on purpose. A
//! program that needs one is bundled before it reaches this loader, and
//! native specifiers never reach it either (the registry's loader is
//! chained ahead of this pair).
//!
//! With [`ModulePolicy::jail`] on, a resolution that lands outside the
//! root -- through `..`, an absolute path, or a symlink -- is refused,
//! so a script confined to a directory cannot pull code from beyond it.

use std::path::{Path, PathBuf};

use rquickjs::{Ctx, Error, Module, Result, loader::Loader, loader::Resolver, module::Declared};

/// Where relative imports resolve from, and whether they may leave it.
#[derive(Debug, Clone)]
pub struct ModulePolicy {
  /// The directory an inline script's relative import resolves against.
  pub root: PathBuf,
  /// Refuse any module whose resolved path is not under `root`. Off,
  /// the root is an anchor, not a boundary: a helper one directory up
  /// is ordinary.
  pub jail: bool,
  /// File extensions the loader reads. A file with any other extension
  /// is refused, so a stray `.json` or `.txt` never runs as code.
  pub extensions: Vec<String>,
}

impl ModulePolicy {
  /// Anchored at `root`, unjailed, serving `.js` and `.mjs`.
  #[must_use]
  pub fn new(root: impl Into<PathBuf>) -> Self {
    Self {
      root: root.into(),
      jail: false,
      extensions: vec!["js".to_string(), "mjs".to_string()],
    }
  }

  #[must_use]
  pub fn jailed(mut self) -> Self {
    self.jail = true;
    self
  }
}

impl Default for ModulePolicy {
  fn default() -> Self {
    Self::new(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
  }
}

/// Resolves relative ES module specifiers to absolute paths.
#[derive(Debug, Clone)]
pub struct FileResolver {
  policy: ModulePolicy,
  /// The root, canonicalised once, so the jail check compares like with
  /// like.
  canonical_root: PathBuf,
}

impl FileResolver {
  #[must_use]
  pub fn new(policy: ModulePolicy) -> Self {
    let canonical_root = std::fs::canonicalize(&policy.root).unwrap_or_else(|_| policy.root.clone());
    Self { policy, canonical_root }
  }

  /// Resolve `name` against `base`, falling back to the root when the
  /// importer has no directory of its own.
  ///
  /// An inline script's base is empty, and a dynamic `import()` from one
  /// carries the eval's NAME (`eval_script`) -- whose parent is the empty
  /// path, not a directory. Both mean "no importer directory", so both
  /// resolve from the root.
  fn join_relative(&self, base: &str, name: &str) -> PathBuf {
    let base_dir = Path::new(base)
      .parent()
      .filter(|parent| !parent.as_os_str().is_empty())
      .map_or_else(|| self.policy.root.clone(), Path::to_path_buf);
    base_dir.join(name)
  }
}

impl Resolver for FileResolver {
  fn resolve<'js>(
    &mut self,
    _ctx: &Ctx<'js>,
    base: &str,
    name: &str,
    _attributes: Option<rquickjs::loader::ImportAttributes<'js>>,
  ) -> Result<String> {
    if !(name.starts_with("./") || name.starts_with("../") || name.starts_with('/')) {
      return Err(Error::new_loading_message(
        name,
        "bare module specifiers are not supported; bundle the program instead",
      ));
    }

    let joined = self.join_relative(base, name);
    let resolved = std::fs::canonicalize(&joined)
      .map_err(|e| Error::new_loading_message(name, format!("cannot resolve {}: {e}", joined.display())))?;

    if self.policy.jail && !resolved.starts_with(&self.canonical_root) {
      return Err(Error::new_loading_message(
        name,
        format!(
          "module {} is outside the module root {}",
          resolved.display(),
          self.canonical_root.display()
        ),
      ));
    }

    Ok(resolved.to_string_lossy().into_owned())
  }
}

/// Reads a module the [`FileResolver`] resolved.
#[derive(Debug, Clone)]
pub struct FileLoader {
  extensions: Vec<String>,
}

impl FileLoader {
  #[must_use]
  pub fn new(policy: &ModulePolicy) -> Self {
    Self {
      extensions: policy.extensions.clone(),
    }
  }
}

impl Loader for FileLoader {
  fn load<'js>(
    &mut self,
    ctx: &Ctx<'js>,
    name: &str,
    _attributes: Option<rquickjs::loader::ImportAttributes<'js>>,
  ) -> Result<Module<'js, Declared>> {
    let path = Path::new(name);
    let allowed = path
      .extension()
      .and_then(|e| e.to_str())
      .is_some_and(|e| self.extensions.iter().any(|x| x == e));
    if !allowed {
      return Err(Error::new_loading_message(
        name,
        format!("only {} modules are supported", self.extensions.join(" / ")),
      ));
    }

    let source = std::fs::read(path).map_err(|e| Error::new_loading_message(name, e.to_string()))?;
    Module::declare(ctx.clone(), name, source)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn mk_root() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(tmp.path()).expect("canonical");
    (tmp, root)
  }

  fn with_ctx(f: impl FnOnce(Ctx<'_>)) {
    let rt = rquickjs::Runtime::new().expect("runtime");
    let cx = rquickjs::Context::full(&rt).expect("context");
    cx.with(f);
  }

  #[test]
  fn resolver_rejects_bare_specifiers() {
    let (_tmp, root) = mk_root();
    let mut r = FileResolver::new(ModulePolicy::new(root));
    with_ctx(|ctx| {
      let err = r.resolve(&ctx, "", "lodash", None).expect_err("bare specifier");
      assert!(err.to_string().contains("bare module"));
    });
  }

  #[test]
  fn resolver_answers_for_a_relative_import() {
    let (tmp, root) = mk_root();
    std::fs::write(tmp.path().join("helper.js"), b"export const x = 1;").expect("write");
    let mut r = FileResolver::new(ModulePolicy::new(root.clone()));
    with_ctx(|ctx| {
      let resolved = r.resolve(&ctx, "", "./helper.js", None).expect("resolve");
      assert_eq!(PathBuf::from(resolved), root.join("helper.js"));
    });
  }

  /// Unjailed, a relative import that climbs out of the root resolves
  /// like any other path: the root is an anchor, not a boundary.
  #[test]
  fn resolver_follows_a_parent_import_when_unjailed() {
    let (tmp, root) = mk_root();
    let nested = tmp.path().join("specs");
    std::fs::create_dir_all(&nested).expect("mkdir");
    std::fs::write(tmp.path().join("shared.js"), b"export const x = 1;").expect("write");
    let mut r = FileResolver::new(ModulePolicy::new(nested.clone()));
    with_ctx(|ctx| {
      let base = nested.join("a.js").to_string_lossy().into_owned();
      let resolved = r.resolve(&ctx, &base, "../shared.js", None).expect("resolve");
      assert_eq!(PathBuf::from(resolved), root.join("shared.js"));
    });
  }

  #[cfg(unix)]
  #[test]
  fn jail_refuses_parent_absolute_and_symlinked_escapes() {
    let (tmp, root) = mk_root();
    let inside = root.join("inside");
    std::fs::create_dir_all(&inside).expect("mkdir");
    std::fs::write(root.join("outside.js"), b"export const x = 1;").expect("write");
    std::fs::write(inside.join("ok.js"), b"export const x = 1;").expect("write");
    std::os::unix::fs::symlink(root.join("outside.js"), inside.join("link.js")).expect("symlink");
    let mut r = FileResolver::new(ModulePolicy::new(inside.clone()).jailed());
    with_ctx(|ctx| {
      assert!(r.resolve(&ctx, "", "./ok.js", None).is_ok());
      assert!(r.resolve(&ctx, "", "../outside.js", None).is_err());
      assert!(r.resolve(&ctx, "", "./link.js", None).is_err());
      let abs = root.join("outside.js").to_string_lossy().into_owned();
      assert!(r.resolve(&ctx, "", &abs, None).is_err());
    });
    let _ = tmp;
  }

  #[test]
  fn loader_refuses_other_extensions() {
    let (tmp, _root) = mk_root();
    let file = tmp.path().join("data.json");
    std::fs::write(&file, b"{}").expect("write");
    let mut l = FileLoader::new(&ModulePolicy::default());
    with_ctx(|ctx| {
      assert!(l.load(&ctx, &file.to_string_lossy(), None).is_err());
    });
  }
}
