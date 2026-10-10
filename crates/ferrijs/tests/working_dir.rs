#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The default module policy anchors at the working directory, which is
//! remembered between realms. This file is its own test binary because
//! it changes the process's working directory.

use ferrijs::ModulePolicy;

fn root() -> std::path::PathBuf {
  std::fs::canonicalize(ModulePolicy::default().root).unwrap()
}

#[test]
fn the_default_root_follows_a_chdir_and_a_rename() {
  let start = std::env::current_dir().unwrap();
  assert_eq!(root(), std::fs::canonicalize(&start).unwrap());
  assert_eq!(root(), std::fs::canonicalize(&start).unwrap());

  let scratch = tempfile::tempdir().unwrap();
  let first = scratch.path().join("first");
  std::fs::create_dir(&first).unwrap();
  std::env::set_current_dir(&first).unwrap();
  assert_eq!(root(), std::fs::canonicalize(&first).unwrap());

  let renamed = scratch.path().join("renamed");
  std::fs::rename(&first, &renamed).unwrap();
  assert_eq!(root(), std::fs::canonicalize(&renamed).unwrap());

  std::env::set_current_dir(&start).unwrap();
  assert_eq!(root(), std::fs::canonicalize(&start).unwrap());
}
