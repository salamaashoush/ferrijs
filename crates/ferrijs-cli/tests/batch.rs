#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `ferrijs batch`: one realm per file, results in the order given.

use std::path::Path;
use std::process::Command;

fn write(dir: &Path, name: &str, source: &str) -> String {
  let path = dir.join(name);
  std::fs::write(&path, source).unwrap();
  path.to_string_lossy().into_owned()
}

fn batch(args: &[&str]) -> (bool, Vec<serde_json::Value>) {
  let out = Command::new(env!("CARGO_BIN_EXE_ferrijs"))
    .arg("batch")
    .args(args)
    .output()
    .expect("run ferrijs");
  let lines = String::from_utf8(out.stdout)
    .unwrap()
    .lines()
    .map(|line| serde_json::from_str(line).unwrap())
    .collect();
  (out.status.success(), lines)
}

#[test]
fn reports_each_file_in_order_and_fails_if_any_failed() {
  let dir = tempfile::tempdir().unwrap();
  let slow = write(
    dir.path(),
    "slow.js",
    "let n = 0; for (let i = 0; i < 2e5; i++) n += i; return n;",
  );
  let fast = write(dir.path(), "fast.js", "console.log('hi'); return 'fast';");
  let bad = write(dir.path(), "bad.js", "throw new RangeError('nope');");
  let missing = dir.path().join("missing.js").to_string_lossy().into_owned();
  let (ok, lines) = batch(&["--jobs", "4", &slow, &fast, &bad, &missing]);
  assert!(!ok);
  let files: Vec<&str> = lines.iter().map(|l| l["file"].as_str().unwrap()).collect();
  assert_eq!(files, [slow.as_str(), fast.as_str(), bad.as_str(), missing.as_str()]);
  assert_eq!(lines[0]["value"], serde_json::json!(19_999_900_000_i64));
  assert_eq!(lines[1]["value"], "fast");
  assert_eq!(lines[1]["console"][0]["message"], "hi");
  assert_eq!(lines[2]["status"], "error");
  assert_eq!(lines[2]["error"]["name"], "RangeError");
  assert_eq!(lines[3]["status"], "error");
}

#[test]
fn files_do_not_share_a_realm() {
  let dir = tempfile::tempdir().unwrap();
  let set = write(dir.path(), "set.js", "globalThis.shared = 1; return 'set';");
  let read = write(dir.path(), "read.js", "return typeof globalThis.shared;");
  let (ok, lines) = batch(&["--jobs", "1", &set, &read]);
  assert!(ok);
  assert_eq!(lines[1]["value"], "undefined");
}

#[test]
fn bundles_typescript_with_imports() {
  let dir = tempfile::tempdir().unwrap();
  write(
    dir.path(),
    "lib.ts",
    "export const twice = (n: number): number => n * 2;",
  );
  let main = write(
    dir.path(),
    "main.ts",
    "import { twice } from './lib.ts';\nexport default twice(21);",
  );
  let (ok, lines) = batch(&[&main]);
  assert!(ok, "{lines:?}");
  assert_eq!(lines[0]["value"], 42);
}
