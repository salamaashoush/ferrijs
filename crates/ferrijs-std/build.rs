//! Wraps the vendored `readable-stream` (`js/readable-stream/lib`) into
//! one ES module that `node:stream` compiles to bytecode at run time.
//!
//! Each CommonJS file becomes a function in a table keyed by its path,
//! and a small `require` resolves the relative paths between them. The
//! names that leave the package go to a function the realm supplies, so
//! `buffer` and `events` are the realm's own modules. The output depends
//! only on the vendored files, sorted, so it is the same on every build.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
  let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("js/readable-stream");
  println!("cargo:rerun-if-changed={}", root.display());

  let mut files = Vec::new();
  collect(&root.join("lib"), &mut files);
  files.sort();

  let mut out = String::from(
    "export default function load(external) {\n  const sources = {\n",
  );
  for file in &files {
    let key = file
      .strip_prefix(&root)
      .expect("vendored file under the package root")
      .to_string_lossy()
      .replace('\\', "/");
    let source = std::fs::read_to_string(file).expect("vendored source is UTF-8");
    let _ = writeln!(
      out,
      "    {key:?}: function (module, exports, require) {{\n{source}\n    }},"
    );
  }
  out.push_str(
    r#"  };
  const cache = {};
  const dirname = (path) => path.slice(0, path.lastIndexOf('/'));
  const join = (base, relative) => {
    const parts = base.split('/');
    for (const part of relative.split('/')) {
      if (part === '..') parts.pop();
      else if (part !== '.' && part !== '') parts.push(part);
    }
    return parts.join('/');
  };
  const resolve = (from, request) => {
    const base = join(dirname(from), request);
    for (const candidate of [base, base + '.js', base + '/index.js']) {
      if (candidate in sources) return candidate;
    }
    throw new Error('readable-stream: cannot resolve ' + request + ' from ' + from);
  };
  const run = (path) => {
    if (path in cache) return cache[path].exports;
    const module = { exports: {} };
    cache[path] = module;
    sources[path].call(module.exports, module, module.exports, (request) =>
      request.startsWith('.') ? run(resolve(path, request)) : external(request.replace(/\/$/, ''))
    );
    return module.exports;
  };
  return { stream: run('lib/stream.js'), promises: run('lib/stream/promises.js') };
}
"#,
  );

  let dest = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("readable_stream.mjs");
  std::fs::write(dest, out).expect("write the wrapped module");
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
  for entry in std::fs::read_dir(dir).expect("vendored directory") {
    let path = entry.expect("directory entry").path();
    if path.is_dir() {
      collect(&path, files);
    } else if path.extension().is_some_and(|e| e == "js") {
      files.push(path);
    }
  }
}
