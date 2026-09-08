//! The standard library a script reaches through: the Node modules and
//! the web globals. Each body loops the binding enough times that the
//! run bracket is noise, so the number is the binding's own cost --
//! argument conversion, the permission check, and the work itself.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use ferrijs::RunOptions;
use support::{granted, hosted, leak, ok, tokio_rt};

/// `(group, name, source)`.
const CASES: &[(&str, &str, &str)] = &[
  // --- node:path -------------------------------------------------------
  (
    "path",
    "join_50k",
    "const { join } = require('node:path'); let n = 0;
     for (let i = 0; i < 50000; i++) n += join('/a/b', 'c', '../d', 'e' + (i & 15)).length; return n",
  ),
  (
    "path",
    "resolve_50k",
    "const { resolve } = require('node:path'); let n = 0;
     for (let i = 0; i < 50000; i++) n += resolve('/a/b', './c/' + (i & 15)).length; return n",
  ),
  (
    "path",
    "parse_50k",
    "const { parse } = require('node:path'); let n = 0;
     for (let i = 0; i < 50000; i++) n += parse('/home/user/file' + (i & 15) + '.txt').name.length; return n",
  ),
  // --- Buffer ----------------------------------------------------------
  (
    "buffer",
    "from_utf8_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) n += Buffer.from('hello world ' + (i & 255)).length; return n",
  ),
  (
    "buffer",
    "base64_roundtrip_20k",
    "const src = Buffer.from('the quick brown fox jumps over the lazy dog'.repeat(4)); let n = 0;
     for (let i = 0; i < 20000; i++) n += Buffer.from(src.toString('base64'), 'base64').length; return n",
  ),
  (
    "buffer",
    "hex_20k",
    "const src = Buffer.from('the quick brown fox'.repeat(8)); let n = 0;
     for (let i = 0; i < 20000; i++) n += src.toString('hex').length; return n",
  ),
  (
    "buffer",
    "concat_20k",
    "const a = Buffer.from('abcdefgh'), b = Buffer.from('12345678'); let n = 0;
     for (let i = 0; i < 20000; i++) n += Buffer.concat([a, b, a]).length; return n",
  ),
  // --- text codecs -----------------------------------------------------
  (
    "text",
    "encode_50k",
    "const enc = new TextEncoder(); let n = 0;
     for (let i = 0; i < 50000; i++) n += enc.encode('hello world ' + (i & 255)).length; return n",
  ),
  (
    "text",
    "decode_50k",
    "const enc = new TextEncoder(), dec = new TextDecoder();
     const bytes = enc.encode('the quick brown fox jumps over the lazy dog'.repeat(4)); let n = 0;
     for (let i = 0; i < 50000; i++) n += dec.decode(bytes).length; return n",
  ),
  (
    "text",
    "atob_btoa_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) n += atob(btoa('payload-' + (i & 255))).length; return n",
  ),
  // --- crypto ----------------------------------------------------------
  (
    "crypto",
    "sha256_20k",
    "const { createHash } = require('node:crypto'); const data = 'x'.repeat(256); let n = 0;
     for (let i = 0; i < 20000; i++) n += createHash('sha256').update(data).digest('hex').length; return n",
  ),
  (
    "crypto",
    "randomUUID_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) n += crypto.randomUUID().length; return n",
  ),
  (
    "crypto",
    "getRandomValues_20k",
    "const a = new Uint8Array(32); let n = 0; for (let i = 0; i < 20000; i++) n += crypto.getRandomValues(a)[0]; return n",
  ),
  // --- URL -------------------------------------------------------------
  (
    "url",
    "parse_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) n += new URL('https://example.com/a/b?c=' + i + '#frag').pathname.length; return n",
  ),
  (
    "url",
    "search_params_20k",
    "let n = 0; for (let i = 0; i < 20000; i++) { const p = new URLSearchParams('a=1&b=2&c=' + i); p.set('d', '4'); n += p.toString().length; } return n",
  ),
  // --- util / inspect --------------------------------------------------
  (
    "util",
    "inspect_20k",
    "const { inspect } = require('node:util');
     const o = { a: 1, b: 'two', c: [1, 2, 3], d: { e: true, f: null } }; let n = 0;
     for (let i = 0; i < 20000; i++) n += inspect(o).length; return n",
  ),
  (
    "util",
    "format_20k",
    "const { format } = require('node:util'); let n = 0;
     for (let i = 0; i < 20000; i++) n += format('%s has %d items: %j', 'list', i, [1, 2]).length; return n",
  ),
  // --- events ----------------------------------------------------------
  (
    "events",
    "emit_100k",
    "const { EventEmitter } = require('node:events'); const e = new EventEmitter(); let n = 0;
     e.on('tick', (v) => { n += v; }); for (let i = 0; i < 100000; i++) e.emit('tick', 1); return n",
  ),
  // --- structuredClone -------------------------------------------------
  (
    "web",
    "structured_clone_20k",
    "const o = { a: 1, b: 'two', c: [1, 2, 3], d: { e: new Date(0) } }; let n = 0;
     for (let i = 0; i < 20000; i++) n += Object.keys(structuredClone(o)).length; return n",
  ),
  // --- assert ----------------------------------------------------------
  (
    "assert",
    "deep_equal_20k",
    "const assert = require('node:assert');
     const a = { x: [1, 2, 3], y: { z: 'v' } }, b = { x: [1, 2, 3], y: { z: 'v' } }; let n = 0;
     for (let i = 0; i < 20000; i++) { assert.deepStrictEqual(a, b); n++; } return n",
  ),
  // --- zlib ------------------------------------------------------------
  (
    "zlib",
    "gzip_roundtrip_2k",
    "const { gzipSync, gunzipSync } = require('node:zlib');
     const data = Buffer.from('the quick brown fox jumps over the lazy dog '.repeat(32)); let n = 0;
     for (let i = 0; i < 2000; i++) n += gunzipSync(gzipSync(data)).length; return n",
  ),
  // --- timers ----------------------------------------------------------
  (
    "timers",
    "set_timeout_0_x5k",
    "let n = 0; for (let i = 0; i < 5000; i++) await new Promise(r => setTimeout(() => { n++; r(); }, 0)); return n",
  ),
  (
    "timers",
    "queue_and_drain_5k",
    "let n = 0; await new Promise(done => {
       for (let i = 0; i < 5000; i++) setTimeout(() => { if (++n === 5000) done(); }, 0);
     }); return n",
  ),
  // --- process ---------------------------------------------------------
  (
    "process",
    "hrtime_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) n += process.hrtime.bigint() > 0n ? 1 : 0; return n",
  ),
  // --- performance -----------------------------------------------------
  (
    "perf",
    "now_100k",
    "let n = 0; for (let i = 0; i < 100000; i++) n += performance.now() >= 0 ? 1 : 0; return n",
  ),
  // --- Date ------------------------------------------------------------
  (
    "date",
    "now_100k",
    "let n = 0; for (let i = 0; i < 100000; i++) n += Date.now() > 0 ? 1 : 0; return n",
  ),
  (
    "date",
    "to_iso_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) n += new Date(1700000000000 + i).toISOString().length; return n",
  ),
];

fn stdlib(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm = rt.block_on(granted());

  let realm: &'static ferrijs::Runtime = leak(realm);
  let mut groups: Vec<&str> = Vec::new();
  for (grp, _, _) in CASES {
    if !groups.contains(grp) {
      groups.push(grp);
    }
  }
  for grp in groups {
    let mut g = c.benchmark_group(format!("std_{grp}"));
    g.sample_size(20);
    for (cg, name, source) in CASES.iter().filter(|(cg, _, _)| *cg == grp) {
      let probe = rt.block_on(realm.eval_script(source, &[], RunOptions::default()));
      if let Some(e) = probe.err() {
        // A case the standard library cannot serve is a gap, not a
        // measurement: report it and keep going so one missing binding
        // does not hide the rest of the suite.
        eprintln!("SKIP {cg}/{name}: {e}");
        continue;
      }
      g.bench_function(*name, |b| {
        b.to_async(&rt).iter_custom(|iters| {
          hosted(iters, move || async move {
            ok(realm.eval_script(source, &[], RunOptions::default()).await)
          })
        });
      });
    }
    g.finish();
  }
}

criterion_group!(benches, stdlib);
criterion_main!(benches);
