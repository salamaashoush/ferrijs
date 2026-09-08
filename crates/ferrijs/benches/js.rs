//! Engine throughput: the JavaScript a script actually spends its time
//! in. These numbers move with the QuickJS build (compile flags, the
//! allocator, the GC threshold) rather than with the Rust around it, so
//! they are the ones that say whether the engine itself got faster.
//!
//! Each body runs entirely inside one `eval_script`, so the per-run
//! bracket (measured in `runtime.rs`) is a constant that the workload
//! sizes here dwarf.

// Benchmarks and the profiling driver are not API. The pedantic
// documentation and `must_use` lints have nothing to protect here, and
// a panic is how a broken measurement is meant to stop.
#![allow(
  // `support` is shared by four bench binaries, each using a subset.
  dead_code,
  clippy::cast_precision_loss,
  clippy::expect_used,
  clippy::unwrap_used,
  clippy::missing_panics_doc,
  clippy::must_use_candidate,
  clippy::semicolon_if_nothing_returned,
  clippy::too_many_lines,
  clippy::doc_markdown
)]

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use ferrijs::{RunOptions, Runtime};
use support::{hosted, leak, ok, plain, tokio_rt};

/// Every workload: a name and the script that is it.
const WORKLOADS: &[(&str, &str)] = &[
  // Call-heavy: function prologue, argument passing, recursion depth.
  ("fib_recursive_27", "function fib(n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); } return fib(27)"),
  // Tight integer loop: the interpreter's dispatch floor.
  ("loop_sum_3m", "let s = 0; for (let i = 0; i < 3000000; i++) s += i; return s"),
  // Float arithmetic, so the number path is not all small ints.
  ("loop_float_1m", "let s = 0.0; for (let i = 0; i < 1000000; i++) s += i * 1.5; return s"),
  // Property access on a monomorphic shape: inline-cache territory.
  (
    "property_access_1m",
    "const o = { a: 1, b: 2, c: 3 }; let s = 0;
     for (let i = 0; i < 1000000; i++) s += o.a + o.b + o.c; return s",
  ),
  // Dynamic property writes: shape transitions and hidden-class churn.
  (
    "object_create_200k",
    "let s = 0; for (let i = 0; i < 200000; i++) { const o = { x: i, y: i + 1, z: 'k' + (i & 7) }; s += o.x + o.y; } return s",
  ),
  // Array element access and growth.
  (
    "array_push_500k",
    "const a = []; for (let i = 0; i < 500000; i++) a.push(i); let s = 0; for (let i = 0; i < a.length; i++) s += a[i]; return s",
  ),
  // The functional trio: closure allocation plus megamorphic call sites.
  (
    "array_map_filter_reduce_200k",
    "const a = new Array(200000); for (let i = 0; i < a.length; i++) a[i] = i;
     return a.map(x => x * 2).filter(x => (x & 3) === 0).reduce((p, c) => p + c, 0)",
  ),
  // Rope building: the string concat path.
  (
    "string_concat_100k",
    "let s = ''; for (let i = 0; i < 100000; i++) s += 'x'; return s.length",
  ),
  // Join is the shape a template renderer actually uses.
  (
    "string_join_200k",
    "const parts = new Array(200000); for (let i = 0; i < parts.length; i++) parts[i] = 'item' + i; return parts.join(',').length",
  ),
  // Substring / indexOf / slice, the scanning primitives.
  (
    "string_scan_200k",
    "const s = 'the quick brown fox jumps over the lazy dog '.repeat(2000); let n = 0;
     for (let i = 0; i < 200000; i++) n += s.charCodeAt(i % s.length); return n",
  ),
  // Regex compile is cached; this is the exec path.
  (
    "regex_exec_50k",
    "const re = /(\\w+)@(\\w+)\\.com/; let n = 0;
     for (let i = 0; i < 50000; i++) { const m = re.exec('user' + i + '@example.com'); if (m) n += m[1].length; } return n",
  ),
  // Global regex over a large haystack.
  (
    "regex_replace_2k",
    "const s = 'a1b2c3d4e5'.repeat(200); let n = 0;
     for (let i = 0; i < 2000; i++) n += s.replace(/\\d/g, '#').length; return n",
  ),
  // The serialisation both directions, on a document with real shape.
  (
    "json_stringify_2k",
    "const doc = { id: 1, name: 'x', items: Array.from({ length: 50 }, (_, i) => ({ i, s: 'v' + i, ok: i % 2 === 0 })) };
     let n = 0; for (let i = 0; i < 2000; i++) n += JSON.stringify(doc).length; return n",
  ),
  (
    "json_parse_2k",
    "const doc = JSON.stringify({ id: 1, name: 'x', items: Array.from({ length: 50 }, (_, i) => ({ i, s: 'v' + i, ok: i % 2 === 0 })) });
     let n = 0; for (let i = 0; i < 2000; i++) n += JSON.parse(doc).items.length; return n",
  ),
  // Class instantiation and method dispatch.
  (
    "class_method_500k",
    "class P { constructor(x, y) { this.x = x; this.y = y; } norm() { return this.x * this.x + this.y * this.y; } }
     let s = 0; for (let i = 0; i < 500000; i++) s += new P(i, i + 1).norm(); return s",
  ),
  // Map and Set, which real code reaches for constantly.
  (
    "map_set_200k",
    "const m = new Map(), st = new Set();
     for (let i = 0; i < 200000; i++) { m.set('k' + (i & 1023), i); st.add(i & 4095); }
     let s = 0; for (const [, v] of m) s += v; return s + st.size",
  ),
  // Typed arrays: the numeric fast path an image or crypto workload uses.
  (
    "typed_array_1m",
    "const a = new Float64Array(1000000); for (let i = 0; i < a.length; i++) a[i] = i * 0.5;
     let s = 0; for (let i = 0; i < a.length; i++) s += a[i]; return s",
  ),
  // Promise resolution and microtask draining.
  (
    "promise_chain_20k",
    "let p = Promise.resolve(0); for (let i = 0; i < 20000; i++) p = p.then(v => v + 1); return await p",
  ),
  // `await` in a loop: the async-function resume path.
  (
    "await_loop_20k",
    "let s = 0; for (let i = 0; i < 20000; i++) s += await Promise.resolve(i); return s",
  ),
  // Generators / iterators, the for-of protocol.
  (
    "generator_200k",
    "function* g(n) { for (let i = 0; i < n; i++) yield i; } let s = 0; for (const v of g(200000)) s += v; return s",
  ),
  // Exception throw/catch, which a validation-heavy program does often.
  (
    "throw_catch_50k",
    "let n = 0; for (let i = 0; i < 50000; i++) { try { throw new Error('e' + i); } catch (e) { n += e.message.length; } } return n",
  ),
  // Sort: comparison callbacks into the engine's own sort.
  (
    "sort_100k",
    "const a = new Array(100000); let x = 12345;
     for (let i = 0; i < a.length; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; a[i] = x; }
     a.sort((p, q) => p - q); return a[0] + a[a.length - 1]",
  ),
  // Spread / destructuring / rest, the syntax modern code is written in.
  (
    "spread_destructure_200k",
    "let s = 0; for (let i = 0; i < 200000; i++) { const [a, b, ...r] = [i, i + 1, i + 2, i + 3]; const { x = 1 } = { x: a }; s += a + b + r.length + x; } return s",
  ),
  // Churn that the cycle collector must actually walk.
  (
    "gc_cycles_100k",
    "let keep = null; for (let i = 0; i < 100000; i++) { const a = { i }; const b = { a }; a.b = b; keep = b; } return typeof keep",
  ),
];

fn engine(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm: &'static Runtime = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("js");
  g.sample_size(20);

  for (name, source) in WORKLOADS {
    // A failure here would otherwise be benchmarked as a fast error path.
    let probe = rt.block_on(realm.eval_script(source, &[], RunOptions::default()));
    assert!(probe.is_ok(), "workload `{name}` failed: {:?}", probe.err());

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

criterion_group!(benches, engine);
criterion_main!(benches);
