//! A single workload in a loop, for a sampling profiler.
//!
//! ```text
//! samply record -- target/release/examples/profile dispatch 200000
//! ```
//!
//! Criterion's own harness shows up in every stack it takes; this
//! driver is one `main`, one realm and one loop, so a profile is all
//! runtime.

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

use std::hint::black_box;
use std::time::Instant;

use ferrijs::{RunOptions, Runtime};

fn usage() -> ! {
  eprintln!(
    "usage: profile <workload> [iterations] [--threads N]\n\
     workloads: dispatch, run_noop, script_noop, startup, args, console, require, \
     json_in, json_out, path_join, path_resolve, url_parse, inspect, timers, <raw js>"
  );
  std::process::exit(2)
}

fn main() {
  let mut args = std::env::args().skip(1);
  let workload = args.next().unwrap_or_else(|| usage());
  let mut iters: u64 = 0;
  let mut threads = 2usize;
  let rest: Vec<String> = args.collect();
  let mut i = 0;
  while i < rest.len() {
    match rest[i].as_str() {
      "--threads" => {
        threads = rest.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(2);
        i += 2;
      },
      other => {
        iters = other.parse().unwrap_or(0);
        i += 1;
      },
    }
  }
  if iters == 0 {
    iters = 100_000;
  }

  let rt = if threads <= 1 {
    tokio::runtime::Builder::new_current_thread().enable_all().build()
  } else {
    tokio::runtime::Builder::new_multi_thread()
      .worker_threads(threads)
      .enable_all()
      .build()
  }
  .expect("tokio");

  // The loop runs on a worker task, not on the `block_on` thread: an
  // await from `block_on` parks an OS thread, which on macOS costs
  // about 7 µs and would be all any profile of a short operation shows.
  rt.block_on(async move { tokio::spawn(run(workload, iters)).await.expect("bench task") });
}

async fn run(workload: String, iters: u64) {
  {
    let realm = Runtime::builder()
      .permissions(ferrijs::Permissions::all())
      .build()
      .await
      .expect("realm");
    let started = Instant::now();
    match workload.as_str() {
      "startup" => {
        for _ in 0..iters {
          let r = Runtime::builder().build().await.expect("realm");
          black_box(r.poisoned());
        }
      },
      "dispatch" => {
        for _ in 0..iters {
          let v = realm.with(|_ctx| Box::pin(async move { 1u8 })).await;
          black_box(v.ok());
        }
      },
      "run_noop" => {
        for _ in 0..iters {
          let r = realm
            .run(RunOptions::default(), Box::new(|_ctx| Box::pin(async move { Ok(()) })))
            .await;
          black_box(r.is_ok());
        }
      },
      "script_noop" => {
        for _ in 0..iters {
          let r = realm.eval_script("return 1", &[], RunOptions::default()).await;
          black_box(r.is_ok());
        }
      },
      "args" => {
        let a = vec![serde_json::json!({ "a": 1, "b": "two", "c": [1, 2, 3] })];
        for _ in 0..iters {
          let r = realm.eval_script("return args[0]", &a, RunOptions::default()).await;
          black_box(r.is_ok());
        }
      },
      "console" => {
        for _ in 0..iters {
          let r = realm
            .eval_script(
              "for (let i = 0; i < 100; i++) console.log('n =', i, { a: 1 }); return 0",
              &[],
              RunOptions::default(),
            )
            .await;
          black_box(r.is_ok());
        }
      },
      "module_growth" => {
        // QuickJS appends every declared module to the context's
        // `loaded_modules` list and only frees it when the context dies,
        // and every import resolution walks that list. Print the cost in
        // deciles so the growth is visible rather than averaged away.
        let bucket = (iters / 10).max(1);
        for i in 0..iters {
          if i % bucket == 0 {
            let t = Instant::now();
            let r = realm
              .eval_module_source(
                "probe.mjs",
                "import { join } from 'node:path'; export default join('a', 'b');",
                &[],
                RunOptions::default(),
              )
              .await;
            assert!(r.is_ok(), "module eval failed");
            println!("  after {i:>6} modules: {:.1} µs", t.elapsed().as_secs_f64() * 1e6);
          } else {
            let r = realm
              .eval_module_source(
                "probe.mjs",
                "import { join } from 'node:path'; export default join('a', 'b');",
                &[],
                RunOptions::default(),
              )
              .await;
            black_box(r.is_ok());
          }
        }
      },
      "value_to_json" | "json_to_js" => {
        // The Rust <-> JS walkers on their own: one dispatch, then the
        // conversion, with no script compiled in between.
        let doc: serde_json::Value = serde_json::Value::Array(
          (0..1000)
            .map(|i| serde_json::json!({ "id": i, "name": format!("row {i}"), "ok": i % 2 == 0, "score": 1.5 * f64::from(i) }))
            .collect(),
        );
        let doc = std::sync::Arc::new(doc);
        let out = workload == "value_to_json";
        for _ in 0..iters {
          let doc = std::sync::Arc::clone(&doc);
          let r = realm
            .with(move |ctx| {
              Box::pin(async move {
                let v = ferrijs::value::json_to_js(&ctx, &doc).expect("json_to_js");
                if out {
                  ferrijs::value::value_to_json(&ctx, v).is_some()
                } else {
                  true
                }
              })
            })
            .await;
          black_box(r.ok());
        }
      },
      "module_probe" => {
        for i in 0..iters {
          let r = realm
            .eval_module_source(
              "probe.mjs",
              "import { join } from 'node:path'; export default join('a', 'b');",
              &[],
              RunOptions::default(),
            )
            .await;
          if i == 0 {
            println!("  first result: {:?}", r.result);
          }
          black_box(r.is_ok());
        }
      },
      "require" => {
        for _ in 0..iters {
          let r = realm
            .eval_script("return typeof require('node:path').join", &[], RunOptions::default())
            .await;
          black_box(r.is_ok());
        }
      },
      other => {
        let source = match other {
          "path_join" => {
            "const { join } = require('node:path'); let n = 0;
             for (let i = 0; i < 50000; i++) n += join('/a/b', 'c', '../d', 'e' + (i & 15)).length; return n"
          },
          "path_resolve" => {
            "const { resolve } = require('node:path'); let n = 0;
             for (let i = 0; i < 50000; i++) n += resolve('/a/b', './c/' + (i & 15)).length; return n"
          },
          "url_parse" => {
            "let n = 0; for (let i = 0; i < 50000; i++) n += new URL('https://example.com/a/b?c=' + i + '#frag').pathname.length; return n"
          },
          "inspect" => {
            "const { inspect } = require('node:util');
             const o = { a: 1, b: 'two', c: [1, 2, 3], d: { e: true, f: null } }; let n = 0;
             for (let i = 0; i < 20000; i++) n += inspect(o).length; return n"
          },
          "timers" => {
            "let n = 0; for (let i = 0; i < 2000; i++) await new Promise(r => setTimeout(() => { n++; r(); }, 0)); return n"
          },
          "json_in" | "json_out" => "return args[0]",
          raw => raw,
        };
        for _ in 0..iters {
          let r = realm.eval_script(source, &[], RunOptions::default()).await;
          if let Some(e) = r.err() {
            eprintln!("workload failed: {e}");
            std::process::exit(1);
          }
          black_box(r.is_ok());
        }
      },
    }
    let elapsed = started.elapsed();
    println!(
      "{workload}: {iters} iters in {:.3?} ({:.3} µs/iter)",
      elapsed,
      elapsed.as_secs_f64() * 1e6 / iters as f64
    );
  }
}
