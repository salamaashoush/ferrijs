//! The runtime's own overhead: what a host pays to build a realm, and
//! what it pays per run on top of the script itself.
//!
//! Every number here is engine-independent work the runtime does around
//! a script -- the install, the run bracket, the dispatch onto the VM
//! loop, the argument binding and the result conversion. A script that
//! does nothing isolates it.

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

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ferrijs::{RunOptions, Runtime};
use support::{granted, hosted, leak, minimal, ok, plain, sample_json, tokio_rt};

/// Building a realm: the engine, the loader table, the standard-library
/// install and the lockdown. What a host pays for a cold start.
fn startup(c: &mut Criterion) {
  let rt = tokio_rt();
  let mut g = c.benchmark_group("startup");
  g.sample_size(30);

  g.bench_function("build_default", |b| {
    b.to_async(&rt)
      .iter_custom(|iters| hosted(iters, || async { plain().await }));
  });

  g.bench_function("build_minimal", |b| {
    b.to_async(&rt)
      .iter_custom(|iters| hosted(iters, || async { minimal().await }));
  });

  g.bench_function("build_run_drop", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, || async {
        let realm = plain().await;
        let run = realm
          .eval_script("return args[0] * 2", &[serde_json::json!(21)], RunOptions::default())
          .await;
        black_box(ok(run))
      })
    });
  });

  g.finish();
}

/// The per-run bracket, with the script itself as close to free as JS
/// gets. The gap between `vm_dispatch` and `noop_script` is everything
/// the runtime adds: limits, deadline, console install, args, the async
/// IIFE wrap, and the JSON round trip of the result.
fn run_overhead(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm: &'static Runtime = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("run_overhead");

  g.bench_function("vm_dispatch", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        realm.with(|_ctx| Box::pin(async move { 1u8 })).await.ok()
      })
    });
  });

  g.bench_function("vm_dispatch_touching_globals", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        realm
          .with(|ctx| Box::pin(async move { ctx.globals().is_object() }))
          .await
          .ok()
      })
    });
  });

  g.bench_function("run_body_noop", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        ok(
          realm
            .run(RunOptions::default(), Box::new(|_ctx| Box::pin(async move { Ok(()) })))
            .await,
        )
      })
    });
  });

  g.bench_function("noop_script", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        ok(realm.eval_script("return 1", &[], RunOptions::default()).await)
      })
    });
  });

  g.bench_function("noop_script_await", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        ok(realm.eval_script("await 0; return 1", &[], RunOptions::default()).await)
      })
    });
  });

  // What a host that calls the runtime from its `block_on` thread pays
  // instead: three OS-thread parks per call, which dwarf everything the
  // runtime itself does. Kept so the gap stays visible.
  g.bench_function("noop_script_from_block_on", |b| {
    b.to_async(&rt)
      .iter(|| async { realm.eval_script("return 1", &[], RunOptions::default()).await });
  });

  g.finish();
}

/// Binding arguments in and converting the result out: the two JSON
/// boundaries every run crosses.
fn interop(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm: &'static Runtime = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("interop");

  let small: &'static Vec<serde_json::Value> = leak(vec![serde_json::json!({ "a": 1, "b": "two" })]);
  let wide: &'static Vec<serde_json::Value> = leak(vec![sample_json(16, 1)]);
  let deep: &'static Vec<serde_json::Value> = leak(vec![sample_json(3, 5)]);
  let strings: &'static Vec<serde_json::Value> = leak(vec![serde_json::Value::Array(
    (0..500).map(|i| serde_json::json!(format!("item-{i}"))).collect(),
  )]);

  for (name, args) in [
    ("args_small_in", small),
    ("args_wide_in", wide),
    ("args_deep_in", deep),
    ("args_strings_in", strings),
  ] {
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        hosted(iters, move || async move {
          ok(realm.eval_script("return 0", args, RunOptions::default()).await)
        })
      });
    });
  }

  for (name, args) in [
    ("roundtrip_wide", wide),
    ("roundtrip_deep", deep),
    ("roundtrip_strings", strings),
  ] {
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        hosted(iters, move || async move {
          ok(realm.eval_script("return args[0]", args, RunOptions::default()).await)
        })
      });
    });
  }

  g.bench_function("build_result_1000_numbers", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        ok(
          realm
            .eval_script(
              "const out = []; for (let i = 0; i < 1000; i++) out.push(i); return out",
              &[],
              RunOptions::default(),
            )
            .await,
        )
      })
    });
  });

  g.finish();
}

/// Console capture and formatting: `console.log` is the most called
/// host binding in a real script.
fn console(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm: &'static Runtime = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("console");

  for (name, source) in [
    (
      "log_string_x100",
      "for (let i = 0; i < 100; i++) console.log('a plain log line'); return 0",
    ),
    (
      "log_object_x100",
      "const o = { a: 1, b: 'two', c: [1, 2, 3], d: { e: true } };
       for (let i = 0; i < 100; i++) console.log(o); return 0",
    ),
    (
      "log_mixed_x100",
      "for (let i = 0; i < 100; i++) console.log('n =', i, 'of', 100, [i, i + 1]); return 0",
    ),
  ] {
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        hosted(iters, move || async move {
          ok(realm.eval_script(source, &[], RunOptions::default()).await)
        })
      });
    });
  }

  g.finish();
}

/// Module loading: what `require` and `import` of a native module cost,
/// and what a module evaluation costs over a plain script.
fn modules(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm: &'static Runtime = leak(rt.block_on(granted()));
  let mut g = c.benchmark_group("modules");

  for (name, source) in [
    ("require_path", "return typeof require('node:path').join"),
    (
      "require_x8",
      "let n = 0;
       for (const m of ['node:path', 'node:os', 'node:util', 'node:events',
                        'node:buffer', 'node:assert', 'node:crypto', 'node:url'])
         n += typeof require(m) === 'object' ? 1 : 0;
       return n",
    ),
  ] {
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        hosted(iters, move || async move {
          ok(realm.eval_script(source, &[], RunOptions::default()).await)
        })
      });
    });
  }

  // Every `Module::declare` appends to the context's module list and
  // QuickJS frees it only with the context, so a realm that evaluates
  // enough of them exhausts its heap. These cases therefore get a realm
  // of their own and a small sample; sharing the group's realm let one
  // of them poison it, after which the other was timing the poisoned
  // fast path rather than a module evaluation.
  g.sample_size(10);
  g.measurement_time(std::time::Duration::from_secs(3));
  for (name, source) in [
    ("eval_module_source", "const x = 1 + 1; export default x;"),
    (
      "eval_module_source_with_import",
      "import { join } from 'node:path'; export default join('a', 'b');",
    ),
  ] {
    let fresh: &'static Runtime = leak(rt.block_on(granted()));
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        hosted(iters, move || async move {
          ok(fresh.eval_module_source(name, source, &[], RunOptions::default()).await)
        })
      });
    });
  }

  g.finish();
}

/// The registry lookups that happen on every resolve and every
/// `require`, measured without the engine in the way.
fn registry(c: &mut Criterion) {
  use ferrijs::ModuleRegistry;
  let reg = ModuleRegistry::with_std();
  let mut g = c.benchmark_group("registry");

  g.bench_function("serves_hit", |b| {
    b.iter(|| black_box(reg.serves(black_box("node:crypto"))))
  });
  g.bench_function("serves_miss", |b| b.iter(|| black_box(reg.serves(black_box("lodash")))));
  g.bench_function("canonical_hit", |b| {
    b.iter(|| black_box(reg.canonical(black_box("node:crypto"))));
  });
  g.bench_function("is_reserved_miss", |b| {
    b.iter(|| black_box(reg.is_reserved(black_box("lodash"))));
  });
  g.bench_function("names", |b| b.iter(|| black_box(reg.names().len())));
  g.bench_function("fingerprint", |b| b.iter(|| black_box(reg.fingerprint())));
  g.bench_function("with_std", |b| {
    b.iter(|| black_box(ModuleRegistry::with_std().modules().len()))
  });

  g.finish();
}

/// A realm answering many small runs back to back, which is the shape a
/// long-lived host (a test runner, a mock server) actually produces.
fn sustained(c: &mut Criterion) {
  let rt = tokio_rt();
  let realm: &'static Runtime = leak(rt.block_on(plain()));
  let mut g = c.benchmark_group("sustained");
  g.sample_size(50);

  g.bench_function("small_run", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        ok(
          realm
            .eval_script("return args[0] + 1", &[serde_json::json!(1)], RunOptions::default())
            .await,
        )
      })
    });
  });

  // Many runs in flight at once against one realm, which is what a
  // server-shaped host produces and what the VM loop's job queue is for.
  g.bench_function("16_concurrent_runs", |b| {
    b.to_async(&rt).iter_custom(|iters| {
      hosted(iters, move || async move {
        let mut set = Vec::with_capacity(16);
        for i in 0..16 {
          set.push(tokio::spawn(async move {
            ok(
              realm
                .eval_script("return args[0] + 1", &[serde_json::json!(i)], RunOptions::default())
                .await,
            )
          }));
        }
        for h in set {
          black_box(h.await.expect("join"));
        }
      })
    });
  });

  g.finish();
}

fn script_working_set(c: &mut Criterion) {
  let rt = tokio_rt();
  let mut g = c.benchmark_group("script_working_set");
  for slots in [0, 32] {
    let realm = leak(rt.block_on(async { Runtime::builder().script_cache(slots).build().await.unwrap() }));
    let hot = leak(format!("{}\nreturn args[0] + 1", "void 0;\n".repeat(512)));
    let mut sequence = 0u64;
    g.bench_function(format!("hot_with_cold_cache_{slots}"), |b| {
      b.to_async(&rt).iter_custom(|iters| {
        let first = sequence;
        sequence += iters;
        hosted(iters, {
          let mut index = first;
          move || {
            let cold = format!("return {index}");
            index += 1;
            async move {
              assert_eq!(ok(realm.eval_script(hot, &[1.into()], RunOptions::default()).await), 2);
              ok(realm.eval_script(&cold, &[], RunOptions::default()).await)
            }
          }
        })
      });
    });
  }
  g.finish();
}

fn stored_handlers(c: &mut Criterion) {
  use ferrijs::{ConsoleEntry, ConsoleOptions, ConsoleSink};
  use std::sync::Arc;

  #[derive(Debug)]
  struct Sink;
  impl ConsoleSink for Sink {
    fn emit(&self, entry: &ConsoleEntry) {
      black_box(entry);
    }
  }

  let rt = tokio_rt();
  let realm = leak(rt.block_on(async {
    let realm = Runtime::builder()
      .console(ConsoleOptions {
        sink: Some(Arc::new(Sink)),
        ..ConsoleOptions::default()
      })
      .build()
      .await
      .unwrap();
    ok(
      realm
        .eval_script(
          "globalThis.handleSync = request => ({ status: 200, body: { id: request.id, ok: true } });
       globalThis.handleAsync = async request => { await Promise.resolve(); return handleSync(request); };",
          &[],
          RunOptions::default(),
        )
        .await,
    );
    realm
  }));
  let request = leak(serde_json::json!({ "id": 42, "method": "GET", "path": "/items/42" }));
  let expected = leak(serde_json::json!({ "status": 200, "body": { "id": 42, "ok": true } }));
  let mut g = c.benchmark_group("stored_handlers");
  for name in ["handleSync", "handleAsync"] {
    g.bench_function(name, |b| {
      b.to_async(&rt).iter_custom(|iters| {
        hosted(iters, move || async move {
          let result = realm
            .run(
              RunOptions::default(),
              Box::new(move |ctx| {
                Box::pin(async move {
                  let handler: rquickjs::Function<'_> = ctx.globals().get(name).unwrap();
                  let request = ferrijs::value::json_to_js(&ctx, request).unwrap();
                  let value: rquickjs::Value<'_> = handler.call((request,)).unwrap();
                  let value = if let Some(promise) = value.as_promise() {
                    promise.clone().into_future::<rquickjs::Value<'_>>().await.unwrap()
                  } else {
                    value
                  };
                  Ok(ferrijs::value::value_to_json(&ctx, value).unwrap())
                })
              }),
            )
            .await;
          assert_eq!(&ok(result), expected);
        })
      });
    });
  }
  g.finish();
}

criterion_group!(
  benches,
  startup,
  run_overhead,
  interop,
  console,
  modules,
  registry,
  sustained,
  script_working_set,
  stored_handlers
);
criterion_main!(benches);
