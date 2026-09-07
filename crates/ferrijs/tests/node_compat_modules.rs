#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Node-compat native modules (`fs`/`node:fs`, `path`/`node:path`,
//! `buffer`/`node:buffer`, and the ones vendored from llrt) over both
//! consumption paths:
//! 1. an ES module that imports them by name, and
//! 2. dynamic `import()` from a plain script (sandbox loader chain).

use ferrijs::{Permissions, RunOptions, Runtime};

async fn runtime(permissions: Permissions) -> Runtime {
  Runtime::builder()
    .permissions(permissions)
    .build()
    .await
    .expect("runtime")
}

fn ok(run: ferrijs::Run<serde_json::Value>) -> serde_json::Value {
  match run.result {
    Ok(value) => value,
    Err(error) => panic!("expected ok, got error: {error:?}"),
  }
}

#[tokio::test]
async fn bundled_module_uses_native_fs_path_buffer() {
  let dir = tempfile::tempdir().expect("tempdir");
  std::fs::write(dir.path().join("data.txt"), "hello-node-compat").expect("data");

  // Node resolves a relative path against the process cwd, so the test
  // names the file it wrote outright rather than relying on a root.
  let source = "import fs from 'node:fs';\n\
     import { readFileSync } from 'fs';\n\
     import { readFile } from 'node:fs/promises';\n\
     import path from 'node:path';\n\
     import { Buffer } from 'node:buffer';\n\
     const file = FILE;\n\
     const viaDefault = fs.readFileSync(file, 'utf8');\n\
     const viaNamed = readFileSync(file, 'utf8');\n\
     const viaPromises = await readFile(file, 'utf8');\n\
     const joined = path.join('a', '..', 'b', 'c.txt');\n\
     const ext = path.extname(joined);\n\
     const b64 = Buffer.from('hi').toString('base64');\n\
     const round = Buffer.from(b64, 'base64').toString('utf8');\n\
     export default { viaDefault, viaNamed, viaPromises, joined, ext, b64, round };\n"
    .replace(
      "FILE",
      &serde_json::to_string(&dir.path().join("data.txt").to_string_lossy().into_owned()).expect("json"),
    );

  let rt = runtime(Permissions::none().allow_read([dir.path()])).await;
  let run = rt
    .eval_module_source("main.mjs", &source, &[], RunOptions::default())
    .await;
  assert_eq!(
    ok(run),
    serde_json::json!({
      "viaDefault": "hello-node-compat",
      "viaNamed": "hello-node-compat",
      "viaPromises": "hello-node-compat",
      "joined": "b/c.txt",
      "ext": ".txt",
      "b64": "aGk=",
      "round": "hi"
    })
  );
}

#[tokio::test]
async fn dynamic_import_resolves_native_modules_in_plain_scripts() {
  let rt = runtime(Permissions::none()).await;
  let run = rt
    .eval_script(
      r"
      const path = (await import('path')).default;
      const { Buffer } = await import('buffer');
      return {
        dir: path.dirname('/a/b/c.txt'),
        rel: path.relative('/a/b', '/a/d'),
        hex: Buffer.from([0xde, 0xad]).toString('hex'),
        isBuf: Buffer.isBuffer(Buffer.alloc(2)),
      };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(run),
    serde_json::json!({
      "dir": "/a/b",
      "rel": "../d",
      "hex": "dead",
      "isBuf": true,
    })
  );
}

#[tokio::test]
async fn bundled_module_uses_zlib_string_decoder_perf_hooks_tty_and_stream_web() {
  // The modules vendored from llrt, each through the module path.
  // `zlib` covers all three codec back-ends because they are separate
  // crates behind separate feature gates: gzip/deflate is flate2's
  // pure-Rust backend, brotli is the `brotli` crate, zstd compiles
  // vendored C. A missing feature compiles the arm out silently, so a
  // round-trip per codec is what proves the gate is actually on.
  let source = "import zlib from 'node:zlib';\n\
     import { StringDecoder } from 'node:string_decoder';\n\
     import { performance as perf } from 'node:perf_hooks';\n\
     import { isatty } from 'node:tty';\n\
     import { ReadableStream } from 'node:stream/web';\n\
     import { Buffer } from 'node:buffer';\n\
     const text = (b) => b.toString('utf8');\n\
     const gzip = text(zlib.gunzipSync(zlib.gzipSync(Buffer.from('hello zlib'))));\n\
     const deflate = text(zlib.inflateSync(zlib.deflateSync(Buffer.from('deflate me'))));\n\
     const deflateRaw = text(zlib.inflateRawSync(zlib.deflateRawSync(Buffer.from('raw me'))));\n\
     const brotli = text(zlib.brotliDecompressSync(zlib.brotliCompressSync(Buffer.from('brotli me'))));\n\
     const zstd = text(zlib.zstdDecompressSync(zlib.zstdCompressSync(Buffer.from('zstd me'))));\n\
     // A euro sign split across two writes: the decoder has to hold the\n\
     // partial sequence rather than emit a replacement character.\n\
     const d = new StringDecoder('utf8');\n\
     const split = d.write(Buffer.from([0xe2, 0x82])) + d.end(Buffer.from([0xac]));\n\
     export default {\n\
     \x20 gzip, deflate, deflateRaw, brotli, zstd, split,\n\
     \x20 perfNow: typeof perf.now(),\n\
     \x20 isatty: typeof isatty(1),\n\
     \x20 streamWeb: typeof ReadableStream,\n\
     };\n";

  let rt = runtime(Permissions::none()).await;
  let run = rt
    .eval_module_source("main.mjs", source, &[], RunOptions::default())
    .await;
  assert_eq!(
    ok(run),
    serde_json::json!({
      "gzip": "hello zlib",
      "deflate": "deflate me",
      "deflateRaw": "raw me",
      "brotli": "brotli me",
      "zstd": "zstd me",
      "split": "\u{20ac}",
      "perfNow": "number",
      "isatty": "boolean",
      "streamWeb": "function",
    })
  );
}

#[tokio::test]
async fn dynamic_import_resolves_the_vendored_modules_and_navigator_names_this_runtime() {
  // The other consumption path, plus `navigator`. Node 21+ has a
  // `navigator.userAgent`, so having one is Node parity rather than a
  // browser claim — but it must name THIS runtime: upstream llrt
  // hardcodes its own name, and shipping that verbatim would tell every
  // user-agent sniffer the wrong thing.
  let rt = runtime(Permissions::none()).await;
  let run = rt
    .eval_script(
      r"
      const zlib = (await import('zlib')).default;
      const { StringDecoder } = await import('string_decoder');
      const { isatty } = await import('tty');
      const { ReadableStream } = await import('stream/web');
      return {
        gzip: zlib.gunzipSync(zlib.gzipSync(Buffer.from('dyn'))).toString('utf8'),
        decoder: new StringDecoder('utf8').end(Buffer.from('ok')),
        isatty: typeof isatty(1),
        streamWeb: typeof ReadableStream,
        ua: navigator.userAgent,
      };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  let value = ok(run);
  assert_eq!(value["gzip"], serde_json::json!("dyn"));
  assert_eq!(value["decoder"], serde_json::json!("ok"));
  assert_eq!(value["isatty"], serde_json::json!("boolean"));
  assert_eq!(value["streamWeb"], serde_json::json!("function"));
  let ua = value["ua"].as_str().expect("userAgent is a string");
  assert!(
    ua.starts_with("ferrijs/"),
    "navigator.userAgent must name this runtime, got {ua:?}"
  );
}

#[tokio::test]
async fn performance_covers_user_timing_and_the_timeline() {
  // High Resolution Time + User Timing + Performance Timeline, through
  // the public surface. The interesting cases are the ones a wrong
  // implementation still passes a smoke test on: an explicit `startTime`
  // that backdates an entry (so insertion order and chronological order
  // differ), `measure`'s three overloads, and the two option
  // combinations the spec refuses outright.
  let rt = runtime(Permissions::none()).await;
  let run = rt
    .eval_script(
      r"
      const threw = (fn) => { try { fn(); return false; } catch { return true; } };

      const m = performance.mark('a', { startTime: 10, detail: { k: 1 } });
      performance.mark('b', { startTime: 40 });
      // Backdated: recorded third, belongs first on the timeline.
      performance.mark('early', { startTime: 5 });

      const span = performance.measure('span', 'a', 'b');
      const fromOptions = performance.measure('opts', { start: 100, duration: 25 });
      const derivedStart = performance.measure('derived', { end: 80, duration: 30 });

      return {
        // now() is monotonic and moves forward, timeOrigin is wall clock.
        nowMonotonic: performance.now() >= 0 && performance.now() <= performance.now(),
        timeOriginIsWallClock: performance.timeOrigin > 1.7e12,
        toJSON: Object.keys(performance.toJSON()).join(','),

        markShape: [m.name, m.entryType, m.startTime, m.duration].join('|'),
        markDetail: m.detail.k,
        markIsEntry: m instanceof PerformanceEntry && m instanceof PerformanceMark,

        measureShape: [span.name, span.entryType, span.startTime, span.duration].join('|'),
        measureIsEntry: span instanceof PerformanceEntry && span instanceof PerformanceMeasure,
        fromOptions: [fromOptions.startTime, fromOptions.duration].join('|'),
        derivedStart: [derivedStart.startTime, derivedStart.duration].join('|'),

        // getEntries sorts by startTime, not insertion order.
        order: performance.getEntries().map((e) => e.name).join(','),
        byType: performance.getEntriesByType('mark').map((e) => e.name).join(','),
        byName: performance.getEntriesByName('a', 'mark').length,
        byNameWrongType: performance.getEntriesByName('a', 'measure').length,
        unknownType: performance.getEntriesByType('resource').length,

        entryJson: JSON.stringify(span.toJSON()),

        // Refusals the spec requires.
        bothEndForms: threw(() => performance.measure('x', { start: 1 }, 'b')),
        allThreeOptions: threw(() => performance.measure('x', { start: 1, end: 2, duration: 1 })),
        emptyOptions: threw(() => performance.measure('x', {})),
        missingMark: threw(() => performance.measure('x', 'nope')),
        negativeStart: threw(() => performance.mark('x', { startTime: -1 })),
        notConstructible: threw(() => new Performance()),

        clearedMarks: (() => {
          performance.clearMarks('a');
          return performance.getEntriesByType('mark').map((e) => e.name).join(',');
        })(),
        clearedMeasures: (() => {
          performance.clearMeasures();
          return performance.getEntriesByType('measure').length;
        })(),
      };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    ok(run),
    serde_json::json!({
      "nowMonotonic": true,
      "timeOriginIsWallClock": true,
      "toJSON": "timeOrigin",
      "markShape": "a|mark|10|0",
      "markDetail": 1,
      "markIsEntry": true,
      "measureShape": "span|measure|10|30",
      "measureIsEntry": true,
      "fromOptions": "100|25",
      "derivedStart": "50|30",
      // early(5), a(10), span(10), b(40), derived(50), opts(100).
      // `a` and `span` tie at 10 and the sort is stable, so they keep
      // the order they were recorded in.
      "order": "early,a,span,b,derived,opts",
      "byType": "early,a,b",
      "byName": 1,
      "byNameWrongType": 0,
      "unknownType": 0,
      "entryJson": "{\"name\":\"span\",\"entryType\":\"measure\",\"startTime\":10,\"duration\":30,\"detail\":null}",
      "bothEndForms": true,
      "allThreeOptions": true,
      "emptyOptions": true,
      "missingMark": true,
      "negativeStart": true,
      "notConstructible": true,
      "clearedMarks": "early,b",
      "clearedMeasures": 0,
    })
  );
}

#[tokio::test]
async fn performance_now_and_process_hrtime_share_one_base() {
  // Node derives both from a single libuv hrtime, so a script that takes
  // one reading of each at the same moment expects them to agree. Two
  // separate `Instant::now()` calls would put a constant, invisible skew
  // between them that only shows up when someone correlates the two.
  let rt = runtime(Permissions::none()).await;
  // `performance.now()` is read BETWEEN two `hrtime()` readings and has
  // to land between them. Comparing a single reading of each against a
  // fixed tolerance instead measures how long the VM took to run two
  // statements, which on a loaded machine exceeds any tolerance small
  // enough to catch a shared-base regression.
  let run = rt
    .eval_script(
      r"
      const before = process.hrtime();
      const now = performance.now();
      const after = process.hrtime();
      const toMs = hr => hr[0] * 1000 + hr[1] / 1e6;
      return { before: toMs(before), now, after: toMs(after) };
      ",
      &[],
      RunOptions::default(),
    )
    .await;
  let value = ok(run);
  let number = |key: &str| value[key].as_f64().expect("reading is a number");
  let (before, now, after) = (number("before"), number("now"), number("after"));
  assert!(
    before <= now && now <= after,
    "performance.now() ({now}ms) fell outside the hrtime readings around it \
     ({before}ms..{after}ms), so they are not counting from the same base"
  );
}
