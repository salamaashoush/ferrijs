# readable-stream

[readable-stream](https://github.com/nodejs/readable-stream) 4.8.0, MIT,
Node's own `lib/stream` and `lib/internal/streams` as the Node project
publishes them for other runtimes. `LICENSE` is upstream's.

Only `lib/` is taken, unmodified, minus the package's entry shims
(`lib/ours/index.js`, `lib/ours/browser.js`) and the legacy `_stream_*.js`
re-exports; `node:stream` is served from `lib/stream.js` directly.
`build.rs` wraps every file into one module whose external `require`s
(`buffer`, `events`, `string_decoder/`, `process/`, `abort-controller`)
are answered by the realm's own modules and globals.

One behaviour is set from outside rather than edited in:
`node/stream.rs` calls `setDefaultHighWaterMark(false, 65536)` on load,
since Node 22 raised the byte-stream default from readable-stream's 16
KiB to 64 KiB.

Re-sync: replace `lib/` with a newer release's `lib/`, delete the same
files, and run the stream tests.
