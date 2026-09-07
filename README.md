# ferrijs

An embeddable JavaScript runtime on QuickJS, written in Rust, for a host
that wants to run scripts it did not write: a plugin system, an
automation tool, a mock server, an agent that executes code. It ships
the Node and web standard library a real program expects, a module
system a host extends with its own API, a bundler that turns TypeScript
and `node_modules` into bytecode, and a sandbox in which nothing is
granted until the host grants it.

```rust
use ferrijs::{Permissions, RunOptions, Runtime};

let rt = Runtime::builder()
  .permissions(Permissions::none().allow_read(["./data"]).allow_net(["api.example.com"])?)
  .build()
  .await?;

let run = rt.eval_script(
  "const fs = require('node:fs'); return fs.readdirSync(args[0]).length",
  &["./data".into()],
  RunOptions::default(),
).await;
println!("{:?} in {}ms", run.result, run.duration_ms);
```

## What a realm has

- **The web platform**: `fetch`, `Headers`, `Request`, `Response`, the
  Streams API, `URL`, `URLSearchParams`, `TextEncoder` / `TextDecoder`,
  `crypto` (WebCrypto with ML-DSA, ML-KEM, SHA-3 and the classics),
  `AbortController`, `Event` / `EventTarget`, `Blob`, `File`,
  `FormData`, `structuredClone`, `atob` / `btoa`, `performance`, the
  compression streams, the timers, `queueMicrotask`, `console`.
- **The Node modules**, under the names Node serves them: `node:fs`
  (and `fs/promises`), `path`, `buffer`, `crypto`, `events`, `util`,
  `assert`, `url`, `os`, `zlib`, `stream/web`, `string_decoder`,
  `timers`, `perf_hooks`, `tty`, `process`; `require()` for the CommonJS
  spelling; `process` with `env`, `cwd()`, `hrtime`, `nextTick`,
  `permission.has()` and `permission.drop()`.
- **ES modules** from disk under a policy (a root, optionally a jail,
  optionally none at all), and native modules a host registers.
- **A run bracket**: a wall-clock budget enforced by the interrupt
  handler with a backstop for a run parked on a native await, a heap
  ceiling, a stack ceiling, console capture with size limits, and a
  poison flag when a run must not continue.

Most of the standard library is [awslabs/llrt](https://github.com/awslabs/llrt)'s,
vendored and kept byte-close so it re-syncs; see
`crates/ferrijs-std/README.md` for the mapping and the local deltas.

## The sandbox

A realm starts with nothing. Five grants (`read`, `write`, `net`,
`env`, `sys`), each none, all or a list, with deny lists on top, held
in one container per realm that only ever narrows. A module the policy
withholds is absent, not present and refusing. `eval` can be switched
off, the intrinsics frozen, the clocks coarsened. The model and the
research behind it (Deno, Node, workerd, Hardened JavaScript, and why
Java's stack-inspection model was removed) are in
[docs/SANDBOX.md](docs/SANDBOX.md).

## The crates

| crate                 | what                                                              |
|-----------------------|-------------------------------------------------------------------|
| `ferrijs`             | the runtime: realm, event loop, limits, modules, console, `fetch` |
| `ferrijs-std`         | the standard library and the permission checks it makes           |
| `ferrijs-permissions` | the policy: grants, deny lists, the container, path and host rules |
| `ferrijs-fetch`       | the WHATWG fetch model and reqwest send loop with the SSRF guard   |
| `ferrijs-bundle`      | rolldown to bytecode, cached on disk under an ABI tag              |
| `ferrijs-cli`         | `ferrijs run file.ts --allow-net api.example.com`                  |

## Extending

```rust
struct Acme;

impl ferrijs::Extension for Acme {
  fn name(&self) -> &str { "acme" }

  fn modules(&self, registry: &mut ferrijs::ModuleRegistry) -> Result<(), String> {
    registry.register(ferrijs::NativeModule::new::<AcmeModule, _>(["acme", "@acme/core"], acme_namespace))
  }

  fn install(&self, ctx: &rquickjs::Ctx<'_>) -> rquickjs::Result<()> {
    ctx.globals().set("acmeGlobal", "here")
  }
}

let rt = Runtime::builder().extension(Acme).build().await?;
```

An extension registers native modules (served to `import` and
`require` from one definition), chains resolver/loader pairs, answers
`require` ahead of the table, and installs globals once per realm. A
host with per-run globals installs them in the body it hands to
`Runtime::run`, which runs under the same bracket as `eval_script`.

## Building

Stable Rust, pinned in `rust-toolchain.toml`. `just ready` is the gate:
format, clippy with warnings denied, every test. `cargo fmt` never
touches `crates/ferrijs-std`, which is vendored.

## License

MIT or Apache-2.0, at your option. `crates/ferrijs-std` carries the
Apache-2.0 sources it vendors from llrt; see its `LICENSE` and `NOTICE`.
