# CLAUDE.md

Guidance for working in this repository.

## What this is

ferrijs is an embeddable JavaScript runtime on QuickJS. A host builds a
`Runtime` (one realm: engine, context, the single event loop that owns
them, and the policy they run under), adds its own API as `Extension`s,
and runs scripts, compiled modules, or bodies of its own under the same
bracket. Two hosts consume it: ferridriver (browser automation, sibling
checkout `../ferridriver`) and ferrimock (a mock server, `../ferrimock`),
both by path dependency while the three move together.

## Crates

```
ferrijs              the runtime: Runtime/Builder, vm loop, limits, modules, console, fetch glue
ferrijs-std          the standard library (vendored llrt + our node/web modules) and its permission checks
ferrijs-permissions  the policy: Permissions, Allow, Deny, Container, PathRule, NetRule
ferrijs-fetch        WHATWG fetch model + reqwest send loop + NetGuard (SSRF)
ferrijs-bundle       rolldown -> bytecode, BytecodeCache
ferrijs-cli          `ferrijs run` / `ferrijs eval`
```

Dependency flow: cli -> bundle -> ferrijs -> std -> permissions; ferrijs
-> fetch -> permissions.

## Rules that exist because they were broken once

- **One policy per realm, narrowing only.** No dynamic scope, no
  "narrow around this call", no policy carried through a timer. Two
  trust levels are two realms. `docs/SANDBOX.md` has the research; read
  it before touching anything that grants or checks authority.
- **Absent beats refusing.** A module the policy withholds is not
  served; `fetch` is not installed rather than installed-and-refusing.
- **Every check is the runtime's.** `ferrijs_std::permissions::check_*`
  at the entry point of the capability, throwing the
  `PermissionDeniedError` with Node's `ERR_ACCESS_DENIED` shape. A host
  extension calls the same functions; it never re-implements a check.
- **Never a transient `async_with` against a runtime.** The scheduler
  has one wake slot; exactly one future (the VM loop) polls it. Use
  `Runtime::with` / `vm_with!`. See `crates/ferrijs/src/vm.rs`.
- **`crates/ferrijs-std` is vendored.** Byte-close to upstream llrt; a
  re-sync is a diff. Every deviation is a numbered local delta in its
  README. No `cargo fmt` there (its own `rustfmt.toml` disables it).
  Our own code lives in `src/node/`, `src/web/`, `src/permissions.rs`,
  `src/identity.rs`, `src/fs/guard.rs`.
- **The bundler reads the runtime's module table.** A `Bundler` is
  built over the same `ModuleRegistry` the realm is, so what stays
  external at bundle time is what the realm serves at link time.
- **Bytecode is loaded only under a matching ABI tag.** `Module::load`
  is unsafe; the cache keys every record by QuickJS version, arch,
  endianness and pointer width, and validates every transitive input.

## Gate

`just ready`: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings`, `cargo test --workspace
--all-features`. Never commit with any of the three red. No
`#[allow]` without a comment saying why the lint is wrong here, and only
where it is.

## Style

Stable Rust (pinned), edition 2024, 2-space indent, 120 columns.
Pedantic clippy is on. Comments carry the why the code cannot; no
narration, no planning metadata, no emoji anywhere. Commit messages:
conventional prefix, a body that names the mechanism and what stops it
coming back, no AI attribution.
