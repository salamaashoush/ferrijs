# ferrijs-serde

A serde `Serializer` and `Deserializer` over `rquickjs::Value`, so a host
converts between Rust types and JS values without a `serde_json::Value`
middle hop.

## Vendored

This is [rquickjs-serde](https://github.com/rquickjs/rquickjs-serde) at
`00ade68` (v0.6.1), Apache-2.0, by Emile Fugulin and The Javy Project
Developers. `LICENSE` and `NOTICE` are upstream's and stay.

It is vendored rather than depended on because upstream pins
`rquickjs ^0.12`, and a version requirement cannot be worked around: two
incompatible `rquickjs` in one graph means two incompatible `Value`
types, so `ferrijs` could not have upgraded to 0.13 at all while the
dependency stood. The code itself needed no changes for 0.13.

Kept byte-close to upstream so a re-sync stays a mechanical diff. Its own
`rustfmt.toml` disables formatting (the workspace `ignore` key is
nightly-only); pedantic clippy is off for the same reason.

## Local deltas

1. Crate renamed `rquickjs-serde` -> `ferrijs-serde`: the doc examples
   and one test-local JS variable name follow the crate name.
2. `Cargo.toml` takes its version, edition, repository and homepage from
   the workspace, and `rquickjs` from `[workspace.dependencies]` (0.13).
3. `de.rs`: five changes on the deserialize hot path, all
   behaviour-preserving. `Deserializer::from` no longer reserves a
   hundred slots for a stack that tracks nesting depth. `current_kv`
   holds only the value, because the key half was never read and
   building it cost a `JS_DupValue` and a `JS_DupContext` per property.
   `deserialize_any` answers a primitive-string map key before walking
   the type ladder. Map keys and string values reach the visitor through
   `visit_string` rather than `visit_str`, so the buffer is moved instead
   of copied. `MapAccess::pop` / `SeqAccess::pop` compare against
   `as_value()` instead of cloning the object to compare. Together these
   halve `value_to_json`.

4. `ser.rs`: recognize serde_json's tagged arbitrary-precision numbers
   when serializing structs and convert them to native JS numbers.
   Ordinary maps with the same key remain objects.

## Re-syncing

```
git clone --depth 1 https://github.com/rquickjs/rquickjs-serde
```

Diff `src/` against it, reapply delta 1, and check whether upstream has
moved to `rquickjs` 0.13 or later — if it has, this crate can be dropped
for the published one again.
