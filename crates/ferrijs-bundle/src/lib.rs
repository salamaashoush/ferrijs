//! The front-end a ferrijs host runs real projects through: rolldown
//! bundles TypeScript and `node_modules` into one ESM chunk, the chunk
//! is compiled to `QuickJS` bytecode once, and the bytecode is cached on
//! disk under an ABI tag so an unchanged tree skips both steps.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines, clippy::doc_markdown)]

pub mod bundle;
pub mod cache;

pub use bundle::{BundledSource, Bundler, BundlerOptions, is_typescript_path, source_is_es_module};
pub use cache::{BytecodeCache, CacheEntry, abi_tag, entry_key, input_set, inputs_fingerprint, source_stamp};
pub use ferrijs::source_map::{CompiledModule, LazyMap, SourceMapper};
