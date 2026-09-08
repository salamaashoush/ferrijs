//! `ferrijs run <file>` and `ferrijs eval <source>`: a realm from the
//! command line, granting exactly what the flags say.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use ferrijs::{
  ConsoleEntry, ConsoleLevel, ConsoleSink, Limits, ModulePolicy, Permissions, RealmOptions, RunOptions, Runtime,
};
use ferrijs_bundle::{Bundler, BundlerOptions, BytecodeCache};

/// The engine already runs on mimalloc; putting the host side on it too
/// means the bundler, the source maps and every binding's `String` come
/// off the same heap, with no second allocator's arenas alongside it.
#[global_allocator]
static GLOBAL: ferrijs::alloc::MiGlobal = ferrijs::alloc::MiGlobal;

#[derive(Parser)]
#[command(name = "ferrijs", version, about = "An embeddable JavaScript runtime on QuickJS", long_about = None)]
struct Cli {
  #[command(subcommand)]
  command: Command,
}

#[derive(Subcommand)]
enum Command {
  /// Run a file. `.ts` / `.mjs` / `.js` with imports are bundled first;
  /// a plain script runs as is, with `args` bound.
  Run {
    file: PathBuf,
    /// Values bound as the `args` global, parsed as JSON when they parse
    /// and taken as strings otherwise.
    args: Vec<String>,
    #[command(flatten)]
    grants: Grants,
  },
  /// Evaluate source from the command line, printing the `return` value
  /// as JSON.
  Eval {
    source: String,
    #[command(flatten)]
    grants: Grants,
  },
}

/// What the realm may reach. Nothing, unless a flag says otherwise.
// A command line is a bag of switches; splitting them into structs would
// only move the booleans around.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Clone)]
struct Grants {
  /// Grant every kind.
  #[arg(long, short = 'A')]
  allow_all: bool,
  /// Directories or files the program may read (repeatable). Bare
  /// `--allow-read` grants everything.
  #[arg(long, num_args = 0.., value_delimiter = ',')]
  allow_read: Option<Vec<PathBuf>>,
  /// Directories or files the program may write (repeatable).
  #[arg(long, num_args = 0.., value_delimiter = ',')]
  allow_write: Option<Vec<PathBuf>>,
  /// Hosts the program may reach, `host`, `host:port` or `*.suffix`.
  #[arg(long, num_args = 0.., value_delimiter = ',')]
  allow_net: Option<Vec<String>>,
  /// Environment variables the program may read.
  #[arg(long, num_args = 0.., value_delimiter = ',')]
  allow_env: Option<Vec<String>>,
  /// Facts about the host the program may learn (`hostname`, `cpus`, ...).
  #[arg(long, num_args = 0.., value_delimiter = ',')]
  allow_sys: Option<Vec<String>>,
  /// Deny a path for reading even when granted (repeatable).
  #[arg(long, value_delimiter = ',')]
  deny_read: Vec<PathBuf>,
  /// Deny a path for writing even when granted (repeatable).
  #[arg(long, value_delimiter = ',')]
  deny_write: Vec<PathBuf>,
  /// Deny a host even when granted (repeatable).
  #[arg(long, value_delimiter = ',')]
  deny_net: Vec<String>,
  /// Wall-clock budget for the run, in seconds.
  #[arg(long, default_value_t = 300)]
  timeout: u64,
  /// Heap ceiling, in MiB.
  #[arg(long, default_value_t = 256)]
  memory_mb: usize,
  /// Refuse `eval` and `new Function`.
  #[arg(long)]
  no_eval: bool,
  /// Freeze the standard intrinsics.
  #[arg(long)]
  freeze_intrinsics: bool,
  /// Coarsen every clock to this many milliseconds.
  #[arg(long)]
  clock_ms: Option<u64>,
  /// Keep `node:fs`, `node:os` and the rest of the standard modules
  /// unserved, so nothing can be imported but files.
  #[arg(long)]
  no_builtins: bool,
  /// Print console output as JSON lines instead of plain text.
  #[arg(long)]
  json: bool,
}

impl Grants {
  fn permissions(&self) -> Result<Permissions, String> {
    if self.allow_all {
      return Ok(Permissions::all());
    }
    let mut p = Permissions::none();
    match &self.allow_read {
      Some(list) if list.is_empty() => p = p.allow_all_read(),
      Some(list) => p = p.allow_read(list),
      None => {},
    }
    match &self.allow_write {
      Some(list) if list.is_empty() => p = p.allow_all_write(),
      Some(list) => p = p.allow_write(list),
      None => {},
    }
    match &self.allow_net {
      Some(list) if list.is_empty() => p = p.allow_all_net(),
      Some(list) => p = p.allow_net(list)?,
      None => {},
    }
    match &self.allow_env {
      Some(list) if list.is_empty() => p = p.allow_all_env(),
      Some(list) => p = p.allow_env(list.clone()),
      None => {},
    }
    match &self.allow_sys {
      Some(list) if list.is_empty() => p = p.allow_all_sys(),
      Some(list) => {
        let items = list
          .iter()
          .map(|s| s.parse::<ferrijs::SysInfo>())
          .collect::<Result<Vec<_>, _>>()?;
        p = p.allow_sys(items);
      },
      None => {},
    }
    p = p
      .deny_read(&self.deny_read)
      .deny_write(&self.deny_write)
      .deny_net(&self.deny_net)?;
    Ok(p)
  }

  async fn runtime(&self, root: PathBuf) -> Result<Runtime, String> {
    let mut modules = ModulePolicy::new(root);
    if self.no_builtins {
      modules = modules.no_builtins();
    }
    let rt = Runtime::builder()
      .permissions(self.permissions()?)
      .limits(Limits {
        timeout: Duration::from_secs(self.timeout),
        memory: self.memory_mb * 1024 * 1024,
        ..Limits::default()
      })
      .realm(RealmOptions {
        eval: !self.no_eval,
        freeze_intrinsics: self.freeze_intrinsics,
        clock_resolution: self.clock_ms.map(Duration::from_millis),
        ..RealmOptions::default()
      })
      .modules(modules)
      .console(ferrijs::ConsoleOptions {
        sink: Some(Arc::new(Stdio { json: self.json })),
        ..ferrijs::ConsoleOptions::default()
      })
      .build()
      .await
      .map_err(|e| e.to_string())?;
    Ok(rt)
  }
}

/// Console output straight to the terminal, `log` and below to stdout,
/// `warn` and `error` to stderr, as Node does.
#[derive(Debug)]
struct Stdio {
  json: bool,
}

impl ConsoleSink for Stdio {
  fn emit(&self, entry: &ConsoleEntry) {
    use std::io::Write as _;
    if self.json {
      let line = serde_json::to_string(entry).unwrap_or_default();
      let _ = writeln!(std::io::stdout(), "{line}");
      return;
    }
    match entry.level {
      ConsoleLevel::Warn | ConsoleLevel::Error | ConsoleLevel::Trace => {
        let _ = writeln!(std::io::stderr(), "{}", entry.message);
      },
      _ => {
        let _ = writeln!(std::io::stdout(), "{}", entry.message);
      },
    }
  }

  fn styled_for(&self, level: ConsoleLevel) -> bool {
    use std::io::IsTerminal as _;
    !self.json
      && match level {
        ConsoleLevel::Warn | ConsoleLevel::Error | ConsoleLevel::Trace => std::io::stderr().is_terminal(),
        _ => std::io::stdout().is_terminal(),
      }
  }
}

fn parse_args(raw: &[String]) -> Vec<serde_json::Value> {
  raw
    .iter()
    .map(|a| serde_json::from_str(a).unwrap_or_else(|_| serde_json::Value::String(a.clone())))
    .collect()
}

async fn run_file(file: PathBuf, args: Vec<String>, grants: Grants) -> Result<ferrijs::Run<serde_json::Value>, String> {
  let file = std::fs::canonicalize(&file).map_err(|e| format!("{}: {e}", file.display()))?;
  let root = file.parent().map(PathBuf::from).unwrap_or_default();
  let rt = grants.runtime(root.clone()).await?;
  let source = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
  let args = parse_args(&args);
  let needs_bundle = ferrijs_bundle::is_typescript_path(&file) || ferrijs_bundle::source_is_es_module(&source);
  if needs_bundle {
    let bundler = Bundler::new(
      BundlerOptions::default(),
      Arc::clone(rt.registry()),
      BytecodeCache::for_app("ferrijs"),
    );
    let name = file
      .file_name()
      .map_or_else(|| "entry.js".to_string(), |n| n.to_string_lossy().into_owned());
    let module = bundler
      .compile(std::slice::from_ref(&file), &root, &name)
      .await
      .map_err(|e| e.to_string())?;
    Ok(rt.eval_module(&module, &args, RunOptions::default()).await)
  } else {
    Ok(rt.eval_script(&source, &args, RunOptions::default()).await)
  }
}

fn report(run: &ferrijs::Run<serde_json::Value>) -> ExitCode {
  match &run.result {
    Ok(value) => {
      if !value.is_null() {
        println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
      }
      ExitCode::SUCCESS
    },
    Err(e) => {
      eprintln!("{e}");
      if let Some(snippet) = &e.source_snippet {
        eprint!("{snippet}");
      }
      if let Some(stack) = &e.stack {
        eprintln!("{}", stack.trim_end());
      }
      ExitCode::FAILURE
    },
  }
}

/// `FERRIJS_STARTUP_TRACE=1` prints how long each startup phase took.
///
/// Worth knowing before reading them: on a typical macOS box most of a
/// `ferrijs eval` is spent before `main` is reached at all -- process
/// spawn, dyld and, where an endpoint-security agent is installed, its
/// inspection of the exec. These stamps measure only what happens after
/// that, which is the part this binary can do anything about.
fn main() -> ExitCode {
  let t = std::time::Instant::now();
  let trace = std::env::var_os("FERRIJS_STARTUP_TRACE").is_some();
  let stamp = move |what: &str| {
    if trace {
      eprintln!("  {:>8.3} ms  {what}", t.elapsed().as_secs_f64() * 1000.0);
    }
  };
  stamp("main entered");
  // Nothing to fall back to: without an executor there is no realm to
  // run anything in, and reporting it as a script failure would be a
  // lie about whose fault it was.
  #[allow(clippy::expect_used)]
  let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
  stamp("tokio runtime built");
  let code = rt.block_on(async_main(&stamp));
  stamp("work done");
  code
}

async fn async_main(stamp: &dyn Fn(&str)) -> ExitCode {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .with_writer(std::io::stderr)
    .init();
  stamp("tracing installed");
  let cli = Cli::parse();
  stamp("args parsed");
  let outcome = match cli.command {
    Command::Run { file, args, grants } => run_file(file, args, grants).await,
    Command::Eval { source, grants } => match grants.runtime(std::env::current_dir().unwrap_or_default()).await {
      Ok(rt) => {
        stamp("realm built");
        let r = rt.eval_script(&source, &[], RunOptions::default()).await;
        stamp("script evaluated");
        Ok(r)
      },
      Err(e) => Err(e),
    },
  };
  match outcome {
    Ok(run) => report(&run),
    Err(message) => {
      eprintln!("{message}");
      ExitCode::FAILURE
    },
  }
}
