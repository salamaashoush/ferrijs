# Embedding ferrijs

How a host puts ferrijs to work: build a realm, give it an API, call
into it and back out, and run code shipped as a bundle. Every item here
is public API; the examples use `acme` as the host.

## A realm

```rust
let realm = ferrijs::Runtime::builder()
  .permissions(ferrijs::Permissions::none())
  .limits(ferrijs::Limits { timeout: Duration::from_secs(5), ..Default::default() })
  .extension(Acme)
  .on_uncaught(|error| tracing::warn!("uncaught: {}", error.message))
  .build()
  .await?;

let run = realm.eval_script("return args[0] * 2", &[21.into()], RunOptions::default()).await;
```

A `Runtime` is one realm: engine, context, event loop and policy. Two
trust levels are two realms. A realm that must start fast takes one from
a `RealmPool`, which keeps built realms ready.

Every run is bracketed: a deadline, a heap ceiling, its own console
capture. A run fails on the first exception nothing caught, whether
thrown by the body or by a timer, `queueMicrotask`, `process.nextTick`
or `setImmediate` callback while it runs, as Node exits on one. Outside
a run, `on_uncaught` hears them. A timeout or an allocation fault
poisons the realm (`Runtime::poisoned`); build a new one.

## An extension

```rust
struct Acme;

impl ferrijs::Extension for Acme {
  fn name(&self) -> &str { "acme" }

  fn modules(&self, registry: &mut ferrijs::ModuleRegistry) -> Result<(), String> {
    registry.register(ferrijs::NativeModule::from_object::<AcmeModule>(["acme"]))
  }

  fn install(&self, ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    ctx.globals().set("acme", Function::new(ctx.clone(), greet)?)
  }
}
```

`install` runs once per realm. Surface a script may never touch goes
behind `ferrijs::lazy::define`, so a realm pays for it on first use.

A module whose exports are one object implements `ObjectModule`: a list
of names and a `build` function. `import` and `require` then see the
same values, built once per realm.

```rust
struct AcmeModule;

impl ferrijs::ObjectModule for AcmeModule {
  const EXPORTS: &'static [&'static str] = &["greet"];

  fn build<'js>(ctx: &Ctx<'js>) -> rquickjs::Result<Object<'js>> {
    let module = Object::new(ctx.clone())?;
    module.set("greet", Function::new(ctx.clone(), greet)?)?;
    Ok(module)
  }
}
```

## Host state

`ferrijs::host` keeps any `'static` value in the realm, found by its
type from any binding, with no `unsafe` on the host's side:

- `host::set(ctx, value)` stores, replacing the value of that type.
- `host::with(ctx, |value: &mut T| ...)` and `with_or_default` borrow it.
- `host::get::<T>(ctx)` clones it out, the way to reach an `Arc` or a
  channel from code that then runs script. `with` must not run script,
  since a binding the script calls may borrow the same value.
- `host::take::<T>(ctx)` removes it.

## Calling back into script

`host::Callback::save(ctx, function)` keeps a script function past the
call that handed it over. `call` invokes it; `call_async` also awaits
the promise it returns, the way script awaits an async listener.

A host task reaches the realm two ways, and only these two:

- **A job.** `vm_with!(realm.handle() => |ctx| { ... })` runs a body on
  the realm's loop and answers its value. `vm_try!` does the same for a
  body that returns `Result<T, ScriptError>` and flattens the result.
  Jobs interleave with each other and with a run parked on an await.
- **A pump.** `host::Pump::start(ctx, capacity, handler)` starts a
  handler on the loop and answers a cloneable, `Send` sender. Events a
  host raises on its own threads (a page event, a socket frame) go in
  with `try_send` or `send` and are handled in order, during a run and
  between runs. A handler's error is reported as uncaught.

Never create an `async_with` against a realm, and never touch its
context from another thread: the loop owns the scheduler's single wake
slot, and a second poller loses every later wake.

## Errors

A binding throws real JavaScript errors that carry their whole message:
`value::type_error`, `value::range_error`, `value::throw_error` (any
built-in class, with an optional Node-style `code`) and
`value::throw_named`. `rquickjs::Error::new_from_js_message` cuts a
message at 255 bytes and reads "Error converting from js", so it is not
for script-facing errors.

Going the other way, `JsResultExt::or_script_error(ctx)` turns any
rquickjs failure into a `ScriptError`: a thrown value keeps its name,
message and stack (mapped through a registered bundle), anything else
is internal. In a job body that is one `?`:

```rust
let total = vm_try!(vm => |ctx| {
  let add: Function = ctx.globals().get("add").or_script_error(&ctx)?;
  add.call::<_, i32>((2, 3)).or_script_error(&ctx)
}).await?;
```

## Values

- `value::serde_to_js` and `value::serde_from_js` convert any serde type
  directly, with no JSON in between; `value::parse_opt_bag` reads an
  optional options object.
- `value::json_to_js` and `value::value_to_json` convert
  `serde_json::Value`, and stay correct when a dependency turns on
  `serde_json/arbitrary_precision`.
- `value::buffer_source_bytes` and `value::value_to_bytes` copy the bytes
  out of any byte-shaped value, so script may run while the host holds
  them.
- `value::settle(ctx, value)` awaits a value that may be a promise.
- `value::Null<T>` answers `null` rather than `undefined` for a missing
  value.

## Bundles

`ferrijs_bundle::Bundler` compiles TypeScript or JavaScript entries to
bytecode over the realm's own module table, so what stays external at
bundle time is what the realm serves. `BytecodeCache::from_env("acme")`
keeps the bytecode between processes, under `$ACME_CACHE_DIR` when set
and off when `ACME_NO_BYTECODE_CACHE` is.

`Runtime::eval_module(&compiled, args, options)` is a whole run. A host
body that does more in the same run calls `compiled.evaluate(&ctx)`,
which registers the source map and answers the evaluated module, then
reads its namespace. `compiled.remap_error(error)` names an error's
position in the original source.
