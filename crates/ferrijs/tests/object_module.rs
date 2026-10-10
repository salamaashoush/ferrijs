#![allow(clippy::expect_used, clippy::unwrap_used)]
//! A host module whose exports are one object: `import` and `require`
//! see the same values, built once per realm.

use std::sync::atomic::{AtomicUsize, Ordering};

use ferrijs::rquickjs::{Ctx, Function, Object};
use ferrijs::{Extension, ModuleRegistry, NativeModule, ObjectModule, RunOptions, Runtime};

static BUILDS: AtomicUsize = AtomicUsize::new(0);

struct Acme;

impl ObjectModule for Acme {
  const EXPORTS: &'static [&'static str] = &["greet", "version"];

  fn build<'js>(ctx: &Ctx<'js>) -> ferrijs::rquickjs::Result<Object<'js>> {
    BUILDS.fetch_add(1, Ordering::Relaxed);
    let object = Object::new(ctx.clone())?;
    object.set(
      "greet",
      Function::new(ctx.clone(), |name: String| format!("hello, {name}"))?,
    )?;
    object.set("version", 3)?;
    Ok(object)
  }
}

struct AcmeExtension;

impl Extension for AcmeExtension {
  fn name(&self) -> &'static str {
    "acme"
  }

  fn modules(&self, registry: &mut ModuleRegistry) -> Result<(), String> {
    registry.register(NativeModule::from_object::<Acme>(["acme", "acme/v3"]))
  }
}

#[tokio::test]
async fn import_and_require_share_one_build() {
  let realm = Runtime::builder()
    .extension(AcmeExtension)
    .build()
    .await
    .expect("runtime");
  let run = realm
    .eval_module_source(
      "entry.mjs",
      "import acme, { greet, version } from 'acme';
       import * as aliased from 'acme/v3';
       export default [
         greet('acme'),
         version,
         require('acme') === acme,
         aliased.default === acme,
         aliased.greet === greet,
       ];",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    run.result.unwrap(),
    serde_json::json!(["hello, acme", 3, true, true, true])
  );
  assert_eq!(BUILDS.load(Ordering::Relaxed), 1);
}
