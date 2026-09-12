use rquickjs::{Context, Runtime, Value};

#[test]
fn lone_surrogate_conversion_releases_temporary_engine_strings() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Runtime::new()?;
  let ctx = Context::full(&rt)?;
  let convert = || ctx.with(|ctx| -> Result<(), Box<dyn std::error::Error>> {
    let value: Value<'_> = ctx.eval("'before\\ud800after'")?;
    let value: String = ferrijs_serde::from_value(value)?;
    assert_eq!(value, "before\u{fffd}after");
    Ok(())
  });
  convert()?;
  rt.run_gc();
  let before = rt.memory_usage().memory_used_size;
  for _ in 0..1000 {
    convert()?;
  }
  rt.run_gc();
  let growth = rt.memory_usage().memory_used_size - before;
  assert!(growth < 1024, "converting 1000 strings retained {growth} bytes");
  Ok(())
}
