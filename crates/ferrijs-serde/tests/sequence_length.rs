use rquickjs::{Context, Runtime, Value};

#[test]
fn proxy_array_lengths_follow_javascript_coercion() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Runtime::new()?;
  let ctx = Context::full(&rt)?;
  for (length, expected) in [
    ("'2'", vec![10, 20]),
    ("undefined", vec![]),
    ("null", vec![]),
    ("true", vec![10]),
    ("-1", vec![]),
    ("1.9", vec![10]),
    ("NaN", vec![]),
    ("({ n: 2, valueOf() { return this.n; } })", vec![10, 20]),
  ] {
    ctx.with(|ctx| -> Result<(), Box<dyn std::error::Error>> {
      let source = format!("new Proxy([10, 20, 30], {{ get(t, k, r) {{ return k === 'length' ? {length} : Reflect.get(t, k, r); }} }})");
      let value: Value<'_> = ctx.eval(source)?;
      let actual: Vec<i32> = ferrijs_serde::from_value(value)?;
      assert_eq!(actual, expected, "{length}");
      Ok(())
    })?;
  }
  Ok(())
}
