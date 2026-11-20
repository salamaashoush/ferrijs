#![allow(clippy::expect_used)]
use ferrijs_intl::{IntlOptions, install};
use rquickjs::{Context, Runtime};

/// Evaluate `source` in a fresh realm with `Intl` installed (default
/// locale `en-US`, default time zone `UTC`) and return its completion
/// value as a string, or the thrown error's `name: message`.
pub fn eval(source: &str) -> String {
  eval_with(
    &IntlOptions {
      default_locale: Some("en-US".to_owned()),
      default_time_zone: Some("UTC".to_owned()),
    },
    source,
  )
}

pub fn eval_with(options: &IntlOptions, source: &str) -> String {
  let runtime = Runtime::new().expect("runtime");
  let context = Context::full(&runtime).expect("context");
  context.with(|ctx| {
    install(&ctx, options).expect("install");
    let wrapped = format!(
      "(() => {{ try {{ return String((() => {{ {source} }})()); }} catch (e) {{ return `${{e && e.name}}: ${{e && e.message}}`; }} }})()"
    );
    ctx.eval::<String, _>(wrapped).expect("eval")
  })
}

/// Evaluate each expression and report every one whose result differs
/// from the expected string, all at once.
pub fn check(cases: &[(&str, &str)]) {
  let mismatches: Vec<String> = cases
    .iter()
    .filter_map(|(expression, expected)| {
      let actual = eval(&format!("return {expression}"));
      (actual != *expected).then(|| format!("{expression}\n    node: {expected:?}\n    ours: {actual:?}"))
    })
    .collect();
  assert!(
    mismatches.is_empty(),
    "{} of {} differ:\n  {}",
    mismatches.len(),
    cases.len(),
    mismatches.join("\n  ")
  );
}
