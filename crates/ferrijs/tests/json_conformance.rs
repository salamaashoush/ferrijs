#![allow(clippy::expect_used, clippy::unwrap_used)]
//! What a realm's `JSON` must do, checked against what Node answers.
//!
//! `ferrijs-std` vendors a simd-json-backed `JSON` (`json::
//! redefine_static_methods`) that is about a third faster than the
//! engine's both ways. It is not installed, and these are the cases
//! that say why: every expectation below is the literal output of
//! Node 22 for the same input, and the vendored implementation fails
//! eight of them -- one by handing back an object whose prototype the
//! parsed text chose.
//!
//! So this file is two things at once. It pins the behaviour a realm
//! has today, and it is the bar the faster implementation has to clear
//! before anyone turns it on.

use ferrijs::{RunOptions, Runtime};

async fn realm() -> Runtime {
  Runtime::builder().build().await.expect("runtime")
}

/// `(what, script, what Node prints)`.
const CASES: &[(&str, &str, &str)] = &[
  // --- the eight the vendored implementation gets wrong ---------------
  (
    "an undefined or function array element is null, not a hole",
    "return JSON.stringify([undefined, function () {}, 1])",
    "[null,null,1]",
  ),
  ("a hole is null", "return JSON.stringify([1, , 3])", "[1,null,3]"),
  ("negative zero serialises as zero", "return JSON.stringify(-0)", "0"),
  (
    "large numbers take ToString's exponent form",
    "return JSON.stringify(1e21)",
    "1e+21",
  ),
  (
    "boxed primitives unwrap",
    "return JSON.stringify({ a: new Number(5), b: new String('x'), c: new Boolean(true) })",
    "{\"a\":5,\"b\":\"x\",\"c\":true}",
  ),
  (
    "parse applies its reviver",
    "return JSON.stringify(JSON.parse('{\"a\":1,\"b\":2}', (k, v) => typeof v === 'number' ? v + 1 : v))",
    "{\"a\":2,\"b\":3}",
  ),
  (
    "a __proto__ key parses to an own property and does not retarget the prototype",
    "const o = JSON.parse('{\"__proto__\":{\"polluted\":1}}');
     return JSON.stringify([Object.keys(o), Object.getPrototypeOf(o) === Object.prototype, o.polluted ?? null])",
    "[[\"__proto__\"],true,null]",
  ),
  (
    "parse preserves negative zero",
    "return String(Object.is(JSON.parse('-0'), -0))",
    "true",
  ),
  // --- and the surface those eight sit in ----------------------------
  (
    "an array replacer keeps the named object keys",
    "return JSON.stringify({ a: 1, b: 2, c: 3 }, ['a', 'c'])",
    "{\"a\":1,\"c\":3}",
  ),
  (
    "an array replacer does not filter array elements by index",
    "return JSON.stringify({ a: [10, 20, 30] }, ['a'])",
    "{\"a\":[10,20,30]}",
  ),
  (
    "a function replacer maps every value",
    "return JSON.stringify({ a: 1, b: 2 }, (k, v) => typeof v === 'number' ? v * 10 : v)",
    "{\"a\":10,\"b\":20}",
  ),
  (
    "a null replacer with a numeric space still indents",
    "return JSON.stringify({ a: [1, 2] }, null, 2)",
    "{\n  \"a\": [\n    1,\n    2\n  ]\n}",
  ),
  (
    "space is clamped to ten",
    "return String(JSON.stringify({ a: 1 }, null, 20).length)",
    "20",
  ),
  (
    "a non-callable toJSON is a plain property, not an error",
    "return JSON.stringify({ toJSON: 'x', a: 1 })",
    "{\"toJSON\":\"x\",\"a\":1}",
  ),
  (
    "a callable toJSON replaces the value",
    "return JSON.stringify({ toJSON() { return { z: 9 }; } })",
    "{\"z\":9}",
  ),
  (
    "a Date serialises through its toJSON",
    "return JSON.stringify({ d: new Date(86400000) })",
    "{\"d\":\"1970-01-02T00:00:00.000Z\"}",
  ),
  (
    "undefined, functions and symbol keys drop out of objects",
    "return JSON.stringify({ a: undefined, f() {}, [Symbol('s')]: 1, b: 1 })",
    "{\"b\":1}",
  ),
  (
    "non-finite numbers are null",
    "return JSON.stringify({ a: NaN, b: Infinity, c: -Infinity })",
    "{\"a\":null,\"b\":null,\"c\":null}",
  ),
  (
    "control characters are escaped",
    "return JSON.stringify(String.fromCharCode(0) + String.fromCharCode(31) + String.fromCharCode(10))",
    "\"\\u0000\\u001f\\n\"",
  ),
  (
    "a lone surrogate is escaped rather than emitted",
    "return JSON.stringify('\\ud800')",
    "\"\\ud800\"",
  ),
  (
    "integer keys come before string keys, in insertion order",
    "return JSON.stringify({ b: 1, a: 2, 1: 3, 0: 4 })",
    "{\"0\":4,\"1\":3,\"b\":1,\"a\":2}",
  ),
  (
    "a surrogate pair parses to one code point",
    "return JSON.parse('\"\\\\ud83d\\\\ude00\"')",
    "\u{1F600}",
  ),
  (
    "the last duplicate key wins",
    "return JSON.stringify(JSON.parse('{\"a\":1,\"a\":2}'))",
    "{\"a\":2}",
  ),
];

/// Inputs `JSON.parse` must reject.
const REJECTED: &[&str] = &[
  "{\"a\":1,}",
  "{'a':1}",
  "NaN",
  "undefined",
  "",
  "01",
  "{\"a\":1} // trailing",
];

#[tokio::test]
async fn json_matches_node() {
  let rt = realm().await;
  let mut failures = Vec::new();
  for (what, script, expected) in CASES {
    let run = rt.eval_script(script, &[], RunOptions::default()).await;
    match run.result {
      Ok(serde_json::Value::String(got)) if got == *expected => {},
      Ok(other) => failures.push(format!("{what}\n  expected {expected:?}\n  got      {other}")),
      Err(e) => failures.push(format!("{what}\n  expected {expected:?}\n  threw    {e}")),
    }
  }
  assert!(
    failures.is_empty(),
    "JSON diverged from Node:\n\n{}",
    failures.join("\n\n")
  );
}

#[tokio::test]
async fn json_stringify_refuses_what_it_cannot_represent() {
  let rt = realm().await;
  for (what, script) in [
    ("a cycle", "const o = {}; o.self = o; return JSON.stringify(o)"),
    ("a BigInt", "return JSON.stringify({ a: 1n })"),
  ] {
    let run = rt.eval_script(script, &[], RunOptions::default()).await;
    let err = run.err().unwrap_or_else(|| panic!("{what} should have thrown"));
    assert_eq!(err.name.as_deref(), Some("TypeError"), "{what}: {err}");
  }
}

#[tokio::test]
async fn json_parse_rejects_what_is_not_json() {
  let rt = realm().await;
  for text in REJECTED {
    let script = format!("return JSON.parse({})", serde_json::Value::String((*text).to_string()));
    let run = rt.eval_script(&script, &[], RunOptions::default()).await;
    let err = run.err().unwrap_or_else(|| panic!("`{text}` should not have parsed"));
    assert_eq!(err.name.as_deref(), Some("SyntaxError"), "`{text}`: {err}");
  }
}

#[tokio::test]
async fn top_level_primitives_round_trip() {
  let rt = realm().await;
  let run = rt
    .eval_script(
      "return [JSON.stringify(1), JSON.stringify('s'), JSON.stringify(null),
               JSON.stringify(true), String(JSON.stringify(undefined))].join('|')",
      &[],
      RunOptions::default(),
    )
    .await;
  assert_eq!(
    run.result.expect("run"),
    serde_json::json!("1|\"s\"|null|true|undefined")
  );
}
