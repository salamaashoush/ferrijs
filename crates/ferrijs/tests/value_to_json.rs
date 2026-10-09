#![allow(clippy::expect_used, clippy::unwrap_used)]
//! What `value_to_json` answers, value by value: the edges a faster
//! conversion would have to reproduce (boxed primitives, `toJSON`, unsafe
//! integers, lone surrogates, cycles, `BigInt`, top-level functions),
//! recorded from the serde walker.

use ferrijs::{RunOptions, Runtime};

/// `(expression, kind of a top-level number, the JSON text it becomes)`.
const CASES: &[(&str, &str, &str)] = &[
  ("1", "u64", "1"),
  ("-1", "i64", "-1"),
  ("0", "u64", "0"),
  ("-0", "u64", "0"),
  ("1.5", "f64", "1.5"),
  ("-2.25", "f64", "-2.25"),
  ("0.1 + 0.2", "f64", "0.30000000000000004"),
  ("2 ** 31", "u64", "2147483648"),
  ("2 ** 32", "u64", "4294967296"),
  ("2 ** 53 - 1", "u64", "9007199254740991"),
  ("2 ** 53", "f64", "9007199254740992.0"),
  ("-(2 ** 53)", "f64", "-9007199254740992.0"),
  ("2 ** 60", "f64", "1.152921504606847e+18"),
  ("1e21", "f64", "1e+21"),
  ("1e-7", "f64", "1e-7"),
  ("NaN", "", "null"),
  ("Infinity", "", "null"),
  ("-Infinity", "", "null"),
  ("true", "", "true"),
  ("false", "", "false"),
  ("null", "", "null"),
  ("undefined", "", "null"),
  (r#""plain""#, "", r#""plain""#),
  (r#""é中😀""#, "", r#""é中😀""#),
  (r#""\ud800""#, "", r#""�""#),
  (r#""a\u0000b\n\"q\"""#, "", r#""a\u0000b\n\"q\"""#),
  ("[]", "", "[]"),
  (
    r#"[1, "two", null, undefined, () => 1, Symbol("s"), NaN, [3]]"#,
    "",
    r#"[1,"two",null,null,null,null,null,[3]]"#,
  ),
  ("[1, , 3]", "", "[1,null,3]"),
  ("({})", "", "{}"),
  (
    r#"({ a: 1, b: "two", c: [1, 2, 3], d: { e: null } })"#,
    "",
    r#"{"a":1,"b":"two","c":[1,2,3],"d":{"e":null}}"#,
  ),
  (
    r#"({ u: undefined, f() {}, s: Symbol("x"), n: NaN, i: -Infinity })"#,
    "",
    r#"{"i":null,"n":null}"#,
  ),
  (r#"({ [Symbol("k")]: 1, k: 2 })"#, "", r#"{"k":2}"#),
  (
    r#"({ 2: "two", 1: "one", b: 1, a: 2 })"#,
    "",
    r#"{"1":"one","2":"two","a":2,"b":1}"#,
  ),
  (
    "({ toJSON() { return { replaced: true }; } })",
    "",
    r#"{"replaced":true}"#,
  ),
  ("({ toJSON() { return undefined; } })", "", "null"),
  (r#"({ nested: { toJSON: () => "s" } })"#, "", r#"{"nested":"s"}"#),
  ("new Date(0)", "", r#""1970-01-01T00:00:00.000Z""#),
  ("({ d: new Date(86400000) })", "", r#"{"d":"1970-01-02T00:00:00.000Z"}"#),
  ("new Number(5)", "u64", "5"),
  (r#"new String("boxed")"#, "", r#""boxed""#),
  ("new Boolean(false)", "", "false"),
  (
    r#"({ a: new Number(1.5), b: new String("x"), c: new Boolean(true) })"#,
    "",
    r#"{"a":1.5,"b":"x","c":true}"#,
  ),
  ("new Map([[1, 2]])", "", "{}"),
  ("new Set([1])", "", "{}"),
  ("/re/g", "", "{}"),
  ("new Uint8Array([1, 2, 3])", "", r#"{"0":1,"1":2,"2":3}"#),
  ("new ArrayBuffer(2)", "", "{}"),
  (r#"new Error("boom")"#, "", "{}"),
  (
    "Object.create({ inherited: 1 }, { own: { value: 2, enumerable: true }, hidden: { value: 3 } })",
    "",
    r#"{"own":2}"#,
  ),
  (
    "new (class P { constructor() { this.x = 1; } get y() { return 2; } })()",
    "",
    r#"{"x":1}"#,
  ),
  ("new Proxy({ a: 1 }, {})", "", r#"{"a":1}"#),
  ("new Proxy([1, 2], {})", "", "[1,2]"),
  ("Object.assign(Object.create(null), { z: 1 })", "", r#"{"z":1}"#),
  ("(() => { const o = { a: 1 }; o.self = o; return o; })()", "", "null"),
  ("10n", "", r#""10""#),
  ("({ big: 10n })", "", r#"{"big":"10"}"#),
  ("() => 1", "", "{}"),
  (r#"Symbol("top")"#, "", "null"),
  (r#""x".repeat(40)"#, "", r#""xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#),
  (
    "Array.from({ length: 5 }, (_, i) => ({ i, s: String(i), f: i / 3 }))",
    "",
    r#"[{"f":0,"i":0,"s":"0"},{"f":0.3333333333333333,"i":1,"s":"1"},{"f":0.6666666666666666,"i":2,"s":"2"},{"f":1,"i":3,"s":"3"},{"f":1.3333333333333333,"i":4,"s":"4"}]"#,
  ),
  (r#"({ "\ud800": 1, "é": 2 })"#, "", r#"{"é":2,"�":1}"#),
];

#[tokio::test]
async fn every_value_converts_as_recorded() {
  let realm = Runtime::builder().build().await.expect("runtime");
  for (expression, kind, expected) in CASES {
    let run = realm
      .eval_script(&format!("return ({expression})"), &[], RunOptions::default())
      .await;
    let value = run.result.unwrap_or_else(|e| panic!("{expression}: {e}"));
    // Compared as values, not text: a workspace that turns on
    // `serde_json/preserve_order` keeps keys in insertion order, and map
    // equality ignores order either way. Number variants still differ.
    let expected_value: serde_json::Value = serde_json::from_str(expected).unwrap();
    assert_eq!(value, expected_value, "{expression}");
    let actual_kind = match &value {
      serde_json::Value::Number(n) if n.is_f64() => "f64",
      serde_json::Value::Number(n) if n.is_u64() => "u64",
      serde_json::Value::Number(_) => "i64",
      _ => "",
    };
    assert_eq!(&actual_kind, kind, "{expression}");
  }
}
