mod support;

/// Collation by the locale's rules (German ä beside a, Swedish ä after
/// z), strength, numeric ordering, the options a collator resolves and
/// reports, `localeCompare` over the same, and the tags it refuses.
const CASES: &[(&str, &str)] = &[
  (
    "['z', 'ä', 'a', 'Z', 'b'].sort(new Intl.Collator('de').compare).join(',')",
    "a,ä,b,z,Z",
  ),
  (
    "['z', 'ä', 'a'].sort(new Intl.Collator('sv').compare).join(',')",
    "a,z,ä",
  ),
  (
    "new Intl.Collator('en', { sensitivity: 'base' }).compare('a', 'Á')",
    "0",
  ),
  (
    "new Intl.Collator('en', { sensitivity: 'accent' }).compare('a', 'á')",
    "-1",
  ),
  (
    "new Intl.Collator('en', { sensitivity: 'case' }).compare('a', 'á')",
    "0",
  ),
  (
    "new Intl.Collator('en', { sensitivity: 'case' }).compare('a', 'A')",
    "-1",
  ),
  (
    "['10', '9', '2'].sort(new Intl.Collator('en', { numeric: true }).compare).join(',')",
    "2,9,10",
  ),
  (
    "['10', '9', '2'].sort(new Intl.Collator('en-u-kn').compare).join(',')",
    "2,9,10",
  ),
  (
    "JSON.stringify(new Intl.Collator('de-u-co-phonebk-kn', { caseFirst: 'upper' }).resolvedOptions())",
    r#"{"locale":"de-u-co-phonebk-kn","usage":"sort","sensitivity":"variant","ignorePunctuation":false,"collation":"phonebk","numeric":true,"caseFirst":"upper"}"#,
  ),
  ("new Intl.Collator().resolvedOptions().locale", "en-US"),
  ("new Intl.Collator('en-u-co-phonebk').resolvedOptions().locale", "en"),
  (
    "(() => { const c = new Intl.Collator(); return c.compare === c.compare; })()",
    "true",
  ),
  (
    "(() => { const { compare } = new Intl.Collator(); return compare('a', 'b'); })()",
    "-1",
  ),
  ("'ä'.localeCompare('z', 'de')", "-1"),
  ("'ä'.localeCompare('z', 'sv')", "1"),
  ("'a'.localeCompare('A', undefined, { sensitivity: 'base' })", "0"),
  (
    "String.prototype.localeCompare.call(null, 'a')",
    "TypeError: String.prototype.localeCompare called on null or undefined",
  ),
  (
    "new Intl.Collator('en_US')",
    "RangeError: Incorrect locale information provided: en_US",
  ),
  ("Intl.getCanonicalLocales(['EN-us', 'en-US', 'iw']).join()", "en-US,he"),
  (
    "new Intl.Collator('en', { usage: 'x' })",
    "RangeError: Value x out of range for option usage",
  ),
  (
    "Intl.Collator.supportedLocalesOf(['en-US', 'zz', 'ar-EG']).join()",
    "en-US,ar-EG",
  ),
];

#[test]
fn collator_compares_by_the_locale() {
  support::check(CASES);
}
