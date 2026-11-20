# ferrijs-intl

ECMA-402 `Intl` for the [ferrijs](../../README.md) runtime, on
[ICU4X](https://github.com/unicode-org/icu4x) with CLDR's data compiled
into the binary. The runtime installs it with its `intl` feature.

```rust
let rt = ferrijs::Runtime::builder()
  .intl(ferrijs::intl::IntlOptions {
    default_locale: Some("ar-EG".into()),
    default_time_zone: Some("Africa/Cairo".into()),
  })
  .build()
  .await?;
```

Without options the defaults are the host's, as Node's are: the locale
from `LC_ALL`, `LC_MESSAGES` or `LANG`, the time zone from `TZ` or the
system's configuration.

## What it has

`Intl.Collator`, `NumberFormat`, `DateTimeFormat`, `PluralRules`,
`RelativeTimeFormat`, `ListFormat`, `DisplayNames`, `Segmenter`,
`Locale`, `getCanonicalLocales` and `supportedValuesOf`; and the
methods ECMA-402 redefines on the language's own prototypes:
`String.prototype.localeCompare`, `toLocaleUpperCase`,
`toLocaleLowerCase`, `Number.prototype.toLocaleString`,
`BigInt.prototype.toLocaleString`, and `Date.prototype.toLocaleString`,
`toLocaleDateString` and `toLocaleTimeString`.

Time zones are IANA's, with real transitions: an instant becomes wall
time through [jiff](https://github.com/BurntSushi/jiff) over the
platform's tzdb, or the copy jiff bundles where there is none. Dates are
formatted in any calendar ICU4X has: Gregorian, ISO, Buddhist, Chinese,
Coptic, Dangi, Ethiopic, Hebrew, Indian, the tabular and Umm al-Qura
Hijri calendars, Japanese, Persian and ROC.

## How it stays fast

- **No parsing at run time.** The data is baked into the binary as
  static structures, so a formatter is built from pointers into it.
- **`Intl` installs on first read.** A realm that never touches it pays
  for one accessor.
- **Formatters are kept.** Every built-in method is specified to make a
  new `Intl` object per call, so `array.sort((a, b) => a.localeCompare(b))`
  would build a collator per comparison. The realm keeps each formatter
  it builds under the options it was resolved from, and constructors
  share them too: `new Intl.NumberFormat('en')` in a loop builds once.
- **`format` and `compare` are bound once** per object, as the spec has
  them, and capture only Rust data.

## Conformance

`tests/cases/*.js` lists expressions; `tests/cases/generate.js` runs each
under Node and writes the Rust test that pins Node's answer. Regenerate
after changing a case:

```sh
LANG=en_US.UTF-8 TZ=UTC node tests/cases/generate.js number_format > tests/number_format.rs
cargo fmt -p ferrijs-intl
```

Where ICU4X's data or algorithm answers differently from V8's ICU4C and
both answers are defensible, the case pins this crate's answer and says
why beside it. Today that is:

- **German default date:** `05.03.2024` where V8 has `5.3.2024`.
  ICU4X uses CLDR's short date pattern; ICU4C matches the `yMd`
  skeleton.
- **A date with a time zone name and no time:** `3/5/2024 PST`, where
  V8 has `3/5/2024, PST`. The difference is the glue pattern.
- **Years before 1:** ICU4X writes the era (`1/1/2 BC`) and ICU4C does
  not.
- **`Intl.Locale#getCalendars()`:** returns only the region's default
  calendar. ICU4X does not carry CLDR's full calendar preference list.

Data ICU4X does not have:

- **Unit names for temperature, digital storage, angle and percent:**
  these use CLDR's root symbols (`°C`, `kB`, `%`) at every width.
- **Calendar and date-time field names in `DisplayNames`:** these
  answer as `fallback` says.
