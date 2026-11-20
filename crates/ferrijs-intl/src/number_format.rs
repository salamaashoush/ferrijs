//! `Intl.NumberFormat`, `Number.prototype.toLocaleString` and
//! `BigInt.prototype.toLocaleString`.
//!
//! The digits are ECMA-402's: the value is rounded here, on an exact
//! decimal, under the digit options, rounding mode and increment the
//! spec defines, and written by ICU4X's `DecimalFormatter` with the
//! grouping and numbering system resolved. What surrounds the digits
//! (a currency symbol and its spacing, a percent sign, a unit name, an
//! accounting parenthesis, where the sign goes) comes from ICU4X's
//! currency, percent and unit data: the style's formatter writes the
//! same value, and its digits are replaced by these.

use std::rc::Rc;

use fixed_decimal::{
  Decimal, FloatPrecision, RoundingIncrement, Sign, SignDisplay, SignedRoundingMode, UnsignedRoundingMode,
};
use icu::decimal::options::{CompactDecimalFormatterOptions, DecimalFormatterOptions, GroupingStrategy};
use icu::decimal::provider::{Baked as DecimalBaked, DecimalDigitsV1, DecimalSymbolsV1};
use icu::decimal::{CompactDecimalFormatter, DecimalFormatter, DecimalFormatterPreferences};
use icu::experimental::dimension::currency::CurrencyType;
use icu::experimental::dimension::currency::formatter::{CurrencyFormatter, CurrencyFormatterPreferences};
use icu::experimental::dimension::currency::options::{CurrencyFormatterOptions, CurrencyUsage};
use icu::experimental::dimension::percent::formatter::{PercentFormatter, PercentFormatterPreferences};
use icu::experimental::dimension::percent::options::PercentFormatterOptions;
use icu::locale::Locale;
use icu::plurals::{PluralRules, PluralRulesPreferences};
use icu_provider::prelude::*;
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Array, Class, Ctx, Exception, Function, JsLifetime, Object, Result, Value};
use writeable::Part;

use crate::locale;
use crate::options;
use crate::parts::{self, JsPart, Recorder};
use crate::units::UnitNames;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
  Decimal,
  Percent,
  Currency,
  Unit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Notation {
  Standard,
  Scientific,
  Engineering,
  Compact,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RoundingType {
  Fraction,
  Significant,
  MorePrecision,
  LessPrecision,
}

/// What `SetNumberFormatDigitOptions` resolves, shared with
/// `Intl.PluralRules`, which takes the same options.
#[derive(Clone)]
pub(crate) struct Digits {
  pub(crate) minimum_integer: i16,
  pub(crate) minimum_fraction: i16,
  pub(crate) maximum_fraction: i16,
  pub(crate) minimum_significant: i16,
  pub(crate) maximum_significant: i16,
  rounding_type: RoundingType,
  pub(crate) rounding_priority: &'static str,
  pub(crate) rounding_increment: u16,
  pub(crate) rounding_mode: &'static str,
  pub(crate) trailing_zero_display: &'static str,
}

impl Digits {
  /// `SetNumberFormatDigitOptions(intlObj, options, mnfdDefault, mxfdDefault, notation)`.
  pub(crate) fn read<'js>(
    ctx: &Ctx<'js>,
    options: Option<&Object<'js>>,
    fraction_defaults: (i16, i16),
    compact: bool,
  ) -> Result<Self> {
    let get = |name: &str| -> Result<Value<'js>> {
      match options {
        Some(options) => options.get(name),
        None => Ok(Value::new_undefined(ctx.clone())),
      }
    };
    let minimum_integer = options::number(ctx, options, "minimumIntegerDigits", 1, 21)?.unwrap_or(1);
    let fraction_min_raw = get("minimumFractionDigits")?;
    let fraction_max_raw = get("maximumFractionDigits")?;
    let significant_min_raw = get("minimumSignificantDigits")?;
    let significant_max_raw = get("maximumSignificantDigits")?;
    let rounding_increment = options::number(ctx, options, "roundingIncrement", 1, 5000)?.unwrap_or(1);
    if ![1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000].contains(&rounding_increment) {
      return Err(Exception::throw_range(ctx, "roundingIncrement value is out of range."));
    }
    let rounding_mode = options::string(
      ctx,
      options,
      "roundingMode",
      &[
        "ceil",
        "floor",
        "expand",
        "trunc",
        "halfCeil",
        "halfFloor",
        "halfExpand",
        "halfTrunc",
        "halfEven",
      ],
    )?
    .unwrap_or("halfExpand");
    let rounding_priority = options::string(
      ctx,
      options,
      "roundingPriority",
      &["auto", "morePrecision", "lessPrecision"],
    )?
    .unwrap_or("auto");
    let trailing_zero_display =
      options::string(ctx, options, "trailingZeroDisplay", &["auto", "stripIfInteger"])?.unwrap_or("auto");

    let (fraction_min_default, fraction_max_default) = fraction_defaults;
    let fraction_max_default = if rounding_increment == 1 {
      fraction_max_default
    } else {
      fraction_min_default
    };
    let significant_given = !significant_min_raw.is_undefined() || !significant_max_raw.is_undefined();
    let fraction_given = !fraction_min_raw.is_undefined() || !fraction_max_raw.is_undefined();
    let mut significant_wanted = true;
    let mut fraction_wanted = true;
    if rounding_priority == "auto" {
      significant_wanted = significant_given;
      if significant_wanted || (!fraction_given && compact) {
        fraction_wanted = false;
      }
    }
    let (mut minimum_significant, mut maximum_significant) = (1, 21);
    if significant_wanted && significant_given {
      minimum_significant =
        options::default_number(ctx, &significant_min_raw, "minimumSignificantDigits", 1, 21)?.unwrap_or(1);
      maximum_significant = options::default_number(
        ctx,
        &significant_max_raw,
        "maximumSignificantDigits",
        minimum_significant,
        21,
      )?
      .unwrap_or(21);
    }
    let (mut minimum_fraction, mut maximum_fraction) = (fraction_min_default, fraction_max_default);
    if fraction_wanted && fraction_given {
      let low = options::default_number(ctx, &fraction_min_raw, "minimumFractionDigits", 0, 100)?;
      let high = options::default_number(ctx, &fraction_max_raw, "maximumFractionDigits", 0, 100)?;
      match (low, high) {
        (None, Some(high)) => {
          minimum_fraction = fraction_min_default.min(high as i16);
          maximum_fraction = high as i16;
        },
        (Some(low), None) => {
          minimum_fraction = low as i16;
          maximum_fraction = fraction_max_default.max(low as i16);
        },
        (Some(low), Some(high)) if low > high => {
          return Err(Exception::throw_range(
            ctx,
            "maximumFractionDigits value is out of range.",
          ));
        },
        (Some(low), Some(high)) => {
          minimum_fraction = low as i16;
          maximum_fraction = high as i16;
        },
        (None, None) => {},
      }
    }
    let (rounding_type, rounding_priority) = if !significant_wanted && !fraction_wanted {
      minimum_fraction = 0;
      maximum_fraction = 0;
      minimum_significant = 1;
      maximum_significant = 2;
      (RoundingType::MorePrecision, "morePrecision")
    } else if rounding_priority == "auto" {
      if significant_wanted {
        (RoundingType::Significant, "auto")
      } else {
        (RoundingType::Fraction, "auto")
      }
    } else if rounding_priority == "morePrecision" {
      (RoundingType::MorePrecision, "morePrecision")
    } else {
      (RoundingType::LessPrecision, "lessPrecision")
    };
    if rounding_increment != 1 {
      if rounding_type != RoundingType::Fraction {
        return Err(Exception::throw_type(
          ctx,
          "roundingIncrement is only allowed with fraction digit rounding",
        ));
      }
      if maximum_fraction != minimum_fraction {
        return Err(Exception::throw_range(
          ctx,
          "maximumFractionDigits must equal minimumFractionDigits with a roundingIncrement",
        ));
      }
    }
    Ok(Self {
      minimum_integer: minimum_integer as i16,
      minimum_fraction,
      maximum_fraction,
      minimum_significant: minimum_significant as i16,
      maximum_significant: maximum_significant as i16,
      rounding_type,
      rounding_priority,
      rounding_increment: rounding_increment as u16,
      rounding_mode,
      trailing_zero_display,
    })
  }

  fn mode(&self) -> SignedRoundingMode {
    match self.rounding_mode {
      "ceil" => SignedRoundingMode::Ceil,
      "floor" => SignedRoundingMode::Floor,
      "expand" => SignedRoundingMode::Unsigned(UnsignedRoundingMode::Expand),
      "trunc" => SignedRoundingMode::Unsigned(UnsignedRoundingMode::Trunc),
      "halfCeil" => SignedRoundingMode::HalfCeil,
      "halfFloor" => SignedRoundingMode::HalfFloor,
      "halfTrunc" => SignedRoundingMode::Unsigned(UnsignedRoundingMode::HalfTrunc),
      "halfEven" => SignedRoundingMode::Unsigned(UnsignedRoundingMode::HalfEven),
      _ => SignedRoundingMode::Unsigned(UnsignedRoundingMode::HalfExpand),
    }
  }

  /// `ToRawFixed`: rounded at `maximumFractionDigits` in steps of the
  /// rounding increment. Returns the value and the magnitude it was
  /// rounded at.
  fn fixed(&self, value: &Decimal) -> (Decimal, i16) {
    let mut increment = self.rounding_increment;
    let mut shift = 0i16;
    while increment.is_multiple_of(10) {
      increment /= 10;
      shift += 1;
    }
    let step = match increment {
      2 => RoundingIncrement::MultiplesOf2,
      5 => RoundingIncrement::MultiplesOf5,
      25 => RoundingIncrement::MultiplesOf25,
      _ => RoundingIncrement::MultiplesOf1,
    };
    let magnitude = -self.maximum_fraction + shift;
    let mut rounded = value.clone();
    rounded.round_with_mode_and_increment(magnitude, self.mode(), step);
    rounded.trim_end();
    if self.minimum_fraction > 0 {
      rounded.pad_end(-self.minimum_fraction);
    }
    (rounded, -self.maximum_fraction)
  }

  /// `ToRawPrecision`: rounded to `maximumSignificantDigits`, padded to
  /// `minimumSignificantDigits`.
  fn precision(&self, value: &Decimal) -> (Decimal, i16) {
    let mut rounded = value.clone();
    let start = if rounded.absolute.is_zero() {
      0
    } else {
      rounded.absolute.nonzero_magnitude_start()
    };
    let magnitude = start - self.maximum_significant + 1;
    rounded.round_with_mode(magnitude, self.mode());
    rounded.trim_end();
    let start = if rounded.absolute.is_zero() {
      0
    } else {
      rounded.absolute.nonzero_magnitude_start()
    };
    let pad = start - self.minimum_significant + 1;
    if pad < 0 {
      rounded.pad_end(pad);
    }
    (rounded, magnitude)
  }

  /// `FormatNumericToString`'s rounding, padding and trailing zeros.
  pub(crate) fn round(&self, value: &Decimal) -> Decimal {
    let mut rounded = match self.rounding_type {
      RoundingType::Fraction => self.fixed(value).0,
      RoundingType::Significant => self.precision(value).0,
      RoundingType::MorePrecision | RoundingType::LessPrecision => {
        let (significant, significant_magnitude) = self.precision(value);
        let (fixed, fixed_magnitude) = self.fixed(value);
        let significant_wins =
          (self.rounding_type == RoundingType::MorePrecision) == (significant_magnitude <= fixed_magnitude);
        if significant_wins { significant } else { fixed }
      },
    };
    if self.trailing_zero_display == "stripIfInteger" && is_integer(&rounded) {
      rounded.trim_end();
    }
    rounded.pad_start(self.minimum_integer);
    rounded
  }

  pub(crate) fn resolved(&self, object: &Object<'_>) -> Result<()> {
    object.set("minimumIntegerDigits", self.minimum_integer)?;
    if self.rounding_type != RoundingType::Significant {
      object.set("minimumFractionDigits", self.minimum_fraction)?;
      object.set("maximumFractionDigits", self.maximum_fraction)?;
    }
    if self.rounding_type != RoundingType::Fraction {
      object.set("minimumSignificantDigits", self.minimum_significant)?;
      object.set("maximumSignificantDigits", self.maximum_significant)?;
    }
    Ok(())
  }

  pub(crate) fn resolved_rounding(&self, object: &Object<'_>) -> Result<()> {
    object.set("roundingIncrement", self.rounding_increment)?;
    object.set("roundingMode", self.rounding_mode)?;
    object.set("roundingPriority", self.rounding_priority)?;
    object.set("trailingZeroDisplay", self.trailing_zero_display)?;
    Ok(())
  }
}

fn shifted(value: &Decimal, by: i16) -> Decimal {
  let mut shifted = value.clone();
  shifted.absolute.multiply_pow10(by);
  shifted
}

fn is_integer(value: &Decimal) -> bool {
  value.absolute.is_zero() || value.absolute.nonzero_magnitude_end() >= 0
}

/// A mathematical value as `ToIntlMathematicalValue` gives it.
#[derive(Clone)]
pub(crate) enum Numeric {
  Finite(Decimal),
  NaN,
  Infinity(Sign),
}

impl Numeric {
  /// `ToIntlMathematicalValue(value)`: a BigInt and a numeric string are
  /// taken exactly; anything else through `ToNumber`.
  pub(crate) fn from_js<'js>(ctx: &Ctx<'js>, value: &Value<'js>) -> Result<Self> {
    if value.is_big_int() {
      let text = bigint_text(ctx, value)?;
      return Ok(Decimal::try_from_str(&text).map_or(Self::NaN, Self::Finite));
    }
    if let Some(text) = value.as_string() {
      return Self::from_string(&text.to_string()?, value);
    }
    let primitive = if value.is_object() {
      let primitive: Value<'js> = crate::state::to_primitive_number(ctx, value)?;
      if primitive.is_big_int() || primitive.is_string() {
        return Self::from_js(ctx, &primitive);
      }
      primitive
    } else {
      value.clone()
    };
    Ok(Self::from_f64(primitive.get::<Coerced<f64>>()?.0))
  }

  pub(crate) fn from_f64(number: f64) -> Self {
    if number.is_nan() {
      Self::NaN
    } else if number.is_infinite() {
      Self::Infinity(if number < 0.0 { Sign::Negative } else { Sign::None })
    } else {
      let mut decimal = Decimal::try_from_f64(number, FloatPrecision::RoundTrip).unwrap_or_default();
      if number == 0.0 && number.is_sign_negative() {
        decimal.sign = Sign::Negative;
      }
      Self::Finite(decimal)
    }
  }

  fn from_string(text: &str, value: &Value<'_>) -> Result<Self> {
    let trimmed = text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if trimmed.is_empty() {
      return Ok(Self::Finite(Decimal::from(0)));
    }
    match trimmed {
      "Infinity" | "+Infinity" => return Ok(Self::Infinity(Sign::None)),
      "-Infinity" => return Ok(Self::Infinity(Sign::Negative)),
      _ => {},
    }
    let decimal_literal = trimmed
      .bytes()
      .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
    if decimal_literal && let Ok(decimal) = Decimal::try_from_str(trimmed.trim_start_matches('+')) {
      return Ok(Self::Finite(decimal));
    }
    Ok(Self::from_f64(value.get::<Coerced<f64>>()?.0))
  }

  fn sign(&self) -> Sign {
    match self {
      Self::Finite(decimal) => decimal.sign,
      Self::NaN => Sign::None,
      Self::Infinity(sign) => *sign,
    }
  }
}

fn bigint_text<'js>(ctx: &Ctx<'js>, value: &Value<'js>) -> Result<String> {
  let string: Function<'js> = ctx.globals().get("String")?;
  string.call((value.clone(),))
}

enum Affixes {
  None,
  /// The percent formatter, and the digits formatter it writes with,
  /// whose output locates the digits in its own.
  Percent(PercentFormatter<DecimalFormatter>, DecimalFormatter),
  Currency(CurrencyFormatter<DecimalFormatter>),
  Unit(UnitNames),
}

pub(crate) struct NumberFormatCore {
  locale: String,
  numbering_system: String,
  style: Style,
  currency: Option<String>,
  currency_display: &'static str,
  currency_sign: &'static str,
  unit: Option<String>,
  unit_display: &'static str,
  digits: Digits,
  notation: Notation,
  compact_display: &'static str,
  use_grouping: Option<&'static str>,
  sign_display: &'static str,
  decimal: DecimalFormatter,
  compact: Option<CompactDecimalFormatter>,
  affixes: Affixes,
  plurals: PluralRules,
  minus_sign: String,
  plus_sign: String,
}

/// `InitializeNumberFormat` to the core that formats under it.
pub(crate) fn resolve<'js>(
  ctx: &Ctx<'js>,
  locales: Option<&Value<'js>>,
  options: Option<Value<'js>>,
) -> Result<Rc<NumberFormatCore>> {
  let requested = locale::canonicalize_list(ctx, locales)?;
  let options = options::coerce_options(ctx, options)?;
  let options = options.as_ref();
  options::locale_matcher(ctx, options)?;
  let numbering_system = options::unicode_type(ctx, options, "numberingSystem")?;

  let style = options::string(ctx, options, "style", &["decimal", "percent", "currency", "unit"])?.unwrap_or("decimal");
  let currency = options::string_any(options, "currency")?;
  if let Some(currency) = &currency
    && !(currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_alphabetic()))
  {
    return Err(Exception::throw_range(
      ctx,
      &format!("Invalid currency code : {currency}"),
    ));
  }
  let currency_display = options::string(
    ctx,
    options,
    "currencyDisplay",
    &["code", "symbol", "narrowSymbol", "name"],
  )?
  .unwrap_or("symbol");
  let currency_sign = options::string(ctx, options, "currencySign", &["standard", "accounting"])?.unwrap_or("standard");
  let unit = options::string_any(options, "unit")?;
  if let Some(unit) = &unit
    && !crate::units::is_well_formed(unit)
  {
    return Err(Exception::throw_range(
      ctx,
      &format!("Invalid unit argument for Intl.NumberFormat() '{unit}'"),
    ));
  }
  let unit_display = options::string(ctx, options, "unitDisplay", &["short", "narrow", "long"])?.unwrap_or("short");
  let style = match style {
    "percent" => Style::Percent,
    "currency" => Style::Currency,
    "unit" => Style::Unit,
    _ => Style::Decimal,
  };
  if style == Style::Currency && currency.is_none() {
    return Err(Exception::throw_type(
      ctx,
      "Currency code is required with currency style.",
    ));
  }
  if style == Style::Unit && unit.is_none() {
    return Err(Exception::throw_type(ctx, "Unit is required with unit style."));
  }
  let currency = currency.map(|c| c.to_ascii_uppercase());
  let fraction_defaults = match style {
    Style::Currency => {
      let digits = currency_digits(currency.as_deref().unwrap_or("XXX"));
      (digits, digits)
    },
    Style::Percent => (0, 0),
    _ => (0, 3),
  };
  let notation = match options::string(
    ctx,
    options,
    "notation",
    &["standard", "scientific", "engineering", "compact"],
  )? {
    Some("scientific") => Notation::Scientific,
    Some("engineering") => Notation::Engineering,
    Some("compact") => Notation::Compact,
    _ => Notation::Standard,
  };
  let digits = Digits::read(ctx, options, fraction_defaults, notation == Notation::Compact)?;
  let compact_display = options::string(ctx, options, "compactDisplay", &["short", "long"])?.unwrap_or("short");
  let default_grouping = if notation == Notation::Compact { "min2" } else { "auto" };
  let use_grouping = grouping_option(ctx, options, default_grouping)?;
  let sign_display = options::string(
    ctx,
    options,
    "signDisplay",
    &["auto", "never", "always", "exceptZero", "negative"],
  )?
  .unwrap_or("auto");

  let state = crate::state::state(ctx)?;
  let key = format!(
    "{}|{numbering_system:?}|{}|{currency:?}|{currency_display}|{currency_sign}|{unit:?}|{unit_display}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{compact_display}|{use_grouping:?}|{sign_display}|{}",
    locale::list_key(&requested),
    style as u8,
    digits.minimum_integer,
    digits.minimum_fraction,
    digits.maximum_fraction,
    digits.minimum_significant,
    digits.maximum_significant,
    digits.rounding_type as u8,
    digits.rounding_priority,
    digits.rounding_increment,
    digits.rounding_mode,
    digits.trailing_zero_display,
    notation as u8,
  );
  if let Some(core) = state.number_formats.get(&key) {
    return Ok(core);
  }
  let found = locale::negotiate(&requested, &state.default_locale);
  let nu = locale::keyword(&found, "nu", numbering_system.as_deref(), numbering_system_supported);
  let resolved = locale::with_keywords(&found.id, &[&nu]);
  let mut data_locale = Locale::from(found.id.clone());
  if let Some(value) = &nu.value {
    locale::set_keyword(&mut data_locale, "nu", value);
  }
  let core = build(
    ctx,
    &data_locale,
    resolved.to_string(),
    Settings {
      style,
      currency,
      currency_display,
      currency_sign,
      unit,
      unit_display,
      digits,
      notation,
      compact_display,
      use_grouping,
      sign_display,
    },
  )?;
  let core = Rc::new(core);
  state.number_formats.insert(key, Rc::clone(&core));
  Ok(core)
}

struct Settings {
  style: Style,
  currency: Option<String>,
  currency_display: &'static str,
  currency_sign: &'static str,
  unit: Option<String>,
  unit_display: &'static str,
  digits: Digits,
  notation: Notation,
  compact_display: &'static str,
  use_grouping: Option<&'static str>,
  sign_display: &'static str,
}

fn build(ctx: &Ctx<'_>, data_locale: &Locale, locale: String, settings: Settings) -> Result<NumberFormatCore> {
  let fail = |error: DataError| Exception::throw_range(ctx, &format!("Intl.NumberFormat: {error}"));
  let grouping = match settings.use_grouping {
    Some("always") => GroupingStrategy::Always,
    Some("min2") => GroupingStrategy::Min2,
    Some(_) => GroupingStrategy::Auto,
    None => GroupingStrategy::Never,
  };
  let decimal_prefs = DecimalFormatterPreferences::from(data_locale);
  let decimal = DecimalFormatter::try_new(decimal_prefs, DecimalFormatterOptions::from(grouping)).map_err(fail)?;
  let compact = if settings.notation == Notation::Compact {
    let mut compact_options = CompactDecimalFormatterOptions::default();
    compact_options.grouping_strategy = Some(grouping);
    let compact = if settings.compact_display == "long" {
      CompactDecimalFormatter::try_new_long(data_locale.into(), compact_options)
    } else {
      CompactDecimalFormatter::try_new_short(data_locale.into(), compact_options)
    };
    Some(compact.map_err(fail)?)
  } else {
    None
  };
  let affixes = match settings.style {
    Style::Decimal => Affixes::None,
    Style::Percent => {
      let prefs = PercentFormatterPreferences::from(data_locale);
      let inner = || DecimalFormatter::try_new(decimal_prefs, DecimalFormatterOptions::default()).map_err(fail);
      Affixes::Percent(
        PercentFormatter::try_new_with_decimal_formatter(prefs, inner()?, PercentFormatterOptions::default())
          .map_err(fail)?,
        inner()?,
      )
    },
    Style::Currency => {
      let code = settings.currency.as_deref().unwrap_or("XXX").to_ascii_lowercase();
      let currency = CurrencyType::try_from_str(&code)
        .map_err(|_| Exception::throw_range(ctx, &format!("Invalid currency code : {code}")))?;
      let prefs = CurrencyFormatterPreferences::from(data_locale);
      let mut currency_options = CurrencyFormatterOptions::default();
      if settings.currency_sign == "accounting" {
        currency_options.usage = CurrencyUsage::Accounting;
      }
      let formatter = match settings.currency_display {
        "code" => CurrencyFormatter::try_new_code(prefs, currency, currency_options),
        "narrowSymbol" => CurrencyFormatter::try_new_symbol_narrow(prefs, currency, currency_options),
        "name" => CurrencyFormatter::try_new_name(prefs, currency),
        _ => CurrencyFormatter::try_new_symbol(prefs, currency, currency_options),
      };
      Affixes::Currency(formatter.map_err(fail)?)
    },
    Style::Unit => Affixes::Unit(UnitNames::load(
      data_locale,
      settings.unit.as_deref().unwrap_or_default(),
      settings.unit_display,
    )),
  };
  let plurals = PluralRules::try_new_cardinal(PluralRulesPreferences::from(data_locale)).map_err(fail)?;
  let plain =
    DecimalFormatter::try_new(decimal_prefs, DecimalFormatterOptions::from(GroupingStrategy::Never)).map_err(fail)?;
  let sign_text = |decimal: &str, part: Part| {
    Decimal::try_from_str(decimal)
      .ok()
      .and_then(|value| {
        Recorder::record(&plain.format(&value))
          .into_iter()
          .find(|(p, _)| *p == Some(part))
          .map(|(_, text)| text)
      })
      .unwrap_or_default()
  };
  let minus_sign = sign_text("-1", icu::decimal::parts::MINUS_SIGN);
  let plus_sign = sign_text("+1", icu::decimal::parts::PLUS_SIGN);
  let numbering_system =
    locale::keyword_value(data_locale, "nu").unwrap_or_else(|| default_numbering_system(data_locale));
  Ok(NumberFormatCore {
    locale,
    numbering_system,
    style: settings.style,
    currency: settings.currency,
    currency_display: settings.currency_display,
    currency_sign: settings.currency_sign,
    unit: settings.unit,
    unit_display: settings.unit_display,
    digits: settings.digits,
    notation: settings.notation,
    compact_display: settings.compact_display,
    use_grouping: settings.use_grouping,
    sign_display: settings.sign_display,
    decimal,
    compact,
    affixes,
    plurals,
    minus_sign,
    plus_sign,
  })
}

/// `GetBooleanOrStringNumberFormatOption(options, "useGrouping", ...)`:
/// `None` is `false`.
fn grouping_option<'js>(
  ctx: &Ctx<'js>,
  options: Option<&Object<'js>>,
  fallback: &'static str,
) -> Result<Option<&'static str>> {
  let Some(options) = options else {
    return Ok(Some(fallback));
  };
  let value: Value<'js> = options.get("useGrouping")?;
  if value.is_undefined() {
    return Ok(Some(fallback));
  }
  if value.as_bool() == Some(true) {
    return Ok(Some("always"));
  }
  if !value.get::<Coerced<bool>>()?.0 {
    return Ok(None);
  }
  let text = value.get::<Coerced<String>>()?.0;
  match text.as_str() {
    "true" | "false" => Ok(Some(fallback)),
    "min2" => Ok(Some("min2")),
    "auto" => Ok(Some("auto")),
    "always" => Ok(Some("always")),
    _ => Err(Exception::throw_range(
      ctx,
      &format!("Value {text} out of range for option useGrouping"),
    )),
  }
}

/// The minor-unit digits CLDR gives `currency` (ISO 4217's, where CLDR
/// does not differ), as ICU4X carries them.
fn currency_digits(currency: &str) -> i16 {
  use icu::experimental::dimension::provider::currency::fractions::CurrencyFractionsV1;
  let Ok(code) = CurrencyType::try_from_str(&currency.to_ascii_lowercase()) else {
    return 2;
  };
  DataProvider::<CurrencyFractionsV1>::load(&icu::experimental::provider::Baked, DataRequest::default())
    .map_or(2, |response| i16::from(response.payload.get().resolve(code).digits))
}

pub(crate) fn numbering_system_supported(value: &str) -> bool {
  let Ok(attributes) = DataMarkerAttributes::try_from_str(value) else {
    return false;
  };
  let mut metadata = DataRequestMetadata::default();
  metadata.silent = true;
  DataProvider::<DecimalDigitsV1>::load(
    &DecimalBaked,
    DataRequest {
      id: DataIdentifierBorrowed::for_marker_attributes(attributes),
      metadata,
    },
  )
  .is_ok()
}

pub(crate) fn default_numbering_system(locale: &Locale) -> String {
  let data_locale = DataLocale::from(locale);
  DataProvider::<DecimalSymbolsV1>::load(
    &DecimalBaked,
    DataRequest {
      id: DataIdentifierBorrowed::for_locale(&data_locale),
      ..Default::default()
    },
  )
  .map_or_else(
    |_| "latn".to_owned(),
    |response| response.payload.get().numsys().to_owned(),
  )
}

impl NumberFormatCore {
  /// `PartitionNumberPattern(numberFormat, x)`.
  pub(crate) fn parts(&self, value: &Numeric) -> Vec<JsPart> {
    let (signed, magnitude) = match value {
      Numeric::Finite(decimal) if self.style == Style::Percent => self.digits_of(&shifted(decimal, 2)),
      Numeric::Finite(decimal) => self.digits_of(decimal),
      Numeric::NaN => (Decimal::from(0), vec![JsPart::new("nan", "NaN")]),
      Numeric::Infinity(sign) => {
        let mut one = Decimal::from(1);
        one.sign = *sign;
        (one, vec![JsPart::new("infinity", "∞")])
      },
    };
    let signed = self.with_sign_display(signed, value);
    let mut out = Vec::new();
    match &self.affixes {
      Affixes::None => {
        self.splice(
          &mut out,
          &Recorder::record(&self.decimal.format(&signed)),
          magnitude,
          "literal",
        );
      },
      Affixes::Percent(formatter, inner) => {
        // The percent formatter writes without part annotations, so its
        // digits are found by the text its own digits formatter gives.
        let template = writeable::Writeable::write_to_string(&formatter.format(&signed)).into_owned();
        let mut absolute = signed.clone();
        absolute.sign = Sign::None;
        let digits = writeable::Writeable::write_to_string(&inner.format(&absolute)).into_owned();
        let segments = match template.find(&digits) {
          Some(at) => vec![
            (None, template[..at].to_owned()),
            (Some(icu::decimal::parts::INTEGER), digits.clone()),
            (None, template[at + digits.len()..].to_owned()),
          ],
          None => vec![(None, template)],
        };
        self.splice(&mut out, &segments, magnitude, "percentSign");
      },
      Affixes::Currency(formatter) => {
        self.splice(
          &mut out,
          &Recorder::record(&formatter.format_fixed_decimal(&signed)),
          magnitude,
          "currency",
        );
      },
      Affixes::Unit(names) => {
        let template = names.template(&signed, &self.plurals, &self.decimal);
        self.splice(&mut out, &template, magnitude, "unit");
      },
    }
    out
  }

  /// The value with the sign `signDisplay` gives it.
  fn with_sign_display(&self, mut signed: Decimal, value: &Numeric) -> Decimal {
    let display = match self.sign_display {
      "never" => SignDisplay::Never,
      "always" => SignDisplay::Always,
      "exceptZero" => SignDisplay::ExceptZero,
      "negative" => SignDisplay::Negative,
      _ => SignDisplay::Auto,
    };
    if matches!(value, Numeric::NaN) {
      signed.sign = if display == SignDisplay::Always {
        Sign::Positive
      } else {
        Sign::None
      };
      return signed;
    }
    if matches!(value, Numeric::Infinity(_)) {
      signed.sign = value.sign();
    }
    signed.apply_sign_display(display);
    signed
  }

  /// The rounded value, and the parts its magnitude formats to under
  /// the notation.
  fn digits_of(&self, value: &Decimal) -> (Decimal, Vec<JsPart>) {
    match self.notation {
      Notation::Standard => {
        let rounded = self.digits.round(value);
        let mut absolute = rounded.clone();
        absolute.sign = Sign::None;
        let number = number_parts(&Recorder::record(&self.decimal.format(&absolute)));
        (rounded, number)
      },
      Notation::Scientific | Notation::Engineering => {
        let (mantissa, exponent) = self.exponent_split(value, |magnitude| {
          if self.notation == Notation::Engineering {
            magnitude.div_euclid(3) * 3
          } else {
            magnitude
          }
        });
        let mut absolute = mantissa.clone();
        absolute.sign = Sign::None;
        let mut number = number_parts(&Recorder::record(&self.decimal.format(&absolute)));
        number.push(JsPart::new("exponentSeparator", "E"));
        if exponent < 0 {
          number.push(JsPart::new("exponentMinusSign", self.minus_sign.trim_matches(is_bidi)));
        }
        let exponent_digits = Decimal::from(i64::from(exponent).abs());
        let exponent_text: String = Recorder::record(&self.decimal.format(&exponent_digits))
          .into_iter()
          .map(|(_, text)| text)
          .collect();
        number.push(JsPart::new("exponentInteger", exponent_text));
        let mut signed = mantissa;
        signed.sign = value.sign;
        (signed, number)
      },
      Notation::Compact => {
        let Some(compact) = &self.compact else {
          return (value.clone(), Vec::new());
        };
        let (significand, exponent) = self.exponent_split(value, |magnitude| {
          i16::from(compact.compact_exponent_for_magnitude(magnitude))
        });
        let mut absolute = significand.clone();
        absolute.sign = Sign::None;
        let number = u8::try_from(exponent)
          .ok()
          .and_then(|exponent| compact.format_with_exponent(&absolute, exponent).ok())
          .map_or_else(
            || number_parts(&Recorder::record(&self.decimal.format(&absolute))),
            |formatted| compact_parts(&Recorder::record(&formatted)),
          );
        let mut signed = significand;
        signed.sign = value.sign;
        (signed, number)
      },
    }
  }

  /// `ComputeExponent(numberFormat, x)` and the rounded significand.
  fn exponent_split(&self, value: &Decimal, exponent_for: impl Fn(i16) -> i16) -> (Decimal, i16) {
    if value.absolute.is_zero() {
      return (self.digits.round(value), 0);
    }
    let magnitude = value.absolute.nonzero_magnitude_start();
    let exponent = exponent_for(magnitude);
    let rounded = self.digits.round(&shifted(value, -exponent));
    if rounded.absolute.is_zero() || rounded.absolute.nonzero_magnitude_start() == magnitude - exponent {
      return (rounded, exponent);
    }
    let exponent = exponent_for(magnitude + 1);
    (self.digits.round(&shifted(value, -exponent)), exponent)
  }

  /// Replace the digits a style formatter wrote with `number`, and name
  /// what surrounds them.
  fn splice(
    &self,
    out: &mut Vec<JsPart>,
    template: &[(Option<Part>, String)],
    number: Vec<JsPart>,
    affix: &'static str,
  ) {
    let is_number = |part: &Option<Part>| {
      matches!(
        part,
        Some(p) if *p == icu::decimal::parts::INTEGER
          || *p == icu::decimal::parts::FRACTION
          || *p == icu::decimal::parts::DECIMAL
          || *p == icu::decimal::parts::GROUP
      )
    };
    let first = template.iter().position(|(part, _)| is_number(part));
    let last = template.iter().rposition(|(part, _)| is_number(part));
    let mut number = Some(number);
    for (index, (part, text)) in template.iter().enumerate() {
      if let (Some(first), Some(last)) = (first, last)
        && (first..=last).contains(&index)
      {
        if let Some(number) = number.take() {
          for piece in number {
            parts::push(out, piece);
          }
        }
        continue;
      }
      match part {
        Some(p) if *p == icu::decimal::parts::MINUS_SIGN => parts::push(out, JsPart::new("minusSign", text.clone())),
        Some(p) if *p == icu::decimal::parts::PLUS_SIGN => parts::push(out, JsPart::new("plusSign", text.clone())),
        _ => self.affix(out, text, affix),
      }
    }
    if let Some(number) = number {
      for piece in number {
        parts::push(out, piece);
      }
    }
  }

  /// Name the text a style writes around the digits: the signs it
  /// writes without annotating them, spacing and parentheses as
  /// literals, and the rest as the style's own part.
  fn affix(&self, out: &mut Vec<JsPart>, text: &str, affix: &'static str) {
    let mut rest = text;
    while !rest.is_empty() {
      if !self.minus_sign.is_empty() && rest.starts_with(&self.minus_sign) {
        parts::push(out, JsPart::new("minusSign", self.minus_sign.clone()));
        rest = &rest[self.minus_sign.len()..];
        continue;
      }
      if !self.plus_sign.is_empty() && rest.starts_with(&self.plus_sign) {
        parts::push(out, JsPart::new("plusSign", self.plus_sign.clone()));
        rest = &rest[self.plus_sign.len()..];
        continue;
      }
      let literal_len = rest
        .char_indices()
        .find(|(_, c)| !(c.is_whitespace() || is_bidi(*c) || matches!(c, '(' | ')')))
        .map_or(rest.len(), |(i, _)| i);
      if literal_len > 0 {
        parts::push(out, JsPart::new("literal", &rest[..literal_len]));
        rest = &rest[literal_len..];
        continue;
      }
      let word_len = rest
        .char_indices()
        .find(|(i, c)| {
          *i > 0
            && (matches!(c, '(' | ')')
              || (c.is_whitespace() && !affix_continues(&rest[*i..]))
              || rest[*i..].starts_with(&self.minus_sign) && !self.minus_sign.is_empty()
              || rest[*i..].starts_with(&self.plus_sign) && !self.plus_sign.is_empty())
        })
        .map_or(rest.len(), |(i, _)| i);
      let kind = if affix == "literal" { "literal" } else { affix };
      parts::push(out, JsPart::new(kind, &rest[..word_len]));
      rest = &rest[word_len..];
    }
  }

  pub(crate) fn format(&self, value: &Numeric) -> String {
    // A plain decimal is the digits formatter's own output, sign and
    // all: written straight, without recording parts to join again.
    if let (Affixes::None, Notation::Standard, Numeric::Finite(decimal)) = (&self.affixes, self.notation, value) {
      let signed = self.with_sign_display(self.digits.round(decimal), value);
      return writeable::Writeable::write_to_string(&self.decimal.format(&signed)).into_owned();
    }
    parts::concat(&self.parts(value))
  }

  fn resolved_options<'js>(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    object.set("locale", self.locale.as_str())?;
    object.set("numberingSystem", self.numbering_system.as_str())?;
    object.set(
      "style",
      match self.style {
        Style::Decimal => "decimal",
        Style::Percent => "percent",
        Style::Currency => "currency",
        Style::Unit => "unit",
      },
    )?;
    if self.style == Style::Currency {
      object.set("currency", self.currency.as_deref())?;
      object.set("currencyDisplay", self.currency_display)?;
      object.set("currencySign", self.currency_sign)?;
    }
    if self.style == Style::Unit {
      object.set("unit", self.unit.as_deref())?;
      object.set("unitDisplay", self.unit_display)?;
    }
    self.digits.resolved(&object)?;
    match self.use_grouping {
      Some(grouping) => object.set("useGrouping", grouping)?,
      None => object.set("useGrouping", false)?,
    }
    object.set(
      "notation",
      match self.notation {
        Notation::Standard => "standard",
        Notation::Scientific => "scientific",
        Notation::Engineering => "engineering",
        Notation::Compact => "compact",
      },
    )?;
    if self.notation == Notation::Compact {
      object.set("compactDisplay", self.compact_display)?;
    }
    object.set("signDisplay", self.sign_display)?;
    self.digits.resolved_rounding(&object)?;
    Ok(object)
  }
}

/// Multi-word affixes (`US dollars`, `kilometers per hour`) are one
/// part: a space continues the affix when a letter follows it.
fn affix_continues(rest: &str) -> bool {
  rest
    .trim_start_matches(char::is_whitespace)
    .chars()
    .next()
    .is_some_and(char::is_alphabetic)
}

pub(crate) fn is_bidi(c: char) -> bool {
  matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
}

fn number_parts(segments: &[(Option<Part>, String)]) -> Vec<JsPart> {
  let mut out = Vec::new();
  for (part, text) in segments {
    let kind = match part {
      Some(p) if *p == icu::decimal::parts::INTEGER => "integer",
      Some(p) if *p == icu::decimal::parts::FRACTION => "fraction",
      Some(p) if *p == icu::decimal::parts::DECIMAL => "decimal",
      Some(p) if *p == icu::decimal::parts::GROUP => "group",
      Some(p) if *p == icu::decimal::parts::MINUS_SIGN => "minusSign",
      Some(p) if *p == icu::decimal::parts::PLUS_SIGN => "plusSign",
      _ => "literal",
    };
    parts::push(&mut out, JsPart::new(kind, text.clone()));
  }
  out
}

fn compact_parts(segments: &[(Option<Part>, String)]) -> Vec<JsPart> {
  let mut out = Vec::new();
  for (part, text) in segments {
    if part.is_some() {
      out.extend(number_parts(&[(*part, text.clone())]));
      continue;
    }
    let trimmed = text.trim_matches(|c: char| c.is_whitespace() || is_bidi(c));
    let start = text.find(trimmed).unwrap_or(0);
    parts::push(&mut out, JsPart::new("literal", &text[..start]));
    parts::push(&mut out, JsPart::new("compact", trimmed));
    parts::push(&mut out, JsPart::new("literal", &text[start + trimmed.len()..]));
  }
  out
}

#[derive(Trace)]
#[rquickjs::class(rename = "NumberFormat")]
pub struct NumberFormat<'js> {
  #[qjs(skip_trace)]
  pub(crate) core: Rc<NumberFormatCore>,
  bound_format: Option<Function<'js>>,
}

// SAFETY: the only `'js` value is the bound `format`, which belongs to
// the context the formatter does.
#[allow(unsafe_code)]
unsafe impl<'js> JsLifetime<'js> for NumberFormat<'js> {
  type Changed<'to> = NumberFormat<'to>;
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> NumberFormat<'js> {
  #[qjs(get)]
  pub fn format(this: This<Class<'js, Self>>, ctx: Ctx<'js>) -> Result<Function<'js>> {
    if let Some(bound) = this.0.borrow().bound_format.clone() {
      return Ok(bound);
    }
    let core = Rc::clone(&this.0.borrow().core);
    let bound = Function::new(ctx, move |ctx: Ctx<'js>, value: Opt<Value<'js>>| -> Result<String> {
      let value = value.0.unwrap_or_else(|| Value::new_undefined(ctx.clone()));
      Ok(core.format(&Numeric::from_js(&ctx, &value)?))
    })?
    .with_length(1)?
    .with_name("")?;
    this.0.borrow_mut().bound_format = Some(bound.clone());
    Ok(bound)
  }

  pub fn format_to_parts(&self, ctx: Ctx<'js>, value: Opt<Value<'js>>) -> Result<Array<'js>> {
    let value = value.0.unwrap_or_else(|| Value::new_undefined(ctx.clone()));
    let numeric = Numeric::from_js(&ctx, &value)?;
    parts::to_array(&ctx, &self.core.parts(&numeric))
  }

  pub fn format_range(&self, ctx: Ctx<'js>, start: Opt<Value<'js>>, end: Opt<Value<'js>>) -> Result<String> {
    let (start, end) = range_values(&ctx, start, end)?;
    Ok(parts::concat(&self.range_parts(&start, &end)))
  }

  pub fn format_range_to_parts(
    &self,
    ctx: Ctx<'js>,
    start: Opt<Value<'js>>,
    end: Opt<Value<'js>>,
  ) -> Result<Array<'js>> {
    let (start, end) = range_values(&ctx, start, end)?;
    parts::to_array(&ctx, &self.range_parts(&start, &end))
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    self.core.resolved_options(ctx)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.NumberFormat"
  }
}

impl NumberFormat<'_> {
  /// `PartitionNumberRangePattern`: both ends, or one approximately
  /// equal value when they format the same.
  fn range_parts(&self, start: &Numeric, end: &Numeric) -> Vec<JsPart> {
    let first = self.core.parts(start);
    let second = self.core.parts(end);
    if parts::concat(&first) == parts::concat(&second) {
      let mut out = vec![JsPart {
        kind: "approximatelySign",
        value: "~".to_owned(),
        source: Some("shared"),
        unit: None,
      }];
      out.extend(first.into_iter().map(|mut part| {
        part.source = Some("shared");
        part
      }));
      return out;
    }
    let mut out: Vec<JsPart> = first
      .into_iter()
      .map(|mut part| {
        part.source = Some("startRange");
        part
      })
      .collect();
    out.push(JsPart {
      kind: "literal",
      value: "–".to_owned(),
      source: Some("shared"),
      unit: None,
    });
    out.extend(second.into_iter().map(|mut part| {
      part.source = Some("endRange");
      part
    }));
    out
  }
}

fn range_values<'js>(ctx: &Ctx<'js>, start: Opt<Value<'js>>, end: Opt<Value<'js>>) -> Result<(Numeric, Numeric)> {
  let (Some(start), Some(end)) = (start.0, end.0) else {
    return Err(Exception::throw_type(ctx, "start and end are required"));
  };
  if start.is_undefined() || end.is_undefined() {
    return Err(Exception::throw_type(ctx, "start and end are required"));
  }
  let start = Numeric::from_js(ctx, &start)?;
  let end = Numeric::from_js(ctx, &end)?;
  if matches!(start, Numeric::NaN) || matches!(end, Numeric::NaN) {
    return Err(Exception::throw_range(ctx, "start and end must not be NaN"));
  }
  Ok((start, end))
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<NumberFormat<'js>, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>, locales: Opt<Value<'js>>, options: Opt<Value<'js>>| -> Result<NumberFormat<'js>> {
      Ok(NumberFormat {
        core: resolve(&ctx, locales.0.as_ref(), options.0)?,
        bound_format: None,
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "NumberFormat", 0)
}

/// `Number.prototype.toLocaleString(locales, options)`.
pub(crate) fn number_to_locale_string<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
) -> Result<String> {
  let number = this_number(&ctx, &this.0)?;
  let defaults =
    locales.0.as_ref().is_none_or(Value::is_undefined) && options.0.as_ref().is_none_or(Value::is_undefined);
  let cached = defaults
    .then(|| crate::state::state(&ctx).ok()?.default_number_format.borrow().clone())
    .flatten();
  let core = if let Some(core) = cached {
    core
  } else {
    let core = resolve(&ctx, locales.0.as_ref(), options.0)?;
    if defaults {
      *crate::state::state(&ctx)?.default_number_format.borrow_mut() = Some(Rc::clone(&core));
    }
    core
  };
  Ok(core.format(&Numeric::from_f64(number)))
}

/// `BigInt.prototype.toLocaleString(locales, options)`.
pub(crate) fn bigint_to_locale_string<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
) -> Result<String> {
  let value = crate::prototypes::this_primitive(&ctx, &this.0, "BigInt")?;
  if !value.is_big_int() {
    return Err(Exception::throw_type(
      &ctx,
      "BigInt.prototype.toLocaleString requires a BigInt",
    ));
  }
  let core = resolve(&ctx, locales.0.as_ref(), options.0)?;
  Ok(core.format(&Numeric::from_js(&ctx, &value)?))
}

fn this_number<'js>(ctx: &Ctx<'js>, this: &Value<'js>) -> Result<f64> {
  let value = crate::prototypes::this_primitive(ctx, this, "Number")?;
  value
    .as_number()
    .ok_or_else(|| Exception::throw_type(ctx, "Number.prototype.toLocaleString requires a Number"))
}

/// The ISO 4217 codes in circulation, as `supportedValuesOf` lists
/// them. ICU4X keeps no list of currencies: its minor-unit table names
/// only those whose minor unit is not two digits.
pub(crate) fn currencies() -> Vec<String> {
  const ISO_4217: &str = "AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN \
    BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP \
    GEL GHS GIP GMD GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT \
    LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB \
    PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SLL SOS SRD SSP STN SVC SYP SZL THB TJS \
    TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UYW UZS VED VES VND VUV WST XAF XAG XAU XBA XBB XBC XBD XCD XCG \
    XDR XOF XPD XPF XPT XSU XTS XUA XXX YER ZAR ZMW ZWG ZWL";
  ISO_4217.split_whitespace().map(str::to_owned).collect()
}

/// Every numbering system ICU4X has digits for.
pub(crate) fn numbering_systems() -> Vec<String> {
  [
    "adlm", "ahom", "arab", "arabext", "bali", "beng", "bhks", "brah", "cakm", "cham", "deva", "diak", "fullwide",
    "gara", "gong", "gonm", "gujr", "gukh", "guru", "hanidec", "hmng", "hmnp", "java", "kali", "kawi", "khmr", "knda",
    "krai", "lana", "lanatham", "laoo", "latn", "lepc", "limb", "mathbold", "mathdbl", "mathmono", "mathsanb",
    "mathsans", "mlym", "modi", "mong", "mroo", "mtei", "mymr", "mymrepka", "mymrpao", "mymrshan", "mymrtlng", "nagm",
    "newa", "nkoo", "olck", "onao", "orya", "osma", "outlined", "rohg", "saur", "segment", "shrd", "sind", "sinh",
    "sora", "sund", "sunu", "takr", "talu", "tamldec", "telu", "thai", "tibt", "tirh", "tnsa", "tols", "vaii", "wara",
    "wcho",
  ]
  .into_iter()
  .filter(|system| numbering_system_supported(system))
  .map(str::to_owned)
  .collect()
}
