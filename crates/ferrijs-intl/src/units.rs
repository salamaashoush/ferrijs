//! Unit names for `style: "unit"`.
//!
//! ICU4X carries CLDR's unit names for length, mass, area, volume and
//! duration, which cover most of ECMA-402's sanctioned units. It has
//! none for temperature, digital storage, angle or percent; those take
//! CLDR's root symbols, which are the same in every locale's short
//! form and stand in for the long and narrow ones.

use fixed_decimal::{Decimal, Sign};
use icu::decimal::DecimalFormatter;
use icu::experimental::dimension::provider::units::categorized_display_names as names;
use icu::experimental::dimension::provider::units::display_names::UnitsDisplayNames;
use icu::locale::Locale;
use icu::plurals::PluralRules;
use icu_provider::prelude::*;
use writeable::Part;

use crate::parts::Recorder;

/// ECMA-402's sanctioned simple units.
const SANCTIONED: &[&str] = &[
  "acre",
  "bit",
  "byte",
  "celsius",
  "centimeter",
  "day",
  "degree",
  "fahrenheit",
  "fluid-ounce",
  "foot",
  "gallon",
  "gigabit",
  "gigabyte",
  "gram",
  "hectare",
  "hour",
  "inch",
  "kilobit",
  "kilobyte",
  "kilogram",
  "kilometer",
  "liter",
  "megabit",
  "megabyte",
  "meter",
  "microsecond",
  "mile",
  "mile-scandinavian",
  "milliliter",
  "millimeter",
  "millisecond",
  "minute",
  "month",
  "nanosecond",
  "ounce",
  "percent",
  "petabyte",
  "pound",
  "second",
  "stone",
  "terabit",
  "terabyte",
  "week",
  "yard",
  "year",
];

pub(crate) fn sanctioned() -> &'static [&'static str] {
  SANCTIONED
}

/// `IsWellFormedUnitIdentifier`: a sanctioned unit, or two joined by
/// `-per-`.
pub(crate) fn is_well_formed(unit: &str) -> bool {
  if SANCTIONED.contains(&unit) {
    return true;
  }
  unit
    .split_once("-per-")
    .is_some_and(|(numerator, denominator)| SANCTIONED.contains(&numerator) && SANCTIONED.contains(&denominator))
}

/// CLDR root's pattern for a sanctioned unit ICU4X has no names for.
fn root_pattern(unit: &str) -> Option<&'static str> {
  Some(match unit {
    "celsius" => "{0}°C",
    "fahrenheit" => "{0}°F",
    "degree" => "{0} deg",
    "percent" => "{0}%",
    "bit" => "{0} bit",
    "byte" => "{0} byte",
    "kilobit" => "{0} kb",
    "kilobyte" => "{0} kB",
    "megabit" => "{0} Mb",
    "megabyte" => "{0} MB",
    "gigabit" => "{0} Gb",
    "gigabyte" => "{0} GB",
    "terabit" => "{0} Tb",
    "terabyte" => "{0} TB",
    "petabyte" => "{0} PB",
    _ => return None,
  })
}

enum Names {
  Data(DataPayload<names::UnitsNamesLengthCoreV1>),
  Root(&'static str),
}

/// A unit's patterns, or a numerator's and a denominator's for a
/// `-per-` unit.
pub(crate) struct UnitNames {
  numerator: Names,
  denominator: Option<(String, String)>,
}

impl UnitNames {
  pub(crate) fn load(locale: &Locale, unit: &str, display: &str) -> Self {
    let width = match display {
      "long" => "long",
      "narrow" => "narrow",
      _ => "short",
    };
    let (numerator, denominator) = match unit.split_once("-per-") {
      Some((numerator, denominator)) => (numerator, Some(denominator)),
      None => (unit, None),
    };
    Self {
      numerator: load(locale, width, numerator),
      denominator: denominator
        .map(|denominator| (per_pattern(locale, width), denominator_name(locale, width, denominator))),
    }
  }

  /// What the unit's pattern writes around `value`: the sign and digits
  /// annotated as the decimal formatter annotates them, the unit as
  /// plain text.
  pub(crate) fn template(
    &self,
    value: &Decimal,
    plurals: &PluralRules,
    decimal: &DecimalFormatter,
  ) -> Vec<(Option<Part>, String)> {
    let number = Recorder::record(&decimal.format(value));
    let mut absolute = value.clone();
    absolute.sign = Sign::None;
    let pattern = pattern_text(&self.numerator, &absolute, plurals);
    let numerator = interpolate(&pattern, &number);
    let Some((per, denominator)) = &self.denominator else {
      return numerator;
    };
    let mut out = Vec::new();
    let mut rest = per.as_str();
    while !rest.is_empty() {
      let next = [rest.find("{0}"), rest.find("{1}")].into_iter().flatten().min();
      let Some(at) = next else {
        out.push((None, rest.to_owned()));
        break;
      };
      if at > 0 {
        out.push((None, rest[..at].to_owned()));
      }
      if rest[at..].starts_with("{0}") {
        out.extend(numerator.iter().cloned());
      } else {
        out.push((None, denominator.clone()));
      }
      rest = &rest[at + 3..];
    }
    out
  }
}

fn load(locale: &Locale, width: &str, unit: &str) -> Names {
  if let Some(pattern) = root_pattern(unit) {
    return Names::Root(pattern);
  }
  let attribute = format!("{width}-{unit}");
  let Ok(attributes) = DataMarkerAttributes::try_from_str(&attribute) else {
    return Names::Root("{0}");
  };
  let data_locale = DataLocale::from(locale);
  // A unit can sit in several markers (`kilometer` is core for some
  // locales, extended for others), each falling back to the root: the
  // first that has it for the locale itself wins, the root's otherwise.
  let mut root = None;
  macro_rules! try_markers {
    ($($marker:ident),*) => {
      $(
        let mut metadata = DataRequestMetadata::default();
        metadata.silent = true;
        let request = DataRequest {
          id: DataIdentifierBorrowed::for_marker_attributes_and_locale(attributes, &data_locale),
          metadata,
        };
        if let Ok(response) = DataProvider::<names::$marker>::load(&icu::experimental::provider::Baked, request) {
          let at_root = response.metadata.locale.is_some_and(|landed| landed.language.is_unknown());
          let payload: DataPayload<names::UnitsNamesLengthCoreV1> = response.payload.cast();
          if !at_root {
            return Names::Data(payload);
          }
          root.get_or_insert(payload);
        }
      )*
    };
  }
  try_markers!(
    UnitsNamesLengthCoreV1,
    UnitsNamesLengthExtendedV1,
    UnitsNamesLengthOutlierV1,
    UnitsNamesMassCoreV1,
    UnitsNamesMassExtendedV1,
    UnitsNamesMassOutlierV1,
    UnitsNamesAreaCoreV1,
    UnitsNamesAreaExtendedV1,
    UnitsNamesAreaOutlierV1,
    UnitsNamesVolumeCoreV1,
    UnitsNamesVolumeExtendedV1,
    UnitsNamesVolumeOutlierV1,
    UnitsNamesDurationCoreV1,
    UnitsNamesDurationExtendedV1,
    UnitsNamesDurationOutlierV1
  );
  root.map_or(Names::Root("{0}"), Names::Data)
}

/// The locale's pattern joining a numerator to a denominator
/// (`{0} per {1}`, `{0}/{1}`).
fn per_pattern(locale: &Locale, width: &str) -> String {
  use icu::experimental::dimension::provider::units::essentials::UnitsEssentialsV1;
  let Ok(attributes) = DataMarkerAttributes::try_from_str(width) else {
    return "{0}/{1}".to_owned();
  };
  let data_locale = DataLocale::from(locale);
  let mut metadata = DataRequestMetadata::default();
  metadata.silent = true;
  DataProvider::<UnitsEssentialsV1>::load(
    &icu::experimental::provider::Baked,
    DataRequest {
      id: DataIdentifierBorrowed::for_marker_attributes_and_locale(attributes, &data_locale),
      metadata,
    },
  )
  .map_or_else(
    |_| "{0}/{1}".to_owned(),
    |response| response.payload.get().per.to_string(),
  )
}

/// A denominator's name: the time units' one-letter symbols CLDR's
/// per-unit patterns use in the short widths (`km/h`), otherwise the
/// singular name with its number taken out.
fn denominator_name(locale: &Locale, width: &str, unit: &str) -> String {
  if width != "long" {
    let symbol = match unit {
      "hour" => Some("h"),
      "minute" => Some("min"),
      "second" => Some("s"),
      "day" => Some("d"),
      "week" => Some("w"),
      "month" => Some("m"),
      "year" => Some("y"),
      _ => None,
    };
    if let Some(symbol) = symbol {
      return symbol.to_owned();
    }
  }
  let plurals = PluralRules::try_new_cardinal(locale.into());
  let pattern = match &plurals {
    Ok(plurals) => pattern_text(&load(locale, width, unit), &Decimal::from(1), plurals),
    Err(_) => "{0}".to_owned(),
  };
  pattern.replace("{0}", "").trim().to_owned()
}

fn pattern_text(names: &Names, value: &Decimal, plurals: &PluralRules) -> String {
  match names {
    Names::Root(pattern) => (*pattern).to_owned(),
    Names::Data(payload) => {
      let display: &UnitsDisplayNames<'_> = payload.get();
      let pattern = display.get(value.into(), plurals);
      writeable::Writeable::write_to_string(&pattern.interpolate(["{0}"])).into_owned()
    },
  }
}

/// `pattern` with `{0}` replaced by the formatted number's segments.
fn interpolate(pattern: &str, number: &[(Option<Part>, String)]) -> Vec<(Option<Part>, String)> {
  let mut out = Vec::new();
  match pattern.split_once("{0}") {
    Some((before, after)) => {
      if !before.is_empty() {
        out.push((None, before.to_owned()));
      }
      out.extend(number.iter().cloned());
      if !after.is_empty() {
        out.push((None, after.to_owned()));
      }
    },
    None => out.push((None, pattern.to_owned())),
  }
  out
}
