//! `Intl.DateTimeFormat` and `Date.prototype.toLocaleString`,
//! `toLocaleDateString` and `toLocaleTimeString`.
//!
//! An instant becomes wall time in the format's time zone through the
//! zone's real transitions (jiff, over the platform's tzdb or its own
//! copy), then ICU4X writes it in the locale's calendar, converting from
//! the ISO date itself. The date comes from the day count rather than
//! from jiff, whose years stop at 9999 while a `Date` reaches 275760.

use std::rc::Rc;

use icu::calendar::types::RataDie;
use icu::calendar::{AnyCalendarKind, Date, Iso};
use icu::datetime::fieldbag::DateTimeFieldBag;
use icu::datetime::fieldbag::field;
use icu::datetime::fieldsets::builder::{DateFields, FieldSetBuilder, ZoneStyle};
use icu::datetime::fieldsets::enums::CompositeFieldSet;
use icu::datetime::options::{Length, TimePrecision};
use icu::datetime::range::DateRangeFormatter;
use icu::datetime::{DateTimeFormatter, DateTimeFormatterPreferences};
use icu::locale::Locale;
use icu::locale::preferences::extensions::unicode::keywords::HourCycle;
use icu::time::zone::{TimeZoneInfo, UtcOffset, ZoneNameTimestamp, models::AtTime};
use icu::time::{Time, TimeZone, ZonedDateTime};
use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::convert::Coerced;
use rquickjs::function::{Opt, This};
use rquickjs::{Array, Class, Ctx, Exception, Function, JsLifetime, Object, Result, Value};
use writeable::Part;

use crate::locale;
use crate::options;
use crate::parts::{self, JsPart, Recorder};

/// `ToDateTimeOptions`' `required` and `defaults`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wanted {
  Any,
  Date,
  Time,
}

#[derive(Clone)]
enum Zone {
  Named {
    id: String,
    tz: jiff::tz::TimeZone,
    icu: TimeZone,
  },
  Offset {
    id: String,
    seconds: i32,
  },
}

impl Zone {
  fn id(&self) -> &str {
    match self {
      Self::Named { id, .. } | Self::Offset { id, .. } => id,
    }
  }

  fn offset_seconds(&self, epoch_ms: i64) -> i32 {
    match self {
      Self::Offset { seconds, .. } => *seconds,
      Self::Named { tz, .. } => {
        // jiff's instants stop short of a `Date`'s; outside them the
        // zone's offset at the nearest end stands.
        let clamped = epoch_ms.clamp(-377_705_116_800_000, 253_402_207_200_000);
        jiff::Timestamp::from_millisecond(clamped).map_or(0, |ts| tz.to_offset(ts).seconds())
      },
    }
  }

  fn info(&self, offset: i32, epoch_ms: i64) -> TimeZoneInfo<AtTime> {
    let zone = match self {
      Self::Named { icu, .. } => *icu,
      Self::Offset { .. } => TimeZone::UNKNOWN,
    };
    zone
      .with_offset(UtcOffset::try_from_seconds(offset).ok())
      .with_zone_name_timestamp(ZoneNameTimestamp::from_epoch_seconds(epoch_ms.div_euclid(1000)))
  }
}

/// The options a format was built from, as `resolvedOptions` reports
/// them.
#[derive(Clone, Default)]
struct Components {
  weekday: Option<&'static str>,
  era: Option<&'static str>,
  year: Option<&'static str>,
  month: Option<&'static str>,
  day: Option<&'static str>,
  day_period: Option<&'static str>,
  hour: Option<&'static str>,
  minute: Option<&'static str>,
  second: Option<&'static str>,
  fractional_second_digits: Option<i32>,
  time_zone_name: Option<&'static str>,
}

impl Components {
  fn has_date(&self) -> bool {
    self.weekday.is_some() || self.year.is_some() || self.month.is_some() || self.day.is_some()
  }

  fn has_time(&self) -> bool {
    self.day_period.is_some()
      || self.hour.is_some()
      || self.minute.is_some()
      || self.second.is_some()
      || self.fractional_second_digits.is_some()
  }

  fn any(&self) -> bool {
    self.has_date() || self.has_time() || self.era.is_some() || self.time_zone_name.is_some()
  }

  fn bag(&self) -> DateTimeFieldBag {
    let mut bag = DateTimeFieldBag::default();
    bag.weekday = self.weekday.map(|v| match v {
      "narrow" => field::Weekday::Narrow,
      "long" => field::Weekday::Long,
      _ => field::Weekday::Short,
    });
    bag.era = self.era.map(|v| match v {
      "narrow" => field::Era::Narrow,
      "long" => field::Era::Long,
      _ => field::Era::Short,
    });
    bag.year = self.year.map(|v| {
      if v == "2-digit" {
        field::Year::TwoDigit
      } else {
        field::Year::Numeric
      }
    });
    bag.month = self.month.map(|v| match v {
      "2-digit" => field::Month::TwoDigit,
      "narrow" => field::Month::Narrow,
      "short" => field::Month::Short,
      "long" => field::Month::Long,
      _ => field::Month::Numeric,
    });
    bag.day = self.day.map(|v| {
      if v == "2-digit" {
        field::Day::TwoDigit
      } else {
        field::Day::Numeric
      }
    });
    bag.day_period = self.day_period.map(|v| match v {
      "narrow" => field::DayPeriod::FlexibleNarrow,
      "long" => field::DayPeriod::FlexibleLong,
      _ => field::DayPeriod::FlexibleShort,
    });
    bag.hour = self.hour.map(|v| {
      if v == "2-digit" {
        field::Hour::TwoDigit
      } else {
        field::Hour::Numeric
      }
    });
    bag.minute = self.minute.map(|v| {
      if v == "2-digit" {
        field::Minute::TwoDigit
      } else {
        field::Minute::Numeric
      }
    });
    bag.second = self.second.map(|v| {
      if v == "2-digit" {
        field::Second::TwoDigit
      } else {
        field::Second::Numeric
      }
    });
    bag.fractional_second_digits = self.fractional_second_digits.map(|v| match v {
      1 => field::FractionalSecondDigits::F1,
      2 => field::FractionalSecondDigits::F2,
      _ => field::FractionalSecondDigits::F3,
    });
    bag.time_zone_name = self.time_zone_name.map(|v| match v {
      "long" => field::TimeZoneName::LongSpecific,
      "shortOffset" => field::TimeZoneName::ShortOffset,
      "longOffset" => field::TimeZoneName::LongOffset,
      "shortGeneric" => field::TimeZoneName::ShortGeneric,
      "longGeneric" => field::TimeZoneName::LongGeneric,
      _ => field::TimeZoneName::ShortSpecific,
    });
    bag
  }
}

pub(crate) struct DateTimeFormatCore {
  locale: String,
  calendar: String,
  numbering_system: String,
  zone: Zone,
  hour_cycle: Option<&'static str>,
  components: Components,
  date_style: Option<&'static str>,
  time_style: Option<&'static str>,
  formatter: DateTimeFormatter<CompositeFieldSet>,
  prefs: DateTimeFormatterPreferences,
  field_set: CompositeFieldSet,
  range: std::cell::OnceCell<Option<DateRangeFormatter<CompositeFieldSet>>>,
}

const COMPONENT_VALUES: &[(&str, &[&str])] = &[
  ("weekday", &["narrow", "short", "long"]),
  ("era", &["narrow", "short", "long"]),
  ("year", &["2-digit", "numeric"]),
  ("month", &["2-digit", "numeric", "narrow", "short", "long"]),
  ("day", &["2-digit", "numeric"]),
  ("dayPeriod", &["narrow", "short", "long"]),
  ("hour", &["2-digit", "numeric"]),
  ("minute", &["2-digit", "numeric"]),
  ("second", &["2-digit", "numeric"]),
];

const CALENDARS: &[&str] = &[
  "buddhist",
  "chinese",
  "coptic",
  "dangi",
  "ethioaa",
  "ethiopic",
  "gregory",
  "hebrew",
  "indian",
  "islamic-civil",
  "islamic-tbla",
  "islamic-umalqura",
  "japanese",
  "persian",
  "roc",
];

pub(crate) fn supported_calendars() -> &'static [&'static str] {
  CALENDARS
}

/// `CreateDateTimeFormat(newTarget, locales, options, required, defaults)`.
pub(crate) fn resolve<'js>(
  ctx: &Ctx<'js>,
  locales: Option<&Value<'js>>,
  options: Option<Value<'js>>,
  required: Wanted,
  defaults: Wanted,
) -> Result<Rc<DateTimeFormatCore>> {
  let requested = locale::canonicalize_list(ctx, locales)?;
  let options = options::coerce_options(ctx, options)?;
  let options = options.as_ref();
  options::locale_matcher(ctx, options)?;
  let calendar = options::unicode_type(ctx, options, "calendar")?;
  let numbering_system = options::unicode_type(ctx, options, "numberingSystem")?;
  let hour12 = options::boolean(options, "hour12")?;
  let mut hour_cycle = options::string(ctx, options, "hourCycle", &["h11", "h12", "h23", "h24"])?;
  if hour12.is_some() {
    hour_cycle = None;
  }
  let time_zone = match options {
    Some(options) => {
      let value: Value<'js> = options.get("timeZone")?;
      if value.is_undefined() {
        None
      } else {
        Some(value.get::<Coerced<String>>()?.0)
      }
    },
    None => None,
  };
  let mut components = Components::default();
  let mut slots: [Option<&'static str>; 9] = [None; 9];
  for (slot, (name, values)) in slots.iter_mut().zip(COMPONENT_VALUES) {
    *slot = options::string(ctx, options, name, values)?;
  }
  components.weekday = slots[0];
  components.era = slots[1];
  components.year = slots[2];
  components.month = slots[3];
  components.day = slots[4];
  components.day_period = slots[5];
  components.hour = slots[6];
  components.minute = slots[7];
  components.second = slots[8];
  components.fractional_second_digits = options::number(ctx, options, "fractionalSecondDigits", 1, 3)?;
  components.time_zone_name = options::string(
    ctx,
    options,
    "timeZoneName",
    &[
      "short",
      "long",
      "shortOffset",
      "longOffset",
      "shortGeneric",
      "longGeneric",
    ],
  )?;
  options::string(ctx, options, "formatMatcher", &["basic", "best fit"])?;
  let date_style = options::string(ctx, options, "dateStyle", &["full", "long", "medium", "short"])?;
  let time_style = options::string(ctx, options, "timeStyle", &["full", "long", "medium", "short"])?;

  if date_style.is_some() || time_style.is_some() {
    if components.any() {
      return Err(Exception::throw_type(ctx, "Invalid option : option"));
    }
    if required == Wanted::Date && time_style.is_some() {
      return Err(Exception::throw_type(ctx, "Invalid option : timeStyle"));
    }
    if required == Wanted::Time && date_style.is_some() {
      return Err(Exception::throw_type(ctx, "Invalid option : dateStyle"));
    }
  } else {
    let mut need_defaults = true;
    if matches!(required, Wanted::Date | Wanted::Any) && components.has_date() {
      need_defaults = false;
    }
    if matches!(required, Wanted::Time | Wanted::Any) && components.has_time() {
      need_defaults = false;
    }
    if need_defaults && matches!(defaults, Wanted::Date | Wanted::Any) {
      components.year = Some("numeric");
      components.month = Some("numeric");
      components.day = Some("numeric");
    }
    if need_defaults && matches!(defaults, Wanted::Time | Wanted::Any) {
      components.hour = Some("numeric");
      components.minute = Some("numeric");
      components.second = Some("numeric");
    }
  }

  let state = crate::state::state(ctx)?;
  let key = format!(
    "{}|{calendar:?}|{numbering_system:?}|{hour12:?}|{hour_cycle:?}|{time_zone:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{date_style:?}|{time_style:?}",
    locale::list_key(&requested),
    components.weekday,
    components.era,
    components.year,
    components.month,
    components.day,
    components.day_period,
    components.hour,
    components.minute,
    components.second,
    components.fractional_second_digits,
    components.time_zone_name,
  );
  if let Some(core) = state.date_time_formats.get(&key) {
    return Ok(core);
  }
  let zone = match &time_zone {
    Some(name) => parse_time_zone(name)
      .ok_or_else(|| Exception::throw_range(ctx, &format!("Invalid time zone specified: {name}")))?,
    None => parse_time_zone(&state.default_time_zone).unwrap_or_else(utc),
  };
  let found = locale::negotiate(&requested, &state.default_locale);
  let ca = locale::keyword(&found, "ca", calendar.as_deref(), |value| CALENDARS.contains(&value));
  let nu = locale::keyword(
    &found,
    "nu",
    numbering_system.as_deref(),
    crate::number_format::numbering_system_supported,
  );
  let hc = locale::keyword(&found, "hc", hour_cycle, |value| {
    matches!(value, "h11" | "h12" | "h23" | "h24")
  });
  let resolved = locale::with_keywords(&found.id, &[&ca, &nu, &hc]);
  let mut data_locale = Locale::from(found.id.clone());
  for keyword in [&ca, &nu] {
    if let Some(value) = &keyword.value {
      locale::set_keyword(&mut data_locale, keyword.key, value);
    }
  }
  drop(state);

  let mut prefs = DateTimeFormatterPreferences::from(&data_locale);
  let uses_hour = components.hour.is_some() || time_style.is_some();
  let hour_cycle = if uses_hour {
    let chosen = match hour12 {
      Some(true) => Some(if found.id.language.as_str() == "ja" {
        "h11"
      } else {
        "h12"
      }),
      Some(false) => Some("h23"),
      None => hc.value.as_deref().map(|value| match value {
        "h11" => "h11",
        "h12" => "h12",
        "h24" => "h24",
        _ => "h23",
      }),
    };
    if let Some(chosen) = chosen {
      prefs.hour_cycle = Some(match chosen {
        "h11" => HourCycle::H11,
        "h12" => HourCycle::H12,
        _ => HourCycle::H23,
      });
    }
    Some(chosen.unwrap_or_else(|| default_hour_cycle(prefs)))
  } else {
    None
  };

  let field_set = match (date_style, time_style) {
    (None, None) => components.bag().to_composite_field_set(),
    (date, time) => style_field_set(date, time).map_err(|error| Exception::throw_range(ctx, &error))?,
  };
  let formatter = DateTimeFormatter::try_new(prefs, field_set)
    .map_err(|error| Exception::throw_range(ctx, &format!("Intl.DateTimeFormat: {error}")))?;
  let calendar = calendar_name(formatter.calendar().kind());
  let numbering_system = nu
    .value
    .clone()
    .unwrap_or_else(|| crate::number_format::default_numbering_system(&data_locale));
  // The patterns ICU4X picks pad minutes and seconds next to an hour,
  // which is what the format then reports.
  if time_style.is_none() && date_style.is_none() && components.hour.is_some() {
    if components.minute.is_some() {
      components.minute = Some("2-digit");
    }
    if components.second.is_some() {
      components.second = Some("2-digit");
    }
  }
  let core = Rc::new(DateTimeFormatCore {
    locale: resolved.to_string(),
    calendar,
    numbering_system,
    zone,
    hour_cycle,
    components,
    date_style,
    time_style,
    formatter,
    prefs,
    field_set,
    range: std::cell::OnceCell::new(),
  });
  crate::state::state(ctx)?
    .date_time_formats
    .insert(key, Rc::clone(&core));
  Ok(core)
}

fn utc() -> Zone {
  Zone::Named {
    id: "UTC".to_owned(),
    tz: jiff::tz::TimeZone::UTC,
    icu: TimeZone::from_iana_id("UTC"),
  }
}

/// A time zone as ECMA-402 accepts it: an IANA name, matched without
/// regard to case, or a UTC offset (`+05:30`, `-0800`, `+01`).
fn parse_time_zone(name: &str) -> Option<Zone> {
  if let Some(seconds) = parse_offset(name) {
    let sign = if seconds < 0 { '-' } else { '+' };
    let minutes = seconds.abs() / 60;
    return Some(Zone::Offset {
      id: format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60),
      seconds,
    });
  }
  let upper = name.to_ascii_uppercase();
  if matches!(
    upper.as_str(),
    "UTC"
      | "ETC/UTC"
      | "ETC/UCT"
      | "UCT"
      | "ETC/UNIVERSAL"
      | "UNIVERSAL"
      | "ETC/ZULU"
      | "ZULU"
      | "GMT"
      | "ETC/GMT"
      | "GMT0"
      | "GMT+0"
      | "GMT-0"
      | "ETC/GMT0"
      | "ETC/GMT+0"
      | "ETC/GMT-0"
      | "ETC/GREENWICH"
      | "GREENWICH"
  ) {
    return Some(utc());
  }
  let tz = jiff::tz::TimeZone::get(name).ok()?;
  let id = tz.iana_name().unwrap_or(name).to_owned();
  let icu = TimeZone::from_iana_id(&id);
  Some(Zone::Named { id, tz, icu })
}

fn parse_offset(text: &str) -> Option<i32> {
  let bytes = text.as_bytes();
  let sign = match bytes.first()? {
    b'+' => 1,
    b'-' => -1,
    _ => return None,
  };
  let rest = &text[1..];
  let digits = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit());
  let (hours, minutes) = match rest.len() {
    2 if digits(rest) => (rest, "00"),
    4 if digits(&rest[..2]) && digits(&rest[2..]) => (&rest[..2], &rest[2..]),
    5 if digits(&rest[..2]) && &rest[2..3] == ":" && digits(&rest[3..]) => (&rest[..2], &rest[3..]),
    _ => return None,
  };
  let hours: i32 = hours.parse().ok()?;
  let minutes: i32 = minutes.parse().ok()?;
  if hours > 23 || minutes > 59 {
    return None;
  }
  Some(sign * (hours * 3600 + minutes * 60))
}

/// `DateTimeStyleFormat(dateStyle, timeStyle)`.
fn style_field_set(date: Option<&str>, time: Option<&str>) -> std::result::Result<CompositeFieldSet, String> {
  let mut builder = FieldSetBuilder::default();
  let length = |style: &str| match style {
    "full" | "long" => Length::Long,
    "medium" => Length::Medium,
    _ => Length::Short,
  };
  if let Some(date) = date {
    builder.length = Some(length(date));
    builder.date_fields = Some(if date == "full" {
      DateFields::YMDE
    } else {
      DateFields::YMD
    });
  }
  if let Some(time) = time {
    if builder.length.is_none() {
      builder.length = Some(length(time));
    }
    builder.time_precision = Some(if time == "short" {
      TimePrecision::Minute
    } else {
      TimePrecision::Second
    });
    builder.zone_style = match time {
      "full" => Some(ZoneStyle::SpecificLong),
      "long" => Some(ZoneStyle::SpecificShort),
      _ => None,
    };
  }
  builder.build_composite().map_err(|error| error.to_string())
}

/// The hour cycle a locale's own time patterns use, read off what it
/// writes for midnight and for 13:00.
fn default_hour_cycle(prefs: DateTimeFormatterPreferences) -> &'static str {
  let mut builder = FieldSetBuilder::default();
  builder.time_precision = Some(TimePrecision::Hour);
  let Ok(field_set) = builder.build_composite() else {
    return "h23";
  };
  let Ok(formatter) = DateTimeFormatter::try_new(prefs, field_set) else {
    return "h23";
  };
  let hour_at = |hour: u8| -> Option<u32> {
    let date = Date::try_new_iso(2000, 1, 1).ok()?;
    let time = Time::try_new(hour, 0, 0, 0).ok()?;
    let input = ZonedDateTime {
      date,
      time,
      zone: TimeZone::UNKNOWN
        .with_offset(UtcOffset::try_from_seconds(0).ok())
        .with_zone_name_timestamp(ZoneNameTimestamp::from_epoch_seconds(0)),
    };
    let text: String = Recorder::segments(&formatter.format(&input))
      .into_iter()
      .filter(|(stack, _)| stack.first() == Some(&icu::datetime::parts::HOUR))
      .map(|(_, text)| text)
      .collect();
    digits_value(&text)
  };
  match (hour_at(0), hour_at(13)) {
    (Some(0), Some(1)) => "h11",
    (Some(12), Some(1)) => "h12",
    (Some(24), _) => "h24",
    _ => "h23",
  }
}

/// The value of a run of decimal digits in any numbering system.
fn digits_value(text: &str) -> Option<u32> {
  let mut value = None;
  for c in text.chars() {
    if let Some(digit) = c.to_digit(10).or_else(|| unicode_digit(c)) {
      value = Some(value.unwrap_or(0) * 10 + digit);
    }
  }
  value
}

fn unicode_digit(c: char) -> Option<u32> {
  // Every Unicode decimal digit block is ten consecutive code points
  // starting at a code point ending in 0 or 6; the zeros of the blocks
  // a CLDR locale uses by default are listed here.
  const ZEROS: &[u32] = &[
    0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0E50, 0x0ED0,
    0x0F20, 0x1040, 0x17E0, 0x1810, 0xFF10,
  ];
  let code = c as u32;
  ZEROS
    .iter()
    .find(|zero| (**zero..**zero + 10).contains(&code))
    .map(|zero| code - zero)
}

/// The calendar a locale formats dates in when it names none.
pub(crate) fn preferred_calendar(locale: &Locale) -> String {
  let mut builder = FieldSetBuilder::default();
  builder.date_fields = Some(DateFields::YMD);
  builder
    .build_composite()
    .ok()
    .and_then(|field_set| DateTimeFormatter::try_new(locale.into(), field_set).ok())
    .map_or_else(
      || "gregory".to_owned(),
      |formatter| calendar_name(formatter.calendar().kind()),
    )
}

fn calendar_name(kind: AnyCalendarKind) -> String {
  match kind {
    AnyCalendarKind::Buddhist => "buddhist",
    AnyCalendarKind::Chinese => "chinese",
    AnyCalendarKind::Coptic => "coptic",
    AnyCalendarKind::Dangi => "dangi",
    AnyCalendarKind::Ethiopian => "ethiopic",
    AnyCalendarKind::EthiopianAmeteAlem => "ethioaa",
    AnyCalendarKind::Hebrew => "hebrew",
    AnyCalendarKind::Indian => "indian",
    AnyCalendarKind::HijriTabularTypeIIFriday => "islamic-civil",
    AnyCalendarKind::HijriTabularTypeIIThursday => "islamic-tbla",
    AnyCalendarKind::HijriUmmAlQura => "islamic-umalqura",
    AnyCalendarKind::HijriSimulatedMecca => "islamic",
    AnyCalendarKind::Iso => "iso8601",
    AnyCalendarKind::Japanese => "japanese",
    AnyCalendarKind::Persian => "persian",
    AnyCalendarKind::Roc => "roc",
    _ => "gregory",
  }
  .to_owned()
}

impl DateTimeFormatCore {
  /// `ToLocalTime`: the instant as wall time in the format's zone.
  fn input(&self, epoch_ms: f64) -> Option<ZonedDateTime<Iso, TimeZoneInfo<AtTime>>> {
    let epoch_ms = epoch_ms as i64;
    let offset = self.zone.offset_seconds(epoch_ms);
    let local = epoch_ms + i64::from(offset) * 1000;
    // 1970-01-01 is rata die 719163. ICU4X's year constructors stop at
    // 9999; a rata die reaches the whole range of a `Date`.
    let date = Date::from_rata_die(RataDie::new(local.div_euclid(86_400_000) + 719_163), Iso);
    let in_day = local.rem_euclid(86_400_000);
    let time = Time::try_new(
      (in_day / 3_600_000) as u8,
      (in_day / 60_000 % 60) as u8,
      (in_day / 1000 % 60) as u8,
      (in_day % 1000) as u32 * 1_000_000,
    )
    .ok()?;
    Some(ZonedDateTime {
      date,
      time,
      zone: self.zone.info(offset, epoch_ms),
    })
  }

  fn shows_zone(&self) -> bool {
    matches!(self.time_style, Some("full" | "long")) || self.components.time_zone_name.is_some()
  }

  fn shows_time(&self) -> bool {
    self.time_style.is_some() || (self.date_style.is_none() && self.components.has_time())
  }

  /// The formatted string: V8 writes a plain space where CLDR puts a
  /// narrow no-break space (before "AM", between a time and its zone)
  /// in `format`, though not in `formatToParts`, and code matching
  /// Node's output looks for the same text.
  fn format(&self, epoch_ms: f64) -> String {
    parts::concat(&self.parts(epoch_ms)).replace('\u{202f}', " ")
  }

  /// `FormatDateTimePattern` for a time value already `TimeClip`ped.
  fn parts(&self, epoch_ms: f64) -> Vec<JsPart> {
    let Some(input) = self.input(epoch_ms) else {
      return Vec::new();
    };
    to_parts(Recorder::segments(&self.formatter.format(&input)))
  }

  /// `PartitionDateTimeRangePattern`: CLDR's interval pattern for the
  /// largest field the two differ in, or one date when they do not.
  fn range_parts(&self, start: f64, end: f64) -> Vec<JsPart> {
    let (Some(mut first), Some(mut second)) = (self.input(start), self.input(end)) else {
      return Vec::new();
    };
    // The interval pattern is chosen by the largest field the two
    // differ in; only the fields shown count, as in V8.
    if !self.shows_time() {
      first.time = Time::start_of_day();
      second.time = Time::start_of_day();
    }
    if !self.shows_zone() {
      second.zone = first.zone;
    }
    let range = self
      .range
      .get_or_init(|| DateRangeFormatter::try_new(self.prefs, self.field_set).ok());
    let Some(range) = range else {
      return Vec::new();
    };
    to_parts(Recorder::segments(&range.format(&first, &second)))
  }

  fn resolved_options<'js>(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    let object = Object::new(ctx)?;
    object.set("locale", self.locale.as_str())?;
    object.set("calendar", self.calendar.as_str())?;
    object.set("numberingSystem", self.numbering_system.as_str())?;
    object.set("timeZone", self.zone.id())?;
    if let Some(hour_cycle) = self.hour_cycle {
      object.set("hourCycle", hour_cycle)?;
      object.set("hour12", matches!(hour_cycle, "h11" | "h12"))?;
    }
    if self.date_style.is_none() && self.time_style.is_none() {
      let c = &self.components;
      let fields: [(&str, Option<&str>); 6] = [
        ("weekday", c.weekday),
        ("era", c.era),
        ("year", c.year),
        ("month", c.month),
        ("day", c.day),
        ("dayPeriod", c.day_period),
      ];
      for (name, value) in fields {
        if let Some(value) = value {
          object.set(name, value)?;
        }
      }
      for (name, value) in [("hour", c.hour), ("minute", c.minute), ("second", c.second)] {
        if let Some(value) = value {
          object.set(name, value)?;
        }
      }
      if let Some(digits) = c.fractional_second_digits {
        object.set("fractionalSecondDigits", digits)?;
      }
      if let Some(name) = c.time_zone_name {
        object.set("timeZoneName", name)?;
      }
    }
    if let Some(style) = self.date_style {
      object.set("dateStyle", style)?;
    }
    if let Some(style) = self.time_style {
      object.set("timeStyle", style)?;
    }
    Ok(object)
  }
}

/// ECMA-402's parts from what ICU4X wrote: each segment's field is the
/// outermost part that is not a range end, a range end gives its
/// `source`, and digits after a seconds separator are the fraction.
fn to_parts(segments: Vec<crate::parts::Segment>) -> Vec<JsPart> {
  use icu::datetime::parts::{RANGE_END, RANGE_START};
  let ranged = segments
    .iter()
    .any(|(stack, _)| stack.contains(&RANGE_START) || stack.contains(&RANGE_END));
  let mut out: Vec<JsPart> = Vec::new();
  for (stack, text) in segments {
    let source = if !ranged {
      None
    } else if stack.contains(&RANGE_START) {
      Some("startRange")
    } else if stack.contains(&RANGE_END) {
      Some("endRange")
    } else {
      Some("shared")
    };
    let field = stack
      .iter()
      .find(|part| **part != RANGE_START && **part != RANGE_END)
      .copied();
    let inner = stack.last().copied();
    let kind = match field {
      Some(part) if part == icu::datetime::parts::SECOND => match inner {
        Some(inner) if inner == icu::decimal::parts::FRACTION => "fractionalSecond",
        Some(inner) if inner == icu::decimal::parts::DECIMAL => "literal",
        _ => "second",
      },
      Some(part) => part_name(part),
      None => "literal",
    };
    match out.last_mut() {
      Some(last) if last.kind == kind && last.source == source => last.value.push_str(&text),
      _ if text.is_empty() => {},
      _ => out.push(JsPart {
        kind,
        value: text,
        source,
        unit: None,
      }),
    }
  }
  out
}

fn part_name(part: Part) -> &'static str {
  match part.value {
    "era" => "era",
    "year" => "year",
    "relatedYear" => "relatedYear",
    "yearName" => "yearName",
    "month" => "month",
    "day" => "day",
    "weekday" => "weekday",
    "dayPeriod" => "dayPeriod",
    "hour" => "hour",
    "minute" => "minute",
    "second" => "second",
    "timeZoneName" => "timeZoneName",
    _ => "literal",
  }
}

/// `ToNumber(date)` then `TimeClip`, or now for `undefined`.
fn time_value<'js>(ctx: &Ctx<'js>, date: Option<Value<'js>>) -> Result<f64> {
  let value = match date {
    Some(value) if !value.is_undefined() => value.get::<Coerced<f64>>()?.0,
    _ => {
      let now: Function<'js> = ctx.globals().get::<_, Object<'js>>("Date")?.get("now")?;
      now.call::<_, f64>(())?
    },
  };
  time_clip(ctx, value)
}

fn time_clip(ctx: &Ctx<'_>, value: f64) -> Result<f64> {
  if !value.is_finite() || value.abs() > 8.64e15 {
    return Err(Exception::throw_range(ctx, "Invalid time value"));
  }
  Ok(value.trunc() + 0.0)
}

#[derive(Trace)]
#[rquickjs::class(rename = "DateTimeFormat")]
pub struct DateTimeFormat<'js> {
  #[qjs(skip_trace)]
  core: Rc<DateTimeFormatCore>,
  bound_format: Option<Function<'js>>,
}

// SAFETY: the only `'js` value is the bound `format`, which belongs to
// the context the formatter does.
#[allow(unsafe_code)]
unsafe impl<'js> JsLifetime<'js> for DateTimeFormat<'js> {
  type Changed<'to> = DateTimeFormat<'to>;
}

#[rquickjs::methods(rename_all = "camelCase")]
impl<'js> DateTimeFormat<'js> {
  #[qjs(get)]
  pub fn format(this: This<Class<'js, Self>>, ctx: Ctx<'js>) -> Result<Function<'js>> {
    if let Some(bound) = this.0.borrow().bound_format.clone() {
      return Ok(bound);
    }
    let core = Rc::clone(&this.0.borrow().core);
    let bound = Function::new(ctx, move |ctx: Ctx<'js>, date: Opt<Value<'js>>| -> Result<String> {
      let time = time_value(&ctx, date.0)?;
      Ok(core.format(time))
    })?
    .with_length(1)?
    .with_name("")?;
    this.0.borrow_mut().bound_format = Some(bound.clone());
    Ok(bound)
  }

  pub fn format_to_parts(&self, ctx: Ctx<'js>, date: Opt<Value<'js>>) -> Result<Array<'js>> {
    let time = time_value(&ctx, date.0)?;
    parts::to_array(&ctx, &self.core.parts(time))
  }

  pub fn format_range(&self, ctx: Ctx<'js>, start: Opt<Value<'js>>, end: Opt<Value<'js>>) -> Result<String> {
    Ok(parts::concat(&self.range_parts(&ctx, start, end)?).replace('\u{202f}', " "))
  }

  pub fn format_range_to_parts(
    &self,
    ctx: Ctx<'js>,
    start: Opt<Value<'js>>,
    end: Opt<Value<'js>>,
  ) -> Result<Array<'js>> {
    let parts = self.range_parts(&ctx, start, end)?;
    parts::to_array(&ctx, &parts)
  }

  pub fn resolved_options(&self, ctx: Ctx<'js>) -> Result<Object<'js>> {
    self.core.resolved_options(ctx)
  }

  #[qjs(prop, rename = PredefinedAtom::SymbolToStringTag, configurable)]
  pub fn to_string_tag() -> &'static str {
    "Intl.DateTimeFormat"
  }
}

impl<'js> DateTimeFormat<'js> {
  fn range_parts(&self, ctx: &Ctx<'js>, start: Opt<Value<'js>>, end: Opt<Value<'js>>) -> Result<Vec<JsPart>> {
    let (Some(start), Some(end)) = (start.0, end.0) else {
      return Err(Exception::throw_type(ctx, "startDate and endDate are required"));
    };
    if start.is_undefined() || end.is_undefined() {
      return Err(Exception::throw_type(ctx, "startDate and endDate are required"));
    }
    let start = time_clip(ctx, start.get::<Coerced<f64>>()?.0)?;
    let end = time_clip(ctx, end.get::<Coerced<f64>>()?.0)?;
    Ok(self.core.range_parts(start, end))
  }
}

pub(crate) fn define<'js>(ctx: &Ctx<'js>, intl: &Object<'js>) -> Result<()> {
  let constructor = rquickjs::Constructor::new_class::<DateTimeFormat<'js>, _, _>(
    ctx.clone(),
    |ctx: Ctx<'js>, locales: Opt<Value<'js>>, options: Opt<Value<'js>>| -> Result<DateTimeFormat<'js>> {
      Ok(DateTimeFormat {
        core: resolve(&ctx, locales.0.as_ref(), options.0, Wanted::Any, Wanted::Date)?,
        bound_format: None,
      })
    },
  )?;
  crate::intl::finish_constructor(ctx, intl, &constructor, "DateTimeFormat", 0)
}

fn date_method<'js>(
  ctx: &Ctx<'js>,
  this: &Value<'js>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
  required: Wanted,
  defaults: Wanted,
) -> Result<String> {
  let date_prototype: Object<'js> = ctx.globals().get::<_, Object<'js>>("Date")?.get("prototype")?;
  let get_time: Function<'js> = date_prototype.get("getTime")?;
  let time: f64 = get_time.call((This(this.clone()),))?;
  if time.is_nan() {
    return Ok("Invalid Date".to_owned());
  }
  let core = resolve(ctx, locales.0.as_ref(), options.0, required, defaults)?;
  Ok(core.format(time))
}

/// `Date.prototype.toLocaleString(locales, options)`.
pub(crate) fn to_locale_string<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
) -> Result<String> {
  date_method(&ctx, &this.0, locales, options, Wanted::Any, Wanted::Any)
}

/// `Date.prototype.toLocaleDateString(locales, options)`.
pub(crate) fn to_locale_date_string<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
) -> Result<String> {
  date_method(&ctx, &this.0, locales, options, Wanted::Date, Wanted::Date)
}

/// `Date.prototype.toLocaleTimeString(locales, options)`.
pub(crate) fn to_locale_time_string<'js>(
  ctx: Ctx<'js>,
  this: This<Value<'js>>,
  locales: Opt<Value<'js>>,
  options: Opt<Value<'js>>,
) -> Result<String> {
  date_method(&ctx, &this.0, locales, options, Wanted::Time, Wanted::Time)
}
