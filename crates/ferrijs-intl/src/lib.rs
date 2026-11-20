//! ECMA-402 `Intl` for the ferrijs runtime, on ICU4X with its data
//! compiled in.
//!
//! [`install`] gives a realm the `Intl` namespace and redefines the
//! locale-sensitive methods ECMA-402 puts on the language's own
//! prototypes (`String.prototype.localeCompare`,
//! `Number.prototype.toLocaleString`, `Date.prototype.toLocaleString`,
//! ...) over the same formatters.
//!
//! `Intl` itself installs on first read, so a realm that never touches
//! it pays only for the accessor. The data is baked into the binary:
//! nothing is read from disk and nothing is parsed at run time, and each
//! formatter a built-in method makes is kept for the next call with the
//! same options.

// The same allowances the `ferrijs` crate makes, for the same reasons:
// rquickjs passes `Ctx`, `Opt` and `This` by value through its function
// ABI; ECMA-402's options are JS numbers narrowed to the spec's integer
// ranges after they are range-checked; and a spec algorithm reads best
// as one function in the spec's step order.
#![allow(
  clippy::needless_pass_by_value,
  clippy::cast_possible_truncation,
  clippy::cast_possible_wrap,
  clippy::cast_precision_loss,
  clippy::cast_sign_loss,
  clippy::too_many_lines,
  clippy::doc_markdown
)]

mod collator;
mod date_time_format;
mod display_names;
mod intl;
mod list_format;
mod locale;
mod locale_object;
mod number_format;
mod options;
mod parts;
mod plural_rules;
mod prototypes;
mod relative_time_format;
mod segmenter;
mod state;
mod units;

use rquickjs::{Ctx, Result};

/// What a realm's `Intl` starts from.
#[derive(Debug, Clone, Default)]
pub struct IntlOptions {
  /// The default locale (`new Intl.NumberFormat().resolvedOptions().locale`).
  /// `None`, or a locale without data, takes the host's, from `LC_ALL`,
  /// `LC_MESSAGES` or `LANG`, as Node does.
  pub default_locale: Option<String>,
  /// The default time zone, as an IANA name. `None` takes the host's,
  /// from `TZ` or the system's configuration.
  pub default_time_zone: Option<String>,
}

/// Install `Intl` and the locale-sensitive prototype methods on the
/// realm `ctx` belongs to.
///
/// # Errors
///
/// Propagates the property definitions.
pub fn install(ctx: &Ctx<'_>, options: &IntlOptions) -> Result<()> {
  let default_locale = locale::configured_default(options.default_locale.as_deref());
  let default_time_zone = options.default_time_zone.clone().unwrap_or_else(|| {
    jiff::tz::TimeZone::system()
      .iana_name()
      .map_or_else(|| "UTC".to_owned(), str::to_owned)
  });
  ctx
    .store_userdata(state::State::new(default_locale, default_time_zone))
    .map_err(|_| rquickjs::Exception::throw_internal(ctx, "Intl is already installed on this realm"))?;
  prototypes::install(ctx)?;
  ferrijs_std::lazy::define(ctx, &["Intl"], intl::install)
}
