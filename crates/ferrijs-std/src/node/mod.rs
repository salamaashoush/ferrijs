//! Node modules with no usable upstream in llrt, written here so the
//! runtime has exactly one implementation of each.

use rquickjs::{Ctx, Object, Value};

pub mod assert;
pub mod buffer;
mod bundled;
pub mod bytes;
pub mod crypto;
pub mod deep_equal;
pub mod diagnostics_channel;
pub mod events;
pub mod inspect;
pub mod path;
pub mod process;
pub mod require_resolve;
pub mod stream;
pub mod system_error;
pub mod timers;
pub mod util;

/// Throw an `Error` carrying a specific `name` (`TypeError`,
/// `RangeError`, ...). QuickJS's own constructors are used so the thrown
/// value is a real `Error` with a stack.
pub fn throw_named<'js>(ctx: &Ctx<'js>, name: &str, message: impl Into<String>) -> rquickjs::Error {
  let message = message.into();
  let built: rquickjs::Result<Value<'js>> = (|| {
    let ctor: rquickjs::function::Constructor<'js> = ctx.globals().get("Error")?;
    let err: Object<'js> = ctor.construct((message.as_str(),))?;
    err.set("name", name)?;
    Ok(err.into_value())
  })();
  match built {
    Ok(v) => ctx.throw(v),
    Err(_) => rquickjs::Exception::throw_message(ctx, &message),
  }
}

/// Throw a real error of the built-in class `kind` (`TypeError`,
/// `RangeError`, `Error`, ...) carrying the whole of `message`, with
/// `code` set when there is one, as Node's `internal/errors` makes them.
///
/// `rquickjs::Error::new_from_js_message` is not a substitute: it formats
/// through `QuickJS`'s 256-byte buffer, so a longer message is cut, and
/// every message reads "Error converting from js ...".
pub fn throw_error(ctx: &Ctx<'_>, kind: &str, code: Option<&str>, message: &str) -> rquickjs::Error {
  let built = (|| -> rquickjs::Result<Value<'_>> {
    let ctor: rquickjs::function::Constructor<'_> = ctx.globals().get(kind)?;
    let error: Object<'_> = ctor.construct((message,))?;
    if let Some(code) = code {
      error.set("code", code)?;
    }
    Ok(error.into_value())
  })();
  match built {
    Ok(error) => ctx.throw(error),
    Err(error) => error,
  }
}

/// [`throw_error`] with Node's `code`.
pub(crate) fn coded(ctx: &Ctx<'_>, kind: &str, code: &str, message: &str) -> rquickjs::Error {
  throw_error(ctx, kind, Some(code), message)
}
