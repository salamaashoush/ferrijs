//! Globals installed on first touch.
//!
//! A realm built per request pays for every global it could use, and
//! most scripts use a handful. A lazy group puts an accessor under each
//! of its names; the first read of any of them, from a script or from
//! Rust, runs the group's install, which leaves ordinary data properties
//! behind. After that nothing pays for the laziness again.
//!
//! What a script did to a name before its group installed survives the
//! install: an assignment or a redefinition stands, and a deleted name
//! stays deleted.
//!
//! A group's install must not depend on running before user code. It
//! sees the realm as the script left it, so anything it captures from
//! another global it should take from a primordial, not from
//! `globalThis`.

use std::cell::RefCell;

use rquickjs::object::{AsProperty, Property, PropertyFlags};
use rquickjs::{Ctx, Function, JsLifetime, Object, Result, Value, qjs};

use crate::utils::primordials::{BasePrimordials, Primordial};

type Install = Box<dyn for<'a> FnOnce(&Ctx<'a>) -> Result<()>>;

struct Group<'js> {
  names: Box<[Box<str>]>,
  /// The getter defined under each name, by index, so an install can
  /// tell its own accessor from one a script defined in its place.
  getters: Vec<Function<'js>>,
  /// Taken when the group installs; `None` means installed or installing.
  install: Option<Install>,
}

#[derive(Default)]
struct Lazy<'js> {
  groups: RefCell<Vec<Group<'js>>>,
}

// SAFETY: every `'js` value inside is tied to the context the userdata is
// stored on, and `Changed` only renames that lifetime.
#[allow(unsafe_code)]
unsafe impl<'js> JsLifetime<'js> for Lazy<'js> {
  type Changed<'to> = Lazy<'to>;
}

/// An accessor from functions already made, so the getter's identity can
/// be kept. rquickjs's own `Accessor` makes its functions internally.
struct Pair<'js> {
  get: Function<'js>,
  set: Function<'js>,
}

impl<'js> AsProperty<'js, ()> for Pair<'js> {
  fn config(self, ctx: &Ctx<'js>) -> Result<(PropertyFlags, Value<'js>, Value<'js>, Value<'js>)> {
    let flags = (qjs::JS_PROP_CONFIGURABLE
      | qjs::JS_PROP_ENUMERABLE
      | qjs::JS_PROP_HAS_CONFIGURABLE
      | qjs::JS_PROP_HAS_ENUMERABLE
      | qjs::JS_PROP_HAS_GET
      | qjs::JS_PROP_HAS_SET) as PropertyFlags;
    Ok((flags, Value::new_undefined(ctx.clone()), self.get.into_value(), self.set.into_value()))
  }
}

/// Put `names` on `globalThis` behind accessors that run `install` the
/// first time any of them is read.
///
/// `install` defines every one of `names` on `globalThis` the way an
/// eager install would; it runs at most once, inside whatever read
/// triggered it. Until then each name is an enumerable, configurable
/// accessor, and assigning to it replaces it with a data property
/// without installing anything. A name already on `globalThis` is
/// replaced by its accessor.
///
/// # Errors
///
/// Propagates the property definitions.
pub fn define<'js, F>(ctx: &Ctx<'js>, names: &[&str], install: F) -> Result<()>
where
  F: for<'a> FnOnce(&Ctx<'a>) -> Result<()> + 'static,
{
  if ctx.userdata::<Lazy<'js>>().is_none() {
    let _ = ctx.store_userdata(Lazy::default());
  }
  let globals = ctx.globals();
  let index = lazy(ctx)?.groups.borrow().len();
  let mut getters = Vec::with_capacity(names.len());
  for (slot, name) in names.iter().enumerate() {
    let get = Function::new(ctx.clone(), move |ctx: Ctx<'js>| -> Result<Value<'js>> {
      install_group(&ctx, index)?;
      let name = lazy(&ctx)?.groups.borrow()[index].names[slot].clone();
      ctx.globals().get(&*name)
    })?;
    let set = Function::new(ctx.clone(), move |ctx: Ctx<'js>, value: Value<'js>| -> Result<()> {
      let name = lazy(&ctx)?.groups.borrow()[index].names[slot].clone();
      ctx
        .globals()
        .prop(&*name, Property::from(value).writable().enumerable().configurable())
    })?;
    globals.prop(*name, Pair { get: get.clone(), set })?;
    getters.push(get);
  }
  lazy(ctx)?.groups.borrow_mut().push(Group {
    names: names.iter().map(|n| Box::from(*n)).collect(),
    getters,
    install: Some(Box::new(install)),
  });
  Ok(())
}

/// Install the group that owns global `name`, if it has not installed.
/// For Rust that is about to build an object whose wiring that install
/// does (a `File` whose prototype chains to `Blob`), where reading the
/// global would not do: a script may have replaced it.
///
/// # Errors
///
/// What the group's install throws.
pub fn ensure(ctx: &Ctx<'_>, name: &str) -> Result<()> {
  let Some(lazy) = ctx.userdata::<Lazy<'_>>() else {
    return Ok(());
  };
  let index = lazy
    .groups
    .borrow()
    .iter()
    .position(|g| g.install.is_some() && g.names.iter().any(|n| &**n == name));
  drop(lazy);
  match index {
    Some(index) => install_group(ctx, index),
    None => Ok(()),
  }
}

/// Install every group still pending, for a realm that wants the eager
/// shape after all.
///
/// # Errors
///
/// What an install throws.
pub fn ensure_all(ctx: &Ctx<'_>) -> Result<()> {
  let Some(lazy) = ctx.userdata::<Lazy<'_>>() else {
    return Ok(());
  };
  let count = lazy.groups.borrow().len();
  drop(lazy);
  for index in 0..count {
    install_group(ctx, index)?;
  }
  Ok(())
}

fn lazy<'a, 'js>(ctx: &'a Ctx<'js>) -> Result<rquickjs::runtime::UserDataGuard<'a, Lazy<'js>>> {
  ctx
    .userdata::<Lazy<'js>>()
    .ok_or_else(|| rquickjs::Exception::throw_internal(ctx, "lazy globals are not set up on this realm"))
}

/// What a script left under a name before its group installed.
enum Before<'js> {
  /// Still the group's accessor: the install's definition stands.
  Lazy,
  /// Deleted: the install's definition is removed again.
  Absent,
  /// Assigned or redefined: moved aside for the install, then put back
  /// over it.
  Defined(Object<'js>),
}

fn install_group<'js>(ctx: &Ctx<'js>, index: usize) -> Result<()> {
  let (names, getters, install) = {
    let lazy = lazy(ctx)?;
    let mut groups = lazy.groups.borrow_mut();
    let group = &mut groups[index];
    let Some(install) = group.install.take() else {
      return Ok(());
    };
    (group.names.clone(), std::mem::take(&mut group.getters), install)
  };

  BasePrimordials::init(ctx)?;
  let describe = BasePrimordials::get(ctx)?.function_get_own_property_descriptor.clone();
  let globals = ctx.globals();
  let mut before = Vec::with_capacity(names.len());
  for (name, getter) in names.iter().zip(&getters) {
    let descriptor: Value<'js> = describe.call((globals.clone(), &**name))?;
    let state = match descriptor.into_object() {
      None => Before::Absent,
      Some(descriptor) if descriptor.get::<_, Value<'js>>("get")? == *getter.as_value() => {
        globals.remove(&**name)?;
        Before::Lazy
      },
      Some(descriptor) => {
        // Out of the install's way, so an install that assigns the name
        // does not throw on a read-only property; put back afterwards. A
        // non-configurable one cannot move and stays where it is.
        if descriptor.get::<_, bool>("configurable")? {
          globals.remove(&**name)?;
        }
        Before::Defined(descriptor)
      },
    };
    before.push(state);
  }

  install(ctx)?;

  let mut define_property = None;
  for (name, state) in names.iter().zip(before) {
    match state {
      Before::Lazy => {},
      Before::Absent => globals.remove(&**name)?,
      Before::Defined(descriptor) => {
        if define_property.is_none() {
          let object = BasePrimordials::get(ctx)?.constructor_object.clone();
          define_property = Some(object.get::<_, Function<'js>>("defineProperty")?);
        }
        if let Some(define) = &define_property {
          define.call::<_, Value<'js>>((globals.clone(), &**name, descriptor))?;
        }
      },
    }
  }
  Ok(())
}
