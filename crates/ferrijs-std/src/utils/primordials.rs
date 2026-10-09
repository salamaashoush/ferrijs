use std::any::{type_name, Any};
use std::cell::OnceCell;
use std::ops::Deref;

use rquickjs::{
    atom::PredefinedAtom, function::Constructor, runtime::UserDataGuard, Ctx, Exception, Function,
    JsLifetime, Object, Result,
};


#[derive(JsLifetime)]
pub struct BasePrimordials<'js> {
    // Constructors
    pub constructor_map: Constructor<'js>,
    pub constructor_set: Constructor<'js>,
    pub constructor_date: Constructor<'js>,
    pub constructor_error: Constructor<'js>,
    pub constructor_type_error: Constructor<'js>,
    pub constructor_range_error: Constructor<'js>,
    pub constructor_regexp: Constructor<'js>,
    pub constructor_uint8array: Constructor<'js>,
    pub constructor_array_buffer: Constructor<'js>,
    pub constructor_proxy: Constructor<'js>,
    pub constructor_object: Constructor<'js>,
    pub constructor_bool: Constructor<'js>,
    pub constructor_number: Constructor<'js>,
    pub constructor_string: Constructor<'js>,

    // Prototypes
    pub prototype_object: Object<'js>,
    pub prototype_date: Object<'js>,
    pub prototype_regexp: Object<'js>,
    pub prototype_set: Object<'js>,
    pub prototype_map: Object<'js>,
    pub prototype_error: Object<'js>,

    // Functions
    pub function_array_from: Function<'js>,
    pub function_array_buffer_is_view: Function<'js>,
    pub function_get_own_property_descriptor: Function<'js>,
    pub function_reflect_own_keys: Function<'js>,
    pub function_parse_int: Function<'js>,
    pub function_parse_float: Function<'js>,
    pub prototype_iterator: Object<'js>,
}

/// Local delta: storage for a primordial reserved before the primordial
/// exists. rquickjs refuses to insert userdata while any userdata is
/// borrowed, and a lazy group can install from deep inside code holding a
/// primordial, so a realm built lazily reserves each such slot at build
/// and the group's `init` fills it in place instead of inserting.
pub struct Reserved<P>(OnceCell<P>);

// SAFETY: `Reserved` only wraps `P`, so its lifetime is `P`'s, renamed.
unsafe impl<'js, P: JsLifetime<'js>> JsLifetime<'js> for Reserved<P> {
    type Changed<'to> = Reserved<P::Changed<'to>>;
}

/// A primordial, wherever it is stored. Local delta: this was a bare
/// `UserDataGuard<P>` before [`Reserved`].
pub enum PrimordialRef<'a, P> {
    Stored(UserDataGuard<'a, P>),
    Reserved(UserDataGuard<'a, Reserved<P>>),
}

impl<P> Deref for PrimordialRef<'_, P> {
    type Target = P;

    fn deref(&self) -> &P {
        match self {
            Self::Stored(guard) => guard,
            Self::Reserved(guard) => guard
                .0
                .get()
                .expect("a reserved primordial is only handed out once filled"),
        }
    }
}

pub trait Primordial<'js>
where
    Self: Sized + JsLifetime<'js>,
    Self::Changed<'static>: Any,
{
    /// A global whose lazy group creates this primordial: a `get` that
    /// finds it missing installs that group first. Local delta.
    const LAZY_GLOBAL: Option<&'static str> = None;

    fn get<'a>(ctx: &'a Ctx<'js>) -> Result<PrimordialRef<'a, Self>> {
        if let Some(found) = Self::find(ctx) {
            return Ok(found);
        }
        if let Some(name) = Self::LAZY_GLOBAL {
            crate::lazy::ensure(ctx, name)?;
            if let Some(found) = Self::find(ctx) {
                return Ok(found);
            }
        }
        Err(Exception::throw_message(
            ctx,
            &[
                "Userdata of ",
                type_name::<Self>(),
                " not initialized. Call init(&ctx) on this type.",
            ]
            .concat(),
        ))
    }

    /// Local delta: the stored or reserved-and-filled primordial, if any.
    fn find<'a>(ctx: &'a Ctx<'js>) -> Option<PrimordialRef<'a, Self>> {
        if let Some(stored) = ctx.userdata::<Self>() {
            return Some(PrimordialRef::Stored(stored));
        }
        ctx.userdata::<Reserved<Self>>()
            .filter(|reserved| reserved.0.get().is_some())
            .map(PrimordialRef::Reserved)
    }

    /// Local delta: reserve this primordial's slot. Only at realm build,
    /// before anything can hold a userdata borrow.
    fn reserve(ctx: &Ctx<'js>) {
        if ctx.userdata::<Self>().is_none() && ctx.userdata::<Reserved<Self>>().is_none() {
            let _ = ctx.store_userdata(Reserved::<Self>(OnceCell::new()));
        }
    }

    fn init<'a>(ctx: &'a Ctx<'js>) -> Result<()> {
        if Self::find(ctx).is_some() {
            return Ok(());
        }
        let primordials = Self::new(ctx)?;
        match ctx.userdata::<Reserved<Self>>() {
            Some(reserved) => {
                let _ = reserved.0.set(primordials);
            },
            None => {
                let _ = ctx.store_userdata(primordials);
            },
        }
        Ok(())
    }
    fn new(ctx: &Ctx<'js>) -> Result<Self>;
}

impl<'js> Primordial<'js> for BasePrimordials<'js> {
    fn new(ctx: &Ctx<'js>) -> Result<Self> {
        let globals = ctx.globals();

        let constructor_object: Constructor = globals.get(PredefinedAtom::Object)?;
        let prototype_object: Object = constructor_object.get(PredefinedAtom::Prototype)?;

        let constructor_proxy: Constructor = globals.get(PredefinedAtom::Proxy)?;

        let function_get_own_property_descriptor: Function =
            constructor_object.get(PredefinedAtom::GetOwnPropertyDescriptor)?;

        let constructor_date: Constructor = globals.get(PredefinedAtom::Date)?;
        let prototype_date: Object = constructor_date.get(PredefinedAtom::Prototype)?;

        let constructor_map: Constructor = globals.get(PredefinedAtom::Map)?;
        let prototype_map: Object = constructor_map.get(PredefinedAtom::Prototype)?;

        let constructor_set: Constructor = globals.get(PredefinedAtom::Set)?;
        let prototype_set: Object = constructor_set.get(PredefinedAtom::Prototype)?;

        let constructor_regexp: Constructor = globals.get(PredefinedAtom::RegExp)?;
        let prototype_regexp: Object = constructor_regexp.get(PredefinedAtom::Prototype)?;

        let constructor_uint8array: Constructor = globals.get(PredefinedAtom::Uint8Array)?;
        let constructor_arraybuffer: Constructor = globals.get(PredefinedAtom::ArrayBuffer)?;

        let constructor_error: Constructor = globals.get(PredefinedAtom::Error)?;
        let constructor_type_error: Constructor = ctx.globals().get(PredefinedAtom::TypeError)?;
        let constructor_range_error: Constructor = ctx.globals().get(PredefinedAtom::RangeError)?;
        let prototype_error: Object = constructor_error.get(PredefinedAtom::Prototype)?;

        let constructor_array: Object = globals.get(PredefinedAtom::Array)?;
        let function_array_from: Function = constructor_array.get(PredefinedAtom::From)?;

        let constructor_array_buffer: Object = globals.get(PredefinedAtom::ArrayBuffer)?;
        let function_array_buffer_is_view: Function = constructor_array_buffer.get("isView")?;

        let constructor_bool: Constructor = globals.get(PredefinedAtom::Boolean)?;

        let constructor_number: Constructor = globals.get(PredefinedAtom::Number)?;
        let function_parse_float: Function = constructor_number.get("parseFloat")?;
        let function_parse_int: Function = constructor_number.get("parseInt")?;

        let constructor_string: Constructor = globals.get(PredefinedAtom::String)?;

        let reflect: Object = globals.get("Reflect")?;
        let function_reflect_own_keys: Function = reflect.get("ownKeys")?;

        // Walk to %IteratorPrototype% via an array iterator.
        let array = rquickjs::Array::new(ctx.clone())?;
        let iter_fn: Function = array
            .as_object()
            .get(rquickjs::atom::PredefinedAtom::SymbolIterator)?;
        let array_iter: Object = iter_fn.call((rquickjs::function::This(array),))?;
        let prototype_iterator = array_iter
            .get_prototype()
            .and_then(|p| p.get_prototype())
            .ok_or_else(|| Exception::throw_internal(ctx, "missing %IteratorPrototype%"))?;

        Ok(Self {
            constructor_map,
            constructor_set,
            constructor_date,
            constructor_proxy,
            constructor_error,
            constructor_type_error,
            constructor_range_error,
            constructor_regexp,
            constructor_uint8array,
            constructor_array_buffer: constructor_arraybuffer,
            constructor_object,
            constructor_bool,
            constructor_number,
            constructor_string,
            prototype_object,
            prototype_date,
            prototype_regexp,
            prototype_set,
            prototype_map,
            prototype_error,
            function_array_from,
            function_array_buffer_is_view,
            function_get_own_property_descriptor,
            function_reflect_own_keys,
            function_parse_float,
            function_parse_int,
            prototype_iterator,
        })
    }
}
