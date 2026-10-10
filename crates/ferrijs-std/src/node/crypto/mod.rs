//! `node:crypto`: the vendored hashing and random functions, plus
//! `KeyObject`, `createSign` / `createVerify`, `crypto.sign` /
//! `crypto.verify`, key generation and `timingSafeEqual`, which upstream
//! does not have.
//!
//! The classes are JavaScript (`crypto.js`), shaped after Node's
//! `lib/internal/crypto/keys.js` and `sig.js`; the key material, its
//! encodings and every signature are native, over the same provider
//! `crypto.subtle` uses. One instance per realm answers both `require`
//! and `import`, so a key made through one is an instance of the other's
//! `KeyObject`.
//!
//! A realm pays for `crypto.js` only when it first uses a key: until
//! then the namespace holds native stand-ins that load it, so `import
//! crypto from 'node:crypto'` for a hash or a UUID costs what it did
//! before these members existed. Evaluating `crypto.js` costs a realm
//! about two thirds of its own build.
//!
//! `Sign` and `Verify` are not streams. Node makes them `Writable`s, and
//! loading `node:stream` for one costs a realm several times its own
//! build; the vendored `Hash` and `Hmac` are not streams either.

mod der;
mod keys;
mod sig;

use std::rc::Rc;

use rquickjs::atom::PredefinedAtom;
use rquickjs::class::Trace;
use rquickjs::function::{Args, Constructor, Opt, Rest, This};
use rquickjs::module::{Declarations, Exports, ModuleDef};
use rquickjs::object::Property;
use rquickjs::{BigInt, Class, Ctx, Function, IntoJs, JsLifetime, Module, Object, Result, Value};

use super::bundled::Bundled;
use super::coded;
use crate::buffer::Buffer;
use crate::crypto::CRYPTO_PROVIDER;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::provider::CryptoProvider;
use crate::utils::bytes::ObjectBytes;
use keys::{KeyError, Material};
use sig::{Options, SignError};

static CRYPTO_JS: Bundled = Bundled::new("ferrijs:crypto", include_str!("crypto.js"));

/// The members this module adds to the vendored ones (`createHmac` is
/// both: the vendored one, taught to take a `KeyObject`).
const OWN_EXPORTS: &[&str] = &[
  "KeyObject",
  "createSecretKey",
  "createPublicKey",
  "createPrivateKey",
  "generateKeyPair",
  "generateKeyPairSync",
  "Sign",
  "Verify",
  "createSign",
  "createVerify",
  "sign",
  "verify",
  "timingSafeEqual",
  "constants",
  "subtle",
];

/// The key material a `KeyObject` holds. Opaque to scripts: the class
/// keeps it in a private field and every operation on it is native.
#[derive(Trace, JsLifetime)]
#[rquickjs::class]
pub struct KeyHandle {
  #[qjs(skip_trace)]
  material: Rc<Material>,
}

fn handle<'js>(ctx: &Ctx<'js>, material: Material) -> Result<Class<'js, KeyHandle>> {
  Class::instance(
    ctx.clone(),
    KeyHandle {
      material: Rc::new(material),
    },
  )
}

fn material(handle: &Class<'_, KeyHandle>) -> Rc<Material> {
  Rc::clone(&handle.borrow().material)
}

fn key_result<T>(ctx: &Ctx<'_>, result: std::result::Result<T, KeyError>) -> Result<T> {
  result.map_err(|error| error.throw(ctx))
}

fn sign_result<T>(ctx: &Ctx<'_>, result: std::result::Result<T, SignError>) -> Result<T> {
  result.map_err(|error| match error {
    SignError::Operation => coded(
      ctx,
      "Error",
      "ERR_CRYPTO_UNSUPPORTED_OPERATION",
      "Unsupported crypto operation",
    ),
    SignError::Unsupported(message) => coded(ctx, "Error", "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM", message),
    SignError::Failed(message) => coded(ctx, "Error", "ERR_CRYPTO_OPERATION_FAILED", &message),
  })
}

fn hash(ctx: &Ctx<'_>, name: &str) -> Result<HashAlgorithm> {
  HashAlgorithm::try_from(name).map_err(|_| coded(ctx, "TypeError", "ERR_CRYPTO_INVALID_DIGEST", "Invalid digest"))
}

fn bytes<'js>(ctx: &Ctx<'js>, value: &ObjectBytes<'js>) -> Result<Vec<u8>> {
  Ok(value.as_bytes(ctx)?.to_vec())
}

fn buffer<'js>(ctx: &Ctx<'js>, bytes: Vec<u8>) -> Result<Value<'js>> {
  Buffer(bytes).into_js(ctx)
}

fn options(padding: Opt<Option<i32>>, salt_length: Opt<Option<i32>>, dsa_der: Opt<bool>) -> Options {
  Options {
    padding: padding.0.flatten(),
    salt_length: salt_length.0.flatten(),
    dsa_der: dsa_der.0.unwrap_or(true),
  }
}

/// The functions `crypto.js` builds the classes over.
fn native<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  let native = Object::new(ctx.clone())?;

  native.set(
    "secret",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, key: ObjectBytes<'js>| {
      handle(&ctx, Material::Secret(bytes(&ctx, &key)?))
    })?,
  )?;

  native.set(
    "parse",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>, data: Value<'js>, format: String, type_name: Option<String>, private: bool| {
        let parsed = match format.as_str() {
          "jwk" => {
            let jwk = data
              .as_object()
              .ok_or_else(|| KeyError::InvalidJwk.throw(&ctx))?;
            keys::from_jwk(jwk, private)
          },
          "der" => {
            let der = bytes(&ctx, &ObjectBytes::from(&ctx, &data)?)?;
            keys::from_der(&der, type_name.as_deref().unwrap_or_default(), private)
          },
          _ => {
            let text = match data.as_string() {
              Some(text) => text.to_string()?,
              None => String::from_utf8_lossy(&bytes(&ctx, &ObjectBytes::from(&ctx, &data)?)?).into_owned(),
            };
            keys::from_pem(&text)
          },
        };
        handle(&ctx, key_result(&ctx, parsed)?)
      },
    )?,
  )?;

  native.set(
    "publicOf",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, key: Class<'js, KeyHandle>| {
      handle(&ctx, material(&key).public())
    })?,
  )?;

  native.set(
    "describe",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, key: Class<'js, KeyHandle>| {
      let material = material(&key);
      let out = rquickjs::Array::new(ctx.clone())?;
      out.set(0, material.kind())?;
      out.set(1, material.asymmetric_type())?;
      out.set(
        2,
        match material.as_ref() {
          Material::Secret(bytes) => Some(bytes.len()),
          _ => None,
        },
      )?;
      Ok::<_, rquickjs::Error>(out)
    })?,
  )?;

  native.set(
    "details",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, key: Class<'js, KeyHandle>| {
      let material = material(&key);
      let details = Object::new(ctx.clone())?;
      match material.as_ref() {
        Material::Rsa { .. } => {
          details.set("modulusLength", material.modulus_bits())?;
          let exponent = material
            .rsa_numbers()
            .map(|(_, e)| e.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
            .unwrap_or_default();
          details.set("publicExponent", BigInt::from_u64(ctx.clone(), exponent)?)?;
        },
        Material::Ec { curve, .. } => details.set("namedCurve", keys::curve_node_name(*curve))?,
        _ => {},
      }
      Ok::<_, rquickjs::Error>(details)
    })?,
  )?;

  native.set(
    "exportDer",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>, key: Class<'js, KeyHandle>, type_name: String, pem: bool| {
        let material = material(&key);
        match material.encoded(&type_name, material.is_private()) {
          Some((der, label)) if pem => keys::pem(&der, label).into_js(&ctx),
          Some((der, _)) => buffer(&ctx, der),
          None => Err(coded(
            &ctx,
            "Error",
            "ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS",
            &format!("The selected key encoding {type_name} can only be used for a different key type."),
          )),
        }
      },
    )?,
  )?;

  native.set(
    "exportJwk",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, key: Class<'js, KeyHandle>| {
      keys::to_jwk(&ctx, &material(&key))
    })?,
  )?;

  native.set(
    "secretBytes",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, key: Class<'js, KeyHandle>| {
      match material(&key).as_ref() {
        Material::Secret(bytes) => buffer(&ctx, bytes.clone()),
        _ => Ok(Value::new_undefined(ctx.clone())),
      }
    })?,
  )?;

  native.set(
    "equals",
    Function::new(ctx.clone(), |a: Class<'js, KeyHandle>, b: Class<'js, KeyHandle>| {
      material(&a).same_as(&material(&b))
    })?,
  )?;

  native.set(
    "signDigest",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>,
       key: Class<'js, KeyHandle>,
       digest_name: String,
       digest: ObjectBytes<'js>,
       padding: Opt<Option<i32>>,
       salt_length: Opt<Option<i32>>,
       dsa_der: Opt<bool>| {
        let algorithm = hash(&ctx, &digest_name)?;
        let digest = bytes(&ctx, &digest)?;
        let options = options(padding, salt_length, dsa_der);
        let signature = sign_result(&ctx, sig::sign_digest(&material(&key), algorithm, &digest, &options))?;
        buffer(&ctx, signature)
      },
    )?,
  )?;

  native.set(
    "verifyDigest",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>,
       key: Class<'js, KeyHandle>,
       digest_name: String,
       digest: ObjectBytes<'js>,
       signature: ObjectBytes<'js>,
       rest: Rest<Value<'js>>| {
        let algorithm = hash(&ctx, &digest_name)?;
        let digest = bytes(&ctx, &digest)?;
        let signature = bytes(&ctx, &signature)?;
        let int = |index: usize| rest.0.get(index).and_then(Value::as_int);
        let options = Options {
          padding: int(0),
          salt_length: int(1),
          dsa_der: rest.0.get(2).and_then(Value::as_bool).unwrap_or(true),
        };
        sign_result(
          &ctx,
          sig::verify_digest(&material(&key), algorithm, &digest, &signature, &options),
        )
      },
    )?,
  )?;

  native.set(
    "signMessage",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>, key: Class<'js, KeyHandle>, data: ObjectBytes<'js>| {
        let data = bytes(&ctx, &data)?;
        let signature = sign_result(&ctx, sig::sign_message(&material(&key), &data))?;
        buffer(&ctx, signature)
      },
    )?,
  )?;

  native.set(
    "verifyMessage",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>, key: Class<'js, KeyHandle>, data: ObjectBytes<'js>, signature: ObjectBytes<'js>| {
        let (data, signature) = (bytes(&ctx, &data)?, bytes(&ctx, &signature)?);
        sign_result(&ctx, sig::verify_message(&material(&key), &data, &signature))
      },
    )?,
  )?;

  native.set(
    "generate",
    Function::new(ctx.clone(), |ctx: Ctx<'js>, kind: String, parameter: Value<'js>| {
      let unsupported = |message: &str| coded(&ctx, "Error", "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM", message);
      let private = match kind.as_str() {
        "rsa" => {
          let bits = parameter.as_number().unwrap_or_default();
          let bits = if bits.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&bits) {
            bits as u32
          } else {
            0
          };
          let (private, _) = CRYPTO_PROVIDER.generate_rsa_key(bits, &[1, 0, 1]).map_err(|_| {
            unsupported("RSA keys can be generated at 2048, 3072, 4096 or 8192 bits with exponent 65537 only")
          })?;
          key_result(&ctx, keys::from_der(&private, "pkcs1", true))?
        },
        "ec" => {
          let curve = parameter
            .as_string()
            .and_then(|s| s.to_string().ok())
            .and_then(|name| keys::curve_from_name(&name))
            .ok_or_else(|| unsupported("this curve is not supported"))?;
          let (private, _) = CRYPTO_PROVIDER
            .generate_ec_key(curve)
            .map_err(|e| coded(&ctx, "Error", "ERR_CRYPTO_OPERATION_FAILED", &e.to_string()))?;
          key_result(&ctx, keys::from_der(&private, "pkcs8", true))?
        },
        "ed25519" => {
          let (private, _) = CRYPTO_PROVIDER
            .generate_ed25519_key()
            .map_err(|e| coded(&ctx, "Error", "ERR_CRYPTO_OPERATION_FAILED", &e.to_string()))?;
          key_result(&ctx, keys::from_der(&private, "pkcs8", true))?
        },
        _ => return Err(unsupported("this key type is not supported")),
      };
      let public = private.public();
      let pair = rquickjs::Array::new(ctx.clone())?;
      pair.set(0, handle(&ctx, public)?)?;
      pair.set(1, handle(&ctx, private)?)?;
      Ok::<_, rquickjs::Error>(pair)
    })?,
  )?;

  native.set(
    "timingSafeEqual",
    Function::new(
      ctx.clone(),
      |ctx: Ctx<'js>, a: ObjectBytes<'js>, b: ObjectBytes<'js>| -> Result<bool> {
        let (a, b) = (a.as_bytes(&ctx)?, b.as_bytes(&ctx)?);
        Ok(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0)
      },
    )?,
  )?;

  native.set(
    "isHandle",
    Function::new(ctx.clone(), |value: Value<'js>| Class::<KeyHandle>::from_value(&value).is_ok())?,
  )?;

  Ok(native)
}

#[derive(JsLifetime)]
struct Instance<'js>(Object<'js>);

/// The members `crypto.js` answers, once a realm has used one.
#[derive(JsLifetime)]
struct Loaded<'js>(Object<'js>);

/// The vendored functions `crypto.js` builds on, kept before the
/// namespace's own `createHmac` replaces one of them.
#[derive(JsLifetime)]
struct Vendored<'js>(Object<'js>);

/// The functions the namespace forwards to `crypto.js`.
const FORWARDED: &[(&str, usize)] = &[
  ("createSecretKey", 2),
  ("createPublicKey", 1),
  ("createPrivateKey", 1),
  ("generateKeyPair", 3),
  ("generateKeyPairSync", 2),
  ("createSign", 2),
  ("createVerify", 2),
  ("sign", 4),
  ("verify", 5),
  ("timingSafeEqual", 2),
];

/// The classes, which a script may test against before it has made a
/// key: `x instanceof KeyObject` is how jsonwebtoken tells a key from a
/// string.
const CLASSES: &[(&str, usize)] = &[("KeyObject", 2), ("Sign", 2), ("Verify", 2)];

const CONSTANTS: &[(&str, i32)] = &[
  ("RSA_PKCS1_PADDING", 1),
  ("RSA_SSLV23_PADDING", 2),
  ("RSA_NO_PADDING", 3),
  ("RSA_PKCS1_OAEP_PADDING", 4),
  ("RSA_X931_PADDING", 5),
  ("RSA_PKCS1_PSS_PADDING", 6),
  ("RSA_PSS_SALTLEN_DIGEST", -1),
  ("RSA_PSS_SALTLEN_MAX_SIGN", -2),
  ("RSA_PSS_SALTLEN_AUTO", -2),
  ("POINT_CONVERSION_COMPRESSED", 2),
  ("POINT_CONVERSION_UNCOMPRESSED", 4),
  ("POINT_CONVERSION_HYBRID", 6),
];

fn loaded<'js>(ctx: &Ctx<'js>) -> Option<Object<'js>> {
  ctx.userdata::<Loaded<'js>>().map(|loaded| loaded.0.clone())
}

/// `crypto.js`'s members, evaluating it on first use.
fn implementation<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  if let Some(members) = loaded(ctx) {
    return Ok(members);
  }
  let vendored = ctx
    .userdata::<Vendored<'js>>()
    .map(|vendored| vendored.0.clone())
    .ok_or(rquickjs::Error::Unknown)?;
  let load: Function<'js> = CRYPTO_JS.evaluate(ctx)?.get()?;
  let members: Object<'js> = load.call((native(ctx)?, vendored))?;
  let _ = ctx.store_userdata(Loaded(members.clone()));
  Ok(members)
}

fn forward<'js>(ctx: &Ctx<'js>, target: &Function<'js>, this: Value<'js>, args: Vec<Value<'js>>) -> Result<Value<'js>> {
  let mut call = Args::new(ctx.clone(), args.len());
  call.this(this)?;
  call.push_args(args)?;
  target.call_arg(call)
}

/// Whether `value` has `class.prototype` on its chain.
fn inherits<'js>(value: &Value<'js>, class: &Object<'js>) -> Result<bool> {
  let prototype: Object<'js> = class.get("prototype")?;
  let mut current = value.as_object().and_then(Object::get_prototype);
  while let Some(object) = current {
    if object == prototype {
      return Ok(true);
    }
    current = object.get_prototype();
  }
  Ok(false)
}

/// The real class a stand-in names.
fn real_class<'js>(ctx: &Ctx<'js>, members: &Object<'js>, stand_in: &Function<'js>) -> Result<Object<'js>> {
  let name: String = stand_in.get("name")?;
  members
    .get::<_, Option<Object<'js>>>(name.as_str())?
    .ok_or_else(|| rquickjs::Exception::throw_type(ctx, "not a node:crypto class"))
}

/// A stand-in for one of `crypto.js`'s classes: constructing it builds
/// the real class's instance, `instanceof` answers for the real class,
/// and `prototype` is the real class's. The last two are shared by the
/// three stand-ins and find their class by the stand-in's name.
fn class_stand_in<'js>(
  ctx: &Ctx<'js>,
  name: &'static str,
  length: usize,
  has_instance: &Function<'js>,
  prototype: &Function<'js>,
  define_property: &Function<'js>,
) -> Result<Function<'js>> {
  let stand_in = Function::new(ctx.clone(), move |ctx: Ctx<'js>, args: Rest<Value<'js>>| {
    let class: Constructor<'js> = implementation(&ctx)?.get(name)?;
    let mut call = Args::new(ctx.clone(), args.0.len());
    call.push_args(args.0)?;
    class.construct_args::<Value<'js>>(call)
  })?
  .with_name(name)?
  .with_length(length)?
  .with_constructor(true);
  // Defined, not assigned: `Function.prototype[Symbol.hasInstance]` is
  // read-only, and an assignment would only shadow it in sloppy mode.
  stand_in.prop(PredefinedAtom::SymbolHasInstance, Property::from(has_instance.clone()))?;
  let descriptor = Object::new(ctx.clone())?;
  descriptor.set("get", prototype.clone())?;
  descriptor.set("configurable", true)?;
  define_property.call::<_, Value<'js>>((stand_in.clone(), "prototype", descriptor))?;
  Ok(stand_in)
}

fn stand_in_helpers<'js>(ctx: &Ctx<'js>) -> Result<(Function<'js>, Function<'js>)> {
  let has_instance = Function::new(
    ctx.clone(),
    |ctx: Ctx<'js>, this: This<Function<'js>>, value: Value<'js>| -> Result<bool> {
      match loaded(&ctx) {
        // No instance exists before `crypto.js` has run.
        None => Ok(false),
        Some(members) => inherits(&value, &real_class(&ctx, &members, &this.0)?),
      }
    },
  )?
  .with_name("[Symbol.hasInstance]")?;
  let prototype = Function::new(
    ctx.clone(),
    |ctx: Ctx<'js>, this: This<Function<'js>>| -> Result<Value<'js>> {
      let members = implementation(&ctx)?;
      real_class(&ctx, &members, &this.0)?.get("prototype")
    },
  )?;
  Ok((has_instance, prototype))
}

/// `require('crypto')`.
pub(crate) fn namespace<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
  if let Some(instance) = ctx.userdata::<Instance<'js>>() {
    return Ok(instance.0.clone());
  }
  let (module, _promise) = Module::evaluate_def::<crate::crypto::CryptoModule, _>(ctx.clone(), "ferrijs:crypto-base")?;
  let namespace: Object<'js> = module.namespace()?.get("default")?;

  let vendored = Object::new(ctx.clone())?;
  let create_hmac: Function<'js> = namespace.get("createHmac")?;
  vendored.set("createHash", namespace.get::<_, Value<'js>>("createHash")?)?;
  vendored.set("createHmac", create_hmac.clone())?;
  let _ = ctx.store_userdata(Vendored(vendored));

  for (name, length) in FORWARDED {
    let name = *name;
    let forwarder = Function::new(
      ctx.clone(),
      move |ctx: Ctx<'js>, this: This<Value<'js>>, args: Rest<Value<'js>>| {
        let target: Function<'js> = implementation(&ctx)?.get(name)?;
        forward(&ctx, &target, this.0, args.0)
      },
    )?
    .with_name(name)?
    .with_length(*length)?;
    namespace.set(name, forwarder)?;
  }
  let (has_instance, prototype) = stand_in_helpers(ctx)?;
  let define_property: Function<'js> = ctx.globals().get::<_, Object<'js>>("Object")?.get("defineProperty")?;
  for (name, length) in CLASSES {
    let stand_in = class_stand_in(ctx, name, *length, &has_instance, &prototype, &define_property)?;
    namespace.set(*name, stand_in)?;
  }
  // A key object exists only once `crypto.js` has run, so until then the
  // vendored function answers every call.
  namespace.set(
    "createHmac",
    Function::new(
      ctx.clone(),
      move |ctx: Ctx<'js>, this: This<Value<'js>>, args: Rest<Value<'js>>| {
        let target = match loaded(&ctx) {
          Some(members) => members.get("createHmac")?,
          None => create_hmac.clone(),
        };
        forward(&ctx, &target, this.0, args.0)
      },
    )?
    .with_name("createHmac")?
    .with_length(3)?,
  )?;
  let constants = Object::new(ctx.clone())?;
  for (name, value) in CONSTANTS {
    constants.set(*name, *value)?;
  }
  namespace.set("constants", constants)?;
  let webcrypto: Object<'js> = ctx.globals().get("crypto")?;
  namespace.set("subtle", webcrypto.get::<_, Value<'js>>("subtle")?)?;

  let _ = ctx.store_userdata(Instance(namespace.clone()));
  Ok(namespace)
}

pub struct CryptoModule;

impl ModuleDef for CryptoModule {
  fn declare(declare: &Declarations<'_>) -> Result<()> {
    <crate::crypto::CryptoModule as ModuleDef>::declare(declare)?;
    for name in OWN_EXPORTS {
      declare.declare(*name)?;
    }
    Ok(())
  }

  fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> Result<()> {
    let namespace = namespace(ctx)?;
    for key in namespace.keys::<String>() {
      let key = key?;
      exports.export(key.as_str(), namespace.get::<_, Value<'js>>(key.as_str())?)?;
    }
    exports.export("default", namespace)?;
    Ok(())
  }
}
