//! Key material behind a `KeyObject`, and its PEM, DER and JWK forms.
//!
//! The material is held in the shapes the WebCrypto provider signs with:
//! PKCS#1 for RSA, the scalar and point for EC, the seed and public key
//! for Ed25519. Every encoding Node exports is rebuilt from those, so a
//! key round-trips to the bytes Node would print whatever form it was
//! read from.

use rquickjs::{Ctx, Object, Result, Value};

use super::der;
use crate::crypto::CRYPTO_PROVIDER;
use crate::crypto::provider::{CryptoError, CryptoProvider, EcJwkImport, OkpJwkImport, RsaJwkImport};
use crate::crypto::subtle::EllipticCurve;
use crate::encoding::{bytes_from_b64, bytes_to_b64_string, bytes_to_b64_url_safe_string};
use crate::node::coded;

const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const ED448: &[u8] = &[0x2b, 0x65, 0x71];
const X448: &[u8] = &[0x2b, 0x65, 0x6f];
const SECP256K1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

pub(super) enum Material {
  Secret(Vec<u8>),
  Rsa {
    /// `RSAPublicKey`.
    public: Vec<u8>,
    /// `RSAPrivateKey`.
    private: Option<Vec<u8>>,
  },
  Ec {
    curve: EllipticCurve,
    /// The uncompressed point.
    point: Vec<u8>,
    /// The private scalar, at the curve's full width.
    scalar: Option<Vec<u8>>,
  },
  Ed25519 {
    public: Vec<u8>,
    seed: Option<Vec<u8>>,
  },
}

/// Why a key could not be read or used, thrown with the code Node's
/// OpenSSL layer gives the same failure.
pub(super) enum KeyError {
  /// Not a key this runtime can read: a format or algorithm it does not
  /// decode, or bytes that are not a key at all.
  Unsupported(String),
  /// A key whose structure is wrong.
  Malformed(String),
  InvalidJwk,
}

impl KeyError {
  pub(super) fn throw(self, ctx: &Ctx<'_>) -> rquickjs::Error {
    match self {
      Self::Unsupported(message) => coded(ctx, "Error", "ERR_OSSL_UNSUPPORTED", &message),
      Self::Malformed(message) => coded(ctx, "Error", "ERR_OSSL_ASN1_WRONG_TAG", &message),
      Self::InvalidJwk => coded(ctx, "TypeError", "ERR_CRYPTO_INVALID_JWK", "Invalid JWK data"),
    }
  }
}

type KeyResult<T> = std::result::Result<T, KeyError>;

fn malformed(what: &str) -> KeyError {
  KeyError::Malformed(format!("{what} is not a valid DER encoding"))
}

fn from_provider(error: CryptoError) -> KeyError {
  KeyError::Malformed(error.to_string())
}

pub(super) fn curve_width(curve: EllipticCurve) -> usize {
  match curve {
    EllipticCurve::P256 => 32,
    EllipticCurve::P384 => 48,
    EllipticCurve::P521 => 66,
  }
}

fn curve_oid(curve: EllipticCurve) -> &'static [u8] {
  match curve {
    EllipticCurve::P256 => P256,
    EllipticCurve::P384 => P384,
    EllipticCurve::P521 => P521,
  }
}

fn curve_from_oid(oid: &[u8]) -> KeyResult<EllipticCurve> {
  match oid {
    P256 => Ok(EllipticCurve::P256),
    P384 => Ok(EllipticCurve::P384),
    P521 => Ok(EllipticCurve::P521),
    SECP256K1 => Err(KeyError::Unsupported("the secp256k1 curve is not supported".into())),
    _ => Err(KeyError::Unsupported("unsupported elliptic curve".into())),
  }
}

/// Node's (OpenSSL's) name for a curve, as `asymmetricKeyDetails` gives it.
pub(super) fn curve_node_name(curve: EllipticCurve) -> &'static str {
  match curve {
    EllipticCurve::P256 => "prime256v1",
    EllipticCurve::P384 => "secp384r1",
    EllipticCurve::P521 => "secp521r1",
  }
}

/// A curve by any name Node accepts for one.
pub(super) fn curve_from_name(name: &str) -> Option<EllipticCurve> {
  match name {
    "P-256" | "prime256v1" | "secp256r1" => Some(EllipticCurve::P256),
    "P-384" | "secp384r1" => Some(EllipticCurve::P384),
    "P-521" | "secp521r1" => Some(EllipticCurve::P521),
    _ => None,
  }
}

fn unsupported_algorithm(oid: &[u8]) -> KeyError {
  let name = match oid {
    RSASSA_PSS => "RSA-PSS keys are",
    X25519 => "X25519 keys are",
    ED448 => "Ed448 keys are",
    X448 => "X448 keys are",
    _ => "this key algorithm is",
  };
  KeyError::Unsupported(format!("{name} not supported"))
}

impl Material {
  pub(super) fn is_private(&self) -> bool {
    match self {
      Self::Secret(_) => false,
      Self::Rsa { private, .. } => private.is_some(),
      Self::Ec { scalar, .. } => scalar.is_some(),
      Self::Ed25519 { seed, .. } => seed.is_some(),
    }
  }

  pub(super) fn kind(&self) -> &'static str {
    match self {
      Self::Secret(_) => "secret",
      _ if self.is_private() => "private",
      _ => "public",
    }
  }

  pub(super) fn asymmetric_type(&self) -> Option<&'static str> {
    match self {
      Self::Secret(_) => None,
      Self::Rsa { .. } => Some("rsa"),
      Self::Ec { .. } => Some("ec"),
      Self::Ed25519 { .. } => Some("ed25519"),
    }
  }

  /// The public half of an asymmetric key.
  pub(super) fn public(&self) -> Self {
    match self {
      Self::Secret(bytes) => Self::Secret(bytes.clone()),
      Self::Rsa { public, .. } => Self::Rsa {
        public: public.clone(),
        private: None,
      },
      Self::Ec { curve, point, .. } => Self::Ec {
        curve: *curve,
        point: point.clone(),
        scalar: None,
      },
      Self::Ed25519 { public, .. } => Self::Ed25519 {
        public: public.clone(),
        seed: None,
      },
    }
  }

  /// `RSAPublicKey`'s modulus and exponent.
  pub(super) fn rsa_numbers(&self) -> Option<(&[u8], &[u8])> {
    let Self::Rsa { public, .. } = self else {
      return None;
    };
    let (content, _) = der::expect(public, der::SEQUENCE)?;
    match der::elements(content)?.as_slice() {
      [(der::INTEGER, n), (der::INTEGER, e)] => Some((der::magnitude(n), der::magnitude(e))),
      _ => None,
    }
  }

  pub(super) fn modulus_bits(&self) -> u32 {
    let Some((n, _)) = self.rsa_numbers() else {
      return 0;
    };
    let Some(first) = n.first() else {
      return 0;
    };
    let whole = u32::try_from(n.len()).unwrap_or(u32::MAX).saturating_mul(8);
    whole - first.leading_zeros()
  }

  pub(super) fn spki(&self) -> Vec<u8> {
    match self {
      Self::Secret(_) => Vec::new(),
      Self::Rsa { public, .. } => der::sequence(&[
        &der::sequence(&[&der::tlv(der::OID, RSA_ENCRYPTION), &der::tlv(der::NULL, &[])]),
        &der::bits(public),
      ]),
      Self::Ec { curve, point, .. } => der::sequence(&[
        &der::sequence(&[&der::tlv(der::OID, EC_PUBLIC_KEY), &der::tlv(der::OID, curve_oid(*curve))]),
        &der::bits(point),
      ]),
      Self::Ed25519 { public, .. } => der::sequence(&[&der::sequence(&[&der::tlv(der::OID, ED25519)]), &der::bits(public)]),
    }
  }

  /// PKCS#8, as OpenSSL writes it. `None` for a key with no private half.
  pub(super) fn pkcs8(&self) -> Option<Vec<u8>> {
    let version = der::tlv(der::INTEGER, &[0]);
    Some(match self {
      Self::Secret(_) => return None,
      Self::Rsa { private, .. } => der::sequence(&[
        &version,
        &der::sequence(&[&der::tlv(der::OID, RSA_ENCRYPTION), &der::tlv(der::NULL, &[])]),
        &der::tlv(der::OCTET_STRING, private.as_ref()?),
      ]),
      Self::Ec { curve, point, scalar } => {
        let inner = der::sequence(&[
          &der::tlv(der::INTEGER, &[1]),
          &der::tlv(der::OCTET_STRING, scalar.as_ref()?),
          &der::tlv(der::CONTEXT_1, &der::bits(point)),
        ]);
        der::sequence(&[
          &version,
          &der::sequence(&[&der::tlv(der::OID, EC_PUBLIC_KEY), &der::tlv(der::OID, curve_oid(*curve))]),
          &der::tlv(der::OCTET_STRING, &inner),
        ])
      },
      Self::Ed25519 { seed, .. } => der::sequence(&[
        &version,
        &der::sequence(&[&der::tlv(der::OID, ED25519)]),
        &der::tlv(der::OCTET_STRING, &der::tlv(der::OCTET_STRING, seed.as_ref()?)),
      ]),
    })
  }

  /// SEC1 `ECPrivateKey`, with its curve and public point.
  pub(super) fn sec1(&self) -> Option<Vec<u8>> {
    let Self::Ec { curve, point, scalar } = self else {
      return None;
    };
    Some(der::sequence(&[
      &der::tlv(der::INTEGER, &[1]),
      &der::tlv(der::OCTET_STRING, scalar.as_ref()?),
      &der::tlv(der::CONTEXT_0, &der::tlv(der::OID, curve_oid(*curve))),
      &der::tlv(der::CONTEXT_1, &der::bits(point)),
    ]))
  }

  /// PKCS#1, public or private as the key is.
  pub(super) fn pkcs1(&self, private: bool) -> Option<&[u8]> {
    match self {
      Self::Rsa { private: Some(key), .. } if private => Some(key),
      Self::Rsa { public, .. } if !private => Some(public),
      _ => None,
    }
  }

  /// The DER of `type_name` (`spki`, `pkcs1`, `pkcs8`, `sec1`) and its
  /// PEM label, or `None` when the key has no such form.
  pub(super) fn encoded(&self, type_name: &str, private: bool) -> Option<(Vec<u8>, &'static str)> {
    match (type_name, private) {
      ("spki", false) => Some((self.spki(), "PUBLIC KEY")),
      ("pkcs1", false) => Some((self.pkcs1(false)?.to_vec(), "RSA PUBLIC KEY")),
      ("pkcs1", true) => Some((self.pkcs1(true)?.to_vec(), "RSA PRIVATE KEY")),
      ("pkcs8", true) => Some((self.pkcs8()?, "PRIVATE KEY")),
      ("sec1", true) => Some((self.sec1()?, "EC PRIVATE KEY")),
      _ => None,
    }
  }

  /// The same key, compared the way Node's `equals` does: type and every
  /// byte of the material.
  pub(super) fn same_as(&self, other: &Self) -> bool {
    match (self, other) {
      (Self::Secret(a), Self::Secret(b)) => a == b,
      _ if self.kind() != other.kind() || self.asymmetric_type() != other.asymmetric_type() => false,
      _ if self.is_private() => self.pkcs8() == other.pkcs8(),
      _ => self.spki() == other.spki(),
    }
  }
}

pub(super) fn pem(der: &[u8], label: &str) -> String {
  let body = bytes_to_b64_string(der);
  let mut out = String::with_capacity(body.len() + body.len() / 64 + label.len() * 2 + 40);
  out.push_str("-----BEGIN ");
  out.push_str(label);
  out.push_str("-----\n");
  for line in body.as_bytes().chunks(64) {
    out.push_str(std::str::from_utf8(line).unwrap_or_default());
    out.push('\n');
  }
  out.push_str("-----END ");
  out.push_str(label);
  out.push_str("-----\n");
  out
}

/// The first PEM block in `text`: its label and decoded body.
fn unpem(text: &str) -> KeyResult<(String, Vec<u8>)> {
  let unsupported = || KeyError::Unsupported("error:1E08010C:DECODER routines::unsupported".into());
  let start = text.find("-----BEGIN ").ok_or_else(unsupported)?;
  let rest = &text[start + 11..];
  let label_end = rest.find("-----").ok_or_else(unsupported)?;
  let label = &rest[..label_end];
  let body = &rest[label_end + 5..];
  let end_marker = format!("-----END {label}-----");
  let end = body.find(&end_marker).ok_or_else(unsupported)?;
  let body = &body[..end];
  if label.contains("ENCRYPTED") || body.contains("Proc-Type:") {
    return Err(KeyError::Unsupported("encrypted private keys are not supported".into()));
  }
  let compact: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
  let bytes = bytes_from_b64(compact).map_err(|_| unsupported())?;
  Ok((label.to_string(), bytes))
}

/// `SEQUENCE { OID algorithm, parameters? }`: the OID and the raw
/// parameter element.
fn algorithm(content: &[u8]) -> KeyResult<(&[u8], Option<der::Element<'_>>)> {
  let parts = der::elements(content).ok_or_else(|| malformed("an algorithm identifier"))?;
  match parts.as_slice() {
    [(der::OID, oid)] => Ok((oid, None)),
    [(der::OID, oid), parameter] => Ok((oid, Some(*parameter))),
    _ => Err(malformed("an algorithm identifier")),
  }
}

fn rsa_public(public: Vec<u8>) -> KeyResult<Material> {
  CRYPTO_PROVIDER.import_rsa_public_key_pkcs1(&public).map_err(from_provider)?;
  Ok(Material::Rsa { public, private: None })
}

fn rsa_private(private: &[u8]) -> KeyResult<Material> {
  let imported = CRYPTO_PROVIDER
    .import_rsa_private_key_pkcs1(private)
    .map_err(from_provider)?;
  let (content, _) = der::expect(&imported.key_data, der::SEQUENCE).ok_or_else(|| malformed("an RSA private key"))?;
  let parts = der::elements(content).ok_or_else(|| malformed("an RSA private key"))?;
  let [_, (der::INTEGER, n), (der::INTEGER, e), ..] = parts.as_slice() else {
    return Err(malformed("an RSA private key"));
  };
  let public = der::sequence(&[&der::unsigned(n), &der::unsigned(e)]);
  Ok(Material::Rsa {
    public,
    private: Some(imported.key_data),
  })
}

fn ec_public(curve: EllipticCurve, point: &[u8]) -> KeyResult<Material> {
  let imported = CRYPTO_PROVIDER
    .import_ec_public_key_sec1(point, curve)
    .map_err(from_provider)?;
  Ok(Material::Ec {
    curve,
    point: imported.key_data,
    scalar: None,
  })
}

fn ec_private(curve: EllipticCurve, scalar: &[u8], point: Option<&[u8]>) -> KeyResult<Material> {
  let scalar = der::padded(scalar, curve_width(curve)).ok_or_else(|| malformed("an EC private key"))?;
  let point = match point {
    Some(point) => {
      CRYPTO_PROVIDER
        .import_ec_public_key_sec1(point, curve)
        .map_err(from_provider)?
        .key_data
    },
    None => {
      let pkcs8 = CRYPTO_PROVIDER
        .import_ec_private_key_sec1(&scalar, curve)
        .map_err(from_provider)?;
      CRYPTO_PROVIDER
        .export_ec_public_key_sec1(&pkcs8.key_data, curve, true)
        .map_err(from_provider)?
    },
  };
  Ok(Material::Ec {
    curve,
    point,
    scalar: Some(scalar),
  })
}

pub(super) fn ed25519_private(seed: &[u8]) -> KeyResult<Material> {
  if seed.len() != 32 {
    return Err(malformed("an Ed25519 private key"));
  }
  let public = CRYPTO_PROVIDER.ed25519_public_key(seed).map_err(from_provider)?;
  Ok(Material::Ed25519 {
    public,
    seed: Some(seed.to_vec()),
  })
}

fn ed25519_public(public: &[u8]) -> KeyResult<Material> {
  if public.len() != 32 {
    return Err(malformed("an Ed25519 public key"));
  }
  Ok(Material::Ed25519 {
    public: public.to_vec(),
    seed: None,
  })
}

/// SEC1 `ECPrivateKey`; `curve` is the one the wrapper named, if any.
fn sec1(content: &[u8], curve: Option<EllipticCurve>) -> KeyResult<Material> {
  let (content, _) = der::expect(content, der::SEQUENCE).ok_or_else(|| malformed("an EC private key"))?;
  let parts = der::elements(content).ok_or_else(|| malformed("an EC private key"))?;
  let [(der::INTEGER, [1]), (der::OCTET_STRING, scalar), optional @ ..] = parts.as_slice() else {
    return Err(malformed("an EC private key"));
  };
  let mut named = curve;
  let mut point = None;
  for (tag, value) in optional {
    match *tag {
      der::CONTEXT_0 => {
        let (oid, _) = der::expect(value, der::OID).ok_or_else(|| malformed("an EC private key"))?;
        named = Some(curve_from_oid(oid)?);
      },
      der::CONTEXT_1 => {
        let (bits, _) = der::expect(value, der::BIT_STRING).ok_or_else(|| malformed("an EC private key"))?;
        point = Some(der::unbits(bits).ok_or_else(|| malformed("an EC private key"))?);
      },
      _ => {},
    }
  }
  let curve = named.ok_or_else(|| malformed("an EC private key"))?;
  ec_private(curve, scalar, point)
}

fn spki(input: &[u8]) -> KeyResult<Material> {
  let (content, _) = der::expect(input, der::SEQUENCE).ok_or_else(|| malformed("a public key"))?;
  let parts = der::elements(content).ok_or_else(|| malformed("a public key"))?;
  let [(der::SEQUENCE, identifier), (der::BIT_STRING, key)] = parts.as_slice() else {
    return Err(malformed("a public key"));
  };
  let key = der::unbits(key).ok_or_else(|| malformed("a public key"))?;
  match algorithm(identifier)? {
    (RSA_ENCRYPTION, _) => rsa_public(key.to_vec()),
    (EC_PUBLIC_KEY, Some((der::OID, curve))) => ec_public(curve_from_oid(curve)?, key),
    (ED25519, _) => ed25519_public(key),
    (oid, _) => Err(unsupported_algorithm(oid)),
  }
}

fn pkcs8(input: &[u8]) -> KeyResult<Material> {
  let (content, _) = der::expect(input, der::SEQUENCE).ok_or_else(|| malformed("a private key"))?;
  let parts = der::elements(content).ok_or_else(|| malformed("a private key"))?;
  let [(der::INTEGER, _), (der::SEQUENCE, identifier), (der::OCTET_STRING, key), ..] = parts.as_slice() else {
    return Err(malformed("a private key"));
  };
  match algorithm(identifier)? {
    (RSA_ENCRYPTION, _) => rsa_private(key),
    (EC_PUBLIC_KEY, Some((der::OID, curve))) => sec1(key, Some(curve_from_oid(curve)?)),
    (ED25519, _) => {
      let (seed, _) = der::expect(key, der::OCTET_STRING).ok_or_else(|| malformed("an Ed25519 private key"))?;
      ed25519_private(seed)
    },
    (oid, _) => Err(unsupported_algorithm(oid)),
  }
}

/// The public key of an X.509 certificate, which Node's
/// `createPublicKey` accepts in place of a key.
fn certificate(input: &[u8]) -> KeyResult<Material> {
  let (content, _) = der::expect(input, der::SEQUENCE).ok_or_else(|| malformed("a certificate"))?;
  let (tbs, _) = der::expect(content, der::SEQUENCE).ok_or_else(|| malformed("a certificate"))?;
  let parts = der::elements(tbs).ok_or_else(|| malformed("a certificate"))?;
  let fields = match parts.first() {
    Some((der::CONTEXT_0, _)) => &parts[1..],
    _ => &parts[..],
  };
  match fields.get(5) {
    Some((der::SEQUENCE, key)) => spki(&der::tlv(der::SEQUENCE, key)),
    _ => Err(malformed("a certificate")),
  }
}

fn looks_private(pkcs1: &[u8]) -> bool {
  der::expect(pkcs1, der::SEQUENCE)
    .and_then(|(content, _)| der::elements(content))
    .is_some_and(|parts| parts.len() >= 9 && parts[0] == (der::INTEGER, &[0][..]))
}

/// A key from DER of a named type.
pub(super) fn from_der(bytes: &[u8], type_name: &str, private: bool) -> KeyResult<Material> {
  match (type_name, private) {
    ("spki", false) => spki(bytes),
    // Node reads PKCS#1 for a public key as either half, telling them
    // apart by the private key's leading version number.
    ("pkcs1", false) if looks_private(bytes) => rsa_private(bytes),
    ("pkcs1", false) => rsa_public(bytes.to_vec()),
    ("pkcs1", true) => rsa_private(bytes),
    ("pkcs8", true) => pkcs8(bytes),
    ("sec1", true) => sec1(bytes, None),
    _ => Err(KeyError::Unsupported("unsupported key encoding".into())),
  }
}

/// A key from the first PEM block in `text`, private or public as the
/// block is.
pub(super) fn from_pem(text: &str) -> KeyResult<Material> {
  let (label, bytes) = unpem(text)?;
  match label.as_str() {
    "PUBLIC KEY" => spki(&bytes),
    "RSA PUBLIC KEY" => rsa_public(bytes),
    "CERTIFICATE" => certificate(&bytes),
    "PRIVATE KEY" => pkcs8(&bytes),
    "RSA PRIVATE KEY" => rsa_private(&bytes),
    "EC PRIVATE KEY" => sec1(&bytes, None),
    _ => Err(KeyError::Unsupported("error:1E08010C:DECODER routines::unsupported".into())),
  }
}

fn jwk_field(jwk: &Object<'_>, name: &str) -> KeyResult<Option<Vec<u8>>> {
  match jwk.get::<_, Value<'_>>(name) {
    Ok(value) if value.is_undefined() => Ok(None),
    Ok(value) => {
      let text = value.as_string().and_then(|s| s.to_string().ok()).ok_or(KeyError::InvalidJwk)?;
      bytes_from_b64(text.into_bytes()).map(Some).map_err(|_| KeyError::InvalidJwk)
    },
    Err(_) => Err(KeyError::InvalidJwk),
  }
}

fn jwk_string(jwk: &Object<'_>, name: &str) -> Option<String> {
  jwk.get::<_, Option<String>>(name).ok().flatten()
}

/// A key from a JWK. `private` asks for the private half; a public JWK
/// then fails.
pub(super) fn from_jwk(jwk: &Object<'_>, private: bool) -> KeyResult<Material> {
  let required = |name: &str| jwk_field(jwk, name)?.ok_or(KeyError::InvalidJwk);
  let material = match jwk_string(jwk, "kty").as_deref() {
    Some("RSA") => {
      let (n, e) = (required("n")?, required("e")?);
      let fields = ["d", "p", "q", "dp", "dq", "qi"].map(|name| jwk_field(jwk, name));
      let [d, p, q, dp, dq, qi] = fields;
      let (d, p, q, dp, dq, qi) = (d?, p?, q?, dp?, dq?, qi?);
      if d.is_some() && [&p, &q, &dp, &dq, &qi].iter().any(|v| v.is_none()) {
        return Err(KeyError::InvalidJwk);
      }
      let imported = CRYPTO_PROVIDER
        .import_rsa_jwk(RsaJwkImport {
          n: &n,
          e: &e,
          d: d.as_deref(),
          p: p.as_deref(),
          q: q.as_deref(),
          dp: dp.as_deref(),
          dq: dq.as_deref(),
          qi: qi.as_deref(),
        })
        .map_err(|_| KeyError::InvalidJwk)?;
      if imported.is_private {
        rsa_private(&imported.key_data)?
      } else {
        rsa_public(imported.key_data)?
      }
    },
    Some("EC") => {
      let curve = jwk_string(jwk, "crv")
        .as_deref()
        .and_then(curve_from_name)
        .ok_or(KeyError::InvalidJwk)?;
      let width = curve_width(curve);
      let x = der::padded(&required("x")?, width).ok_or(KeyError::InvalidJwk)?;
      let y = der::padded(&required("y")?, width).ok_or(KeyError::InvalidJwk)?;
      let d = jwk_field(jwk, "d")?;
      CRYPTO_PROVIDER
        .import_ec_jwk(EcJwkImport { x: &x, y: &y, d: d.as_deref() }, curve)
        .map_err(|_| KeyError::InvalidJwk)?;
      let point = [&[0x04][..], &x, &y].concat();
      match d {
        Some(d) => ec_private(curve, &d, Some(&point))?,
        None => ec_public(curve, &point)?,
      }
    },
    Some("OKP") => {
      if jwk_string(jwk, "crv").as_deref() != Some("Ed25519") {
        return Err(KeyError::Unsupported("only Ed25519 OKP keys are supported".into()));
      }
      let x = required("x")?;
      let d = jwk_field(jwk, "d")?;
      CRYPTO_PROVIDER
        .import_okp_jwk(OkpJwkImport { x: &x, d: d.as_deref() }, true)
        .map_err(|_| KeyError::InvalidJwk)?;
      match d {
        Some(seed) => {
          let key = ed25519_private(&seed)?;
          if matches!(&key, Material::Ed25519 { public, .. } if *public != x) {
            return Err(KeyError::InvalidJwk);
          }
          key
        },
        None => ed25519_public(&x)?,
      }
    },
    _ => return Err(KeyError::InvalidJwk),
  };
  if private && !material.is_private() {
    return Err(KeyError::InvalidJwk);
  }
  Ok(material)
}

/// The JWK Node exports, members in Node's order.
pub(super) fn to_jwk<'js>(ctx: &Ctx<'js>, material: &Material) -> Result<Object<'js>> {
  let jwk = Object::new(ctx.clone())?;
  let b64 = bytes_to_b64_url_safe_string;
  match material {
    Material::Secret(bytes) => {
      jwk.set("kty", "oct")?;
      jwk.set("k", b64(bytes))?;
    },
    Material::Rsa { private, .. } => {
      let (n, e) = material.rsa_numbers().unwrap_or_default();
      jwk.set("kty", "RSA")?;
      jwk.set("n", b64(n))?;
      jwk.set("e", b64(e))?;
      if let Some(private) = private {
        let parts = der::expect(private, der::SEQUENCE)
          .and_then(|(content, _)| der::elements(content))
          .unwrap_or_default();
        for (name, (_, value)) in ["d", "p", "q", "dp", "dq", "qi"].iter().zip(parts.iter().skip(3)) {
          jwk.set(*name, b64(der::magnitude(value)))?;
        }
      }
    },
    Material::Ec { curve, point, scalar } => {
      let width = curve_width(*curve);
      let coordinates = point.get(1..).unwrap_or_default();
      let (x, y) = coordinates.split_at(width.min(coordinates.len()));
      jwk.set("kty", "EC")?;
      jwk.set("x", b64(x))?;
      jwk.set("y", b64(y))?;
      jwk.set("crv", curve.as_str())?;
      if let Some(scalar) = scalar {
        jwk.set("d", b64(scalar))?;
      }
    },
    Material::Ed25519 { public, seed } => {
      jwk.set("crv", "Ed25519")?;
      if let Some(seed) = seed {
        jwk.set("d", b64(seed))?;
      }
      jwk.set("x", b64(public))?;
      jwk.set("kty", "OKP")?;
    },
  }
  Ok(jwk)
}
