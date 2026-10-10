//! `Sign`, `Verify`, `crypto.sign` and `crypto.verify` over the
//! WebCrypto provider.
//!
//! The provider is AWS-LC, which fixes an RSA-PSS salt at the digest
//! length. Node's default salt for signing is the longest the key allows,
//! and for verifying is whatever the signature carries, so a PSS
//! signature here is made and checked only at the digest length, and any
//! other salt asked for explicitly is refused rather than silently
//! replaced.

use super::der;
use super::keys::{Material, curve_width};
use crate::crypto::CRYPTO_PROVIDER;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::provider::{CryptoError, CryptoProvider};

pub(super) const RSA_PKCS1_PADDING: i32 = 1;
pub(super) const RSA_PKCS1_PSS_PADDING: i32 = 6;
pub(super) const RSA_PSS_SALTLEN_DIGEST: i32 = -1;
pub(super) const RSA_PSS_SALTLEN_MAX_SIGN: i32 = -2;

pub(super) enum SignError {
  /// What Node reports as `ERR_CRYPTO_UNSUPPORTED_OPERATION`.
  Operation,
  /// Something this provider cannot do that Node can.
  Unsupported(&'static str),
  Failed(String),
}

pub(super) struct Options {
  pub padding: Option<i32>,
  pub salt_length: Option<i32>,
  /// DER (`true`, Node's default) or IEEE-P1363 for (EC)DSA.
  pub dsa_der: bool,
}

fn digest_length(hash: HashAlgorithm) -> usize {
  match hash {
    HashAlgorithm::Md5 => 16,
    HashAlgorithm::Sha1 => 20,
    HashAlgorithm::Sha256 => 32,
    HashAlgorithm::Sha384 => 48,
    HashAlgorithm::Sha512 => 64,
  }
}

/// The PSS salt length to use, or why it cannot be honoured.
fn pss_salt(material: &Material, hash: HashAlgorithm, salt: Option<i32>, signing: bool) -> Result<usize, SignError> {
  let digest = digest_length(hash);
  let refused = Err(SignError::Unsupported(
    "RSA-PSS salt lengths other than the digest length are not supported",
  ));
  match salt {
    Some(RSA_PSS_SALTLEN_DIGEST) => Ok(digest),
    // Signing defaults to the longest salt the key allows, which equals the
    // digest length only for one modulus size per hash.
    None | Some(RSA_PSS_SALTLEN_MAX_SIGN) if signing => {
      let bits = usize::try_from(material.modulus_bits()).unwrap_or_default();
      let longest = bits.saturating_sub(1).div_ceil(8).saturating_sub(digest + 2);
      if longest == digest { Ok(digest) } else { refused }
    },
    // Verification defaults to recovering the salt from the signature.
    None | Some(RSA_PSS_SALTLEN_MAX_SIGN) => Ok(digest),
    Some(length) if usize::try_from(length) == Ok(digest) => Ok(digest),
    Some(_) => refused,
  }
}

fn fail(error: CryptoError) -> SignError {
  match error {
    // AWS-LC pairs each ECDSA curve with one hash and signs RSA with SHA-2
    // only; Node's OpenSSL takes any pairing.
    CryptoError::UnsupportedAlgorithm => SignError::Unsupported("this digest is not supported with this key"),
    error => SignError::Failed(error.to_string()),
  }
}

/// An ECDSA signature from fixed-width `r || s` to DER.
fn ecdsa_to_der(fixed: &[u8]) -> Vec<u8> {
  let (r, s) = fixed.split_at(fixed.len() / 2);
  der::sequence(&[&der::unsigned(r), &der::unsigned(s)])
}

/// An ECDSA signature from DER to fixed-width `r || s`; `None` for one
/// that is not a well-formed signature on this curve.
fn ecdsa_from_der(signature: &[u8], width: usize) -> Option<Vec<u8>> {
  let (content, rest) = der::expect(signature, der::SEQUENCE)?;
  if !rest.is_empty() {
    return None;
  }
  match der::elements(content)?.as_slice() {
    [(der::INTEGER, r), (der::INTEGER, s)] => Some([der::padded(r, width)?, der::padded(s, width)?].concat()),
    _ => None,
  }
}

/// Sign a digest made with `hash`.
pub(super) fn sign_digest(
  material: &Material,
  hash: HashAlgorithm,
  digest: &[u8],
  options: &Options,
) -> Result<Vec<u8>, SignError> {
  match material {
    Material::Rsa { private: Some(key), .. } => match options.padding.unwrap_or(RSA_PKCS1_PADDING) {
      RSA_PKCS1_PADDING => CRYPTO_PROVIDER.rsa_pkcs1v15_sign(key, digest, hash).map_err(fail),
      RSA_PKCS1_PSS_PADDING => {
        let salt = pss_salt(material, hash, options.salt_length, true)?;
        CRYPTO_PROVIDER.rsa_pss_sign(key, digest, salt, hash).map_err(fail)
      },
      _ => Err(SignError::Unsupported("this RSA padding is not supported for signing")),
    },
    Material::Ec { curve, .. } => {
      let pkcs8 = material.pkcs8().ok_or(SignError::Operation)?;
      let fixed = CRYPTO_PROVIDER.ecdsa_sign(*curve, &pkcs8, digest).map_err(fail)?;
      Ok(if options.dsa_der { ecdsa_to_der(&fixed) } else { fixed })
    },
    _ => Err(SignError::Operation),
  }
}

/// Verify a signature over a digest made with `hash`.
pub(super) fn verify_digest(
  material: &Material,
  hash: HashAlgorithm,
  digest: &[u8],
  signature: &[u8],
  options: &Options,
) -> Result<bool, SignError> {
  match material {
    Material::Rsa { public, .. } => match options.padding.unwrap_or(RSA_PKCS1_PADDING) {
      RSA_PKCS1_PADDING => CRYPTO_PROVIDER
        .rsa_pkcs1v15_verify(public, signature, digest, hash)
        .map_err(fail),
      RSA_PKCS1_PSS_PADDING => {
        let salt = pss_salt(material, hash, options.salt_length, false)?;
        CRYPTO_PROVIDER
          .rsa_pss_verify(public, signature, digest, salt, hash)
          .map_err(fail)
      },
      _ => Err(SignError::Unsupported("this RSA padding is not supported for verifying")),
    },
    Material::Ec { curve, point, .. } => {
      let width = curve_width(*curve);
      let fixed = if options.dsa_der {
        ecdsa_from_der(signature, width)
      } else {
        (signature.len() == width * 2).then(|| signature.to_vec())
      };
      match fixed {
        Some(fixed) => CRYPTO_PROVIDER.ecdsa_verify(*curve, point, &fixed, digest).map_err(fail),
        None => Ok(false),
      }
    },
    _ => Err(SignError::Operation),
  }
}

/// Ed25519 over the message itself, as `crypto.sign(null, ...)` does.
pub(super) fn sign_message(material: &Material, data: &[u8]) -> Result<Vec<u8>, SignError> {
  let Material::Ed25519 { seed: Some(_), .. } = material else {
    return Err(SignError::Operation);
  };
  let pkcs8 = material.pkcs8().ok_or(SignError::Operation)?;
  CRYPTO_PROVIDER.ed25519_sign(&pkcs8, data).map_err(fail)
}

pub(super) fn verify_message(material: &Material, data: &[u8], signature: &[u8]) -> Result<bool, SignError> {
  let Material::Ed25519 { public, .. } = material else {
    return Err(SignError::Operation);
  };
  CRYPTO_PROVIDER.ed25519_verify(public, signature, data).map_err(fail)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ecdsa_signatures_convert_both_ways() {
    let fixed: Vec<u8> = (0u8..64).map(|i| if i == 0 || i == 32 { 0x80 } else { i }).collect();
    let encoded = ecdsa_to_der(&fixed);
    assert_eq!(ecdsa_from_der(&encoded, 32), Some(fixed));
    let short = [vec![0u8; 31], vec![1u8], vec![0u8; 31], vec![2u8]].concat();
    assert_eq!(ecdsa_from_der(&ecdsa_to_der(&short), 32), Some(short));
  }

  #[test]
  fn a_malformed_der_signature_is_no_signature() {
    assert_eq!(ecdsa_from_der(b"garbage", 32), None);
    assert_eq!(ecdsa_from_der(&[der::SEQUENCE, 0], 32), None);
    let oversized = der::sequence(&[&der::unsigned(&[1u8; 33]), &der::unsigned(&[1])]);
    assert_eq!(ecdsa_from_der(&oversized, 32), None);
  }
}
