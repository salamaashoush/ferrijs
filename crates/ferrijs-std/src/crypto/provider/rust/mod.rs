// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod aes_variants;

use std::num::NonZeroU32;

use der::{
    asn1::{BitStringRef, OctetString, OctetStringRef},
    Decode, Encode,
};

use aws_lc_rs::agreement::PrivateKey as LcAgreementPrivateKey;
use aws_lc_rs::cipher::{self as lc_cipher};
use aws_lc_rs::constant_time as lc_constant_time;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin, EcPrivateKeyBin};
use aws_lc_rs::signature::{
    EcdsaKeyPair as LcEcdsaKeyPair, Ed25519KeyPair as LcEd25519KeyPair, KeyPair as _,
};
use aws_lc_rs::rsa::{
    KeyPair as LcRsaKeyPair, KeySize as LcRsaKeySize, OaepAlgorithm as LcOaepAlgorithm,
    OaepPrivateDecryptingKey as LcRsaOaepPrivateDecryptingKey,
    OaepPublicEncryptingKey as LcRsaOaepPublicEncryptingKey,
    PrivateDecryptingKey as LcRsaPrivateDecryptingKey,
    PublicEncryptingKey as LcRsaPublicEncryptingKey,
};
use aws_lc_rs::{
    agreement as lc_agreement, digest as lc_digest, hkdf as lc_hkdf, hmac as lc_hmac, pbkdf2 as lc_pbkdf2, rsa as lc_rsa,
    signature as lc_signature,
};
use hmac::{digest::KeyInit as _, Hmac as HmacImpl, Mac};
use aes_variants::AesGcmVariant;
use md5::Digest as Md5Digest;

// AWS-LC has no MD5. It is the one hash this runtime exposes that has to come
// from somewhere else, so it is named once here rather than spelled out at
// each use.
type HmacMd5 = HmacImpl<md5::Md5>;


use crate::crypto::{
    hash::HashAlgorithm,
    provider::{
        parse_rsa_public_exponent, AesMode, CryptoError, CryptoProvider, HmacProvider, SimpleDigest,
    },
    random_byte_array,
    subtle::EllipticCurve,
};

// X25519 public points are derived through OpenSSL from the raw scalar, which
// is how this provider stores an X25519 private key.
fn x25519_public_from_raw(secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = LcAgreementPrivateKey::from_private_key(&lc_agreement::X25519, secret)
        .map_err(|_| CryptoError::InvalidKey(None))?;
    key.compute_public_key()
        .map(|public| public.as_ref().to_vec())
        .map_err(|_| CryptoError::InvalidKey(None))
}

fn ec_curve_oid(curve: EllipticCurve) -> der::asn1::ObjectIdentifier {
    match curve {
        EllipticCurve::P256 => const_oid::db::rfc5912::SECP_256_R_1,
        EllipticCurve::P384 => const_oid::db::rfc5912::SECP_384_R_1,
        EllipticCurve::P521 => const_oid::db::rfc5912::SECP_521_R_1,
    }
}

fn ec_pkcs8_from_scalar(curve: EllipticCurve, scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = LcAgreementPrivateKey::from_private_key(ecdh_algorithm(curve), scalar)
        .map_err(|_| CryptoError::InvalidKey(None))?;
    AsDer::<Pkcs8V1Der<'_>>::as_der(&key)
        .map(|der| der.as_ref().to_vec())
        .map_err(|_| CryptoError::OperationFailed(None))
}

fn ecdh_algorithm(curve: EllipticCurve) -> &'static lc_agreement::Algorithm {
    match curve {
        EllipticCurve::P256 => &lc_agreement::ECDH_P256,
        EllipticCurve::P384 => &lc_agreement::ECDH_P384,
        EllipticCurve::P521 => &lc_agreement::ECDH_P521,
    }
}

// AWS-LC has no MD5, so that one digest stays on a pure-Rust implementation.
// Both enums carry it as a separate arm rather than pushing the whole surface
// onto the slower path.
// The byte width of a coordinate on this curve. P-521's field is 521 bits, so
// its coordinates are 66 bytes and are left-padded rather than trimmed.
fn ec_field_len(curve: EllipticCurve) -> usize {
    match curve {
        EllipticCurve::P256 => 32,
        EllipticCurve::P384 => 48,
        EllipticCurve::P521 => 66,
    }
}

// One place maps this runtime's hash names onto AWS-LC's, so a hash AWS-LC does
// not implement is rejected here rather than somewhere downstream. MD5 is the
// only one, and it has no home in any of these: AWS-LC omits it, and WebCrypto
// does not name it for HKDF, PBKDF2 or a signature.
fn lc_digest_algorithm(algorithm: HashAlgorithm) -> &'static lc_digest::Algorithm {
    match algorithm {
        HashAlgorithm::Sha1 => &lc_digest::SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha256 => &lc_digest::SHA256,
        HashAlgorithm::Sha384 => &lc_digest::SHA384,
        HashAlgorithm::Sha512 => &lc_digest::SHA512,
        // The caller handles MD5 before it reaches here.
        HashAlgorithm::Md5 => &lc_digest::SHA256,
    }
}

fn lc_hmac_algorithm(algorithm: HashAlgorithm) -> lc_hmac::Algorithm {
    match algorithm {
        HashAlgorithm::Sha1 => lc_hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha256 => lc_hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => lc_hmac::HMAC_SHA384,
        HashAlgorithm::Sha512 => lc_hmac::HMAC_SHA512,
        HashAlgorithm::Md5 => lc_hmac::HMAC_SHA256,
    }
}

fn lc_hkdf_algorithm(algorithm: HashAlgorithm) -> Result<lc_hkdf::Algorithm, CryptoError> {
    match algorithm {
        HashAlgorithm::Sha1 => Ok(lc_hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY),
        HashAlgorithm::Sha256 => Ok(lc_hkdf::HKDF_SHA256),
        HashAlgorithm::Sha384 => Ok(lc_hkdf::HKDF_SHA384),
        HashAlgorithm::Sha512 => Ok(lc_hkdf::HKDF_SHA512),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn lc_pbkdf2_algorithm(algorithm: HashAlgorithm) -> Result<lc_pbkdf2::Algorithm, CryptoError> {
    match algorithm {
        HashAlgorithm::Sha1 => Ok(lc_pbkdf2::PBKDF2_HMAC_SHA1),
        HashAlgorithm::Sha256 => Ok(lc_pbkdf2::PBKDF2_HMAC_SHA256),
        HashAlgorithm::Sha384 => Ok(lc_pbkdf2::PBKDF2_HMAC_SHA384),
        HashAlgorithm::Sha512 => Ok(lc_pbkdf2::PBKDF2_HMAC_SHA512),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

// `expand` wants a type carrying the output length; WebCrypto's is a runtime
// value rather than a constant.
#[derive(Clone, Copy)]
struct HkdfLen(usize);

impl lc_hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

// AWS-LC signs only under SHA-256, SHA-384 and SHA-512; it has no
// `RsaSignatureEncoding` for SHA-1, though it will still verify one.
fn rsa_pss_encoding(
    hash_alg: HashAlgorithm,
) -> Result<(&'static lc_signature::RsaSignatureEncoding, &'static lc_digest::Algorithm), CryptoError>
{
    match hash_alg {
        HashAlgorithm::Sha256 => Ok((&lc_signature::RSA_PSS_SHA256, &lc_digest::SHA256)),
        HashAlgorithm::Sha384 => Ok((&lc_signature::RSA_PSS_SHA384, &lc_digest::SHA384)),
        HashAlgorithm::Sha512 => Ok((&lc_signature::RSA_PSS_SHA512, &lc_digest::SHA512)),
        HashAlgorithm::Sha1 | HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn rsa_pkcs1_encoding(
    hash_alg: HashAlgorithm,
) -> Result<(&'static lc_signature::RsaSignatureEncoding, &'static lc_digest::Algorithm), CryptoError>
{
    match hash_alg {
        HashAlgorithm::Sha256 => Ok((&lc_signature::RSA_PKCS1_SHA256, &lc_digest::SHA256)),
        HashAlgorithm::Sha384 => Ok((&lc_signature::RSA_PKCS1_SHA384, &lc_digest::SHA384)),
        HashAlgorithm::Sha512 => Ok((&lc_signature::RSA_PKCS1_SHA512, &lc_digest::SHA512)),
        HashAlgorithm::Sha1 | HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn rsa_pss_params(
    hash_alg: HashAlgorithm,
) -> Result<(&'static lc_signature::RsaParameters, &'static lc_digest::Algorithm), CryptoError> {
    match hash_alg {
        HashAlgorithm::Sha256 => Ok((&lc_signature::RSA_PSS_2048_8192_SHA256, &lc_digest::SHA256)),
        HashAlgorithm::Sha384 => Ok((&lc_signature::RSA_PSS_2048_8192_SHA384, &lc_digest::SHA384)),
        HashAlgorithm::Sha512 => Ok((&lc_signature::RSA_PSS_2048_8192_SHA512, &lc_digest::SHA512)),
        HashAlgorithm::Sha1 | HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn rsa_pkcs1_params(
    hash_alg: HashAlgorithm,
) -> Result<(&'static lc_signature::RsaParameters, &'static lc_digest::Algorithm), CryptoError> {
    match hash_alg {
        HashAlgorithm::Sha1 => Ok((
            &lc_signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            &lc_digest::SHA1_FOR_LEGACY_USE_ONLY,
        )),
        HashAlgorithm::Sha256 => Ok((&lc_signature::RSA_PKCS1_2048_8192_SHA256, &lc_digest::SHA256)),
        HashAlgorithm::Sha384 => Ok((&lc_signature::RSA_PKCS1_2048_8192_SHA384, &lc_digest::SHA384)),
        HashAlgorithm::Sha512 => Ok((&lc_signature::RSA_PKCS1_2048_8192_SHA512, &lc_digest::SHA512)),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn rsa_oaep_algorithm(hash_alg: HashAlgorithm) -> Result<&'static LcOaepAlgorithm, CryptoError> {
    match hash_alg {
        HashAlgorithm::Sha1 => Ok(&lc_rsa::OAEP_SHA1_MGF1SHA1),
        HashAlgorithm::Sha256 => Ok(&lc_rsa::OAEP_SHA256_MGF1SHA256),
        HashAlgorithm::Sha384 => Ok(&lc_rsa::OAEP_SHA384_MGF1SHA384),
        HashAlgorithm::Sha512 => Ok(&lc_rsa::OAEP_SHA512_MGF1SHA512),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

// An absent label and an empty one are the same input to OAEP.
fn oaep_label(label: Option<&[u8]>) -> Option<&[u8]> {
    label.filter(|l| !l.is_empty())
}

fn rsa_sign_prehashed(
    private_key_der: &[u8],
    digest: &[u8],
    encoding: &'static lc_signature::RsaSignatureEncoding,
    algorithm: &'static lc_digest::Algorithm,
) -> Result<Vec<u8>, CryptoError> {
    let key = LcRsaKeyPair::from_der(private_key_der).map_err(|_| CryptoError::InvalidKey(None))?;
    let prehashed = lc_digest::Digest::import_less_safe(digest, algorithm)
        .map_err(|_| CryptoError::SigningFailed(None))?;
    let mut signature = vec![0u8; key.public_modulus_len()];
    key.sign_digest(encoding, &prehashed, &mut signature)
        .map_err(|_| CryptoError::SigningFailed(None))?;
    Ok(signature)
}

fn rsa_verify_prehashed(
    public_key_der: &[u8],
    signature: &[u8],
    digest: &[u8],
    params: &'static lc_signature::RsaParameters,
    algorithm: &'static lc_digest::Algorithm,
) -> Result<bool, CryptoError> {
    let Ok(prehashed) = lc_digest::Digest::import_less_safe(digest, algorithm) else {
        return Ok(false);
    };
    // Parsing up front rejects a malformed key as invalid rather than letting
    // it read as a failed verification. AWS-LC takes either RFC 8017 or RFC
    // 5280 here, and this provider stores the RFC 8017 form.
    let key = lc_signature::ParsedPublicKey::new(params, public_key_der)
        .map_err(|_| CryptoError::InvalidKey(None))?;
    Ok(key.verify_digest_sig(&prehashed, signature).is_ok())
}

// This provider stores RSA keys in the RFC 8017 shapes, while parts of AWS-LC
// want the RFC 5280 and PKCS#8 wrappers around them.
fn rsa_spki_from_pkcs1(public_key_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let spki = spki::SubjectPublicKeyInfo {
        algorithm: spki::AlgorithmIdentifier::<der::asn1::Any> {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: Some(der::asn1::Null.into()),
        },
        subject_public_key: spki::der::asn1::BitString::from_bytes(public_key_der)
            .map_err(|_| CryptoError::InvalidKey(None))?,
    };
    spki.to_der().map_err(|_| CryptoError::InvalidKey(None))
}

// AWS-LC parses PKCS#1 and emits PKCS#8, so it does the wrapping rather than
// this reassembling the algorithm identifier by hand. Parsing also rejects a
// malformed key here instead of further in.
fn rsa_pkcs8_from_pkcs1(private_key_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = LcRsaKeyPair::from_der(private_key_der).map_err(|_| CryptoError::InvalidKey(None))?;
    AsDer::<Pkcs8V1Der<'_>>::as_der(&key)
        .map(|der| der.as_ref().to_vec())
        .map_err(|_| CryptoError::InvalidKey(None))
}

fn rsa_pkcs1_from_pkcs8(pkcs8_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let info =
        pkcs8::PrivateKeyInfoRef::from_der(pkcs8_der).map_err(|_| CryptoError::InvalidKey(None))?;
    Ok(info.private_key.as_bytes().to_vec())
}

// AWS-LC pairs each curve with the hashes it will sign under, and `sign_digest`
// refuses a digest from any other. WebCrypto allows any pairing, so the ones
// AWS-LC does not carry are refused here rather than signed under the wrong
// hash. What remains is ES256, ES384 and ES512, which is every pairing JOSE and
// TLS use.
fn ecdsa_signing_algorithm(
    curve: EllipticCurve,
    digest_len: usize,
) -> Result<(&'static lc_signature::EcdsaSigningAlgorithm, &'static lc_digest::Algorithm), CryptoError>
{
    match (curve, digest_len) {
        (EllipticCurve::P256, 32) => Ok((
            &lc_signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &lc_digest::SHA256,
        )),
        (EllipticCurve::P384, 48) => Ok((
            &lc_signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &lc_digest::SHA384,
        )),
        (EllipticCurve::P521, 32) => Ok((
            &lc_signature::ECDSA_P521_SHA256_FIXED_SIGNING,
            &lc_digest::SHA256,
        )),
        (EllipticCurve::P521, 48) => Ok((
            &lc_signature::ECDSA_P521_SHA384_FIXED_SIGNING,
            &lc_digest::SHA384,
        )),
        (EllipticCurve::P521, 64) => Ok((
            &lc_signature::ECDSA_P521_SHA512_FIXED_SIGNING,
            &lc_digest::SHA512,
        )),
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn ecdsa_verification_algorithm(
    curve: EllipticCurve,
    digest_len: usize,
) -> Result<
    (&'static lc_signature::EcdsaVerificationAlgorithm, &'static lc_digest::Algorithm),
    CryptoError,
> {
    match (curve, digest_len) {
        (EllipticCurve::P256, 32) => {
            Ok((&lc_signature::ECDSA_P256_SHA256_FIXED, &lc_digest::SHA256))
        },
        (EllipticCurve::P384, 48) => {
            Ok((&lc_signature::ECDSA_P384_SHA384_FIXED, &lc_digest::SHA384))
        },
        (EllipticCurve::P521, 32) => {
            Ok((&lc_signature::ECDSA_P521_SHA256_FIXED, &lc_digest::SHA256))
        },
        (EllipticCurve::P521, 48) => {
            Ok((&lc_signature::ECDSA_P521_SHA384_FIXED, &lc_digest::SHA384))
        },
        (EllipticCurve::P521, 64) => {
            Ok((&lc_signature::ECDSA_P521_SHA512_FIXED, &lc_digest::SHA512))
        },
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

impl From<aes_gcm::aes::cipher::InvalidLength> for CryptoError {
    fn from(_: aes_gcm::aes::cipher::InvalidLength) -> Self {
        CryptoError::InvalidLength
    }
}

fn aes_algorithm(key_len: usize) -> Result<&'static lc_cipher::Algorithm, CryptoError> {
    match key_len {
        16 => Ok(&lc_cipher::AES_128),
        24 => Ok(&lc_cipher::AES_192),
        32 => Ok(&lc_cipher::AES_256),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn aes_key(key: &[u8]) -> Result<lc_cipher::UnboundCipherKey, CryptoError> {
    lc_cipher::UnboundCipherKey::new(aes_algorithm(key.len())?, key)
        .map_err(|_| CryptoError::InvalidKey(None))
}

fn aes_iv_context(iv: &[u8]) -> Result<lc_cipher::EncryptionContext, CryptoError> {
    let iv = <[u8; 16]>::try_from(iv).map_err(|_| CryptoError::InvalidData(None))?;
    Ok(lc_cipher::EncryptionContext::Iv128(FixedLength::from(iv)))
}

fn aes_cbc(key: &[u8], iv: &[u8], data: &[u8], encrypt: bool) -> Result<Vec<u8>, CryptoError> {
    if encrypt {
        let cipher = lc_cipher::PaddedBlockEncryptingKey::cbc_pkcs7(aes_key(key)?)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let mut out = data.to_vec();
        cipher
            .less_safe_encrypt(&mut out, aes_iv_context(iv)?)
            .map_err(|_| CryptoError::EncryptionFailed(None))?;
        Ok(out)
    } else {
        let cipher = lc_cipher::PaddedBlockDecryptingKey::cbc_pkcs7(aes_key(key)?)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let mut out = data.to_vec();
        let plaintext = cipher
            .decrypt(&mut out, aes_iv_context(iv)?.into())
            .map_err(|_| CryptoError::DecryptionFailed(None))?;
        Ok(plaintext.to_vec())
    }
}

// AES-ECB over one buffer. It is the primitive CTR and RFC 3394 are built from
// rather than a mode this runtime offers on its own.
fn aes_ecb_blocks(key: &[u8], blocks: &[u8], encrypt: bool) -> Result<Vec<u8>, CryptoError> {
    let mut out = blocks.to_vec();
    if encrypt {
        lc_cipher::EncryptingKey::ecb(aes_key(key)?)
            .and_then(|cipher| {
                cipher.less_safe_encrypt(&mut out, lc_cipher::EncryptionContext::None)
            })
            .map_err(|_| CryptoError::EncryptionFailed(None))?;
    } else {
        lc_cipher::DecryptingKey::ecb(aes_key(key)?)
            .and_then(|cipher| cipher.decrypt(&mut out, lc_cipher::DecryptionContext::None))
            .map_err(|_| CryptoError::DecryptionFailed(None))?;
    }
    Ok(out)
}

// The tag lengths WebCrypto allows for AES-GCM.
fn aes_gcm_tag_len(tag_length: u8) -> Result<usize, CryptoError> {
    match tag_length {
        32 | 64 | 96 | 104 | 112 | 120 | 128 => Ok(usize::from(tag_length) / 8),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn aes_gcm_variant(key: &[u8], tag_length: u8) -> Result<AesGcmVariant, CryptoError> {
    aes_gcm_tag_len(tag_length)?;
    let key_bits = u16::try_from(key.len() * 8).map_err(|_| CryptoError::InvalidKey(None))?;
    Ok(AesGcmVariant::new(key_bits, tag_length, key)?)
}

fn aes_gcm_seal(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    tag_length: u8,
) -> Result<Vec<u8>, CryptoError> {
    aes_gcm_variant(key, tag_length)?
        .encrypt(iv, data, additional_data)
        .map_err(|_| CryptoError::EncryptionFailed(None))
}

fn aes_gcm_open(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    tag_length: u8,
) -> Result<Vec<u8>, CryptoError> {
    aes_gcm_variant(key, tag_length)?
        .decrypt(iv, data, additional_data)
        .map_err(|_| CryptoError::DecryptionFailed(None))
}

// RFC 3394. `aws_lc_rs::key_wrap` carries no 192-bit algorithm, so the
// algorithm is run here over AES-ECB. `A` is the integrity value, starting at
// the default IV the RFC fixes and which WebCrypto's AES-KW uses.
const AES_KW_IV: [u8; 8] = [0xa6; 8];

fn aes_kw_wrap_rfc3394(kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() < 16 || !key.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    let n = key.len() / 8;
    let mut a = AES_KW_IV;
    let mut r = key.to_vec();

    let mut block = [0u8; 16];
    for j in 0..6u64 {
        for (i, chunk) in (1..=n).zip(r.chunks_mut(8)) {
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(chunk);
            let out = aes_ecb_blocks(kek, &block, true)?;
            // t = n * j + i, xored into the low bytes of A.
            let t = j * n as u64 + i as u64;
            a.copy_from_slice(&out[..8]);
            for (byte, t_byte) in a.iter_mut().rev().zip(t.to_le_bytes()) {
                *byte ^= t_byte;
            }
            chunk.copy_from_slice(&out[8..]);
        }
    }

    let mut wrapped = Vec::with_capacity(key.len() + 8);
    wrapped.extend_from_slice(&a);
    wrapped.extend_from_slice(&r);
    Ok(wrapped)
}

fn aes_kw_unwrap_rfc3394(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(CryptoError::OperationFailed(None));
    }
    let n = wrapped.len() / 8 - 1;
    let mut a = <[u8; 8]>::try_from(&wrapped[..8]).map_err(|_| CryptoError::OperationFailed(None))?;
    let mut r = wrapped[8..].to_vec();

    let mut block = [0u8; 16];
    for j in (0..6u64).rev() {
        for (i, chunk) in (1..=n).rev().zip(r.chunks_mut(8).rev()) {
            let t = j * n as u64 + i as u64;
            block[..8].copy_from_slice(&a);
            for (byte, t_byte) in block[..8].iter_mut().rev().zip(t.to_le_bytes()) {
                *byte ^= t_byte;
            }
            block[8..].copy_from_slice(chunk);
            let out = aes_ecb_blocks(kek, &block, false)?;
            a.copy_from_slice(&out[..8]);
            chunk.copy_from_slice(&out[8..]);
        }
    }

    // The integrity value is the whole point: a wrong KEK or a tampered
    // wrapping lands here and must not return a key.
    if lc_constant_time::verify_slices_are_equal(&a, &AES_KW_IV).is_err() {
        return Err(CryptoError::OperationFailed(None));
    }
    Ok(r)
}

// WebCrypto's AES-CTR `length` is the width of the counter field, and the
// counter wraps inside that field alone. AWS-LC's own CTR always increments the
// whole 128-bit block, so it cannot express a 32- or 64-bit counter; the
// keystream is built here from ECB instead, which is what CTR is defined as,
// with the increment applied at the requested width.
fn ctr_increment(block: &mut [u8; 16], counter_length: u32) {
    let start = 16 - (counter_length as usize / 8);
    for byte in block[start..].iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn aes_ctr_apply(
    key: &[u8],
    iv: &[u8],
    counter_length: u32,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !matches!(counter_length, 32 | 64 | 128) {
        return Err(CryptoError::InvalidKey(None));
    }
    let mut counter = <[u8; 16]>::try_from(iv).map_err(|_| CryptoError::InvalidData(None))?;

    let mut out = data.to_vec();
    // Bounded so the keystream buffer stays small whatever the message size.
    const BLOCKS_PER_PASS: usize = 512;
    for segment in out.chunks_mut(16 * BLOCKS_PER_PASS) {
        let blocks = segment.len().div_ceil(16);
        let mut counters = Vec::with_capacity(blocks * 16);
        for _ in 0..blocks {
            counters.extend_from_slice(&counter);
            ctr_increment(&mut counter, counter_length);
        }
        let keystream = aes_ecb_blocks(key, &counters, true)?;
        for (byte, k) in segment.iter_mut().zip(keystream.iter()) {
            *byte ^= k;
        }
    }
    Ok(out)
}

pub enum RustDigest {
    Lc(lc_digest::Context),
    Md5(md5::Md5),
}

impl SimpleDigest for RustDigest {
    fn update(&mut self, data: &[u8]) {
        match self {
            RustDigest::Lc(ctx) => ctx.update(data),
            RustDigest::Md5(hasher) => Md5Digest::update(hasher, data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            RustDigest::Lc(ctx) => ctx.finish().as_ref().to_vec(),
            RustDigest::Md5(hasher) => hasher.finalize().to_vec(),
        }
    }
}

pub enum RustHmac {
    Lc(Box<lc_hmac::Context>),
    Md5(HmacMd5),
}

impl HmacProvider for RustHmac {
    fn update(&mut self, data: &[u8]) {
        match self {
            RustHmac::Lc(ctx) => ctx.update(data),
            RustHmac::Md5(mac) => Mac::update(mac, data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            RustHmac::Lc(ctx) => ctx.sign().as_ref().to_vec(),
            RustHmac::Md5(mac) => mac.finalize().into_bytes().to_vec(),
        }
    }
}

// Main Crypto Provider
#[derive(Default)]
pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {
    type Digest = RustDigest;
    type Hmac = RustHmac;

    fn digest(&self, algorithm: HashAlgorithm) -> Self::Digest {
        match algorithm {
            HashAlgorithm::Md5 => RustDigest::Md5(md5::Md5::new()),
            other => RustDigest::Lc(lc_digest::Context::new(lc_digest_algorithm(other))),
        }
    }

    fn hmac(&self, algorithm: HashAlgorithm, key: &[u8]) -> Self::Hmac {
        match algorithm {
            HashAlgorithm::Md5 => RustHmac::Md5(
                HmacMd5::new_from_slice(key).expect("HMAC accepts a key of any length"),
            ),
            other => {
                let key = lc_hmac::Key::new(lc_hmac_algorithm(other), key);
                RustHmac::Lc(Box::new(lc_hmac::Context::with_key(&key)))
            },
        }
    }

    fn ecdsa_sign(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        digest: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (algorithm, hash) = ecdsa_signing_algorithm(curve, digest.len())?;
        let key = LcEcdsaKeyPair::from_pkcs8(algorithm, private_key_der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let prehashed = lc_digest::Digest::import_less_safe(digest, hash)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        key.sign_digest(&prehashed)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| CryptoError::SigningFailed(None))
    }

    fn ecdsa_verify(
        &self,
        curve: EllipticCurve,
        public_key_sec1: &[u8],
        signature: &[u8],
        digest: &[u8],
    ) -> Result<bool, CryptoError> {
        let (algorithm, hash) = ecdsa_verification_algorithm(curve, digest.len())?;
        let Ok(prehashed) = lc_digest::Digest::import_less_safe(digest, hash) else {
            return Ok(false);
        };
        let key = lc_signature::ParsedPublicKey::new(algorithm, public_key_sec1)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(key.verify_digest_sig(&prehashed, signature).is_ok())
    }

    fn ed25519_sign(&self, private_key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Ed25519 hashes internally, so it signs the message rather than a
        // digest of it.
        let key = LcEd25519KeyPair::from_pkcs8(private_key_der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(key.sign(data).as_ref().to_vec())
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, CryptoError> {
        let key = lc_signature::UnparsedPublicKey::new(&lc_signature::ED25519, public_key_bytes);
        Ok(key.verify(data, signature).is_ok())
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let (encoding, algorithm) = rsa_pss_encoding(hash_alg)?;
        // AWS-LC fixes the PSS salt at the digest length and exposes no way to
        // ask for another, so a caller-chosen saltLength is only honoured when
        // it already agrees rather than silently producing a different
        // signature from the one that was asked for.
        if salt_length != algorithm.output_len() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        rsa_sign_prehashed(private_key_der, digest, encoding, algorithm)
    }

    fn rsa_pss_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        digest: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let (params, algorithm) = rsa_pss_params(hash_alg)?;
        if salt_length != algorithm.output_len() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        rsa_verify_prehashed(public_key_der, signature, digest, params, algorithm)
    }

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let (encoding, algorithm) = rsa_pkcs1_encoding(hash_alg)?;
        rsa_sign_prehashed(private_key_der, digest, encoding, algorithm)
    }

    fn rsa_pkcs1v15_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        digest: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let (params, algorithm) = rsa_pkcs1_params(hash_alg)?;
        rsa_verify_prehashed(public_key_der, signature, digest, params, algorithm)
    }

    fn rsa_oaep_encrypt(
        &self,
        public_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let algorithm = rsa_oaep_algorithm(hash_alg)?;
        let public_key = LcRsaPublicEncryptingKey::from_der(&rsa_spki_from_pkcs1(public_key_der)?)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let key = LcRsaOaepPublicEncryptingKey::new(public_key)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let mut out = vec![0u8; key.ciphertext_size()];
        let written = key
            .encrypt(algorithm, data, &mut out, oaep_label(label))
            .map_err(|_| CryptoError::EncryptionFailed(None))?
            .len();
        out.truncate(written);
        Ok(out)
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let algorithm = rsa_oaep_algorithm(hash_alg)?;
        let private_key =
            LcRsaPrivateDecryptingKey::from_pkcs8(&rsa_pkcs8_from_pkcs1(private_key_der)?)
                .map_err(|_| CryptoError::InvalidKey(None))?;
        let key = LcRsaOaepPrivateDecryptingKey::new(private_key)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let mut out = vec![0u8; key.min_output_size()];
        let written = key
            .decrypt(algorithm, data, &mut out, oaep_label(label))
            .map_err(|_| CryptoError::DecryptionFailed(None))?
            .len();
        out.truncate(written);
        Ok(out)
    }

    fn ecdh_derive_bits(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        public_key_sec1: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let algorithm = ecdh_algorithm(curve);
        let private_key = LcAgreementPrivateKey::from_private_key_der(algorithm, private_key_der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let peer = lc_agreement::UnparsedPublicKey::new(algorithm, public_key_sec1);
        // ECDH yields the x coordinate at the curve's field width, which is
        // what WebCrypto's deriveBits counts its length against.
        lc_agreement::agree(&private_key, peer, CryptoError::DerivationFailed(None), |secret| {
            Ok(secret.to_vec())
        })
    }

    fn x25519_derive_bits(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // This provider carries X25519 keys as the raw scalar and point rather
        // than wrapped in PKCS#8.
        let private_key = LcAgreementPrivateKey::from_private_key(&lc_agreement::X25519, private_key)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let peer = lc_agreement::UnparsedPublicKey::new(&lc_agreement::X25519, public_key);
        let shared = lc_agreement::agree(
            &private_key,
            peer,
            CryptoError::DerivationFailed(None),
            |secret| Ok(secret.to_vec()),
        )?;
        // RFC 7748 says to reject an all-zero secret, which is what a
        // small-order peer point produces.
        if shared.iter().all(|byte| *byte == 0) {
            return Err(CryptoError::OperationFailed(None));
        }
        Ok(shared)
    }

    fn aes_encrypt(
        &self,
        mode: AesMode,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        match mode {
            AesMode::Cbc => aes_cbc(key, iv, data, true),
            AesMode::Ctr { counter_length } => aes_ctr_apply(key, iv, counter_length, data),
            AesMode::Gcm { tag_length } => {
                aes_gcm_seal(key, iv, data, additional_data, tag_length)
            },
        }
    }

    fn aes_decrypt(
        &self,
        mode: AesMode,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        match mode {
            AesMode::Cbc => aes_cbc(key, iv, data, false),
            AesMode::Ctr { counter_length } => aes_ctr_apply(key, iv, counter_length, data),
            AesMode::Gcm { tag_length } => {
                aes_gcm_open(key, iv, data, additional_data, tag_length)
            },
        }
    }

    fn aes_kw_wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aes_kw_wrap_rfc3394(kek, key)
    }

    fn aes_kw_unwrap(&self, kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aes_kw_unwrap_rfc3394(kek, wrapped_key)
    }

    fn hkdf_derive_key(
        &self,
        key: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let algorithm = lc_hkdf_algorithm(hash_alg)?;
        let mut out = vec![0u8; length];
        lc_hkdf::Salt::new(algorithm, salt)
            .extract(key)
            .expand(&[info], HkdfLen(length))
            .and_then(|okm| okm.fill(&mut out))
            .map_err(|_| CryptoError::DerivationFailed(None))?;
        Ok(out)
    }

    fn pbkdf2_derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let algorithm = lc_pbkdf2_algorithm(hash_alg)?;
        let iterations = NonZeroU32::new(iterations).ok_or(CryptoError::InvalidData(None))?;
        let mut out = vec![0; length];
        lc_pbkdf2::derive(algorithm, iterations, salt, password, &mut out);
        Ok(out)
    }

    fn generate_aes_key(&self, length_bits: u16) -> Result<Vec<u8>, CryptoError> {
        let length_bytes = (length_bits / 8) as usize;
        if !matches!(length_bits, 128 | 192 | 256) {
            return Err(CryptoError::InvalidLength);
        }
        Ok(random_byte_array(length_bytes))
    }

    fn generate_hmac_key(
        &self,
        hash_alg: HashAlgorithm,
        length_bits: u16,
    ) -> Result<Vec<u8>, CryptoError> {
        let length_bytes = if length_bits == 0 {
            hash_alg.block_len()
        } else {
            (length_bits / 8) as usize
        };

        if length_bytes > 128 {
            return Err(CryptoError::InvalidLength);
        }

        Ok(random_byte_array(length_bytes))
    }

    fn generate_ec_key(&self, curve: EllipticCurve) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // Generated through the agreement side so the pair is usable for both
        // ECDH and ECDSA; the signing algorithms differ per hash, and a key
        // does not carry one.
        let private_key = LcAgreementPrivateKey::generate(ecdh_algorithm(curve))
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::OperationFailed(None))?
            .as_ref()
            .to_vec();
        let pkcs8 = AsDer::<Pkcs8V1Der<'_>>::as_der(&private_key)
            .map_err(|_| CryptoError::OperationFailed(None))?
            .as_ref()
            .to_vec();
        Ok((pkcs8, public_key))
    }

    fn generate_ed25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key = LcEd25519KeyPair::generate().map_err(|_| CryptoError::OperationFailed(None))?;
        let public_key = key.public_key().as_ref().to_vec();
        let private_key = key
            .to_pkcs8v1()
            .map_err(|_| CryptoError::OperationFailed(None))?
            .as_ref()
            .to_vec();
        Ok((private_key, public_key))
    }

    fn generate_x25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let private_key = LcAgreementPrivateKey::generate(&lc_agreement::X25519)
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::OperationFailed(None))?
            .as_ref()
            .to_vec();
        // Stored as the raw scalar, which is how the rest of this provider and
        // the OKP import and export paths carry it.
        let raw = AsBigEndian::<Curve25519SeedBin<'_>>::as_be_bytes(&private_key)
            .map_err(|_| CryptoError::OperationFailed(None))?
            .as_ref()
            .to_vec();
        Ok((raw, public_key))
    }

    fn generate_rsa_key(
        &self,
        modulus_length: u32,
        public_exponent: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // AWS-LC generates from a fixed set of sizes and always with e = 65537.
        // Anything else is refused rather than quietly generating a key the
        // caller did not ask for.
        if parse_rsa_public_exponent(public_exponent)? != 65537 {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let size = match modulus_length {
            2048 => LcRsaKeySize::Rsa2048,
            3072 => LcRsaKeySize::Rsa3072,
            4096 => LcRsaKeySize::Rsa4096,
            8192 => LcRsaKeySize::Rsa8192,
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        let key = LcRsaKeyPair::generate(size).map_err(|_| CryptoError::OperationFailed(None))?;
        // The provider stores RSA keys as PKCS#1; AWS-LC hands back PKCS#8, so
        // the inner key is taken out of it.
        let pkcs8 = AsDer::<Pkcs8V1Der<'_>>::as_der(&key)
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let private_key = rsa_pkcs1_from_pkcs8(pkcs8.as_ref())?;
        let public_key = pkcs1::RsaPrivateKey::from_der(&private_key)
            .map_err(|_| CryptoError::OperationFailed(None))
            .and_then(|k| {
                pkcs1::RsaPublicKey {
                    modulus: k.modulus,
                    public_exponent: k.public_exponent,
                }
                .to_der()
                .map_err(|_| CryptoError::OperationFailed(None))
            })?;
        Ok((private_key, public_key))
    }

    fn import_rsa_public_key_pkcs1(
        &self,
        der: &[u8],
    ) -> Result<super::RsaImportResult, CryptoError> {
        use der::Decode;
        let public_key =
            pkcs1::RsaPublicKey::from_der(der).map_err(|_| CryptoError::InvalidKey(None))?;
        let modulus_length = public_key.modulus.as_bytes().len() * 8;
        let public_exponent = public_key.public_exponent.as_bytes().to_vec();
        let key_data = public_key
            .to_der()
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(super::RsaImportResult {
            key_data,
            modulus_length: modulus_length as u32,
            public_exponent,
            is_private: false,
        })
    }

    fn import_rsa_private_key_pkcs1(
        &self,
        der: &[u8],
    ) -> Result<super::RsaImportResult, CryptoError> {
        use der::Decode;
        let private_key =
            pkcs1::RsaPrivateKey::from_der(der).map_err(|_| CryptoError::InvalidKey(None))?;
        let modulus_length = private_key.modulus.as_bytes().len() * 8;
        let public_exponent = private_key.public_exponent.as_bytes().to_vec();
        let key_data = private_key
            .to_der()
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(super::RsaImportResult {
            key_data,
            modulus_length: modulus_length as u32,
            public_exponent,
            is_private: true,
        })
    }

    fn import_rsa_public_key_spki(
        &self,
        der: &[u8],
    ) -> Result<super::RsaImportResult, CryptoError> {
        use der::Decode;
        let spki = spki::SubjectPublicKeyInfoRef::try_from(der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let public_key = pkcs1::RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let modulus_length = public_key.modulus.as_bytes().len() * 8;
        let public_exponent = public_key.public_exponent.as_bytes().to_vec();
        let key_data = public_key
            .to_der()
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(super::RsaImportResult {
            key_data,
            modulus_length: modulus_length as u32,
            public_exponent,
            is_private: false,
        })
    }

    fn import_rsa_private_key_pkcs8(
        &self,
        der: &[u8],
    ) -> Result<super::RsaImportResult, CryptoError> {
        use der::Decode;
        let pk_info =
            pkcs8::PrivateKeyInfoRef::from_der(der).map_err(|_| CryptoError::InvalidKey(None))?;
        let private_key = pkcs1::RsaPrivateKey::from_der(pk_info.private_key.as_bytes())
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let modulus_length = private_key.modulus.as_bytes().len() * 8;
        let public_exponent = private_key.public_exponent.as_bytes().to_vec();
        let key_data = pk_info.private_key.as_bytes().to_vec();
        Ok(super::RsaImportResult {
            key_data,
            modulus_length: modulus_length as u32,
            public_exponent,
            is_private: true,
        })
    }

    fn export_rsa_public_key_pkcs1(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // key_data is already PKCS1 DER
        Ok(key_data.to_vec())
    }

    fn export_rsa_public_key_spki(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use der::{Decode, Encode};
        let public_key = pkcs1::RsaPublicKey::from_der(key_data)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let spki = spki::SubjectPublicKeyInfo {
            algorithm: spki::AlgorithmIdentifier::<der::asn1::Any> {
                oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
                parameters: Some(der::asn1::Null.into()),
            },
            subject_public_key: spki::der::asn1::BitString::from_bytes(
                &public_key
                    .to_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?,
            )
            .map_err(|_| CryptoError::InvalidKey(None))?,
        };
        spki.to_der().map_err(|_| CryptoError::InvalidKey(None))
    }

    fn export_rsa_private_key_pkcs8(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // PKCS#8 is the PKCS#1 key this provider stores, wrapped in an
        // algorithm identifier. That is ASN.1 only, so no key parsing is
        // needed and a malformed key still fails here.
        pkcs1::RsaPrivateKey::from_der(key_data).map_err(|_| CryptoError::InvalidKey(None))?;
        rsa_pkcs8_from_pkcs1(key_data)
    }

    fn import_ec_public_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<super::EcImportResult, CryptoError> {
        // Parsing validates that the point is on the curve. WebCrypto's raw EC
        // format is the uncompressed point, and the rest of this provider
        // splits it on that shape, so a compressed one is refused rather than
        // stored as something the JWK export cannot read.
        let key = lc_agreement::UnparsedPublicKey::new(ecdh_algorithm(curve), data);
        let _: lc_agreement::ParsedPublicKey =
            key.try_into().map_err(|_| CryptoError::InvalidKey(None))?;
        if data.len() != 1 + 2 * ec_field_len(curve) || data[0] != 0x04 {
            return Err(CryptoError::InvalidKey(None));
        }
        Ok(super::EcImportResult {
            key_data: data.to_vec(),
            is_private: false,
        })
    }

    fn import_ec_public_key_spki(
        &self,
        der: &[u8],
        curve: EllipticCurve,
    ) -> Result<super::EcImportResult, CryptoError> {
        let spki = spki::SubjectPublicKeyInfoRef::try_from(der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let point = spki.subject_public_key.raw_bytes();
        self.import_ec_public_key_sec1(point, curve)
    }

    fn import_ec_private_key_pkcs8(
        &self,
        der: &[u8],
    ) -> Result<super::EcImportResult, CryptoError> {
        Ok(super::EcImportResult {
            key_data: der.to_vec(),
            is_private: true,
        })
    }

    fn import_ec_private_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<super::EcImportResult, CryptoError> {
        Ok(super::EcImportResult {
            key_data: ec_pkcs8_from_scalar(curve, data)?,
            is_private: true,
        })
    }

    fn export_ec_public_key_sec1(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
        is_private: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        if is_private {
            let key = LcAgreementPrivateKey::from_private_key_der(ecdh_algorithm(curve), key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?;
            key.compute_public_key()
                .map(|public| public.as_ref().to_vec())
                .map_err(|_| CryptoError::OperationFailed(None))
        } else {
            // key_data is already SEC1 encoded
            Ok(key_data.to_vec())
        }
    }

    fn export_ec_public_key_spki(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
    ) -> Result<Vec<u8>, CryptoError> {
        // The point is parsed first, so a caller that passes private key
        // material gets a rejection rather than an SPKI with the private key
        // wrapped inside it.
        let key = lc_agreement::UnparsedPublicKey::new(ecdh_algorithm(curve), key_data);
        let _: lc_agreement::ParsedPublicKey =
            key.try_into().map_err(|_| CryptoError::InvalidKey(None))?;

        let spki = spki::SubjectPublicKeyInfo {
            algorithm: spki::AlgorithmIdentifier::<der::asn1::ObjectIdentifier> {
                oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
                parameters: Some(ec_curve_oid(curve)),
            },
            subject_public_key: spki::der::asn1::BitString::from_bytes(key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?,
        };
        spki.to_der().map_err(|_| CryptoError::InvalidKey(None))
    }

    fn export_ec_private_key_pkcs8(
        &self,
        key_data: &[u8],
        _curve: EllipticCurve,
    ) -> Result<Vec<u8>, CryptoError> {
        // key_data is already PKCS8
        Ok(key_data.to_vec())
    }

    fn import_okp_public_key_raw(
        &self,
        data: &[u8],
    ) -> Result<super::OkpImportResult, CryptoError> {
        if data.len() != 32 {
            return Err(CryptoError::InvalidLength);
        }
        Ok(super::OkpImportResult {
            key_data: data.to_vec(),
            is_private: false,
        })
    }

    fn import_okp_public_key_spki(
        &self,
        der: &[u8],
        _expected_oid: &[u8],
    ) -> Result<super::OkpImportResult, CryptoError> {
        let spki = spki::SubjectPublicKeyInfoRef::try_from(der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(super::OkpImportResult {
            key_data: spki.subject_public_key.raw_bytes().to_vec(),
            is_private: false,
        })
    }

    fn import_okp_private_key_pkcs8(
        &self,
        der: &[u8],
        _expected_oid: &[u8],
    ) -> Result<super::OkpImportResult, CryptoError> {
        Ok(super::OkpImportResult {
            key_data: der.to_vec(),
            is_private: true,
        })
    }

    fn export_okp_public_key_raw(
        &self,
        key_data: &[u8],
        is_private: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        if is_private {
            // Extract public key from PKCS8 - for X25519/Ed25519
            use der::Decode;
            let pk_info = pkcs8::PrivateKeyInfoRef::from_der(key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?;
            // The private key is wrapped in an OCTET STRING, skip the tag+length (2 bytes)
            let private_key_bytes = pk_info.private_key.as_bytes();
            let seed = if private_key_bytes.len() > 2 && private_key_bytes[0] == 0x04 {
                &private_key_bytes[2..]
            } else {
                private_key_bytes
            };
            x25519_public_from_raw(seed)
        } else {
            Ok(key_data.to_vec())
        }
    }

    fn export_okp_public_key_spki(
        &self,
        key_data: &[u8],
        oid: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use der::Encode;
        let oid = const_oid::ObjectIdentifier::from_bytes(oid)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let spki = spki::SubjectPublicKeyInfo {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            subject_public_key: spki::der::asn1::BitString::from_bytes(key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?,
        };
        spki.to_der().map_err(|_| CryptoError::InvalidKey(None))
    }

    fn export_okp_private_key_pkcs8(
        &self,
        key_data: &[u8],
        oid: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Ed25519: key_data is already PKCS#8.
        if oid == const_oid::db::rfc8410::ID_ED_25519.as_bytes() {
            return Ok(key_data.to_vec());
        }
        // X25519: key_data is the raw 32-byte private scalar.
        if oid == const_oid::db::rfc8410::ID_X_25519.as_bytes() {
            if key_data.len() != 32 {
                return Err(CryptoError::InvalidKey(None));
            }

            // RFC 8410 requires the privateKey field to contain
            // an encoded OCTET STRING containing the 32-byte scalar.
            let inner = OctetStringRef::new(key_data).map_err(|_| CryptoError::InvalidKey(None))?;
            let inner_der = inner.to_der().map_err(|_| CryptoError::InvalidKey(None))?;
            let pk_info = pkcs8::PrivateKeyInfoRef {
                algorithm: spki::AlgorithmIdentifier {
                    oid: const_oid::db::rfc8410::ID_X_25519,
                    parameters: None,
                },
                private_key: OctetStringRef::new(&inner_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?,
                public_key: None,
            };
            return pk_info.to_der().map_err(|_| CryptoError::InvalidKey(None));
        }
        Err(CryptoError::InvalidKey(None))
    }

    fn import_rsa_jwk(
        &self,
        jwk: super::RsaJwkImport<'_>,
    ) -> Result<super::RsaImportResult, CryptoError> {
        use der::{asn1::UintRef, Encode};
        let modulus = UintRef::new(jwk.n).map_err(|_| CryptoError::InvalidKey(None))?;
        let public_exponent = UintRef::new(jwk.e).map_err(|_| CryptoError::InvalidKey(None))?;
        let modulus_length = (modulus.as_bytes().len() * 8) as u32;
        let pub_exp_bytes = public_exponent.as_bytes().to_vec();

        if let (Some(d), Some(p), Some(q), Some(dp), Some(dq), Some(qi)) =
            (jwk.d, jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi)
        {
            let private_key = pkcs1::RsaPrivateKey {
                modulus,
                public_exponent,
                private_exponent: UintRef::new(d).map_err(|_| CryptoError::InvalidKey(None))?,
                prime1: UintRef::new(p).map_err(|_| CryptoError::InvalidKey(None))?,
                prime2: UintRef::new(q).map_err(|_| CryptoError::InvalidKey(None))?,
                exponent1: UintRef::new(dp).map_err(|_| CryptoError::InvalidKey(None))?,
                exponent2: UintRef::new(dq).map_err(|_| CryptoError::InvalidKey(None))?,
                coefficient: UintRef::new(qi).map_err(|_| CryptoError::InvalidKey(None))?,
                other_prime_infos: None,
            };
            Ok(super::RsaImportResult {
                key_data: private_key
                    .to_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?,
                modulus_length,
                public_exponent: pub_exp_bytes,
                is_private: true,
            })
        } else {
            let public_key = pkcs1::RsaPublicKey {
                modulus,
                public_exponent,
            };
            Ok(super::RsaImportResult {
                key_data: public_key
                    .to_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?,
                modulus_length,
                public_exponent: pub_exp_bytes,
                is_private: false,
            })
        }
    }

    fn export_rsa_jwk(
        &self,
        key_data: &[u8],
        is_private: bool,
    ) -> Result<super::RsaJwkExport, CryptoError> {
        use der::Decode;
        if is_private {
            let key = pkcs1::RsaPrivateKey::from_der(key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?;
            Ok(super::RsaJwkExport {
                n: key.modulus.as_bytes().to_vec(),
                e: key.public_exponent.as_bytes().to_vec(),
                d: Some(key.private_exponent.as_bytes().to_vec()),
                p: Some(key.prime1.as_bytes().to_vec()),
                q: Some(key.prime2.as_bytes().to_vec()),
                dp: Some(key.exponent1.as_bytes().to_vec()),
                dq: Some(key.exponent2.as_bytes().to_vec()),
                qi: Some(key.coefficient.as_bytes().to_vec()),
            })
        } else {
            let key = pkcs1::RsaPublicKey::from_der(key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?;
            Ok(super::RsaJwkExport {
                n: key.modulus.as_bytes().to_vec(),
                e: key.public_exponent.as_bytes().to_vec(),
                d: None,
                p: None,
                q: None,
                dp: None,
                dq: None,
                qi: None,
            })
        }
    }

    fn import_ec_jwk(
        &self,
        jwk: super::EcJwkImport<'_>,
        curve: EllipticCurve,
    ) -> Result<super::EcImportResult, CryptoError> {
        if let Some(d) = jwk.d {
            // A JWK carries the scalar alone, and AWS-LC derives the point from
            // it when the key is built.
            Ok(super::EcImportResult {
                key_data: ec_pkcs8_from_scalar(curve, d)?,
                is_private: true,
            })
        } else {
            // Public key - encode as SEC1 uncompressed point
            let mut point = Vec::with_capacity(1 + jwk.x.len() + jwk.y.len());
            point.push(0x04); // uncompressed
            point.extend_from_slice(jwk.x);
            point.extend_from_slice(jwk.y);
            Ok(super::EcImportResult {
                key_data: point,
                is_private: false,
            })
        }
    }

    fn export_ec_jwk(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
        is_private: bool,
    ) -> Result<super::EcJwkExport, CryptoError> {
        let coord_len = ec_field_len(curve);
        if is_private {
            let key = LcAgreementPrivateKey::from_private_key_der(ecdh_algorithm(curve), key_data)
                .map_err(|_| CryptoError::InvalidKey(None))?;
            let point = key
                .compute_public_key()
                .map_err(|_| CryptoError::OperationFailed(None))?;
            let point = point.as_ref();
            // The uncompressed point is 0x04 followed by x and y at the field
            // width, which is what the JWK coordinates are.
            if point.len() != 1 + 2 * coord_len || point[0] != 0x04 {
                return Err(CryptoError::InvalidKey(None));
            }
            let scalar = AsBigEndian::<EcPrivateKeyBin<'_>>::as_be_bytes(&key)
                .map_err(|_| CryptoError::OperationFailed(None))?;
            Ok(super::EcJwkExport {
                x: point[1..1 + coord_len].to_vec(),
                y: point[1 + coord_len..].to_vec(),
                d: Some(scalar.as_ref().to_vec()),
            })
        } else {
            // key_data is SEC1 uncompressed point (0x04 || x || y)
            if key_data.len() != 1 + 2 * coord_len || key_data[0] != 0x04 {
                return Err(CryptoError::InvalidKey(None));
            }
            let x = key_data[1..1 + coord_len].to_vec();
            let y = key_data[1 + coord_len..].to_vec();
            Ok(super::EcJwkExport { x, y, d: None })
        }
    }

    fn import_okp_jwk(
        &self,
        jwk: super::OkpJwkImport<'_>,
        is_ed25519: bool,
    ) -> Result<super::OkpImportResult, CryptoError> {
        if let Some(d) = jwk.d {
            // Private key - for Ed25519 we need PKCS8, for X25519 we store raw
            if is_ed25519 {
                // Ed25519: construct PKCS8 from raw private key
                let pk_info = pkcs8::PrivateKeyInfoRef {
                    algorithm: spki::AlgorithmIdentifier {
                        oid: const_oid::db::rfc8410::ID_ED_25519,
                        parameters: None,
                    },
                    private_key: OctetStringRef::new(d)
                        .map_err(|_| CryptoError::InvalidKey(None))?,
                    public_key: Some(
                        BitStringRef::from_bytes(jwk.x)
                            .map_err(|_| CryptoError::InvalidKey(None))?,
                    ),
                };
                let der = pk_info
                    .to_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                Ok(super::OkpImportResult {
                    key_data: der,
                    is_private: true,
                })
            } else {
                // X25519: store raw 32-byte secret
                Ok(super::OkpImportResult {
                    key_data: d.to_vec(),
                    is_private: true,
                })
            }
        } else {
            // Public key - store raw bytes
            Ok(super::OkpImportResult {
                key_data: jwk.x.to_vec(),
                is_private: false,
            })
        }
    }

    fn export_okp_jwk(
        &self,
        key_data: &[u8],
        is_private: bool,
        is_ed25519: bool,
    ) -> Result<super::OkpJwkExport, CryptoError> {
        if is_private {
            if is_ed25519 {
                // Ed25519: key_data is complete PKCS#8 DER.
                let pk_info = pkcs8::PrivateKeyInfoRef::from_der(key_data)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let d = OctetString::from_der(pk_info.private_key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKey(None))?
                    .as_bytes()
                    .to_vec();

                if d.len() != 32 {
                    return Err(CryptoError::InvalidKey(None));
                }

                let x = pk_info
                    .public_key
                    .ok_or(CryptoError::InvalidKey(None))?
                    .raw_bytes()
                    .to_vec();

                if x.len() != 32 {
                    return Err(CryptoError::InvalidKey(None));
                }

                Ok(super::OkpJwkExport { x, d: Some(d) })
            } else {
                // X25519: key_data is raw 32-byte secret
                Ok(super::OkpJwkExport {
                    x: x25519_public_from_raw(key_data)?,
                    d: Some(key_data.to_vec()),
                })
            }
        } else {
            // Public key - key_data is raw bytes
            Ok(super::OkpJwkExport {
                x: key_data.to_vec(),
                d: None,
            })
        }
    }
}
