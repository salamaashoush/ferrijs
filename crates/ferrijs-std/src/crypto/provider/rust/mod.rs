// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU32;

use der::{
    asn1::{BitStringRef, OctetString, OctetStringRef},
    Decode, Encode,
};
use ecdsa::signature::hazmat::PrehashVerifier;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use elliptic_curve::{sec1::ToSec1Point, Generate};
use p256::{
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    },
    SecretKey as P256SecretKey,
};
use p384::{
    ecdsa::{
        Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
    },
    SecretKey as P384SecretKey,
};
use p521::{
    ecdsa::{
        Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
    },
    SecretKey as P521SecretKey,
};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use std::ffi::c_int;

use ecdsa::signature::hazmat::PrehashSigner;
use openssl::bn::BigNum;
use openssl::hash::{Hasher, MessageDigest};
use openssl::cipher::{Cipher as OsslCipher, CipherRef};
use openssl::cipher_ctx::{CipherCtx, CipherCtxFlags};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::md_ctx::MdCtx;
use openssl::md::{Md, MdRef};
use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::RsaPssSaltlen;

use crate::crypto::{
    hash::HashAlgorithm,
    provider::{
        parse_rsa_public_exponent, AesMode, CryptoError, CryptoProvider, HmacProvider, SimpleDigest,
    },
    random_byte_array,
    subtle::EllipticCurve,
};

fn aes_cbc_cipher(key_len: usize) -> Result<Cipher, CryptoError> {
    match key_len {
        16 => Ok(Cipher::aes_128_cbc()),
        24 => Ok(Cipher::aes_192_cbc()),
        32 => Ok(Cipher::aes_256_cbc()),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn aes_gcm_cipher(key_len: usize) -> Result<Cipher, CryptoError> {
    match key_len {
        16 => Ok(Cipher::aes_128_gcm()),
        24 => Ok(Cipher::aes_192_gcm()),
        32 => Ok(Cipher::aes_256_gcm()),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn aes_ecb_cipher(key_len: usize) -> Result<Cipher, CryptoError> {
    match key_len {
        16 => Ok(Cipher::aes_128_ecb()),
        24 => Ok(Cipher::aes_192_ecb()),
        32 => Ok(Cipher::aes_256_ecb()),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn aes_kw_cipher(kek_len: usize) -> Result<&'static CipherRef, CryptoError> {
    match kek_len {
        16 => Ok(OsslCipher::aes_128_wrap()),
        24 => Ok(OsslCipher::aes_192_wrap()),
        32 => Ok(OsslCipher::aes_256_wrap()),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

// The tag lengths WebCrypto allows for AES-GCM.
fn aes_gcm_tag_len(tag_length: u8) -> Result<usize, CryptoError> {
    match tag_length {
        32 | 64 | 96 | 104 | 112 | 120 | 128 => Ok(usize::from(tag_length) / 8),
        _ => Err(CryptoError::InvalidKey(None)),
    }
}

fn openssl_crypt(
    cipher: Cipher,
    mode: Mode,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
    pad: bool,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut crypter = Crypter::new(cipher, mode, key, iv)?;
    crypter.pad(pad);
    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

// OpenSSL gates its key-wrap ciphers behind an explicit flag, and passing no
// IV selects RFC 3394's default integrity value, which is the one WebCrypto's
// AES-KW specifies.
fn aes_kw_crypt(
    cipher: &'static CipherRef,
    encrypt: bool,
    kek: &[u8],
    data: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = CipherCtx::new().map_err(|_| CryptoError::OperationFailed(None))?;
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    if encrypt {
        ctx.encrypt_init(Some(cipher), Some(kek), None)
    } else {
        ctx.decrypt_init(Some(cipher), Some(kek), None)
    }
    .map_err(|_| CryptoError::InvalidKey(None))?;
    ctx.set_padding(false);
    let mut out = Vec::with_capacity(out_len + cipher.block_size());
    ctx.cipher_update_vec(data, &mut out)
        .map_err(|_| CryptoError::OperationFailed(None))?;
    ctx.cipher_final_vec(&mut out)
        .map_err(|_| CryptoError::OperationFailed(None))?;
    if out.len() != out_len {
        return Err(CryptoError::OperationFailed(None));
    }
    Ok(out)
}

// WebCrypto's AES-CTR `length` is the width of the counter field, and the
// counter wraps inside that field alone. OpenSSL's own CTR mode always
// increments the whole 128-bit block, so it cannot express a 32- or 64-bit
// counter; the keystream is built here from ECB instead, which is what CTR is
// defined as, with the increment applied at the requested width.
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
    let cipher = aes_ecb_cipher(key.len())?;
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
        let keystream = openssl_crypt(cipher, Mode::Encrypt, key, None, &counters, false)
            .map_err(|_| CryptoError::EncryptionFailed(None))?;
        for (byte, k) in segment.iter_mut().zip(keystream.iter()) {
            *byte ^= k;
        }
    }
    Ok(out)
}

fn digest_message_digest_checked(algorithm: HashAlgorithm) -> Result<MessageDigest, CryptoError> {
    match algorithm {
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
        other => Ok(digest_message_digest(other)),
    }
}

fn digest_message_digest(algorithm: HashAlgorithm) -> MessageDigest {
    match algorithm {
        HashAlgorithm::Md5 => MessageDigest::md5(),
        HashAlgorithm::Sha1 => MessageDigest::sha1(),
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
        HashAlgorithm::Sha384 => MessageDigest::sha384(),
        HashAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

// HMAC-MD5 has no WebCrypto or Node surface here; the previous provider
// panicked on it and the enum arm has to stay total.
fn hmac_md(algorithm: HashAlgorithm) -> &'static MdRef {
    match algorithm {
        HashAlgorithm::Md5 => Md::md5(),
        HashAlgorithm::Sha1 => Md::sha1(),
        HashAlgorithm::Sha256 => Md::sha256(),
        HashAlgorithm::Sha384 => Md::sha384(),
        HashAlgorithm::Sha512 => Md::sha512(),
    }
}

fn rsa_md(hash_alg: HashAlgorithm) -> Result<&'static MdRef, CryptoError> {
    match hash_alg {
        HashAlgorithm::Sha1 => Ok(Md::sha1()),
        HashAlgorithm::Sha256 => Ok(Md::sha256()),
        HashAlgorithm::Sha384 => Ok(Md::sha384()),
        HashAlgorithm::Sha512 => Ok(Md::sha512()),
        HashAlgorithm::Md5 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn rsa_private_key(private_key_der: &[u8]) -> Result<PKey<openssl::pkey::Private>, CryptoError> {
    let rsa = Rsa::private_key_from_der(private_key_der).map_err(|_| CryptoError::InvalidKey(None))?;
    PKey::from_rsa(rsa).map_err(|_| CryptoError::InvalidKey(None))
}

fn rsa_public_key(public_key_der: &[u8]) -> Result<PKey<openssl::pkey::Public>, CryptoError> {
    let rsa =
        Rsa::public_key_from_der_pkcs1(public_key_der).map_err(|_| CryptoError::InvalidKey(None))?;
    PKey::from_rsa(rsa).map_err(|_| CryptoError::InvalidKey(None))
}

// An empty label and an absent one are the same input to OAEP, and OpenSSL
// rejects a zero-length label rather than treating it as absent.
fn rsa_configure_oaep<T>(
    ctx: &mut PkeyCtx<T>,
    md: &'static MdRef,
    label: Option<&[u8]>,
) -> Result<(), openssl::error::ErrorStack> {
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(md)?;
    ctx.set_rsa_mgf1_md(md)?;
    if let Some(label) = label {
        if !label.is_empty() {
            ctx.set_rsa_oaep_label(label)?;
        }
    }
    Ok(())
}


// Digest and HMAC both run on OpenSSL's EVP layer. `EVP_DigestUpdate` and
// `EVP_DigestSignUpdate` cannot fail once their context is initialised, and the
// algorithm set here is closed, so the only reachable failure is allocation.
// Returning a short or empty digest instead would be a silently wrong answer.
pub struct RustDigest(Hasher);

impl SimpleDigest for RustDigest {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("EVP_DigestUpdate on an initialised context");
    }

    fn finalize(mut self) -> Vec<u8> {
        self.0
            .finish()
            .expect("EVP_DigestFinal on an initialised context")
            .to_vec()
    }
}

pub struct RustHmac {
    ctx: MdCtx,
    // EVP_DigestSignInit keeps the key in the context, so it has to outlive it.
    // Field order is drop order: `ctx` goes first.
    _key: PKey<Private>,
}

impl HmacProvider for RustHmac {
    fn update(&mut self, data: &[u8]) {
        self.ctx
            .digest_sign_update(data)
            .expect("EVP_DigestSignUpdate on an initialised context");
    }

    fn finalize(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.ctx
            .digest_sign_final_to_vec(&mut out)
            .expect("EVP_DigestSignFinal on an initialised context");
        out
    }
}

// Main Crypto Provider
#[derive(Default)]
pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {
    type Digest = RustDigest;
    type Hmac = RustHmac;

    fn digest(&self, algorithm: HashAlgorithm) -> Self::Digest {
        RustDigest(Hasher::new(digest_message_digest(algorithm)).expect("EVP_MD_CTX allocation"))
    }

    fn hmac(&self, algorithm: HashAlgorithm, key: &[u8]) -> Self::Hmac {
        let key = PKey::hmac(key).expect("HMAC key of any length is accepted by EVP_PKEY_new_mac_key");
        let mut ctx = MdCtx::new().expect("EVP_MD_CTX allocation");
        ctx
            .digest_sign_init(Some(hmac_md(algorithm)), &key)
            .expect("EVP_DigestSignInit with a known digest and a MAC key");
        RustHmac { ctx, _key: key }
    }

    fn ecdsa_sign(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        digest: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match curve {
            EllipticCurve::P256 => {
                let secret_key = P256SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let signing_key = P256SigningKey::from(secret_key);
                let signature: p256::ecdsa::Signature = signing_key
                    .sign_prehash(digest)
                    .map_err(|_| CryptoError::SigningFailed(None))?;
                Ok(signature.to_bytes().to_vec())
            },
            EllipticCurve::P384 => {
                let secret_key = P384SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let signing_key = P384SigningKey::from(secret_key);
                let signature: p384::ecdsa::Signature = signing_key
                    .sign_prehash(digest)
                    .map_err(|_| CryptoError::SigningFailed(None))?;
                Ok(signature.to_bytes().to_vec())
            },
            EllipticCurve::P521 => {
                let secret_key = P521SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let signing_key = P521SigningKey::from(secret_key);
                let signature: p521::ecdsa::Signature = signing_key
                    .sign_prehash(digest)
                    .map_err(|_| CryptoError::SigningFailed(None))?;
                Ok(signature.to_bytes().to_vec())
            },
        }
    }

    fn ecdsa_verify(
        &self,
        curve: EllipticCurve,
        public_key_sec1: &[u8],
        signature: &[u8],
        digest: &[u8],
    ) -> Result<bool, CryptoError> {
        match curve {
            EllipticCurve::P256 => {
                let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_sec1)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let sig = P256Signature::from_slice(signature)
                    .map_err(|_| CryptoError::InvalidSignature(None))?;
                Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
            },
            EllipticCurve::P384 => {
                let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_sec1)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let sig = P384Signature::from_slice(signature)
                    .map_err(|_| CryptoError::InvalidSignature(None))?;
                Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
            },
            EllipticCurve::P521 => {
                let verifying_key = P521VerifyingKey::from_sec1_bytes(public_key_sec1)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let sig = P521Signature::from_slice(signature)
                    .map_err(|_| CryptoError::InvalidSignature(None))?;
                Ok(verifying_key.verify_prehash(digest, &sig).is_ok())
            },
        }
    }

    fn ed25519_sign(&self, private_key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let signature = signing_key
            .try_sign(data)
            .map_err(|_| CryptoError::InvalidSignature(None))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, CryptoError> {
        let public_key = VerifyingKey::from_bytes(
            public_key_bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidKey(None))?,
        )
        .map_err(|_| CryptoError::InvalidKey(None))?;
        let signature = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature(None))?,
        );
        Ok(public_key.verify_strict(data, &signature).is_ok())
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let key = rsa_private_key(private_key_der)?;
        let mut ctx = PkeyCtx::new(&key).map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.sign_init().map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.set_signature_md(md)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.set_rsa_mgf1_md(md)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        let salt = c_int::try_from(salt_length).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt))
            .map_err(|_| CryptoError::SigningFailed(None))?;
        let mut signature = Vec::new();
        ctx.sign_to_vec(digest, &mut signature)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        Ok(signature)
    }

    fn rsa_pss_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        digest: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let key = rsa_public_key(public_key_der)?;
        let mut ctx = PkeyCtx::new(&key).map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.verify_init().map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.set_signature_md(md)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.set_rsa_mgf1_md(md)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let salt = c_int::try_from(salt_length).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt))
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(ctx.verify(digest, signature).unwrap_or(false))
    }

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let key = rsa_private_key(private_key_der)?;
        let mut ctx = PkeyCtx::new(&key).map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.sign_init().map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.set_rsa_padding(Padding::PKCS1)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        ctx.set_signature_md(md)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        let mut signature = Vec::new();
        ctx.sign_to_vec(digest, &mut signature)
            .map_err(|_| CryptoError::SigningFailed(None))?;
        Ok(signature)
    }

    fn rsa_pkcs1v15_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        digest: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let key = rsa_public_key(public_key_der)?;
        let mut ctx = PkeyCtx::new(&key).map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.verify_init().map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.set_rsa_padding(Padding::PKCS1)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        ctx.set_signature_md(md)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        Ok(ctx.verify(digest, signature).unwrap_or(false))
    }

    fn rsa_oaep_encrypt(
        &self,
        public_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let key = rsa_public_key(public_key_der)?;
        let mut ctx = PkeyCtx::new(&key).map_err(|_| CryptoError::EncryptionFailed(None))?;
        ctx.encrypt_init()
            .map_err(|_| CryptoError::EncryptionFailed(None))?;
        rsa_configure_oaep(&mut ctx, md, label).map_err(|_| CryptoError::EncryptionFailed(None))?;
        let mut out = Vec::new();
        ctx.encrypt_to_vec(data, &mut out)
            .map_err(|_| CryptoError::EncryptionFailed(None))?;
        Ok(out)
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let key = rsa_private_key(private_key_der)?;
        let mut ctx = PkeyCtx::new(&key).map_err(|_| CryptoError::DecryptionFailed(None))?;
        ctx.decrypt_init()
            .map_err(|_| CryptoError::DecryptionFailed(None))?;
        rsa_configure_oaep(&mut ctx, md, label).map_err(|_| CryptoError::DecryptionFailed(None))?;
        let mut out = Vec::new();
        ctx.decrypt_to_vec(data, &mut out)
            .map_err(|_| CryptoError::DecryptionFailed(None))?;
        Ok(out)
    }

    fn ecdh_derive_bits(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        public_key_sec1: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match curve {
            EllipticCurve::P256 => {
                let secret_key = P256SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let public_key = p256::PublicKey::from_sec1_bytes(public_key_sec1)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let shared_secret = p256::elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                );
                Ok(shared_secret.raw_secret_bytes().to_vec())
            },
            EllipticCurve::P384 => {
                let secret_key = P384SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let public_key = p384::PublicKey::from_sec1_bytes(public_key_sec1)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let shared_secret = p384::elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                );
                Ok(shared_secret.raw_secret_bytes().to_vec())
            },
            EllipticCurve::P521 => {
                let secret_key = P521SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let public_key = p521::PublicKey::from_sec1_bytes(public_key_sec1)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                let shared_secret = p521::elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                );
                Ok(shared_secret.raw_secret_bytes().to_vec())
            },
        }
    }

    fn x25519_derive_bits(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let private_array: [u8; 32] = private_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let public_array: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKey(None))?;

        let secret_key = x25519_dalek::StaticSecret::from(private_array);
        let public_key = x25519_dalek::PublicKey::from(public_array);
        let shared_secret = secret_key.diffie_hellman(&public_key);

        if shared_secret.as_bytes().iter().all(|b| *b == 0) {
            return Err(CryptoError::OperationFailed(None));
        }

        Ok(shared_secret.as_bytes().to_vec())
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
            AesMode::Cbc => {
                let cipher = aes_cbc_cipher(key.len())?;
                openssl_crypt(cipher, Mode::Encrypt, key, Some(iv), data, true)
                    .map_err(|_| CryptoError::EncryptionFailed(None))
            },
            AesMode::Ctr { counter_length } => aes_ctr_apply(key, iv, counter_length, data),
            AesMode::Gcm { tag_length } => {
                let cipher = aes_gcm_cipher(key.len())?;
                let tag_len = aes_gcm_tag_len(tag_length)?;
                let mut tag = vec![0u8; tag_len];
                let mut ciphertext = openssl::symm::encrypt_aead(
                    cipher,
                    key,
                    Some(iv),
                    additional_data.unwrap_or_default(),
                    data,
                    &mut tag,
                )
                .map_err(|_| CryptoError::EncryptionFailed(None))?;
                // WebCrypto returns the tag appended to the ciphertext.
                ciphertext.extend_from_slice(&tag);
                Ok(ciphertext)
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
            AesMode::Cbc => {
                let cipher = aes_cbc_cipher(key.len())?;
                openssl_crypt(cipher, Mode::Decrypt, key, Some(iv), data, true)
                    .map_err(|_| CryptoError::DecryptionFailed(None))
            },
            AesMode::Ctr { counter_length } => aes_ctr_apply(key, iv, counter_length, data),
            AesMode::Gcm { tag_length } => {
                let cipher = aes_gcm_cipher(key.len())?;
                let tag_len = aes_gcm_tag_len(tag_length)?;
                if data.len() < tag_len {
                    return Err(CryptoError::DecryptionFailed(None));
                }
                let (ciphertext, tag) = data.split_at(data.len() - tag_len);
                openssl::symm::decrypt_aead(
                    cipher,
                    key,
                    Some(iv),
                    additional_data.unwrap_or_default(),
                    ciphertext,
                    tag,
                )
                .map_err(|_| CryptoError::DecryptionFailed(None))
            },
        }
    }

    fn aes_kw_wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = aes_kw_cipher(kek.len())?;
        // RFC 3394 prepends the 8-byte integrity value, so the output is one
        // block longer than the input.
        aes_kw_crypt(cipher, true, kek, key, key.len() + 8)
    }

    fn aes_kw_unwrap(&self, kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = aes_kw_cipher(kek.len())?;
        let out_len = wrapped_key
            .len()
            .checked_sub(8)
            .ok_or(CryptoError::OperationFailed(None))?;
        aes_kw_crypt(cipher, false, kek, wrapped_key, out_len)
    }

    fn hkdf_derive_key(
        &self,
        key: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = rsa_md(hash_alg)?;
        let mut out = vec![0u8; length];
        openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::HKDF)
            .and_then(|mut ctx| {
                ctx.derive_init()?;
                ctx.set_hkdf_md(md)?;
                ctx.set_hkdf_key(key)?;
                ctx.set_hkdf_salt(salt)?;
                ctx.add_hkdf_info(info)?;
                ctx.derive(Some(&mut out))?;
                Ok(())
            })
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
        let iterations = NonZeroU32::new(iterations).ok_or(CryptoError::InvalidData(None))?;
        let digest = digest_message_digest_checked(hash_alg)?;
        let mut out = vec![0; length];
        let iter = usize::try_from(iterations.get()).map_err(|_| CryptoError::InvalidData(None))?;
        openssl::pkcs5::pbkdf2_hmac(password, salt, iter, digest, &mut out)
            .map_err(|_| CryptoError::InvalidLength)?;
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
        let mut rng = rand::rng();

        match curve {
            EllipticCurve::P256 => {
                let key = P256SecretKey::try_generate_from_rng(&mut rng)
                    .map_err(|_| CryptoError::OperationFailed(None))?;
                let pkcs8 = key
                    .to_pkcs8_der()
                    .map_err(|_| CryptoError::OperationFailed(None))?;
                let private_key = pkcs8.as_bytes().to_vec();
                let public_key = key.public_key().to_sec1_bytes().to_vec();
                Ok((private_key, public_key))
            },
            EllipticCurve::P384 => {
                let key = P384SecretKey::try_generate_from_rng(&mut rng)
                    .map_err(|_| CryptoError::OperationFailed(None))?;
                let pkcs8 = key
                    .to_pkcs8_der()
                    .map_err(|_| CryptoError::OperationFailed(None))?;
                let private_key = pkcs8.as_bytes().to_vec();
                let public_key = key.public_key().to_sec1_bytes().to_vec();
                Ok((private_key, public_key))
            },
            EllipticCurve::P521 => {
                let key = P521SecretKey::try_generate_from_rng(&mut rng)
                    .map_err(|_| CryptoError::OperationFailed(None))?;
                let pkcs8 = key
                    .to_pkcs8_der()
                    .map_err(|_| CryptoError::OperationFailed(None))?;
                let private_key = pkcs8.as_bytes().to_vec();
                let public_key = key.public_key().to_sec1_bytes().to_vec();
                Ok((private_key, public_key))
            },
        }
    }

    fn generate_ed25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = rand::rng();
        let private_key = ed25519_dalek::SigningKey::generate(&mut rng)
            .to_pkcs8_der()
            .map_err(|_| CryptoError::OperationFailed(None))?
            .as_bytes()
            .to_vec();
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(&private_key)
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        Ok((private_key, public_key))
    }

    fn generate_x25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = rand::rng();
        let secret_key = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let private_key = secret_key.as_bytes().to_vec();
        let public_key = x25519_dalek::PublicKey::from(&secret_key)
            .as_bytes()
            .to_vec();
        Ok((private_key, public_key))
    }

    fn generate_rsa_key(
        &self,
        modulus_length: u32,
        public_exponent: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let exponent = parse_rsa_public_exponent(public_exponent)?;
        let e = BigNum::from_u32(u32::try_from(exponent).map_err(|_| CryptoError::OperationFailed(None))?)
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let key = Rsa::generate_with_e(modulus_length, &e)
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let private_key = key
            .private_key_to_der()
            .map_err(|_| CryptoError::OperationFailed(None))?;
        let public_key = key
            .public_key_to_der_pkcs1()
            .map_err(|_| CryptoError::OperationFailed(None))?;
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
        let rsa = Rsa::private_key_from_der(key_data).map_err(|_| CryptoError::InvalidKey(None))?;
        let key = PKey::from_rsa(rsa).map_err(|_| CryptoError::InvalidKey(None))?;
        key
            .private_key_to_pkcs8()
            .map_err(|_| CryptoError::InvalidKey(None))
    }

    fn import_ec_public_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<super::EcImportResult, CryptoError> {
        let key_data = match curve {
            EllipticCurve::P256 => {
                let public_key = p256::PublicKey::from_sec1_bytes(data)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                public_key.to_sec1_point(false).as_bytes().to_vec()
            },
            EllipticCurve::P384 => {
                let public_key = p384::PublicKey::from_sec1_bytes(data)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                public_key.to_sec1_point(false).as_bytes().to_vec()
            },
            EllipticCurve::P521 => {
                let public_key = p521::PublicKey::from_sec1_bytes(data)
                    .map_err(|_| CryptoError::InvalidKey(None))?;
                public_key.to_sec1_point(false).as_bytes().to_vec()
            },
        };

        Ok(super::EcImportResult {
            key_data,
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
        // Convert SEC1 private key to PKCS8
        let pkcs8_der = match curve {
            EllipticCurve::P256 => {
                let key =
                    P256SecretKey::from_slice(data).map_err(|_| CryptoError::InvalidKey(None))?;
                key.to_pkcs8_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?
                    .as_bytes()
                    .to_vec()
            },
            EllipticCurve::P384 => {
                let key =
                    P384SecretKey::from_slice(data).map_err(|_| CryptoError::InvalidKey(None))?;
                key.to_pkcs8_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?
                    .as_bytes()
                    .to_vec()
            },
            EllipticCurve::P521 => {
                let key =
                    P521SecretKey::from_slice(data).map_err(|_| CryptoError::InvalidKey(None))?;
                key.to_pkcs8_der()
                    .map_err(|_| CryptoError::InvalidKey(None))?
                    .as_bytes()
                    .to_vec()
            },
        };
        Ok(super::EcImportResult {
            key_data: pkcs8_der,
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
            // Extract public key from PKCS8 private key
            match curve {
                EllipticCurve::P256 => {
                    let key = P256SecretKey::from_pkcs8_der(key_data)
                        .map_err(|_| CryptoError::InvalidKey(None))?;
                    Ok(key.public_key().to_sec1_point(false).as_bytes().to_vec())
                },
                EllipticCurve::P384 => {
                    let key = P384SecretKey::from_pkcs8_der(key_data)
                        .map_err(|_| CryptoError::InvalidKey(None))?;
                    Ok(key.public_key().to_sec1_point(false).as_bytes().to_vec())
                },
                EllipticCurve::P521 => {
                    let key = P521SecretKey::from_pkcs8_der(key_data)
                        .map_err(|_| CryptoError::InvalidKey(None))?;
                    Ok(key.public_key().to_sec1_point(false).as_bytes().to_vec())
                },
            }
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
        use der::Encode;
        use elliptic_curve::pkcs8::AssociatedOid;
        let curve_oid = match curve {
            EllipticCurve::P256 => p256::NistP256::OID,
            EllipticCurve::P384 => p384::NistP384::OID,
            EllipticCurve::P521 => p521::NistP521::OID,
        };
        let spki = spki::SubjectPublicKeyInfo {
            algorithm: spki::AlgorithmIdentifier::<der::asn1::ObjectIdentifier> {
                oid: elliptic_curve::ALGORITHM_OID,
                parameters: Some(curve_oid),
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
            let bytes: [u8; 32] = seed.try_into().map_err(|_| CryptoError::InvalidKey(None))?;
            let secret = x25519_dalek::StaticSecret::from(bytes);
            let public = x25519_dalek::PublicKey::from(&secret);
            Ok(public.as_bytes().to_vec())
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
            // Private key - convert to PKCS8
            let pkcs8_der = match curve {
                EllipticCurve::P256 => {
                    let key =
                        P256SecretKey::from_slice(d).map_err(|_| CryptoError::InvalidKey(None))?;
                    key.to_pkcs8_der()
                        .map_err(|_| CryptoError::InvalidKey(None))?
                        .as_bytes()
                        .to_vec()
                },
                EllipticCurve::P384 => {
                    let key =
                        P384SecretKey::from_slice(d).map_err(|_| CryptoError::InvalidKey(None))?;
                    key.to_pkcs8_der()
                        .map_err(|_| CryptoError::InvalidKey(None))?
                        .as_bytes()
                        .to_vec()
                },
                EllipticCurve::P521 => {
                    let key =
                        P521SecretKey::from_slice(d).map_err(|_| CryptoError::InvalidKey(None))?;
                    key.to_pkcs8_der()
                        .map_err(|_| CryptoError::InvalidKey(None))?
                        .as_bytes()
                        .to_vec()
                },
            };
            Ok(super::EcImportResult {
                key_data: pkcs8_der,
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
        let coord_len = match curve {
            EllipticCurve::P256 => 32,
            EllipticCurve::P384 => 48,
            EllipticCurve::P521 => 66,
        };
        if is_private {
            // key_data is PKCS8 - use elliptic_curve's SecretKey to parse it
            let (x, y, d) = match curve {
                EllipticCurve::P256 => {
                    let sk = P256SecretKey::from_pkcs8_der(key_data)
                        .map_err(|_| CryptoError::InvalidKey(None))?;
                    let pk = sk.public_key();
                    let pt = pk.to_sec1_point(false);
                    (
                        pt.x().unwrap().to_vec(),
                        pt.y().unwrap().to_vec(),
                        sk.to_bytes().to_vec(),
                    )
                },
                EllipticCurve::P384 => {
                    let sk = P384SecretKey::from_pkcs8_der(key_data)
                        .map_err(|_| CryptoError::InvalidKey(None))?;
                    let pk = sk.public_key();
                    let pt = pk.to_sec1_point(false);
                    (
                        pt.x().unwrap().to_vec(),
                        pt.y().unwrap().to_vec(),
                        sk.to_bytes().to_vec(),
                    )
                },
                EllipticCurve::P521 => {
                    let sk = P521SecretKey::from_pkcs8_der(key_data)
                        .map_err(|_| CryptoError::InvalidKey(None))?;
                    let pk = sk.public_key();
                    let pt = pk.to_sec1_point(false);
                    (
                        pt.x().unwrap().to_vec(),
                        pt.y().unwrap().to_vec(),
                        sk.to_bytes().to_vec(),
                    )
                },
            };
            Ok(super::EcJwkExport { x, y, d: Some(d) })
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
                let secret = x25519_dalek::StaticSecret::from(
                    <[u8; 32]>::try_from(key_data).map_err(|_| CryptoError::InvalidKey(None))?,
                );
                let public = x25519_dalek::PublicKey::from(&secret);
                Ok(super::OkpJwkExport {
                    x: public.as_bytes().to_vec(),
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
