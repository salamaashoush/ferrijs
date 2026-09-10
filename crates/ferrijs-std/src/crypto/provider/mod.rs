// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Ensure only one crypto provider is selected
#[cfg(all(feature = "crypto-rust", feature = "crypto-openssl"))]
compile_error!("Features `crypto-rust` and `crypto-openssl` are mutually exclusive");

#[cfg(all(feature = "crypto-rust", feature = "crypto-ring"))]
compile_error!("Features `crypto-rust` and `crypto-ring` are mutually exclusive");

#[cfg(all(feature = "crypto-rust", feature = "crypto-graviola"))]
compile_error!("Features `crypto-rust` and `crypto-graviola` are mutually exclusive");

#[cfg(all(feature = "crypto-ring", feature = "crypto-openssl"))]
compile_error!("Features `crypto-ring` and `crypto-openssl` are mutually exclusive");

#[cfg(all(feature = "crypto-ring", feature = "crypto-graviola"))]
compile_error!("Features `crypto-ring` and `crypto-graviola` are mutually exclusive");

#[cfg(all(feature = "crypto-openssl", feature = "crypto-graviola"))]
compile_error!("Features `crypto-openssl` and `crypto-graviola` are mutually exclusive");

#[cfg(all(feature = "crypto-ring-rust", feature = "crypto-graviola-rust"))]
compile_error!("Features `crypto-ring-rust` and `crypto-graviola-rust` are mutually exclusive");

#[cfg(any(feature = "crypto-graviola", feature = "crypto-graviola-rust"))]
mod graviola;

#[cfg(feature = "crypto-openssl")]
mod openssl;

#[cfg(any(feature = "crypto-ring", feature = "crypto-ring-rust"))]
mod ring;

#[cfg(feature = "_modern-webcrypto")]
pub(crate) mod modern;

#[cfg(feature = "_rustcrypto")]
mod rust;

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::subtle::EllipticCurve;
use crate::str_enum;

#[derive(Debug)]
#[allow(dead_code)]
pub struct RsaImportResult {
    pub key_data: Vec<u8>,
    pub modulus_length: u32,
    pub public_exponent: Vec<u8>,
    pub is_private: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct EcImportResult {
    pub key_data: Vec<u8>,
    pub is_private: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct OkpImportResult {
    pub key_data: Vec<u8>,
    pub is_private: bool,
}

/// RSA JWK components for import (all values are raw bytes, not base64)
#[derive(Debug)]
#[allow(dead_code)]
pub struct RsaJwkImport<'a> {
    pub n: &'a [u8],          // modulus
    pub e: &'a [u8],          // public exponent
    pub d: Option<&'a [u8]>,  // private exponent
    pub p: Option<&'a [u8]>,  // first prime
    pub q: Option<&'a [u8]>,  // second prime
    pub dp: Option<&'a [u8]>, // first factor CRT exponent
    pub dq: Option<&'a [u8]>, // second factor CRT exponent
    pub qi: Option<&'a [u8]>, // first CRT coefficient
}

/// RSA JWK components for export
#[derive(Debug)]
#[allow(dead_code)]
pub struct RsaJwkExport {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Option<Vec<u8>>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub dp: Option<Vec<u8>>,
    pub dq: Option<Vec<u8>>,
    pub qi: Option<Vec<u8>>,
}

/// EC JWK components for import (all values are raw bytes)
#[derive(Debug)]
#[allow(dead_code)]
pub struct EcJwkImport<'a> {
    pub x: &'a [u8],
    pub y: &'a [u8],
    pub d: Option<&'a [u8]>,
}

/// EC JWK components for export
#[derive(Debug)]
#[allow(dead_code)]
pub struct EcJwkExport {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    pub d: Option<Vec<u8>>,
}

/// OKP (Ed25519/X25519) JWK components for import
#[derive(Debug)]
#[allow(dead_code)]
pub struct OkpJwkImport<'a> {
    pub x: &'a [u8],         // public key
    pub d: Option<&'a [u8]>, // private key
}

/// OKP JWK components for export
#[derive(Debug)]
#[allow(dead_code)]
pub struct OkpJwkExport {
    pub x: Vec<u8>,
    pub d: Option<Vec<u8>>,
}

pub trait SimpleDigest: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>
    where
        Self: Sized;
}

pub const MAX_HMAC_KEY_LENGTH_BITS: u32 = 1024;
pub(crate) fn hmac_length_is_byte_aligned(length_bits: u32) -> bool {
    length_bits.is_multiple_of(8)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

str_enum!(
    MlDsaVariant,
    MlDsa44 => "ML-DSA-44",
    MlDsa65 => "ML-DSA-65",
    MlDsa87 => "ML-DSA-87"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

str_enum!(
    MlKemVariant,
    MlKem512 => "ML-KEM-512",
    MlKem768 => "ML-KEM-768",
    MlKem1024 => "ML-KEM-1024"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridKemVariant {
    MlKem768P256,
    MlKem768X25519,
    MlKem1024P384,
}

str_enum!(
    HybridKemVariant,
    MlKem768P256 => "MLKEM768-P256",
    MlKem768X25519 => "MLKEM768-X25519",
    MlKem1024P384 => "MLKEM1024-P384"
);

impl HybridKemVariant {
    pub const fn ml_kem_variant(self) -> MlKemVariant {
        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 => MlKemVariant::MlKem768,
            Self::MlKem1024P384 => MlKemVariant::MlKem1024,
        }
    }

    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 1249,
            Self::MlKem768X25519 => 1216,
            Self::MlKem1024P384 => 1665,
        }
    }

    pub const fn ciphertext_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 1153,
            Self::MlKem768X25519 => 1120,
            Self::MlKem1024P384 => 1665,
        }
    }

    pub const fn pq_public_key_length(self) -> usize {
        match self.ml_kem_variant() {
            MlKemVariant::MlKem768 => 1184,
            MlKemVariant::MlKem1024 => 1568,
            MlKemVariant::MlKem512 => unreachable!(),
        }
    }

    pub const fn pq_ciphertext_length(self) -> usize {
        match self.ml_kem_variant() {
            MlKemVariant::MlKem768 => 1088,
            MlKemVariant::MlKem1024 => 1568,
            MlKemVariant::MlKem512 => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AesMode {
    Ctr { counter_length: u32 },
    Cbc,
    Gcm { tag_length: u8 },
}

#[allow(dead_code)]
pub trait CryptoProvider {
    type Digest: SimpleDigest;
    type Hmac: HmacProvider;

    // Digest operations
    fn digest(&self, algorithm: HashAlgorithm) -> Self::Digest;

    // HMAC operations
    fn hmac(&self, algorithm: HashAlgorithm, key: &[u8]) -> Self::Hmac;

    // ECDSA operations
    fn ecdsa_sign(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        digest: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn ecdsa_verify(
        &self,
        curve: EllipticCurve,
        public_key_sec1: &[u8],
        signature: &[u8],
        digest: &[u8],
    ) -> Result<bool, CryptoError>;

    // EdDSA operations
    fn ed25519_sign(&self, private_key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, CryptoError>;

    // RSA operations
    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError>;
    fn rsa_pss_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        digest: &[u8],
        salt_length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError>;
    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError>;
    fn rsa_pkcs1v15_verify(
        &self,
        public_key_der: &[u8],
        signature: &[u8],
        digest: &[u8],
        hash_alg: HashAlgorithm,
    ) -> Result<bool, CryptoError>;
    fn rsa_oaep_encrypt(
        &self,
        public_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;
    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlgorithm,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;

    // ECDH operations
    fn ecdh_derive_bits(
        &self,
        curve: EllipticCurve,
        private_key_der: &[u8],
        public_key_sec1: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    // X25519 operations
    fn x25519_derive_bits(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    // AES operations
    fn aes_encrypt(
        &self,
        mode: AesMode,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;
    fn aes_decrypt(
        &self,
        mode: AesMode,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;

    // AES-KW operations
    fn aes_kw_wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn aes_kw_unwrap(&self, kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError>;

    // KDF operations
    fn hkdf_derive_key(
        &self,
        key: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError>;
    fn pbkdf2_derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        length: usize,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError>;

    fn generate_aes_key(&self, length_bits: u16) -> Result<Vec<u8>, CryptoError>;
    fn generate_hmac_key(
        &self,
        hash_alg: HashAlgorithm,
        length_bits: u16,
    ) -> Result<Vec<u8>, CryptoError>;
    fn generate_ec_key(&self, curve: EllipticCurve) -> Result<(Vec<u8>, Vec<u8>), CryptoError>; // (private, public)
    fn generate_ed25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    fn generate_x25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    fn generate_rsa_key(
        &self,
        modulus_length: u32,
        public_exponent: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    // RSA key import from DER formats
    fn import_rsa_public_key_pkcs1(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError>;
    fn import_rsa_private_key_pkcs1(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError>;
    fn import_rsa_public_key_spki(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError>;
    fn import_rsa_private_key_pkcs8(&self, der: &[u8]) -> Result<RsaImportResult, CryptoError>;

    // RSA key export to DER formats
    fn export_rsa_public_key_pkcs1(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn export_rsa_public_key_spki(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn export_rsa_private_key_pkcs8(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    // EC key import from DER formats
    fn import_ec_public_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError>;
    fn import_ec_public_key_spki(
        &self,
        der: &[u8],
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError>;
    fn import_ec_private_key_pkcs8(&self, der: &[u8]) -> Result<EcImportResult, CryptoError>;
    fn import_ec_private_key_sec1(
        &self,
        data: &[u8],
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError>;

    // EC key export
    fn export_ec_public_key_sec1(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
        is_private: bool,
    ) -> Result<Vec<u8>, CryptoError>;
    fn export_ec_public_key_spki(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
    ) -> Result<Vec<u8>, CryptoError>;
    fn export_ec_private_key_pkcs8(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
    ) -> Result<Vec<u8>, CryptoError>;

    // OKP (Ed25519/X25519) key import
    fn import_okp_public_key_raw(&self, data: &[u8]) -> Result<OkpImportResult, CryptoError>;
    fn import_okp_public_key_spki(
        &self,
        der: &[u8],
        expected_oid: &[u8],
    ) -> Result<OkpImportResult, CryptoError>;
    fn import_okp_private_key_pkcs8(
        &self,
        der: &[u8],
        expected_oid: &[u8],
    ) -> Result<OkpImportResult, CryptoError>;

    // OKP key export
    fn export_okp_public_key_raw(
        &self,
        key_data: &[u8],
        is_private: bool,
    ) -> Result<Vec<u8>, CryptoError>;
    fn export_okp_public_key_spki(
        &self,
        key_data: &[u8],
        oid: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn export_okp_private_key_pkcs8(
        &self,
        key_data: &[u8],
        oid: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    // JWK import/export
    fn import_rsa_jwk(&self, jwk: RsaJwkImport<'_>) -> Result<RsaImportResult, CryptoError>;
    fn export_rsa_jwk(
        &self,
        key_data: &[u8],
        is_private: bool,
    ) -> Result<RsaJwkExport, CryptoError>;
    fn import_ec_jwk(
        &self,
        jwk: EcJwkImport<'_>,
        curve: EllipticCurve,
    ) -> Result<EcImportResult, CryptoError>;
    fn export_ec_jwk(
        &self,
        key_data: &[u8],
        curve: EllipticCurve,
        is_private: bool,
    ) -> Result<EcJwkExport, CryptoError>;

    // OKP JWK import/export
    fn import_okp_jwk(
        &self,
        jwk: OkpJwkImport<'_>,
        is_ed25519: bool,
    ) -> Result<OkpImportResult, CryptoError>;
    fn export_okp_jwk(
        &self,
        key_data: &[u8],
        is_private: bool,
        is_ed25519: bool,
    ) -> Result<OkpJwkExport, CryptoError>;
}

pub trait HmacProvider: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>
    where
        Self: Sized;
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum CryptoError {
    InvalidKey(Option<Box<str>>),
    InvalidData(Option<Box<str>>),
    InvalidSignature(Option<Box<str>>),
    InvalidLength,
    SigningFailed(Option<Box<str>>),
    VerificationFailed,
    OperationFailed(Option<Box<str>>),
    UnsupportedAlgorithm,
    DerivationFailed(Option<Box<str>>),
    EncryptionFailed(Option<Box<str>>),
    DecryptionFailed(Option<Box<str>>),
    InvalidAccess(Option<Box<str>>),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKey(None) => write!(f, "Invalid key"),
            CryptoError::InvalidKey(Some(msg)) => write!(f, "Invalid key: {}", msg),
            CryptoError::InvalidData(None) => write!(f, "Invalid data"),
            CryptoError::InvalidData(Some(msg)) => write!(f, "Invalid data: {}", msg),
            CryptoError::InvalidSignature(None) => write!(f, "Invalid signature"),
            CryptoError::InvalidSignature(Some(msg)) => write!(f, "Invalid signature: {}", msg),
            CryptoError::InvalidLength => write!(f, "Invalid length"),
            CryptoError::SigningFailed(None) => write!(f, "Signing failed"),
            CryptoError::SigningFailed(Some(msg)) => write!(f, "Signing failed: {}", msg),
            CryptoError::VerificationFailed => write!(f, "Verification failed"),
            CryptoError::OperationFailed(None) => write!(f, "Operation failed"),
            CryptoError::OperationFailed(Some(msg)) => write!(f, "Operation failed: {}", msg),
            CryptoError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
            CryptoError::DerivationFailed(None) => write!(f, "Derivation failed"),
            CryptoError::DerivationFailed(Some(msg)) => write!(f, "Derivation failed: {}", msg),
            CryptoError::EncryptionFailed(None) => write!(f, "Encryption failed"),
            CryptoError::EncryptionFailed(Some(msg)) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(None) => write!(f, "Decryption failed"),
            CryptoError::DecryptionFailed(Some(msg)) => write!(f, "Decryption failed: {}", msg),
            CryptoError::InvalidAccess(None) => write!(f, "Invalid access"),
            CryptoError::InvalidAccess(Some(msg)) => write!(f, "Invalid access: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn parse_rsa_public_exponent(public_exponent: &[u8]) -> Result<u64, CryptoError> {
    match public_exponent {
        [0x01, 0x00, 0x01] => Ok(65537),
        [0x03] => Ok(3),
        bytes if bytes.ends_with(&[0x03]) && bytes[..bytes.len() - 1].iter().all(|&b| b == 0) => {
            Ok(3)
        },
        _ => Err(CryptoError::OperationFailed(None)),
    }
}

#[cfg(feature = "crypto-openssl")]
pub type DefaultProvider = openssl::OpenSslProvider;

#[cfg(feature = "crypto-rust")]
pub type DefaultProvider = rust::RustCryptoProvider;

#[cfg(feature = "crypto-ring")]
pub type DefaultProvider = ring::RingProvider;

#[cfg(feature = "crypto-ring-rust")]
pub type DefaultProvider = RingRustProvider;

#[cfg(all(feature = "crypto-graviola", not(feature = "crypto-graviola-rust")))]
pub type DefaultProvider = graviola::GraviolaProvider;

#[cfg(feature = "crypto-graviola-rust")]
pub type DefaultProvider = GraviolaRustProvider;

// Macro to generate hybrid providers that delegate to RustCrypto
#[cfg(any(feature = "crypto-ring-rust", feature = "crypto-graviola-rust"))]
macro_rules! impl_hybrid_provider {
    ($name:ident, $digest:ty, $hmac:ty, $digest_fn:expr, $hmac_fn:expr, $aes_encrypt:expr, $aes_decrypt:expr) => {
        pub struct $name;
        impl CryptoProvider for $name {
            type Digest = $digest;
            type Hmac = $hmac;
            fn digest(&self, alg: HashAlgorithm) -> Self::Digest {
                $digest_fn(alg)
            }
            fn hmac(&self, alg: HashAlgorithm, key: &[u8]) -> Self::Hmac {
                $hmac_fn(alg, key)
            }
            fn ecdsa_sign(
                &self,
                c: EllipticCurve,
                k: &[u8],
                d: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.ecdsa_sign(c, k, d)
            }
            fn ecdsa_verify(
                &self,
                c: EllipticCurve,
                k: &[u8],
                s: &[u8],
                d: &[u8],
            ) -> Result<bool, CryptoError> {
                rust::RustCryptoProvider.ecdsa_verify(c, k, s, d)
            }
            fn ed25519_sign(&self, k: &[u8], d: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.ed25519_sign(k, d)
            }
            fn ed25519_verify(&self, k: &[u8], s: &[u8], d: &[u8]) -> Result<bool, CryptoError> {
                rust::RustCryptoProvider.ed25519_verify(k, s, d)
            }
            fn rsa_pss_sign(
                &self,
                k: &[u8],
                d: &[u8],
                s: usize,
                a: HashAlgorithm,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.rsa_pss_sign(k, d, s, a)
            }
            fn rsa_pss_verify(
                &self,
                k: &[u8],
                s: &[u8],
                d: &[u8],
                sl: usize,
                a: HashAlgorithm,
            ) -> Result<bool, CryptoError> {
                rust::RustCryptoProvider.rsa_pss_verify(k, s, d, sl, a)
            }
            fn rsa_pkcs1v15_sign(
                &self,
                k: &[u8],
                d: &[u8],
                a: HashAlgorithm,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.rsa_pkcs1v15_sign(k, d, a)
            }
            fn rsa_pkcs1v15_verify(
                &self,
                k: &[u8],
                s: &[u8],
                d: &[u8],
                a: HashAlgorithm,
            ) -> Result<bool, CryptoError> {
                rust::RustCryptoProvider.rsa_pkcs1v15_verify(k, s, d, a)
            }
            fn rsa_oaep_encrypt(
                &self,
                k: &[u8],
                d: &[u8],
                a: HashAlgorithm,
                l: Option<&[u8]>,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.rsa_oaep_encrypt(k, d, a, l)
            }
            fn rsa_oaep_decrypt(
                &self,
                k: &[u8],
                d: &[u8],
                a: HashAlgorithm,
                l: Option<&[u8]>,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.rsa_oaep_decrypt(k, d, a, l)
            }
            fn ecdh_derive_bits(
                &self,
                c: EllipticCurve,
                pk: &[u8],
                pubk: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.ecdh_derive_bits(c, pk, pubk)
            }
            fn x25519_derive_bits(&self, pk: &[u8], pubk: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.x25519_derive_bits(pk, pubk)
            }
            fn aes_encrypt(
                &self,
                m: AesMode,
                k: &[u8],
                iv: &[u8],
                d: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<Vec<u8>, CryptoError> {
                $aes_encrypt(m, k, iv, d, aad)
            }
            fn aes_decrypt(
                &self,
                m: AesMode,
                k: &[u8],
                iv: &[u8],
                d: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<Vec<u8>, CryptoError> {
                $aes_decrypt(m, k, iv, d, aad)
            }
            fn aes_kw_wrap(&self, kek: &[u8], k: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.aes_kw_wrap(kek, k)
            }
            fn aes_kw_unwrap(&self, kek: &[u8], w: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.aes_kw_unwrap(kek, w)
            }
            fn hkdf_derive_key(
                &self,
                k: &[u8],
                s: &[u8],
                i: &[u8],
                l: usize,
                a: HashAlgorithm,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.hkdf_derive_key(k, s, i, l, a)
            }
            fn pbkdf2_derive_key(
                &self,
                p: &[u8],
                s: &[u8],
                i: u32,
                l: usize,
                a: HashAlgorithm,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.pbkdf2_derive_key(p, s, i, l, a)
            }
            fn generate_aes_key(&self, b: u16) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.generate_aes_key(b)
            }
            fn generate_hmac_key(&self, a: HashAlgorithm, b: u16) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.generate_hmac_key(a, b)
            }
            fn generate_ec_key(&self, c: EllipticCurve) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
                rust::RustCryptoProvider.generate_ec_key(c)
            }
            fn generate_ed25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
                rust::RustCryptoProvider.generate_ed25519_key()
            }
            fn generate_x25519_key(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
                rust::RustCryptoProvider.generate_x25519_key()
            }
            fn generate_rsa_key(
                &self,
                b: u32,
                e: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
                rust::RustCryptoProvider.generate_rsa_key(b, e)
            }
            fn import_rsa_public_key_pkcs1(
                &self,
                d: &[u8],
            ) -> Result<RsaImportResult, CryptoError> {
                rust::RustCryptoProvider.import_rsa_public_key_pkcs1(d)
            }
            fn import_rsa_private_key_pkcs1(
                &self,
                d: &[u8],
            ) -> Result<RsaImportResult, CryptoError> {
                rust::RustCryptoProvider.import_rsa_private_key_pkcs1(d)
            }
            fn import_rsa_public_key_spki(&self, d: &[u8]) -> Result<RsaImportResult, CryptoError> {
                rust::RustCryptoProvider.import_rsa_public_key_spki(d)
            }
            fn import_rsa_private_key_pkcs8(
                &self,
                d: &[u8],
            ) -> Result<RsaImportResult, CryptoError> {
                rust::RustCryptoProvider.import_rsa_private_key_pkcs8(d)
            }
            fn export_rsa_public_key_pkcs1(&self, d: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_rsa_public_key_pkcs1(d)
            }
            fn export_rsa_public_key_spki(&self, d: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_rsa_public_key_spki(d)
            }
            fn export_rsa_private_key_pkcs8(&self, d: &[u8]) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_rsa_private_key_pkcs8(d)
            }
            fn import_ec_public_key_sec1(
                &self,
                d: &[u8],
                c: EllipticCurve,
            ) -> Result<EcImportResult, CryptoError> {
                rust::RustCryptoProvider.import_ec_public_key_sec1(d, c)
            }
            fn import_ec_public_key_spki(
                &self,
                d: &[u8],
                c: EllipticCurve,
            ) -> Result<EcImportResult, CryptoError> {
                rust::RustCryptoProvider.import_ec_public_key_spki(d, c)
            }
            fn import_ec_private_key_pkcs8(&self, d: &[u8]) -> Result<EcImportResult, CryptoError> {
                rust::RustCryptoProvider.import_ec_private_key_pkcs8(d)
            }
            fn import_ec_private_key_sec1(
                &self,
                d: &[u8],
                c: EllipticCurve,
            ) -> Result<EcImportResult, CryptoError> {
                rust::RustCryptoProvider.import_ec_private_key_sec1(d, c)
            }
            fn export_ec_public_key_sec1(
                &self,
                d: &[u8],
                c: EllipticCurve,
                p: bool,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_ec_public_key_sec1(d, c, p)
            }
            fn export_ec_public_key_spki(
                &self,
                d: &[u8],
                c: EllipticCurve,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_ec_public_key_spki(d, c)
            }
            fn export_ec_private_key_pkcs8(
                &self,
                d: &[u8],
                c: EllipticCurve,
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_ec_private_key_pkcs8(d, c)
            }
            fn import_okp_public_key_raw(&self, d: &[u8]) -> Result<OkpImportResult, CryptoError> {
                rust::RustCryptoProvider.import_okp_public_key_raw(d)
            }
            fn import_okp_public_key_spki(
                &self,
                d: &[u8],
                o: &[u8],
            ) -> Result<OkpImportResult, CryptoError> {
                rust::RustCryptoProvider.import_okp_public_key_spki(d, o)
            }
            fn import_okp_private_key_pkcs8(
                &self,
                d: &[u8],
                o: &[u8],
            ) -> Result<OkpImportResult, CryptoError> {
                rust::RustCryptoProvider.import_okp_private_key_pkcs8(d, o)
            }
            fn export_okp_public_key_raw(&self, d: &[u8], p: bool) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_okp_public_key_raw(d, p)
            }
            fn export_okp_public_key_spki(
                &self,
                d: &[u8],
                o: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_okp_public_key_spki(d, o)
            }
            fn export_okp_private_key_pkcs8(
                &self,
                d: &[u8],
                o: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                rust::RustCryptoProvider.export_okp_private_key_pkcs8(d, o)
            }
            fn import_rsa_jwk(&self, j: RsaJwkImport<'_>) -> Result<RsaImportResult, CryptoError> {
                rust::RustCryptoProvider.import_rsa_jwk(j)
            }
            fn export_rsa_jwk(&self, d: &[u8], p: bool) -> Result<RsaJwkExport, CryptoError> {
                rust::RustCryptoProvider.export_rsa_jwk(d, p)
            }
            fn import_ec_jwk(
                &self,
                j: EcJwkImport<'_>,
                c: EllipticCurve,
            ) -> Result<EcImportResult, CryptoError> {
                rust::RustCryptoProvider.import_ec_jwk(j, c)
            }
            fn export_ec_jwk(
                &self,
                d: &[u8],
                c: EllipticCurve,
                p: bool,
            ) -> Result<EcJwkExport, CryptoError> {
                rust::RustCryptoProvider.export_ec_jwk(d, c, p)
            }
            fn import_okp_jwk(
                &self,
                j: OkpJwkImport<'_>,
                is_ed25519: bool,
            ) -> Result<OkpImportResult, CryptoError> {
                rust::RustCryptoProvider.import_okp_jwk(j, is_ed25519)
            }
            fn export_okp_jwk(
                &self,
                d: &[u8],
                is_private: bool,
                is_ed25519: bool,
            ) -> Result<OkpJwkExport, CryptoError> {
                rust::RustCryptoProvider.export_okp_jwk(d, is_private, is_ed25519)
            }
        }
    };
}

#[cfg(feature = "crypto-ring-rust")]
impl_hybrid_provider!(
    RingRustProvider,
    ring::RingDigestType,
    ring::RingHmacType,
    |a| ring::RingProvider.digest(a),
    |a, k| ring::RingProvider.hmac(a, k),
    |m, k, iv, d, aad| rust::RustCryptoProvider.aes_encrypt(m, k, iv, d, aad),
    |m, k, iv, d, aad| rust::RustCryptoProvider.aes_decrypt(m, k, iv, d, aad)
);

#[cfg(feature = "crypto-graviola-rust")]
fn graviola_aes_supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(feature = "crypto-graviola-rust")]
impl_hybrid_provider!(
    GraviolaRustProvider,
    graviola::GraviolaRustDigest,
    graviola::GraviolaRustHmac,
    graviola::GraviolaRustDigest::new,
    graviola::GraviolaRustHmac::new,
    |m: AesMode, k: &[u8], iv: &[u8], d: &[u8], aad: Option<&[u8]>| {
        if graviola_aes_supported()
            && matches!(m, AesMode::Gcm { tag_length: 128 })
            && matches!(k.len(), 16 | 32)
        {
            graviola::GraviolaProvider.aes_encrypt(m, k, iv, d, aad)
        } else {
            rust::RustCryptoProvider.aes_encrypt(m, k, iv, d, aad)
        }
    },
    |m: AesMode, k: &[u8], iv: &[u8], d: &[u8], aad: Option<&[u8]>| {
        if graviola_aes_supported()
            && matches!(m, AesMode::Gcm { tag_length: 128 })
            && matches!(k.len(), 16 | 32)
        {
            graviola::GraviolaProvider.aes_decrypt(m, k, iv, d, aad)
        } else {
            rust::RustCryptoProvider.aes_decrypt(m, k, iv, d, aad)
        }
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> impl CryptoProvider {
        #[cfg(feature = "crypto-rust")]
        return rust::RustCryptoProvider;
        #[cfg(feature = "crypto-ring-rust")]
        return RingRustProvider;
        #[cfg(feature = "crypto-graviola-rust")]
        return GraviolaRustProvider;
        #[cfg(feature = "crypto-openssl")]
        return openssl::OpenSslProvider;
        #[cfg(feature = "crypto-ring")]
        return ring::RingProvider;
        #[cfg(all(feature = "crypto-graviola", not(feature = "crypto-graviola-rust")))]
        return graviola::GraviolaProvider;
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // SHA digest tests
    #[test]
    fn test_sha256_digest() {
        let p = provider();
        let mut digest = p.digest(HashAlgorithm::Sha256);
        digest.update(b"hello world");
        let result = digest.finalize();
        assert_eq!(result.len(), 32);
        assert_eq!(
            to_hex(&result),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha384_digest() {
        let p = provider();
        let mut digest = p.digest(HashAlgorithm::Sha384);
        digest.update(b"hello world");
        let result = digest.finalize();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512_digest() {
        let p = provider();
        let mut digest = p.digest(HashAlgorithm::Sha512);
        digest.update(b"hello world");
        let result = digest.finalize();
        assert_eq!(result.len(), 64);
    }

    // HMAC tests
    #[test]
    fn test_hmac_sha256() {
        let p = provider();
        let key = b"secret key";
        let mut hmac = p.hmac(HashAlgorithm::Sha256, key);
        hmac.update(b"hello world");
        let result = hmac.finalize();
        assert_eq!(result.len(), 32);
    }

    // AES-GCM tests - only for providers that support AES
    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    #[test]
    fn test_aes_gcm_128_roundtrip() {
        let p = provider();
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let plaintext = b"hello world";
        let aad = b"additional data";

        let ciphertext = p
            .aes_encrypt(
                AesMode::Gcm { tag_length: 128 },
                &key,
                &iv,
                plaintext,
                Some(aad),
            )
            .unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() + 16); // plaintext + tag

        let decrypted = p
            .aes_decrypt(
                AesMode::Gcm { tag_length: 128 },
                &key,
                &iv,
                &ciphertext,
                Some(aad),
            )
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    #[test]
    fn test_aes_gcm_256_roundtrip() {
        let p = provider();
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let plaintext = b"hello world";

        let ciphertext = p
            .aes_encrypt(AesMode::Gcm { tag_length: 128 }, &key, &iv, plaintext, None)
            .unwrap();

        let decrypted = p
            .aes_decrypt(
                AesMode::Gcm { tag_length: 128 },
                &key,
                &iv,
                &ciphertext,
                None,
            )
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    #[test]
    fn test_aes_gcm_wrong_key_fails() {
        let p = provider();
        let key = [0u8; 16];
        let wrong_key = [1u8; 16];
        let iv = [0u8; 12];
        let plaintext = b"hello world";

        let ciphertext = p
            .aes_encrypt(AesMode::Gcm { tag_length: 128 }, &key, &iv, plaintext, None)
            .unwrap();

        let result = p.aes_decrypt(
            AesMode::Gcm { tag_length: 128 },
            &wrong_key,
            &iv,
            &ciphertext,
            None,
        );

        assert!(result.is_err());
    }

    #[cfg(all(feature = "crypto-graviola", not(feature = "crypto-graviola-rust")))]
    #[test]
    fn test_graviola_rejects_unsupported_aes_gcm_tag_length() {
        let p = provider();
        let result = p.aes_encrypt(
            AesMode::Gcm { tag_length: 64 },
            &[0; 16],
            &[0; 12],
            b"hello world",
            None,
        );

        assert!(matches!(result, Err(CryptoError::UnsupportedAlgorithm)));
    }

    // Key generation tests - only for providers that support key generation
    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    #[test]
    fn test_generate_aes_key_128() {
        let p = provider();
        let key = p.generate_aes_key(128).unwrap();
        assert_eq!(key.len(), 16);
    }

    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    #[test]
    fn test_generate_aes_key_256() {
        let p = provider();
        let key = p.generate_aes_key(256).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    #[test]
    fn test_generate_hmac_key() {
        let p = provider();
        let key = p.generate_hmac_key(HashAlgorithm::Sha256, 256).unwrap();
        assert_eq!(key.len(), 32);
    }

    // Tests that require full crypto support
    #[cfg(any(
        feature = "crypto-rust",
        feature = "crypto-openssl",
        feature = "crypto-ring-rust",
        feature = "crypto-graviola-rust"
    ))]
    mod full_provider_tests {
        use super::*;

        #[test]
        fn test_aes_cbc_roundtrip() {
            let p = provider();
            let key = [0u8; 16];
            let iv = [0u8; 16];
            let plaintext = b"hello world12345"; // 16 bytes for block alignment

            let ciphertext = p
                .aes_encrypt(AesMode::Cbc, &key, &iv, plaintext, None)
                .unwrap();

            let decrypted = p
                .aes_decrypt(AesMode::Cbc, &key, &iv, &ciphertext, None)
                .unwrap();

            assert_eq!(decrypted, plaintext);
        }

        // AES-CTR's `length` is the width of the counter field, and WebCrypto
        // wraps only within that field. OpenSSL's own CTR always increments the
        // full 128-bit block, so a 32-bit counter that wraps would diverge
        // silently. These vectors were taken from the RustCrypto implementation
        // this provider replaced, with a counter one short of wrapping its low
        // 32 bits over a 3-block message, which is where the widths disagree.
        const CTR_VECTORS: &[(usize, u32, &str)] = &[
            (16, 32, "3fbf0b00d7febb5bd68bf816a3be5af7d4aa9e4069229bd7c7cc20451546cfd356edc038d0a61259"),
            (16, 64, "3fbf0b00d7febb5bd68bf816a3be5af7d4aa9e4069229bd7c7cc20451546cfd333494050b418e836"),
            (16, 128, "3fbf0b00d7febb5bd68bf816a3be5af7d4aa9e4069229bd7c7cc20451546cfd333494050b418e836"),
            (24, 32, "a7f3a35f6b3d2c45a0e918a57fa97789af6e365c775920e6582c198c154e5c891fa21537d5ed233a"),
            (24, 64, "a7f3a35f6b3d2c45a0e918a57fa97789af6e365c775920e6582c198c154e5c89bcc1519790650e23"),
            (24, 128, "a7f3a35f6b3d2c45a0e918a57fa97789af6e365c775920e6582c198c154e5c89bcc1519790650e23"),
            (32, 32, "405d14fcebc697d024aa171141692dd9d14ea0bdbba3da73e60e24a419b89d6ebe920798b8a29fca"),
            (32, 64, "405d14fcebc697d024aa171141692dd9d14ea0bdbba3da73e60e24a419b89d6ef6da045478eb0843"),
            (32, 128, "405d14fcebc697d024aa171141692dd9d14ea0bdbba3da73e60e24a419b89d6ef6da045478eb0843"),
        ];

        fn ctr_vector_iv() -> Vec<u8> {
            let mut iv: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(17)).collect();
            iv[12] = 0xff;
            iv[13] = 0xff;
            iv[14] = 0xff;
            iv[15] = 0xfe;
            iv
        }

        #[test]
        fn test_aes_ctr_counter_width_known_answers() {
            let p = provider();
            let data: Vec<u8> = (0u8..40).collect();
            let iv = ctr_vector_iv();
            for (klen, clen, want) in CTR_VECTORS {
                let key: Vec<u8> = (0..*klen).map(|i| i as u8).collect();
                let got = p
                    .aes_encrypt(AesMode::Ctr { counter_length: *clen }, &key, &iv, &data, None)
                    .unwrap();
                let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(&got_hex, want, "AES-{}-CTR length={}", klen * 8, clen);

                let back = p
                    .aes_decrypt(AesMode::Ctr { counter_length: *clen }, &key, &iv, &got, None)
                    .unwrap();
                assert_eq!(back, data, "AES-{}-CTR length={} round trip", klen * 8, clen);
            }
        }

        #[test]
        fn test_aes_ctr_roundtrip() {
            let p = provider();
            let key = [0u8; 16];
            let iv = [0u8; 16];
            let plaintext = b"hello world";

            let ciphertext = p
                .aes_encrypt(
                    AesMode::Ctr { counter_length: 64 },
                    &key,
                    &iv,
                    plaintext,
                    None,
                )
                .unwrap();

            let decrypted = p
                .aes_decrypt(
                    AesMode::Ctr { counter_length: 64 },
                    &key,
                    &iv,
                    &ciphertext,
                    None,
                )
                .unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_aes_kw_roundtrip() {
            let p = provider();
            let kek = [0u8; 16];
            let key_to_wrap = [1u8; 16];

            let wrapped = p.aes_kw_wrap(&kek, &key_to_wrap).unwrap();
            let unwrapped = p.aes_kw_unwrap(&kek, &wrapped).unwrap();

            assert_eq!(unwrapped, key_to_wrap);
        }

        #[test]
        fn test_hkdf_derive() {
            let p = provider();
            let ikm = b"input key material";
            let salt = b"salt";
            let info = b"info";

            let derived = p
                .hkdf_derive_key(ikm, salt, info, 32, HashAlgorithm::Sha256)
                .unwrap();

            assert_eq!(derived.len(), 32);
        }

        #[test]
        fn test_pbkdf2_derive() {
            let p = provider();
            let password = b"password";
            let salt = b"salt";

            let derived = p
                .pbkdf2_derive_key(password, salt, 1000, 32, HashAlgorithm::Sha256)
                .unwrap();

            assert_eq!(derived.len(), 32);
        }

        #[test]
        fn test_ec_p256_sign_verify() {
            let p = provider();
            let (private_key, public_key) = p.generate_ec_key(EllipticCurve::P256).unwrap();

            // Create a digest to sign
            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(b"message to sign");
            let hash = digest.finalize();

            let signature = p
                .ecdsa_sign(EllipticCurve::P256, &private_key, &hash)
                .unwrap();

            let valid = p
                .ecdsa_verify(EllipticCurve::P256, &public_key, &signature, &hash)
                .unwrap();

            assert!(valid);
        }

        #[test]
        fn test_ec_p384_sign_verify() {
            let p = provider();
            let (private_key, public_key) = p.generate_ec_key(EllipticCurve::P384).unwrap();

            let mut digest = p.digest(HashAlgorithm::Sha384);
            digest.update(b"message to sign");
            let hash = digest.finalize();

            let signature = p
                .ecdsa_sign(EllipticCurve::P384, &private_key, &hash)
                .unwrap();

            let valid = p
                .ecdsa_verify(EllipticCurve::P384, &public_key, &signature, &hash)
                .unwrap();

            assert!(valid);
        }

        #[test]
        fn test_ed25519_sign_verify() {
            let p = provider();
            let (private_key, public_key) = p.generate_ed25519_key().unwrap();

            let message = b"message to sign";
            let signature = p.ed25519_sign(&private_key, message).unwrap();

            let valid = p.ed25519_verify(&public_key, &signature, message).unwrap();

            assert!(valid);
        }

        #[test]
        fn test_x25519_key_exchange() {
            let p = provider();
            let (alice_private, alice_public) = p.generate_x25519_key().unwrap();
            let (bob_private, bob_public) = p.generate_x25519_key().unwrap();

            let alice_shared = p.x25519_derive_bits(&alice_private, &bob_public).unwrap();
            let bob_shared = p.x25519_derive_bits(&bob_private, &alice_public).unwrap();

            assert_eq!(alice_shared, bob_shared);
            assert_eq!(alice_shared.len(), 32);
        }

        #[test]
        fn test_ecdh_p256_key_exchange() {
            let p = provider();
            let (alice_private, alice_public) = p.generate_ec_key(EllipticCurve::P256).unwrap();
            let (bob_private, bob_public) = p.generate_ec_key(EllipticCurve::P256).unwrap();

            let alice_shared = p
                .ecdh_derive_bits(EllipticCurve::P256, &alice_private, &bob_public)
                .unwrap();
            let bob_shared = p
                .ecdh_derive_bits(EllipticCurve::P256, &bob_private, &alice_public)
                .unwrap();

            assert_eq!(alice_shared, bob_shared);
        }

        // Vectors produced by the OpenSSL command-line tool, an implementation
        // independent of this binding, so a padding, digest or label regression
        // in the port fails here rather than round-tripping against itself.
        const KAT_PRIVATE_KEY_PKCS1_DER: &str = "308204a40201000282010100b6bea7cd955740133dd49eae5358b3016ebce706f1d05974bc2b3e3ffc98099a7fbbc00d31cf8097f61dbbec2a7fc810f75c5ea90725cd758ed61c993269421f584c0fab8aea4bd56f70cb2fc34aa2c894b35c1bfc96b0212c076d58a34ef20c430401e4bb13498ba6285292fa86a99fccd144a254a65e3ab9a577b0068114ef80664d6ae987433ff53620494449d9a1d44aa1e60e53123dad6e4c26818bc1fc3b925074908a1e1143352dc3ed04370ec21393949d9618ac4c19b3d3cb0b11152df5103f70050bf538c92758d5b219d1b1ff81a3e1a2aec1e997662c7c575e759434a25f8e9f1def13f6723c4a0d7a1aefe28d949151d5eebde4250874efb10302030100010282010000fbbeff6b8c4ffb4a868db6b6701b167e380f58dee2eb7850ad92e4d94120316ffa8755602d3e5892ff24a1bd60cea778b7f5dd1c52bc6ba387221998f1d964931f1053db52d8c6f495e62202ffb07c8fd59f4099f8084945696227409f0e226417436e03010990f225f41122695319af0a793f690bdecf461723dbbdf7e2859d16a9bba6ad5fff4a305291f6ef3ad227ad5ccbd6519748694633d3904b2af48f137a437891bb6b74c7d6bedd417ce88562601a4b9a55b2df5857e79871f117b10add8be40c5be81ca1980c3bec88ce20170cc4b24951a7cb33605763f8f433361667b9f843d6c362d632a83681e7dedd345520a54effdb408f8a0836a6f0c102818100d97008c5b2ef4d2ed4d905150eddd15011a580b0b0bfa403e4d3d6100d6d7310e3f2537e515bb4c526456276ee1728fd91ee2d773ee645aaaf639d7d3e508fc23b822a3b866aeb452a64a421e16c53717a8b508f83b751a05a8b90dfc7c0d527507f18b020fa396febcc5e734019e6f5fe4f09bcabb26e03db88ab204a030cd302818100d727844bdf3996bbd1c3a2033509f8cbd5627cc4c495a7cfe1ce6930fb928361e200c51ae7af252b0f6a16c486a7bbcace399ccbcc90e029fd195a9deaf27e33e09f7a088fe4af96fc377f77d252cbb4413f4dd0d1916508bd9f47eb35105caa00b893935dd02f19d253943687b008aa3664d10bd85484c5519236d1e4e26d1102818100c5c79e73159b8dfd37265ff5139cb8b3b8196ec14944481032a86d621494a5c18b55f49445b4c0ed432e81ade44bb4c15167f07b32ff8a070399fcbadb5fb423dcb53d6cff8b698d744e2eed927a523c3a575663f44f5f3418a832931ac3501f7e9cdcfbf84322d3a70c322d6af5249c4541e77d723fceca3b7a490e09c45479028181009e75392753f92afd9b08f52a5d86c19905c82a5214e28f9c3816f83c1e1c12ed253121f9a5c6c59e08153f3d705adaa10bef3c7e9063e6e4a5c66589c6bedf99bf8654af37a2da7b5db85605de7e220ed8bb11c9887f07a53f5aaef218bbbb336da282f5d6f2fbad8dcd066c7ed4741d40405201e24aa51a59f050b59757f7b102818031cc5b6b4eb01bf457a1e1152ee7b77128a2c62922d7f750ab16d2563859031fc8b401c442ef03d0ede358baac43dc1ec0fd03ccaea4ce3fd80d1462302d05005f38b6abb22bff69eee01b98e46a43d0c76fba071df7ac1cdf4dd4261c85befa9fdda04be703cec0b332f233f0401777e4f68b59d513db6ffda73bc0442c6a92";
        const KAT_PUBLIC_KEY_PKCS1_DER: &str = "3082010a0282010100b6bea7cd955740133dd49eae5358b3016ebce706f1d05974bc2b3e3ffc98099a7fbbc00d31cf8097f61dbbec2a7fc810f75c5ea90725cd758ed61c993269421f584c0fab8aea4bd56f70cb2fc34aa2c894b35c1bfc96b0212c076d58a34ef20c430401e4bb13498ba6285292fa86a99fccd144a254a65e3ab9a577b0068114ef80664d6ae987433ff53620494449d9a1d44aa1e60e53123dad6e4c26818bc1fc3b925074908a1e1143352dc3ed04370ec21393949d9618ac4c19b3d3cb0b11152df5103f70050bf538c92758d5b219d1b1ff81a3e1a2aec1e997662c7c575e759434a25f8e9f1def13f6723c4a0d7a1aefe28d949151d5eebde4250874efb1030203010001";
        const KAT_PKCS1V15_SHA256_SIG: &str = "032464396e8ff2484b13570d49fad435c145b47eae3a257a6238f5e0c00431901d43c663ae785bda51b8ba35d50fe9a41f682c3765bcb3ad4b8fd704a3ca849da0ebc62e8c02bdc0310c336c2040d6f50331cbe65590ba3d30cb5300cd9dd2681a714abfb90a55db592d770281990f246b229b73ca2a257d4766663b3eb599fcf809da50c00d0b14395dc91522707c6d8e9d4de6e3b3986b8dee0dc5c5a963d1b3107a21e2f82fa5d7d2a7438f412e1f1ebec41a05e3f03ed192cf904b959d434830f53219eaa3088670bee1b4582b542f4fda69c3cfbee035a4e16f1042c37225b6ab4bed319cc9ee0cc7009c743059bc29ed6651f74cd8afd93fc9158ab6c3";
        const KAT_OAEP_SHA256_LABELLED_CT: &str = "62c250501c105feb2a9334d607724b2369a84b9e1f7f2b052cb68a5e1ed9d321a811aaf7f799ee802457a49f331ca93ae7d1be0d7c2fd3922e030f3961c8f8e40e831325a1df5240f5a70893b5d12eeb8352bea8a92996567ea1535abeab10949a04f716143ba9b8a53223bfc6c264ef39f4c0998c0d7c9c7cac90e4d40717f768296405690fb9b477c42835dee2d8ba4c8945551a32f17e4295fac020b3a26274b265574b1e762bb1b7b5ee410c5029de5fc1ce963a52a21230ebece2bee3088b9b295b18a6b5a6d0c40a82e1a679f085eabf0e8cc6c16f0bfe9859928350e6dc6be9c2cfd3ff6a69b336203e093b59df5f16db08ba7b0748d73fccc8a1a330";
        const KAT_MESSAGE: &[u8] = b"message to sign";
        const KAT_OAEP_PLAINTEXT: &[u8] = b"secret payload";
        const KAT_OAEP_LABEL: &[u8] = &[0x00, 0xff, 0x10];

        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        fn kat_keys() -> (Vec<u8>, Vec<u8>) {
            (
                unhex(KAT_PRIVATE_KEY_PKCS1_DER),
                unhex(KAT_PUBLIC_KEY_PKCS1_DER),
            )
        }

        // EC key formats and ECDH are deterministic, so they pin exactly what a
        // backend swap could change quietly: the SEC1 point encoding, the SPKI
        // wrapper, the PKCS#8 round trip, the JWK coordinate widths (P-521's
        // are 66 bytes, left-padded) and the raw shared secret. Captured from
        // the RustCrypto implementation this provider replaced.
        struct EcVector {
            curve: EllipticCurve,
            private_pkcs8: &'static str,
            public_sec1: &'static str,
            public_spki: &'static str,
            jwk_x: &'static str,
            jwk_y: &'static str,
            jwk_d: &'static str,
            peer_sec1: &'static str,
            ecdh: &'static str,
        }

        const EC_VECTORS: &[EcVector] = &[
            EcVector {
                curve: EllipticCurve::P256,
                private_pkcs8: "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420d14161e04fe7dc1c104b1edf09339e996c26783f76a589a54b486f231f2978fca14403420004a35fe6aa124822ddeb972ec3e3ae6bfd8f6c3275a0f23a5bed975ff90b2459fe545c2e788559da140ec3a0968197066570d56aa0e293ca791445457b2aa61897",
                public_sec1: "04a35fe6aa124822ddeb972ec3e3ae6bfd8f6c3275a0f23a5bed975ff90b2459fe545c2e788559da140ec3a0968197066570d56aa0e293ca791445457b2aa61897",
                public_spki: "3059301306072a8648ce3d020106082a8648ce3d03010703420004a35fe6aa124822ddeb972ec3e3ae6bfd8f6c3275a0f23a5bed975ff90b2459fe545c2e788559da140ec3a0968197066570d56aa0e293ca791445457b2aa61897",
                jwk_x: "a35fe6aa124822ddeb972ec3e3ae6bfd8f6c3275a0f23a5bed975ff90b2459fe",
                jwk_y: "545c2e788559da140ec3a0968197066570d56aa0e293ca791445457b2aa61897",
                jwk_d: "d14161e04fe7dc1c104b1edf09339e996c26783f76a589a54b486f231f2978fc",
                peer_sec1: "04b9865604deed965b34b2a2d45661991b34e4eb6c9f9e0fde92c9f877a80a414533c63b7571d0473943c5a24a57f1ef78a0c18974381c5d89b62e28b0272a5b4b",
                ecdh: "45e6029d23d4ee3791a09e156d0f5ba9d415d82a7cbe516bb6a9a3c503c231ea",
            },
            EcVector {
                curve: EllipticCurve::P384,
                private_pkcs8: "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201010430056eb29c942483489dafbd6cc11692ec3402952397647cfd9f7ac29ee272f5118b2cadb26ce27815bf6f3aa2f0e82179a16403620004daea916a477a7c4bfa5703f3d97c59b28f32f511fa02b49d755bdfae38356f0a15edfc18be403fdb5acb3e4dd692e17bac5150c1d0d744563668ccc80f6ac32b856c13ae2b164e2699501b7c2b421d6cb4900215b04dc9d463b21e98ba61c681",
                public_sec1: "04daea916a477a7c4bfa5703f3d97c59b28f32f511fa02b49d755bdfae38356f0a15edfc18be403fdb5acb3e4dd692e17bac5150c1d0d744563668ccc80f6ac32b856c13ae2b164e2699501b7c2b421d6cb4900215b04dc9d463b21e98ba61c681",
                public_spki: "3076301006072a8648ce3d020106052b8104002203620004daea916a477a7c4bfa5703f3d97c59b28f32f511fa02b49d755bdfae38356f0a15edfc18be403fdb5acb3e4dd692e17bac5150c1d0d744563668ccc80f6ac32b856c13ae2b164e2699501b7c2b421d6cb4900215b04dc9d463b21e98ba61c681",
                jwk_x: "daea916a477a7c4bfa5703f3d97c59b28f32f511fa02b49d755bdfae38356f0a15edfc18be403fdb5acb3e4dd692e17b",
                jwk_y: "ac5150c1d0d744563668ccc80f6ac32b856c13ae2b164e2699501b7c2b421d6cb4900215b04dc9d463b21e98ba61c681",
                jwk_d: "056eb29c942483489dafbd6cc11692ec3402952397647cfd9f7ac29ee272f5118b2cadb26ce27815bf6f3aa2f0e82179",
                peer_sec1: "0429f85fd4b44b4997b5791a1cbc973f45e6effee2b1cbc659c59896d8536ea556a93a91ee3f744a0d27501bacea48e760dc1ab078bd747d95b8aafb3860f08a66fa826180c9b3a9613587b4e025d2d66031c23939f1e4763e83d24378dbd73c75",
                ecdh: "814f4ccaa8b200f35696af511dae818abf0d970531c0b2017217b8bb3fa9d0d89d13926c80ec8d53eca4c6a9840f2d0f",
            },
            EcVector {
                curve: EllipticCurve::P521,
                private_pkcs8: "3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020101044201e858f96577fbf091a1da211d9b8bfbe30dc4511e20bae50953c169c6ef5d8e474b63cea23a43770f5a3e9865e1b5b140c1fcb6f649d1270fd2a30bf4611a7a8422a18189038186000401564137ea4e3423f622847074f6bff0231e590a30d07702663d96713abbdbb947c7225f03a897ab516398a7210970a3378261c04ea6d03b2cf4e0b14ce00dc53d80011f3d59ddb9013ac28a65ed2d6ba9e624fae397d9a18b4624f232af1c58f3f82906d8771721c3895b18d7056e7de25e3e44bc6834d27a8266b78d0d08631906cecd",
                public_sec1: "0401564137ea4e3423f622847074f6bff0231e590a30d07702663d96713abbdbb947c7225f03a897ab516398a7210970a3378261c04ea6d03b2cf4e0b14ce00dc53d80011f3d59ddb9013ac28a65ed2d6ba9e624fae397d9a18b4624f232af1c58f3f82906d8771721c3895b18d7056e7de25e3e44bc6834d27a8266b78d0d08631906cecd",
                public_spki: "30819b301006072a8648ce3d020106052b81040023038186000401564137ea4e3423f622847074f6bff0231e590a30d07702663d96713abbdbb947c7225f03a897ab516398a7210970a3378261c04ea6d03b2cf4e0b14ce00dc53d80011f3d59ddb9013ac28a65ed2d6ba9e624fae397d9a18b4624f232af1c58f3f82906d8771721c3895b18d7056e7de25e3e44bc6834d27a8266b78d0d08631906cecd",
                jwk_x: "01564137ea4e3423f622847074f6bff0231e590a30d07702663d96713abbdbb947c7225f03a897ab516398a7210970a3378261c04ea6d03b2cf4e0b14ce00dc53d80",
                jwk_y: "011f3d59ddb9013ac28a65ed2d6ba9e624fae397d9a18b4624f232af1c58f3f82906d8771721c3895b18d7056e7de25e3e44bc6834d27a8266b78d0d08631906cecd",
                jwk_d: "01e858f96577fbf091a1da211d9b8bfbe30dc4511e20bae50953c169c6ef5d8e474b63cea23a43770f5a3e9865e1b5b140c1fcb6f649d1270fd2a30bf4611a7a8422",
                peer_sec1: "0400505cec9cb1bcaa62980d895fef02cd68aa244cc8d8ce32244ad2810dbfcf05ba8b42abb7eabf39f98c3185ea0d5689acf09e696d90e2f8a3b8faad0877ed9eb79600d05717bc2b63b914101e1fcf05cb3d3b6e77ccfaccd67d09c9b44702ad98f0146a6b2fcc98e4290b5d46c18d690a4f051396ea865a16b311b0f892121274c0b27f",
                ecdh: "019706ee595096e2bb953771170013bc2b6669abfcc3c958a2894f590816c2c38f7d62ea4641bacceb46e8a869a026f26cb84cac798550ded20ec346a525541ce183",
            },
        ];

        #[test]
        fn test_ec_key_formats_and_ecdh_known_answers() {
            let p = provider();
            let hx = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
            for v in EC_VECTORS {
                let kd = unhex(v.private_pkcs8);

                let sec1 = p.export_ec_public_key_sec1(&kd, v.curve, true).unwrap();
                assert_eq!(hx(&sec1), v.public_sec1, "SEC1 point");

                // SPKI export is only reached with public key data.
                let spki = p.export_ec_public_key_spki(&sec1, v.curve).unwrap();
                assert_eq!(hx(&spki), v.public_spki, "SPKI");

                let pkcs8 = p.export_ec_private_key_pkcs8(&kd, v.curve).unwrap();
                assert_eq!(hx(&pkcs8), v.private_pkcs8, "PKCS#8 round trip");

                let jwk = p.export_ec_jwk(&kd, v.curve, true).unwrap();
                assert_eq!(hx(&jwk.x), v.jwk_x, "JWK x");
                assert_eq!(hx(&jwk.y), v.jwk_y, "JWK y");
                assert_eq!(hx(jwk.d.as_deref().unwrap_or_default()), v.jwk_d, "JWK d");

                let shared = p
                    .ecdh_derive_bits(v.curve, &kd, &unhex(v.peer_sec1))
                    .unwrap();
                assert_eq!(hx(&shared), v.ecdh, "ECDH shared secret");

                // A signature this provider produces must verify against the
                // point it exported, whichever way the signature is encoded.
                let digest = {
                    let mut d = p.digest(HashAlgorithm::Sha256);
                    d.update(b"ec vector message");
                    d.finalize()
                };
                let sig = p.ecdsa_sign(v.curve, &kd, &digest).unwrap();
                assert!(p.ecdsa_verify(v.curve, &sec1, &sig, &digest).unwrap());
                let mut bad = sig.clone();
                bad[0] ^= 0x01;
                assert!(!p.ecdsa_verify(v.curve, &sec1, &bad, &digest).unwrap());
            }
        }

        #[test]
        fn test_rsa_pkcs1v15_known_answer() {
            let p = provider();
            let (_, public_key) = kat_keys();
            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(KAT_MESSAGE);
            let hash = digest.finalize();

            assert!(p
                .rsa_pkcs1v15_verify(
                    &public_key,
                    &unhex(KAT_PKCS1V15_SHA256_SIG),
                    &hash,
                    HashAlgorithm::Sha256
                )
                .unwrap());
        }

        #[test]
        fn test_rsa_pkcs1v15_sign_matches_known_answer() {
            // PKCS#1 v1.5 is deterministic, so our signature must be the vector.
            let p = provider();
            let (private_key, _) = kat_keys();
            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(KAT_MESSAGE);
            let hash = digest.finalize();

            let signature = p
                .rsa_pkcs1v15_sign(&private_key, &hash, HashAlgorithm::Sha256)
                .unwrap();
            assert_eq!(signature, unhex(KAT_PKCS1V15_SHA256_SIG));
        }

        #[test]
        fn test_rsa_oaep_decrypt_known_answer_with_binary_label() {
            let p = provider();
            let (private_key, _) = kat_keys();
            let plaintext = p
                .rsa_oaep_decrypt(
                    &private_key,
                    &unhex(KAT_OAEP_SHA256_LABELLED_CT),
                    HashAlgorithm::Sha256,
                    Some(KAT_OAEP_LABEL),
                )
                .unwrap();
            assert_eq!(plaintext, KAT_OAEP_PLAINTEXT);
        }

        #[test]
        fn test_rsa_oaep_wrong_label_is_rejected() {
            // The label authenticates the ciphertext; a different one must not decrypt.
            let p = provider();
            let (private_key, _) = kat_keys();
            assert!(p
                .rsa_oaep_decrypt(
                    &private_key,
                    &unhex(KAT_OAEP_SHA256_LABELLED_CT),
                    HashAlgorithm::Sha256,
                    Some(&[0x00, 0xff, 0x11]),
                )
                .is_err());
        }

        #[test]
        fn test_rsa_oaep_binary_label_round_trip() {
            let p = provider();
            let (private_key, public_key) = kat_keys();
            let label: &[u8] = &[0x00, 0x01, 0xfe, 0xff, 0x00];
            let ciphertext = p
                .rsa_oaep_encrypt(&public_key, b"payload", HashAlgorithm::Sha256, Some(label))
                .unwrap();
            let plaintext = p
                .rsa_oaep_decrypt(&private_key, &ciphertext, HashAlgorithm::Sha256, Some(label))
                .unwrap();
            assert_eq!(plaintext, b"payload");
        }

        #[test]
        fn test_rsa_pss_non_default_salt_length_round_trip() {
            // WebCrypto lets the caller choose saltLength; 20 is not the digest length.
            let p = provider();
            let (private_key, public_key) = kat_keys();
            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(KAT_MESSAGE);
            let hash = digest.finalize();

            let signature = p
                .rsa_pss_sign(&private_key, &hash, 20, HashAlgorithm::Sha256)
                .unwrap();
            assert!(p
                .rsa_pss_verify(&public_key, &signature, &hash, 20, HashAlgorithm::Sha256)
                .unwrap());
            // A verifier expecting a different salt length must reject it.
            assert!(!p
                .rsa_pss_verify(&public_key, &signature, &hash, 32, HashAlgorithm::Sha256)
                .unwrap());
        }

        #[test]
        fn test_rsa_generate_key_with_exponent_3() {
            let p = provider();
            let (private_key, public_key) = p.generate_rsa_key(2048, &[0x03]).unwrap();
            let imported = p.import_rsa_public_key_pkcs1(&public_key).unwrap();
            assert_eq!(imported.public_exponent, vec![0x03]);
            assert_eq!(imported.modulus_length, 2048);
            assert!(!private_key.is_empty());
        }

        #[test]
        fn test_rsa_malformed_private_key_is_rejected() {
            let p = provider();
            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(KAT_MESSAGE);
            let hash = digest.finalize();

            for bad in [b"".as_slice(), b"not der at all".as_slice(), &[0x30, 0x82, 0xff, 0xff]] {
                assert!(p
                    .rsa_pkcs1v15_sign(bad, &hash, HashAlgorithm::Sha256)
                    .is_err());
                assert!(p.import_rsa_private_key_pkcs1(bad).is_err());
            }
        }

        #[test]
        fn test_rsa_malformed_public_key_is_rejected() {
            let p = provider();
            for bad in [b"".as_slice(), b"not der at all".as_slice(), &[0x30, 0x82, 0xff, 0xff]] {
                assert!(p.import_rsa_public_key_pkcs1(bad).is_err());
                assert!(p
                    .rsa_oaep_encrypt(bad, b"x", HashAlgorithm::Sha256, None)
                    .is_err());
            }
        }

        #[test]
        fn test_rsa_malformed_signature_is_rejected() {
            let p = provider();
            let (_, public_key) = kat_keys();
            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(KAT_MESSAGE);
            let hash = digest.finalize();

            let mut tampered = unhex(KAT_PKCS1V15_SHA256_SIG);
            tampered[0] ^= 0x01;
            assert!(!p
                .rsa_pkcs1v15_verify(&public_key, &tampered, &hash, HashAlgorithm::Sha256)
                .unwrap());

            // Truncated and empty signatures must be rejected, not panic.
            assert!(!p
                .rsa_pkcs1v15_verify(&public_key, &[], &hash, HashAlgorithm::Sha256)
                .unwrap());
            assert!(!p
                .rsa_pkcs1v15_verify(&public_key, &tampered[..128], &hash, HashAlgorithm::Sha256)
                .unwrap());
        }

        #[test]
        fn test_rsa_malformed_ciphertext_is_rejected() {
            let p = provider();
            let (private_key, _) = kat_keys();
            let mut tampered = unhex(KAT_OAEP_SHA256_LABELLED_CT);
            tampered[0] ^= 0x01;
            assert!(p
                .rsa_oaep_decrypt(
                    &private_key,
                    &tampered,
                    HashAlgorithm::Sha256,
                    Some(KAT_OAEP_LABEL)
                )
                .is_err());
            assert!(p
                .rsa_oaep_decrypt(&private_key, &[], HashAlgorithm::Sha256, Some(KAT_OAEP_LABEL))
                .is_err());
        }

        #[test]
        fn test_rsa_pss_sign_verify() {
            let p = provider();
            let (private_key, public_key) = p.generate_rsa_key(2048, &[1, 0, 1]).unwrap();

            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(b"message to sign");
            let hash = digest.finalize();

            let signature = p
                .rsa_pss_sign(&private_key, &hash, 32, HashAlgorithm::Sha256)
                .unwrap();

            let valid = p
                .rsa_pss_verify(&public_key, &signature, &hash, 32, HashAlgorithm::Sha256)
                .unwrap();

            assert!(valid);
        }

        #[test]
        fn test_rsa_pkcs1v15_sign_verify() {
            let p = provider();
            let (private_key, public_key) = p.generate_rsa_key(2048, &[1, 0, 1]).unwrap();

            let mut digest = p.digest(HashAlgorithm::Sha256);
            digest.update(b"message to sign");
            let hash = digest.finalize();

            let signature = p
                .rsa_pkcs1v15_sign(&private_key, &hash, HashAlgorithm::Sha256)
                .unwrap();

            let valid = p
                .rsa_pkcs1v15_verify(&public_key, &signature, &hash, HashAlgorithm::Sha256)
                .unwrap();

            assert!(valid);
        }

        #[test]
        fn test_rsa_oaep_encrypt_decrypt() {
            let p = provider();
            let (private_key, public_key) = p.generate_rsa_key(2048, &[1, 0, 1]).unwrap();

            let plaintext = b"secret message";

            let ciphertext = p
                .rsa_oaep_encrypt(&public_key, plaintext, HashAlgorithm::Sha256, None)
                .unwrap();

            let decrypted = p
                .rsa_oaep_decrypt(&private_key, &ciphertext, HashAlgorithm::Sha256, None)
                .unwrap();

            assert_eq!(decrypted, plaintext);
        }
    }
}
