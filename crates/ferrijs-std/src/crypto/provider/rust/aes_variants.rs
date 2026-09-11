// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AES-GCM at every tag length WebCrypto allows.
//!
//! AWS-LC's AEAD is fixed at a 128-bit tag, and a shorter tag cannot be had by
//! truncating one: the shortened tag has to be what the decrypt side verifies
//! against, which its API will not do. The seven tag lengths are therefore
//! typed out here over a pure-Rust AES-GCM, which costs no C build and
//! cross-compiles wherever the runtime does. Everything else AES is AWS-LC.

use aes_gcm::{
    aead::{Aead, Payload},
    aes::cipher::{
        consts::{U12, U13, U14, U15, U16, U4, U8},
        InvalidLength,
    },
    AesGcm, KeyInit, Nonce,
};
use aes_gcm::aes::{Aes128, Aes192, Aes256};

pub enum AesGcmVariant {
    Aes128Gcm32(AesGcm<Aes128, U12, U4>),
    Aes192Gcm32(AesGcm<Aes192, U12, U4>),
    Aes256Gcm32(AesGcm<Aes256, U12, U4>),
    Aes128Gcm64(AesGcm<Aes128, U12, U8>),
    Aes192Gcm64(AesGcm<Aes192, U12, U8>),
    Aes256Gcm64(AesGcm<Aes256, U12, U8>),
    Aes128Gcm96(AesGcm<Aes128, U12, U12>),
    Aes192Gcm96(AesGcm<Aes192, U12, U12>),
    Aes256Gcm96(AesGcm<Aes256, U12, U12>),
    Aes128Gcm104(AesGcm<Aes128, U12, U13>),
    Aes192Gcm104(AesGcm<Aes192, U12, U13>),
    Aes256Gcm104(AesGcm<Aes256, U12, U13>),
    Aes128Gcm112(AesGcm<Aes128, U12, U14>),
    Aes192Gcm112(AesGcm<Aes192, U12, U14>),
    Aes256Gcm112(AesGcm<Aes256, U12, U14>),
    Aes128Gcm120(AesGcm<Aes128, U12, U15>),
    Aes192Gcm120(AesGcm<Aes192, U12, U15>),
    Aes256Gcm120(AesGcm<Aes256, U12, U15>),
    Aes128Gcm128(AesGcm<Aes128, U12, U16>),
    Aes192Gcm128(AesGcm<Aes192, U12, U16>),
    Aes256Gcm128(AesGcm<Aes256, U12, U16>),
}

#[allow(dead_code)]
impl AesGcmVariant {
    pub fn new(
        key_len: u16,
        tag_length: u8,
        key: &[u8],
    ) -> std::result::Result<Self, InvalidLength> {
        let variant = match (key_len, tag_length) {
            (128, 32) => Self::Aes128Gcm32(AesGcm::new_from_slice(key)?),
            (192, 32) => Self::Aes192Gcm32(AesGcm::new_from_slice(key)?),
            (256, 32) => Self::Aes256Gcm32(AesGcm::new_from_slice(key)?),
            (128, 64) => Self::Aes128Gcm64(AesGcm::new_from_slice(key)?),
            (192, 64) => Self::Aes192Gcm64(AesGcm::new_from_slice(key)?),
            (256, 64) => Self::Aes256Gcm64(AesGcm::new_from_slice(key)?),
            (128, 96) => Self::Aes128Gcm96(AesGcm::new_from_slice(key)?),
            (192, 96) => Self::Aes192Gcm96(AesGcm::new_from_slice(key)?),
            (256, 96) => Self::Aes256Gcm96(AesGcm::new_from_slice(key)?),
            (128, 104) => Self::Aes128Gcm104(AesGcm::new_from_slice(key)?),
            (192, 104) => Self::Aes192Gcm104(AesGcm::new_from_slice(key)?),
            (256, 104) => Self::Aes256Gcm104(AesGcm::new_from_slice(key)?),
            (128, 112) => Self::Aes128Gcm112(AesGcm::new_from_slice(key)?),
            (192, 112) => Self::Aes192Gcm112(AesGcm::new_from_slice(key)?),
            (256, 112) => Self::Aes256Gcm112(AesGcm::new_from_slice(key)?),
            (128, 120) => Self::Aes128Gcm120(AesGcm::new_from_slice(key)?),
            (192, 120) => Self::Aes192Gcm120(AesGcm::new_from_slice(key)?),
            (256, 120) => Self::Aes256Gcm120(AesGcm::new_from_slice(key)?),
            (128, 128) => Self::Aes128Gcm128(AesGcm::new_from_slice(key)?),
            (192, 128) => Self::Aes192Gcm128(AesGcm::new_from_slice(key)?),
            (256, 128) => Self::Aes256Gcm128(AesGcm::new_from_slice(key)?),
            _ => return Err(InvalidLength),
        };

        Ok(variant)
    }

    pub fn encrypt(
        &self,
        nonce: &[u8],
        msg: &[u8],
        aad: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, aes_gcm::Error> {
        let plaintext: Payload = Payload {
            msg,
            aad: aad.unwrap_or_default(),
        };
        let nonce: &aes_gcm::aes::cipher::Array<_, _> =
            &Nonce::<U12>::try_from(nonce).map_err(|_| aes_gcm::Error)?;
        match self {
            Self::Aes128Gcm32(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm32(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm32(v) => v.encrypt(nonce, plaintext),
            Self::Aes128Gcm64(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm64(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm64(v) => v.encrypt(nonce, plaintext),
            Self::Aes128Gcm96(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm96(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm96(v) => v.encrypt(nonce, plaintext),
            Self::Aes128Gcm104(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm104(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm104(v) => v.encrypt(nonce, plaintext),
            Self::Aes128Gcm112(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm112(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm112(v) => v.encrypt(nonce, plaintext),
            Self::Aes128Gcm120(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm120(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm120(v) => v.encrypt(nonce, plaintext),
            Self::Aes128Gcm128(v) => v.encrypt(nonce, plaintext),
            Self::Aes192Gcm128(v) => v.encrypt(nonce, plaintext),
            Self::Aes256Gcm128(v) => v.encrypt(nonce, plaintext),
        }
    }

    pub fn decrypt(
        &self,
        nonce: &[u8],
        msg: &[u8],
        aad: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, aes_gcm::Error> {
        let ciphertext: Payload = Payload {
            msg,
            aad: aad.unwrap_or_default(),
        };
        let nonce: &aes_gcm::aes::cipher::Array<_, _> =
            &Nonce::<U12>::try_from(nonce).map_err(|_| aes_gcm::Error)?;
        match self {
            Self::Aes128Gcm32(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm32(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm32(v) => v.decrypt(nonce, ciphertext),
            Self::Aes128Gcm64(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm64(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm64(v) => v.decrypt(nonce, ciphertext),
            Self::Aes128Gcm96(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm96(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm96(v) => v.decrypt(nonce, ciphertext),
            Self::Aes128Gcm104(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm104(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm104(v) => v.decrypt(nonce, ciphertext),
            Self::Aes128Gcm112(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm112(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm112(v) => v.decrypt(nonce, ciphertext),
            Self::Aes128Gcm120(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm120(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm120(v) => v.decrypt(nonce, ciphertext),
            Self::Aes128Gcm128(v) => v.decrypt(nonce, ciphertext),
            Self::Aes192Gcm128(v) => v.decrypt(nonce, ciphertext),
            Self::Aes256Gcm128(v) => v.decrypt(nonce, ciphertext),
        }
    }
}
