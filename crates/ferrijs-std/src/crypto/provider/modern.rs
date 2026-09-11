// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "_subtle-full")]
use ml_dsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ml_dsa::{
    pkcs8::{der::AnyRef, spki::AssociatedAlgorithmIdentifier, DecodePublicKey},
    Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey,
};
use ml_kem::{
    Decapsulate, EncapsulationKey as MlKemEncapsulationKey, Key as MlKemKey,
    KeyExport as MlKemKeyExport, MlKem1024, MlKem512, MlKem768, Seed as MlKemSeed,
    B32 as MlKemRandomness,
};

use aws_lc_rs::{aead as lc_aead, agreement as lc_agreement, digest as lc_digest};

use super::{CryptoError, HybridKemVariant, MlDsaVariant, MlKemVariant};

trait MlDsaParameterSet: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>> {}

impl MlDsaParameterSet for MlDsa44 {}
impl MlDsaParameterSet for MlDsa65 {}
impl MlDsaParameterSet for MlDsa87 {}

macro_rules! dispatch_ml_dsa {
    ($variant:expr, $function:ident $(, $argument:expr)* $(,)?) => {
        match $variant {
            MlDsaVariant::MlDsa44 => $function::<MlDsa44>($($argument),*),
            MlDsaVariant::MlDsa65 => $function::<MlDsa65>($($argument),*),
            MlDsaVariant::MlDsa87 => $function::<MlDsa87>($($argument),*),
        }
    };
}

macro_rules! dispatch_ml_kem {
    ($variant:expr, |$kem:ident| $body:block) => {
        match $variant {
            MlKemVariant::MlKem512 => {
                type $kem = MlKem512;
                $body
            },
            MlKemVariant::MlKem768 => {
                type $kem = MlKem768;
                $body
            },
            MlKemVariant::MlKem1024 => {
                type $kem = MlKem1024;
                $body
            },
        }
    };
}

// ChaCha20-Poly1305 always carries a 128-bit tag, and WebCrypto appends it to
// the ciphertext, the same shape as AES-GCM here; `seal_in_place_append_tag`
// and `open_in_place` handle that placement themselves.
// ChaCha20-Poly1305 always carries a 128-bit tag, and WebCrypto appends it to
// the ciphertext, the same shape as AES-GCM here.
fn chacha20_poly1305_key(key: &[u8]) -> Result<lc_aead::LessSafeKey, CryptoError> {
    lc_aead::UnboundKey::new(&lc_aead::CHACHA20_POLY1305, key)
        .map(lc_aead::LessSafeKey::new)
        .map_err(|_| CryptoError::InvalidKey(None))
}

fn chacha20_poly1305_nonce(iv: &[u8]) -> Result<lc_aead::Nonce, CryptoError> {
    let iv = <[u8; 12]>::try_from(iv).map_err(|_| CryptoError::InvalidData(None))?;
    Ok(lc_aead::Nonce::assume_unique_for_key(iv))
}

pub(crate) fn chacha20_poly1305_encrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let sealing_key = chacha20_poly1305_key(key)?;
    let mut in_out = data.to_vec();
    sealing_key
        .seal_in_place_append_tag(
            chacha20_poly1305_nonce(iv)?,
            lc_aead::Aad::from(additional_data.unwrap_or_default()),
            &mut in_out,
        )
        .map_err(|_| CryptoError::EncryptionFailed(None))?;
    Ok(in_out)
}

pub(crate) fn chacha20_poly1305_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let opening_key = chacha20_poly1305_key(key)?;
    let mut in_out = data.to_vec();
    let plaintext = opening_key
        .open_in_place(
            chacha20_poly1305_nonce(iv)?,
            lc_aead::Aad::from(additional_data.unwrap_or_default()),
            &mut in_out,
        )
        .map_err(|_| CryptoError::DecryptionFailed(None))?;
    Ok(plaintext.to_vec())
}

fn ml_dsa_signing_key<P: MlDsaParameterSet>(seed: &[u8]) -> Result<SigningKey<P>, CryptoError> {
    let seed = Seed::try_from(seed).map_err(|_| CryptoError::InvalidKey(None))?;
    Ok(SigningKey::from_seed(&seed))
}

fn ml_dsa_verifying_key<P: MlDsaParameterSet>(
    public_key: &[u8],
) -> Result<VerifyingKey<P>, CryptoError> {
    let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(public_key)
        .map_err(|_| CryptoError::InvalidKey(None))?;
    Ok(VerifyingKey::decode(&encoded))
}

fn generate_ml_dsa_key_for<P: MlDsaParameterSet>() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let seed = crate::crypto::random_byte_array(32);
    let signing_key = ml_dsa_signing_key::<P>(&seed)?;
    let public_key = signing_key.verifying_key().encode().to_vec();
    Ok((seed, public_key))
}

pub(crate) fn generate_ml_dsa_key(
    variant: MlDsaVariant,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    dispatch_ml_dsa!(variant, generate_ml_dsa_key_for)
}

fn ml_dsa_public_key_for<P: MlDsaParameterSet>(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(ml_dsa_signing_key::<P>(seed)?
        .verifying_key()
        .encode()
        .to_vec())
}

pub(crate) fn ml_dsa_public_key(
    variant: MlDsaVariant,
    seed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_dsa!(variant, ml_dsa_public_key_for, seed)
}

fn ml_dsa_sign_for<P: MlDsaParameterSet>(
    seed: &[u8],
    data: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let signing_key = ml_dsa_signing_key::<P>(seed)?;
    let mut rng = rand::rng();
    signing_key
        .expanded_key()
        .sign_randomized(data, context, &mut rng)
        .map(|signature| signature.encode().to_vec())
        .map_err(|_| CryptoError::SigningFailed(None))
}

pub(crate) fn ml_dsa_sign(
    variant: MlDsaVariant,
    seed: &[u8],
    data: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_dsa!(variant, ml_dsa_sign_for, seed, data, context)
}

fn ml_dsa_verify_for<P: MlDsaParameterSet>(
    public_key: &[u8],
    signature: &[u8],
    data: &[u8],
    context: &[u8],
) -> Result<bool, CryptoError> {
    let verifying_key = ml_dsa_verifying_key::<P>(public_key)?;
    let signature =
        Signature::<P>::try_from(signature).map_err(|_| CryptoError::InvalidSignature(None))?;
    Ok(verifying_key.verify_with_context(data, context, &signature))
}

pub(crate) fn ml_dsa_verify(
    variant: MlDsaVariant,
    public_key: &[u8],
    signature: &[u8],
    data: &[u8],
    context: &[u8],
) -> Result<bool, CryptoError> {
    dispatch_ml_dsa!(
        variant,
        ml_dsa_verify_for,
        public_key,
        signature,
        data,
        context,
    )
}

#[cfg(feature = "_subtle-full")]
fn import_ml_dsa_public_key_for<P: MlDsaParameterSet>(
    data: &[u8],
    spki: bool,
) -> Result<Vec<u8>, CryptoError> {
    let key = if spki {
        VerifyingKey::<P>::from_public_key_der(data).map_err(|_| CryptoError::InvalidKey(None))?
    } else {
        ml_dsa_verifying_key::<P>(data)?
    };
    Ok(key.encode().to_vec())
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn import_ml_dsa_public_key(
    variant: MlDsaVariant,
    data: &[u8],
    spki: bool,
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_dsa!(variant, import_ml_dsa_public_key_for, data, spki)
}

#[cfg(feature = "_subtle-full")]
fn import_ml_dsa_private_key_for<P: MlDsaParameterSet>(
    data: &[u8],
    pkcs8: bool,
) -> Result<Vec<u8>, CryptoError> {
    let key = if pkcs8 {
        SigningKey::<P>::from_pkcs8_der(data).map_err(|_| CryptoError::InvalidKey(None))?
    } else {
        ml_dsa_signing_key::<P>(data)?
    };
    Ok(key.to_seed().to_vec())
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn import_ml_dsa_private_key(
    variant: MlDsaVariant,
    data: &[u8],
    pkcs8: bool,
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_dsa!(variant, import_ml_dsa_private_key_for, data, pkcs8)
}

#[cfg(feature = "_subtle-full")]
fn export_ml_dsa_public_key_spki_for<P: MlDsaParameterSet>(
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ml_dsa_verifying_key::<P>(public_key)?
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|_| CryptoError::InvalidKey(None))
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn export_ml_dsa_public_key_spki(
    variant: MlDsaVariant,
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_dsa!(variant, export_ml_dsa_public_key_spki_for, public_key,)
}

#[cfg(feature = "_subtle-full")]
fn export_ml_dsa_private_key_pkcs8_for<P: MlDsaParameterSet>(
    seed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ml_dsa_signing_key::<P>(seed)?
        .to_pkcs8_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|_| CryptoError::InvalidKey(None))
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn export_ml_dsa_private_key_pkcs8(
    variant: MlDsaVariant,
    seed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_dsa!(variant, export_ml_dsa_private_key_pkcs8_for, seed,)
}

pub(crate) fn generate_ml_kem_key(
    variant: MlKemVariant,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let seed = crate::crypto::random_byte_array(64);
    let seed = MlKemSeed::try_from(seed.as_slice()).map_err(|_| CryptoError::InvalidKey(None))?;
    dispatch_ml_kem!(variant, |Kem| {
        let private_key = ml_kem::DecapsulationKey::<Kem>::from_seed(seed);
        let public_key = private_key.encapsulation_key().to_bytes().to_vec();
        Ok((seed.to_vec(), public_key))
    })
}

pub(crate) fn ml_kem_public_key(
    variant: MlKemVariant,
    seed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let seed = MlKemSeed::try_from(seed).map_err(|_| CryptoError::InvalidKey(None))?;
    dispatch_ml_kem!(variant, |Kem| {
        let private_key = ml_kem::DecapsulationKey::<Kem>::from_seed(seed);
        Ok(private_key.encapsulation_key().to_bytes().to_vec())
    })
}

pub(crate) fn ml_kem_encapsulate(
    variant: MlKemVariant,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let randomness = crate::crypto::random_byte_array(32);
    let randomness = MlKemRandomness::try_from(randomness.as_slice())
        .map_err(|_| CryptoError::OperationFailed(None))?;
    dispatch_ml_kem!(variant, |Kem| {
        let encoded = MlKemKey::<MlKemEncapsulationKey<Kem>>::try_from(public_key)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let public_key = MlKemEncapsulationKey::<Kem>::new(&encoded)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        let (ciphertext, shared_key) = public_key.encapsulate_deterministic(&randomness);
        Ok((ciphertext.to_vec(), shared_key.to_vec()))
    })
}

pub(crate) fn ml_kem_decapsulate(
    variant: MlKemVariant,
    seed: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let seed = MlKemSeed::try_from(seed).map_err(|_| CryptoError::InvalidKey(None))?;
    dispatch_ml_kem!(variant, |Kem| {
        let private_key = ml_kem::DecapsulationKey::<Kem>::from_seed(seed);
        private_key
            .decapsulate_slice(ciphertext)
            .map(|shared_key| shared_key.to_vec())
            .map_err(|_| CryptoError::OperationFailed(Some("Invalid ML-KEM ciphertext".into())))
    })
}

pub(crate) fn import_ml_kem_public_key(
    variant: MlKemVariant,
    data: &[u8],
    spki: bool,
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_kem!(variant, |Kem| {
        let key = if spki {
            MlKemEncapsulationKey::<Kem>::from_public_key_der(data)
                .map_err(|_| CryptoError::InvalidKey(None))?
        } else {
            let encoded = MlKemKey::<MlKemEncapsulationKey<Kem>>::try_from(data)
                .map_err(|_| CryptoError::InvalidKey(None))?;
            MlKemEncapsulationKey::<Kem>::new(&encoded)
                .map_err(|_| CryptoError::InvalidKey(None))?
        };
        Ok(key.to_bytes().to_vec())
    })
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn import_ml_kem_private_key(
    variant: MlKemVariant,
    data: &[u8],
    pkcs8: bool,
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_kem!(variant, |Kem| {
        let key = if pkcs8 {
            ml_kem::DecapsulationKey::<Kem>::from_pkcs8_der(data)
                .map_err(|_| CryptoError::InvalidKey(None))?
        } else {
            let seed = MlKemSeed::try_from(data).map_err(|_| CryptoError::InvalidKey(None))?;
            ml_kem::DecapsulationKey::<Kem>::from_seed(seed)
        };
        key.to_seed()
            .map(|seed| seed.to_vec())
            .ok_or(CryptoError::InvalidKey(None))
    })
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn export_ml_kem_public_key_spki(
    variant: MlKemVariant,
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch_ml_kem!(variant, |Kem| {
        let encoded = MlKemKey::<MlKemEncapsulationKey<Kem>>::try_from(public_key)
            .map_err(|_| CryptoError::InvalidKey(None))?;
        MlKemEncapsulationKey::<Kem>::new(&encoded)
            .map_err(|_| CryptoError::InvalidKey(None))?
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| CryptoError::InvalidKey(None))
    })
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn export_ml_kem_private_key_pkcs8(
    variant: MlKemVariant,
    seed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let seed = MlKemSeed::try_from(seed).map_err(|_| CryptoError::InvalidKey(None))?;
    dispatch_ml_kem!(variant, |Kem| {
        ml_kem::DecapsulationKey::<Kem>::from_seed(seed)
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| CryptoError::InvalidKey(None))
    })
}

// Ec carries its curve so decapsulation can parse the peer point; X25519 is
// kept apart because its shared secret needs the all-zero rejection.
// The algorithm the key was built under says which curve it is, so the key
// needs no tag of its own; only whether the all-zero rejection applies.
struct TraditionalPrivateKey {
    key: lc_agreement::PrivateKey,
    algorithm: &'static lc_agreement::Algorithm,
    is_x25519: bool,
}

struct HybridKeyPair {
    pq_seed: Vec<u8>,
    traditional_private_key: TraditionalPrivateKey,
    traditional_public_key: Vec<u8>,
    public_key: Vec<u8>,
}

fn shake256(input: &[u8], output_length: usize) -> Vec<u8> {
    // SHAKE is an XOF, so the digest length is the caller's choice rather than
    // the algorithm's. AWS-LC implements SHA-3 but exposes no XOF, so this one
    // stays on a pure-Rust implementation.
    use shake::{ExtendableOutput, Update, XofReader};

    let mut output = vec![0; output_length];
    let mut hash = shake::Shake256::default();
    hash.update(input);
    hash.finalize_xof().read(&mut output);
    output
}

// The traditional half of a hybrid key is rejection-sampled from the SHAKE
// expansion: the first fixed-width chunk that is a valid scalar wins. A scalar
// is valid when 0 < d < n, which is the same test `SecretKey::from_slice` made
// before this moved to OpenSSL, so derived keys are unchanged.
fn ec_private_key_from_seed(
    algorithm: &'static lc_agreement::Algorithm,
    chunk_len: usize,
    seed: &[u8],
) -> Result<lc_agreement::PrivateKey, CryptoError> {
    for chunk in seed.chunks_exact(chunk_len) {
        // AWS-LC validates the scalar, so the first chunk it accepts is the
        // first valid one, which is the rejection sampling this needs.
        if let Ok(key) = lc_agreement::PrivateKey::from_private_key(algorithm, chunk) {
            return Ok(key);
        }
    }
    Err(CryptoError::OperationFailed(Some(
        "hybrid KEM traditional key rejection sampling failed".into(),
    )))
}

fn ec_public_point(key: &lc_agreement::PrivateKey) -> Result<Vec<u8>, CryptoError> {
    key.compute_public_key()
        .map(|public| public.as_ref().to_vec())
        .map_err(|_| CryptoError::OperationFailed(None))
}

fn agree(
    private_key: &lc_agreement::PrivateKey,
    algorithm: &'static lc_agreement::Algorithm,
    peer: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let peer = lc_agreement::UnparsedPublicKey::new(algorithm, peer);
    lc_agreement::agree(
        private_key,
        peer,
        CryptoError::OperationFailed(None),
        |secret| Ok(secret.to_vec()),
    )
}

// RFC 7748 says to reject an all-zero X25519 secret, which is what a
// small-order peer point produces.
fn reject_all_zero(shared: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::OperationFailed(None));
    }
    Ok(shared)
}

// The traditional half of each hybrid, and the width of the scalar the seed is
// sampled into. X25519 takes its seed whole rather than by rejection.
fn hybrid_traditional(
    variant: HybridKemVariant,
) -> (&'static lc_agreement::Algorithm, usize) {
    match variant {
        HybridKemVariant::MlKem768P256 => (&lc_agreement::ECDH_P256, 32),
        HybridKemVariant::MlKem768X25519 => (&lc_agreement::X25519, 32),
        HybridKemVariant::MlKem1024P384 => (&lc_agreement::ECDH_P384, 48),
    }
}

fn derive_hybrid_key_pair(
    variant: HybridKemVariant,
    seed: &[u8],
) -> Result<HybridKeyPair, CryptoError> {
    if seed.len() != 32 {
        return Err(CryptoError::InvalidKey(None));
    }
    let traditional_seed_length = match variant {
        HybridKemVariant::MlKem768P256 => 128,
        HybridKemVariant::MlKem768X25519 => 32,
        HybridKemVariant::MlKem1024P384 => 48,
    };
    let expanded = shake256(seed, 64 + traditional_seed_length);
    let (pq_seed, traditional_seed) = expanded.split_at(64);
    let pq_public_key = ml_kem_public_key(variant.ml_kem_variant(), pq_seed)?;

    let (algorithm, chunk_len) = hybrid_traditional(variant);
    let is_x25519 = matches!(variant, HybridKemVariant::MlKem768X25519);
    let private_key = if is_x25519 {
        lc_agreement::PrivateKey::from_private_key(algorithm, traditional_seed)
            .map_err(|_| CryptoError::OperationFailed(None))?
    } else {
        ec_private_key_from_seed(algorithm, chunk_len, traditional_seed)?
    };
    let traditional_public_key = ec_public_point(&private_key)?;
    let traditional_private_key = TraditionalPrivateKey {
        key: private_key,
        algorithm,
        is_x25519,
    };

    let mut public_key = pq_public_key;
    public_key.extend_from_slice(&traditional_public_key);
    Ok(HybridKeyPair {
        pq_seed: pq_seed.to_vec(),
        traditional_private_key,
        traditional_public_key,
        public_key,
    })
}

fn hybrid_kem_combiner(
    variant: HybridKemVariant,
    pq_shared_key: &[u8],
    traditional_shared_key: &[u8],
    traditional_ciphertext: &[u8],
    traditional_public_key: &[u8],
) -> Vec<u8> {
    let label: &[u8] = match variant {
        HybridKemVariant::MlKem768P256 => b"MLKEM768-P256",
        HybridKemVariant::MlKem768X25519 => b"\\.//^\\",
        HybridKemVariant::MlKem1024P384 => b"MLKEM1024-P384",
    };
    let mut input = Vec::with_capacity(
        pq_shared_key.len()
            + traditional_shared_key.len()
            + traditional_ciphertext.len()
            + traditional_public_key.len()
            + label.len(),
    );
    input.extend_from_slice(pq_shared_key);
    input.extend_from_slice(traditional_shared_key);
    input.extend_from_slice(traditional_ciphertext);
    input.extend_from_slice(traditional_public_key);
    input.extend_from_slice(label);
    lc_digest::digest(&lc_digest::SHA3_256, &input).as_ref().to_vec()
}

fn traditional_encapsulate(
    variant: HybridKemVariant,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (algorithm, chunk_len) = hybrid_traditional(variant);
    let is_x25519 = matches!(variant, HybridKemVariant::MlKem768X25519);
    let ephemeral = if is_x25519 {
        lc_agreement::PrivateKey::generate(algorithm)
            .map_err(|_| CryptoError::OperationFailed(None))?
    } else {
        // The seed is drawn wide so rejection sampling has several chunks to
        // try before giving up.
        ec_private_key_from_seed(
            algorithm,
            chunk_len,
            &crate::crypto::random_byte_array(chunk_len * 4),
        )?
    };
    let ciphertext = ec_public_point(&ephemeral)?;
    let shared_key = agree(&ephemeral, algorithm, public_key)?;
    let shared_key = if is_x25519 {
        reject_all_zero(shared_key)?
    } else {
        shared_key
    };
    Ok((ciphertext, shared_key))
}

fn traditional_decapsulate(
    private_key: &TraditionalPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let shared = agree(&private_key.key, private_key.algorithm, ciphertext)?;
    if private_key.is_x25519 {
        reject_all_zero(shared)
    } else {
        Ok(shared)
    }
}

pub(crate) fn generate_hybrid_kem_key(
    variant: HybridKemVariant,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let seed = crate::crypto::random_byte_array(32);
    let public_key = derive_hybrid_key_pair(variant, &seed)?.public_key;
    Ok((seed, public_key))
}

pub(crate) fn hybrid_kem_public_key(
    variant: HybridKemVariant,
    seed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Ok(derive_hybrid_key_pair(variant, seed)?.public_key)
}

pub(crate) fn import_hybrid_kem_public_key(
    variant: HybridKemVariant,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if data.len() != variant.public_key_length() {
        return Err(CryptoError::InvalidKey(None));
    }
    let (pq_public_key, traditional_public_key) = data.split_at(variant.pq_public_key_length());
    let pq_public_key = import_ml_kem_public_key(variant.ml_kem_variant(), pq_public_key, false)?;
    // Parsing is the validation: an EC point has to be on the curve, and an
    // X25519 point has to be the right length.
    let (algorithm, _) = hybrid_traditional(variant);
    let peer = lc_agreement::UnparsedPublicKey::new(algorithm, traditional_public_key);
    let _: lc_agreement::ParsedPublicKey =
        peer.try_into().map_err(|_| CryptoError::InvalidKey(None))?;
    let mut normalized = pq_public_key;
    normalized.extend_from_slice(traditional_public_key);
    Ok(normalized)
}

#[cfg(feature = "_subtle-full")]
pub(crate) fn import_hybrid_kem_private_key(
    variant: HybridKemVariant,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    derive_hybrid_key_pair(variant, data)?;
    Ok(data.to_vec())
}

pub(crate) fn hybrid_kem_encapsulate(
    variant: HybridKemVariant,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let public_key = import_hybrid_kem_public_key(variant, public_key)?;
    let (pq_public_key, traditional_public_key) =
        public_key.split_at(variant.pq_public_key_length());
    let (pq_ciphertext, pq_shared_key) =
        ml_kem_encapsulate(variant.ml_kem_variant(), pq_public_key)?;
    let (traditional_ciphertext, traditional_shared_key) =
        traditional_encapsulate(variant, traditional_public_key)?;
    let shared_key = hybrid_kem_combiner(
        variant,
        &pq_shared_key,
        &traditional_shared_key,
        &traditional_ciphertext,
        traditional_public_key,
    );
    let mut ciphertext = pq_ciphertext;
    ciphertext.extend_from_slice(&traditional_ciphertext);
    Ok((ciphertext, shared_key))
}

pub(crate) fn hybrid_kem_decapsulate(
    variant: HybridKemVariant,
    seed: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() != variant.ciphertext_length() {
        return Err(CryptoError::OperationFailed(Some(
            "Invalid hybrid KEM ciphertext".into(),
        )));
    }
    let key_pair = derive_hybrid_key_pair(variant, seed)?;
    let (pq_ciphertext, traditional_ciphertext) =
        ciphertext.split_at(variant.pq_ciphertext_length());
    let pq_shared_key =
        ml_kem_decapsulate(variant.ml_kem_variant(), &key_pair.pq_seed, pq_ciphertext)?;
    let traditional_shared_key =
        traditional_decapsulate(&key_pair.traditional_private_key, traditional_ciphertext)?;
    Ok(hybrid_kem_combiner(
        variant,
        &pq_shared_key,
        &traditional_shared_key,
        traditional_ciphertext,
        &key_pair.traditional_public_key,
    ))
}
