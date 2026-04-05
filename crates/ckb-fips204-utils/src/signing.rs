//! Deterministic ML-DSA-65 key derivation and signing for CKB.
//!
//! Key derivation chain:
//!   master_seed  →  HKDF-SHA256("ckb/quantum-purse/ml-dsa-65/{index}")  →  32-byte ξ
//!               →  ML-DSA-65.KeyGen_internal(ξ)  →  (pubkey, secret_key)
//!
//! This mirrors the SPHINCS+ HKDF pattern in key-vault-wasm but uses a distinct
//! path prefix to ensure complete key-space separation between the two schemes.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    lock_args_from_pubkey, serialize_mldsa_witness, signing_message,
    KDF_PATH_PREFIX, LOCK_ARGS_LEN, MLDSA_WITNESS_LEN, PUBKEY_LEN, SIG_LEN, SK_LEN,
};

/// A zeroize-on-drop container for an ML-DSA-65 secret key.
#[derive(ZeroizeOnDrop)]
struct SecretKeyBytes([u8; SK_LEN]);

/// Derive a 32-byte ML-DSA-65 keygen seed from the wallet master seed + account index.
///
/// Uses HKDF-SHA256 with `info = "ckb/quantum-purse/ml-dsa-65/{index}"`.
/// The master seed is used as IKM in its entirety (works with any length ≥ 0).
fn derive_seed(master_seed: &[u8], index: u32) -> Result<[u8; 32], String> {
    let info = format!("{}{}", KDF_PATH_PREFIX, index);
    let hkdf = Hkdf::<Sha256>::new(None, master_seed);
    let mut seed = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut seed)
        .map_err(|e| format!("HKDF expand error: {:?}", e))?;
    Ok(seed)
}

/// Derive the ML-DSA-65 public key bytes and lock script args for an account.
///
/// Returns `(pubkey_bytes [1952 B], lock_args [36 B])`.
/// The secret key is derived and immediately dropped — this is a read-only path
/// for account creation / batch scanning.
pub fn derive_lock_args(master_seed: &[u8], index: u32) -> Result<([u8; PUBKEY_LEN], [u8; LOCK_ARGS_LEN]), String> {
    let mut seed = derive_seed(master_seed, index)?;
    let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    seed.zeroize();

    let pubkey = pk.into_bytes();
    let args = lock_args_from_pubkey(&pubkey);
    Ok((pubkey, args))
}

/// Sign a CKB transaction and return the Molecule-encoded MldsaWitness bytes.
///
/// `tx_hash`: raw 32-byte CKB transaction hash (from `ckb_checked_load_tx_hash`).
///
/// Internally computes `msg = blake2b_256("CKB-MLDSA-LOCK" || tx_hash)` and
/// then calls `ml_dsa_65::PrivateKey::try_sign(msg, b"CKB-MLDSA-LOCK")`.
///
/// Returns `MLDSA_WITNESS_LEN` (5305) bytes — the content of `WitnessArgs.lock`.
pub fn sign(
    master_seed: &[u8],
    index: u32,
    tx_hash: &[u8],
) -> Result<Vec<u8>, String> {
    let mut seed = derive_seed(master_seed, index)?;
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    seed.zeroize();

    // Wrap SK bytes for zeroize-on-drop
    let mut sk_bytes = SecretKeyBytes(
        sk.into_bytes()
            .try_into()
            .map_err(|_| "SK serialization length mismatch".to_string())?,
    );

    let msg = signing_message(tx_hash);
    let signing_key = ml_dsa_65::PrivateKey::try_from_bytes(&sk_bytes.0)
        .map_err(|e| format!("Invalid ML-DSA-65 secret key: {:?}", e))?;

    let signature = signing_key
        .try_sign(&msg, CRATE_DOMAIN)
        .map_err(|e| format!("ML-DSA-65 signing failed: {:?}", e))?;

    sk_bytes.0.zeroize();

    let sig_bytes: &[u8; SIG_LEN] = signature
        .as_ref()
        .try_into()
        .map_err(|_| "Signature length mismatch".to_string())?;

    let pk_raw = pk.into_bytes();
    let pk_bytes: &[u8; PUBKEY_LEN] = pk_raw
        .as_ref()
        .try_into()
        .map_err(|_| "Public key length mismatch".to_string())?;

    Ok(serialize_mldsa_witness(pk_bytes, sig_bytes))
}

// The domain context passed to ML-DSA sign/verify — must match the on-chain lock script.
const CRATE_DOMAIN: &[u8] = crate::DOMAIN;
