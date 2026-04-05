//! CKB ML-DSA-65 (FIPS 204) utilities for QuantumPurse key-vault-wasm.
//!
//! # Lock script args layout (36 bytes)
//!   [0]    version   = 0x01
//!   [1]    algo_id   = 0x02  (ML-DSA)
//!   [2]    param_id  = 0x02  (ML-DSA-65)
//!   [3]    reserved  = 0x00
//!   [4-35] blake2b_256(pubkey)
//!
//! # Witness lock field: Molecule-encoded MldsaWitness table (5305 bytes)
//!   version | algo_id | param_id | flags | pubkey (1952 B) | signature (3309 B)
//!
//! # Signing message
//!   msg = blake2b_256("CKB-MLDSA-LOCK" || tx_hash)   [32 bytes]
//!   ctx = b"CKB-MLDSA-LOCK"                           [14 bytes]
//!   Passed to ML-DSA sign/verify as (msg, ctx).

pub mod signing;

// ── sizes ─────────────────────────────────────────────────────────────────────

/// ML-DSA-65 public key length in bytes (FIPS 204 fixed parameter)
pub const PUBKEY_LEN: usize = 1952;
/// ML-DSA-65 signature length in bytes (FIPS 204 fixed parameter)
pub const SIG_LEN: usize = 3309;
/// ML-DSA-65 secret key length in bytes (FIPS 204 fixed parameter)
pub const SK_LEN: usize = 4032;

// ── lock args ─────────────────────────────────────────────────────────────────

/// Total length of the lock script args field
pub const LOCK_ARGS_LEN: usize = 36;
pub const LOCK_VERSION: u8 = 0x01;
pub const LOCK_ALGO_ID: u8 = 0x02; // ML-DSA
pub const LOCK_PARAM_ID: u8 = 0x02; // ML-DSA-65

// ── MldsaWitness Molecule encoding ───────────────────────────────────────────
//
// table MldsaWitness {
//   version:   Bytes,   // 1 byte
//   algo_id:   Bytes,   // 1 byte
//   param_id:  Bytes,   // 1 byte
//   flags:     Bytes,   // 1 byte
//   pubkey:    Bytes,   // 1952 bytes
//   signature: Bytes,   // 3309 bytes
// }
//
// Molecule table layout:
//   full_size(4) | offset[0..5](4 each) | field_data
// Each Bytes field: length_prefix(4) + data

const N_FIELDS: usize = 6;
const WIT_HEADER: usize = 4 + N_FIELDS * 4; // 28 bytes
/// Total size of a serialised MldsaWitness (the lock field content)
pub const MLDSA_WITNESS_LEN: usize = WIT_HEADER
    + 1 + 1 + 1 + 1          // four single-byte fields (no length prefix in simple Bytes)
    + 4 + PUBKEY_LEN          // pubkey Bytes field
    + 4 + SIG_LEN;            // signature Bytes field
// = 28 + 4 + 1956 + 3313 = 5305

// ── domain separator ──────────────────────────────────────────────────────────

pub const DOMAIN: &[u8] = b"CKB-MLDSA-LOCK";

// ── KDF path ─────────────────────────────────────────────────────────────────

/// HKDF info prefix used for ML-DSA-65 child key derivation.
/// Full info string per account: `"ckb/quantum-purse/ml-dsa-65/{index}"`.
pub const KDF_PATH_PREFIX: &str = "ckb/quantum-purse/ml-dsa-65/";

// ── public helpers ────────────────────────────────────────────────────────────

/// Compute the CKB ML-DSA signing message: `blake2b_256("CKB-MLDSA-LOCK" || tx_hash)`.
pub fn signing_message(tx_hash: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(DOMAIN.len() + tx_hash.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(tx_hash);
    ckb_hash::blake2b_256(input)
}

/// Derive the 36-byte lock script args from an ML-DSA-65 public key.
pub fn lock_args_from_pubkey(pubkey: &[u8]) -> [u8; LOCK_ARGS_LEN] {
    let hash = ckb_hash::blake2b_256(pubkey);
    let mut args = [0u8; LOCK_ARGS_LEN];
    args[0] = LOCK_VERSION;
    args[1] = LOCK_ALGO_ID;
    args[2] = LOCK_PARAM_ID;
    args[3] = 0x00; // reserved
    args[4..].copy_from_slice(&hash);
    args
}

/// Serialize pubkey + signature into a Molecule-encoded MldsaWitness table.
/// Returns exactly `MLDSA_WITNESS_LEN` (5305) bytes — the content of `WitnessArgs.lock`.
pub fn serialize_mldsa_witness(pubkey: &[u8; PUBKEY_LEN], sig: &[u8; SIG_LEN]) -> Vec<u8> {
    let total = MLDSA_WITNESS_LEN;
    let mut buf = vec![0u8; total];

    // total_size
    write_u32_le(&mut buf[0..], total as u32);

    // field offsets (each field starts after the header + preceding fields)
    let mut off = WIT_HEADER as u32;
    write_u32_le(&mut buf[4..],  off); off += 1;                          // version (1 B)
    write_u32_le(&mut buf[8..],  off); off += 1;                          // algo_id (1 B)
    write_u32_le(&mut buf[12..], off); off += 1;                          // param_id (1 B)
    write_u32_le(&mut buf[16..], off); off += 1;                          // flags (1 B)
    write_u32_le(&mut buf[20..], off); off += 4 + PUBKEY_LEN as u32;     // pubkey Bytes
    write_u32_le(&mut buf[24..], off);                                     // signature Bytes

    let p = &mut buf[WIT_HEADER..];
    p[0] = LOCK_VERSION;
    p[1] = LOCK_ALGO_ID;
    p[2] = LOCK_PARAM_ID;
    p[3] = 0x00; // flags (reserved)

    let mut cursor = 4;
    write_u32_le(&mut p[cursor..], PUBKEY_LEN as u32); cursor += 4;
    p[cursor..cursor + PUBKEY_LEN].copy_from_slice(pubkey);               cursor += PUBKEY_LEN;
    write_u32_le(&mut p[cursor..], SIG_LEN as u32);   cursor += 4;
    p[cursor..cursor + SIG_LEN].copy_from_slice(sig);

    buf
}

#[inline]
fn write_u32_le(buf: &mut [u8], v: u32) {
    buf[0] = v as u8;
    buf[1] = (v >> 8) as u8;
    buf[2] = (v >> 16) as u8;
    buf[3] = (v >> 24) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_len_constant_matches_layout() {
        let pk = [0u8; PUBKEY_LEN];
        let sig = [0u8; SIG_LEN];
        let w = serialize_mldsa_witness(&pk, &sig);
        assert_eq!(w.len(), MLDSA_WITNESS_LEN);
        // total_size field equals actual length
        let total = u32::from_le_bytes(w[0..4].try_into().unwrap()) as usize;
        assert_eq!(total, w.len());
    }

    #[test]
    fn lock_args_header() {
        let pk = [0u8; PUBKEY_LEN];
        let args = lock_args_from_pubkey(&pk);
        assert_eq!(args.len(), LOCK_ARGS_LEN);
        assert_eq!(args[0], LOCK_VERSION);
        assert_eq!(args[1], LOCK_ALGO_ID);
        assert_eq!(args[2], LOCK_PARAM_ID);
        assert_eq!(args[3], 0x00);
    }
}
