use super::types::ScryptParam;

// Constants
pub const SALT_LENGTH: usize = 16; // 128-bit salt
pub const IV_LENGTH: usize = 12; // 96-bit IV for AES-GCM
pub const DB_NAME: &str = "quantum_purse";
pub const MASTER_SEED_KEY: &str = "master_seed";
pub const MASTER_SEED_STORE: &str = "master_seed_store";
pub const CHILD_KEYS_STORE: &str = "child_keys_store";
pub const ML_DSA_KEYS_STORE: &str = "ml_dsa_keys_store";
pub const KDF_PATH_PREFIX: &str = "ckb/quantum-purse/sphincs-plus/";

/// Given NIST new security post-quantum standards categorized as:
/// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
/// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
/// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
/// 
/// First protection layer: For a symetrical encryption practice, the first protection effort SHOULD be the responsibitlity of 
/// the higher layer impelementation (Quantum Purse Wallet or any other system using this library) to ensure that the encrypted data
/// is never exposed. It is also the responsibility of the end-users to always lock their device carefully.
/// 
/// Second protection layer: Should the first protection layer fall in any situation, the encryption itself stands as the last resistance
/// against quantum attacks. It should be strong enough, so that breaking it requires comparable resouce to break the NIST category level 1), 3) and 5).
/// 
/// This library is aiming for level 1) minimum and let users decide if they want to go beyond that with longer passwords because
/// longer passwords are hard to manage. Letting users choose a pass phrase (similar to bip39 but has clearer patterns) is a good practice
/// but then if the passphrase is too long, it is unclear if we shouldlet users authenticate with the mnemonic seed directly.
/// 
/// For a reference setup:
///  - Minimum required 20-character passwords alone put us at ~128-bit of security in theory (less in reality because of human factors).
///  - Scrypt with param {log_n = 17, r = 8, p = 1, len 32} make each effort to guess a password even harder for the attacker. 
/// 
/// The theoretical security for this setup, thus starts at level 1) and is not upper limited.
/// 
pub const ENC_SCRYPT: ScryptParam = ScryptParam {
    log_n: 17,
    r: 8,
    p: 1,
    len: 32,
};

/// All-in-one quantum resistant lock script configuration
pub const MULTISIG_RESERVED_FIELD_VALUE: u8 = 0x80;
pub const REQUIRED_FIRST_N: u8 = 0x00;
pub const THRESHOLD: u8 = 0x01;
pub const PUBKEY_NUM: u8 = 0x01;
