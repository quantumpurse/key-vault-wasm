//! # QuantumPurse KeyVault
//!
//! This module provides a secure password-based authentication interface for managing cryptographic keys in
//! QuantumPurse project using WebAssembly. It leverages AES-GCM for encryption, Scrypt for key derivation & hashing,
//! and the SPHINCS+ signature scheme for post-quantum transaction signing. The master seed is encrypted and stored in
//! the browser IndexedDB, with access authenticated by user-provided passwords.

use bip39::{Language, Mnemonic};
use ckb_fips205_utils::{
    ckb_tx_message_all_from_mock_tx::{generate_ckb_tx_message_all_from_mock_tx, ScriptOrIndex},
    Hasher,
};
use ckb_fips204_utils::signing as mldsa_signing;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction};
use fips205::{
    traits::{KeyGen, SerDes, Signer},
    *,
};
use hex::encode;
use wasm_bindgen::{prelude::*, JsValue};
use web_sys::js_sys::Uint8Array;

mod constants;
mod db;
mod macros;
mod secure_vec;
mod secure_string;
mod types;
mod utilities;

use crate::constants::{
    KDF_PATH_PREFIX, MULTISIG_RESERVED_FIELD_VALUE,
    PUBKEY_NUM, REQUIRED_FIRST_N, THRESHOLD,
};
use secure_vec::SecureVec;
use secure_string::SecureString;
use types::*;

////////////////////////////////////////////////////////////////////////////////
///  Key-vault functions
////////////////////////////////////////////////////////////////////////////////
#[wasm_bindgen]
pub struct KeyVault {
    /// The one parameter set chosen for QuantumPurse KeyVault setup in all 12 NIST-approved SPHINCS+ FIPS205 variants
    pub variant: SpxVariant,
}

#[wasm_bindgen]
impl KeyVault {
    /// Constructs a new `KeyVault` to serve as a namespace in the output js interface.
    ///
    /// **Returns**:
    /// - `KeyVault` - A new instance of the struct.
    #[wasm_bindgen(constructor)]
    pub fn new(variant: SpxVariant) -> Self {
        KeyVault { variant: variant }
    }

    /// To derive SPHINCS+ key pair. One master seed can derive multiple child index-based SPHINCS+ key pairs on demand.
    ///
    /// **Parameters**:
    /// - `seed: &[u8]` - The master seed from which the child sphincs+ key is derived. MUST carry at least N*3 bytes of entropy or panics.
    /// - `index: u32` - The index of the child sphincs+ key to be derived.
    ///
    /// **Returns**:
    /// - `Result<SecureVec, SecureVec>` - The SPHINCS+ key pair on success, or an error message on failure.
    ///
    /// Warning: Proper zeroization of the input seed is the responsibility of the caller.
    fn derive_spx_keys(
        &self,
        seed: &[u8],
        index: u32,
    ) -> Result<(SecureVec, SecureVec), String> {
        match self.variant {
            SpxVariant::Sha2128S => spx_keygen!(slh_dsa_sha2_128s::KG, slh_dsa_sha2_128s::N, seed, index),
            SpxVariant::Sha2128F => spx_keygen!(slh_dsa_sha2_128f::KG, slh_dsa_sha2_128f::N, seed, index),
            SpxVariant::Sha2192S => spx_keygen!(slh_dsa_sha2_192s::KG, slh_dsa_sha2_192s::N, seed, index),
            SpxVariant::Sha2192F => spx_keygen!(slh_dsa_sha2_192f::KG, slh_dsa_sha2_192f::N, seed, index),
            SpxVariant::Sha2256S => spx_keygen!(slh_dsa_sha2_256s::KG, slh_dsa_sha2_256s::N, seed, index),
            SpxVariant::Sha2256F => spx_keygen!(slh_dsa_sha2_256f::KG, slh_dsa_sha2_256f::N, seed, index),
            SpxVariant::Shake128S => spx_keygen!(slh_dsa_shake_128s::KG, slh_dsa_shake_128s::N, seed, index),
            SpxVariant::Shake128F => spx_keygen!(slh_dsa_shake_128f::KG, slh_dsa_shake_128f::N, seed, index),
            SpxVariant::Shake192S => spx_keygen!(slh_dsa_shake_192s::KG, slh_dsa_shake_192s::N, seed, index),
            SpxVariant::Shake192F => spx_keygen!(slh_dsa_shake_192f::KG, slh_dsa_shake_192f::N, seed, index),
            SpxVariant::Shake256S => spx_keygen!(slh_dsa_shake_256s::KG, slh_dsa_shake_256s::N, seed, index),
            SpxVariant::Shake256F => spx_keygen!(slh_dsa_shake_256f::KG, slh_dsa_shake_256f::N, seed, index),
        }
    }

    /// Clears all data in the `seed_phrase_store` and `child_keys_store` in IndexedDB.
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn clear_database() -> Result<(), JsValue> {
        db::clear_all_stores().await.map_err(|e| e.to_jsvalue())?;
        Ok(())
    }

    /// Retrieves all SPHINCS+ lock script arguments (processed public keys) from the database in the order they get inserted.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - A JavaScript Promise that resolves to an array of hex-encoded SPHINCS+ lock script arguments on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn get_all_sphincs_lock_args() -> Result<Vec<String>, JsValue> {
        db::get_all_lock_args().await.map_err(|e| e.to_jsvalue())
    }

    /// Check if there's a master seed stored in the indexDB.
    ///
    /// **Returns**:
    /// - `Result<bool, JsValue>` - A JavaScript Promise that resolves to `true` if a master seed exists,
    ///   or `false` if it doesn't.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn has_master_seed(&self) -> Result<bool, JsValue> {
        let payload = db::get_encrypted_seed().await.map_err(|e| e.to_jsvalue())?;
        Ok(payload.is_some())
    }

    /// Generates master seed for your wallet, encrypts it with the provided password, and stores it in IndexedDB.
    /// Throw if the master seed already exists.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to encrypt the generated master seed, input from js env. Must not be empty or uninitialized.
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    /// 
    /// Given NIST new security post-quantum standards categorized as:
    /// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
    /// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
    /// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
    /// 
    /// First protection layer: For a symetrical encryption practice, the first protection effort SHOULD be the responsibitlity of 
    /// the higher layer impelementation (Quantum Purse Wallet or any other system using this library) to ensure that the encrypted data
    /// is never exposed. It is also the responsibility of the end-users to always lock their device carefully.
    /// 
    /// Second protection layer: Should the first protection layer fall in any situation, the encryption itself stands as the last
    /// resistance against quantum attacks. The passwords provided should be strong enough, so that breaking it requires comparable
    /// resouce to break the NIST category level 1), 3) and 5).
    /// 
    /// For a reference setup:
    ///  - Minimum required 20-character passwords. This puts us at ~128-bit of security in theory (less in reality because of human factors).
    ///  - Scrypt with param {log_n = 17, r = 8, p = 1, len 32} make each effort to guess a password even harder for the attacker. 
    /// 
    /// The theoretical security for this setup, thus starts at level 1) and is not upper limited following how long users passwords can be.
    #[wasm_bindgen]
    pub async fn generate_master_seed(&self, js_password: Uint8Array) -> Result<(), JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        if self.has_master_seed().await? {
            return Err(JsValue::from_str("Master seed already exists"));
        }

        let size = self.variant.required_entropy_size_total();
        let entropy = utilities::get_random_bytes(size)
            .map_err(|e| JsValue::from_str(&format!("Failed generating master seed: {}", e)))?;
        let encrypted_seed = utilities::encrypt(password.as_ref(), entropy.as_ref())
            .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

        db::set_encrypted_seed(encrypted_seed)
            .await
            .map_err(|e| e.to_jsvalue())?;
        Ok(())
    }

    /// Generates a new SPHINCS+ account - a SPHINCS+ Lock Script arguments that can be encoded to CKB quantum safe addresses at higher layers.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed and encrypt the child private key, input from js env. Must not be empty or uninitialized.
    ///
    /// **Returns**:
    /// - `Result<String, JsValue>` - A String Promise that resolves to the hex-encoded SPHINCS+ lock argument (processed SPHINCS+ public key) of the account on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    #[wasm_bindgen]
    pub async fn gen_new_account(&self, js_password: Uint8Array) -> Result<String, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;

        let index = Self::get_all_sphincs_lock_args().await?.len() as u32;
        let (pub_key, _) = self
            .derive_spx_keys(&seed, index)
            .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

        // Calculate lock script args
        let lock_script_args = self.get_lock_scrip_arg(&pub_key);

        // Store to DB
        let account = SphincsPlusAccount {
            index: 0, // Init to 0; Will be set correctly in add_account
            lock_args: encode(lock_script_args),
        };

        db::add_account(account).await.map_err(|e| e.to_jsvalue())?;

        Ok(encode(lock_script_args))
    }

    /// Imports master seed then encrypting it with the provided password.
    /// Overwrite the existing master seed.
    ///
    /// **Parameters**:
    /// - `js_seed_phrase: Uint8Array` - The mnemonic phrase as a valid UTF-8 encoded Uint8Array to import, input from js env.
    ///    There're only 3 options accepted: 36, 54 or 72 words.
    /// - `js_password: Uint8Array` - The password used to encrypt the translated master seed, input from js env. Must not be empty or uninitialized.
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    ///
    /// **Notes**:
    /// - The provided `js_password` and the js_seed_phrase buffers are cleared immediately after use.
    /// 
    /// Given NIST new security post-quantum standards categorized as:
    /// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
    /// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
    /// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
    /// 
    /// First protection layer: For a symetrical encryption practice, the first protection effort SHOULD be the responsibitlity of 
    /// the higher layer impelementation (Quantum Purse Wallet or any other system using this library) to ensure that the encrypted data
    /// is never exposed. It is also the responsibility of the end-users to always lock their device carefully.
    /// 
    /// Second protection layer: Should the first protection layer fall in any situation, the encryption itself stands as the last
    /// resistance against quantum attacks. The passwords provided should be strong enough, so that breaking it requires comparable
    /// resouce to break the NIST category level 1), 3) and 5).
    /// 
    /// For a reference setup:
    ///  - Minimum required 20-character passwords. This puts us at ~128-bit of security in theory (less in reality because of human factors).
    ///  - Scrypt with param {log_n = 17, r = 8, p = 1, len 32} make each effort to guess a password even harder for the attacker. 
    /// 
    /// The theoretical security for this setup, thus starts at level 1) and is not upper limited following how long users passwords can be.
    #[wasm_bindgen]
    pub async fn import_seed_phrase(
        &self,
        js_seed_phrase: Uint8Array,
        js_password: Uint8Array,
    ) -> Result<(), JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        let seed_phrase_str = SecureString::from_uint8array(js_seed_phrase)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        if seed_phrase_str.is_empty() || seed_phrase_str.is_uninitialized() {
            return Err(JsValue::from_str("Seed phrase cannot be empty or uninitialized"));
        }

        let words: Vec<&str> = seed_phrase_str.split_whitespace().collect();
        let word_count = words.len();

        if word_count != self.variant.required_bip39_size_in_word_total() {
            return Err(JsValue::from_str(&format!(
                "Mismatch: The chosen SPHINCS+ parameter set {} requires {} words whereas the input mnemonic has {} words.",
                self.variant,
                self.variant.required_bip39_size_in_word_total(),
                word_count
            )));
        }

        let mut combined_entropy = SecureVec::new_with_length(0);
        let mut index: u8 = 0;
        let size = self.variant.required_bip39_size_in_word_component();
        for chunk in words.chunks(size) {
            index += 1;
            let chunk_str = SecureString::from_string(chunk.join(" "));
            let mnemonic = Mnemonic::parse_in(Language::English, &*chunk_str).map_err(|e| {
                JsValue::from_str(&format!(
                    "Invalid mnemonic: Chunk{} index {}: {}",
                    size, index, e
                ))
            })?;
            combined_entropy.extend(&mnemonic.to_entropy());
        }

        let payload = utilities::encrypt(password.as_ref(), &combined_entropy)?;
        db::set_encrypted_seed(payload)
            .await
            .map_err(|e| e.to_jsvalue())?;
        Ok(())
    }

    /// Exports the master seed in the form of a custom bip39 mnemonic phrase. There're only 3 options: 36, 54 or 72 words.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed, input from js env. Must not be empty or uninitialized.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - A JavaScript Promise that resolves to the mnemonic as a UTF-8 encoded `Uint8Array` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    ///
    /// **Warning**: Exporting the mnemonic exposes it in JavaScript may pose a security risk.
    /// 
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    #[wasm_bindgen]
    pub async fn export_seed_phrase(&self, js_password: Uint8Array) -> Result<Uint8Array, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;

        let entropy = utilities::decrypt(password.as_ref(), payload)?;
        let size = self.variant.required_entropy_size_component();
        let chunks = entropy.chunks(size);

        let mut combined_mnemonic  = SecureString::new();
        for chunk in chunks {
            let mnemonic = Mnemonic::from_entropy_in(Language::English, chunk)
                .map_err(|e| JsValue::from_str(&format!("Export seed error: {}", e)))?;
            for word in mnemonic.words() {
                combined_mnemonic.extend(word);
            }
        }
        Ok(Uint8Array::from(combined_mnemonic.as_ref()))
    }

    /// Sign and produce a valid signature for the Quantum Resistant lock script.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the private key, input from js env. Must not be empty or uninitialized.
    /// - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
    ///    This is a CKB specific thing, check https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/script-p2.png for more information.
    /// - `message: Uint8Array` - The message to be signed.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - The signature as a `Uint8Array` on success,
    ///   or a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    #[wasm_bindgen]
    pub async fn sign(
        &self,
        js_password: Uint8Array,
        lock_args: String,
        message: Uint8Array,
    ) -> Result<Uint8Array, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let account = db::get_account(&lock_args)
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Account not found"))?;

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;

        let (_, pri_key) = self
            .derive_spx_keys(&seed, account.index)
            .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

        let message_vec = message.to_vec();

        match self.variant {
            SpxVariant::Sha2128S => spx_sign!(slh_dsa_sha2_128s, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2128F => spx_sign!(slh_dsa_sha2_128f, pri_key, &message_vec, self.variant),
            SpxVariant::Shake128S => spx_sign!(slh_dsa_shake_128s, pri_key, &message_vec, self.variant),
            SpxVariant::Shake128F => spx_sign!(slh_dsa_shake_128f, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2192S => spx_sign!(slh_dsa_sha2_192s, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2192F => spx_sign!(slh_dsa_sha2_192f, pri_key, &message_vec, self.variant),
            SpxVariant::Shake192S => spx_sign!(slh_dsa_shake_192s, pri_key, &message_vec, self.variant),
            SpxVariant::Shake192F => spx_sign!(slh_dsa_shake_192f, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2256S => spx_sign!(slh_dsa_sha2_256s, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2256F => spx_sign!(slh_dsa_sha2_256f, pri_key, &message_vec, self.variant),
            SpxVariant::Shake256S => spx_sign!(slh_dsa_shake_256s, pri_key, &message_vec, self.variant),
            SpxVariant::Shake256F => spx_sign!(slh_dsa_shake_256f, pri_key, &message_vec, self.variant),
        }
    }

    /// Supporting wallet recovery - quickly derives a list of lock script arguments (processed public keys).
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed used for account generation, input from js env. Must not be empty or uninitialized.
    /// - `start_index: u32` - The starting index for derivation.
    /// - `count: u32` - The number of sequential lock scripts arguments to derive.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - A list of lock script arguments on success,
    ///   or a JavaScript error on failure.
    /// 
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    #[wasm_bindgen]
    pub async fn try_gen_account_batch(
        &self,
        js_password: Uint8Array,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<String>, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;
        let mut lock_args_array: Vec<String> = Vec::new();
        for index in start_index..(start_index + count) {
            let (pub_key, _) = self
                .derive_spx_keys(&seed, index)
                .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

            // Calculate lock script args
            let lock_script_args = self.get_lock_scrip_arg(&pub_key);
            lock_args_array.push(encode(lock_script_args));
        }
        Ok(lock_args_array)
    }

    /// Supporting wallet recovery - Recovers the wallet by deriving and caching quantum-safe Lock Script arguments for the first N addresses.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed, input from js env. Must not be empty or uninitialized.
    /// - `count: u32` - The number of accounts to recover (from index 0 to count-1).
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A list of newly generated sphincs+ lock script arguments (processed public keys) on success, or a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    #[wasm_bindgen]
    pub async fn recover_accounts(
        &self,
        js_password: Uint8Array,
        count: u32,
    ) -> Result<Vec<String>, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let mut lock_args_array: Vec<String> = Vec::new();
        let seed = utilities::decrypt(password.as_ref(), payload)?;
        for index in 0..count {
            let (pub_key, _) = self
                .derive_spx_keys(&seed, index)
                .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

            // Calculate lock script args
            let lock_script_args = self.get_lock_scrip_arg(&pub_key);
            // Store to DB
            let account = SphincsPlusAccount {
                index: 0, // Init to 0; Will be set correctly in add_account
                lock_args: encode(lock_script_args),
            };
            lock_args_array.push(encode(lock_script_args));

            db::add_account(account).await.map_err(|e| e.to_jsvalue())?;
        }
        Ok(lock_args_array)
    }

    // ── ML-DSA-65 (FIPS 204) account management ───────────────────────────────

    /// Retrieves all ML-DSA-65 lock script arguments from the database in insertion order.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - Array of hex-encoded 36-byte lock args on success.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn get_all_ml_dsa_lock_args() -> Result<Vec<String>, JsValue> {
        db::get_all_ml_dsa_lock_args().await.map_err(|e| e.to_jsvalue())
    }

    /// Generates a new ML-DSA-65 account derived from the wallet master seed.
    ///
    /// Derives the account at index = (number of existing ML-DSA-65 accounts).
    /// The secret key is never stored — it is re-derived on every signing call.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - Password to decrypt the master seed. Zeroed after use.
    ///
    /// **Returns**:
    /// - `Result<String, JsValue>` - Hex-encoded 36-byte ML-DSA-65 lock args on success.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn gen_new_ml_dsa_account(&self, js_password: Uint8Array) -> Result<String, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;

        let index = Self::get_all_ml_dsa_lock_args().await?.len() as u32;
        let (_pubkey, lock_args) = mldsa_signing::derive_lock_args(&seed, index)
            .map_err(|e| JsValue::from_str(&format!("ML-DSA-65 key derivation error: {}", e)))?;

        let lock_args_hex = encode(lock_args);
        let account = MlDsaAccount {
            index: 0, // set correctly by add_ml_dsa_account
            lock_args: lock_args_hex.clone(),
        };
        db::add_ml_dsa_account(account).await.map_err(|e| e.to_jsvalue())?;
        Ok(lock_args_hex)
    }

    /// Signs a CKB transaction with an ML-DSA-65 key and returns the MldsaWitness bytes.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - Password to decrypt the master seed. Zeroed after use.
    /// - `lock_args: String` - Hex-encoded lock args identifying the signing account.
    /// - `tx_hash: Uint8Array` - Raw 32-byte CKB transaction hash.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - 5305-byte Molecule-encoded MldsaWitness (the `WitnessArgs.lock` content).
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn sign_ml_dsa(
        &self,
        js_password: Uint8Array,
        lock_args: String,
        tx_hash: Uint8Array,
    ) -> Result<Uint8Array, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let account = db::get_ml_dsa_account(&lock_args)
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("ML-DSA account not found"))?;

        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;

        let tx_hash_bytes = tx_hash.to_vec();
        let witness_bytes = mldsa_signing::sign(&seed, account.index, &tx_hash_bytes)
            .map_err(|e| JsValue::from_str(&format!("ML-DSA-65 signing error: {}", e)))?;

        Ok(Uint8Array::from(witness_bytes.as_slice()))
    }

    /// Batch-derives ML-DSA-65 lock args without storing them — used for wallet recovery scanning.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - Password to decrypt the master seed. Zeroed after use.
    /// - `start_index: u32` - Starting derivation index.
    /// - `count: u32` - Number of accounts to derive.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - Array of hex-encoded lock args.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn try_gen_ml_dsa_account_batch(
        &self,
        js_password: Uint8Array,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<String>, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;

        let mut results = Vec::with_capacity(count as usize);
        for i in start_index..(start_index + count) {
            let (_pubkey, lock_args) = mldsa_signing::derive_lock_args(&seed, i)
                .map_err(|e| JsValue::from_str(&format!("ML-DSA-65 key derivation error: {}", e)))?;
            results.push(encode(lock_args));
        }
        Ok(results)
    }

    /// Recover ML-DSA-65 accounts — derives and caches `count` accounts from index 0.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - Password to decrypt the master seed. Zeroed after use.
    /// - `count: u32` - Number of accounts to recover.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - Hex-encoded lock args for each recovered account.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn recover_ml_dsa_accounts(
        &self,
        js_password: Uint8Array,
        count: u32,
    ) -> Result<Vec<String>, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(password.as_ref(), payload)?;

        let mut results = Vec::with_capacity(count as usize);
        for i in 0..count {
            let (_pubkey, lock_args) = mldsa_signing::derive_lock_args(&seed, i)
                .map_err(|e| JsValue::from_str(&format!("ML-DSA-65 key derivation error: {}", e)))?;
            let lock_args_hex = encode(lock_args);
            let account = MlDsaAccount { index: 0, lock_args: lock_args_hex.clone() };
            db::add_ml_dsa_account(account).await.map_err(|e| e.to_jsvalue())?;
            results.push(lock_args_hex);
        }
        Ok(results)
    }

    // ── SPHINCS+ lock script args builder ────────────────────────────────────

    /// Building CKB SPHINCS+ all-in-one lockscript arguments
    ///
    /// **Parameters**:
    /// - `public_key: &SecureVec` - The SPHINCS+ public key to be used in the lock script.
    ///
    /// **Returns**:
    /// - `[u8; 32]` - The lock script arguments as a byte array.
    fn get_lock_scrip_arg(&self, public_key: &SecureVec) -> [u8; 32] {
        let all_in_one_config: [u8; 4] = [
            MULTISIG_RESERVED_FIELD_VALUE,
            REQUIRED_FIRST_N,
            THRESHOLD,
            PUBKEY_NUM,
        ];
        let sign_flag: u8 = self.variant << 1;
        let mut script_args_hasher = Hasher::script_args_hasher();
        script_args_hasher.update(&all_in_one_config);
        script_args_hasher.update(&[sign_flag]);
        script_args_hasher.update(&public_key);
        script_args_hasher.hash()
    }
}

////////////////////////////////////////////////////////////////////////////////
///  Key-vault utility functions
////////////////////////////////////////////////////////////////////////////////
#[wasm_bindgen]
pub struct Util;

#[wasm_bindgen]
impl Util {
    /// https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md.
    ///
    /// **Parameters**:
    /// - `serialized_mock_tx: Uint8Array` - serialized CKB mock transaction.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - The CKB transaction message all hash digest as a `Uint8Array` on success,
    ///   or a JavaScript error on failure.
    ///
    /// **Async**: no
    #[wasm_bindgen]
    pub fn get_ckb_tx_message_all(serialized_mock_tx: Uint8Array) -> Result<Uint8Array, JsValue> {
        let serialized_bytes = serialized_mock_tx.to_vec();
        let repr_mock_tx: ReprMockTransaction = serde_json::from_slice(&serialized_bytes)
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
        let mock_tx: MockTransaction = repr_mock_tx.into();
        let mut message_hasher = Hasher::message_hasher();
        generate_ckb_tx_message_all_from_mock_tx(
            &mock_tx,
            ScriptOrIndex::Index(0),
            &mut message_hasher,
        )
        .map_err(|e| JsValue::from_str(&format!("CKB_TX_MESSAGE_ALL error: {:?}", e)))?;
        let message = message_hasher.hash();
        Ok(Uint8Array::from(message.as_slice()))
    }

    /// Check strength of a password.
    /// There is no official weighting system to calculate the strength of a password.
    /// This is just a simple implementation for ASCII passwords. Feel free to use your own password checker.
    /// By default will require at least 20 characters
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - utf8 serialized password, input from js env. Must not be empty or uninitialized.
    ///
    /// **Returns**:
    /// - `Result<u16, JsValue>` - The strength of the password measured in bit on success,
    ///   or a JavaScript error on failure.
    ///
    /// **Async**: no
    /// 
    /// **Notes**:
    /// - The provided `js_password` buffer is cleared immediately after use.
    #[wasm_bindgen]
    pub fn password_checker(js_password: Uint8Array) -> Result<u32, JsValue> {
        let password = SecureString::from_uint8array(js_password)
            .map_err(|e| JsValue::from_str(&e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let mut has_space = false;
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_digit = false;
        let mut has_punctuation = false;
        let mut has_other = false;

        for c in password.chars() {
            if c == ' ' {
                has_space = true;
            } else if c.is_ascii_lowercase() {
                has_lowercase = true;
            } else if c.is_ascii_uppercase() {
                has_uppercase = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else if c.is_ascii_punctuation() {
                has_punctuation = true;
            } else {
                has_other = true;
            }
        }

        if !has_uppercase {
            return Err(JsValue::from_str("Password must contain at least one uppercase letter!"));
        }
        if !has_lowercase {
            return Err(JsValue::from_str("Password must contain at least one lowercase letter!"));
        }
        if !has_digit {
            return Err(JsValue::from_str("Password must contain at least one digit!"));
        }
        if !has_punctuation {
            return Err(JsValue::from_str("Password must contain at least one symbol!"));
        }
        if password.len() < 20 {
            return Err(JsValue::from_str("Password must contain at least 20 characters!"));
        }

        let character_set_size = if has_other {
            256 // Entire characters space in ASCII
        } else {
            let mut size = 0;
            if has_space {
                size += 1;
            } // Space character
            if has_lowercase {
                size += 26;
            } // a-z
            if has_uppercase {
                size += 26;
            } // A-Z
            if has_digit {
                size += 10;
            } // 0-9
            if has_punctuation {
                size += 32;
            } // ASCII punctuation
            size
        };

        let entropy = (password.len() as f64) * (character_set_size as f64).log2();
        let rounded_entropy = entropy.round() as u32;
        Ok(rounded_entropy)
    }
}
