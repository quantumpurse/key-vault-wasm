mod errors;

use super::types::{CipherPayload, MlDsaAccount, SphincsPlusAccount};
use crate::constants::{CHILD_KEYS_STORE, DB_NAME, MASTER_SEED_KEY, MASTER_SEED_STORE, ML_DSA_KEYS_STORE};
use errors::KeyVaultDBError;
use indexed_db_futures::{
    database::Database, prelude::*, transaction::TransactionMode, iter::ArrayMapIter
};
use wasm_bindgen::{JsValue};

const VERSION: u8 = 2;

/// Opens the IndexedDB database, creating object stores if necessary.
///
/// **Returns**:
/// - `Result<Database, KeyVaultDBError>` - The opened database on success, or an error if the operation fails.
///
/// **Async**: Yes
pub async fn open_db() -> Result<Database, KeyVaultDBError> {
    Database::open(DB_NAME)
        .with_version(VERSION)
        .with_on_blocked(|_event| Ok(()))
        .with_on_upgrade_needed(|event, db| {
            let old_version = event.old_version() as u8;

            if old_version < 1 {
                db.create_object_store(MASTER_SEED_STORE).build()?;
                db.create_object_store(CHILD_KEYS_STORE).build()?;
            }

            if old_version < 2 {
                // ML-DSA-65 accounts store (added in v0.4.0)
                db.create_object_store(ML_DSA_KEYS_STORE).build()?;
            }

            Ok(())
        })
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(format!("Failed to open IndexedDB: {}", e)))
}

/// Stores the encrypted master seed in the indexed DB.
///
/// **Parameters**:
/// - `payload: CipherPayload` - The encrypted master seed data to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
///
/// **Async**: Yes
///
/// **Warning**: This method overwrites the existing master seed in the indexed DB.
pub async fn set_encrypted_seed(payload: CipherPayload) -> Result<(), KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(MASTER_SEED_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(MASTER_SEED_STORE)?;

    let js_value = serde_wasm_bindgen::to_value(&payload)?;
    store.put(&js_value).with_key(MASTER_SEED_KEY).await?;
    tx.commit().await?;
    Ok(())
}

/// Retrieves the encrypted masterseed from the indexed DB.
///
/// **Returns**:
/// - `Result<Option<CipherPayload>, KeyVaultDBError>` - The encrypted master seed if it exists, `None` if not found, or an error if retrieval fails.
///
/// **Async**: Yes
pub async fn get_encrypted_seed() -> Result<Option<CipherPayload>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(MASTER_SEED_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(MASTER_SEED_STORE)?;

    if let Some(js_value) = store
        .get(MASTER_SEED_KEY)
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(e.to_string()))?
    {
        let payload: CipherPayload = serde_wasm_bindgen::from_value(js_value)?;
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}

/// Stores a SPHINCS+ account to the indexed DB.
///
/// **Parameters**:
/// - `account: SphincsPlusAccount` - The SPHINCS+ account to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
///
/// **Async**: Yes
pub async fn add_account(mut account: SphincsPlusAccount) -> Result<(), KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;
    let count = store.count().await?;
    account.index = count as u32;
    let js_value = serde_wasm_bindgen::to_value(&account)?;

    store.add(js_value).with_key(account.lock_args).await?;
    tx.commit().await?;
    Ok(())
}

/// Retrieves a child account by its public Lock Script arguments from the indexed DB.
///
/// **Parameters**:
/// - `lock_args: &str` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the retrieved child account.
///
/// **Returns**:
/// - `Result<Option<SphincsPlusAccount>, KeyVaultDBError>` - The child key if found, `None` if not found, or an error if retrieval fails.
///
/// **Async**: Yes
pub async fn get_account(lock_args: &str) -> Result<Option<SphincsPlusAccount>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;

    if let Some(js_value) = store
        .get(lock_args)
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(e.to_string()))?
    {
        let account: SphincsPlusAccount = serde_wasm_bindgen::from_value(js_value)?;
        Ok(Some(account))
    } else {
        Ok(None)
    }
}

// ── ML-DSA-65 account CRUD ────────────────────────────────────────────────────

/// Stores an ML-DSA-65 account in the indexed DB.
pub async fn add_ml_dsa_account(mut account: MlDsaAccount) -> Result<(), KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(ML_DSA_KEYS_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(ML_DSA_KEYS_STORE)?;
    let count = store.count().await?;
    account.index = count as u32;
    let js_value = serde_wasm_bindgen::to_value(&account)?;
    store.add(js_value).with_key(account.lock_args).await?;
    tx.commit().await?;
    Ok(())
}

/// Retrieves an ML-DSA-65 account by its lock script args.
pub async fn get_ml_dsa_account(lock_args: &str) -> Result<Option<MlDsaAccount>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(ML_DSA_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(ML_DSA_KEYS_STORE)?;
    if let Some(js_value) = store
        .get(lock_args)
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(e.to_string()))?
    {
        let account: MlDsaAccount = serde_wasm_bindgen::from_value(js_value)?;
        Ok(Some(account))
    } else {
        Ok(None)
    }
}

/// Retrieves all ML-DSA-65 lock args from the indexed DB, sorted by insertion order.
pub async fn get_all_ml_dsa_lock_args() -> Result<Vec<String>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(ML_DSA_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(ML_DSA_KEYS_STORE)?;
    let iter: ArrayMapIter<JsValue> = store.get_all().await?;
    let mut accounts: Vec<MlDsaAccount> = Vec::new();
    for result in iter {
        let js_value = result?;
        let account: MlDsaAccount = serde_wasm_bindgen::from_value(js_value)?;
        accounts.push(account);
    }
    accounts.sort_by_key(|a| a.index);
    Ok(accounts.into_iter().map(|a| a.lock_args).collect())
}

// ─────────────────────────────────────────────────────────────────────────────

/// Clears all data in the `master_seed_store` and `child_keys_store` in IndexedDB.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if the operation fails.
///
/// **Async**: Yes
pub async fn clear_all_stores() -> Result<(), KeyVaultDBError> {
    let db = open_db().await?;
    clear_object_store(&db, MASTER_SEED_STORE).await?;
    clear_object_store(&db, CHILD_KEYS_STORE).await?;
    clear_object_store(&db, ML_DSA_KEYS_STORE).await?;
    Ok(())
}

/// Retrieves all accounts' lock script arguments from the indexed DB in the order they were inserted.
///
/// **Returns**:
/// - `Result<Vec<String>, KeyVaultDBError>` - A vector of hex-encoded SPHINCS+ lock script arguments on success,
///   or an error if retrieval fails.
///
/// **Async**: Yes
pub async fn get_all_lock_args() -> Result<Vec<String>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;

    // Retrieve all accounts
    let iter: ArrayMapIter<JsValue> = store.get_all().await?;
    let mut accounts: Vec<SphincsPlusAccount> = Vec::new();
    for result in iter {
        let js_value = result?;
        let account: SphincsPlusAccount = serde_wasm_bindgen::from_value(js_value)?;
        accounts.push(account);
    }

    // Sort by index
    accounts.sort_by_key(|account| account.index);

    // Extract lock args in sorted order
    let lock_args_array: Vec<String> = accounts
        .into_iter()
        .map(|account| account.lock_args)
        .collect();

    Ok(lock_args_array)
}

/// Clears a specific object store in the indexed DB.
///
/// **Parameters**:
/// - `db: &Database` - The indexed DB instance to operate on.
/// - `store_name: &str` - The name of the object store to clear.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if the operation fails.
///
/// **Async**: Yes
pub async fn clear_object_store(db: &Database, store_name: &str) -> Result<(), KeyVaultDBError> {
    let tx = db
        .transaction(store_name)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|e| {
            KeyVaultDBError::DatabaseError(format!(
                "Error starting transaction for {}: {}",
                store_name, e
            ))
        })?;
    let store = tx.object_store(store_name).map_err(|e| {
        KeyVaultDBError::DatabaseError(format!("Error getting object store {}: {}", store_name, e))
    })?;
    store.clear().map_err(|e| {
        KeyVaultDBError::DatabaseError(format!("Error clearing object store {}: {}", store_name, e))
    })?;
    tx.commit().await.map_err(|e| {
        KeyVaultDBError::DatabaseError(format!(
            "Error committing transaction for {}: {}",
            store_name, e
        ))
    })?;
    Ok(())
}
