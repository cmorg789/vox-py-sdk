use std::rc::Rc;

use openmls_libcrux_crypto::CryptoProvider;
use openmls_sqlite_storage::{Connection, SqliteStorageProvider};
use openmls_traits::{types::CryptoError, OpenMlsProvider};
use rusqlite::params;

use crate::codec::JsonCodec;

/// Composite OpenMLS provider: libcrux crypto + SQLite storage.
pub struct VoxProvider {
    crypto: CryptoProvider,
    connection: Rc<Connection>,
    storage: SqliteStorageProvider<JsonCodec, Rc<Connection>>,
}

impl VoxProvider {
    /// Create a new provider backed by the given SQLite database path.
    /// Pass `":memory:"` for an in-memory database (backward compat).
    pub fn new(db_path: &str) -> Result<Self, String> {
        let mut conn = Connection::open(db_path)
            .map_err(|e| format!("Failed to open SQLite database: {e}"))?;

        // Run OpenMLS storage migrations before wrapping in Rc
        // (run_migrations needs BorrowMut<Connection>)
        {
            let mut temp_storage = SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut conn);
            temp_storage
                .run_migrations()
                .map_err(|e| format!("Failed to run storage migrations: {e}"))?;
        }

        // Create our custom identity table
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vox_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                credential_with_key TEXT NOT NULL,
                signature_key_pair TEXT NOT NULL
            )"
        ).map_err(|e| format!("Failed to create vox_identity table: {e}"))?;

        let rc_conn = Rc::new(conn);
        let storage = SqliteStorageProvider::<JsonCodec, Rc<Connection>>::new(Rc::clone(&rc_conn));

        let crypto = CryptoProvider::new()
            .map_err(|e: CryptoError| format!("Failed to create crypto provider: {e:?}"))?;

        Ok(VoxProvider {
            crypto,
            connection: rc_conn,
            storage,
        })
    }

    /// Save identity metadata to the `vox_identity` table.
    pub fn save_identity(
        &self,
        user_id: u64,
        device_id: &str,
        credential_with_key_json: &str,
        signature_key_pair_json: &str,
    ) -> Result<(), String> {
        let user_id_i64: i64 = user_id
            .try_into()
            .map_err(|_| format!("user_id {user_id} exceeds i64::MAX"))?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO vox_identity (id, user_id, device_id, credential_with_key, signature_key_pair)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                params![user_id_i64, device_id, credential_with_key_json, signature_key_pair_json],
            )
            .map_err(|e| format!("Failed to save identity: {e}"))?;
        Ok(())
    }

    /// Load identity metadata from the `vox_identity` table.
    /// Returns `(user_id, device_id, credential_with_key_json, signature_key_pair_json)` or None.
    pub fn load_identity(&self) -> Result<Option<(u64, String, String, String)>, String> {
        let mut stmt = self
            .connection
            .prepare("SELECT user_id, device_id, credential_with_key, signature_key_pair FROM vox_identity WHERE id = 1")
            .map_err(|e| format!("Failed to prepare identity query: {e}"))?;

        let result = stmt
            .query_row([], |row| {
                let user_id: i64 = row.get(0)?;
                let device_id: String = row.get(1)?;
                let cwk_json: String = row.get(2)?;
                let sig_json: String = row.get(3)?;
                Ok((user_id as u64, device_id, cwk_json, sig_json))
            });

        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to load identity: {e}")),
        }
    }

    /// Export the entire SQLite database as raw bytes (for full state backup).
    pub fn export_db(&self) -> Result<Vec<u8>, String> {
        let temp_path =
            std::env::temp_dir().join(format!("vox-mls-export-{}.db", std::process::id()));

        let temp_str = temp_path
            .to_str()
            .ok_or_else(|| "Invalid temp path".to_string())?;

        // VACUUM INTO creates a clean snapshot (requires SQLite 3.27+, bundled is 3.46+)
        self.connection
            .execute(
                &format!("VACUUM INTO '{}'", temp_str.replace('\'', "''")),
                [],
            )
            .map_err(|e| format!("VACUUM INTO failed: {e}"))?;

        let bytes = std::fs::read(&temp_path)
            .map_err(|e| format!("Failed to read backup file: {e}"))?;
        let _ = std::fs::remove_file(&temp_path);

        Ok(bytes)
    }

    /// Restore the full SQLite database from raw bytes (for full state restore).
    ///
    /// This replaces all data in the current database with the backup data.
    pub fn import_db(&self, data: &[u8]) -> Result<(), String> {
        let temp_path =
            std::env::temp_dir().join(format!("vox-mls-import-{}.db", std::process::id()));

        std::fs::write(&temp_path, data)
            .map_err(|e| format!("Failed to write backup file: {e}"))?;

        let temp_str = temp_path
            .to_str()
            .ok_or_else(|| "Invalid temp path".to_string())?;

        let result = (|| -> Result<(), String> {
            // Attach the backup database
            self.connection
                .execute_batch(&format!(
                    "ATTACH DATABASE '{}' AS backup_src",
                    temp_str.replace('\'', "''")
                ))
                .map_err(|e| format!("Failed to attach backup: {e}"))?;

            // Get list of tables in backup
            let mut stmt = self
                .connection
                .prepare("SELECT name FROM backup_src.sqlite_master WHERE type='table'")
                .map_err(|e| format!("Failed to list backup tables: {e}"))?;

            let table_names: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .map_err(|e| format!("Failed to query tables: {e}"))?
                .filter_map(|r| r.ok())
                .collect();

            // For each table, clear current data and copy from backup
            for table in &table_names {
                if table.starts_with("sqlite_") {
                    continue;
                }
                self.connection
                    .execute(&format!("DELETE FROM main.\"{table}\""), [])
                    .map_err(|e| format!("Failed to clear table {table}: {e}"))?;
                self.connection
                    .execute(
                        &format!(
                            "INSERT INTO main.\"{table}\" SELECT * FROM backup_src.\"{table}\""
                        ),
                        [],
                    )
                    .map_err(|e| format!("Failed to restore table {table}: {e}"))?;
            }

            self.connection
                .execute_batch("DETACH DATABASE backup_src")
                .map_err(|e| format!("Failed to detach backup: {e}"))?;

            Ok(())
        })();

        // Always clean up the temp file
        let _ = std::fs::remove_file(&temp_path);

        result
    }

    /// List all group IDs stored by OpenMLS.
    pub fn list_group_ids(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .connection
            .prepare("SELECT DISTINCT group_id FROM openmls_group_data")
            .map_err(|e| format!("Failed to prepare group query: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let blob: Vec<u8> = row.get(0)?;
                Ok(blob)
            })
            .map_err(|e| format!("Failed to query groups: {e}"))?;

        let mut group_ids = Vec::new();
        for row in rows {
            let blob = row.map_err(|e| format!("Failed to read group row: {e}"))?;
            // The group_id is stored as serialized bytes via the codec.
            // Try to deserialize as JSON string first, fall back to raw UTF-8.
            if let Ok(id) = serde_json::from_slice::<String>(&blob) {
                group_ids.push(id);
            } else if let Ok(id) = String::from_utf8(blob.clone()) {
                group_ids.push(id);
            }
        }
        Ok(group_ids)
    }
}

impl OpenMlsProvider for VoxProvider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Rc<Connection>>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
