use std::ptr::NonNull;
use std::rc::Rc;

use openmls_libcrux_crypto::CryptoProvider;
use openmls_sqlite_storage::{Connection, SqliteStorageProvider};
use openmls_traits::{types::CryptoError, OpenMlsProvider};
use rusqlite::backup::Backup;
use rusqlite::params;
use rusqlite::serialize::OwnedData;
use rusqlite::DatabaseName;

use crate::codec::JsonCodec;

/// Composite OpenMLS provider: libcrux crypto + SQLite storage.
pub struct VoxProvider {
    db_path: String,
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

        // Create our custom tables
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vox_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                credential_with_key TEXT NOT NULL,
                signature_key_pair TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vox_groups (
                group_id TEXT PRIMARY KEY
            )"
        ).map_err(|e| format!("Failed to create custom tables: {e}"))?;

        let rc_conn = Rc::new(conn);
        let storage = SqliteStorageProvider::<JsonCodec, Rc<Connection>>::new(Rc::clone(&rc_conn));

        let crypto = CryptoProvider::new()
            .map_err(|e: CryptoError| format!("Failed to create crypto provider: {e:?}"))?;

        Ok(VoxProvider {
            db_path: db_path.to_string(),
            crypto,
            connection: rc_conn,
            storage,
        })
    }

    /// Save identity metadata to the `vox_identity` table.
    ///
    /// # Security
    ///
    /// This stores private key material (signature key pair) in SQLite.
    /// The database file should be protected with appropriate filesystem
    /// permissions. For transport, use `export_state()` + `encrypt_backup()`.
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
    ///
    /// # Security
    ///
    /// Returns private key material. Callers must not log or serialize the
    /// returned signature key pair without encryption.
    pub fn load_identity(&self) -> Result<Option<(u64, String, String, String)>, String> {
        let mut stmt = self
            .connection
            .prepare("SELECT user_id, device_id, credential_with_key, signature_key_pair FROM vox_identity WHERE id = 1")
            .map_err(|e| format!("Failed to prepare identity query: {e}"))?;

        let result = stmt
            .query_row([], |row| {
                let user_id: i64 = row.get(0)?;
                let user_id_u64: u64 = user_id.try_into().map_err(|_| {
                    rusqlite::Error::IntegralValueOutOfRange(0, user_id.into())
                })?;
                let device_id: String = row.get(1)?;
                let cwk_json: String = row.get(2)?;
                let sig_json: String = row.get(3)?;
                Ok((user_id_u64, device_id, cwk_json, sig_json))
            });

        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to load identity: {e}")),
        }
    }

    /// Record a group ID in the `vox_groups` tracking table.
    pub fn save_group_id(&self, group_id: &str) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO vox_groups (group_id) VALUES (?1)",
                params![group_id],
            )
            .map_err(|e| format!("Failed to save group ID: {e}"))?;
        Ok(())
    }

    /// List all group IDs tracked in the `vox_groups` table.
    pub fn list_group_ids(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .connection
            .prepare("SELECT group_id FROM vox_groups")
            .map_err(|e| format!("Failed to prepare group query: {e}"))?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| format!("Failed to query groups: {e}"))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|e| format!("Failed to read group row: {e}"))?);
        }
        Ok(ids)
    }

    /// Export the entire SQLite database as raw bytes (for full state backup).
    ///
    /// Uses SQLite's serialize API — no temporary files are created.
    pub fn export_db(&self) -> Result<Vec<u8>, String> {
        let data = self
            .connection
            .serialize(DatabaseName::Main)
            .map_err(|e| format!("Failed to serialize database: {e}"))?;
        Ok(data.to_vec())
    }

    /// Restore the full SQLite database from raw bytes (for full state restore).
    ///
    /// Deserializes the backup into a temporary in-memory connection, then uses
    /// the Backup API to atomically copy into a fresh connection at the original
    /// database path. No temporary files or dynamic SQL are used.
    pub fn import_db(&mut self, data: &[u8]) -> Result<(), String> {
        // 1. Allocate sqlite3_malloc memory and copy backup data into it.
        //    OwnedData requires sqlite3_malloc-allocated memory because it
        //    calls sqlite3_free on drop.
        let owned_data = {
            let ptr = unsafe { rusqlite::ffi::sqlite3_malloc64(data.len() as u64) } as *mut u8;
            if ptr.is_null() {
                return Err("Failed to allocate memory for deserialization".to_string());
            }
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                OwnedData::from_raw_nonnull(NonNull::new_unchecked(ptr), data.len())
            }
        };

        // 2. Deserialize backup into a temporary in-memory connection
        let mut mem_conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory database: {e}"))?;
        mem_conn
            .deserialize(DatabaseName::Main, owned_data, false)
            .map_err(|e| format!("Failed to deserialize backup: {e}"))?;

        // 3. Open a fresh connection at the original path
        let mut new_conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open new connection: {e}"))?;

        // 4. Atomically copy from in-memory → new connection via Backup API
        {
            let backup = Backup::new(&mem_conn, &mut new_conn)
                .map_err(|e| format!("Failed to initialize backup: {e}"))?;
            backup
                .run_to_completion(100, std::time::Duration::ZERO, None)
                .map_err(|e| format!("Failed to restore backup: {e}"))?;
        }

        // 5. Run migrations on the restored connection
        {
            let mut temp_storage =
                SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut new_conn);
            temp_storage
                .run_migrations()
                .map_err(|e| format!("Failed to run migrations after restore: {e}"))?;
        }

        // Ensure custom tables exist
        new_conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS vox_identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    user_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    credential_with_key TEXT NOT NULL,
                    signature_key_pair TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vox_groups (
                    group_id TEXT PRIMARY KEY
                )",
            )
            .map_err(|e| format!("Failed to create custom tables after restore: {e}"))?;

        // 6. Replace self's connection and storage
        let rc_conn = Rc::new(new_conn);
        let storage =
            SqliteStorageProvider::<JsonCodec, Rc<Connection>>::new(Rc::clone(&rc_conn));
        self.connection = rc_conn;
        self.storage = storage;

        Ok(())
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
