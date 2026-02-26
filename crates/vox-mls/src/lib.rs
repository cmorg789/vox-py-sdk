mod codec;
mod group;
mod identity;
mod provider;

use openmls::prelude::{
    CredentialWithKey, GroupId, KeyPackageIn, MlsGroup,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::provider::VoxProvider;

/// Result of processing an incoming MLS message.
#[pyclass]
struct ProcessedMessage {
    #[pyo3(get)]
    kind: String, // "application", "commit", "proposal"
    #[pyo3(get)]
    data: Option<Vec<u8>>, // plaintext for application messages
}

/// MLS encryption engine wrapping OpenMLS.
///
/// Each engine manages one identity and multiple groups.
/// State is persisted to SQLite via the storage provider.
///
/// # Threading
///
/// This class is marked `unsendable` (cannot cross Python thread boundaries)
/// because it uses `Rc<Connection>` internally. This is correct for typical
/// async Python usage where the event loop runs on a single thread. Do not
/// attempt to share an `MlsEngine` instance across threads.
#[pyclass(unsendable)]
struct MlsEngine {
    provider: VoxProvider,
    credential_with_key: Option<CredentialWithKey>,
    signature_keys: Option<SignatureKeyPair>,
}

#[pymethods]
impl MlsEngine {
    #[new]
    #[pyo3(signature = (db_path=None))]
    fn new(db_path: Option<&str>) -> PyResult<Self> {
        let path = db_path.unwrap_or(":memory:");
        let provider = VoxProvider::new(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        // Attempt to restore identity from SQLite
        let (credential_with_key, signature_keys) = match provider.load_identity() {
            Ok(Some((_user_id, _device_id, cwk_json, sig_json))) => {
                let cwk: CredentialWithKey = serde_json::from_str(&cwk_json).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to deserialize stored credential: {e:?}"
                    ))
                })?;
                let sig: SignatureKeyPair = serde_json::from_str(&sig_json).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to deserialize stored signature keys: {e:?}"
                    ))
                })?;

                // Re-store the signature key pair in the storage provider so OpenMLS can find it
                sig.store(provider.storage()).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to re-store signature keys: {e:?}"
                    ))
                })?;

                (Some(cwk), Some(sig))
            }
            Ok(None) => (None, None),
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to load identity from database: {e}"
                )));
            }
        };

        Ok(MlsEngine {
            provider,
            credential_with_key,
            signature_keys,
        })
    }

    /// Generate a new MLS identity for the given user/device.
    /// Returns the public identity key bytes.
    fn generate_identity<'py>(
        &mut self,
        py: Python<'py>,
        user_id: u64,
        device_id: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if self.signature_keys.is_some() {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Identity already initialized — cannot re-initialize without reset",
            ));
        }

        let (cwk, sig_keys) = identity::generate_identity(&self.provider, user_id, device_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        // Persist identity to SQLite
        let cwk_json = serde_json::to_string(&cwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;
        let sig_json = serde_json::to_string(&sig_keys)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;
        self.provider
            .save_identity(user_id, device_id, &cwk_json, &sig_json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let public_key = sig_keys.to_public_vec();
        self.credential_with_key = Some(cwk);
        self.signature_keys = Some(sig_keys);

        Ok(PyBytes::new(py, &public_key))
    }

    /// Generate a serialized KeyPackage for uploading to the server.
    fn generate_key_package<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let (cwk, sig) = self.require_identity()?;

        let kp = identity::generate_key_package(&self.provider, cwk, sig)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let bytes = kp
            .tls_serialize_detached()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;

        Ok(PyBytes::new(py, &bytes))
    }

    /// Generate multiple KeyPackages.
    fn generate_key_packages<'py>(
        &self,
        py: Python<'py>,
        count: usize,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let (cwk, sig) = self.require_identity()?;
        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            let kp = identity::generate_key_package(&self.provider, cwk, sig)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
            let bytes = kp
                .tls_serialize_detached()
                .map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}"))
                })?;
            result.push(PyBytes::new(py, &bytes));
        }

        Ok(result)
    }

    /// Create a new MLS group.
    /// member_key_packages: list of serialized KeyPackages for initial members.
    /// Returns (welcome_bytes | None, commit_bytes | None).
    fn create_group<'py>(
        &mut self,
        py: Python<'py>,
        group_id: &str,
        member_key_packages: Vec<Vec<u8>>,
    ) -> PyResult<(Option<Bound<'py, PyBytes>>, Option<Bound<'py, PyBytes>>)> {
        let cwk = self
            .credential_with_key
            .as_ref()
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
            })?
            .clone();
        let sig = self
            .signature_keys
            .as_ref()
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
            })?;

        let kp_ins: Vec<KeyPackageIn> = member_key_packages
            .iter()
            .map(|bytes| {
                KeyPackageIn::tls_deserialize_exact(bytes).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Invalid key package: {e:?}"
                    ))
                })
            })
            .collect::<PyResult<Vec<_>>>()?;

        let (_mls_group, welcome, commit) =
            group::create_group(&self.provider, &sig, &cwk, group_id, &kp_ins)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        // Group is automatically persisted by the SQLite storage provider

        let welcome_bytes = welcome
            .map(|w| {
                w.tls_serialize_detached()
                    .map(|b| PyBytes::new(py, &b))
                    .map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}"))
                    })
            })
            .transpose()?;

        let commit_bytes = commit
            .map(|c| {
                c.tls_serialize_detached()
                    .map(|b| PyBytes::new(py, &b))
                    .map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}"))
                    })
            })
            .transpose()?;

        Ok((welcome_bytes, commit_bytes))
    }

    /// Join a group from a Welcome message.
    /// Returns the group ID string.
    fn join_group(&mut self, welcome: Vec<u8>) -> PyResult<String> {
        let mls_group = group::join_group(&self.provider, &welcome)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let gid_bytes = mls_group.group_id().as_slice();
        let group_id = String::from_utf8(gid_bytes.to_vec()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid group ID: {e}"))
        })?;

        // Group is automatically persisted by the SQLite storage provider
        Ok(group_id)
    }

    /// Add a member to an existing group.
    /// Returns (welcome_bytes, commit_bytes).
    fn add_member<'py>(
        &mut self,
        py: Python<'py>,
        group_id: &str,
        key_package: Vec<u8>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let sig = self
            .signature_keys
            .as_ref()
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
            })?;

        let mut mls_group = self.load_group(group_id)?;

        let (welcome, commit) =
            group::add_member(&self.provider, &mut mls_group, &sig, &key_package)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;

        Ok((
            PyBytes::new(py, &welcome_bytes),
            PyBytes::new(py, &commit_bytes),
        ))
    }

    /// Remove a member from a group by leaf index.
    /// Returns commit bytes.
    fn remove_member<'py>(
        &mut self,
        py: Python<'py>,
        group_id: &str,
        member_index: u32,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self
            .signature_keys
            .as_ref()
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
            })?;

        let mut mls_group = self.load_group(group_id)?;

        let commit = group::remove_member(&self.provider, &mut mls_group, &sig, member_index)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let bytes = commit
            .tls_serialize_detached()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;

        Ok(PyBytes::new(py, &bytes))
    }

    /// Process an incoming MLS message (commit, proposal, or application message).
    fn process_message(&mut self, group_id: &str, message: Vec<u8>) -> PyResult<ProcessedMessage> {
        let mut mls_group = self.load_group(group_id)?;

        let result = group::process_message(&self.provider, &mut mls_group, &message)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        match result {
            group::ProcessedResult::Application(plaintext) => Ok(ProcessedMessage {
                kind: "application".to_string(),
                data: Some(plaintext),
            }),
            group::ProcessedResult::Commit => Ok(ProcessedMessage {
                kind: "commit".to_string(),
                data: None,
            }),
            group::ProcessedResult::Proposal => Ok(ProcessedMessage {
                kind: "proposal".to_string(),
                data: None,
            }),
            group::ProcessedResult::ExternalJoinProposal => Ok(ProcessedMessage {
                kind: "external_join_proposal".to_string(),
                data: None,
            }),
        }
    }

    /// Encrypt plaintext into an MLS application message.
    fn encrypt<'py>(
        &mut self,
        py: Python<'py>,
        group_id: &str,
        plaintext: Vec<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self
            .signature_keys
            .as_ref()
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
            })?;

        let mut mls_group = self.load_group(group_id)?;

        let ciphertext = group::encrypt(&self.provider, &mut mls_group, &sig, &plaintext)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        Ok(PyBytes::new(py, &ciphertext))
    }

    /// Decrypt an MLS application message.
    /// Convenience wrapper around process_message that returns just the plaintext.
    fn decrypt<'py>(
        &mut self,
        py: Python<'py>,
        group_id: &str,
        ciphertext: Vec<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let result = self.process_message(group_id, ciphertext)?;
        match result.data {
            Some(plaintext) => Ok(PyBytes::new(py, &plaintext)),
            None => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Message is not an application message",
            )),
        }
    }

    /// Check if a group exists in storage.
    fn group_exists(&self, group_id: &str) -> bool {
        let gid = GroupId::from_slice(group_id.as_bytes());
        MlsGroup::load(self.provider.storage(), &gid)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    /// List all group IDs managed by this engine.
    fn list_groups(&self) -> PyResult<Vec<String>> {
        self.provider
            .list_group_ids()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))
    }

    /// Get the public identity key bytes, or None if not initialized.
    fn identity_key<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.signature_keys
            .as_ref()
            .map(|sk| PyBytes::new(py, &sk.to_public_vec()))
    }

    /// Export the full MLS state (identity + all groups) as raw SQLite database bytes.
    ///
    /// This is the recommended backup method — it preserves group memberships,
    /// epoch keys, and all other state. Use `import_state()` to restore.
    fn export_state<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self
            .provider
            .export_db()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Restore full MLS state from raw SQLite database bytes.
    ///
    /// Replaces all data in the current database and reloads identity.
    fn import_state(&mut self, data: Vec<u8>) -> PyResult<()> {
        self.provider
            .import_db(&data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        // Re-load identity from the restored database
        match self.provider.load_identity() {
            Ok(Some((_user_id, _device_id, cwk_json, sig_json))) => {
                let cwk: CredentialWithKey =
                    serde_json::from_str(&cwk_json).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                            "Failed to deserialize restored credential: {e:?}"
                        ))
                    })?;
                let sig: SignatureKeyPair =
                    serde_json::from_str(&sig_json).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                            "Failed to deserialize restored signature keys: {e:?}"
                        ))
                    })?;
                self.credential_with_key = Some(cwk);
                self.signature_keys = Some(sig);
            }
            Ok(None) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Backup does not contain identity data",
                ));
            }
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to load identity from backup: {e}"
                )));
            }
        }

        Ok(())
    }

    /// Export the identity only (private + public key material) as serialized bytes.
    /// Use `export_state()` for a full backup including group memberships.
    fn export_identity<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self.signature_keys.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
        })?;
        let cwk = self.credential_with_key.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Identity not initialized")
        })?;
        let payload = serde_json::json!({
            "signature_keys": sig,
            "credential_with_key": cwk,
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Import a previously exported identity (private + public key material).
    /// Also persists to the vox_identity SQLite table so it survives engine restarts.
    fn import_identity(&mut self, data: Vec<u8>, user_id: u64, device_id: &str) -> PyResult<()> {
        let payload: serde_json::Value = serde_json::from_slice(&data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{e:?}")))?;

        let sig: SignatureKeyPair = serde_json::from_value(
            payload.get("signature_keys")
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing signature_keys"))?
                .clone()
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{e:?}")))?;

        let cwk: CredentialWithKey = serde_json::from_value(
            payload.get("credential_with_key")
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing credential_with_key"))?
                .clone()
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{e:?}")))?;

        sig.store(self.provider.storage())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;

        // Persist identity to SQLite so it survives engine restarts
        let cwk_json = serde_json::to_string(&cwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;
        let sig_json = serde_json::to_string(&sig)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e:?}")))?;
        self.provider
            .save_identity(user_id, device_id, &cwk_json, &sig_json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        self.signature_keys = Some(sig);
        self.credential_with_key = Some(cwk);
        Ok(())
    }
}

impl MlsEngine {
    fn require_identity(&self) -> PyResult<(&CredentialWithKey, &SignatureKeyPair)> {
        match (&self.credential_with_key, &self.signature_keys) {
            (Some(cwk), Some(sig)) => Ok((cwk, sig)),
            _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Identity not initialized — call generate_identity() first",
            )),
        }
    }

    /// Load a group from SQLite storage by group ID.
    fn load_group(&self, group_id: &str) -> PyResult<MlsGroup> {
        let gid = GroupId::from_slice(group_id.as_bytes());
        MlsGroup::load(self.provider.storage(), &gid)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to load group '{group_id}': {e:?}"
                ))
            })?
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyKeyError, _>(format!(
                    "No group with id '{group_id}'"
                ))
            })
    }
}

#[pymodule]
fn vox_mls(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MlsEngine>()?;
    m.add_class::<ProcessedMessage>()?;
    Ok(())
}
