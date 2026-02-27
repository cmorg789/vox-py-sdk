use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use crate::provider::VoxProvider;

pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Generate a new MLS identity (credential + signing keys) for the given user/device.
pub fn generate_identity(
    provider: &VoxProvider,
    user_id: u64,
    device_id: &str,
) -> Result<(CredentialWithKey, SignatureKeyPair), String> {
    let identity = format!("{user_id}:{device_id}");
    let credential = BasicCredential::new(identity.into_bytes());

    let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| format!("Failed to generate signature keys: {e:?}"))?;

    signature_keys
        .store(provider.storage())
        .map_err(|e| format!("Failed to store signature keys: {e:?}"))?;

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    Ok((credential_with_key, signature_keys))
}

/// Generate a KeyPackage for distribution to other members.
pub fn generate_key_package(
    provider: &VoxProvider,
    credential_with_key: &CredentialWithKey,
    signature_keys: &SignatureKeyPair,
) -> Result<KeyPackage, String> {
    let bundle = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            provider,
            signature_keys,
            credential_with_key.clone(),
        )
        .map_err(|e| format!("Failed to build key package: {e:?}"))?;
    Ok(bundle.key_package().clone())
}
