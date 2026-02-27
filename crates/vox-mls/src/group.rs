use openmls::framing::MlsMessageBodyIn;
use openmls::messages::Welcome;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::identity::CIPHERSUITE;
use crate::provider::VoxProvider;

/// Create a new MLS group with the given group ID, optionally adding initial members.
pub fn create_group(
    provider: &VoxProvider,
    signature_keys: &SignatureKeyPair,
    credential_with_key: &CredentialWithKey,
    group_id: &str,
    member_key_packages: &[KeyPackageIn],
) -> Result<(MlsGroup, Option<MlsMessageOut>, Option<MlsMessageOut>), String> {
    let gid = GroupId::from_slice(group_id.as_bytes());

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut group = MlsGroup::new_with_group_id(
        provider,
        signature_keys,
        &config,
        gid,
        credential_with_key.clone(),
    )
    .map_err(|e| format!("Failed to create group: {e:?}"))?;

    if member_key_packages.is_empty() {
        // No merge_pending_commit needed here: OpenMLS does not generate a
        // proposal/commit when creating a group with no initial members, so
        // there is no pending commit to merge.
        return Ok((group, None, None));
    }

    // Validate incoming key packages
    let validated: Vec<KeyPackage> = member_key_packages
        .iter()
        .map(|kp_in| {
            kp_in
                .clone()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| format!("Invalid key package: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (commit, welcome, _group_info) = group
        .add_members(provider, signature_keys, &validated)
        .map_err(|e| format!("Failed to add members: {e:?}"))?;

    group
        .merge_pending_commit(provider)
        .map_err(|e| format!("Failed to merge pending commit: {e:?}"))?;

    Ok((group, Some(welcome), Some(commit)))
}

/// Join a group from a serialized MLS Welcome message.
///
/// Accepts either a raw Welcome or an MlsMessage-wrapped Welcome.
pub fn join_group(provider: &VoxProvider, welcome_bytes: &[u8]) -> Result<MlsGroup, String> {
    // Try deserializing as MlsMessageIn (the MlsMessageOut envelope format)
    let welcome = if let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(welcome_bytes) {
        match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("MLS message is not a Welcome".to_string()),
        }
    } else {
        // Fall back to raw Welcome deserialization
        Welcome::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| format!("Failed to deserialize welcome: {e:?}"))?
    };

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged = StagedWelcome::new_from_welcome(provider, &join_config, welcome, None)
        .map_err(|e| format!("Failed to stage welcome: {e:?}"))?;

    let group = staged
        .into_group(provider)
        .map_err(|e| format!("Failed to create group from welcome: {e:?}"))?;

    Ok(group)
}

/// Add a member to an existing group.
pub fn add_member(
    provider: &VoxProvider,
    group: &mut MlsGroup,
    signature_keys: &SignatureKeyPair,
    key_package_bytes: &[u8],
) -> Result<(MlsMessageOut, MlsMessageOut), String> {
    let kp_in = KeyPackageIn::tls_deserialize_exact(key_package_bytes)
        .map_err(|e| format!("Failed to deserialize key package: {e:?}"))?;

    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| format!("Invalid key package: {e:?}"))?;

    let (commit, welcome, _group_info) = group
        .add_members(provider, signature_keys, &[kp])
        .map_err(|e| format!("Failed to add member: {e:?}"))?;

    group
        .merge_pending_commit(provider)
        .map_err(|e| format!("Failed to merge pending commit: {e:?}"))?;

    Ok((welcome, commit))
}

/// Remove a member from an existing group by credential identity.
///
/// Iterates the group's members to find one whose credential identity matches
/// `member_identity`, then removes them by their leaf index.
pub fn remove_member_by_identity(
    provider: &VoxProvider,
    group: &mut MlsGroup,
    signature_keys: &SignatureKeyPair,
    member_identity: &str,
) -> Result<MlsMessageOut, String> {
    let leaf = group
        .members()
        .find_map(|m| {
            let id_bytes = m.credential.serialized_content();
            if id_bytes == member_identity.as_bytes() {
                Some(m.index)
            } else {
                None
            }
        })
        .ok_or_else(|| format!("Member '{}' not found in group", member_identity))?;

    let (commit, _welcome, _group_info) = group
        .remove_members(provider, signature_keys, &[leaf])
        .map_err(|e| format!("Failed to remove member: {e:?}"))?;

    group
        .merge_pending_commit(provider)
        .map_err(|e| format!("Failed to merge pending commit: {e:?}"))?;

    Ok(commit)
}

/// Simplified result of processing an MLS message.
pub enum ProcessedResult {
    Application(Vec<u8>),
    Commit,
    Proposal,
    ExternalJoinProposal,
}

/// Process an incoming MLS message (commit, proposal, or application message).
/// Automatically merges staged commits and stores proposals.
pub fn process_message(
    provider: &VoxProvider,
    group: &mut MlsGroup,
    message_bytes: &[u8],
) -> Result<ProcessedResult, String> {
    let mls_in = MlsMessageIn::tls_deserialize_exact(message_bytes)
        .map_err(|e| format!("Failed to deserialize message: {e:?}"))?;

    let protocol_msg = mls_in
        .try_into_protocol_message()
        .map_err(|e| format!("Not a protocol message: {e:?}"))?;

    let processed = group
        .process_message(provider, protocol_msg)
        .map_err(|e| format!("Failed to process message: {e:?}"))?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            Ok(ProcessedResult::Application(app_msg.into_bytes()))
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(provider, *staged_commit)
                .map_err(|e| format!("Failed to merge staged commit: {e:?}"))?;
            Ok(ProcessedResult::Commit)
        }
        ProcessedMessageContent::ProposalMessage(proposal) => {
            group
                .store_pending_proposal(provider.storage(), *proposal)
                .map_err(|e| format!("Failed to store pending proposal: {e:?}"))?;
            Ok(ProcessedResult::Proposal)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            Ok(ProcessedResult::ExternalJoinProposal)
        }
    }
}

/// Encrypt plaintext into an MLS application message.
pub fn encrypt(
    provider: &VoxProvider,
    group: &mut MlsGroup,
    signature_keys: &SignatureKeyPair,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let msg = group
        .create_message(provider, signature_keys, plaintext)
        .map_err(|e| format!("Failed to encrypt: {e:?}"))?;

    msg.tls_serialize_detached()
        .map_err(|e| format!("Failed to serialize ciphertext: {e:?}"))
}
