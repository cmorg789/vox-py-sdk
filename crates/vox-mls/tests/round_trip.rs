use openmls::prelude::*;
use openmls_libcrux_crypto::Provider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

// Re-use the crate's internal modules for testing
// Since we're testing the PyO3 wrapper's underlying logic, we test at the Rust level.

mod helpers {
    use super::*;
    use openmls_basic_credential::SignatureKeyPair;

    pub const CIPHERSUITE: Ciphersuite =
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    pub struct TestClient {
        pub provider: Provider,
        pub credential_with_key: CredentialWithKey,
        pub signature_keys: SignatureKeyPair,
    }

    impl TestClient {
        pub fn new(name: &str) -> Self {
            let provider = Provider::new().unwrap();
            let credential = BasicCredential::new(name.as_bytes().to_vec());
            let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
            signature_keys.store(provider.storage()).unwrap();

            let credential_with_key = CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.to_public_vec().into(),
            };

            TestClient {
                provider,
                credential_with_key,
                signature_keys,
            }
        }

        pub fn generate_key_package(&self) -> KeyPackage {
            KeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &self.provider,
                    &self.signature_keys,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone()
        }
    }
}

#[test]
fn test_create_group_empty() {
    let alice = helpers::TestClient::new("alice");

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(helpers::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let group = MlsGroup::new_with_group_id(
        &alice.provider,
        &alice.signature_keys,
        &config,
        GroupId::from_slice(b"test:empty"),
        alice.credential_with_key.clone(),
    );

    assert!(group.is_ok());
}

#[test]
fn test_add_member_and_join() {
    let alice = helpers::TestClient::new("alice");
    let bob = helpers::TestClient::new("bob");

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(helpers::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice.provider,
        &alice.signature_keys,
        &config,
        GroupId::from_slice(b"test:chat"),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    // Alice adds Bob
    let bob_kp = bob.generate_key_package();
    let (_commit, welcome, _group_info) = alice_group
        .add_members(&alice.provider, &alice.signature_keys, &[bob_kp])
        .unwrap();

    alice_group.merge_pending_commit(&alice.provider).unwrap();

    // Bob joins from Welcome
    let welcome_bytes = welcome.tls_serialize_detached().unwrap();
    let welcome_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).unwrap();
    let welcome_deser = match welcome_in.extract() {
        openmls::framing::MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("Expected Welcome message"),
    };

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged = StagedWelcome::new_from_welcome(
        &bob.provider,
        &join_config,
        welcome_deser,
        None,
    )
    .unwrap();

    let bob_group = staged.into_group(&bob.provider).unwrap();
    assert_eq!(alice_group.group_id(), bob_group.group_id());
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let alice = helpers::TestClient::new("alice");
    let bob = helpers::TestClient::new("bob");

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(helpers::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice.provider,
        &alice.signature_keys,
        &config,
        GroupId::from_slice(b"test:e2ee"),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    // Add Bob
    let bob_kp = bob.generate_key_package();
    let (_commit, welcome, _group_info) = alice_group
        .add_members(&alice.provider, &alice.signature_keys, &[bob_kp])
        .unwrap();
    alice_group.merge_pending_commit(&alice.provider).unwrap();

    // Bob joins
    let welcome_bytes = welcome.tls_serialize_detached().unwrap();
    let welcome_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).unwrap();
    let welcome_deser = match welcome_in.extract() {
        openmls::framing::MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("Expected Welcome message"),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged =
        StagedWelcome::new_from_welcome(&bob.provider, &join_config, welcome_deser, None).unwrap();
    let mut bob_group = staged.into_group(&bob.provider).unwrap();

    // Alice encrypts
    let plaintext = b"Hello, Bob! This is encrypted.";
    let mls_msg = alice_group
        .create_message(&alice.provider, &alice.signature_keys, plaintext)
        .unwrap();

    let msg_bytes = mls_msg.tls_serialize_detached().unwrap();

    // Bob decrypts
    let msg_in = MlsMessageIn::tls_deserialize_exact(&msg_bytes).unwrap();
    let protocol_msg = msg_in.try_into_protocol_message().unwrap();
    let processed = bob_group
        .process_message(&bob.provider, protocol_msg)
        .unwrap();

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            assert_eq!(app_msg.into_bytes(), plaintext);
        }
        other => panic!("Expected ApplicationMessage, got: {:?}", other),
    }
}

#[test]
fn test_multiple_messages() {
    let alice = helpers::TestClient::new("alice");
    let bob = helpers::TestClient::new("bob");

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(helpers::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice.provider,
        &alice.signature_keys,
        &config,
        GroupId::from_slice(b"test:multi"),
        alice.credential_with_key.clone(),
    )
    .unwrap();

    let bob_kp = bob.generate_key_package();
    let (_commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signature_keys, &[bob_kp])
        .unwrap();
    alice_group.merge_pending_commit(&alice.provider).unwrap();

    let welcome_bytes = welcome.tls_serialize_detached().unwrap();
    let welcome_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).unwrap();
    let welcome_deser = match welcome_in.extract() {
        openmls::framing::MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("Expected Welcome message"),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged =
        StagedWelcome::new_from_welcome(&bob.provider, &join_config, welcome_deser, None).unwrap();
    let mut bob_group = staged.into_group(&bob.provider).unwrap();

    // Send multiple messages
    for i in 0..5 {
        let msg_text = format!("Message {i}");
        let mls_msg = alice_group
            .create_message(&alice.provider, &alice.signature_keys, msg_text.as_bytes())
            .unwrap();
        let msg_bytes = mls_msg.tls_serialize_detached().unwrap();

        let msg_in = MlsMessageIn::tls_deserialize_exact(&msg_bytes).unwrap();
        let protocol_msg = msg_in.try_into_protocol_message().unwrap();
        let processed = bob_group
            .process_message(&bob.provider, protocol_msg)
            .unwrap();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                assert_eq!(app_msg.into_bytes(), msg_text.as_bytes());
            }
            _ => panic!("Expected ApplicationMessage"),
        }
    }
}
