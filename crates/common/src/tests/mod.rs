// use prism_keys::SigningKey;

use std::collections::HashMap;

use base64::{Engine as _, alphabet, engine::general_purpose};

use prism_keys::{CryptoAlgorithm, Signature};

use crate::{
    account::Service,
    operation::{SignedPLCOp, UnsignedPLCOp},
    transaction::{SignedPlcTransaction, Transaction},
};

#[test]
fn test_did_creation() {
    let plc_op = UnsignedPLCOp {
        type_: "plc_operation".to_string(),
        services: HashMap::from([(
            "atproto_pds".to_string(),
            Service::new_pds("http://localhost:65473".to_string()),
        )]),
        verification_methods: HashMap::from([(
            "atproto".to_string(),
            "did:key:zQ3shRqHqyhXgCjBmLyPhwN6ENSLMYCVUS7684MKrmVunRF8H".to_string(),
        )]),
        rotation_keys: vec![
            "did:key:zQ3shYUkjUJWLxshqnPbDb1bwc2wMeRy65yQ7TdeotDRoA54G".to_string(),
            "did:key:zQ3shZUHZuc3Z74mmMhZG2FS87oLqdiHBJyrv5vSc4tychPZF".to_string(),
        ],
        also_known_as: vec!["at://mod-authority.test".to_string()],
        prev: None,
    };

    let signed = SignedPLCOp {
        unsigned: plc_op,
        sig:
            "F0_AgX0tghOjtCMPsMGxHP-8JL11GiR8ikgf68XofQAa1vgEZvEe9VBWFko8isAjT5pkcZOf0GBPAq1cujBNHw"
                .to_string(),
    };
    let did = signed.derive_did();

    assert_eq!(did, "did:prism:3l3bnfketdgiqyfxjju4pfda".to_string());
}

#[test]
fn plc_signature_verification() {
    let signature =
        "C_EJ4mrlmfouuXepfMy2ZJkwTUGYyTy9TuL-EThzyYV9SwLenDeJaTOhYUFnJ-C4pxKOrghNjWueNQpEUAIbbw"
            .to_string();
    let sig_bytes =
        general_purpose::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
            .decode(&signature)
            .unwrap();
    let parsed_signature =
        Signature::from_algorithm_and_bytes(CryptoAlgorithm::Secp256k1, &sig_bytes).unwrap();
    let reparsed_signature = parsed_signature.to_plc_signature().unwrap();
    assert_eq!(signature, reparsed_signature);

    let key_str = "did:key:zQ3shYxgqcVTCgB5z21jid9vfJy1GkFUySPMzLQDPUtdN5qPe";

    let plc_op = UnsignedPLCOp {
        type_: "plc_operation".to_string(),
        services: HashMap::from([(
            "atproto_pds".to_string(),
            Service::new_pds("http://localhost:49793".to_string()),
        )]),
        verification_methods: HashMap::from([(
            "atproto".to_string(),
            "did:key:zQ3shnpPSGRJGPFVNYZSrrz4CHjqW5eFau6gsGXFrdmsJ4axx".to_string(),
        )]),
        rotation_keys: vec![
            "did:key:zQ3shcmbGVVFBmW8kM1ffcrmPDFB8u4YFxWH7gemf6SpsGNzL".to_string(),
            "did:key:zQ3shYxgqcVTCgB5z21jid9vfJy1GkFUySPMzLQDPUtdN5qPe".to_string(),
        ],
        also_known_as: vec!["at://mod-authority.test".to_string()],
        prev: None,
    };

    let signed = SignedPLCOp {
        unsigned: plc_op.clone(),
        sig:
            "yFKwHXi1q5if7hhyYjp5boUx-IrgEDzslnQl-fwwGNsr0Mrbcgkkgjxo_H8v6SW7i2IgVNUPmM-VStgTPIu0mQ"
                .to_string(),
    };

    let did = signed.derive_did();
    assert_eq!(did, "did:prism:moipkdqlz5x3qjmdqjwa6zsk");

    let tx: Transaction = SignedPlcTransaction {
        did: did.clone(),
        operation: SignedPLCOp {
            unsigned: UnsignedPLCOp::new_genesis(
                plc_op.rotation_keys.clone(),
                plc_op.verification_methods.clone(),
                plc_op.also_known_as.clone(),
                "http://localhost:49793".to_string(),
            ),
            sig: signed.sig.clone(),
        },
        nonce: 0,
        signature: reparsed_signature,
        vk: key_str.to_string(),
    }
    .try_into()
    .unwrap();

    tx.verify_cbor_signature().unwrap();
}

// use crate::{account::Account, operation::Operation};
// #[test]
// fn test_process_register_service_transactions() {
//     let service_key = SigningKey::new_ed25519();
//     let challenge_key = SigningKey::new_ed25519();

//     // happy path - should succeed
//     let create_tx = Account::builder()
//         .register_service()
//         .with_id("Service".to_string())
//         .with_key(service_key.verifying_key())
//         .requiring_signed_challenge(challenge_key.verifying_key())
//         .unwrap()
//         .sign(&service_key)
//         .unwrap()
//         .transaction();

//     assert!(Account::default().process_transaction(&create_tx).is_ok());

//     // should fail with invalid nonce
//     let mut unsigned_invalid_tx = Account::builder()
//         .register_service()
//         .with_id("Service".to_string())
//         .with_key(service_key.verifying_key())
//         .requiring_signed_challenge(challenge_key.verifying_key())
//         .unwrap()
//         .transaction();

//     unsigned_invalid_tx.nonce = 1; // has to be 0 for RegisterService
//     let invalid_tx = unsigned_invalid_tx.sign(&service_key).unwrap();

//     assert!(Account::default().process_transaction(&invalid_tx).is_err());

//     // should fail when operation id and transaction id are not equal
//     let mut unsigned_invalid_tx = Account::builder()
//         .register_service()
//         .with_id("Service".to_string())
//         .with_key(service_key.verifying_key())
//         .requiring_signed_challenge(challenge_key.verifying_key())
//         .unwrap()
//         .transaction();

//     if let Operation::RegisterService { id, .. } = &mut unsigned_invalid_tx.operation {
//         *id = "DifferentService".to_string();
//     } else {
//         panic!("Unexpected operation type");
//     }
//     let invalid_tx = unsigned_invalid_tx.sign(&service_key).unwrap();

//     assert!(Account::default().process_transaction(&invalid_tx).is_err());

//     // should fail when transaction is signed with an invalid key
//     let invalid_key = SigningKey::new_ed25519();
//     let invalid_tx = Account::builder()
//         .register_service()
//         .with_id("Service".to_string())
//         .with_key(service_key.verifying_key())
//         .requiring_signed_challenge(challenge_key.verifying_key())
//         .unwrap()
//         .sign(&invalid_key)
//         .unwrap()
//         .transaction();

//     assert!(Account::default().process_transaction(&invalid_tx).is_err());
// }

// #[test]
// fn test_process_create_account_transactions() {
//     let service_key = SigningKey::new_ed25519();
//     let acc_key = SigningKey::new_ed25519();

//     // happy path - should succeed
//     let create_tx = Account::builder()
//         .create_account()
//         .with_id("Acc".to_string())
//         .for_service_with_id("Service".to_string())
//         .with_key(acc_key.verifying_key())
//         .meeting_signed_challenge(&service_key)
//         .unwrap()
//         .sign(&acc_key)
//         .unwrap()
//         .transaction();

//     assert!(Account::default().process_transaction(&create_tx).is_ok());

//     // should fail with invalid nonce
//     let mut unsigned_invalid_tx = Account::builder()
//         .create_account()
//         .with_id("Acc".to_string())
//         .for_service_with_id("Service".to_string())
//         .with_key(acc_key.verifying_key())
//         .meeting_signed_challenge(&service_key)
//         .unwrap()
//         .transaction();

//     unsigned_invalid_tx.nonce = 1; // has to be 0 for CreateAccount
//     let invalid_tx = unsigned_invalid_tx.sign(&acc_key).unwrap();

//     assert!(Account::default().process_transaction(&invalid_tx).is_err());

//     // should fail when operation id and transaction id are not equal
//     let mut unsigned_invalid_tx = Account::builder()
//         .create_account()
//         .with_id("Acc".to_string())
//         .for_service_with_id("Service".to_string())
//         .with_key(acc_key.verifying_key())
//         .meeting_signed_challenge(&service_key)
//         .unwrap()
//         .transaction();

//     if let Operation::CreateAccount { id, .. } = &mut unsigned_invalid_tx.operation {
//         *id = "DifferentAcc".to_string();
//     } else {
//         panic!("Unexpected operation type");
//     }
//     let invalid_tx = unsigned_invalid_tx.sign(&acc_key).unwrap();

//     assert!(Account::default().process_transaction(&invalid_tx).is_err());

//     // should fail when transaction is signed with an invalid key
//     let invalid_key = SigningKey::new_ed25519();
//     let invalid_tx = Account::builder()
//         .create_account()
//         .with_id("Acc".to_string())
//         .for_service_with_id("Service".to_string())
//         .with_key(acc_key.verifying_key())
//         .meeting_signed_challenge(&service_key)
//         .unwrap()
//         .sign(&invalid_key)
//         .unwrap()
//         .transaction();

//     assert!(Account::default().process_transaction(&invalid_tx).is_err());
// }
