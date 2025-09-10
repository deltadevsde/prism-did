use std::collections::HashMap;

use base64::{Engine as _, alphabet, engine::general_purpose};
use celestia_types::Blob;
use prism_errors::TransactionError;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::operation::{Operation, SignatureBundle, SignedPLCOp, UnsignedPLCOp};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Represents a partial prism transaction that still needs to be signed.
pub struct UnsignedTransaction {
    /// The account id that this transaction is for
    pub id: String,
    /// The [`Operation`] to be applied to the account
    pub operation: Operation,
    /// The nonce of the account at the time of this transaction
    pub nonce: u64,
}

impl UnsignedTransaction {
    /// Signs the transaction with the given [`SigningKey`] and gives out a full [`Transaction`].
    pub fn sign(self, sk: &SigningKey) -> Result<Transaction, TransactionError> {
        let bytes = self.signing_payload()?;
        let signature = sk.sign(&bytes).map_err(|_| TransactionError::SigningFailed)?;

        Ok(Transaction {
            id: self.id,
            operation: self.operation,
            nonce: self.nonce,
            signature,
            vk: sk.verifying_key(),
        })
    }

    /// Creates a full transaction by adding an externally provided signature.
    /// Can be used to create a transaction that has been signed by an external source,
    /// such as a wallet or a mobile app.
    pub fn externally_signed(self, signature_bundle: SignatureBundle) -> Transaction {
        Transaction {
            id: self.id,
            operation: self.operation,
            nonce: self.nonce,
            signature: signature_bundle.signature,
            vk: signature_bundle.verifying_key,
        }
    }

    /// Returns the transaction's payload that needs to be signed, or a TransactionError if encoding
    /// fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, TransactionError> {
        self.encode_to_bytes().map_err(|e| TransactionError::EncodingFailed(e.to_string()))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Represents a prism transaction that can be applied to an account.
pub struct DidTransaction {
    /// The account id that this transaction is for
    pub did: String,
    /// The [`Operation`] to be applied to the account
    pub operation: SignedPLCOp,
    /// The nonce of the account at the time of this transaction
    pub nonce: u64,
    /// The signature of the transaction, signed by [`self::vk`].
    pub signature: String,
    /// The verifying key of the signer of this transaction. This vk must be
    /// included in the account's valid_keys set.
    pub vk: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Represents a prism transaction that can be applied to an account.
pub struct USDidTransaction {
    /// The account id that this transaction is for
    pub did: String,
    /// The [`Operation`] to be applied to the account
    pub operation: SignedPLCOp,
    /// The nonce of the account at the time of this transaction
    pub nonce: u64,
}

impl From<DidTransaction> for USDidTransaction {
    fn from(tx: DidTransaction) -> Self {
        USDidTransaction {
            did: tx.did,
            operation: tx.operation,
            nonce: tx.nonce,
        }
    }
}

impl TryInto<DidTransaction> for Transaction {
    type Error = std::io::Error;

    fn try_into(self) -> Result<DidTransaction, Self::Error> {
        match self.operation {
            Operation::CreateDID {
                did,
                verification_methods,
                rotation_keys,
                also_known_as,
                atproto_pds,
                signature,
            } => {
                let verification_methods: HashMap<String, String> = verification_methods
                    .into_iter()
                    .map(|(a, b)| (a, b.to_did().unwrap()))
                    .collect();
                let rotation_keys: Vec<String> =
                    rotation_keys.into_iter().map(|a| a.to_did().unwrap()).collect();

                let plc_sig = signature.to_plc_signature().unwrap();
                let operation = SignedPLCOp {
                    unsigned: UnsignedPLCOp::new_genesis(
                        rotation_keys,
                        verification_methods,
                        also_known_as,
                        atproto_pds,
                    ),
                    sig: plc_sig.clone(),
                };
                Ok(DidTransaction {
                    did,
                    operation,
                    nonce: self.nonce,
                    signature: plc_sig.clone(),
                    vk: self.vk.to_did().unwrap(),
                })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid operation",
            )),
        }
    }
}

impl TryInto<Transaction> for DidTransaction {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Transaction, Self::Error> {
        let DidTransaction {
            did,
            operation,
            nonce,
            signature,
            vk,
        } = self;

        let verification_methods: HashMap<String, VerifyingKey> = operation
            .unsigned
            .verification_methods
            .into_iter()
            .map(|(a, b)| (a, VerifyingKey::from_did(&b).unwrap()))
            .collect();
        let rotation_keys: Vec<VerifyingKey> = operation
            .unsigned
            .rotation_keys
            .into_iter()
            .map(|a| VerifyingKey::from_did(&a).unwrap())
            .collect();

        Ok(Transaction {
            id: did.clone(),
            operation: Operation::CreateDID {
                did,
                verification_methods,
                rotation_keys,
                also_known_as: operation.unsigned.also_known_as,
                atproto_pds: operation
                    .unsigned
                    .services
                    .get("atproto_pds")
                    .unwrap()
                    .endpoint
                    .clone(),
                signature: Signature::from_algorithm_and_bytes(
                    prism_keys::CryptoAlgorithm::Secp256k1,
                    &general_purpose::GeneralPurpose::new(
                        &alphabet::URL_SAFE,
                        general_purpose::NO_PAD,
                    )
                    .decode(&operation.sig)
                    .unwrap(),
                )
                .unwrap(),
            },
            nonce,
            signature: Signature::from_algorithm_and_bytes(
                prism_keys::CryptoAlgorithm::Secp256k1,
                &general_purpose::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
                    .decode(&signature)
                    .unwrap(),
            )
            .unwrap(),
            vk: VerifyingKey::from_did(&vk).unwrap(),
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Represents a prism transaction that can be applied to an account.
pub struct Transaction {
    /// The account id that this transaction is for
    pub id: String,
    /// The [`Operation`] to be applied to the account
    pub operation: Operation,
    /// The nonce of the account at the time of this transaction
    pub nonce: u64,
    /// The signature of the transaction, signed by [`self::vk`].
    pub signature: Signature,
    /// The verifying key of the signer of this transaction. This vk must be
    /// included in the account's valid_keys set.
    // #[serde(deserialize_with = "deserialize_from_did_str")]
    pub vk: VerifyingKey,
}

impl Transaction {
    /// Verifies the signature of the transaction
    pub fn verify_signature(&self) -> Result<(), TransactionError> {
        let message = self
            .to_unsigned_tx()
            .encode_to_bytes()
            .map_err(|e| TransactionError::EncodingFailed(e.to_string()))?;

        self.vk
            .verify_signature(&message, &self.signature)
            .map_err(|e| TransactionError::InvalidOp(e.to_string()))
    }

    // Used for verifying CBOR-encoded transactions (for DID operations)
    pub fn verify_cbor_signature(&self) -> Result<(), TransactionError> {
        let did_tx: DidTransaction = self.clone().try_into().unwrap();
        let us_did_tx: USDidTransaction = did_tx.into();

        let message = serde_ipld_dagcbor::to_vec(&us_did_tx)
            .map_err(|e| TransactionError::EncodingFailed(e.to_string()))?;

        self.vk
            .verify_signature(&message, &self.signature)
            .map_err(|e| TransactionError::InvalidOp(e.to_string()))
    }

    /// Extracts the part of the transaction that was signed
    fn to_unsigned_tx(&self) -> UnsignedTransaction {
        UnsignedTransaction {
            id: self.id.clone(),
            operation: self.operation.clone(),
            nonce: self.nonce,
        }
    }
}

impl TryFrom<&Blob> for Transaction {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        Transaction::decode_from_bytes(&value.data).map_err(|e| e.into())
    }
}
