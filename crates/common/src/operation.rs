use base32::Alphabet;
use serde::{Deserialize, Serialize};
use std::{self, collections::HashMap, fmt::Display};
use utoipa::ToSchema;

use crate::{account::Service, digest::Digest};
use prism_keys::{Signature, VerifyingKey};

use prism_errors::OperationError;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[schema(
    title = "Operation",
    description = "State transition operation in the system"
)]
/// An [`Operation`] represents a state transition in the system.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    #[schema(title = "CreateAccount")]
    /// Creates a new account with the given id and key.
    CreateAccount {
        /// Unique identifier for the account
        #[schema(example = "user123@prism.xyz")]
        id: String,
        /// Public key associated with the account
        key: VerifyingKey,
    },
    #[schema(title = "CreateDID")]
    CreateDID {
        did: String,
        verification_methods: HashMap<String, VerifyingKey>,
        rotation_keys: Vec<VerifyingKey>,
        also_known_as: Vec<String>,
        atproto_pds: String,
        // NOTE: This signature is not a prism signature, so is held in a string.
        // TODO(did): Do validation anyways
        signature: Signature,
    },
    #[schema(title = "AddKey")]
    /// Adds a key to an existing account.
    AddKey {
        /// Public key to be added to the account
        key: VerifyingKey,
    },
    #[schema(title = "RevokeKey")]
    /// Revokes a key from an existing account.
    RevokeKey {
        /// Public key to be revoked from the account
        key: VerifyingKey,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedPLCOp {
    #[serde(rename = "type")]
    #[serde(default)]
    pub type_: String,
    #[serde(default)]
    pub rotation_keys: Vec<String>,
    #[serde(default)]
    pub verification_methods: HashMap<String, String>,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub services: HashMap<String, Service>,
    pub prev: Option<String>,
}

impl UnsignedPLCOp {
    pub fn new_genesis(
        rotation_keys: Vec<String>,
        verification_methods: HashMap<String, String>,
        also_known_as: Vec<String>,
        atproto_pds: String,
    ) -> Self {
        UnsignedPLCOp {
            type_: "plc_operation".to_string(),
            rotation_keys,
            verification_methods,
            also_known_as,
            services: HashMap::from([("atproto_pds".to_string(), Service::new_pds(atproto_pds))]),
            prev: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignedPLCOp {
    #[serde(flatten)]
    pub unsigned: UnsignedPLCOp,
    pub sig: String,
}

impl TryFrom<&Operation> for SignedPLCOp {
    type Error = OperationError;

    fn try_from(operation: &Operation) -> Result<Self, Self::Error> {
        match operation {
            Operation::CreateDID {
                rotation_keys,
                also_known_as,
                verification_methods,
                atproto_pds,
                signature,
                ..
            } => {
                // TODO(DID): dangerous unwrap, not all key types are supported
                let rotation_keys =
                    rotation_keys.iter().map(|k| k.to_did().unwrap()).collect::<Vec<_>>();

                let verification_methods = verification_methods
                    .iter()
                    .map(|(n, k)| (n.clone(), k.to_did().unwrap()))
                    .collect::<HashMap<String, String>>();

                let plc_op = UnsignedPLCOp {
                    type_: "plc_operation".to_string(),
                    rotation_keys,
                    also_known_as: also_known_as.clone(),
                    verification_methods,
                    services: HashMap::from([(
                        "atproto_pds".to_string(),
                        Service::new_pds(atproto_pds.clone()),
                    )]),
                    prev: None,
                };

                Ok(SignedPLCOp {
                    unsigned: plc_op,
                    sig: signature.to_plc_signature().unwrap(),
                })
            }
            _ => Err(OperationError::InvalidPLCConversion),
        }
    }
}

impl SignedPLCOp {
    pub fn derive_did(&self) -> String {
        let cbor_val = serde_ipld_dagcbor::to_vec(&self).unwrap();
        let hash = Digest::hash(cbor_val.as_slice());

        let b32 = base32::encode(Alphabet::Rfc4648Lower { padding: false }, hash.as_bytes());
        let derived_did = format!("did:prism:{}", b32[0..24].to_string());

        derived_did
    }

    // TODO(DID): This is very inefficient, and "reconverts" the signature back
    // into a string in circuit. Pretty sure this can already be done at the
    // operation level instead of here.
    pub fn verify_signature(&self, vk: VerifyingKey) -> Result<(), prism_keys::CryptoError> {
        let cbor_val = serde_ipld_dagcbor::to_vec(&self).unwrap();
        let hash = Digest::hash(cbor_val.as_slice());

        let sig = Signature::from_plc_signature(&self.sig).unwrap();

        vk.verify_signature(hash, &sig)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Represents a signature and the key to verify it.
pub struct SignatureBundle {
    /// The key that can be used to verify the signature
    pub verifying_key: VerifyingKey,
    /// The actual signature
    pub signature: Signature,
}

impl SignatureBundle {
    /// Creates a new `SignatureBundle` with the given verifying key and signature.
    pub fn new(verifying_key: VerifyingKey, signature: Signature) -> Self {
        SignatureBundle {
            verifying_key,
            signature,
        }
    }
}

impl Operation {
    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        match self {
            Operation::RevokeKey { key }
            | Operation::AddKey { key }
            | Operation::CreateAccount { key, .. } => Some(key),
            Operation::CreateDID { .. } => None,
        }
    }

    pub fn validate_basic(&self) -> Result<(), OperationError> {
        match &self {
            Operation::CreateAccount { id, .. } => {
                if id.is_empty() {
                    return Err(OperationError::EmptyAccountId);
                }

                Ok(())
            }
            Operation::CreateDID {
                verification_methods,
                rotation_keys,
                ..
            } => {
                // TODO(DID): Obviously placeholder validations, but they refer to the
                // did-method-plc README.md
                if verification_methods.len() > 10 {
                    return Err(OperationError::DataTooLarge(10));
                }

                if rotation_keys.is_empty() {
                    return Err(OperationError::EmptyAccountId);
                }

                Ok(())
            }
            Operation::AddKey { .. } | Operation::RevokeKey { .. } => Ok(()),
        }
    }
}

impl Display for Operation {
    // just print the debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
