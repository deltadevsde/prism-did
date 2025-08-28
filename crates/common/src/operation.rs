use serde::{Deserialize, Serialize};
use std::{self, collections::HashMap, fmt::Display};
use utoipa::ToSchema;

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
