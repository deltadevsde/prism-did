use serde::{Deserialize, Serialize};
use std::{self, fmt::Display};
use utoipa::ToSchema;

use prism_keys::{Signature, SigningKey, VerifyingKey};

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
        /// Identifier of the service this account belongs to
        #[schema(example = "prism")]
        service_id: String,
        /// Challenge response required for account creation
        challenge: ServiceChallengeInput,
        /// Public key associated with the account
        key: VerifyingKey,
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

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    /// Input required when meeting `ServiceChallenge::Signed`.
    /// The provided signature will be verified using the corresponding key from the challenge.
    #[schema(title = "Signed")]
    Signed(Signature),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// A challenge that must be met with valid corresponding `ServiceChallengeInput`
/// when creating an account.
pub enum ServiceChallenge {
    /// Challenge that requires the service to sign corresponding CreateAccount operations
    /// such that the given key can be used to verify their signatures.
    #[schema(title = "Signed")]
    Signed(VerifyingKey),
}

impl From<SigningKey> for ServiceChallenge {
    fn from(sk: SigningKey) -> Self {
        ServiceChallenge::Signed(sk.into())
    }
}

impl Operation {
    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        match self {
            Operation::RevokeKey { key }
            | Operation::AddKey { key }
            | Operation::CreateAccount { key, .. } => Some(key),
        }
    }

    pub fn validate_basic(&self) -> Result<(), OperationError> {
        match &self {
            Operation::CreateAccount { id, service_id, .. } => {
                if id.is_empty() {
                    return Err(OperationError::EmptyAccountId);
                }

                if service_id.is_empty() {
                    return Err(OperationError::EmptyServiceIdForAccount);
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
