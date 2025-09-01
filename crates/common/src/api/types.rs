use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{account::Account, digest::Digest};

#[derive(Default, Debug, Serialize, Deserialize, ToSchema)]
/// Request to retrieve account information
pub struct AccountRequest {
    /// Identifier for the account to look up
    pub id: String,
}

#[derive(Default, Debug, Serialize, Deserialize, ToSchema)]
/// Response containing account data and a corresponding Merkle proof
pub struct AccountResponse {
    /// The account if found, or None if not found
    pub account: Option<Account>,
    /// Merkle proof for account membership or non-membership
    pub proof: HashedMerkleProof,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
/// Response representing a cryptographic commitment towards the current state of prism
pub struct CommitmentResponse {
    /// Commitment as root hash of Merkle tree
    pub commitment: Digest,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = r#"{
    "leaf": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "siblings": [
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
    ]
}"#)]
/// A compact representation of a Merkle proof where the nodes are represented by their hash values.
/// Used to verify the inclusion or exclusion of data in a Merkle tree.
pub struct HashedMerkleProof {
    /// The hash of the leaf node being proven, if it exists. None if proving non-existence.
    pub leaf: Option<Digest>,
    /// The hashes of sibling nodes along the path from the leaf to the root.
    pub siblings: Vec<Digest>,
}

impl HashedMerkleProof {
    pub fn empty() -> Self {
        Self {
            leaf: None,
            siblings: vec![],
        }
    }
}

impl Default for HashedMerkleProof {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
/// A verification method in a DID document
pub struct VerificationMethod {
    /// The verification method identifier
    pub id: String,
    /// The type of verification method
    #[serde(rename = "type")]
    pub method_type: String,
    /// The controller of the verification method
    pub controller: String,
    /// The public key in multibase format
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
/// A service endpoint in a DID document
pub struct DidService {
    /// The service identifier
    pub id: String,
    /// The type of service
    #[serde(rename = "type")]
    pub service_type: String,
    /// The service endpoint URL
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
/// A complete DID document
pub struct DidDocument {
    /// The JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID identifier
    pub id: String,
    /// Alternative identifiers for the DID subject
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    /// Verification methods
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Services
    pub service: Vec<DidService>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
/// Response containing account data, Merkle proof, and DID document
pub struct AccountDidResponse {
    /// The account if found, or None if not found
    pub account: Option<Account>,
    /// Merkle proof for account membership or non-membership
    pub proof: HashedMerkleProof,
    /// The DID document derived from the account
    pub did_document: Option<DidDocument>,
}
