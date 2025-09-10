use base32::Alphabet;
use serde::{Deserialize, Serialize};
use std::{self, collections::HashMap, fmt::Display};
use utoipa::ToSchema;

use crate::{account::Service, digest::Digest, transaction};
use prism_keys::{CryptoAlgorithm, Signature, VerifyingKey};
use prism_serde::base64::FromBase64;

use prism_errors::{OperationError, TransactionError};

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

/*
export const addSignature = async <T extends Record<string, unknown>>(
  object: T,
  key: Keypair,
): Promise<T & { sig: string }> => {
  const data = new Uint8Array(cbor.encode(object))
  const sig = await key.sign(data)
  return {
    ...object,
    sig: uint8arrays.toString(sig, 'base64url'),
  }
}

export const formatAtprotoOp = (opts: {
  signingKey: string
  handle: string
  pds: string
  rotationKeys: string[]
  prev: CID | null
}): t.UnsignedOperation => {
  return {
    type: 'plc_operation',
    verificationMethods: {
      atproto: opts.signingKey,
    },
    rotationKeys: opts.rotationKeys,
    alsoKnownAs: [ensureAtprotoPrefix(opts.handle)],
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: ensureHttpPrefix(opts.pds),
      },
    },
    prev: opts.prev?.toString() ?? null,
  }
}

export const atprotoOp = async (opts: {
  signingKey: string
  handle: string
  pds: string
  rotationKeys: string[]
  prev: CID | null
  signer: Keypair
}) => {
  return addSignature(formatAtprotoOp(opts), opts.signer)
}
*/

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
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

    // Not needed because done on Transaction level before being converted into SignedPLCOp
    // Takes vk to avoid re-conversion from string to VerifyingKey in circuit.
    // pub fn verify_signature(&self, vk: VerifyingKey) -> Result<(), TransactionError> {
    //     let cbor_val = serde_ipld_dagcbor::to_vec(&self).unwrap();
    //     let hash = Digest::hash(cbor_val.as_slice());

    //     match &vk {
    //         VerifyingKey::Secp256r1(key) => {
    //             let sig_bytes =
    //                 &Vec::from_base64(transaction::base64url_to_base64(&self.sig)).unwrap();
    //             let signature =
    //                 Signature::from_algorithm_and_bytes(CryptoAlgorithm::Secp256r1, sig_bytes)
    //                     .unwrap();

    //             vk.verify_signature(message, signature)
    //             signature.verify(hash, key)
    //         }
    //         VerifyingKey::Secp256k1(key) => {
    //             let signature =
    //                 Signature::from_algorithm_and_bytes(CryptoAlgorithm::Secp256k1, &self.sig)?;
    //             signature.verify(hash, key)
    //         }
    //         _ => Err(TransactionError::EncodingFailed(
    //             "Signature type not supported for PLC operations".to_string(),
    //         )),
    //     }

    //     vk.verify_signature(hash, &self.sig)
    // }
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{
        account::Service,
        operation::{SignedPLCOp, UnsignedPLCOp},
    };

    #[test]
    fn test_did_creation() {
        /*
        * {
          "did": "did:prism:yczau3zqp3lf7dtwffbac4y7",
          "operation": {
            "did": "did:prism:yczau3zqp3lf7dtwffbac4y7",
            "verification_methods": {
              "atproto": "did:key:zQ3shqps6kmePGGkLWoN9yjS622YVjix3i4X3Qrf1ks6bunQY"
            },
            "rotation_keys": [
              "did:key:zQ3shTYYrKBPaMZArFcpggX8PESrEjhQcH3Qcin2y6onN12By",
              "did:key:zQ3shmjpf1Rm5dkfmjhYEBNghqovFrcVsYWz4MnqMkiwx6Wh1"
            ],
            "also_known_as": [
              "at://mod-authority.test"
            ],
            "atproto_pds": "http://localhost:64519"
          },
          "nonce": 0,
          "signature": "A_f9qHR4Gl_DkI8kAr2HP2d5rdqon-aHCWKM4bkooZw_L2KfoRXmC--92eCZ0sIESuM6-h8cqsqcMVvqbNoIVw",
          "vk": "did:key:zQ3shmjpf1Rm5dkfmjhYEBNghqovFrcVsYWz4MnqMkiwx6Wh1"
        }
        */

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
            sig: "F0_AgX0tghOjtCMPsMGxHP-8JL11GiR8ikgf68XofQAa1vgEZvEe9VBWFko8isAjT5pkcZOf0GBPAq1cujBNHw".to_string()
        };
        let did = signed.derive_did();

        assert_eq!(did, "did:prism:3l3bnfketdgiqyfxjju4pfda".to_string());
    }
}
