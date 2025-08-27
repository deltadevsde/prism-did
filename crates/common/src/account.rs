use std::collections::HashMap;

use anyhow::{Result, anyhow};
use prism_errors::AccountError;
use prism_keys::VerifyingKey;
use prism_serde::raw_or_b64;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    api::{PrismApi, noop::NoopPrismApi},
    builder::{ModifyAccountRequestBuilder, RequestBuilder},
    operation::Operation,
    transaction::Transaction,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, ToSchema)]
/// A structure representing data signed by an (external) key.
pub struct SignedData {
    /// The key that signed the data
    pub key: VerifyingKey,
    /// The signed data as bytes
    #[schema(
        value_type = String,
        format = Byte,
        example = "jMaZEeHpjIrpO33dkS223jPhurSFixoDJUzNWBAiZKA")]
    #[serde(with = "raw_or_b64")]
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default, ToSchema)]
/// Represents an account or service on prism, making up the values of our state
/// tree.
pub struct Account {
    /// The unique identifier for the account.
    // TODO(DID): Make Did type that has verification, also the did should be hash over self
    // without the did
    did: String,

    /// The transaction nonce for the account.
    // TODO(DID): This is not included in the PLC spec, do we need to modify it in any way?
    nonce: u64,

    // TODO(DID): Implement conversion from VerifyingKey to DID format.
    #[serde(rename = "verificationMethods")]
    verification_methods: HashMap<String, VerifyingKey>,

    /// The current set of valid keys for the account. Any of these keys can be
    /// used to sign transactions.
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<VerifyingKey>,

    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    services: HashMap<String, Service>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Service {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

impl Account {
    pub fn id(&self) -> &str {
        &self.did
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn valid_keys(&self) -> &[VerifyingKey] {
        &self.rotation_keys
    }

    /// Creates a new request builder with the default NoopPrismApi implementation.
    /// This is useful for local testing and validation without a real API connection.
    pub fn builder<'a>() -> RequestBuilder<'a, NoopPrismApi> {
        RequestBuilder::new()
    }

    /// Creates a new request builder using the provided PrismApi implementation.
    /// This allows interaction with a specific API instance.
    pub fn builder_via_api<P>(prism: &P) -> RequestBuilder<'_, P>
    where
        P: PrismApi,
    {
        RequestBuilder::new_with_prism(prism)
    }

    /// Creates a modification request builder for this account using the default NoopPrismApi.
    /// This is useful for local testing and validation without a real API connection.
    pub fn modify(&self) -> ModifyAccountRequestBuilder<'_, NoopPrismApi> {
        RequestBuilder::new().to_modify_account(self)
    }

    /// Creates a modification request builder for this account using the provided PrismApi
    /// implementation. This allows building and submitting transactions that modify the current
    /// account state through a specific API.
    pub fn modify_via_api<'a, P>(&self, prism: &'a P) -> ModifyAccountRequestBuilder<'a, P>
    where
        P: PrismApi,
    {
        RequestBuilder::new_with_prism(prism).to_modify_account(self)
    }

    /// Validates and processes an incoming [`Transaction`], updating the account state.
    pub fn process_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.validate_transaction(tx)?;
        self.process_operation(&tx.operation)?;
        self.nonce += 1;
        Ok(())
    }

    /// Validates a transaction against the current account state. Please note
    /// that the operation must be validated separately.
    fn validate_transaction(&self, tx: &Transaction) -> Result<(), AccountError> {
        if tx.nonce != self.nonce {
            return Err(AccountError::NonceError(tx.nonce, self.nonce));
        }

        match &tx.operation {
            Operation::CreateAccount { id, key, .. } => {
                if &tx.id != id {
                    return Err(AccountError::AccountIdError(
                        tx.id.to_string(),
                        id.to_string(),
                    ));
                }
                if &tx.vk != key {
                    return Err(AccountError::AccountKeyError(
                        tx.vk.to_string(),
                        key.to_string(),
                    ));
                }
            }
            _ => {
                if tx.id != self.did {
                    return Err(AccountError::TransactionIdError(
                        tx.id.to_string(),
                        self.did.to_string(),
                    ));
                }
                if !self.rotation_keys.contains(&tx.vk) {
                    return Err(AccountError::InvalidKey);
                }
            }
        }

        tx.verify_signature()?;
        Ok(())
    }

    /// Validates an operation against the current account state.
    fn validate_operation(&self, operation: &Operation) -> Result<()> {
        match operation {
            Operation::AddKey { key } => {
                if self.rotation_keys.contains(key) {
                    return Err(anyhow!("Key already exists"));
                }
            }
            Operation::RevokeKey { key } => {
                if !self.rotation_keys.contains(key) {
                    return Err(anyhow!("Key does not exist"));
                }
            }
            Operation::CreateAccount { .. } => {
                if !self.is_empty() {
                    return Err(anyhow!("Account already exists"));
                }
            }
        }
        Ok(())
    }

    /// Processes an operation, updating the account state. Should only be run
    /// in the context of a transaction.
    fn process_operation(&mut self, operation: &Operation) -> Result<()> {
        self.validate_operation(operation)?;

        match operation {
            Operation::AddKey { key } => {
                self.rotation_keys.push(key.clone());
            }
            Operation::RevokeKey { key } => {
                self.rotation_keys.retain(|k| k != key);
            }
            Operation::CreateAccount { id, key, .. } => {
                self.did = id.clone();
                self.rotation_keys.push(key.clone());
            }
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.nonce == 0
    }
}
