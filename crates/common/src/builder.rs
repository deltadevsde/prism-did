use std::collections::HashMap;

use prism_errors::TransactionError;
use prism_keys::{SigningKey, VerifyingKey};
use prism_serde::binary::ToBinary;

use crate::{
    account::Account,
    api::{PendingTransaction, PrismApi, PrismApiError, noop::NoopPrismApi},
    digest::Digest,
    operation::{Operation, SignatureBundle},
    transaction::{Transaction, UnsignedTransaction},
};

pub struct RequestBuilder<'a, P = NoopPrismApi> {
    prism: Option<&'a P>,
}

impl<'a, P> RequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new() -> Self {
        Self { prism: None }
    }

    pub fn new_with_prism(prism: &'a P) -> Self {
        Self { prism: Some(prism) }
    }

    pub fn create_account(self) -> CreateAccountRequestBuilder<'a, P> {
        CreateAccountRequestBuilder::new(self.prism)
    }

    pub fn to_modify_account(self, account: &Account) -> ModifyAccountRequestBuilder<'a, P> {
        ModifyAccountRequestBuilder::new(self.prism, account)
    }

    pub fn create_did(self) -> CreateDIDRequestBuilder<'a, P> {
        CreateDIDRequestBuilder::new(self.prism)
    }

    pub fn continue_transaction(
        self,
        unsigned_transaction: UnsignedTransaction,
    ) -> SigningTransactionRequestBuilder<'a, P> {
        SigningTransactionRequestBuilder::new(self.prism, unsigned_transaction)
    }
}

impl<P> Default for RequestBuilder<'_, P>
where
    P: PrismApi,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct CreateAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    id: String,
    service_id: String,
    key: Option<VerifyingKey>,
}

impl<'a, P> CreateAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>) -> Self {
        Self {
            prism,
            id: String::new(),
            service_id: String::new(),
            key: None,
        }
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    pub fn with_key(mut self, key: VerifyingKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn for_service_with_id(mut self, service_id: String) -> Self {
        self.service_id = service_id;
        self
    }

    pub fn meeting_signed_challenge(
        self,
        service_signing_key: &SigningKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        let Some(key) = self.key else {
            return Err(TransactionError::MissingKey);
        };

        // This could be some external service signing account creation credentials
        let hash = Digest::hash_items(&[
            self.id.as_bytes(),
            self.service_id.as_bytes(),
            &key.to_bytes(),
        ]);
        let signature =
            service_signing_key.sign(hash).map_err(|_| TransactionError::SigningFailed)?;

        let operation = Operation::CreateAccount {
            id: self.id.clone(),
            key,
        };

        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;

        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: 0,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }
}

pub struct CreateDIDRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    did: String,
    verification_methods: HashMap<String, VerifyingKey>,
    rotation_keys: Vec<VerifyingKey>,
    also_known_as: Vec<String>,
    atproto_pds: String,
}
// TODO(DID): not okay
fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    if data.is_empty() {
        return String::new();
    }

    let mut result = String::new();
    let mut buffer = 0u64;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_in_buffer += 8;

        // Extract 5-bit chunks from the buffer
        while bits_in_buffer >= 5 {
            let index = ((buffer >> (bits_in_buffer - 5)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
            bits_in_buffer -= 5;
        }
    }

    // Handle remaining bits
    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    // Add padding
    while result.len().is_multiple_of(8) {
        result.push('=');
    }

    result
}

impl<'a, P> CreateDIDRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>) -> Self {
        Self {
            prism,
            did: String::new(),
            verification_methods: HashMap::new(),
            rotation_keys: Vec::new(),
            also_known_as: Vec::new(),
            atproto_pds: String::new(),
        }
    }

    pub fn with_verification_method(mut self, id: String, key: VerifyingKey) -> Self {
        self.verification_methods.insert(id, key);
        self
    }

    pub fn with_rotation_keys(mut self, keys: Vec<VerifyingKey>) -> Self {
        self.rotation_keys = keys;
        self
    }

    pub fn with_also_known_as(mut self, alias: String) -> Self {
        self.also_known_as.push(alias);
        self
    }

    pub fn with_atproto_pds(mut self, pds: String) -> Self {
        self.atproto_pds = pds;
        self
    }

    // TODO(DID): atrocious, hacky rust
    pub fn build(self) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        let operation = Operation::CreateDID {
            did: "".to_string(),
            verification_methods: self.verification_methods.clone(),
            rotation_keys: self.rotation_keys.clone(),
            also_known_as: self.also_known_as.clone(),
            atproto_pds: self.atproto_pds.clone(),
        };

        // TODO(DID): This needs to use DAG-CBOR encoding
        let op_hash = Digest::hash(
            &operation
                .encode_to_bytes()
                .map_err(|e| TransactionError::EncodingFailed(e.to_string()))?,
        );

        let mut b32 = encode_base32(op_hash.as_bytes());
        b32.split_off(24);
        let did = format!("did:prism:{}", b32);

        let operation = Operation::CreateDID {
            did: did.clone(),
            verification_methods: self.verification_methods,
            rotation_keys: self.rotation_keys,
            also_known_as: self.also_known_as,
            atproto_pds: self.atproto_pds,
        };

        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;

        let unsigned_transaction = UnsignedTransaction {
            id: self.did,
            operation,
            nonce: 0,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }
}

pub struct ModifyAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    id: String,
    nonce: u64,
}

impl<'a, P> ModifyAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>, account: &Account) -> Self {
        Self {
            prism,
            id: account.id().to_string(),
            nonce: account.nonce(),
        }
    }

    pub fn add_key(
        self,
        key: VerifyingKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        self.validate_id_and_nonce()?;
        let operation = Operation::AddKey { key };
        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;
        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: self.nonce,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }

    pub fn revoke_key(
        self,
        key: VerifyingKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        self.validate_id_and_nonce()?;
        let operation = Operation::RevokeKey { key };
        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;
        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: self.nonce,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }

    fn validate_id_and_nonce(&self) -> Result<(), TransactionError> {
        if self.id.len() < 3 {
            return Err(TransactionError::InvalidOp(format!(
                "Invalid ID: {}",
                self.id
            )));
        }

        if self.nonce == 0 {
            return Err(TransactionError::InvalidNonce(self.nonce));
        }
        Ok(())
    }
}

pub struct SigningTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    unsigned_transaction: UnsignedTransaction,
}

impl<'a, P> SigningTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>, unsigned_transaction: UnsignedTransaction) -> Self {
        Self {
            prism,
            unsigned_transaction,
        }
    }

    pub fn sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<SendingTransactionRequestBuilder<'a, P>, TransactionError> {
        let transaction = self.unsigned_transaction.sign(signing_key)?;
        Ok(SendingTransactionRequestBuilder::new(
            self.prism,
            transaction,
        ))
    }

    pub fn with_external_signature(
        self,
        signature_bundle: SignatureBundle,
    ) -> SendingTransactionRequestBuilder<'a, P> {
        SendingTransactionRequestBuilder::new(
            self.prism,
            self.unsigned_transaction.externally_signed(signature_bundle),
        )
    }

    pub fn transaction(self) -> UnsignedTransaction {
        self.unsigned_transaction
    }
}

pub struct SendingTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    transaction: Transaction,
}

impl<'a, P> SendingTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>, transaction: Transaction) -> Self {
        Self { prism, transaction }
    }

    pub async fn send(
        self,
    ) -> Result<impl PendingTransaction<'a, Timer = P::Timer>, PrismApiError> {
        let Some(prism) = self.prism else {
            return Err(TransactionError::MissingSender.into());
        };

        prism.post_transaction(self.transaction).await
    }

    pub fn transaction(self) -> Transaction {
        self.transaction
    }
}
