#[cfg(feature = "mockall")]
pub mod mock;
pub mod noop;
pub mod types;

use async_trait::async_trait;
use prism_errors::TransactionError;
use prism_keys::{SigningKey, VerifyingKey};
use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    future::Future,
    sync::Arc,
    time::Duration,
};

use crate::{account::Account, builder::RequestBuilder, transaction::Transaction};
use types::{AccountResponse, CommitmentResponse};

#[derive(Clone, Debug)]
pub enum PrismApiError {
    /// Error while preparing the transaction
    Transaction(TransactionError),
    /// Error trying to send a request
    RequestFailed(String),
    /// The target of that API request is invalid
    InvalidTarget(String),
    /// Error during (de)serialization of data
    SerdeFailed(String),
    /// Bridge for [`anyhow::Error`]
    Any(Arc<anyhow::Error>),
    /// Unknown error
    Unknown,
}

impl Display for PrismApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transaction(err) => write!(f, "Transaction error {}", err),
            Self::RequestFailed(msg) => write!(f, "Request execution failed: {}", msg),
            Self::InvalidTarget(msg) => write!(f, "Invalid target: {}", msg),
            Self::SerdeFailed(msg) => write!(f, "(De)Serialization error: {}", msg),
            Self::Any(msg) => write!(f, "Unspecific error: {}", msg),
            Self::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl Error for PrismApiError {}

impl From<TransactionError> for PrismApiError {
    fn from(err: TransactionError) -> Self {
        PrismApiError::Transaction(err)
    }
}

impl From<anyhow::Error> for PrismApiError {
    fn from(err: anyhow::Error) -> Self {
        PrismApiError::Any(Arc::new(err))
    }
}

#[async_trait]
pub trait PrismApi
where
    Self: Sized + Send + Sync,
{
    type Timer: PrismApiTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError>;

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError>;

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError>;

    fn build_request(&self) -> RequestBuilder<'_, Self> {
        RequestBuilder::new_with_prism(self)
    }

    async fn create_account(
        &self,
        id: String,
        service_id: String,
        service_signing_key: &SigningKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .create_account()
            .with_id(id)
            .for_service_with_id(service_id)
            .with_key(signing_key.verifying_key())
            .meeting_signed_challenge(service_signing_key)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn add_key(
        &self,
        account: &Account,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .to_modify_account(account)
            .add_key(key)?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn create_did(
        &self,
        verification_method: VerifyingKey,
        rotation_keys: Vec<VerifyingKey>,
        also_known_as: String,
        atproto_pds: String,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        assert!(rotation_keys.contains(&signing_key.clone().verifying_key()));
        self.build_request()
            .create_did()
            .with_also_known_as(also_known_as)
            .with_verification_method("atproto".to_string(), verification_method)
            .with_atproto_pds(atproto_pds)
            .with_rotation_keys(rotation_keys)
            .build()?
            .sign(signing_key)?
            .send()
            .await
    }

    async fn revoke_key(
        &self,
        account: &Account,
        key: VerifyingKey,
        signing_key: &SigningKey,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.build_request()
            .to_modify_account(account)
            .revoke_key(key)?
            .sign(signing_key)?
            .send()
            .await
    }
}

pub trait PrismApiTimer {
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send;
}

const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait]
pub trait PendingTransaction<'a>
where
    Self: Send + Sync,
{
    type Timer: PrismApiTimer;

    async fn wait(&self) -> Result<Account, PrismApiError> {
        self.wait_with_interval(DEFAULT_POLLING_INTERVAL).await
    }

    async fn wait_with_interval(&self, interval: Duration) -> Result<Account, PrismApiError>;
}

pub struct PendingTransactionImpl<'a, P>
where
    P: PrismApi,
{
    prism: &'a P,
    transaction: Transaction,
}

impl<'a, P> PendingTransactionImpl<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P, transaction: Transaction) -> Self {
        Self { prism, transaction }
    }
}

#[async_trait]
impl<'a, P> PendingTransaction<'a> for PendingTransactionImpl<'a, P>
where
    P: PrismApi,
{
    type Timer = P::Timer;

    async fn wait_with_interval(&self, interval: Duration) -> Result<Account, PrismApiError> {
        loop {
            if let AccountResponse {
                account: Some(account),
                proof: _,
            } = self.prism.get_account(&self.transaction.id).await?
                && account.nonce() > self.transaction.nonce
            {
                return Ok(account);
            };
            Self::Timer::sleep(interval).await;
        }
    }
}
