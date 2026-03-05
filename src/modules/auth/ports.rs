use async_trait::async_trait;
use chrono::{DateTime, Utc};
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::modules::auth::domain::{
    EmailOutboxMessage, EmailOutboxPayload, EmailTemplate, MfaChallengeRecord, MfaFactorRecord,
    PasswordResetTokenRecord, User, VerificationTokenRecord,
};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Option<User>;
    async fn find_by_id(&self, user_id: &str) -> Option<User>;
    async fn create_pending_user(
        &self,
        email: &str,
        password_hash: &str,
    ) -> Result<Option<User>, String>;
    async fn activate_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn update_password(
        &self,
        user_id: &str,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationTokenConsumeState {
    Consumed { user_id: String },
    NotFound,
    AlreadyUsed,
    Expired,
}

#[async_trait]
pub trait VerificationTokenRepository: Send + Sync {
    async fn issue(&self, token: VerificationTokenRecord) -> Result<(), String>;
    async fn consume(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<VerificationTokenConsumeState, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordResetTokenConsumeState {
    Consumed { user_id: String },
    NotFound,
    AlreadyUsed,
    Expired,
}

#[async_trait]
pub trait PasswordResetTokenRepository: Send + Sync {
    async fn issue(&self, token: PasswordResetTokenRecord) -> Result<(), String>;
    async fn consume(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<PasswordResetTokenConsumeState, String>;
}

#[derive(Clone, Debug)]
pub enum LoginGateDecision {
    Allowed,
    Locked { until: DateTime<Utc> },
}

#[async_trait]
pub trait LoginAbuseProtector: Send + Sync {
    async fn check(
        &self,
        email: &str,
        source_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> LoginGateDecision;
    async fn register_failure(
        &self,
        email: &str,
        source_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>>;
    async fn register_success(&self, email: &str, source_ip: Option<&str>);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginRiskDecision {
    Allow,
    Block { reason: String },
    Challenge { reason: String },
}

#[async_trait]
pub trait LoginRiskAnalyzer: Send + Sync {
    async fn evaluate_login(
        &self,
        email: &str,
        user_id: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
        now: DateTime<Utc>,
    ) -> LoginRiskDecision;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MfaChallengeLookupState {
    Active {
        user_id: String,
        device_info: Option<String>,
    },
    NotFound,
    AlreadyUsed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MfaChallengeFailureState {
    RetryAllowed { remaining_attempts: u32 },
    Exhausted,
    NotFound,
    AlreadyUsed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MfaBackupCodeConsumeState {
    Consumed,
    NotFound,
    AlreadyUsed,
}

#[async_trait]
pub trait MfaFactorRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: &str) -> Option<MfaFactorRecord>;
    async fn upsert(&self, factor: MfaFactorRecord) -> Result<(), String>;
    async fn set_enabled_at(&self, user_id: &str, enabled_at: DateTime<Utc>) -> Result<(), String>;
    async fn delete_for_user(&self, user_id: &str) -> Result<(), String>;
}

#[async_trait]
pub trait MfaChallengeRepository: Send + Sync {
    async fn issue(&self, challenge: MfaChallengeRecord) -> Result<(), String>;
    async fn find_active(
        &self,
        challenge_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookupState, String>;
    async fn mark_used(&self, challenge_hash: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn register_failure(
        &self,
        challenge_hash: &str,
        now: DateTime<Utc>,
        max_attempts: u32,
    ) -> Result<MfaChallengeFailureState, String>;
}

#[async_trait]
pub trait MfaBackupCodeRepository: Send + Sync {
    async fn replace_for_user(
        &self,
        user_id: &str,
        code_hashes: &[String],
        now: DateTime<Utc>,
    ) -> Result<(), String>;
    async fn consume(
        &self,
        user_id: &str,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<MfaBackupCodeConsumeState, String>;
}

#[async_trait]
pub trait PasskeyCredentialRepository: Send + Sync {
    async fn list_for_user(&self, user_id: &str) -> Result<Vec<Passkey>, String>;
    async fn upsert_for_user(
        &self,
        user_id: &str,
        passkey: Passkey,
        now: DateTime<Utc>,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub struct PasskeyRegistrationChallengeRecord {
    pub user_id: String,
    pub state: PasskeyRegistration,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct PasskeyAuthenticationChallengeRecord {
    pub user_id: String,
    pub state: PasskeyAuthentication,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum PasskeyRegistrationChallengeConsumeState {
    Active(PasskeyRegistrationChallengeRecord),
    NotFound,
    Expired,
}

#[derive(Clone, Debug)]
pub enum PasskeyAuthenticationChallengeConsumeState {
    Active(PasskeyAuthenticationChallengeRecord),
    NotFound,
    Expired,
}

#[async_trait]
pub trait PasskeyChallengeRepository: Send + Sync {
    async fn issue_registration(
        &self,
        flow_id: &str,
        challenge: PasskeyRegistrationChallengeRecord,
    ) -> Result<(), String>;

    async fn consume_registration(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyRegistrationChallengeConsumeState, String>;

    async fn issue_authentication(
        &self,
        flow_id: &str,
        challenge: PasskeyAuthenticationChallengeRecord,
    ) -> Result<(), String>;

    async fn consume_authentication(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyAuthenticationChallengeConsumeState, String>;

    async fn prune_expired(&self, now: DateTime<Utc>) -> Result<u64, String>;
}

#[async_trait]
pub trait TransactionalEmailSender: Send + Sync {
    async fn send_verification_email(
        &self,
        recipient_email: &str,
        verification_token: &str,
        expires_in_seconds: i64,
    ) -> Result<(), String>;

    async fn send_password_reset_email(
        &self,
        recipient_email: &str,
        reset_token: &str,
        expires_in_seconds: i64,
    ) -> Result<(), String>;
}

#[async_trait]
pub trait EmailOutboxRepository: Send + Sync {
    async fn enqueue(
        &self,
        recipient_email: &str,
        provider: &str,
        template: EmailTemplate,
        payload: EmailOutboxPayload,
        now: DateTime<Utc>,
    ) -> Result<(), String>;

    async fn fetch_due(
        &self,
        now: DateTime<Utc>,
        batch_size: u32,
        max_attempts: u32,
        lease_expires_at: DateTime<Utc>,
        worker_id: &str,
    ) -> Result<EmailOutboxFetchResult, String>;

    async fn mark_sent(
        &self,
        message_id: &str,
        worker_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String>;

    async fn mark_failed_backoff(
        &self,
        message_id: &str,
        worker_id: &str,
        next_attempt_at: Option<DateTime<Utc>>,
        last_error: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String>;

    async fn queue_snapshot(&self, now: DateTime<Utc>) -> Result<EmailOutboxQueueSnapshot, String>;
}

#[derive(Clone, Debug, Default)]
pub struct EmailOutboxFetchResult {
    pub messages: Vec<EmailOutboxMessage>,
    pub claimed_count: u64,
    pub reclaimed_after_expiry_count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EmailOutboxQueueSnapshot {
    pub pending_count: u64,
    pub oldest_pending_age_seconds: u64,
    pub oldest_due_age_seconds: u64,
}
