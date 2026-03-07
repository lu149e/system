use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::modules::auth::domain::{
    AccountRecord, AuthFlowRecord, EmailOutboxMessage, EmailOutboxPayload, EmailTemplate,
    LegacyPasswordRecord, MfaChallengeRecord, MfaFactorRecord, OpaqueCredentialRecord,
    PasswordResetTokenRecord, User, VerificationTokenRecord,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthFlowMetricBucket {
    pub flow_kind: crate::modules::auth::domain::AuthFlowKind,
    pub pending_total: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthFlowMetricsSnapshot {
    pub active_by_kind: Vec<AuthFlowMetricBucket>,
    pub expired_pending_total: u64,
    pub oldest_expired_pending_age_seconds: u64,
}

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

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Option<AccountRecord>;
    async fn find_by_id(&self, user_id: &str) -> Option<AccountRecord>;
    async fn create_pending(
        &self,
        email: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AccountRecord>, String>;
    async fn activate(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
}

#[async_trait]
pub trait LegacyPasswordRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Option<LegacyPasswordRecord>, String>;
    async fn upsert_hash(
        &self,
        user_id: &str,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String>;
    async fn mark_verified(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn set_legacy_login_allowed(
        &self,
        user_id: &str,
        allowed: bool,
        now: DateTime<Utc>,
    ) -> Result<(), String>;
}

#[async_trait]
pub trait OpaqueCredentialRepository: Send + Sync {
    async fn find_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<OpaqueCredentialRecord>, String>;
    async fn upsert_for_user(&self, record: OpaqueCredentialRecord) -> Result<(), String>;
    async fn mark_verified(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn revoke_for_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthFlowConsumeState {
    Active(Box<AuthFlowRecord>),
    NotFound,
    AlreadyConsumed,
    Expired,
    Cancelled,
}

#[allow(dead_code)]
#[async_trait]
pub trait AuthFlowRepository: Send + Sync {
    async fn issue(&self, flow: AuthFlowRecord) -> Result<(), String>;
    async fn consume(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthFlowConsumeState, String>;
    async fn increment_attempts(&self, flow_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn cancel_active_for_subject(
        &self,
        subject_user_id: Option<&str>,
        subject_identifier_hash: Option<&str>,
        flow_kind: &str,
        now: DateTime<Utc>,
    ) -> Result<u64, String>;
    async fn metrics_snapshot(&self, now: DateTime<Utc>)
        -> Result<AuthFlowMetricsSnapshot, String>;
    async fn prune_expired(&self, now: DateTime<Utc>) -> Result<u64, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AuthMethodKind {
    PasswordPake,
    PasswordUpgrade,
    Passkey,
    LegacyPassword,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthMethodDescriptor {
    pub kind: AuthMethodKind,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct AuthMethodDiscoveryRequest {
    pub identifier: String,
    pub client_id: Option<String>,
    pub supports_passkeys: bool,
    pub supports_pake: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct AuthMethodDiscoveryResult {
    pub discovery_token: String,
    pub recommended_method: Option<AuthMethodKind>,
    pub methods: Vec<AuthMethodDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PakeLoginCredentialView {
    pub user_id: Option<String>,
    pub opaque_credential: Option<Vec<u8>>,
    pub legacy_password_allowed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PakeStartRequest {
    pub flow_id: String,
    pub request: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PakeStartResult {
    pub response: Value,
    pub server_state: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PakeRegistrationStartRequest {
    pub flow_id: String,
    pub user_id: String,
    pub request: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PakeRegistrationFinishResult {
    pub credential_blob: Vec<u8>,
    pub server_key_ref: Option<String>,
    pub envelope_kms_key_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PakeFinishResult {
    pub session_user_id: String,
    pub session_device_info: Option<String>,
}

#[async_trait]
pub trait PasswordPakeService: Send + Sync {
    async fn start_login(
        &self,
        credential: PakeLoginCredentialView,
        request: PakeStartRequest,
    ) -> Result<PakeStartResult, String>;
    async fn finish_login(
        &self,
        server_state: Value,
        client_message: Value,
    ) -> Result<PakeFinishResult, String>;
    async fn start_registration(
        &self,
        request: PakeRegistrationStartRequest,
    ) -> Result<PakeStartResult, String>;
    async fn finish_registration(
        &self,
        server_state: Value,
        client_message: Value,
    ) -> Result<PakeRegistrationFinishResult, String>;
}

pub trait PasskeyService: Send + Sync {
    fn start_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), String>;
    fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, String>;
    fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), String>;
    fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, String>;
}

#[allow(dead_code)]
#[async_trait]
pub trait AuthMethodDiscoveryService: Send + Sync {
    async fn discover(
        &self,
        request: AuthMethodDiscoveryRequest,
    ) -> Result<AuthMethodDiscoveryResult, String>;
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
