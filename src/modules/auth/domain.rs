use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    PendingVerification,
    Locked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub status: UserStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    PendingVerification,
    Locked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    pub id: String,
    pub email: String,
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyPasswordRecord {
    pub user_id: String,
    pub password_hash: String,
    pub legacy_login_allowed: bool,
    pub migrated_to_opaque_at: Option<DateTime<Utc>>,
    pub last_legacy_verified_at: Option<DateTime<Utc>>,
    pub legacy_deprecation_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpaqueCredentialState {
    Active,
    Superseded,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpaqueCredentialRecord {
    pub user_id: String,
    pub protocol: String,
    pub credential_blob: Vec<u8>,
    pub server_key_ref: Option<String>,
    pub envelope_kms_key_id: Option<String>,
    pub state: OpaqueCredentialState,
    pub migrated_from_legacy_at: Option<DateTime<Utc>>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthFlowKind {
    MethodsDiscovery,
    PasswordLogin,
    RecoveryUpgradeBridge,
    PasswordUpgrade,
    PasskeyLogin,
    PasskeyRegister,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBridgeSource {
    PasswordReset,
    PasswordChange,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryUpgradeBridge {
    pub flow_id: String,
    pub user_id: String,
    pub source: RecoveryBridgeSource,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PasswordUpgradeContext {
    Session,
    RecoveryBridge { flow_id: String },
}

impl PasswordUpgradeContext {
    pub fn session() -> Self {
        Self::Session
    }

    pub fn recovery_bridge(flow_id: impl Into<String>) -> Self {
        Self::RecoveryBridge {
            flow_id: flow_id.into(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::RecoveryBridge { .. } => "recovery_bridge",
        }
    }

    pub fn flow_id(&self) -> Option<&str> {
        match self {
            Self::Session => None,
            Self::RecoveryBridge { flow_id } => Some(flow_id.as_str()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthFlowStatus {
    Pending,
    Consumed,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthFlowRecord {
    pub flow_id: String,
    pub subject_user_id: Option<String>,
    pub subject_identifier_hash: Option<String>,
    pub flow_kind: AuthFlowKind,
    pub protocol: String,
    pub state: serde_json::Value,
    pub status: AuthFlowStatus,
    pub rollout_tenant_id: Option<String>,
    pub rollout_request_channel: Option<String>,
    pub rollout_cohort: Option<String>,
    pub rollout_channel: Option<String>,
    pub fallback_policy: Option<String>,
    pub trace_id: Option<String>,
    pub issued_ip: Option<String>,
    pub issued_user_agent: Option<String>,
    pub attempt_count: u32,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationTokenRecord {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordResetTokenRecord {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaFactorRecord {
    pub user_id: String,
    pub secret_ciphertext: String,
    pub secret_nonce: String,
    pub enabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaChallengeRecord {
    pub id: String,
    pub user_id: String,
    pub challenge_hash: String,
    pub device_info: Option<String>,
    pub failed_attempts: u32,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaBackupCodeRecord {
    pub id: String,
    pub user_id: String,
    pub code_hash: String,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmailTemplate {
    Verification,
    PasswordReset,
}

impl EmailTemplate {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verification => "verification",
            Self::PasswordReset => "password_reset",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "verification" => Some(Self::Verification),
            "password_reset" => Some(Self::PasswordReset),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmailOutboxPayload {
    Verification {
        verification_token: String,
        expires_in_seconds: i64,
    },
    PasswordReset {
        reset_token: String,
        expires_in_seconds: i64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailOutboxMessage {
    pub id: String,
    pub recipient_email: String,
    pub provider: String,
    pub template: EmailTemplate,
    pub payload: EmailOutboxPayload,
    pub attempts: u32,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
