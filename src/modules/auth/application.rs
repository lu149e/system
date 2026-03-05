use std::sync::Arc;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base32::Alphabet;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::Serialize;
use serde_json::json;
use sha1::Sha1;
use thiserror::Error;
use uuid::Uuid;

use crate::modules::{
    audit::{domain::AuditEvent, ports::AuditRepository},
    auth::{
        domain::{
            MfaChallengeRecord, MfaFactorRecord, PasswordResetTokenRecord, UserStatus,
            VerificationTokenRecord,
        },
        ports::{
            LoginAbuseProtector, LoginGateDecision, MfaBackupCodeConsumeState,
            MfaBackupCodeRepository, MfaChallengeFailureState, MfaChallengeLookupState,
            MfaChallengeRepository, MfaFactorRepository, PasswordResetTokenConsumeState,
            PasswordResetTokenRepository, TransactionalEmailSender, UserRepository,
            VerificationTokenConsumeState, VerificationTokenRepository,
        },
    },
    sessions::{
        domain::{Session, SessionStatus},
        ports::SessionRepository,
    },
    tokens::{
        domain::{AccessTokenClaims, RefreshTokenRecord},
        ports::{JwtService, RefreshCryptoService, RefreshRotationState, RefreshTokenRepository},
    },
};

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
pub struct AuthService {
    users: Arc<dyn UserRepository>,
    login_abuse: Arc<dyn LoginAbuseProtector>,
    verification_tokens: Arc<dyn VerificationTokenRepository>,
    password_reset_tokens: Arc<dyn PasswordResetTokenRepository>,
    mfa_factors: Arc<dyn MfaFactorRepository>,
    mfa_challenges: Arc<dyn MfaChallengeRepository>,
    mfa_backup_codes: Arc<dyn MfaBackupCodeRepository>,
    sessions: Arc<dyn SessionRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    audit: Arc<dyn AuditRepository>,
    email_sender: Arc<dyn TransactionalEmailSender>,
    jwt: Arc<dyn JwtService>,
    refresh_crypto: Arc<dyn RefreshCryptoService>,
    access_ttl_seconds: i64,
    refresh_ttl_seconds: i64,
    email_verification_ttl_seconds: i64,
    password_reset_ttl_seconds: i64,
    mfa_challenge_ttl_seconds: i64,
    mfa_challenge_max_attempts: u32,
    mfa_totp_issuer: String,
    mfa_encryption_key: [u8; 32],
    jwt_issuer: String,
    jwt_audience: String,
    dummy_password_hash: Option<String>,
}

#[derive(Clone)]
pub struct RequestContext {
    pub trace_id: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password does not meet policy")]
    WeakPassword,
    #[error("invalid or expired verification token")]
    InvalidVerificationToken,
    #[error("invalid or expired password reset token")]
    InvalidPasswordResetToken,
    #[error("invalid current password")]
    InvalidCurrentPassword,
    #[error("invalid or expired mfa challenge")]
    InvalidMfaChallenge,
    #[error("invalid mfa code")]
    InvalidMfaCode,
    #[error("mfa enrollment not found")]
    MfaEnrollmentNotFound,
    #[error("mfa already enabled")]
    MfaAlreadyEnabled,
    #[error("mfa not enabled")]
    MfaNotEnabled,
    #[error("session not found")]
    SessionNotFound,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account temporarily locked")]
    LoginLocked { retry_after_seconds: i64 },
    #[error("account is not active")]
    AccountNotActive,
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("refresh token reuse detected")]
    RefreshReuseDetected,
    #[error("internal error")]
    Internal,
}

#[derive(Clone)]
pub struct LoginCommand {
    pub email: String,
    pub password: String,
    pub device_info: Option<String>,
}

#[derive(Clone)]
pub struct RegisterCommand {
    pub email: String,
    pub password: String,
}

#[derive(Clone)]
pub struct VerifyEmailCommand {
    pub token: String,
}

#[derive(Clone)]
pub struct PasswordForgotCommand {
    pub email: String,
}

#[derive(Clone)]
pub struct PasswordResetCommand {
    pub token: String,
    pub new_password: String,
}

#[derive(Clone)]
pub struct PasswordChangeCommand {
    pub user_id: String,
    pub current_password: String,
    pub new_password: String,
}

#[derive(Clone)]
pub struct MfaActivateCommand {
    pub user_id: String,
    pub totp_code: String,
}

#[derive(Clone)]
pub struct MfaVerifyCommand {
    pub challenge_id: String,
    pub totp_code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Clone)]
pub struct MfaDisableCommand {
    pub user_id: String,
    pub current_password: String,
    pub totp_code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Clone)]
pub struct RefreshCommand {
    pub refresh_token: String,
}

#[derive(Clone)]
pub struct LogoutCommand {
    pub session_id: String,
    pub user_id: String,
}

#[derive(Clone, Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Clone, Serialize)]
pub struct RegisterAccepted {
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct PasswordForgotAccepted {
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct PasswordResetCompleted {
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct PasswordChangeCompleted {
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct MfaEnrollResponse {
    pub secret: String,
    pub otpauth_url: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

#[derive(Clone, Serialize)]
pub struct MfaActivateCompleted {
    pub backup_codes: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct MfaChallengeRequired {
    pub challenge_id: String,
    pub message: String,
}

#[derive(Clone)]
pub enum LoginResult {
    Authenticated {
        tokens: AuthTokens,
        principal: Principal,
    },
    MfaRequired(MfaChallengeRequired),
}

#[derive(Clone)]
pub struct Principal {
    pub user_id: String,
    pub session_id: String,
}

impl AuthService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        login_abuse: Arc<dyn LoginAbuseProtector>,
        verification_tokens: Arc<dyn VerificationTokenRepository>,
        password_reset_tokens: Arc<dyn PasswordResetTokenRepository>,
        mfa_factors: Arc<dyn MfaFactorRepository>,
        mfa_challenges: Arc<dyn MfaChallengeRepository>,
        mfa_backup_codes: Arc<dyn MfaBackupCodeRepository>,
        sessions: Arc<dyn SessionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        audit: Arc<dyn AuditRepository>,
        email_sender: Arc<dyn TransactionalEmailSender>,
        jwt: Arc<dyn JwtService>,
        refresh_crypto: Arc<dyn RefreshCryptoService>,
        access_ttl_seconds: i64,
        refresh_ttl_seconds: i64,
        email_verification_ttl_seconds: i64,
        password_reset_ttl_seconds: i64,
        mfa_challenge_ttl_seconds: i64,
        mfa_challenge_max_attempts: u32,
        mfa_totp_issuer: String,
        mfa_encryption_key_base64: String,
        jwt_issuer: String,
        jwt_audience: String,
    ) -> anyhow::Result<Self> {
        let raw_key = BASE64_STANDARD
            .decode(mfa_encryption_key_base64.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid MFA encryption key encoding"))?;
        if raw_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "invalid MFA encryption key length: expected 32 bytes"
            ));
        }
        let mfa_encryption_key = <[u8; 32]>::try_from(raw_key.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid MFA encryption key length: expected 32 bytes"))?;

        Ok(Self {
            users,
            login_abuse,
            verification_tokens,
            password_reset_tokens,
            mfa_factors,
            mfa_challenges,
            mfa_backup_codes,
            sessions,
            refresh_tokens,
            audit,
            email_sender,
            jwt,
            refresh_crypto,
            access_ttl_seconds,
            refresh_ttl_seconds,
            email_verification_ttl_seconds,
            password_reset_ttl_seconds,
            mfa_challenge_ttl_seconds,
            mfa_challenge_max_attempts,
            mfa_totp_issuer,
            mfa_encryption_key,
            jwt_issuer,
            jwt_audience,
            dummy_password_hash: build_dummy_password_hash(),
        })
    }

    pub async fn register(
        &self,
        cmd: RegisterCommand,
        ctx: RequestContext,
    ) -> Result<RegisterAccepted, AuthError> {
        let email = cmd.email.to_ascii_lowercase();
        let now = Utc::now();

        if !is_strong_password(&cmd.password) {
            self.audit_register_rejected("weak_password", &email, &ctx, now)
                .await;
            return Err(AuthError::WeakPassword);
        }

        if let Some(existing_user) = self.users.find_by_email(&email).await {
            self.consume_dummy_password_work(&cmd.password);
            if existing_user.status == UserStatus::PendingVerification {
                self.issue_email_verification_token(&existing_user.id, &existing_user.email, &ctx)
                    .await?;
            }
            self.audit_register_accepted(
                &email,
                Some(existing_user.id.as_str()),
                "existing",
                &ctx,
                now,
            )
            .await;
            return Ok(register_accepted_response());
        }

        let password_hash = hash_password(&cmd.password).map_err(|_| AuthError::Internal)?;

        let created_user = self
            .users
            .create_pending_user(&email, &password_hash)
            .await
            .map_err(|_| AuthError::Internal)?;

        if let Some(user) = created_user {
            self.issue_email_verification_token(&user.id, &email, &ctx)
                .await?;
            self.audit_register_accepted(&email, Some(user.id.as_str()), "created", &ctx, now)
                .await;
            return Ok(register_accepted_response());
        }

        self.audit_register_accepted(&email, None, "raced_existing", &ctx, now)
            .await;
        Ok(register_accepted_response())
    }

    pub async fn verify_email(
        &self,
        cmd: VerifyEmailCommand,
        ctx: RequestContext,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let token_hash = self.refresh_crypto.hash_refresh_token(&cmd.token).await;

        let consumed = self
            .verification_tokens
            .consume(&token_hash, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let user_id = match consumed {
            VerificationTokenConsumeState::Consumed { user_id } => user_id,
            VerificationTokenConsumeState::NotFound => {
                self.audit_verify_email_rejected("token_not_found", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidVerificationToken);
            }
            VerificationTokenConsumeState::AlreadyUsed => {
                self.audit_verify_email_rejected("token_already_used", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidVerificationToken);
            }
            VerificationTokenConsumeState::Expired => {
                self.audit_verify_email_rejected("token_expired", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidVerificationToken);
            }
        };

        if self.users.activate_user(&user_id, now).await.is_err() {
            self.audit_verify_email_rejected("user_not_found", Some(user_id.as_str()), &ctx, now)
                .await;
            return Err(AuthError::InvalidVerificationToken);
        }

        self.audit
            .append(AuditEvent {
                event_type: "auth.verify_email.success".to_string(),
                actor_user_id: Some(user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(())
    }

    pub async fn password_forgot(
        &self,
        cmd: PasswordForgotCommand,
        ctx: RequestContext,
    ) -> Result<PasswordForgotAccepted, AuthError> {
        let email = cmd.email.to_ascii_lowercase();
        let now = Utc::now();

        let user = self.users.find_by_email(&email).await;
        if let Some(user) = user {
            self.issue_password_reset_token(&user.id, &user.email, &ctx)
                .await?;
            self.audit_password_forgot_accepted(
                &email,
                Some(user.id.as_str()),
                "existing",
                &ctx,
                now,
            )
            .await;
            return Ok(password_forgot_accepted_response());
        }

        let fake_token = self.refresh_crypto.generate_refresh_token().await;
        let _ = self.refresh_crypto.hash_refresh_token(&fake_token).await;
        self.audit_password_forgot_accepted(&email, None, "unknown", &ctx, now)
            .await;
        Ok(password_forgot_accepted_response())
    }

    pub async fn password_reset(
        &self,
        cmd: PasswordResetCommand,
        ctx: RequestContext,
    ) -> Result<PasswordResetCompleted, AuthError> {
        let now = Utc::now();
        if !is_strong_password(&cmd.new_password) {
            self.audit_password_reset_rejected("weak_password", None, &ctx, now)
                .await;
            return Err(AuthError::WeakPassword);
        }

        let token_hash = self.refresh_crypto.hash_refresh_token(&cmd.token).await;
        let consumed = self
            .password_reset_tokens
            .consume(&token_hash, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let user_id = match consumed {
            PasswordResetTokenConsumeState::Consumed { user_id } => user_id,
            PasswordResetTokenConsumeState::NotFound => {
                self.audit_password_reset_rejected("token_not_found", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidPasswordResetToken);
            }
            PasswordResetTokenConsumeState::AlreadyUsed => {
                self.audit_password_reset_rejected("token_already_used", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidPasswordResetToken);
            }
            PasswordResetTokenConsumeState::Expired => {
                self.audit_password_reset_rejected("token_expired", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidPasswordResetToken);
            }
        };

        let password_hash = hash_password(&cmd.new_password).map_err(|_| AuthError::Internal)?;
        if self
            .users
            .update_password(&user_id, &password_hash, now)
            .await
            .is_err()
        {
            self.audit_password_reset_rejected("user_not_found", Some(user_id.as_str()), &ctx, now)
                .await;
            return Err(AuthError::InvalidPasswordResetToken);
        }

        let session_ids = self.sessions.revoke_all_for_user(&user_id).await;
        self.refresh_tokens
            .revoke_by_session_ids(&session_ids, now)
            .await;

        self.audit
            .append(AuditEvent {
                event_type: "auth.password.reset.success".to_string(),
                actor_user_id: Some(user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"revoked_sessions": session_ids.len(), "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(password_reset_completed_response())
    }

    pub async fn password_change(
        &self,
        cmd: PasswordChangeCommand,
        ctx: RequestContext,
    ) -> Result<PasswordChangeCompleted, AuthError> {
        let now = Utc::now();
        if !is_strong_password(&cmd.new_password) {
            self.audit_password_change_rejected(
                "weak_password",
                Some(cmd.user_id.as_str()),
                &ctx,
                now,
            )
            .await;
            return Err(AuthError::WeakPassword);
        }

        let Some(user) = self.users.find_by_id(&cmd.user_id).await else {
            self.audit_password_change_rejected(
                "user_not_found",
                Some(cmd.user_id.as_str()),
                &ctx,
                now,
            )
            .await;
            return Err(AuthError::InvalidToken);
        };

        let parsed_hash = match PasswordHash::new(&user.password_hash) {
            Ok(parsed_hash) => parsed_hash,
            Err(_) => {
                self.audit_password_change_rejected(
                    "invalid_stored_hash",
                    Some(cmd.user_id.as_str()),
                    &ctx,
                    now,
                )
                .await;
                return Err(AuthError::InvalidCurrentPassword);
            }
        };

        if Argon2::default()
            .verify_password(cmd.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            self.audit_password_change_rejected(
                "invalid_current_password",
                Some(cmd.user_id.as_str()),
                &ctx,
                now,
            )
            .await;
            return Err(AuthError::InvalidCurrentPassword);
        }

        let password_hash = hash_password(&cmd.new_password).map_err(|_| AuthError::Internal)?;
        self.users
            .update_password(&cmd.user_id, &password_hash, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let session_ids = self.sessions.revoke_all_for_user(&cmd.user_id).await;
        self.refresh_tokens
            .revoke_by_session_ids(&session_ids, now)
            .await;

        self.audit
            .append(AuditEvent {
                event_type: "auth.password.change.success".to_string(),
                actor_user_id: Some(cmd.user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"revoked_sessions": session_ids.len(), "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(password_change_completed_response())
    }

    pub async fn mfa_enroll(
        &self,
        user_id: &str,
        ctx: RequestContext,
    ) -> Result<MfaEnrollResponse, AuthError> {
        let now = Utc::now();
        let Some(user) = self.users.find_by_id(user_id).await else {
            self.audit_mfa_enroll_rejected("user_not_found", user_id, &ctx, now)
                .await;
            return Err(AuthError::InvalidToken);
        };

        if let Some(existing_factor) = self.mfa_factors.find_by_user_id(user_id).await {
            if existing_factor.enabled_at.is_some() {
                self.audit_mfa_enroll_rejected("already_enabled", user_id, &ctx, now)
                    .await;
                return Err(AuthError::MfaAlreadyEnabled);
            }
        }

        let secret = generate_totp_secret();
        let (secret_ciphertext, secret_nonce) = self.encrypt_mfa_secret(&secret)?;

        self.mfa_factors
            .upsert(MfaFactorRecord {
                user_id: user_id.to_string(),
                secret_ciphertext,
                secret_nonce,
                enabled_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .map_err(|_| AuthError::Internal)?;

        let otpauth_url = build_totp_uri(&self.mfa_totp_issuer, &user.email, &secret);

        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.enroll.issued".to_string(),
                actor_user_id: Some(user_id.to_string()),
                trace_id: ctx.trace_id,
                metadata: json!({"ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(MfaEnrollResponse {
            secret,
            otpauth_url,
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        })
    }

    pub async fn mfa_activate(
        &self,
        cmd: MfaActivateCommand,
        ctx: RequestContext,
    ) -> Result<MfaActivateCompleted, AuthError> {
        let now = Utc::now();
        let Some(factor) = self.mfa_factors.find_by_user_id(&cmd.user_id).await else {
            self.audit_mfa_activate_rejected("factor_not_found", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::MfaEnrollmentNotFound);
        };

        if factor.enabled_at.is_some() {
            self.audit_mfa_activate_rejected("already_enabled", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::MfaAlreadyEnabled);
        }

        let normalized_totp =
            normalize_totp_code(&cmd.totp_code).ok_or(AuthError::InvalidMfaCode)?;
        let secret = self.decrypt_mfa_secret(&factor.secret_ciphertext, &factor.secret_nonce)?;
        if !verify_totp_code(&secret, &normalized_totp, now) {
            self.audit_mfa_activate_rejected("invalid_totp", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::InvalidMfaCode);
        }

        self.mfa_factors
            .set_enabled_at(&cmd.user_id, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let backup_codes = generate_backup_codes(10);
        let mut backup_code_hashes = Vec::with_capacity(backup_codes.len());
        for backup_code in &backup_codes {
            let normalized_code = normalize_backup_code(backup_code).ok_or(AuthError::Internal)?;
            let code_hash = self
                .refresh_crypto
                .hash_refresh_token(&normalized_code)
                .await;
            backup_code_hashes.push(code_hash);
        }

        self.mfa_backup_codes
            .replace_for_user(&cmd.user_id, &backup_code_hashes, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.activate.success".to_string(),
                actor_user_id: Some(cmd.user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"backup_codes": backup_codes.len(), "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(MfaActivateCompleted { backup_codes })
    }

    pub async fn mfa_verify(
        &self,
        cmd: MfaVerifyCommand,
        ctx: RequestContext,
    ) -> Result<(AuthTokens, Principal), AuthError> {
        let now = Utc::now();

        let challenge_hash = self
            .refresh_crypto
            .hash_refresh_token(&cmd.challenge_id)
            .await;
        let challenge = self
            .mfa_challenges
            .find_active(&challenge_hash, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let (user_id, device_info) = match challenge {
            MfaChallengeLookupState::Active {
                user_id,
                device_info,
            } => (user_id, device_info),
            MfaChallengeLookupState::NotFound
            | MfaChallengeLookupState::AlreadyUsed
            | MfaChallengeLookupState::Expired => {
                self.audit_mfa_verify_rejected("invalid_challenge", None, &ctx, now)
                    .await;
                return Err(AuthError::InvalidMfaChallenge);
            }
        };

        let Some(factor) = self.mfa_factors.find_by_user_id(&user_id).await else {
            self.audit_mfa_verify_rejected("factor_not_found", Some(user_id.as_str()), &ctx, now)
                .await;
            return Err(AuthError::MfaNotEnabled);
        };

        if factor.enabled_at.is_none() {
            self.audit_mfa_verify_rejected("factor_not_enabled", Some(user_id.as_str()), &ctx, now)
                .await;
            return Err(AuthError::MfaNotEnabled);
        }

        let verified = if let Some(totp_code) = cmd.totp_code {
            let normalized_totp =
                normalize_totp_code(&totp_code).ok_or(AuthError::InvalidMfaCode)?;
            let secret =
                self.decrypt_mfa_secret(&factor.secret_ciphertext, &factor.secret_nonce)?;
            verify_totp_code(&secret, &normalized_totp, now)
        } else if let Some(backup_code) = cmd.backup_code {
            let normalized_backup =
                normalize_backup_code(&backup_code).ok_or(AuthError::InvalidMfaCode)?;
            let backup_hash = self
                .refresh_crypto
                .hash_refresh_token(&normalized_backup)
                .await;
            matches!(
                self.mfa_backup_codes
                    .consume(&user_id, &backup_hash, now)
                    .await
                    .map_err(|_| AuthError::Internal)?,
                MfaBackupCodeConsumeState::Consumed
            )
        } else {
            false
        };

        if !verified {
            let failure_state = self
                .mfa_challenges
                .register_failure(&challenge_hash, now, self.mfa_challenge_max_attempts)
                .await
                .map_err(|_| AuthError::Internal)?;

            let rejection_reason = match failure_state {
                MfaChallengeFailureState::RetryAllowed { .. } => "invalid_mfa_code",
                MfaChallengeFailureState::Exhausted => "invalid_mfa_code_exhausted",
                MfaChallengeFailureState::NotFound
                | MfaChallengeFailureState::AlreadyUsed
                | MfaChallengeFailureState::Expired => "invalid_challenge",
            };

            self.audit_mfa_verify_rejected(rejection_reason, Some(user_id.as_str()), &ctx, now)
                .await;
            return match rejection_reason {
                "invalid_challenge" => Err(AuthError::InvalidMfaChallenge),
                _ => Err(AuthError::InvalidMfaCode),
            };
        }

        self.mfa_challenges
            .mark_used(&challenge_hash, now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let (tokens, principal) = self
            .issue_session_tokens(&user_id, device_info, &ctx, now)
            .await?;

        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.verify.success".to_string(),
                actor_user_id: Some(user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"session_id": principal.session_id, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok((tokens, principal))
    }

    pub async fn mfa_disable(
        &self,
        cmd: MfaDisableCommand,
        ctx: RequestContext,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let Some(user) = self.users.find_by_id(&cmd.user_id).await else {
            self.audit_mfa_disable_rejected("user_not_found", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::InvalidToken);
        };

        let parsed_hash =
            PasswordHash::new(&user.password_hash).map_err(|_| AuthError::InvalidToken)?;
        if Argon2::default()
            .verify_password(cmd.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            self.audit_mfa_disable_rejected("invalid_current_password", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::InvalidCurrentPassword);
        }

        let Some(factor) = self.mfa_factors.find_by_user_id(&cmd.user_id).await else {
            self.audit_mfa_disable_rejected("factor_not_found", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::MfaNotEnabled);
        };

        if factor.enabled_at.is_none() {
            self.audit_mfa_disable_rejected("factor_not_enabled", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::MfaNotEnabled);
        }

        let verified = if let Some(totp_code) = cmd.totp_code {
            let normalized_totp =
                normalize_totp_code(&totp_code).ok_or(AuthError::InvalidMfaCode)?;
            let secret =
                self.decrypt_mfa_secret(&factor.secret_ciphertext, &factor.secret_nonce)?;
            verify_totp_code(&secret, &normalized_totp, now)
        } else if let Some(backup_code) = cmd.backup_code {
            let normalized_backup =
                normalize_backup_code(&backup_code).ok_or(AuthError::InvalidMfaCode)?;
            let backup_hash = self
                .refresh_crypto
                .hash_refresh_token(&normalized_backup)
                .await;
            matches!(
                self.mfa_backup_codes
                    .consume(&cmd.user_id, &backup_hash, now)
                    .await
                    .map_err(|_| AuthError::Internal)?,
                MfaBackupCodeConsumeState::Consumed
            )
        } else {
            false
        };

        if !verified {
            self.audit_mfa_disable_rejected("invalid_mfa_code", &cmd.user_id, &ctx, now)
                .await;
            return Err(AuthError::InvalidMfaCode);
        }

        self.mfa_factors
            .delete_for_user(&cmd.user_id)
            .await
            .map_err(|_| AuthError::Internal)?;
        self.mfa_backup_codes
            .replace_for_user(&cmd.user_id, &[], now)
            .await
            .map_err(|_| AuthError::Internal)?;

        let session_ids = self.sessions.revoke_all_for_user(&cmd.user_id).await;
        self.refresh_tokens
            .revoke_by_session_ids(&session_ids, now)
            .await;

        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.disable.success".to_string(),
                actor_user_id: Some(cmd.user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"ip": ctx.ip, "user_agent": ctx.user_agent, "revoked_sessions": session_ids.len()}),
                created_at: now,
            })
            .await;

        Ok(())
    }

    pub async fn login(
        &self,
        cmd: LoginCommand,
        ctx: RequestContext,
    ) -> Result<LoginResult, AuthError> {
        let email = cmd.email.to_ascii_lowercase();
        let now = Utc::now();

        match self.login_abuse.check(&email, ctx.ip.as_deref(), now).await {
            LoginGateDecision::Allowed => {}
            LoginGateDecision::Locked { until } => {
                let retry_after_seconds = (until - now).num_seconds().max(1);
                self.audit_login_locked(&email, &ctx, retry_after_seconds)
                    .await;
                return Err(AuthError::LoginLocked {
                    retry_after_seconds,
                });
            }
        }

        let user = self.users.find_by_email(&email).await;
        if user.is_none() {
            self.consume_dummy_password_work(&cmd.password);
            self.audit_login_failed(&email, &ctx).await;
            self.try_lock_login(&email, ctx.ip.as_deref(), &ctx, now)
                .await;
            return Err(AuthError::InvalidCredentials);
        }
        let user = user.expect("checked is_some");

        let parsed_hash = match PasswordHash::new(&user.password_hash) {
            Ok(parsed_hash) => parsed_hash,
            Err(_) => {
                self.consume_dummy_password_work(&cmd.password);
                self.audit_login_failed(&email, &ctx).await;
                self.try_lock_login(&email, ctx.ip.as_deref(), &ctx, now)
                    .await;
                return Err(AuthError::InvalidCredentials);
            }
        };
        if Argon2::default()
            .verify_password(cmd.password.as_bytes(), &parsed_hash)
            .is_err()
        {
            self.audit_login_failed(&email, &ctx).await;
            self.try_lock_login(&email, ctx.ip.as_deref(), &ctx, now)
                .await;
            return Err(AuthError::InvalidCredentials);
        }

        if user.status != UserStatus::Active {
            self.audit_login_rejected("account_not_active", &email, Some(user.id.as_str()), &ctx)
                .await;
            return Err(AuthError::AccountNotActive);
        }

        self.login_abuse
            .register_success(&email, ctx.ip.as_deref())
            .await;

        if let Some(factor) = self.mfa_factors.find_by_user_id(&user.id).await {
            if factor.enabled_at.is_some() {
                let challenge_id = self.refresh_crypto.generate_refresh_token().await;
                let challenge_hash = self.refresh_crypto.hash_refresh_token(&challenge_id).await;
                self.mfa_challenges
                    .issue(MfaChallengeRecord {
                        id: Uuid::new_v4().to_string(),
                        user_id: user.id.clone(),
                        challenge_hash,
                        device_info: cmd.device_info,
                        failed_attempts: 0,
                        expires_at: now + Duration::seconds(self.mfa_challenge_ttl_seconds),
                        used_at: None,
                        created_at: now,
                    })
                    .await
                    .map_err(|_| AuthError::Internal)?;

                self.audit
                    .append(AuditEvent {
                        event_type: "auth.mfa.challenge.issued".to_string(),
                        actor_user_id: Some(user.id),
                        trace_id: ctx.trace_id,
                        metadata: json!({"ip": ctx.ip, "user_agent": ctx.user_agent}),
                        created_at: now,
                    })
                    .await;

                return Ok(LoginResult::MfaRequired(MfaChallengeRequired {
                    challenge_id,
                    message: "Multi-factor authentication required".to_string(),
                }));
            }
        }

        let (tokens, principal) = self
            .issue_session_tokens(&user.id, cmd.device_info, &ctx, now)
            .await?;

        self.audit
            .append(AuditEvent {
                event_type: "auth.login.success".to_string(),
                actor_user_id: Some(user.id),
                trace_id: ctx.trace_id,
                metadata: json!({"session_id": principal.session_id, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(LoginResult::Authenticated { tokens, principal })
    }

    async fn issue_session_tokens(
        &self,
        user_id: &str,
        device_info: Option<String>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) -> Result<(AuthTokens, Principal), AuthError> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            device_info,
            ip: ctx.ip.clone(),
            status: SessionStatus::Active,
            created_at: now,
            last_seen_at: now,
        };
        self.sessions.create(session.clone()).await;

        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            sid: session.id.clone(),
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(self.access_ttl_seconds)).timestamp(),
        };

        let access_token = self
            .jwt
            .issue_access_token(&claims)
            .await
            .map_err(|_| AuthError::Internal)?;
        let refresh_token = self.refresh_crypto.generate_refresh_token().await;
        let refresh_hash = self.refresh_crypto.hash_refresh_token(&refresh_token).await;

        let refresh_record = RefreshTokenRecord {
            id: Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            token_hash: refresh_hash,
            expires_at: now + Duration::seconds(self.refresh_ttl_seconds),
            revoked_at: None,
            replaced_by: None,
            created_at: now,
        };
        self.refresh_tokens.insert(refresh_record).await;

        Ok((
            AuthTokens {
                access_token,
                refresh_token,
                token_type: "Bearer".to_string(),
                expires_in: self.access_ttl_seconds,
            },
            Principal {
                user_id: user_id.to_string(),
                session_id: session.id,
            },
        ))
    }

    fn encrypt_mfa_secret(&self, plaintext: &str) -> Result<(String, String), AuthError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.mfa_encryption_key).map_err(|_| AuthError::Internal)?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| AuthError::Internal)?;

        Ok((
            BASE64_STANDARD.encode(ciphertext),
            BASE64_STANDARD.encode(nonce_bytes),
        ))
    }

    fn decrypt_mfa_secret(
        &self,
        ciphertext_b64: &str,
        nonce_b64: &str,
    ) -> Result<String, AuthError> {
        let nonce = BASE64_STANDARD
            .decode(nonce_b64.as_bytes())
            .map_err(|_| AuthError::Internal)?;
        if nonce.len() != 12 {
            return Err(AuthError::Internal);
        }
        let ciphertext = BASE64_STANDARD
            .decode(ciphertext_b64.as_bytes())
            .map_err(|_| AuthError::Internal)?;

        let cipher =
            Aes256Gcm::new_from_slice(&self.mfa_encryption_key).map_err(|_| AuthError::Internal)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| AuthError::Internal)?;

        String::from_utf8(plaintext).map_err(|_| AuthError::Internal)
    }

    fn consume_dummy_password_work(&self, password: &str) {
        let Some(dummy_password_hash) = self.dummy_password_hash.as_deref() else {
            return;
        };
        let Ok(parsed_hash) = PasswordHash::new(dummy_password_hash) else {
            return;
        };

        let _ = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);
    }

    async fn issue_email_verification_token(
        &self,
        user_id: &str,
        recipient_email: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let verification_token = self.refresh_crypto.generate_refresh_token().await;
        let verification_token_hash = self
            .refresh_crypto
            .hash_refresh_token(&verification_token)
            .await;

        self.verification_tokens
            .issue(VerificationTokenRecord {
                id: Uuid::new_v4().to_string(),
                user_id: user_id.to_string(),
                token_hash: verification_token_hash,
                expires_at: now + Duration::seconds(self.email_verification_ttl_seconds),
                used_at: None,
                created_at: now,
            })
            .await
            .map_err(|_| AuthError::Internal)?;

        if let Err(error) = self
            .email_sender
            .send_verification_email(
                recipient_email,
                &verification_token,
                self.email_verification_ttl_seconds,
            )
            .await
        {
            tracing::warn!(user_id = %user_id, error = %error, "verification email delivery failed");
        }

        self.audit
            .append(AuditEvent {
                event_type: "auth.verify_email.token_issued".to_string(),
                actor_user_id: Some(user_id.to_string()),
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(())
    }

    async fn issue_password_reset_token(
        &self,
        user_id: &str,
        recipient_email: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let reset_token = self.refresh_crypto.generate_refresh_token().await;
        let reset_token_hash = self.refresh_crypto.hash_refresh_token(&reset_token).await;

        self.password_reset_tokens
            .issue(PasswordResetTokenRecord {
                id: Uuid::new_v4().to_string(),
                user_id: user_id.to_string(),
                token_hash: reset_token_hash,
                expires_at: now + Duration::seconds(self.password_reset_ttl_seconds),
                used_at: None,
                created_at: now,
            })
            .await
            .map_err(|_| AuthError::Internal)?;

        if let Err(error) = self
            .email_sender
            .send_password_reset_email(
                recipient_email,
                &reset_token,
                self.password_reset_ttl_seconds,
            )
            .await
        {
            tracing::warn!(user_id = %user_id, error = %error, "password reset email delivery failed");
        }

        self.audit
            .append(AuditEvent {
                event_type: "auth.password.forgot.token_issued".to_string(),
                actor_user_id: Some(user_id.to_string()),
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(())
    }

    pub async fn refresh(
        &self,
        cmd: RefreshCommand,
        ctx: RequestContext,
    ) -> Result<(AuthTokens, Principal), AuthError> {
        let now = Utc::now();
        let current_hash = self
            .refresh_crypto
            .hash_refresh_token(&cmd.refresh_token)
            .await;

        let current = self.refresh_tokens.find_by_hash(&current_hash).await;
        if current.is_none() {
            self.audit_refresh_rejected("token_not_found", None, None, &ctx, now)
                .await;
            return Err(AuthError::InvalidToken);
        }
        let current = current.expect("checked is_some");

        let session = self.sessions.find_by_id(&current.session_id).await;
        if session.is_none() {
            self.audit_refresh_rejected(
                "session_not_found",
                None,
                Some(current.session_id.as_str()),
                &ctx,
                now,
            )
            .await;
            return Err(AuthError::InvalidToken);
        }
        let session = session.expect("checked is_some");

        if session.status != SessionStatus::Active {
            self.audit_refresh_rejected(
                "session_not_active",
                Some(session.user_id.as_str()),
                Some(session.id.as_str()),
                &ctx,
                now,
            )
            .await;
            return Err(AuthError::InvalidToken);
        }

        let user = self.users.find_by_id(&session.user_id).await;
        if user.is_none() {
            self.audit_refresh_rejected(
                "user_not_found",
                Some(session.user_id.as_str()),
                Some(session.id.as_str()),
                &ctx,
                now,
            )
            .await;
            return Err(AuthError::InvalidToken);
        }
        let user = user.expect("checked is_some");

        let claims = AccessTokenClaims {
            sub: user.id.clone(),
            sid: session.id.clone(),
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(self.access_ttl_seconds)).timestamp(),
        };
        let access_token = self
            .jwt
            .issue_access_token(&claims)
            .await
            .map_err(|_| AuthError::Internal)?;

        let next_refresh = self.refresh_crypto.generate_refresh_token().await;
        let next_hash = self.refresh_crypto.hash_refresh_token(&next_refresh).await;

        let next_record = RefreshTokenRecord {
            id: Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            token_hash: next_hash.clone(),
            expires_at: now + Duration::seconds(self.refresh_ttl_seconds),
            revoked_at: None,
            replaced_by: None,
            created_at: now,
        };
        let rotation_state = self
            .refresh_tokens
            .rotate_strong(&current_hash, next_record, now)
            .await;
        let rotation_state = match rotation_state {
            Ok(state) => state,
            Err(_) => {
                self.audit_refresh_rejected(
                    "token_rotation_error",
                    Some(session.user_id.as_str()),
                    Some(session.id.as_str()),
                    &ctx,
                    now,
                )
                .await;
                return Err(AuthError::Internal);
            }
        };

        match rotation_state {
            RefreshRotationState::Rotated => {}
            RefreshRotationState::NotFound => {
                self.audit_refresh_rejected(
                    "token_not_found_during_rotation",
                    Some(session.user_id.as_str()),
                    Some(session.id.as_str()),
                    &ctx,
                    now,
                )
                .await;
                return Err(AuthError::InvalidToken);
            }
            RefreshRotationState::AlreadyRevoked => {
                let session_ids = self
                    .sessions
                    .mark_compromised_and_revoke_all_for_user(&session.user_id)
                    .await;
                self.refresh_tokens
                    .revoke_by_session_ids(&session_ids, now)
                    .await;

                self.audit
                    .append(AuditEvent {
                        event_type: "auth.refresh.reuse_detected".to_string(),
                        actor_user_id: Some(session.user_id.clone()),
                        trace_id: ctx.trace_id,
                        metadata: json!({"session_id": session.id, "reason": "token_revoked_or_reused"}),
                        created_at: now,
                    })
                    .await;
                return Err(AuthError::RefreshReuseDetected);
            }
            RefreshRotationState::Expired => {
                self.refresh_tokens
                    .revoke_by_session_ids(std::slice::from_ref(&session.id), now)
                    .await;
                self.audit_refresh_rejected(
                    "token_expired",
                    Some(session.user_id.as_str()),
                    Some(session.id.as_str()),
                    &ctx,
                    now,
                )
                .await;
                return Err(AuthError::TokenExpired);
            }
        }

        self.audit
            .append(AuditEvent {
                event_type: "auth.refresh.success".to_string(),
                actor_user_id: Some(user.id.clone()),
                trace_id: ctx.trace_id,
                metadata: json!({"session_id": session.id}),
                created_at: now,
            })
            .await;

        Ok((
            AuthTokens {
                access_token,
                refresh_token: next_refresh,
                token_type: "Bearer".to_string(),
                expires_in: self.access_ttl_seconds,
            },
            Principal {
                user_id: user.id,
                session_id: session.id,
            },
        ))
    }

    pub async fn logout(&self, cmd: LogoutCommand, ctx: RequestContext) {
        let now = Utc::now();
        self.sessions.revoke_session(&cmd.session_id).await;
        self.refresh_tokens
            .revoke_by_session_ids(std::slice::from_ref(&cmd.session_id), now)
            .await;
        self.audit
            .append(AuditEvent {
                event_type: "auth.logout".to_string(),
                actor_user_id: Some(cmd.user_id),
                trace_id: ctx.trace_id,
                metadata: json!({"session_id": cmd.session_id}),
                created_at: now,
            })
            .await;
    }

    pub async fn logout_all(&self, user_id: &str, ctx: RequestContext) {
        let now = Utc::now();
        let session_ids = self.sessions.revoke_all_for_user(user_id).await;
        self.refresh_tokens
            .revoke_by_session_ids(&session_ids, now)
            .await;

        self.audit
            .append(AuditEvent {
                event_type: "auth.logout_all".to_string(),
                actor_user_id: Some(user_id.to_string()),
                trace_id: ctx.trace_id,
                metadata: json!({"revoked_sessions": session_ids.len()}),
                created_at: now,
            })
            .await;
    }

    pub async fn list_active_sessions(&self, user_id: &str) -> Vec<Session> {
        self.sessions.list_active_for_user(user_id).await
    }

    pub async fn revoke_session_by_id(
        &self,
        user_id: &str,
        session_id: &str,
        ctx: RequestContext,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let Some(session) = self.sessions.find_by_id(session_id).await else {
            self.audit_session_revoke_rejected("session_not_found", user_id, session_id, &ctx, now)
                .await;
            return Err(AuthError::SessionNotFound);
        };

        if session.user_id != user_id {
            self.audit_session_revoke_rejected("session_not_owned", user_id, session_id, &ctx, now)
                .await;
            return Err(AuthError::SessionNotFound);
        }

        self.sessions.revoke_session(session_id).await;
        self.refresh_tokens
            .revoke_by_session_ids(std::slice::from_ref(&session.id), now)
            .await;

        self.audit
            .append(AuditEvent {
                event_type: "auth.sessions.revoke".to_string(),
                actor_user_id: Some(user_id.to_string()),
                trace_id: ctx.trace_id,
                metadata: json!({"session_id": session_id, "status_before": session_status_label(&session.status), "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;

        Ok(())
    }

    pub async fn authenticate_access_token(&self, token: &str) -> Result<Principal, AuthError> {
        let claims = self
            .jwt
            .validate_access_token(token)
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let session = self.sessions.find_by_id(&claims.sid).await;
        if session.is_none() {
            return Err(AuthError::InvalidToken);
        }
        let session = session.expect("checked is_some");
        if session.status != SessionStatus::Active {
            return Err(AuthError::InvalidToken);
        }

        Ok(Principal {
            user_id: claims.sub,
            session_id: claims.sid,
        })
    }

    async fn audit_register_rejected(
        &self,
        reason: &str,
        email: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.register.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "email": email, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_register_accepted(
        &self,
        email: &str,
        _actor_user_id: Option<&str>,
        outcome: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.register.accepted".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"email": email, "outcome": outcome, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_verify_email_rejected(
        &self,
        reason: &str,
        _actor_user_id: Option<&str>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.verify_email.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_password_forgot_accepted(
        &self,
        email: &str,
        _actor_user_id: Option<&str>,
        outcome: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.password.forgot.accepted".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"email": email, "outcome": outcome, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_password_reset_rejected(
        &self,
        reason: &str,
        _actor_user_id: Option<&str>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.password.reset.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_password_change_rejected(
        &self,
        reason: &str,
        _actor_user_id: Option<&str>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.password.change.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_session_revoke_rejected(
        &self,
        reason: &str,
        actor_user_id: &str,
        session_id: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.sessions.revoke.rejected".to_string(),
                actor_user_id: Some(actor_user_id.to_string()),
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "session_id": session_id, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_mfa_enroll_rejected(
        &self,
        reason: &str,
        actor_user_id: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.enroll.rejected".to_string(),
                actor_user_id: Some(actor_user_id.to_string()),
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_mfa_activate_rejected(
        &self,
        reason: &str,
        actor_user_id: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.activate.rejected".to_string(),
                actor_user_id: Some(actor_user_id.to_string()),
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_mfa_verify_rejected(
        &self,
        reason: &str,
        _actor_user_id: Option<&str>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.verify.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_mfa_disable_rejected(
        &self,
        reason: &str,
        actor_user_id: &str,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.mfa.disable.rejected".to_string(),
                actor_user_id: Some(actor_user_id.to_string()),
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }

    async fn audit_login_failed(&self, email: &str, ctx: &RequestContext) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.login.failed".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"email": email, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: Utc::now(),
            })
            .await;
    }

    async fn audit_login_rejected(
        &self,
        reason: &str,
        email: &str,
        _actor_user_id: Option<&str>,
        ctx: &RequestContext,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.login.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "email": email, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: Utc::now(),
            })
            .await;
    }

    async fn try_lock_login(
        &self,
        email: &str,
        source_ip: Option<&str>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        if let Some(lock_until) = self
            .login_abuse
            .register_failure(email, source_ip, now)
            .await
        {
            let retry_after_seconds = (lock_until - now).num_seconds().max(1);
            self.audit_login_locked(email, ctx, retry_after_seconds)
                .await;
        }
    }

    async fn audit_login_locked(
        &self,
        email: &str,
        ctx: &RequestContext,
        retry_after_seconds: i64,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.login.locked".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"email": email, "ip": ctx.ip, "user_agent": ctx.user_agent, "retry_after_seconds": retry_after_seconds}),
                created_at: Utc::now(),
            })
            .await;
    }

    async fn audit_refresh_rejected(
        &self,
        reason: &str,
        _actor_user_id: Option<&str>,
        session_id: Option<&str>,
        ctx: &RequestContext,
        now: chrono::DateTime<Utc>,
    ) {
        self.audit
            .append(AuditEvent {
                event_type: "auth.refresh.rejected".to_string(),
                actor_user_id: None,
                trace_id: ctx.trace_id.clone(),
                metadata: json!({"reason": reason, "session_id": session_id, "ip": ctx.ip, "user_agent": ctx.user_agent}),
                created_at: now,
            })
            .await;
    }
}

fn register_accepted_response() -> RegisterAccepted {
    RegisterAccepted {
        message: "If the email is eligible, verification instructions will be sent".to_string(),
    }
}

fn password_forgot_accepted_response() -> PasswordForgotAccepted {
    PasswordForgotAccepted {
        message: "If the account exists, reset instructions will be sent".to_string(),
    }
}

fn password_reset_completed_response() -> PasswordResetCompleted {
    PasswordResetCompleted {
        message: "Password has been reset".to_string(),
    }
}

fn password_change_completed_response() -> PasswordChangeCompleted {
    PasswordChangeCompleted {
        message: "Password has been changed".to_string(),
    }
}

fn session_status_label(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active => "active",
        SessionStatus::Revoked => "revoked",
        SessionStatus::Compromised => "compromised",
    }
}

fn generate_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    base32::encode(Alphabet::RFC4648 { padding: false }, &bytes)
}

fn build_totp_uri(issuer: &str, email: &str, secret: &str) -> String {
    let encoded_issuer = urlencoding::encode(issuer);
    let label = format!("{}:{}", issuer, email);
    let encoded_label = urlencoding::encode(&label);
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        encoded_label, secret, encoded_issuer
    )
}

fn normalize_totp_code(input: &str) -> Option<String> {
    let normalized: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
    if normalized.len() != 6 || !normalized.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(normalized)
}

fn verify_totp_code(secret_base32: &str, provided_code: &str, now: chrono::DateTime<Utc>) -> bool {
    let Some(secret) = base32::decode(Alphabet::RFC4648 { padding: false }, secret_base32) else {
        return false;
    };

    let current_step = now.timestamp() / 30;
    for step_offset in [-1_i64, 0, 1] {
        let step = current_step + step_offset;
        if step < 0 {
            continue;
        }

        if let Some(expected_code) = totp_code_for_step(&secret, step as u64) {
            if expected_code == provided_code {
                return true;
            }
        }
    }

    false
}

fn totp_code_for_step(secret: &[u8], step: u64) -> Option<String> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).ok()?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0f) as usize;
    if offset + 3 >= digest.len() {
        return None;
    }

    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let code = binary % 1_000_000;

    Some(format!("{code:06}"))
}

fn generate_backup_codes(count: usize) -> Vec<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let mut rng = OsRng;
    let mut codes = Vec::with_capacity(count);

    for _ in 0..count {
        let mut code = String::with_capacity(9);
        for idx in 0..8 {
            if idx == 4 {
                code.push('-');
            }
            let ch = ALPHABET[rng.gen_range(0..ALPHABET.len())] as char;
            code.push(ch);
        }
        codes.push(code);
    }

    codes
}

fn normalize_backup_code(input: &str) -> Option<String> {
    let normalized: String = input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();

    if normalized.len() != 8 {
        return None;
    }

    Some(normalized)
}

fn is_strong_password(password: &str) -> bool {
    if password.len() < 12 {
        return false;
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for ch in password.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch.is_ascii_punctuation() {
            has_symbol = true;
        }
    }

    has_upper && has_lower && has_digit && has_symbol
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "password hash failed".to_string())
        .map(|hash| hash.to_string())
}

fn build_dummy_password_hash() -> Option<String> {
    let salt = SaltString::encode_b64(b"auth_timing_salt_2026").ok()?;
    Argon2::default()
        .hash_password(b"auth_timing_password", &salt)
        .ok()
        .map(|hash| hash.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use chrono::{DateTime, Utc};
    use rand::{rngs::OsRng, RngCore};
    use uuid::Uuid;

    use crate::{
        adapters::inmemory::{
            InMemoryAdapters, InMemoryAuditRepository, JwtEdDsaService, RefreshCryptoHmacService,
        },
        config::{AppConfig, AuthRuntime, LoginAbuseBucketMode, LoginAbuseRedisFailMode},
        modules::{
            auth::ports::UserRepository,
            tokens::{domain::RefreshTokenRecord, ports::RefreshRotationState},
        },
    };

    use super::{
        AuthError, AuthService, LoginCommand, LoginResult, MfaActivateCommand, MfaVerifyCommand,
        PasswordChangeCommand, RefreshCommand, RequestContext,
    };

    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIMn3Wcxxd4JzzjbshVFXz8jSGuF9ErqngPTzYhbfm6hd\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdIROjbNDN9NHACJMCdMbdRjmUZp05u0E+QVRzrqB6eM=\n-----END PUBLIC KEY-----\n";

    struct TestHarness {
        service: AuthService,
        users: Arc<dyn UserRepository>,
        audit: Arc<InMemoryAuditRepository>,
        bootstrap_email: String,
        bootstrap_password: String,
    }

    struct FailOnceRotateRefreshTokenRepository {
        inner: Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>,
        fail_next_rotation: Mutex<bool>,
    }

    impl FailOnceRotateRefreshTokenRepository {
        fn new(inner: Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>) -> Self {
            Self {
                inner,
                fail_next_rotation: Mutex::new(true),
            }
        }
    }

    #[async_trait]
    impl crate::modules::tokens::ports::RefreshTokenRepository
        for FailOnceRotateRefreshTokenRepository
    {
        async fn insert(&self, token: RefreshTokenRecord) {
            self.inner.insert(token).await;
        }

        async fn find_by_hash(&self, token_hash: &str) -> Option<RefreshTokenRecord> {
            self.inner.find_by_hash(token_hash).await
        }

        async fn rotate_strong(
            &self,
            current_hash: &str,
            next_token: RefreshTokenRecord,
            now: DateTime<Utc>,
        ) -> Result<RefreshRotationState, String> {
            let fail_now = {
                let mut should_fail = self
                    .fail_next_rotation
                    .lock()
                    .map_err(|_| "test lock unavailable".to_string())?;
                let fail_now = *should_fail;
                if *should_fail {
                    *should_fail = false;
                }
                fail_now
            };

            if fail_now {
                return Err("forced refresh rotation failure".to_string());
            }

            self.inner
                .rotate_strong(current_hash, next_token, now)
                .await
        }

        async fn rotate(
            &self,
            current_hash: &str,
            next_token: RefreshTokenRecord,
            revoked_at: DateTime<Utc>,
        ) -> Result<(), String> {
            self.inner
                .rotate(current_hash, next_token, revoked_at)
                .await
        }

        async fn revoke_by_session_ids(&self, session_ids: &[String], revoked_at: DateTime<Utc>) {
            self.inner
                .revoke_by_session_ids(session_ids, revoked_at)
                .await;
        }
    }

    struct AlwaysFailRotateRefreshTokenRepository {
        inner: Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>,
    }

    impl AlwaysFailRotateRefreshTokenRepository {
        fn new(inner: Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>) -> Self {
            Self { inner }
        }
    }

    #[async_trait]
    impl crate::modules::tokens::ports::RefreshTokenRepository
        for AlwaysFailRotateRefreshTokenRepository
    {
        async fn insert(&self, token: RefreshTokenRecord) {
            self.inner.insert(token).await;
        }

        async fn find_by_hash(&self, token_hash: &str) -> Option<RefreshTokenRecord> {
            self.inner.find_by_hash(token_hash).await
        }

        async fn rotate_strong(
            &self,
            _current_hash: &str,
            _next_token: RefreshTokenRecord,
            _now: DateTime<Utc>,
        ) -> Result<RefreshRotationState, String> {
            Err("forced persistent refresh rotation failure".to_string())
        }

        async fn rotate(
            &self,
            current_hash: &str,
            next_token: RefreshTokenRecord,
            revoked_at: DateTime<Utc>,
        ) -> Result<(), String> {
            self.inner
                .rotate(current_hash, next_token, revoked_at)
                .await
        }

        async fn revoke_by_session_ids(&self, session_ids: &[String], revoked_at: DateTime<Utc>) {
            self.inner
                .revoke_by_session_ids(session_ids, revoked_at)
                .await;
        }
    }

    #[tokio::test]
    async fn password_change_revokes_sessions_and_replaces_credentials() {
        let harness = build_harness();
        let wrong_current_password = generated_test_password();
        let next_password = generated_test_password();

        let login_initial = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("test-device-1".to_string()),
                },
                test_context("login-initial"),
            )
            .await
            .expect("bootstrap login should succeed");
        let (tokens, principal) = assert_authenticated(login_initial);

        let wrong_current = harness
            .service
            .password_change(
                PasswordChangeCommand {
                    user_id: principal.user_id.clone(),
                    current_password: wrong_current_password,
                    new_password: next_password.clone(),
                },
                test_context("password-change-wrong-current"),
            )
            .await;
        assert!(matches!(
            wrong_current,
            Err(AuthError::InvalidCurrentPassword)
        ));

        harness
            .service
            .password_change(
                PasswordChangeCommand {
                    user_id: principal.user_id.clone(),
                    current_password: harness.bootstrap_password.clone(),
                    new_password: next_password.clone(),
                },
                test_context("password-change-success"),
            )
            .await
            .expect("password change should succeed");

        let stale_access_result = harness
            .service
            .authenticate_access_token(&tokens.access_token)
            .await;
        assert!(matches!(stale_access_result, Err(AuthError::InvalidToken)));

        let old_password_login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("test-device-2".to_string()),
                },
                test_context("login-old-password"),
            )
            .await;
        assert!(matches!(
            old_password_login,
            Err(AuthError::InvalidCredentials)
        ));

        let new_login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: next_password,
                    device_info: Some("test-device-3".to_string()),
                },
                test_context("login-new-password"),
            )
            .await
            .expect("login with new password should succeed");
        let _ = assert_authenticated(new_login);
    }

    #[tokio::test]
    async fn session_revoke_enforces_ownership_and_filters_active_sessions() {
        let harness = build_harness();

        let login_primary = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("primary-device".to_string()),
                },
                test_context("login-primary"),
            )
            .await
            .expect("primary login should succeed");
        let (_tokens1, principal1) = assert_authenticated(login_primary);

        let login_secondary = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("secondary-device".to_string()),
                },
                test_context("login-secondary"),
            )
            .await
            .expect("secondary login should succeed");
        let (_tokens2, principal2) = assert_authenticated(login_secondary);

        let active_before = harness
            .service
            .list_active_sessions(&principal1.user_id)
            .await;
        assert_eq!(active_before.len(), 2);

        harness
            .service
            .revoke_session_by_id(
                &principal1.user_id,
                &principal2.session_id,
                test_context("revoke-own-session"),
            )
            .await
            .expect("owner should be able to revoke own session");

        let active_after = harness
            .service
            .list_active_sessions(&principal1.user_id)
            .await;
        assert_eq!(active_after.len(), 1);
        assert_eq!(active_after[0].id, principal1.session_id);

        let other_email = "other@example.com";
        let other_password = generated_test_password();
        let other_hash = super::hash_password(&other_password).expect("hashing should work");
        let other_user = harness
            .users
            .create_pending_user(other_email, &other_hash)
            .await
            .expect("other user creation should succeed")
            .expect("other user should be inserted");
        harness
            .users
            .activate_user(&other_user.id, Utc::now())
            .await
            .expect("other user activation should succeed");

        let login_other = harness
            .service
            .login(
                LoginCommand {
                    email: other_email.to_string(),
                    password: other_password,
                    device_info: Some("other-device".to_string()),
                },
                test_context("login-other-user"),
            )
            .await
            .expect("other user login should succeed");
        let (_other_tokens, other_principal) = assert_authenticated(login_other);

        let cross_user_revoke = harness
            .service
            .revoke_session_by_id(
                &principal1.user_id,
                &other_principal.session_id,
                test_context("cross-user-revoke"),
            )
            .await;
        assert!(matches!(cross_user_revoke, Err(AuthError::SessionNotFound)));
    }

    #[tokio::test]
    async fn refresh_reuse_detection_revokes_session_family() {
        let harness = build_harness();

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("refresh-reuse-device".to_string()),
                },
                test_context("refresh-reuse-login"),
            )
            .await
            .expect("login should succeed");
        let (initial_tokens, _principal) = assert_authenticated(login);

        let (rotated_tokens, _rotated_principal) = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: initial_tokens.refresh_token.clone(),
                },
                test_context("refresh-rotate-initial"),
            )
            .await
            .expect("initial refresh rotation should succeed");

        let replay_attempt = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: initial_tokens.refresh_token,
                },
                test_context("refresh-replay-detected"),
            )
            .await;
        assert!(matches!(
            replay_attempt,
            Err(AuthError::RefreshReuseDetected)
        ));

        let access_after_replay = harness
            .service
            .authenticate_access_token(&rotated_tokens.access_token)
            .await;
        assert!(matches!(access_after_replay, Err(AuthError::InvalidToken)));

        let rotated_refresh_after_replay = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: rotated_tokens.refresh_token,
                },
                test_context("refresh-after-replay"),
            )
            .await;
        assert!(matches!(
            rotated_refresh_after_replay,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn concurrent_refresh_on_same_token_detects_reuse() {
        let harness = build_harness();

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("refresh-concurrency-device".to_string()),
                },
                test_context("refresh-concurrency-login"),
            )
            .await
            .expect("login should succeed");
        let (initial_tokens, _principal) = assert_authenticated(login);

        let refresh_token_a = initial_tokens.refresh_token.clone();
        let refresh_token_b = initial_tokens.refresh_token;

        let (result_a, result_b) = tokio::join!(
            harness.service.refresh(
                RefreshCommand {
                    refresh_token: refresh_token_a,
                },
                test_context("refresh-concurrency-a"),
            ),
            harness.service.refresh(
                RefreshCommand {
                    refresh_token: refresh_token_b,
                },
                test_context("refresh-concurrency-b"),
            )
        );

        let mut successful_tokens = None;
        let mut reuse_detected = 0;

        for result in [result_a, result_b] {
            match result {
                Ok((tokens, _principal)) => successful_tokens = Some(tokens),
                Err(AuthError::RefreshReuseDetected) => reuse_detected += 1,
                Err(other) => panic!("unexpected refresh outcome: {other:?}"),
            }
        }

        assert_eq!(reuse_detected, 1);
        let successful_tokens = successful_tokens.expect("one refresh should rotate successfully");

        let access_after_concurrency = harness
            .service
            .authenticate_access_token(&successful_tokens.access_token)
            .await;
        assert!(matches!(
            access_after_concurrency,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn refresh_rotation_storage_failure_returns_internal_and_emits_audit() {
        let harness = build_harness_with_refresh_factory(|base_refresh| {
            Arc::new(FailOnceRotateRefreshTokenRepository::new(base_refresh))
                as Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>
        });

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("refresh-storage-failure-device".to_string()),
                },
                test_context("refresh-storage-failure-login"),
            )
            .await
            .expect("login should succeed");
        let (initial_tokens, _principal) = assert_authenticated(login);

        let first_refresh = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: initial_tokens.refresh_token.clone(),
                },
                test_context("refresh-storage-failure-first"),
            )
            .await;
        assert!(matches!(first_refresh, Err(AuthError::Internal)));

        let second_refresh = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: initial_tokens.refresh_token,
                },
                test_context("refresh-storage-failure-second"),
            )
            .await;
        assert!(second_refresh.is_ok());

        let audit_events = harness
            .audit
            .events
            .lock()
            .expect("audit storage should be available");
        let refresh_rejection = audit_events
            .iter()
            .find(|event| {
                event.event_type == "auth.refresh.rejected"
                    && event.trace_id == "refresh-storage-failure-first"
            })
            .expect("refresh rejection audit should be recorded");

        assert_eq!(
            refresh_rejection
                .metadata
                .get("reason")
                .and_then(|value| value.as_str()),
            Some("token_rotation_error")
        );
    }

    #[tokio::test]
    async fn refresh_rotation_persistent_failure_emits_rejection_audit_per_attempt() {
        let harness = build_harness_with_refresh_factory(|base_refresh| {
            Arc::new(AlwaysFailRotateRefreshTokenRepository::new(base_refresh))
                as Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>
        });

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("refresh-persistent-failure-device".to_string()),
                },
                test_context("refresh-persistent-failure-login"),
            )
            .await
            .expect("login should succeed");
        let (initial_tokens, _principal) = assert_authenticated(login);

        let first_attempt = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: initial_tokens.refresh_token.clone(),
                },
                test_context("refresh-persistent-failure-first"),
            )
            .await;
        assert!(matches!(first_attempt, Err(AuthError::Internal)));

        let second_attempt = harness
            .service
            .refresh(
                RefreshCommand {
                    refresh_token: initial_tokens.refresh_token,
                },
                test_context("refresh-persistent-failure-second"),
            )
            .await;
        assert!(matches!(second_attempt, Err(AuthError::Internal)));

        let audit_events = harness
            .audit
            .events
            .lock()
            .expect("audit storage should be available");
        let rotation_error_events: Vec<_> = audit_events
            .iter()
            .filter(|event| {
                event.event_type == "auth.refresh.rejected"
                    && event
                        .metadata
                        .get("reason")
                        .and_then(|value| value.as_str())
                        == Some("token_rotation_error")
            })
            .collect();

        assert!(rotation_error_events
            .iter()
            .any(|event| event.trace_id == "refresh-persistent-failure-first"));
        assert!(rotation_error_events
            .iter()
            .any(|event| event.trace_id == "refresh-persistent-failure-second"));
    }

    #[tokio::test]
    async fn mfa_totp_flow_requires_challenge_and_verifies_successfully() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll"))
            .await
            .expect("mfa enroll should succeed");
        let activate_code = current_totp_code(&enroll.secret);
        harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id.clone(),
                    totp_code: activate_code,
                },
                test_context("mfa-activate"),
            )
            .await
            .expect("mfa activation should succeed");

        let login_result = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("mfa-device".to_string()),
                },
                test_context("mfa-login"),
            )
            .await
            .expect("login should return mfa challenge");

        let challenge_id = match login_result {
            LoginResult::MfaRequired(challenge) => challenge.challenge_id,
            LoginResult::Authenticated { .. } => panic!("mfa challenge should be required"),
        };

        let verify_code = current_totp_code(&enroll.secret);
        let (tokens, _principal) = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id,
                    totp_code: Some(verify_code),
                    backup_code: None,
                },
                test_context("mfa-verify"),
            )
            .await
            .expect("mfa verify should issue tokens");

        let authenticated = harness
            .service
            .authenticate_access_token(&tokens.access_token)
            .await;
        assert!(authenticated.is_ok());
    }

    #[tokio::test]
    async fn mfa_backup_code_is_one_time_use() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-backup"))
            .await
            .expect("mfa enroll should succeed");
        let activate_code = current_totp_code(&enroll.secret);
        let activation = harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id.clone(),
                    totp_code: activate_code,
                },
                test_context("mfa-activate-backup"),
            )
            .await
            .expect("mfa activation should succeed");

        let backup_code = activation.backup_codes[0].clone();

        let first_login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("backup-device-1".to_string()),
                },
                test_context("backup-login-1"),
            )
            .await
            .expect("login should return mfa challenge");

        let first_challenge = match first_login {
            LoginResult::MfaRequired(challenge) => challenge.challenge_id,
            LoginResult::Authenticated { .. } => panic!("mfa challenge should be required"),
        };

        harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id: first_challenge,
                    totp_code: None,
                    backup_code: Some(backup_code.clone()),
                },
                test_context("backup-verify-1"),
            )
            .await
            .expect("first backup code use should succeed");

        let second_login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("backup-device-2".to_string()),
                },
                test_context("backup-login-2"),
            )
            .await
            .expect("second login should return mfa challenge");

        let second_challenge = match second_login {
            LoginResult::MfaRequired(challenge) => challenge.challenge_id,
            LoginResult::Authenticated { .. } => panic!("mfa challenge should be required"),
        };

        let second_verify = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id: second_challenge,
                    totp_code: None,
                    backup_code: Some(backup_code),
                },
                test_context("backup-verify-2"),
            )
            .await;
        assert!(matches!(second_verify, Err(AuthError::InvalidMfaCode)));
    }

    #[tokio::test]
    async fn mfa_backup_codes_reject_after_all_codes_are_consumed() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-backup-exhaust"))
            .await
            .expect("mfa enroll should succeed");
        let activation = harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id,
                    totp_code: current_totp_code(&enroll.secret),
                },
                test_context("mfa-activate-backup-exhaust"),
            )
            .await
            .expect("mfa activation should succeed");

        let backup_codes = activation.backup_codes;
        assert!(!backup_codes.is_empty());

        for (idx, backup_code) in backup_codes.iter().enumerate() {
            let login = harness
                .service
                .login(
                    LoginCommand {
                        email: harness.bootstrap_email.clone(),
                        password: harness.bootstrap_password.clone(),
                        device_info: Some(format!("backup-exhaust-device-{idx}")),
                    },
                    test_context("backup-exhaust-login"),
                )
                .await
                .expect("login should return mfa challenge");
            let challenge_id = assert_mfa_required(login);

            let verify = harness
                .service
                .mfa_verify(
                    MfaVerifyCommand {
                        challenge_id,
                        totp_code: None,
                        backup_code: Some(backup_code.clone()),
                    },
                    test_context("backup-exhaust-verify"),
                )
                .await;
            assert!(verify.is_ok());
        }

        let login_after_exhaustion = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("backup-exhaust-after".to_string()),
                },
                test_context("backup-exhaust-login-after"),
            )
            .await
            .expect("login should still return mfa challenge");
        let challenge_id = assert_mfa_required(login_after_exhaustion);

        let rejected_after_exhaustion = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id,
                    totp_code: None,
                    backup_code: Some(backup_codes[0].clone()),
                },
                test_context("backup-exhaust-verify-after"),
            )
            .await;
        assert!(matches!(
            rejected_after_exhaustion,
            Err(AuthError::InvalidMfaCode)
        ));
    }

    #[tokio::test]
    async fn mfa_challenge_cannot_be_replayed() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-replay"))
            .await
            .expect("mfa enroll should succeed");
        let activate_code = current_totp_code(&enroll.secret);
        harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id.clone(),
                    totp_code: activate_code,
                },
                test_context("mfa-activate-replay"),
            )
            .await
            .expect("mfa activation should succeed");

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("replay-device".to_string()),
                },
                test_context("mfa-login-replay"),
            )
            .await
            .expect("login should return mfa challenge");
        let challenge_id = assert_mfa_required(login);

        let verify_code = current_totp_code(&enroll.secret);
        harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id: challenge_id.clone(),
                    totp_code: Some(verify_code),
                    backup_code: None,
                },
                test_context("mfa-verify-replay-initial"),
            )
            .await
            .expect("initial challenge verification should succeed");

        let replay_attempt = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id,
                    totp_code: Some(current_totp_code(&enroll.secret)),
                    backup_code: None,
                },
                test_context("mfa-verify-replay-second"),
            )
            .await;
        assert!(matches!(
            replay_attempt,
            Err(AuthError::InvalidMfaChallenge)
        ));
    }

    #[tokio::test]
    async fn mfa_challenge_allows_retry_before_max_attempts() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-retry"))
            .await
            .expect("mfa enroll should succeed");
        harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id.clone(),
                    totp_code: current_totp_code(&enroll.secret),
                },
                test_context("mfa-activate-retry"),
            )
            .await
            .expect("mfa activation should succeed");

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("retry-device".to_string()),
                },
                test_context("mfa-login-retry"),
            )
            .await
            .expect("login should return mfa challenge");
        let challenge_id = assert_mfa_required(login);

        let first_attempt = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id: challenge_id.clone(),
                    totp_code: Some("000000".to_string()),
                    backup_code: None,
                },
                test_context("mfa-verify-retry-invalid"),
            )
            .await;
        assert!(matches!(first_attempt, Err(AuthError::InvalidMfaCode)));

        let second_attempt = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id,
                    totp_code: Some(current_totp_code(&enroll.secret)),
                    backup_code: None,
                },
                test_context("mfa-verify-retry-valid"),
            )
            .await;
        assert!(second_attempt.is_ok());
    }

    #[tokio::test]
    async fn mfa_challenge_is_consumed_after_max_failed_attempts() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-max-attempts"))
            .await
            .expect("mfa enroll should succeed");
        harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id,
                    totp_code: current_totp_code(&enroll.secret),
                },
                test_context("mfa-activate-max-attempts"),
            )
            .await
            .expect("mfa activation should succeed");

        let login = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("max-attempts-device".to_string()),
                },
                test_context("mfa-login-max-attempts"),
            )
            .await
            .expect("login should return mfa challenge");
        let challenge_id = assert_mfa_required(login);

        let max_attempts = test_config().mfa_challenge_max_attempts;
        for _ in 0..max_attempts {
            let failed = harness
                .service
                .mfa_verify(
                    MfaVerifyCommand {
                        challenge_id: challenge_id.clone(),
                        totp_code: None,
                        backup_code: Some("ABCD-EFGH".to_string()),
                    },
                    test_context("mfa-verify-max-attempts-failed"),
                )
                .await;
            assert!(matches!(failed, Err(AuthError::InvalidMfaCode)));
        }

        let verify_after_exhaustion = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id,
                    totp_code: Some(current_totp_code(&enroll.secret)),
                    backup_code: None,
                },
                test_context("mfa-verify-max-attempts-after"),
            )
            .await;
        assert!(matches!(
            verify_after_exhaustion,
            Err(AuthError::InvalidMfaChallenge)
        ));
    }

    #[test]
    fn totp_verification_tolerates_single_step_clock_drift_only() {
        let secret = super::generate_totp_secret();
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret)
            .expect("secret should be valid base32");

        let now = Utc::now();
        let current_step = (now.timestamp() / 30) as u64;
        let previous_code =
            super::totp_code_for_step(&secret_bytes, current_step.saturating_sub(1))
                .expect("previous step code should be generated");
        let next_code = super::totp_code_for_step(&secret_bytes, current_step + 1)
            .expect("next step code should be generated");
        let far_future_code = super::totp_code_for_step(&secret_bytes, current_step + 3)
            .expect("far future step code should be generated");

        assert!(super::verify_totp_code(&secret, &previous_code, now));
        assert!(super::verify_totp_code(&secret, &next_code, now));
        assert!(!super::verify_totp_code(&secret, &far_future_code, now));
    }

    #[tokio::test]
    async fn mfa_disable_restores_password_only_login() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-disable"))
            .await
            .expect("mfa enroll should succeed");
        harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id.clone(),
                    totp_code: current_totp_code(&enroll.secret),
                },
                test_context("mfa-activate-disable"),
            )
            .await
            .expect("mfa activation should succeed");

        let login_before_disable = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("disable-device-before".to_string()),
                },
                test_context("mfa-login-before-disable"),
            )
            .await
            .expect("login should return mfa challenge before disable");
        let _ = assert_mfa_required(login_before_disable);

        let disable_invalid_code = harness
            .service
            .mfa_disable(
                super::MfaDisableCommand {
                    user_id: user.id.clone(),
                    current_password: harness.bootstrap_password.clone(),
                    totp_code: Some("000000".to_string()),
                    backup_code: None,
                },
                test_context("mfa-disable-invalid-code"),
            )
            .await;
        assert!(matches!(
            disable_invalid_code,
            Err(AuthError::InvalidMfaCode)
        ));

        harness
            .service
            .mfa_disable(
                super::MfaDisableCommand {
                    user_id: user.id,
                    current_password: harness.bootstrap_password.clone(),
                    totp_code: Some(current_totp_code(&enroll.secret)),
                    backup_code: None,
                },
                test_context("mfa-disable-success"),
            )
            .await
            .expect("mfa disable should succeed");

        let login_after_disable = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("disable-device-after".to_string()),
                },
                test_context("mfa-login-after-disable"),
            )
            .await
            .expect("login should succeed after mfa disable");
        let _ = assert_authenticated(login_after_disable);
    }

    #[tokio::test]
    async fn mfa_disable_revokes_existing_sessions() {
        let harness = build_harness();
        let user = harness
            .users
            .find_by_email(&harness.bootstrap_email)
            .await
            .expect("bootstrap user should exist");

        let enroll = harness
            .service
            .mfa_enroll(&user.id, test_context("mfa-enroll-disable-revoke"))
            .await
            .expect("mfa enroll should succeed");
        harness
            .service
            .mfa_activate(
                MfaActivateCommand {
                    user_id: user.id.clone(),
                    totp_code: current_totp_code(&enroll.secret),
                },
                test_context("mfa-activate-disable-revoke"),
            )
            .await
            .expect("mfa activation should succeed");

        let login_before_disable = harness
            .service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("disable-revoke-device".to_string()),
                },
                test_context("mfa-login-disable-revoke"),
            )
            .await
            .expect("login should return mfa challenge before disable");
        let challenge_id = assert_mfa_required(login_before_disable);

        let (tokens, _principal) = harness
            .service
            .mfa_verify(
                MfaVerifyCommand {
                    challenge_id,
                    totp_code: Some(current_totp_code(&enroll.secret)),
                    backup_code: None,
                },
                test_context("mfa-verify-disable-revoke"),
            )
            .await
            .expect("mfa verify should issue tokens");

        harness
            .service
            .mfa_disable(
                super::MfaDisableCommand {
                    user_id: user.id,
                    current_password: harness.bootstrap_password.clone(),
                    totp_code: Some(current_totp_code(&enroll.secret)),
                    backup_code: None,
                },
                test_context("mfa-disable-revoke"),
            )
            .await
            .expect("mfa disable should succeed");

        let old_token_after_disable = harness
            .service
            .authenticate_access_token(&tokens.access_token)
            .await;
        assert!(matches!(
            old_token_after_disable,
            Err(AuthError::InvalidToken)
        ));
    }

    fn build_harness() -> TestHarness {
        build_harness_with_refresh_factory(|refresh_tokens| refresh_tokens)
    }

    fn build_harness_with_refresh_factory<F>(refresh_factory: F) -> TestHarness
    where
        F: FnOnce(
            Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>,
        ) -> Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>,
    {
        let cfg = test_config();
        let bootstrap_email = cfg
            .bootstrap_user_email
            .clone()
            .expect("bootstrap email should be present");
        let bootstrap_password = cfg
            .bootstrap_user_password
            .clone()
            .expect("bootstrap password should be present");

        let adapters =
            InMemoryAdapters::bootstrap(&cfg).expect("in-memory adapters should bootstrap");

        let users = Arc::new(adapters.users) as Arc<dyn UserRepository>;
        let login_abuse = Arc::new(adapters.login_abuse)
            as Arc<dyn crate::modules::auth::ports::LoginAbuseProtector>;
        let verification_tokens = Arc::new(adapters.verification_tokens)
            as Arc<dyn crate::modules::auth::ports::VerificationTokenRepository>;
        let password_reset_tokens = Arc::new(adapters.password_reset_tokens)
            as Arc<dyn crate::modules::auth::ports::PasswordResetTokenRepository>;
        let mfa_factors = Arc::new(adapters.mfa_factors)
            as Arc<dyn crate::modules::auth::ports::MfaFactorRepository>;
        let mfa_challenges = Arc::new(adapters.mfa_challenges)
            as Arc<dyn crate::modules::auth::ports::MfaChallengeRepository>;
        let mfa_backup_codes = Arc::new(adapters.mfa_backup_codes)
            as Arc<dyn crate::modules::auth::ports::MfaBackupCodeRepository>;
        let sessions = Arc::new(adapters.sessions)
            as Arc<dyn crate::modules::sessions::ports::SessionRepository>;
        let base_refresh_tokens = Arc::new(adapters.refresh_tokens)
            as Arc<dyn crate::modules::tokens::ports::RefreshTokenRepository>;
        let refresh_tokens = refresh_factory(base_refresh_tokens);
        let audit = Arc::new(adapters.audit);
        let audit_repo = audit.clone();
        let audit = audit as Arc<dyn crate::modules::audit::ports::AuditRepository>;
        let jwt = Arc::new(
            JwtEdDsaService::new(
                cfg.jwt_keys.clone(),
                cfg.jwt_primary_kid.clone(),
                cfg.jwt_issuer.clone(),
                cfg.jwt_audience.clone(),
            )
            .expect("jwt service should initialize"),
        ) as Arc<dyn crate::modules::tokens::ports::JwtService>;
        let refresh_crypto = Arc::new(RefreshCryptoHmacService::new(cfg.refresh_pepper.clone()))
            as Arc<dyn crate::modules::tokens::ports::RefreshCryptoService>;

        let service = AuthService::new(
            users.clone(),
            login_abuse,
            verification_tokens,
            password_reset_tokens,
            mfa_factors,
            mfa_challenges,
            mfa_backup_codes,
            sessions,
            refresh_tokens,
            audit,
            Arc::new(crate::adapters::email::NoopTransactionalEmailSender),
            jwt,
            refresh_crypto,
            cfg.access_ttl_seconds,
            cfg.refresh_ttl_seconds,
            cfg.email_verification_ttl_seconds,
            cfg.password_reset_ttl_seconds,
            cfg.mfa_challenge_ttl_seconds,
            cfg.mfa_challenge_max_attempts,
            cfg.mfa_totp_issuer,
            cfg.mfa_encryption_key,
            cfg.jwt_issuer,
            cfg.jwt_audience,
        )
        .expect("auth service should initialize");

        TestHarness {
            service,
            users,
            audit: audit_repo,
            bootstrap_email,
            bootstrap_password,
        }
    }

    fn test_context(trace_id: &str) -> RequestContext {
        RequestContext {
            trace_id: trace_id.to_string(),
            ip: Some("127.0.0.1".to_string()),
            user_agent: Some("unit-test".to_string()),
        }
    }

    fn test_config() -> AppConfig {
        AppConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            auth_runtime: AuthRuntime::InMemory,
            jwt_keys: vec![crate::config::JwtKeyConfig {
                kid: "auth-tests-ed25519-v1".to_string(),
                private_key_pem: Some(TEST_PRIVATE_KEY_PEM.to_string()),
                public_key_pem: TEST_PUBLIC_KEY_PEM.to_string(),
            }],
            jwt_primary_kid: "auth-tests-ed25519-v1".to_string(),
            metrics_bearer_token: None,
            metrics_allowed_cidrs: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_ips: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
            database_url: "".to_string(),
            database_max_connections: 1,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            jwt_issuer: "auth-tests".to_string(),
            jwt_audience: "auth-tests-clients".to_string(),
            refresh_pepper: "integration-test-refresh-pepper".to_string(),
            access_ttl_seconds: 900,
            refresh_ttl_seconds: 1209600,
            email_verification_ttl_seconds: 86400,
            password_reset_ttl_seconds: 900,
            mfa_challenge_ttl_seconds: 300,
            mfa_challenge_max_attempts: 3,
            mfa_totp_issuer: "auth-tests".to_string(),
            mfa_encryption_key: generated_test_mfa_encryption_key_base64(),
            bootstrap_user_email: Some("bootstrap@example.com".to_string()),
            bootstrap_user_password: Some(generated_test_password()),
            login_max_attempts: 5,
            login_attempt_window_seconds: 300,
            login_lockout_seconds: 900,
            login_lockout_max_seconds: 7200,
            login_abuse_attempts_prefix: "test:attempts".to_string(),
            login_abuse_lock_prefix: "test:lock".to_string(),
            login_abuse_strikes_prefix: "test:strikes".to_string(),
            login_abuse_redis_fail_mode: LoginAbuseRedisFailMode::FailClosed,
            login_abuse_bucket_mode: LoginAbuseBucketMode::EmailAndIp,
            email_metrics_latency_enabled: false,
            email_provider: crate::config::EmailProviderConfig::Noop,
            email_delivery_mode: crate::config::EmailDeliveryMode::Inline,
            email_outbox: crate::config::EmailOutboxConfig {
                poll_interval_ms: 1000,
                batch_size: 25,
                max_attempts: 8,
                lease_ms: 30_000,
                backoff_base_ms: 1000,
                backoff_max_ms: 60_000,
            },
        }
    }

    fn assert_authenticated(result: LoginResult) -> (super::AuthTokens, super::Principal) {
        match result {
            LoginResult::Authenticated { tokens, principal } => (tokens, principal),
            LoginResult::MfaRequired(_) => panic!("expected token-based authentication"),
        }
    }

    fn assert_mfa_required(result: LoginResult) -> String {
        match result {
            LoginResult::MfaRequired(challenge) => challenge.challenge_id,
            LoginResult::Authenticated { .. } => panic!("expected mfa challenge"),
        }
    }

    fn current_totp_code(secret: &str) -> String {
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
            .expect("secret should be valid base32");
        let step = (Utc::now().timestamp() / 30) as u64;
        super::totp_code_for_step(&secret_bytes, step).expect("totp generation should succeed")
    }

    fn generated_test_password() -> String {
        format!("Aa!9z{}", Uuid::new_v4().simple())
    }

    fn generated_test_mfa_encryption_key_base64() -> String {
        let mut key_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        BASE64_STANDARD.encode(key_bytes)
    }
}
