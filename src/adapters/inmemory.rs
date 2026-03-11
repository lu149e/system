use std::{collections::HashMap, sync::Mutex};

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{
    config::{AppConfig, LoginAbuseBucketMode},
    modules::{
        audit::{domain::AuditEvent, ports::AuditRepository},
        auth::{
            domain::{
                MfaChallengeRecord, MfaFactorRecord, PasswordResetTokenRecord, User,
                VerificationTokenRecord,
            },
            ports::{
                LoginAbuseProtector, LoginGateDecision, MfaBackupCodeConsumeState,
                MfaBackupCodeRepository, MfaChallengeFailureState, MfaChallengeLookupState,
                MfaChallengeRepository, MfaFactorRepository,
                PasskeyAuthenticationChallengeConsumeState, PasskeyAuthenticationChallengeRecord,
                PasskeyChallengeRepository, PasskeyCredentialRepository,
                PasskeyRegistrationChallengeConsumeState, PasskeyRegistrationChallengeRecord,
                PasswordResetTokenConsumeState, PasswordResetTokenRepository, UserRepository,
                VerificationTokenConsumeState, VerificationTokenRepository,
            },
        },
        sessions::{
            domain::{Session, SessionStatus},
            ports::SessionRepository,
        },
        tokens::{
            domain::{AccessTokenClaims, RefreshTokenRecord},
            ports::{
                JwtService, RefreshCryptoService, RefreshRotationState, RefreshTokenRepository,
            },
        },
    },
};

type HmacSha256 = Hmac<Sha256>;

pub struct InMemoryAdapters {
    pub users: InMemoryUserRepository,
    pub verification_tokens: InMemoryVerificationTokenRepository,
    pub password_reset_tokens: InMemoryPasswordResetTokenRepository,
    pub mfa_factors: InMemoryMfaFactorRepository,
    pub mfa_challenges: InMemoryMfaChallengeRepository,
    pub mfa_backup_codes: InMemoryMfaBackupCodeRepository,
    pub passkeys: InMemoryPasskeyCredentialRepository,
    pub passkey_challenges: InMemoryPasskeyChallengeRepository,
    pub sessions: InMemorySessionRepository,
    pub refresh_tokens: InMemoryRefreshTokenRepository,
    pub audit: InMemoryAuditRepository,
    pub login_abuse: InMemoryLoginAbuseProtector,
}

impl InMemoryAdapters {
    pub fn bootstrap(cfg: &AppConfig) -> anyhow::Result<Self> {
        let mut seed_users = Vec::new();
        match (&cfg.bootstrap_user_email, &cfg.bootstrap_user_password) {
            (Some(email), Some(password)) => {
                let user_id = Uuid::new_v4().to_string();
                let password_hash = {
                    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
                    Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .map_err(|_| anyhow::anyhow!("failed to hash BOOTSTRAP_USER_PASSWORD"))?
                        .to_string()
                };

                seed_users.push(User {
                    id: user_id,
                    email: email.to_ascii_lowercase(),
                    password_hash,
                    status: crate::modules::auth::domain::UserStatus::Active,
                });
            }
            (None, None) => {}
            _ => {
                tracing::warn!(
                    "bootstrap user disabled: set both BOOTSTRAP_USER_EMAIL and BOOTSTRAP_USER_PASSWORD"
                );
            }
        }

        Ok(Self {
            users: InMemoryUserRepository::new(seed_users),
            verification_tokens: InMemoryVerificationTokenRepository::new(),
            password_reset_tokens: InMemoryPasswordResetTokenRepository::new(),
            mfa_factors: InMemoryMfaFactorRepository::new(),
            mfa_challenges: InMemoryMfaChallengeRepository::new(),
            mfa_backup_codes: InMemoryMfaBackupCodeRepository::new(),
            passkeys: InMemoryPasskeyCredentialRepository::new(),
            passkey_challenges: InMemoryPasskeyChallengeRepository::new(),
            sessions: InMemorySessionRepository::new(),
            refresh_tokens: InMemoryRefreshTokenRepository::new(),
            audit: InMemoryAuditRepository::new(),
            login_abuse: InMemoryLoginAbuseProtector::new(
                cfg.login_max_attempts,
                cfg.login_attempt_window_seconds,
                cfg.login_lockout_seconds,
                cfg.login_lockout_max_seconds,
                cfg.login_abuse_bucket_mode,
            )?,
        })
    }
}

pub struct InMemoryUserRepository {
    users_by_id: Mutex<HashMap<String, User>>,
    id_by_email: Mutex<HashMap<String, String>>,
}

impl InMemoryUserRepository {
    fn new(seed_users: Vec<User>) -> Self {
        let mut users_by_id = HashMap::new();
        let mut id_by_email = HashMap::new();
        for user in seed_users {
            id_by_email.insert(user.email.clone(), user.id.clone());
            users_by_id.insert(user.id.clone(), user);
        }
        Self {
            users_by_id: Mutex::new(users_by_id),
            id_by_email: Mutex::new(id_by_email),
        }
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn find_by_email(&self, email: &str) -> Option<User> {
        let email_key = email.to_ascii_lowercase();
        let id = self.id_by_email.lock().ok()?.get(&email_key).cloned()?;
        self.users_by_id.lock().ok()?.get(&id).cloned()
    }

    async fn find_by_id(&self, user_id: &str) -> Option<User> {
        self.users_by_id.lock().ok()?.get(user_id).cloned()
    }

    async fn create_pending_user(
        &self,
        email: &str,
        password_hash: &str,
    ) -> Result<Option<User>, String> {
        let email_key = email.to_ascii_lowercase();
        let mut id_by_email = self
            .id_by_email
            .lock()
            .map_err(|_| "user email index unavailable".to_string())?;
        if id_by_email.contains_key(&email_key) {
            return Ok(None);
        }

        let user = User {
            id: Uuid::new_v4().to_string(),
            email: email_key.clone(),
            password_hash: password_hash.to_string(),
            status: crate::modules::auth::domain::UserStatus::PendingVerification,
        };

        let mut users_by_id = self
            .users_by_id
            .lock()
            .map_err(|_| "user storage unavailable".to_string())?;
        id_by_email.insert(email_key, user.id.clone());
        users_by_id.insert(user.id.clone(), user.clone());

        Ok(Some(user))
    }

    async fn activate_user(&self, user_id: &str, _now: DateTime<Utc>) -> Result<(), String> {
        let mut users_by_id = self
            .users_by_id
            .lock()
            .map_err(|_| "user storage unavailable".to_string())?;
        let Some(user) = users_by_id.get_mut(user_id) else {
            return Err("user not found".to_string());
        };

        user.status = crate::modules::auth::domain::UserStatus::Active;
        Ok(())
    }

    async fn update_password(
        &self,
        user_id: &str,
        password_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut users_by_id = self
            .users_by_id
            .lock()
            .map_err(|_| "user storage unavailable".to_string())?;
        let Some(user) = users_by_id.get_mut(user_id) else {
            return Err("user not found".to_string());
        };

        user.password_hash = password_hash.to_string();
        Ok(())
    }
}

pub struct InMemoryVerificationTokenRepository {
    tokens_by_hash: Mutex<HashMap<String, VerificationTokenRecord>>,
}

impl InMemoryVerificationTokenRepository {
    fn new() -> Self {
        Self {
            tokens_by_hash: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl VerificationTokenRepository for InMemoryVerificationTokenRepository {
    async fn issue(&self, token: VerificationTokenRecord) -> Result<(), String> {
        let mut guard = self
            .tokens_by_hash
            .lock()
            .map_err(|_| "verification token storage unavailable".to_string())?;

        for record in guard.values_mut() {
            if record.user_id == token.user_id && record.used_at.is_none() {
                record.used_at = Some(token.created_at);
            }
        }

        guard.insert(token.token_hash.clone(), token);
        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<VerificationTokenConsumeState, String> {
        let mut guard = self
            .tokens_by_hash
            .lock()
            .map_err(|_| "verification token storage unavailable".to_string())?;
        let Some(record) = guard.get_mut(token_hash) else {
            return Ok(VerificationTokenConsumeState::NotFound);
        };

        if record.used_at.is_some() {
            return Ok(VerificationTokenConsumeState::AlreadyUsed);
        }
        if record.expires_at <= now {
            return Ok(VerificationTokenConsumeState::Expired);
        }

        record.used_at = Some(now);
        Ok(VerificationTokenConsumeState::Consumed {
            user_id: record.user_id.clone(),
        })
    }
}

pub struct InMemoryPasswordResetTokenRepository {
    tokens_by_hash: Mutex<HashMap<String, PasswordResetTokenRecord>>,
}

impl InMemoryPasswordResetTokenRepository {
    fn new() -> Self {
        Self {
            tokens_by_hash: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl PasswordResetTokenRepository for InMemoryPasswordResetTokenRepository {
    async fn issue(&self, token: PasswordResetTokenRecord) -> Result<(), String> {
        let mut guard = self
            .tokens_by_hash
            .lock()
            .map_err(|_| "password reset token storage unavailable".to_string())?;

        for record in guard.values_mut() {
            if record.user_id == token.user_id && record.used_at.is_none() {
                record.used_at = Some(token.created_at);
            }
        }

        guard.insert(token.token_hash.clone(), token);
        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<PasswordResetTokenConsumeState, String> {
        let mut guard = self
            .tokens_by_hash
            .lock()
            .map_err(|_| "password reset token storage unavailable".to_string())?;
        let Some(record) = guard.get_mut(token_hash) else {
            return Ok(PasswordResetTokenConsumeState::NotFound);
        };

        if record.used_at.is_some() {
            return Ok(PasswordResetTokenConsumeState::AlreadyUsed);
        }
        if record.expires_at <= now {
            return Ok(PasswordResetTokenConsumeState::Expired);
        }

        record.used_at = Some(now);
        Ok(PasswordResetTokenConsumeState::Consumed {
            user_id: record.user_id.clone(),
        })
    }
}

pub struct InMemoryMfaFactorRepository {
    factors_by_user: Mutex<HashMap<String, MfaFactorRecord>>,
}

impl InMemoryMfaFactorRepository {
    fn new() -> Self {
        Self {
            factors_by_user: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl MfaFactorRepository for InMemoryMfaFactorRepository {
    async fn find_by_user_id(&self, user_id: &str) -> Option<MfaFactorRecord> {
        self.factors_by_user.lock().ok()?.get(user_id).cloned()
    }

    async fn upsert(&self, factor: MfaFactorRecord) -> Result<(), String> {
        let mut guard = self
            .factors_by_user
            .lock()
            .map_err(|_| "mfa factor storage unavailable".to_string())?;
        guard.insert(factor.user_id.clone(), factor);
        Ok(())
    }

    async fn set_enabled_at(&self, user_id: &str, enabled_at: DateTime<Utc>) -> Result<(), String> {
        let mut guard = self
            .factors_by_user
            .lock()
            .map_err(|_| "mfa factor storage unavailable".to_string())?;
        let Some(record) = guard.get_mut(user_id) else {
            return Err("mfa factor not found".to_string());
        };

        record.enabled_at = Some(enabled_at);
        record.updated_at = enabled_at;
        Ok(())
    }

    async fn delete_for_user(&self, user_id: &str) -> Result<(), String> {
        let mut guard = self
            .factors_by_user
            .lock()
            .map_err(|_| "mfa factor storage unavailable".to_string())?;
        guard.remove(user_id);
        Ok(())
    }
}

pub struct InMemoryMfaChallengeRepository {
    challenges_by_hash: Mutex<HashMap<String, MfaChallengeRecord>>,
}

impl InMemoryMfaChallengeRepository {
    fn new() -> Self {
        Self {
            challenges_by_hash: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl MfaChallengeRepository for InMemoryMfaChallengeRepository {
    async fn issue(&self, challenge: MfaChallengeRecord) -> Result<(), String> {
        let mut guard = self
            .challenges_by_hash
            .lock()
            .map_err(|_| "mfa challenge storage unavailable".to_string())?;

        for record in guard.values_mut() {
            if record.user_id == challenge.user_id && record.used_at.is_none() {
                record.used_at = Some(challenge.created_at);
            }
        }

        guard.insert(challenge.challenge_hash.clone(), challenge);
        Ok(())
    }

    async fn find_active(
        &self,
        challenge_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookupState, String> {
        let guard = self
            .challenges_by_hash
            .lock()
            .map_err(|_| "mfa challenge storage unavailable".to_string())?;
        let Some(record) = guard.get(challenge_hash) else {
            return Ok(MfaChallengeLookupState::NotFound);
        };

        if record.used_at.is_some() {
            return Ok(MfaChallengeLookupState::AlreadyUsed);
        }
        if record.expires_at <= now {
            return Ok(MfaChallengeLookupState::Expired);
        }

        Ok(MfaChallengeLookupState::Active {
            user_id: record.user_id.clone(),
            device_info: record.device_info.clone(),
        })
    }

    async fn mark_used(&self, challenge_hash: &str, now: DateTime<Utc>) -> Result<(), String> {
        let mut guard = self
            .challenges_by_hash
            .lock()
            .map_err(|_| "mfa challenge storage unavailable".to_string())?;
        let Some(record) = guard.get_mut(challenge_hash) else {
            return Err("mfa challenge not found".to_string());
        };

        if record.used_at.is_some() {
            return Err("mfa challenge already used".to_string());
        }
        if record.expires_at <= now {
            return Err("mfa challenge expired".to_string());
        }

        record.used_at = Some(now);
        Ok(())
    }

    async fn register_failure(
        &self,
        challenge_hash: &str,
        now: DateTime<Utc>,
        max_attempts: u32,
    ) -> Result<MfaChallengeFailureState, String> {
        let mut guard = self
            .challenges_by_hash
            .lock()
            .map_err(|_| "mfa challenge storage unavailable".to_string())?;
        let Some(record) = guard.get_mut(challenge_hash) else {
            return Ok(MfaChallengeFailureState::NotFound);
        };

        if record.used_at.is_some() {
            return Ok(MfaChallengeFailureState::AlreadyUsed);
        }
        if record.expires_at <= now {
            return Ok(MfaChallengeFailureState::Expired);
        }

        record.failed_attempts = record.failed_attempts.saturating_add(1);
        if record.failed_attempts >= max_attempts {
            record.used_at = Some(now);
            return Ok(MfaChallengeFailureState::Exhausted);
        }

        Ok(MfaChallengeFailureState::RetryAllowed {
            remaining_attempts: max_attempts - record.failed_attempts,
        })
    }
}

pub struct InMemoryMfaBackupCodeRepository {
    codes_by_hash: Mutex<HashMap<String, crate::modules::auth::domain::MfaBackupCodeRecord>>,
}

impl InMemoryMfaBackupCodeRepository {
    fn new() -> Self {
        Self {
            codes_by_hash: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl MfaBackupCodeRepository for InMemoryMfaBackupCodeRepository {
    async fn replace_for_user(
        &self,
        user_id: &str,
        code_hashes: &[String],
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut guard = self
            .codes_by_hash
            .lock()
            .map_err(|_| "mfa backup code storage unavailable".to_string())?;

        guard.retain(|_, record| record.user_id != user_id);

        for code_hash in code_hashes {
            guard.insert(
                code_hash.clone(),
                crate::modules::auth::domain::MfaBackupCodeRecord {
                    id: Uuid::new_v4().to_string(),
                    user_id: user_id.to_string(),
                    code_hash: code_hash.clone(),
                    used_at: None,
                    created_at: now,
                },
            );
        }

        Ok(())
    }

    async fn consume(
        &self,
        user_id: &str,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<MfaBackupCodeConsumeState, String> {
        let mut guard = self
            .codes_by_hash
            .lock()
            .map_err(|_| "mfa backup code storage unavailable".to_string())?;
        let Some(record) = guard.get_mut(code_hash) else {
            return Ok(MfaBackupCodeConsumeState::NotFound);
        };

        if record.user_id != user_id {
            return Ok(MfaBackupCodeConsumeState::NotFound);
        }
        if record.used_at.is_some() {
            return Ok(MfaBackupCodeConsumeState::AlreadyUsed);
        }

        record.used_at = Some(now);
        Ok(MfaBackupCodeConsumeState::Consumed)
    }
}

pub struct InMemoryPasskeyCredentialRepository {
    passkeys_by_user: Mutex<HashMap<String, Vec<Passkey>>>,
}

impl InMemoryPasskeyCredentialRepository {
    fn new() -> Self {
        Self {
            passkeys_by_user: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl PasskeyCredentialRepository for InMemoryPasskeyCredentialRepository {
    async fn list_for_user(&self, user_id: &str) -> Result<Vec<Passkey>, String> {
        let passkeys = self
            .passkeys_by_user
            .lock()
            .map_err(|_| "passkey storage unavailable".to_string())?
            .get(user_id)
            .cloned()
            .unwrap_or_default();

        Ok(passkeys)
    }

    async fn upsert_for_user(
        &self,
        user_id: &str,
        passkey: Passkey,
        _now: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut passkeys_by_user = self
            .passkeys_by_user
            .lock()
            .map_err(|_| "passkey storage unavailable".to_string())?;
        let passkeys = passkeys_by_user.entry(user_id.to_string()).or_default();

        if let Some(existing_passkey) = passkeys
            .iter_mut()
            .find(|existing_passkey| existing_passkey.cred_id() == passkey.cred_id())
        {
            *existing_passkey = passkey;
            return Ok(());
        }

        passkeys.push(passkey);
        Ok(())
    }
}

pub struct InMemoryPasskeyChallengeRepository {
    registration_by_flow: Mutex<HashMap<String, PasskeyRegistrationChallengeRecord>>,
    authentication_by_flow: Mutex<HashMap<String, PasskeyAuthenticationChallengeRecord>>,
}

impl InMemoryPasskeyChallengeRepository {
    fn new() -> Self {
        Self {
            registration_by_flow: Mutex::new(HashMap::new()),
            authentication_by_flow: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub fn has_authentication_challenge(&self, flow_id: &str) -> bool {
        self.authentication_by_flow
            .lock()
            .map(|guard| guard.contains_key(flow_id))
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub fn peek_authentication_challenge(
        &self,
        flow_id: &str,
    ) -> Option<PasskeyAuthenticationChallengeRecord> {
        self.authentication_by_flow
            .lock()
            .ok()
            .and_then(|guard| guard.get(flow_id).cloned())
    }
}

#[async_trait]
impl PasskeyChallengeRepository for InMemoryPasskeyChallengeRepository {
    async fn issue_registration(
        &self,
        flow_id: &str,
        challenge: PasskeyRegistrationChallengeRecord,
    ) -> Result<(), String> {
        let mut guard = self
            .registration_by_flow
            .lock()
            .map_err(|_| "passkey registration challenge storage unavailable".to_string())?;
        guard.retain(|_, existing| existing.user_id != challenge.user_id);
        guard.insert(flow_id.to_string(), challenge);
        Ok(())
    }

    async fn consume_registration(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyRegistrationChallengeConsumeState, String> {
        let mut guard = self
            .registration_by_flow
            .lock()
            .map_err(|_| "passkey registration challenge storage unavailable".to_string())?;
        let Some(challenge) = guard.remove(flow_id) else {
            return Ok(PasskeyRegistrationChallengeConsumeState::NotFound);
        };

        if challenge.expires_at <= now {
            return Ok(PasskeyRegistrationChallengeConsumeState::Expired);
        }

        Ok(PasskeyRegistrationChallengeConsumeState::Active(Box::new(
            challenge,
        )))
    }

    async fn issue_authentication(
        &self,
        flow_id: &str,
        challenge: PasskeyAuthenticationChallengeRecord,
    ) -> Result<(), String> {
        let mut guard = self
            .authentication_by_flow
            .lock()
            .map_err(|_| "passkey authentication challenge storage unavailable".to_string())?;
        guard.retain(|_, existing| existing.user_id != challenge.user_id);
        guard.insert(flow_id.to_string(), challenge);
        Ok(())
    }

    async fn consume_authentication(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyAuthenticationChallengeConsumeState, String> {
        let mut guard = self
            .authentication_by_flow
            .lock()
            .map_err(|_| "passkey authentication challenge storage unavailable".to_string())?;
        let Some(challenge) = guard.remove(flow_id) else {
            return Ok(PasskeyAuthenticationChallengeConsumeState::NotFound);
        };

        if challenge.expires_at <= now {
            return Ok(PasskeyAuthenticationChallengeConsumeState::Expired);
        }

        Ok(PasskeyAuthenticationChallengeConsumeState::Active(
            Box::new(challenge),
        ))
    }

    async fn prune_expired(&self, now: DateTime<Utc>) -> Result<u64, String> {
        let mut registration_guard = self
            .registration_by_flow
            .lock()
            .map_err(|_| "passkey registration challenge storage unavailable".to_string())?;
        let registration_before = registration_guard.len();
        registration_guard.retain(|_, challenge| challenge.expires_at > now);
        let registration_pruned = registration_before.saturating_sub(registration_guard.len());
        drop(registration_guard);

        let mut authentication_guard = self
            .authentication_by_flow
            .lock()
            .map_err(|_| "passkey authentication challenge storage unavailable".to_string())?;
        let authentication_before = authentication_guard.len();
        authentication_guard.retain(|_, challenge| challenge.expires_at > now);
        let authentication_pruned =
            authentication_before.saturating_sub(authentication_guard.len());

        Ok((registration_pruned + authentication_pruned) as u64)
    }
}

pub struct InMemorySessionRepository {
    sessions: Mutex<HashMap<String, Session>>,
}

impl InMemorySessionRepository {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn create(&self, session: Session) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(session.id.clone(), session);
        }
    }

    async fn find_by_id(&self, session_id: &str) -> Option<Session> {
        self.sessions.lock().ok()?.get(session_id).cloned()
    }

    async fn list_active_for_user(&self, user_id: &str) -> Vec<Session> {
        let mut sessions = self
            .sessions
            .lock()
            .ok()
            .map(|guard| {
                guard
                    .values()
                    .filter(|session| {
                        session.user_id == user_id && session.status == SessionStatus::Active
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        sessions.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        sessions
    }

    async fn update(&self, session: Session) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(session.id.clone(), session);
        }
    }

    async fn revoke_session(&self, session_id: &str) {
        if let Ok(mut guard) = self.sessions.lock() {
            if let Some(session) = guard.get_mut(session_id) {
                session.status = SessionStatus::Revoked;
                session.last_seen_at = Utc::now();
            }
        }
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Vec<String> {
        let mut revoked_ids = Vec::new();
        if let Ok(mut guard) = self.sessions.lock() {
            for (session_id, session) in guard.iter_mut() {
                if session.user_id == user_id && session.status == SessionStatus::Active {
                    session.status = SessionStatus::Revoked;
                    session.last_seen_at = Utc::now();
                    revoked_ids.push(session_id.clone());
                }
            }
        }
        revoked_ids
    }

    async fn mark_compromised_and_revoke_all_for_user(&self, user_id: &str) -> Vec<String> {
        let mut compromised_ids = Vec::new();
        if let Ok(mut guard) = self.sessions.lock() {
            for (session_id, session) in guard.iter_mut() {
                if session.user_id == user_id {
                    session.status = SessionStatus::Compromised;
                    session.last_seen_at = Utc::now();
                    compromised_ids.push(session_id.clone());
                }
            }
        }
        compromised_ids
    }
}

pub struct InMemoryRefreshTokenRepository {
    tokens_by_hash: Mutex<HashMap<String, RefreshTokenRecord>>,
}

impl InMemoryRefreshTokenRepository {
    fn new() -> Self {
        Self {
            tokens_by_hash: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RefreshTokenRepository for InMemoryRefreshTokenRepository {
    async fn insert(&self, token: RefreshTokenRecord) {
        if let Ok(mut guard) = self.tokens_by_hash.lock() {
            guard.insert(token.token_hash.clone(), token);
        }
    }

    async fn find_by_hash(&self, token_hash: &str) -> Option<RefreshTokenRecord> {
        self.tokens_by_hash.lock().ok()?.get(token_hash).cloned()
    }

    async fn rotate_strong(
        &self,
        current_hash: &str,
        next_token: RefreshTokenRecord,
        now: DateTime<Utc>,
    ) -> Result<RefreshRotationState, String> {
        let mut guard = self
            .tokens_by_hash
            .lock()
            .map_err(|_| "refresh token storage unavailable".to_string())?;

        let Some(current) = guard.get_mut(current_hash) else {
            return Ok(RefreshRotationState::NotFound);
        };

        if current.revoked_at.is_some() {
            return Ok(RefreshRotationState::AlreadyRevoked);
        }
        if current.expires_at <= now {
            current.revoked_at = Some(now);
            return Ok(RefreshRotationState::Expired);
        }

        current.revoked_at = Some(now);
        current.replaced_by = Some(next_token.token_hash.clone());
        guard.insert(next_token.token_hash.clone(), next_token);

        Ok(RefreshRotationState::Rotated)
    }

    async fn rotate(
        &self,
        current_hash: &str,
        next_token: RefreshTokenRecord,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut guard = self
            .tokens_by_hash
            .lock()
            .map_err(|_| "refresh token storage unavailable".to_string())?;
        let current = guard
            .get_mut(current_hash)
            .ok_or_else(|| "current refresh token not found".to_string())?;
        if current.revoked_at.is_some() {
            return Err("refresh token already revoked".to_string());
        }
        current.revoked_at = Some(revoked_at);
        current.replaced_by = Some(next_token.token_hash.clone());
        guard.insert(next_token.token_hash.clone(), next_token);
        Ok(())
    }

    async fn revoke_by_session_ids(&self, session_ids: &[String], revoked_at: DateTime<Utc>) {
        if let Ok(mut guard) = self.tokens_by_hash.lock() {
            for token in guard.values_mut() {
                if session_ids.contains(&token.session_id) && token.revoked_at.is_none() {
                    token.revoked_at = Some(revoked_at);
                }
            }
        }
    }
}

pub struct InMemoryAuditRepository {
    pub events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditRepository {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl AuditRepository for InMemoryAuditRepository {
    async fn append(&self, event: AuditEvent) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event);
        }
    }
}

pub struct JwtEdDsaService {
    encoding_key: EncodingKey,
    decoding_keys_by_kid: HashMap<String, DecodingKey>,
    primary_key_id: String,
    issuer: String,
    audience: String,
}

impl JwtEdDsaService {
    pub fn new(
        jwt_keys: Vec<crate::config::JwtKeyConfig>,
        primary_key_id: String,
        issuer: String,
        audience: String,
    ) -> anyhow::Result<Self> {
        let primary_key = jwt_keys
            .iter()
            .find(|candidate| candidate.kid == primary_key_id)
            .ok_or_else(|| anyhow::anyhow!("missing primary JWT key: {primary_key_id}"))?;
        let signing_private_key = primary_key.private_key_pem.as_deref().ok_or_else(|| {
            anyhow::anyhow!("primary JWT key '{primary_key_id}' is missing private key material")
        })?;

        let encoding_key = EncodingKey::from_ed_pem(signing_private_key.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid JWT_PRIVATE_KEY_PEM"))?;
        let mut decoding_keys_by_kid = HashMap::with_capacity(jwt_keys.len());
        for jwt_key in jwt_keys {
            let decoding_key = DecodingKey::from_ed_pem(jwt_key.public_key_pem.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid JWT public key for kid '{}'", jwt_key.kid))?;
            decoding_keys_by_kid.insert(jwt_key.kid, decoding_key);
        }

        Ok(Self {
            encoding_key,
            decoding_keys_by_kid,
            primary_key_id,
            issuer,
            audience,
        })
    }
}

#[async_trait]
impl JwtService for JwtEdDsaService {
    async fn issue_access_token(&self, claims: &AccessTokenClaims) -> Result<String, String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());
        header.kid = Some(self.primary_key_id.clone());

        encode(&header, claims, &self.encoding_key).map_err(|_| "failed to issue jwt".to_string())
    }

    async fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims, String> {
        let kid = jsonwebtoken::decode_header(token)
            .map_err(|_| "invalid jwt".to_string())?
            .kid
            .ok_or_else(|| "jwt missing kid".to_string())?;
        let decoding_key = self
            .decoding_keys_by_kid
            .get(&kid)
            .ok_or_else(|| "invalid jwt kid".to_string())?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = true;
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        decode::<AccessTokenClaims>(token, decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|_| "invalid jwt".to_string())
    }
}

struct LoginAttemptState {
    failed_attempts: Vec<DateTime<Utc>>,
    lock_until: Option<DateTime<Utc>>,
    lock_strikes: u32,
    last_failure_at: Option<DateTime<Utc>>,
}

pub struct InMemoryLoginAbuseProtector {
    attempts_by_key: Mutex<HashMap<String, LoginAttemptState>>,
    max_attempts: u32,
    window_seconds: i64,
    lockout_base_seconds: i64,
    lockout_max_seconds: i64,
    bucket_mode: LoginAbuseBucketMode,
}

impl InMemoryLoginAbuseProtector {
    fn new(
        max_attempts: u32,
        window_seconds: i64,
        lockout_base_seconds: i64,
        lockout_max_seconds: i64,
        bucket_mode: LoginAbuseBucketMode,
    ) -> anyhow::Result<Self> {
        if max_attempts == 0 {
            return Err(anyhow::anyhow!("LOGIN_MAX_ATTEMPTS must be greater than 0"));
        }
        if window_seconds <= 0 {
            return Err(anyhow::anyhow!(
                "LOGIN_ATTEMPT_WINDOW_SECONDS must be greater than 0"
            ));
        }
        if lockout_base_seconds <= 0 {
            return Err(anyhow::anyhow!(
                "LOGIN_LOCKOUT_SECONDS must be greater than 0"
            ));
        }
        if lockout_max_seconds < lockout_base_seconds {
            return Err(anyhow::anyhow!(
                "LOGIN_LOCKOUT_MAX_SECONDS must be greater than or equal to LOGIN_LOCKOUT_SECONDS"
            ));
        }

        Ok(Self {
            attempts_by_key: Mutex::new(HashMap::new()),
            max_attempts,
            window_seconds,
            lockout_base_seconds,
            lockout_max_seconds,
            bucket_mode,
        })
    }

    fn lockout_seconds_for_strikes(&self, strikes: u32) -> i64 {
        let mut seconds = self.lockout_base_seconds.max(1);

        for _ in 1..strikes {
            seconds = seconds.saturating_mul(2);
            if seconds >= self.lockout_max_seconds {
                return self.lockout_max_seconds;
            }
        }

        seconds.min(self.lockout_max_seconds)
    }

    fn decay_stale_state(&self, state: &mut LoginAttemptState, now: DateTime<Utc>) {
        let Some(last_failure_at) = state.last_failure_at else {
            return;
        };

        let decay_deadline = last_failure_at + chrono::Duration::seconds(self.window_seconds);
        if now >= decay_deadline {
            state.lock_strikes = 0;
            state.failed_attempts.clear();
            state.last_failure_at = None;
        }
    }

    fn source_bucket_key(email: &str, source_ip: Option<&str>) -> String {
        let ip_part = source_ip
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("no-ip")
            .to_ascii_lowercase();
        format!("{}|{}", email.to_ascii_lowercase(), ip_part)
    }

    fn abuse_keys(
        email: &str,
        source_ip: Option<&str>,
        bucket_mode: LoginAbuseBucketMode,
    ) -> Vec<String> {
        let source_bucket_key = Self::source_bucket_key(email, source_ip);
        match bucket_mode {
            LoginAbuseBucketMode::IpOnly => vec![source_bucket_key],
            LoginAbuseBucketMode::EmailAndIp => {
                vec![
                    format!("{}|any", email.to_ascii_lowercase()),
                    source_bucket_key,
                ]
            }
        }
    }
}

#[async_trait]
impl LoginAbuseProtector for InMemoryLoginAbuseProtector {
    async fn check(
        &self,
        email: &str,
        source_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> LoginGateDecision {
        let abuse_keys = Self::abuse_keys(email, source_ip, self.bucket_mode);
        let Ok(mut guard) = self.attempts_by_key.lock() else {
            return LoginGateDecision::Allowed;
        };

        let mut locked_until: Option<DateTime<Utc>> = None;
        for abuse_key in abuse_keys {
            let Some(state) = guard.get_mut(&abuse_key) else {
                continue;
            };
            self.decay_stale_state(state, now);

            if let Some(lock_until) = state.lock_until {
                if lock_until > now {
                    locked_until = Some(match locked_until {
                        Some(current) if current > lock_until => current,
                        _ => lock_until,
                    });
                    continue;
                }
                state.lock_until = None;
                state.failed_attempts.clear();
            }
        }

        match locked_until {
            Some(until) => LoginGateDecision::Locked { until },
            None => LoginGateDecision::Allowed,
        }
    }

    async fn register_failure(
        &self,
        email: &str,
        source_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let abuse_keys = Self::abuse_keys(email, source_ip, self.bucket_mode);
        let Ok(mut guard) = self.attempts_by_key.lock() else {
            return None;
        };

        let mut lock_until: Option<DateTime<Utc>> = None;

        for abuse_key in abuse_keys {
            let state = guard.entry(abuse_key).or_insert(LoginAttemptState {
                failed_attempts: Vec::new(),
                lock_until: None,
                lock_strikes: 0,
                last_failure_at: None,
            });
            self.decay_stale_state(state, now);

            if let Some(current_lock_until) = state.lock_until {
                if current_lock_until > now {
                    lock_until = Some(match lock_until {
                        Some(current) if current > current_lock_until => current,
                        _ => current_lock_until,
                    });
                    continue;
                }
                state.lock_until = None;
                state.failed_attempts.clear();
            }

            let window_start = now - chrono::Duration::seconds(self.window_seconds);
            state
                .failed_attempts
                .retain(|attempt| *attempt >= window_start);
            state.failed_attempts.push(now);
            state.last_failure_at = Some(now);

            if state.failed_attempts.len() >= self.max_attempts as usize {
                state.lock_strikes = state.lock_strikes.saturating_add(1);
                let lockout_seconds = self.lockout_seconds_for_strikes(state.lock_strikes);
                let current_lock_until = now + chrono::Duration::seconds(lockout_seconds);
                state.lock_until = Some(current_lock_until);
                state.failed_attempts.clear();
                lock_until = Some(match lock_until {
                    Some(current) if current > current_lock_until => current,
                    _ => current_lock_until,
                });
            }
        }

        lock_until
    }

    async fn register_success(&self, email: &str, source_ip: Option<&str>) {
        let abuse_keys = Self::abuse_keys(email, source_ip, self.bucket_mode);
        if let Ok(mut guard) = self.attempts_by_key.lock() {
            for abuse_key in abuse_keys {
                guard.remove(&abuse_key);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn seconds_between(start: DateTime<Utc>, end: DateTime<Utc>) -> i64 {
        (end - start).num_seconds()
    }

    fn jwt_claims(now: DateTime<Utc>) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: "user-1".to_string(),
            sid: "session-1".to_string(),
            iss: TEST_JWT_ISSUER.to_string(),
            aud: TEST_JWT_AUDIENCE.to_string(),
            iat: now.timestamp(),
            exp: (now + chrono::Duration::minutes(5)).timestamp(),
        }
    }

    fn jwt_key(
        kid: &str,
        include_private: bool,
        private_key_pem: &str,
        public_key_pem: &str,
    ) -> crate::config::JwtKeyConfig {
        crate::config::JwtKeyConfig {
            kid: kid.to_string(),
            private_key_pem: include_private.then(|| private_key_pem.to_string()),
            public_key_pem: public_key_pem.to_string(),
        }
    }

    const TEST_JWT_ISSUER: &str = "auth-tests";
    const TEST_JWT_AUDIENCE: &str = "auth-clients";
    const TEST_PRIVATE_KEY_PEM_V1: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIMn3Wcxxd4JzzjbshVFXz8jSGuF9ErqngPTzYhbfm6hd\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM_V1: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdIROjbNDN9NHACJMCdMbdRjmUZp05u0E+QVRzrqB6eM=\n-----END PUBLIC KEY-----\n";
    const TEST_PRIVATE_KEY_PEM_V2: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHKXEA5E1r7pR80Ucu171MabNn+ku13GSavWIB/BKqmv\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM_V2: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA3Pt04RjQQMO4XZTq01rN87smwi6wkOTzBX7P5z6DI/M=\n-----END PUBLIC KEY-----\n";

    #[tokio::test]
    async fn lockout_backoff_doubles_until_max() {
        let protector =
            InMemoryLoginAbuseProtector::new(1, 300, 10, 40, LoginAbuseBucketMode::IpOnly)
                .expect("in-memory abuse protector should initialize");
        let email = "user@example.com";
        let ip = Some("10.0.0.5");

        let first_now = Utc::now();
        let first_until = protector
            .register_failure(email, ip, first_now)
            .await
            .expect("first lockout should be generated");
        assert_eq!(seconds_between(first_now, first_until), 10);

        let second_now = first_until + chrono::Duration::seconds(1);
        let second_until = protector
            .register_failure(email, ip, second_now)
            .await
            .expect("second lockout should be generated");
        assert_eq!(seconds_between(second_now, second_until), 20);

        let third_now = second_until + chrono::Duration::seconds(1);
        let third_until = protector
            .register_failure(email, ip, third_now)
            .await
            .expect("third lockout should be generated");
        assert_eq!(seconds_between(third_now, third_until), 40);

        let fourth_now = third_until + chrono::Duration::seconds(1);
        let fourth_until = protector
            .register_failure(email, ip, fourth_now)
            .await
            .expect("fourth lockout should be generated");
        assert_eq!(seconds_between(fourth_now, fourth_until), 40);
    }

    #[tokio::test]
    async fn lockout_backoff_resets_after_decay_window() {
        let protector =
            InMemoryLoginAbuseProtector::new(1, 60, 10, 40, LoginAbuseBucketMode::IpOnly)
                .expect("in-memory abuse protector should initialize");
        let email = "user@example.com";
        let ip = Some("10.0.0.6");

        let first_now = Utc::now();
        let first_until = protector
            .register_failure(email, ip, first_now)
            .await
            .expect("first lockout should be generated");
        assert_eq!(seconds_between(first_now, first_until), 10);

        let decayed_now = first_now + chrono::Duration::seconds(61);
        let decayed_until = protector
            .register_failure(email, ip, decayed_now)
            .await
            .expect("lockout should still be generated after decay");
        assert_eq!(seconds_between(decayed_now, decayed_until), 10);
    }

    #[tokio::test]
    async fn lockout_backoff_clears_on_success() {
        let protector =
            InMemoryLoginAbuseProtector::new(1, 300, 10, 40, LoginAbuseBucketMode::IpOnly)
                .expect("in-memory abuse protector should initialize");
        let email = "user@example.com";
        let ip = Some("10.0.0.7");

        let first_now = Utc::now();
        let first_until = protector
            .register_failure(email, ip, first_now)
            .await
            .expect("first lockout should be generated");
        assert_eq!(seconds_between(first_now, first_until), 10);

        protector.register_success(email, ip).await;

        let second_now = first_now + chrono::Duration::seconds(2);
        let second_until = protector
            .register_failure(email, ip, second_now)
            .await
            .expect("lockout should be generated after reset");
        assert_eq!(seconds_between(second_now, second_until), 10);
    }

    #[tokio::test]
    async fn batched_auth_flow_penalties_follow_existing_lockout_progression() {
        let protector =
            InMemoryLoginAbuseProtector::new(5, 300, 10, 40, LoginAbuseBucketMode::IpOnly)
                .expect("in-memory abuse protector should initialize");
        let email = "user@example.com";
        let ip = Some("10.0.0.8");

        let first_now = Utc::now();
        for attempt in 0..4 {
            let result = protector.register_failure(email, ip, first_now).await;
            assert!(
                result.is_none(),
                "attempt {attempt} should not lock before the threshold"
            );
        }
        let first_until = protector
            .register_failure(email, ip, first_now)
            .await
            .expect("fifth penalty unit should lock like a normal failure threshold");
        assert_eq!(seconds_between(first_now, first_until), 10);

        let second_now = first_until + chrono::Duration::seconds(1);
        for attempt in 0..4 {
            let result = protector.register_failure(email, ip, second_now).await;
            assert!(
                result.is_none(),
                "repeat attempt {attempt} should rebuild the threshold after the prior lock expires"
            );
        }
        let second_until = protector
            .register_failure(email, ip, second_now)
            .await
            .expect("next penalty batch should advance the strike backoff");
        assert_eq!(seconds_between(second_now, second_until), 20);
    }

    fn refresh_record(
        token_hash: &str,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> RefreshTokenRecord {
        RefreshTokenRecord {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            token_hash: token_hash.to_string(),
            expires_at: now + chrono::Duration::seconds(300),
            revoked_at: None,
            replaced_by: None,
            created_at: now,
        }
    }

    #[tokio::test]
    async fn refresh_rotate_strong_returns_not_found_when_current_missing() {
        let repo = InMemoryRefreshTokenRepository::new();
        let now = Utc::now();
        let next_token = refresh_record("next-hash", "session-1", now);

        let result = repo.rotate_strong("missing-hash", next_token, now).await;
        assert!(matches!(result, Ok(RefreshRotationState::NotFound)));
    }

    #[tokio::test]
    async fn refresh_rotate_strong_returns_expired_and_marks_current_revoked() {
        let repo = InMemoryRefreshTokenRepository::new();
        let now = Utc::now();
        let expired_hash = "expired-hash";
        let mut expired = refresh_record(expired_hash, "session-1", now);
        expired.expires_at = now - chrono::Duration::seconds(1);
        repo.insert(expired).await;

        let result = repo
            .rotate_strong(
                expired_hash,
                refresh_record("next-hash", "session-1", now),
                now,
            )
            .await;
        assert!(matches!(result, Ok(RefreshRotationState::Expired)));

        let stored_expired = repo
            .find_by_hash(expired_hash)
            .await
            .expect("expired token should still exist");
        assert_eq!(stored_expired.revoked_at, Some(now));
        assert!(repo.find_by_hash("next-hash").await.is_none());
    }

    #[tokio::test]
    async fn refresh_rotate_strong_returns_already_revoked_for_replayed_token() {
        let repo = InMemoryRefreshTokenRepository::new();
        let now = Utc::now();
        let revoked_hash = "revoked-hash";
        let mut revoked = refresh_record(revoked_hash, "session-1", now);
        revoked.revoked_at = Some(now - chrono::Duration::seconds(1));
        repo.insert(revoked).await;

        let result = repo
            .rotate_strong(
                revoked_hash,
                refresh_record("next-hash", "session-1", now),
                now,
            )
            .await;
        assert!(matches!(result, Ok(RefreshRotationState::AlreadyRevoked)));
        assert!(repo.find_by_hash("next-hash").await.is_none());
    }

    #[tokio::test]
    async fn refresh_rotate_strong_rotates_and_links_replacement_on_success() {
        let repo = InMemoryRefreshTokenRepository::new();
        let now = Utc::now();
        let current_hash = "current-hash";
        let next_hash = "next-hash";

        repo.insert(refresh_record(current_hash, "session-1", now))
            .await;

        let result = repo
            .rotate_strong(
                current_hash,
                refresh_record(next_hash, "session-1", now),
                now,
            )
            .await;
        assert!(matches!(result, Ok(RefreshRotationState::Rotated)));

        let current = repo
            .find_by_hash(current_hash)
            .await
            .expect("current token should exist");
        assert_eq!(current.revoked_at, Some(now));
        assert_eq!(current.replaced_by.as_deref(), Some(next_hash));

        let next = repo
            .find_by_hash(next_hash)
            .await
            .expect("next token should be inserted");
        assert_eq!(next.session_id, "session-1");
        assert!(next.revoked_at.is_none());
    }

    #[tokio::test]
    async fn jwt_rotation_overlap_keeps_old_tokens_valid_while_old_key_remains() {
        let now = Utc::now();
        let old_key_id = "auth-ed25519-v1";
        let new_key_id = "auth-ed25519-v2";
        let old_signer = JwtEdDsaService::new(
            vec![jwt_key(
                old_key_id,
                true,
                TEST_PRIVATE_KEY_PEM_V1,
                TEST_PUBLIC_KEY_PEM_V1,
            )],
            old_key_id.to_string(),
            TEST_JWT_ISSUER.to_string(),
            TEST_JWT_AUDIENCE.to_string(),
        )
        .expect("old signer should initialize");
        let token = old_signer
            .issue_access_token(&jwt_claims(now))
            .await
            .expect("token should be issued with old key");

        let overlap_service = JwtEdDsaService::new(
            vec![
                jwt_key(
                    new_key_id,
                    true,
                    TEST_PRIVATE_KEY_PEM_V2,
                    TEST_PUBLIC_KEY_PEM_V2,
                ),
                jwt_key(
                    old_key_id,
                    false,
                    TEST_PRIVATE_KEY_PEM_V1,
                    TEST_PUBLIC_KEY_PEM_V1,
                ),
            ],
            new_key_id.to_string(),
            TEST_JWT_ISSUER.to_string(),
            TEST_JWT_AUDIENCE.to_string(),
        )
        .expect("overlap service should initialize");

        let validated = overlap_service
            .validate_access_token(&token)
            .await
            .expect("old token should validate during overlap window");
        assert_eq!(validated.sub, "user-1");
    }

    #[tokio::test]
    async fn jwt_rotation_retiring_old_key_invalidates_old_tokens() {
        let now = Utc::now();
        let old_key_id = "auth-ed25519-v1";
        let new_key_id = "auth-ed25519-v2";
        let old_signer = JwtEdDsaService::new(
            vec![jwt_key(
                old_key_id,
                true,
                TEST_PRIVATE_KEY_PEM_V1,
                TEST_PUBLIC_KEY_PEM_V1,
            )],
            old_key_id.to_string(),
            TEST_JWT_ISSUER.to_string(),
            TEST_JWT_AUDIENCE.to_string(),
        )
        .expect("old signer should initialize");
        let token = old_signer
            .issue_access_token(&jwt_claims(now))
            .await
            .expect("token should be issued with old key");

        let post_retirement_service = JwtEdDsaService::new(
            vec![jwt_key(
                new_key_id,
                true,
                TEST_PRIVATE_KEY_PEM_V2,
                TEST_PUBLIC_KEY_PEM_V2,
            )],
            new_key_id.to_string(),
            TEST_JWT_ISSUER.to_string(),
            TEST_JWT_AUDIENCE.to_string(),
        )
        .expect("post-retirement service should initialize");

        let error = post_retirement_service
            .validate_access_token(&token)
            .await
            .expect_err("old token should fail once old key is removed");
        assert_eq!(error, "invalid jwt kid");
    }

    #[tokio::test]
    async fn jwt_issue_access_token_uses_configured_primary_kid() {
        let now = Utc::now();
        let old_key_id = "auth-ed25519-v1";
        let new_key_id = "auth-ed25519-v2";
        let signer = JwtEdDsaService::new(
            vec![
                jwt_key(
                    old_key_id,
                    false,
                    TEST_PRIVATE_KEY_PEM_V1,
                    TEST_PUBLIC_KEY_PEM_V1,
                ),
                jwt_key(
                    new_key_id,
                    true,
                    TEST_PRIVATE_KEY_PEM_V2,
                    TEST_PUBLIC_KEY_PEM_V2,
                ),
            ],
            new_key_id.to_string(),
            TEST_JWT_ISSUER.to_string(),
            TEST_JWT_AUDIENCE.to_string(),
        )
        .expect("signer should initialize");

        let token = signer
            .issue_access_token(&jwt_claims(now))
            .await
            .expect("token should be issued");

        let header = jsonwebtoken::decode_header(&token).expect("jwt header should decode");
        assert_eq!(header.kid.as_deref(), Some(new_key_id));
    }
}

pub struct RefreshCryptoHmacService {
    pepper: String,
}

impl RefreshCryptoHmacService {
    pub fn new(pepper: String) -> Self {
        Self { pepper }
    }
}

#[async_trait]
impl RefreshCryptoService for RefreshCryptoHmacService {
    async fn generate_refresh_token(&self) -> String {
        let mut buffer = [0u8; 32];
        OsRng.fill_bytes(&mut buffer);
        URL_SAFE_NO_PAD.encode(buffer)
    }

    async fn hash_refresh_token(&self, token: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.pepper.as_bytes())
            .expect("hmac accepts any key length");
        mac.update(token.as_bytes());
        let output = mac.finalize().into_bytes();
        URL_SAFE_NO_PAD.encode(output)
    }
}
