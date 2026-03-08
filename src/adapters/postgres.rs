use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::{
    adapters::outbox::PostgresEmailOutboxRepository,
    config::AppConfig,
    modules::{
        audit::{domain::AuditEvent, ports::AuditRepository},
        auth::{
            domain::{
                AccountRecord, AccountStatus, AuthFlowKind, AuthFlowRecord, AuthFlowStatus,
                LegacyPasswordRecord, MfaChallengeRecord, MfaFactorRecord, OpaqueCredentialRecord,
                OpaqueCredentialState, PasswordResetTokenRecord, User, UserStatus,
                VerificationTokenRecord,
            },
            ports::{
                AccountRepository, AuthFlowConsumeState, AuthFlowMetricBucket,
                AuthFlowMetricsSnapshot, AuthFlowRepository, LegacyPasswordRepository,
                MfaBackupCodeConsumeState, MfaBackupCodeRepository, MfaChallengeFailureState,
                MfaChallengeLookupState, MfaChallengeRepository, MfaFactorRepository,
                OpaqueCredentialRepository, PasskeyAuthenticationChallengeConsumeState,
                PasskeyAuthenticationChallengeRecord, PasskeyChallengeRepository,
                PasskeyCredentialRepository, PasskeyRegistrationChallengeConsumeState,
                PasskeyRegistrationChallengeRecord, PasswordResetTokenConsumeState,
                PasswordResetTokenRepository, UserRepository, VerificationTokenConsumeState,
                VerificationTokenRepository,
            },
        },
        sessions::{
            domain::{Session, SessionStatus},
            ports::SessionRepository,
        },
        tokens::{
            domain::RefreshTokenRecord,
            ports::{RefreshRotationState, RefreshTokenRepository},
        },
    },
};

#[derive(Clone)]
pub struct PostgresAdapters {
    pub pool: PgPool,
    pub users: PostgresUserRepository,
    pub accounts: PostgresAccountRepository,
    pub legacy_passwords: PostgresLegacyPasswordRepository,
    pub opaque_credentials: PostgresOpaqueCredentialRepository,
    pub auth_flows: PostgresAuthFlowRepository,
    pub verification_tokens: PostgresVerificationTokenRepository,
    pub password_reset_tokens: PostgresPasswordResetTokenRepository,
    pub mfa_factors: PostgresMfaFactorRepository,
    pub mfa_challenges: PostgresMfaChallengeRepository,
    pub mfa_backup_codes: PostgresMfaBackupCodeRepository,
    pub passkeys: PostgresPasskeyCredentialRepository,
    pub passkey_challenges: PostgresPasskeyChallengeRepository,
    pub sessions: PostgresSessionRepository,
    pub refresh_tokens: PostgresRefreshTokenRepository,
    pub audit: PostgresAuditRepository,
    pub email_outbox: PostgresEmailOutboxRepository,
}

impl PostgresAdapters {
    pub async fn bootstrap(cfg: &AppConfig) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(cfg.database_max_connections)
            .connect(&cfg.database_url)
            .await?;

        run_migrations(&pool).await?;

        let users = PostgresUserRepository { pool: pool.clone() };
        let accounts = PostgresAccountRepository { pool: pool.clone() };
        let legacy_passwords = PostgresLegacyPasswordRepository { pool: pool.clone() };
        users.ensure_bootstrap_user(cfg).await?;

        Ok(Self {
            pool: pool.clone(),
            users,
            accounts,
            legacy_passwords,
            opaque_credentials: PostgresOpaqueCredentialRepository { pool: pool.clone() },
            auth_flows: PostgresAuthFlowRepository { pool: pool.clone() },
            verification_tokens: PostgresVerificationTokenRepository { pool: pool.clone() },
            password_reset_tokens: PostgresPasswordResetTokenRepository { pool: pool.clone() },
            mfa_factors: PostgresMfaFactorRepository { pool: pool.clone() },
            mfa_challenges: PostgresMfaChallengeRepository { pool: pool.clone() },
            mfa_backup_codes: PostgresMfaBackupCodeRepository { pool: pool.clone() },
            passkeys: PostgresPasskeyCredentialRepository { pool: pool.clone() },
            passkey_challenges: PostgresPasskeyChallengeRepository { pool: pool.clone() },
            sessions: PostgresSessionRepository { pool: pool.clone() },
            refresh_tokens: PostgresRefreshTokenRepository { pool: pool.clone() },
            audit: PostgresAuditRepository { pool: pool.clone() },
            email_outbox: PostgresEmailOutboxRepository { pool },
        })
    }
}

pub(crate) async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let migrations_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let migrator = sqlx::migrate::Migrator::new(migrations_path.as_path()).await?;
    migrator.run(pool).await
}

#[derive(Clone)]
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    async fn ensure_bootstrap_user(&self, cfg: &AppConfig) -> anyhow::Result<()> {
        match (&cfg.bootstrap_user_email, &cfg.bootstrap_user_password) {
            (Some(email), Some(password)) => {
                let mut tx = self.pool.begin().await?;
                let email = email.to_ascii_lowercase();

                let exists = sqlx::query("SELECT id FROM users WHERE email = $1")
                    .bind(&email)
                    .fetch_optional(&mut *tx)
                    .await?
                    .is_some();
                if exists {
                    tx.commit().await?;
                    return Ok(());
                }

                let user_id = Uuid::new_v4().to_string();
                let password_hash = {
                    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
                    Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .map_err(|_| anyhow::anyhow!("failed to hash BOOTSTRAP_USER_PASSWORD"))?
                        .to_string()
                };

                sqlx::query(
                    "INSERT INTO users (id, email, status, created_at, updated_at) VALUES ($1::uuid, $2, $3, NOW(), NOW())",
                )
                .bind(&user_id)
                .bind(&email)
                .bind("active")
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO credentials (user_id, password_hash, password_changed_at) VALUES ($1::uuid, $2, NOW())",
                )
                .bind(&user_id)
                .bind(&password_hash)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                Ok(())
            }
            (None, None) => Ok(()),
            _ => {
                tracing::warn!(
                    "bootstrap user disabled: set both BOOTSTRAP_USER_EMAIL and BOOTSTRAP_USER_PASSWORD"
                );
                Ok(())
            }
        }
    }

    async fn account_by_email(&self, email: &str) -> Option<AccountRecord> {
        fetch_account_by_email(&self.pool, email).await
    }

    async fn account_by_id(&self, user_id: &str) -> Option<AccountRecord> {
        fetch_account_by_id(&self.pool, user_id).await
    }

    async fn legacy_password_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<LegacyPasswordRecord>, String> {
        fetch_legacy_password_by_user_id(&self.pool, user_id).await
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_email(&self, email: &str) -> Option<User> {
        let account = self.account_by_email(email).await?;
        let password = self.legacy_password_by_user_id(&account.id).await.ok()??;

        Some(User {
            id: account.id,
            email: account.email,
            password_hash: password.password_hash,
            status: account_status_to_user_status(account.status),
        })
    }

    async fn find_by_id(&self, user_id: &str) -> Option<User> {
        let account = self.account_by_id(user_id).await?;
        let password = self.legacy_password_by_user_id(&account.id).await.ok()??;

        Some(User {
            id: account.id,
            email: account.email,
            password_hash: password.password_hash,
            status: account_status_to_user_status(account.status),
        })
    }

    async fn create_pending_user(
        &self,
        email: &str,
        password_hash: &str,
    ) -> Result<Option<User>, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "user transaction begin failed".to_string())?;

        let user_id = Uuid::new_v4().to_string();
        let inserted = sqlx::query(
            "INSERT INTO users (id, email, status, created_at, updated_at)
             VALUES ($1::uuid, $2, 'pending_verification', NOW(), NOW())
             ON CONFLICT (email) DO NOTHING
             RETURNING id::text AS id",
        )
        .bind(&user_id)
        .bind(email.to_ascii_lowercase())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "user insert failed".to_string())?;

        let Some(_row) = inserted else {
            tx.rollback().await.ok();
            return Ok(None);
        };

        sqlx::query(
            "INSERT INTO credentials (user_id, password_hash, password_changed_at)
             VALUES ($1::uuid, $2, NOW())",
        )
        .bind(&user_id)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|_| "credential insert failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "user transaction commit failed".to_string())?;

        Ok(Some(User {
            id: user_id,
            email: email.to_ascii_lowercase(),
            password_hash: password_hash.to_string(),
            status: UserStatus::PendingVerification,
        }))
    }

    async fn activate_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE users
             SET status = 'active', email_verified_at = $2, updated_at = $2
             WHERE id = $1::uuid",
        )
        .bind(user_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "user activation failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("user not found".to_string());
        }

        Ok(())
    }

    async fn update_password(
        &self,
        user_id: &str,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE credentials
             SET password_hash = $2, password_changed_at = $3
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "password update failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("user credentials not found".to_string());
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresAccountRepository {
    pool: PgPool,
}

#[async_trait]
impl AccountRepository for PostgresAccountRepository {
    async fn find_by_email(&self, email: &str) -> Option<AccountRecord> {
        fetch_account_by_email(&self.pool, email).await
    }

    async fn find_by_id(&self, user_id: &str) -> Option<AccountRecord> {
        fetch_account_by_id(&self.pool, user_id).await
    }

    async fn create_pending(
        &self,
        email: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AccountRecord>, String> {
        let user_id = Uuid::new_v4().to_string();
        let row = sqlx::query(
            "INSERT INTO users (id, email, status, created_at, updated_at)
             VALUES ($1::uuid, $2, 'pending_verification', $3, $3)
             ON CONFLICT (email) DO NOTHING
             RETURNING id::text AS id, email, status, created_at, updated_at",
        )
        .bind(&user_id)
        .bind(email.to_ascii_lowercase())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "account insert failed".to_string())?;

        row.map(account_from_row).transpose()
    }

    async fn activate(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE users
             SET status = 'active', email_verified_at = $2, updated_at = $2
             WHERE id = $1::uuid",
        )
        .bind(user_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "account activation failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("account not found".to_string());
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresLegacyPasswordRepository {
    pool: PgPool,
}

#[async_trait]
impl LegacyPasswordRepository for PostgresLegacyPasswordRepository {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Option<LegacyPasswordRecord>, String> {
        fetch_legacy_password_by_user_id(&self.pool, user_id).await
    }

    async fn upsert_hash(
        &self,
        user_id: &str,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO credentials (
                user_id,
                password_hash,
                password_changed_at,
                legacy_login_allowed,
                migrated_to_opaque_at,
                last_legacy_verified_at,
                legacy_deprecation_at
             )
             VALUES ($1::uuid, $2, $3, TRUE, NULL, NULL, NULL)
             ON CONFLICT (user_id)
             DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                password_changed_at = EXCLUDED.password_changed_at,
                legacy_login_allowed = TRUE,
                migrated_to_opaque_at = NULL,
                legacy_deprecation_at = NULL",
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "legacy password upsert failed".to_string())?;

        Ok(())
    }

    async fn mark_verified(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE credentials
             SET last_legacy_verified_at = $2
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "legacy password verification mark failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("legacy password not found".to_string());
        }

        Ok(())
    }

    async fn mark_upgraded_to_opaque(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE credentials
             SET migrated_to_opaque_at = COALESCE(migrated_to_opaque_at, $2),
                 last_legacy_verified_at = $2
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "legacy password upgrade mark failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("legacy password not found".to_string());
        }

        Ok(())
    }

    async fn set_legacy_login_allowed(
        &self,
        user_id: &str,
        allowed: bool,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE credentials
             SET legacy_login_allowed = $2,
                 legacy_deprecation_at = CASE WHEN $2 THEN NULL ELSE COALESCE(legacy_deprecation_at, $3) END
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(allowed)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "legacy password policy update failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("legacy password not found".to_string());
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresOpaqueCredentialRepository {
    pool: PgPool,
}

#[async_trait]
impl OpaqueCredentialRepository for PostgresOpaqueCredentialRepository {
    async fn find_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<OpaqueCredentialRecord>, String> {
        let row = sqlx::query(
            "SELECT user_id::text AS user_id, protocol, credential_blob, server_key_ref,
                    envelope_kms_key_id, state, migrated_from_legacy_at, last_verified_at,
                    created_at, updated_at
             FROM opaque_credentials
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "opaque credential fetch failed".to_string())?;

        row.map(opaque_credential_from_row).transpose()
    }

    async fn upsert_for_user(&self, record: OpaqueCredentialRecord) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO opaque_credentials (
                user_id,
                protocol,
                credential_blob,
                server_key_ref,
                envelope_kms_key_id,
                state,
                migrated_from_legacy_at,
                last_verified_at,
                created_at,
                updated_at
             )
             VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (user_id)
             DO UPDATE SET
                protocol = EXCLUDED.protocol,
                credential_blob = EXCLUDED.credential_blob,
                server_key_ref = EXCLUDED.server_key_ref,
                envelope_kms_key_id = EXCLUDED.envelope_kms_key_id,
                state = EXCLUDED.state,
                migrated_from_legacy_at = EXCLUDED.migrated_from_legacy_at,
                last_verified_at = EXCLUDED.last_verified_at,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(record.user_id)
        .bind(record.protocol)
        .bind(record.credential_blob)
        .bind(record.server_key_ref)
        .bind(record.envelope_kms_key_id)
        .bind(opaque_credential_state_to_db(&record.state))
        .bind(record.migrated_from_legacy_at)
        .bind(record.last_verified_at)
        .bind(record.created_at)
        .bind(record.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "opaque credential upsert failed".to_string())?;

        Ok(())
    }

    async fn mark_verified(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE opaque_credentials
             SET last_verified_at = $2, updated_at = $2
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "opaque credential verify mark failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("opaque credential not found".to_string());
        }

        Ok(())
    }

    async fn revoke_for_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE opaque_credentials
             SET state = 'revoked', updated_at = $2
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "opaque credential revoke failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("opaque credential not found".to_string());
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresAuthFlowRepository {
    pool: PgPool,
}

#[async_trait]
impl AuthFlowRepository for PostgresAuthFlowRepository {
    async fn issue(&self, flow: AuthFlowRecord) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO auth_flows (
                flow_id,
                subject_user_id,
                subject_identifier_hash,
                flow_kind,
                protocol,
                state,
                status,
                rollout_channel,
                fallback_policy,
                trace_id,
                issued_ip,
                issued_user_agent,
                attempt_count,
                expires_at,
                consumed_at,
                created_at,
                updated_at
             )
             VALUES ($1, $2::uuid, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11::inet, $12, $13, $14, $15, $16, $17)
             ON CONFLICT (flow_id)
             DO UPDATE SET
                subject_user_id = EXCLUDED.subject_user_id,
                subject_identifier_hash = EXCLUDED.subject_identifier_hash,
                flow_kind = EXCLUDED.flow_kind,
                protocol = EXCLUDED.protocol,
                state = EXCLUDED.state,
                status = EXCLUDED.status,
                rollout_channel = EXCLUDED.rollout_channel,
                fallback_policy = EXCLUDED.fallback_policy,
                trace_id = EXCLUDED.trace_id,
                issued_ip = EXCLUDED.issued_ip,
                issued_user_agent = EXCLUDED.issued_user_agent,
                attempt_count = EXCLUDED.attempt_count,
                expires_at = EXCLUDED.expires_at,
                consumed_at = EXCLUDED.consumed_at,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(flow.flow_id)
        .bind(flow.subject_user_id)
        .bind(flow.subject_identifier_hash)
        .bind(auth_flow_kind_to_db(&flow.flow_kind))
        .bind(flow.protocol)
        .bind(flow.state)
        .bind(auth_flow_status_to_db(&flow.status))
        .bind(flow.rollout_channel)
        .bind(flow.fallback_policy)
        .bind(flow.trace_id)
        .bind(flow.issued_ip)
        .bind(flow.issued_user_agent)
        .bind(flow.attempt_count as i32)
        .bind(flow.expires_at)
        .bind(flow.consumed_at)
        .bind(flow.created_at)
        .bind(flow.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "auth flow upsert failed".to_string())?;

        Ok(())
    }

    async fn consume(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthFlowConsumeState, String> {
        let row = sqlx::query(
            "UPDATE auth_flows
             SET status = 'consumed', consumed_at = $2, updated_at = $2
             WHERE flow_id = $1 AND status = 'pending' AND expires_at > $2
             RETURNING flow_id, subject_user_id::text AS subject_user_id, subject_identifier_hash,
                       flow_kind, protocol, state, status, rollout_channel, fallback_policy,
                       trace_id, issued_ip::text AS issued_ip, issued_user_agent, attempt_count,
                       expires_at, consumed_at, created_at, updated_at",
        )
        .bind(flow_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "auth flow consume failed".to_string())?;

        if let Some(row) = row {
            return Ok(AuthFlowConsumeState::Active(Box::new(auth_flow_from_row(
                row,
            )?)));
        }

        let row = sqlx::query(
            "SELECT flow_id, subject_user_id::text AS subject_user_id, subject_identifier_hash,
                    flow_kind, protocol, state, status, rollout_channel, fallback_policy,
                    trace_id, issued_ip::text AS issued_ip, issued_user_agent, attempt_count,
                    expires_at, consumed_at, created_at, updated_at
             FROM auth_flows
             WHERE flow_id = $1",
        )
        .bind(flow_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "auth flow fetch failed".to_string())?;

        let Some(row) = row else {
            return Ok(AuthFlowConsumeState::NotFound);
        };

        let record = auth_flow_from_row(row)?;
        if record.expires_at <= now {
            return Ok(AuthFlowConsumeState::Expired);
        }

        Ok(match record.status {
            AuthFlowStatus::Consumed => AuthFlowConsumeState::AlreadyConsumed,
            AuthFlowStatus::Cancelled => AuthFlowConsumeState::Cancelled,
            AuthFlowStatus::Expired => AuthFlowConsumeState::Expired,
            AuthFlowStatus::Pending => AuthFlowConsumeState::AlreadyConsumed,
        })
    }

    async fn increment_attempts(&self, flow_id: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE auth_flows
             SET attempt_count = attempt_count + 1, updated_at = $2
             WHERE flow_id = $1",
        )
        .bind(flow_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "auth flow attempt increment failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("auth flow not found".to_string());
        }

        Ok(())
    }

    async fn cancel_active_for_subject(
        &self,
        subject_user_id: Option<&str>,
        subject_identifier_hash: Option<&str>,
        flow_kind: &str,
        now: DateTime<Utc>,
    ) -> Result<u64, String> {
        let updated = sqlx::query(
            "UPDATE auth_flows
              SET status = 'cancelled', updated_at = $4
              WHERE flow_kind = $3
                AND status = 'pending'
                AND expires_at > $4
                AND ((subject_user_id = $1::uuid) OR (subject_identifier_hash = $2))",
        )
        .bind(subject_user_id)
        .bind(subject_identifier_hash)
        .bind(flow_kind)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "auth flow cancel failed".to_string())?;

        Ok(updated.rows_affected())
    }

    async fn metrics_snapshot(
        &self,
        now: DateTime<Utc>,
    ) -> Result<AuthFlowMetricsSnapshot, String> {
        let active_rows = sqlx::query(
            "SELECT flow_kind, COUNT(*)::bigint AS pending_total
             FROM auth_flows
             WHERE status = 'pending' AND expires_at > $1
             GROUP BY flow_kind",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| "auth flow metrics snapshot failed".to_string())?;

        let mut active_by_kind = active_rows
            .into_iter()
            .map(|row| {
                Ok(AuthFlowMetricBucket {
                    flow_kind: parse_auth_flow_kind(
                        row.try_get::<String, _>("flow_kind")
                            .map_err(|_| "invalid auth flow metrics flow_kind".to_string())?,
                    ),
                    pending_total: row
                        .try_get::<i64, _>("pending_total")
                        .map_err(|_| "invalid auth flow metrics pending_total".to_string())?
                        .max(0) as u64,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        active_by_kind.sort_by_key(|bucket| auth_flow_kind_to_db(&bucket.flow_kind));

        let backlog_row = sqlx::query(
            "SELECT COUNT(*)::bigint AS expired_pending_total,
                    COALESCE(EXTRACT(EPOCH FROM ($1 - MIN(expires_at))), 0)::bigint AS oldest_expired_pending_age_seconds
             FROM auth_flows
             WHERE status = 'pending' AND expires_at <= $1",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| "auth flow backlog metrics failed".to_string())?;

        Ok(AuthFlowMetricsSnapshot {
            active_by_kind,
            expired_pending_total: backlog_row
                .try_get::<i64, _>("expired_pending_total")
                .map_err(|_| "invalid auth flow expired_pending_total".to_string())?
                .max(0) as u64,
            oldest_expired_pending_age_seconds: backlog_row
                .try_get::<i64, _>("oldest_expired_pending_age_seconds")
                .map_err(|_| "invalid auth flow oldest_expired_pending_age_seconds".to_string())?
                .max(0) as u64,
        })
    }

    async fn prune_expired(&self, now: DateTime<Utc>) -> Result<u64, String> {
        let updated = sqlx::query(
            "UPDATE auth_flows
             SET status = 'expired', updated_at = $1
             WHERE status = 'pending' AND expires_at <= $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "auth flow prune failed".to_string())?;

        Ok(updated.rows_affected())
    }
}

async fn fetch_account_by_email(pool: &PgPool, email: &str) -> Option<AccountRecord> {
    let row = sqlx::query(
        "SELECT id::text AS id, email, status, created_at, updated_at
         FROM users
         WHERE email = $1",
    )
    .bind(email.to_ascii_lowercase())
    .fetch_optional(pool)
    .await
    .ok()??;

    account_from_row(row).ok()
}

async fn fetch_account_by_id(pool: &PgPool, user_id: &str) -> Option<AccountRecord> {
    let row = sqlx::query(
        "SELECT id::text AS id, email, status, created_at, updated_at
         FROM users
         WHERE id = $1::uuid",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()??;

    account_from_row(row).ok()
}

async fn fetch_legacy_password_by_user_id(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<LegacyPasswordRecord>, String> {
    let row = sqlx::query(
        "SELECT user_id::text AS user_id, password_hash, legacy_login_allowed,
                migrated_to_opaque_at, last_legacy_verified_at, legacy_deprecation_at
         FROM credentials
         WHERE user_id = $1::uuid",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| "legacy password fetch failed".to_string())?;

    row.map(legacy_password_from_row).transpose()
}

fn account_from_row(row: sqlx::postgres::PgRow) -> Result<AccountRecord, String> {
    Ok(AccountRecord {
        id: row
            .try_get("id")
            .map_err(|_| "invalid account id".to_string())?,
        email: row
            .try_get("email")
            .map_err(|_| "invalid account email".to_string())?,
        status: parse_account_status(
            row.try_get::<String, _>("status")
                .map_err(|_| "invalid account status".to_string())?,
        ),
        created_at: row
            .try_get("created_at")
            .map_err(|_| "invalid account created_at".to_string())?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| "invalid account updated_at".to_string())?,
    })
}

fn legacy_password_from_row(row: sqlx::postgres::PgRow) -> Result<LegacyPasswordRecord, String> {
    Ok(LegacyPasswordRecord {
        user_id: row
            .try_get("user_id")
            .map_err(|_| "invalid legacy password user_id".to_string())?,
        password_hash: row
            .try_get("password_hash")
            .map_err(|_| "invalid legacy password hash".to_string())?,
        legacy_login_allowed: row
            .try_get("legacy_login_allowed")
            .map_err(|_| "invalid legacy login policy".to_string())?,
        migrated_to_opaque_at: row
            .try_get("migrated_to_opaque_at")
            .map_err(|_| "invalid migrated_to_opaque_at".to_string())?,
        last_legacy_verified_at: row
            .try_get("last_legacy_verified_at")
            .map_err(|_| "invalid last_legacy_verified_at".to_string())?,
        legacy_deprecation_at: row
            .try_get("legacy_deprecation_at")
            .map_err(|_| "invalid legacy_deprecation_at".to_string())?,
    })
}

fn opaque_credential_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<OpaqueCredentialRecord, String> {
    Ok(OpaqueCredentialRecord {
        user_id: row
            .try_get("user_id")
            .map_err(|_| "invalid opaque credential user_id".to_string())?,
        protocol: row
            .try_get("protocol")
            .map_err(|_| "invalid opaque credential protocol".to_string())?,
        credential_blob: row
            .try_get("credential_blob")
            .map_err(|_| "invalid opaque credential blob".to_string())?,
        server_key_ref: row
            .try_get("server_key_ref")
            .map_err(|_| "invalid opaque credential server key ref".to_string())?,
        envelope_kms_key_id: row
            .try_get("envelope_kms_key_id")
            .map_err(|_| "invalid opaque credential envelope key id".to_string())?,
        state: parse_opaque_credential_state(
            row.try_get::<String, _>("state")
                .map_err(|_| "invalid opaque credential state".to_string())?,
        ),
        migrated_from_legacy_at: row
            .try_get("migrated_from_legacy_at")
            .map_err(|_| "invalid migrated_from_legacy_at".to_string())?,
        last_verified_at: row
            .try_get("last_verified_at")
            .map_err(|_| "invalid last_verified_at".to_string())?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| "invalid opaque credential created_at".to_string())?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| "invalid opaque credential updated_at".to_string())?,
    })
}

fn auth_flow_from_row(row: sqlx::postgres::PgRow) -> Result<AuthFlowRecord, String> {
    Ok(AuthFlowRecord {
        flow_id: row
            .try_get("flow_id")
            .map_err(|_| "invalid auth flow id".to_string())?,
        subject_user_id: row
            .try_get("subject_user_id")
            .map_err(|_| "invalid auth flow subject user".to_string())?,
        subject_identifier_hash: row
            .try_get("subject_identifier_hash")
            .map_err(|_| "invalid auth flow identifier hash".to_string())?,
        flow_kind: parse_auth_flow_kind(
            row.try_get::<String, _>("flow_kind")
                .map_err(|_| "invalid auth flow kind".to_string())?,
        ),
        protocol: row
            .try_get("protocol")
            .map_err(|_| "invalid auth flow protocol".to_string())?,
        state: row
            .try_get("state")
            .map_err(|_| "invalid auth flow state".to_string())?,
        status: parse_auth_flow_status(
            row.try_get::<String, _>("status")
                .map_err(|_| "invalid auth flow status".to_string())?,
        ),
        rollout_channel: row
            .try_get("rollout_channel")
            .map_err(|_| "invalid auth flow rollout channel".to_string())?,
        fallback_policy: row
            .try_get("fallback_policy")
            .map_err(|_| "invalid auth flow fallback policy".to_string())?,
        trace_id: row
            .try_get("trace_id")
            .map_err(|_| "invalid auth flow trace id".to_string())?,
        issued_ip: row
            .try_get("issued_ip")
            .map_err(|_| "invalid auth flow ip".to_string())?,
        issued_user_agent: row
            .try_get("issued_user_agent")
            .map_err(|_| "invalid auth flow user agent".to_string())?,
        attempt_count: row
            .try_get::<i32, _>("attempt_count")
            .map_err(|_| "invalid auth flow attempts".to_string())?
            .max(0) as u32,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| "invalid auth flow expires_at".to_string())?,
        consumed_at: row
            .try_get("consumed_at")
            .map_err(|_| "invalid auth flow consumed_at".to_string())?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| "invalid auth flow created_at".to_string())?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| "invalid auth flow updated_at".to_string())?,
    })
}

#[derive(Clone)]
pub struct PostgresVerificationTokenRepository {
    pool: PgPool,
}

#[async_trait]
impl VerificationTokenRepository for PostgresVerificationTokenRepository {
    async fn issue(&self, token: VerificationTokenRecord) -> Result<(), String> {
        sqlx::query(
            "UPDATE verification_tokens
             SET used_at = $2
             WHERE user_id = $1::uuid AND used_at IS NULL",
        )
        .bind(token.user_id.clone())
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "verification token cleanup failed".to_string())?;

        sqlx::query(
            "INSERT INTO verification_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
        )
        .bind(token.id)
        .bind(token.user_id)
        .bind(token.token_hash)
        .bind(token.expires_at)
        .bind(token.used_at)
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "verification token insert failed".to_string())?;

        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<VerificationTokenConsumeState, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "verification token transaction begin failed".to_string())?;

        let row = sqlx::query(
            "SELECT id::text AS id, user_id::text AS user_id, expires_at, used_at
             FROM verification_tokens
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "verification token fetch failed".to_string())?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(VerificationTokenConsumeState::NotFound);
        };

        let token_id: String = row
            .try_get("id")
            .map_err(|_| "invalid verification token id".to_string())?;
        let user_id: String = row
            .try_get("user_id")
            .map_err(|_| "invalid verification token user".to_string())?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid verification token expiration".to_string())?;
        let used_at: Option<DateTime<Utc>> = row
            .try_get("used_at")
            .map_err(|_| "invalid verification token used marker".to_string())?;

        if used_at.is_some() {
            tx.rollback().await.ok();
            return Ok(VerificationTokenConsumeState::AlreadyUsed);
        }

        if expires_at <= now {
            tx.rollback().await.ok();
            return Ok(VerificationTokenConsumeState::Expired);
        }

        sqlx::query(
            "UPDATE verification_tokens
             SET used_at = $2
             WHERE id = $1::uuid AND used_at IS NULL",
        )
        .bind(token_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| "verification token consume failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "verification token transaction commit failed".to_string())?;

        Ok(VerificationTokenConsumeState::Consumed { user_id })
    }
}

#[derive(Clone)]
pub struct PostgresPasswordResetTokenRepository {
    pool: PgPool,
}

#[async_trait]
impl PasswordResetTokenRepository for PostgresPasswordResetTokenRepository {
    async fn issue(&self, token: PasswordResetTokenRecord) -> Result<(), String> {
        sqlx::query(
            "UPDATE password_reset_tokens
             SET used_at = $2
             WHERE user_id = $1::uuid AND used_at IS NULL",
        )
        .bind(token.user_id.clone())
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "password reset token cleanup failed".to_string())?;

        sqlx::query(
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
        )
        .bind(token.id)
        .bind(token.user_id)
        .bind(token.token_hash)
        .bind(token.expires_at)
        .bind(token.used_at)
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "password reset token insert failed".to_string())?;

        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<PasswordResetTokenConsumeState, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "password reset token transaction begin failed".to_string())?;

        let row = sqlx::query(
            "SELECT id::text AS id, user_id::text AS user_id, expires_at, used_at
             FROM password_reset_tokens
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "password reset token fetch failed".to_string())?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(PasswordResetTokenConsumeState::NotFound);
        };

        let token_id: String = row
            .try_get("id")
            .map_err(|_| "invalid password reset token id".to_string())?;
        let user_id: String = row
            .try_get("user_id")
            .map_err(|_| "invalid password reset token user".to_string())?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid password reset token expiration".to_string())?;
        let used_at: Option<DateTime<Utc>> = row
            .try_get("used_at")
            .map_err(|_| "invalid password reset token used marker".to_string())?;

        if used_at.is_some() {
            tx.rollback().await.ok();
            return Ok(PasswordResetTokenConsumeState::AlreadyUsed);
        }

        if expires_at <= now {
            tx.rollback().await.ok();
            return Ok(PasswordResetTokenConsumeState::Expired);
        }

        sqlx::query(
            "UPDATE password_reset_tokens
             SET used_at = $2
             WHERE id = $1::uuid AND used_at IS NULL",
        )
        .bind(token_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| "password reset token consume failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "password reset token transaction commit failed".to_string())?;

        Ok(PasswordResetTokenConsumeState::Consumed { user_id })
    }
}

#[derive(Clone)]
pub struct PostgresMfaFactorRepository {
    pool: PgPool,
}

#[async_trait]
impl MfaFactorRepository for PostgresMfaFactorRepository {
    async fn find_by_user_id(&self, user_id: &str) -> Option<MfaFactorRecord> {
        let row = sqlx::query(
            "SELECT user_id::text AS user_id, secret_ciphertext, secret_nonce, enabled_at, created_at, updated_at
             FROM mfa_factors
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??;

        Some(MfaFactorRecord {
            user_id: row.try_get("user_id").ok()?,
            secret_ciphertext: row.try_get("secret_ciphertext").ok()?,
            secret_nonce: row.try_get("secret_nonce").ok()?,
            enabled_at: row.try_get("enabled_at").ok()?,
            created_at: row.try_get("created_at").ok()?,
            updated_at: row.try_get("updated_at").ok()?,
        })
    }

    async fn upsert(&self, factor: MfaFactorRecord) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO mfa_factors (user_id, secret_ciphertext, secret_nonce, enabled_at, created_at, updated_at)
             VALUES ($1::uuid, $2, $3, $4, $5, $6)
             ON CONFLICT (user_id)
             DO UPDATE SET
               secret_ciphertext = EXCLUDED.secret_ciphertext,
               secret_nonce = EXCLUDED.secret_nonce,
               enabled_at = EXCLUDED.enabled_at,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(factor.user_id)
        .bind(factor.secret_ciphertext)
        .bind(factor.secret_nonce)
        .bind(factor.enabled_at)
        .bind(factor.created_at)
        .bind(factor.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "mfa factor upsert failed".to_string())?;

        Ok(())
    }

    async fn set_enabled_at(&self, user_id: &str, enabled_at: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE mfa_factors
             SET enabled_at = $2, updated_at = $2
             WHERE user_id = $1::uuid",
        )
        .bind(user_id)
        .bind(enabled_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "mfa factor enable failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("mfa factor not found".to_string());
        }

        Ok(())
    }

    async fn delete_for_user(&self, user_id: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM mfa_factors WHERE user_id = $1::uuid")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|_| "mfa factor delete failed".to_string())?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresMfaChallengeRepository {
    pool: PgPool,
}

#[async_trait]
impl MfaChallengeRepository for PostgresMfaChallengeRepository {
    async fn issue(&self, challenge: MfaChallengeRecord) -> Result<(), String> {
        sqlx::query(
            "UPDATE mfa_challenges
             SET used_at = $2
             WHERE user_id = $1::uuid AND used_at IS NULL",
        )
        .bind(challenge.user_id.clone())
        .bind(challenge.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "mfa challenge cleanup failed".to_string())?;

        sqlx::query(
            "INSERT INTO mfa_challenges (id, user_id, challenge_hash, device_info, failed_attempts, expires_at, used_at, created_at)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)",
        )
        .bind(challenge.id)
        .bind(challenge.user_id)
        .bind(challenge.challenge_hash)
        .bind(challenge.device_info)
        .bind(challenge.failed_attempts as i32)
        .bind(challenge.expires_at)
        .bind(challenge.used_at)
        .bind(challenge.created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| "mfa challenge insert failed".to_string())?;

        Ok(())
    }

    async fn find_active(
        &self,
        challenge_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookupState, String> {
        let row = sqlx::query(
            "SELECT user_id::text AS user_id, device_info, expires_at, used_at
             FROM mfa_challenges
             WHERE challenge_hash = $1",
        )
        .bind(challenge_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "mfa challenge fetch failed".to_string())?;

        let Some(row) = row else {
            return Ok(MfaChallengeLookupState::NotFound);
        };

        let user_id: String = row
            .try_get("user_id")
            .map_err(|_| "invalid mfa challenge user".to_string())?;
        let device_info: Option<String> = row
            .try_get("device_info")
            .map_err(|_| "invalid mfa challenge device info".to_string())?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid mfa challenge expiration".to_string())?;
        let used_at: Option<DateTime<Utc>> = row
            .try_get("used_at")
            .map_err(|_| "invalid mfa challenge used marker".to_string())?;

        if used_at.is_some() {
            return Ok(MfaChallengeLookupState::AlreadyUsed);
        }

        if expires_at <= now {
            return Ok(MfaChallengeLookupState::Expired);
        }

        Ok(MfaChallengeLookupState::Active {
            user_id,
            device_info,
        })
    }

    async fn mark_used(&self, challenge_hash: &str, now: DateTime<Utc>) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE mfa_challenges
             SET used_at = $2
             WHERE challenge_hash = $1 AND used_at IS NULL",
        )
        .bind(challenge_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "mfa challenge consume failed".to_string())?;

        if updated.rows_affected() == 0 {
            return Err("mfa challenge already consumed or missing".to_string());
        }

        Ok(())
    }

    async fn register_failure(
        &self,
        challenge_hash: &str,
        now: DateTime<Utc>,
        max_attempts: u32,
    ) -> Result<MfaChallengeFailureState, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "mfa challenge transaction begin failed".to_string())?;

        let row = sqlx::query(
            "SELECT id::text AS id, failed_attempts, expires_at, used_at
             FROM mfa_challenges
             WHERE challenge_hash = $1
             FOR UPDATE",
        )
        .bind(challenge_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "mfa challenge fetch failed".to_string())?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(MfaChallengeFailureState::NotFound);
        };

        let challenge_id: String = row
            .try_get("id")
            .map_err(|_| "invalid mfa challenge id".to_string())?;
        let failed_attempts: i32 = row
            .try_get("failed_attempts")
            .map_err(|_| "invalid mfa challenge attempts".to_string())?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid mfa challenge expiration".to_string())?;
        let used_at: Option<DateTime<Utc>> = row
            .try_get("used_at")
            .map_err(|_| "invalid mfa challenge used marker".to_string())?;

        if used_at.is_some() {
            tx.rollback().await.ok();
            return Ok(MfaChallengeFailureState::AlreadyUsed);
        }

        if expires_at <= now {
            tx.rollback().await.ok();
            return Ok(MfaChallengeFailureState::Expired);
        }

        let failed_attempts = failed_attempts.max(0);
        let updated_attempts = failed_attempts.saturating_add(1);
        if updated_attempts as u32 >= max_attempts {
            sqlx::query(
                "UPDATE mfa_challenges
                 SET failed_attempts = $2, used_at = $3
                 WHERE id = $1::uuid",
            )
            .bind(challenge_id)
            .bind(updated_attempts)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| "mfa challenge exhaustion update failed".to_string())?;

            tx.commit()
                .await
                .map_err(|_| "mfa challenge transaction commit failed".to_string())?;

            return Ok(MfaChallengeFailureState::Exhausted);
        }

        sqlx::query(
            "UPDATE mfa_challenges
             SET failed_attempts = $2
             WHERE id = $1::uuid",
        )
        .bind(challenge_id)
        .bind(updated_attempts)
        .execute(&mut *tx)
        .await
        .map_err(|_| "mfa challenge failure update failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "mfa challenge transaction commit failed".to_string())?;

        Ok(MfaChallengeFailureState::RetryAllowed {
            remaining_attempts: max_attempts - updated_attempts as u32,
        })
    }
}

#[derive(Clone)]
pub struct PostgresMfaBackupCodeRepository {
    pool: PgPool,
}

#[async_trait]
impl MfaBackupCodeRepository for PostgresMfaBackupCodeRepository {
    async fn replace_for_user(
        &self,
        user_id: &str,
        code_hashes: &[String],
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "mfa backup code transaction begin failed".to_string())?;

        sqlx::query("DELETE FROM mfa_backup_codes WHERE user_id = $1::uuid")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| "mfa backup code cleanup failed".to_string())?;

        for code_hash in code_hashes {
            sqlx::query(
                "INSERT INTO mfa_backup_codes (id, user_id, code_hash, used_at, created_at)
                 VALUES ($1::uuid, $2::uuid, $3, NULL, $4)",
            )
            .bind(Uuid::new_v4())
            .bind(user_id)
            .bind(code_hash)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| "mfa backup code insert failed".to_string())?;
        }

        tx.commit()
            .await
            .map_err(|_| "mfa backup code transaction commit failed".to_string())?;

        Ok(())
    }

    async fn consume(
        &self,
        user_id: &str,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<MfaBackupCodeConsumeState, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "mfa backup code transaction begin failed".to_string())?;

        let row = sqlx::query(
            "SELECT id::text AS id, used_at
             FROM mfa_backup_codes
             WHERE user_id = $1::uuid AND code_hash = $2
             FOR UPDATE",
        )
        .bind(user_id)
        .bind(code_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "mfa backup code fetch failed".to_string())?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(MfaBackupCodeConsumeState::NotFound);
        };

        let backup_code_id: String = row
            .try_get("id")
            .map_err(|_| "invalid mfa backup code id".to_string())?;
        let used_at: Option<DateTime<Utc>> = row
            .try_get("used_at")
            .map_err(|_| "invalid mfa backup code used marker".to_string())?;

        if used_at.is_some() {
            tx.rollback().await.ok();
            return Ok(MfaBackupCodeConsumeState::AlreadyUsed);
        }

        sqlx::query(
            "UPDATE mfa_backup_codes
             SET used_at = $2
             WHERE id = $1::uuid AND used_at IS NULL",
        )
        .bind(backup_code_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| "mfa backup code consume failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "mfa backup code transaction commit failed".to_string())?;

        Ok(MfaBackupCodeConsumeState::Consumed)
    }
}

#[derive(Clone)]
pub struct PostgresPasskeyCredentialRepository {
    pool: PgPool,
}

#[async_trait]
impl PasskeyCredentialRepository for PostgresPasskeyCredentialRepository {
    async fn list_for_user(&self, user_id: &str) -> Result<Vec<Passkey>, String> {
        let rows = sqlx::query(
            "SELECT passkey_data
             FROM passkey_credentials
             WHERE user_id = $1::uuid
             ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| "passkey credential fetch failed".to_string())?;

        let mut passkeys = Vec::with_capacity(rows.len());
        for row in rows {
            let passkey_data: serde_json::Value = row
                .try_get("passkey_data")
                .map_err(|_| "invalid passkey payload".to_string())?;
            let passkey: Passkey = serde_json::from_value(passkey_data)
                .map_err(|_| "invalid passkey payload".to_string())?;
            passkeys.push(passkey);
        }

        Ok(passkeys)
    }

    async fn upsert_for_user(
        &self,
        user_id: &str,
        passkey: Passkey,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let credential_id = passkey_credential_key(&passkey);
        let passkey_data = serde_json::to_value(&passkey)
            .map_err(|_| "passkey serialization failed".to_string())?;

        sqlx::query(
            "INSERT INTO passkey_credentials (user_id, credential_id, passkey_data, created_at, updated_at)
             VALUES ($1::uuid, $2, $3::jsonb, $4, $4)
             ON CONFLICT (user_id, credential_id)
             DO UPDATE SET
               passkey_data = EXCLUDED.passkey_data,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(user_id)
        .bind(credential_id)
        .bind(passkey_data)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if let sqlx::Error::Database(database_error) = &error {
                if database_error.code().as_deref() == Some("23505") {
                    return "passkey credential already registered".to_string();
                }
            }

            "passkey credential upsert failed".to_string()
        })?;

        Ok(())
    }
}

fn passkey_credential_key(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())
}

#[derive(Clone)]
pub struct PostgresPasskeyChallengeRepository {
    pool: PgPool,
}

#[async_trait]
impl PasskeyChallengeRepository for PostgresPasskeyChallengeRepository {
    async fn issue_registration(
        &self,
        flow_id: &str,
        challenge: PasskeyRegistrationChallengeRecord,
    ) -> Result<(), String> {
        let challenge_state = serde_json::to_value(&challenge.state)
            .map_err(|_| "passkey registration challenge serialization failed".to_string())?;

        let mut tx =
            self.pool.begin().await.map_err(|_| {
                "passkey registration challenge transaction begin failed".to_string()
            })?;

        sqlx::query(
            "DELETE FROM passkey_challenges
             WHERE user_id = $1::uuid AND challenge_type = 'registration'",
        )
        .bind(&challenge.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| "passkey registration challenge cleanup failed".to_string())?;

        sqlx::query(
            "INSERT INTO passkey_challenges (flow_id, user_id, challenge_type, challenge_state, expires_at, created_at)
             VALUES ($1, $2::uuid, 'registration', $3::jsonb, $4, $5)",
        )
        .bind(flow_id)
        .bind(&challenge.user_id)
        .bind(challenge_state)
        .bind(challenge.expires_at)
        .bind(challenge.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| "passkey registration challenge insert failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "passkey registration challenge transaction commit failed".to_string())?;

        Ok(())
    }

    async fn consume_registration(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyRegistrationChallengeConsumeState, String> {
        let row = sqlx::query(
            "DELETE FROM passkey_challenges
             WHERE flow_id = $1 AND challenge_type = 'registration'
             RETURNING user_id::text AS user_id, challenge_state, created_at, expires_at",
        )
        .bind(flow_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "passkey registration challenge consume failed".to_string())?;

        let Some(row) = row else {
            return Ok(PasskeyRegistrationChallengeConsumeState::NotFound);
        };

        let user_id: String = row
            .try_get("user_id")
            .map_err(|_| "invalid passkey registration challenge user".to_string())?;
        let challenge_state: serde_json::Value = row
            .try_get("challenge_state")
            .map_err(|_| "invalid passkey registration challenge payload".to_string())?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|_| "invalid passkey registration challenge timestamp".to_string())?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid passkey registration challenge expiration".to_string())?;

        if expires_at <= now {
            return Ok(PasskeyRegistrationChallengeConsumeState::Expired);
        }

        let state: PasskeyRegistration = serde_json::from_value(challenge_state)
            .map_err(|_| "invalid passkey registration challenge payload".to_string())?;

        Ok(PasskeyRegistrationChallengeConsumeState::Active(
            PasskeyRegistrationChallengeRecord {
                user_id,
                state,
                created_at,
                expires_at,
            },
        ))
    }

    async fn issue_authentication(
        &self,
        flow_id: &str,
        challenge: PasskeyAuthenticationChallengeRecord,
    ) -> Result<(), String> {
        let challenge_state = serde_json::to_value(&challenge.state)
            .map_err(|_| "passkey authentication challenge serialization failed".to_string())?;

        let mut tx =
            self.pool.begin().await.map_err(|_| {
                "passkey authentication challenge transaction begin failed".to_string()
            })?;

        sqlx::query(
            "DELETE FROM passkey_challenges
             WHERE user_id = $1::uuid AND challenge_type = 'authentication'",
        )
        .bind(&challenge.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| "passkey authentication challenge cleanup failed".to_string())?;

        sqlx::query(
            "INSERT INTO passkey_challenges (flow_id, user_id, challenge_type, challenge_state, expires_at, created_at)
             VALUES ($1, $2::uuid, 'authentication', $3::jsonb, $4, $5)",
        )
        .bind(flow_id)
        .bind(&challenge.user_id)
        .bind(challenge_state)
        .bind(challenge.expires_at)
        .bind(challenge.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| "passkey authentication challenge insert failed".to_string())?;

        tx.commit().await.map_err(|_| {
            "passkey authentication challenge transaction commit failed".to_string()
        })?;

        Ok(())
    }

    async fn consume_authentication(
        &self,
        flow_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyAuthenticationChallengeConsumeState, String> {
        let row = sqlx::query(
            "DELETE FROM passkey_challenges
             WHERE flow_id = $1 AND challenge_type = 'authentication'
             RETURNING user_id::text AS user_id, challenge_state, created_at, expires_at",
        )
        .bind(flow_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "passkey authentication challenge consume failed".to_string())?;

        let Some(row) = row else {
            return Ok(PasskeyAuthenticationChallengeConsumeState::NotFound);
        };

        let user_id: String = row
            .try_get("user_id")
            .map_err(|_| "invalid passkey authentication challenge user".to_string())?;
        let challenge_state: serde_json::Value = row
            .try_get("challenge_state")
            .map_err(|_| "invalid passkey authentication challenge payload".to_string())?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|_| "invalid passkey authentication challenge timestamp".to_string())?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid passkey authentication challenge expiration".to_string())?;

        if expires_at <= now {
            return Ok(PasskeyAuthenticationChallengeConsumeState::Expired);
        }

        let state: PasskeyAuthentication = serde_json::from_value(challenge_state)
            .map_err(|_| "invalid passkey authentication challenge payload".to_string())?;

        Ok(PasskeyAuthenticationChallengeConsumeState::Active(
            PasskeyAuthenticationChallengeRecord {
                user_id,
                state,
                created_at,
                expires_at,
            },
        ))
    }

    async fn prune_expired(&self, now: DateTime<Utc>) -> Result<u64, String> {
        let deleted = sqlx::query("DELETE FROM passkey_challenges WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|_| "passkey challenge prune failed".to_string())?;

        Ok(deleted.rows_affected())
    }
}

#[derive(Clone)]
pub struct PostgresSessionRepository {
    pool: PgPool,
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create(&self, session: Session) {
        if let Err(error) = sqlx::query(
            "INSERT INTO sessions (id, user_id, device_info, ip, status, created_at, last_seen_at)
             VALUES ($1::uuid, $2::uuid, $3, $4::inet, $5, $6, $7)",
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(session.device_info)
        .bind(session.ip)
        .bind(session_status_to_db(&session.status))
        .bind(session.created_at)
        .bind(session.last_seen_at)
        .execute(&self.pool)
        .await
        {
            tracing::error!(?error, "failed to create session");
        }
    }

    async fn find_by_id(&self, session_id: &str) -> Option<Session> {
        let row = sqlx::query(
            "SELECT id::text AS id, user_id::text AS user_id, device_info, ip::text AS ip, status, created_at, last_seen_at
             FROM sessions
             WHERE id = $1::uuid",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??;

        Some(Session {
            id: row.try_get("id").ok()?,
            user_id: row.try_get("user_id").ok()?,
            device_info: row.try_get("device_info").ok()?,
            ip: row.try_get("ip").ok()?,
            status: parse_session_status(row.try_get::<String, _>("status").ok()?),
            created_at: row.try_get("created_at").ok()?,
            last_seen_at: row.try_get("last_seen_at").ok()?,
        })
    }

    async fn list_active_for_user(&self, user_id: &str) -> Vec<Session> {
        let rows = match sqlx::query(
            "SELECT id::text AS id, user_id::text AS user_id, device_info, ip::text AS ip, status, created_at, last_seen_at
             FROM sessions
             WHERE user_id = $1::uuid AND status = 'active'
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(?error, "failed to list active sessions for user");
                return Vec::new();
            }
        };

        rows.into_iter()
            .filter_map(|row| {
                Some(Session {
                    id: row.try_get("id").ok()?,
                    user_id: row.try_get("user_id").ok()?,
                    device_info: row.try_get("device_info").ok()?,
                    ip: row.try_get("ip").ok()?,
                    status: parse_session_status(row.try_get::<String, _>("status").ok()?),
                    created_at: row.try_get("created_at").ok()?,
                    last_seen_at: row.try_get("last_seen_at").ok()?,
                })
            })
            .collect()
    }

    async fn update(&self, session: Session) {
        if let Err(error) = sqlx::query(
            "UPDATE sessions
             SET device_info = $2, ip = $3::inet, status = $4, last_seen_at = $5
             WHERE id = $1::uuid",
        )
        .bind(session.id)
        .bind(session.device_info)
        .bind(session.ip)
        .bind(session_status_to_db(&session.status))
        .bind(session.last_seen_at)
        .execute(&self.pool)
        .await
        {
            tracing::error!(?error, "failed to update session");
        }
    }

    async fn revoke_session(&self, session_id: &str) {
        if let Err(error) = sqlx::query(
            "UPDATE sessions
             SET status = 'revoked', revoked_at = NOW(), last_seen_at = NOW()
             WHERE id = $1::uuid AND status = 'active'",
        )
        .bind(session_id)
        .execute(&self.pool)
        .await
        {
            tracing::error!(?error, "failed to revoke session");
        }
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Vec<String> {
        let rows = match sqlx::query(
            "UPDATE sessions
             SET status = 'revoked', revoked_at = NOW(), last_seen_at = NOW()
             WHERE user_id = $1::uuid AND status = 'active'
             RETURNING id::text AS id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(?error, "failed to revoke all sessions for user");
                return Vec::new();
            }
        };

        rows.into_iter()
            .filter_map(|row| row.try_get::<String, _>("id").ok())
            .collect()
    }

    async fn mark_compromised_and_revoke_all_for_user(&self, user_id: &str) -> Vec<String> {
        let rows = match sqlx::query(
            "UPDATE sessions
             SET status = 'compromised', compromised_at = NOW(), last_seen_at = NOW()
             WHERE user_id = $1::uuid
             RETURNING id::text AS id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(?error, "failed to compromise sessions for user");
                return Vec::new();
            }
        };

        rows.into_iter()
            .filter_map(|row| row.try_get::<String, _>("id").ok())
            .collect()
    }
}

#[derive(Clone)]
pub struct PostgresRefreshTokenRepository {
    pool: PgPool,
}

#[async_trait]
impl RefreshTokenRepository for PostgresRefreshTokenRepository {
    async fn insert(&self, token: RefreshTokenRecord) {
        if let Err(error) = sqlx::query(
            "INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at, revoked_at, replaced_by, created_at)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)",
        )
        .bind(token.id)
        .bind(token.session_id)
        .bind(token.token_hash)
        .bind(token.expires_at)
        .bind(token.revoked_at)
        .bind(token.replaced_by)
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        {
            tracing::error!(?error, "failed to insert refresh token");
        }
    }

    async fn find_by_hash(&self, token_hash: &str) -> Option<RefreshTokenRecord> {
        let row = sqlx::query(
            "SELECT id::text AS id, session_id::text AS session_id, token_hash, expires_at, revoked_at, replaced_by, created_at
             FROM refresh_tokens
             WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .ok()??;

        Some(RefreshTokenRecord {
            id: row.try_get("id").ok()?,
            session_id: row.try_get("session_id").ok()?,
            token_hash: row.try_get("token_hash").ok()?,
            expires_at: row.try_get("expires_at").ok()?,
            revoked_at: row.try_get("revoked_at").ok()?,
            replaced_by: row.try_get("replaced_by").ok()?,
            created_at: row.try_get("created_at").ok()?,
        })
    }

    async fn rotate_strong(
        &self,
        current_hash: &str,
        next_token: RefreshTokenRecord,
        now: DateTime<Utc>,
    ) -> Result<RefreshRotationState, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "refresh transaction begin failed".to_string())?;

        let row = sqlx::query(
            "SELECT expires_at, revoked_at
             FROM refresh_tokens
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(current_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "refresh token fetch failed".to_string())?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(RefreshRotationState::NotFound);
        };

        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|_| "invalid refresh token expiration".to_string())?;
        let revoked_at: Option<DateTime<Utc>> = row
            .try_get("revoked_at")
            .map_err(|_| "invalid refresh token revocation".to_string())?;

        if revoked_at.is_some() {
            tx.rollback().await.ok();
            return Ok(RefreshRotationState::AlreadyRevoked);
        }

        if expires_at <= now {
            sqlx::query(
                "UPDATE refresh_tokens
                 SET revoked_at = COALESCE(revoked_at, $2)
                 WHERE token_hash = $1",
            )
            .bind(current_hash)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| "refresh token expiration update failed".to_string())?;

            tx.commit()
                .await
                .map_err(|_| "refresh transaction commit failed".to_string())?;
            return Ok(RefreshRotationState::Expired);
        }

        sqlx::query(
            "UPDATE refresh_tokens
             SET revoked_at = $2, replaced_by = $3
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(current_hash)
        .bind(now)
        .bind(next_token.token_hash.clone())
        .execute(&mut *tx)
        .await
        .map_err(|_| "refresh token revoke failed".to_string())?;

        sqlx::query(
            "INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at, revoked_at, replaced_by, created_at)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)",
        )
        .bind(next_token.id)
        .bind(next_token.session_id)
        .bind(next_token.token_hash)
        .bind(next_token.expires_at)
        .bind(next_token.revoked_at)
        .bind(next_token.replaced_by)
        .bind(next_token.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| "next refresh token insert failed".to_string())?;

        tx.commit()
            .await
            .map_err(|_| "refresh transaction commit failed".to_string())?;

        Ok(RefreshRotationState::Rotated)
    }

    async fn rotate(
        &self,
        current_hash: &str,
        next_token: RefreshTokenRecord,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), String> {
        match self
            .rotate_strong(current_hash, next_token, revoked_at)
            .await?
        {
            RefreshRotationState::Rotated => Ok(()),
            RefreshRotationState::NotFound => Err("current refresh token not found".to_string()),
            RefreshRotationState::AlreadyRevoked => {
                Err("refresh token already revoked".to_string())
            }
            RefreshRotationState::Expired => Err("refresh token expired".to_string()),
        }
    }

    async fn revoke_by_session_ids(&self, session_ids: &[String], revoked_at: DateTime<Utc>) {
        let ids = parse_uuids(session_ids);
        if ids.is_empty() {
            return;
        }

        if let Err(error) = sqlx::query(
            "UPDATE refresh_tokens
             SET revoked_at = $2
             WHERE session_id = ANY($1::uuid[]) AND revoked_at IS NULL",
        )
        .bind(ids)
        .bind(revoked_at)
        .execute(&self.pool)
        .await
        {
            tracing::error!(?error, "failed to revoke refresh tokens by session ids");
        }
    }
}

#[derive(Clone)]
pub struct PostgresAuditRepository {
    pool: PgPool,
}

#[async_trait]
impl AuditRepository for PostgresAuditRepository {
    async fn append(&self, event: AuditEvent) {
        if let Err(error) = sqlx::query(
            "INSERT INTO audit_events (actor_user_id, event_type, trace_id, metadata, created_at)
             VALUES ($1::uuid, $2, $3, $4::jsonb, $5)",
        )
        .bind(event.actor_user_id)
        .bind(event.event_type)
        .bind(event.trace_id)
        .bind(event.metadata)
        .bind(event.created_at)
        .execute(&self.pool)
        .await
        {
            tracing::error!(?error, "failed to append audit event");
        }
    }
}

fn parse_uuids(values: &[String]) -> Vec<Uuid> {
    values
        .iter()
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect()
}

fn parse_account_status(value: String) -> AccountStatus {
    match value.as_str() {
        "active" => AccountStatus::Active,
        "pending_verification" => AccountStatus::PendingVerification,
        "locked" => AccountStatus::Locked,
        _ => AccountStatus::Locked,
    }
}

fn account_status_to_user_status(status: AccountStatus) -> UserStatus {
    match status {
        AccountStatus::Active => UserStatus::Active,
        AccountStatus::PendingVerification => UserStatus::PendingVerification,
        AccountStatus::Locked => UserStatus::Locked,
    }
}

fn parse_opaque_credential_state(value: String) -> OpaqueCredentialState {
    match value.as_str() {
        "active" => OpaqueCredentialState::Active,
        "superseded" => OpaqueCredentialState::Superseded,
        "revoked" => OpaqueCredentialState::Revoked,
        _ => OpaqueCredentialState::Revoked,
    }
}

fn opaque_credential_state_to_db(state: &OpaqueCredentialState) -> &'static str {
    match state {
        OpaqueCredentialState::Active => "active",
        OpaqueCredentialState::Superseded => "superseded",
        OpaqueCredentialState::Revoked => "revoked",
    }
}

fn parse_auth_flow_kind(value: String) -> AuthFlowKind {
    match value.as_str() {
        "methods_discovery" => AuthFlowKind::MethodsDiscovery,
        "password_login" => AuthFlowKind::PasswordLogin,
        "recovery_upgrade_bridge" => AuthFlowKind::RecoveryUpgradeBridge,
        "password_upgrade" => AuthFlowKind::PasswordUpgrade,
        "passkey_login" => AuthFlowKind::PasskeyLogin,
        "passkey_register" => AuthFlowKind::PasskeyRegister,
        _ => AuthFlowKind::MethodsDiscovery,
    }
}

fn auth_flow_kind_to_db(kind: &AuthFlowKind) -> &'static str {
    match kind {
        AuthFlowKind::MethodsDiscovery => "methods_discovery",
        AuthFlowKind::PasswordLogin => "password_login",
        AuthFlowKind::RecoveryUpgradeBridge => "recovery_upgrade_bridge",
        AuthFlowKind::PasswordUpgrade => "password_upgrade",
        AuthFlowKind::PasskeyLogin => "passkey_login",
        AuthFlowKind::PasskeyRegister => "passkey_register",
    }
}

fn parse_auth_flow_status(value: String) -> AuthFlowStatus {
    match value.as_str() {
        "pending" => AuthFlowStatus::Pending,
        "consumed" => AuthFlowStatus::Consumed,
        "expired" => AuthFlowStatus::Expired,
        "cancelled" => AuthFlowStatus::Cancelled,
        _ => AuthFlowStatus::Expired,
    }
}

fn auth_flow_status_to_db(status: &AuthFlowStatus) -> &'static str {
    match status {
        AuthFlowStatus::Pending => "pending",
        AuthFlowStatus::Consumed => "consumed",
        AuthFlowStatus::Expired => "expired",
        AuthFlowStatus::Cancelled => "cancelled",
    }
}

fn parse_session_status(value: String) -> SessionStatus {
    match value.as_str() {
        "active" => SessionStatus::Active,
        "revoked" => SessionStatus::Revoked,
        "compromised" => SessionStatus::Compromised,
        _ => SessionStatus::Revoked,
    }
}

fn session_status_to_db(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active => "active",
        SessionStatus::Revoked => "revoked",
        SessionStatus::Compromised => "compromised",
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use sqlx::{postgres::PgPoolOptions, PgPool};

    use crate::modules::tokens::{
        domain::RefreshTokenRecord,
        ports::{RefreshRotationState, RefreshTokenRepository},
    };

    use super::{
        PostgresAccountRepository, PostgresPasskeyChallengeRepository,
        PostgresRefreshTokenRepository, PostgresUserRepository,
    };
    use crate::modules::auth::ports::{
        AccountRepository, PasskeyChallengeRepository, UserRepository,
    };

    #[tokio::test]
    async fn postgres_account_lookup_is_decoupled_from_legacy_credentials() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let account_repo = PostgresAccountRepository { pool: pool.clone() };
        let user_repo = PostgresUserRepository { pool: pool.clone() };
        let user_id = create_user(&pool).await;

        let account = account_repo
            .find_by_id(&user_id.to_string())
            .await
            .expect("account should be readable without credentials row");
        assert_eq!(account.id, user_id.to_string());
        assert!(user_repo.find_by_id(&user_id.to_string()).await.is_none());
    }

    #[tokio::test]
    async fn postgres_refresh_rotate_strong_returns_not_found_when_current_missing() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresRefreshTokenRepository { pool: pool.clone() };

        let now = Utc::now();
        let session_id = create_user_and_session(&pool).await;
        let state = repo
            .rotate_strong(
                "missing-refresh-hash",
                refresh_record(
                    &session_id,
                    &format!("next-{}", uuid::Uuid::new_v4()),
                    now,
                    now + Duration::seconds(300),
                    None,
                ),
                now,
            )
            .await
            .expect("rotation state should be returned");

        assert_eq!(state, RefreshRotationState::NotFound);
    }

    #[tokio::test]
    async fn postgres_refresh_rotate_strong_returns_expired_and_marks_current_revoked() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresRefreshTokenRepository { pool: pool.clone() };

        let now = Utc::now();
        let session_id = create_user_and_session(&pool).await;
        let current_hash = format!("expired-{}", uuid::Uuid::new_v4());
        let next_hash = format!("next-expired-{}", uuid::Uuid::new_v4());

        repo.insert(refresh_record(
            &session_id,
            &current_hash,
            now,
            now - Duration::seconds(1),
            None,
        ))
        .await;

        let state = repo
            .rotate_strong(
                &current_hash,
                refresh_record(
                    &session_id,
                    &next_hash,
                    now,
                    now + Duration::seconds(300),
                    None,
                ),
                now,
            )
            .await
            .expect("rotation state should be returned");
        assert_eq!(state, RefreshRotationState::Expired);

        let current = repo
            .find_by_hash(&current_hash)
            .await
            .expect("current token should exist");
        let revoked_at = current
            .revoked_at
            .expect("expired token should be marked revoked");
        assert_eq!(revoked_at.timestamp_micros(), now.timestamp_micros());
        assert!(repo.find_by_hash(&next_hash).await.is_none());
    }

    #[tokio::test]
    async fn postgres_refresh_rotate_strong_returns_already_revoked_for_replayed_token() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresRefreshTokenRepository { pool: pool.clone() };

        let now = Utc::now();
        let session_id = create_user_and_session(&pool).await;
        let current_hash = format!("revoked-{}", uuid::Uuid::new_v4());
        let next_hash = format!("next-revoked-{}", uuid::Uuid::new_v4());

        repo.insert(refresh_record(
            &session_id,
            &current_hash,
            now,
            now + Duration::seconds(300),
            Some(now - Duration::seconds(1)),
        ))
        .await;

        let state = repo
            .rotate_strong(
                &current_hash,
                refresh_record(
                    &session_id,
                    &next_hash,
                    now,
                    now + Duration::seconds(300),
                    None,
                ),
                now,
            )
            .await
            .expect("rotation state should be returned");
        assert_eq!(state, RefreshRotationState::AlreadyRevoked);
        assert!(repo.find_by_hash(&next_hash).await.is_none());
    }

    #[tokio::test]
    async fn postgres_refresh_rotate_strong_rotates_and_links_replacement() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresRefreshTokenRepository { pool: pool.clone() };

        let now = Utc::now();
        let session_id = create_user_and_session(&pool).await;
        let current_hash = format!("current-{}", uuid::Uuid::new_v4());
        let next_hash = format!("next-{}", uuid::Uuid::new_v4());

        repo.insert(refresh_record(
            &session_id,
            &current_hash,
            now,
            now + Duration::seconds(300),
            None,
        ))
        .await;

        let state = repo
            .rotate_strong(
                &current_hash,
                refresh_record(
                    &session_id,
                    &next_hash,
                    now,
                    now + Duration::seconds(600),
                    None,
                ),
                now,
            )
            .await
            .expect("rotation state should be returned");
        assert_eq!(state, RefreshRotationState::Rotated);

        let current = repo
            .find_by_hash(&current_hash)
            .await
            .expect("current token should exist");
        let revoked_at = current
            .revoked_at
            .expect("rotated token should be marked revoked");
        assert_eq!(revoked_at.timestamp_micros(), now.timestamp_micros());
        assert_eq!(current.replaced_by.as_deref(), Some(next_hash.as_str()));

        let next = repo
            .find_by_hash(&next_hash)
            .await
            .expect("next token should be persisted");
        assert_eq!(next.session_id, session_id);
        assert!(next.revoked_at.is_none());
    }

    #[tokio::test]
    async fn postgres_passkey_prune_expired_deletes_only_expired_rows() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresPasskeyChallengeRepository { pool: pool.clone() };

        let now = Utc::now();
        let user_id = create_user(&pool).await;
        let flow_prefix = format!("passkey-prune-{}", uuid::Uuid::new_v4());
        let expired_flow = format!("{flow_prefix}-expired");
        let edge_flow = format!("{flow_prefix}-edge");
        let active_flow = format!("{flow_prefix}-active");

        sqlx::query(
            "INSERT INTO passkey_challenges (flow_id, user_id, challenge_type, challenge_state, expires_at, created_at)
             VALUES ($1, $2, 'registration', '{}'::jsonb, $3, $4),
                    ($5, $2, 'authentication', '{}'::jsonb, $6, $4),
                    ($7, $2, 'registration', '{}'::jsonb, $8, $4)",
        )
        .bind(&expired_flow)
        .bind(user_id)
        .bind(now - Duration::seconds(5))
        .bind(now)
        .bind(&edge_flow)
        .bind(now)
        .bind(&active_flow)
        .bind(now + Duration::seconds(300))
        .execute(&pool)
        .await
        .expect("passkey challenges should be inserted");

        let deleted = repo
            .prune_expired(now)
            .await
            .expect("prune should execute successfully");
        assert_eq!(deleted, 2);

        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM passkey_challenges WHERE flow_id LIKE $1")
                .bind(format!("{flow_prefix}%"))
                .fetch_one(&pool)
                .await
                .expect("remaining count should be queryable");
        assert_eq!(remaining, 1);

        let second_deleted = repo
            .prune_expired(now)
            .await
            .expect("second prune should execute successfully");
        assert_eq!(second_deleted, 0);
    }

    async fn test_pool() -> Option<PgPool> {
        if let Some(database_url) = non_empty_env("AUTH_TEST_DATABASE_URL") {
            return Some(
                connect_and_prepare_pool(&database_url)
                    .await
                    .expect("AUTH_TEST_DATABASE_URL is set but connection/migration failed"),
            );
        }

        for database_url in local_postgres_test_urls() {
            if let Ok(pool) = connect_and_prepare_pool(database_url).await {
                return Some(pool);
            }
        }

        None
    }

    async fn connect_and_prepare_pool(database_url: &str) -> Result<PgPool, String> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|_| "postgres test connection failed".to_string())?;

        super::run_migrations(&pool)
            .await
            .map_err(|_| "postgres test migrations failed".to_string())?;

        Ok(pool)
    }

    fn non_empty_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn local_postgres_test_urls() -> [&'static str; 4] {
        [
            "postgres://auth_user:change_me@127.0.0.1:5432/auth",
            "postgres://postgres:postgres@127.0.0.1:5432/postgres",
            "postgres://postgres@127.0.0.1:5432/postgres",
            "postgresql:///postgres?host=/var/run/postgresql",
        ]
    }

    async fn create_user_and_session(pool: &PgPool) -> String {
        let now = Utc::now();
        let user_id = create_user(pool).await;
        let session_id = uuid::Uuid::new_v4();

        sqlx::query(
            "INSERT INTO sessions (id, user_id, device_info, ip, status, created_at, last_seen_at)
             VALUES ($1, $2, $3, NULL, 'active', $4, $5)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind("postgres-refresh-test-device")
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .expect("test session should be inserted");

        session_id.to_string()
    }

    async fn create_user(pool: &PgPool) -> uuid::Uuid {
        let now = Utc::now();
        let user_id = uuid::Uuid::new_v4();

        sqlx::query(
            "INSERT INTO users (id, email, status, created_at, updated_at)
             VALUES ($1, $2, 'active', $3, $4)",
        )
        .bind(user_id)
        .bind(format!("postgres-refresh-test-{}@example.com", user_id))
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .expect("test user should be inserted");

        user_id
    }

    fn refresh_record(
        session_id: &str,
        token_hash: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> RefreshTokenRecord {
        RefreshTokenRecord {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            token_hash: token_hash.to_string(),
            expires_at,
            revoked_at,
            replaced_by: None,
            created_at: now,
        }
    }
}
