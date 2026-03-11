use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tokio::sync::watch;
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    modules::auth::{
        domain::{EmailOutboxMessage, EmailOutboxPayload, EmailTemplate},
        ports::{
            EmailOutboxFetchResult, EmailOutboxQueueSnapshot, EmailOutboxRepository,
            TransactionalEmailSender,
        },
    },
    observability,
};

#[derive(Clone)]
pub struct PostgresEmailOutboxRepository {
    pub pool: PgPool,
}

#[async_trait]
impl EmailOutboxRepository for PostgresEmailOutboxRepository {
    async fn enqueue(
        &self,
        recipient_email: &str,
        provider: &str,
        template: EmailTemplate,
        payload: EmailOutboxPayload,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let payload_json = serde_json::to_value(payload)
            .map_err(|_| "outbox payload serialize failed".to_string())?;

        sqlx::query(
            "INSERT INTO email_outbox (
                id,
                status,
                provider,
                template,
                recipient_email,
                payload,
                attempts,
                next_attempt_at,
                last_error,
                sent_at,
                failed_at,
                last_attempt_at,
                processing_owner,
                lease_expires_at,
                created_at,
                updated_at
            ) VALUES (
                $1::uuid,
                'pending',
                $2,
                $3,
                $4,
                $5::jsonb,
                0,
                $6,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                $6,
                $6
            )",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(provider)
        .bind(template.as_str())
        .bind(recipient_email.to_ascii_lowercase())
        .bind(payload_json)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| "outbox enqueue failed".to_string())?;

        Ok(())
    }

    async fn fetch_due(
        &self,
        now: DateTime<Utc>,
        batch_size: u32,
        max_attempts: u32,
        lease_expires_at: DateTime<Utc>,
        worker_id: &str,
    ) -> Result<EmailOutboxFetchResult, String> {
        let rows = sqlx::query(
            "WITH claimed AS (
                SELECT id,
                       CASE
                           WHEN status = 'processing'
                            AND (lease_expires_at IS NULL OR lease_expires_at <= $1)
                           THEN TRUE
                           ELSE FALSE
                       END AS reclaimed_after_expiry
                FROM email_outbox
                WHERE (
                        status IN ('pending', 'failed')
                        OR (
                            status = 'processing'
                            AND (lease_expires_at IS NULL OR lease_expires_at <= $1)
                        )
                    )
                  AND next_attempt_at IS NOT NULL
                  AND next_attempt_at <= $1
                  AND attempts < $2
                ORDER BY next_attempt_at ASC
                LIMIT $3
                FOR UPDATE SKIP LOCKED
            )
            UPDATE email_outbox AS outbox
            SET status = 'processing',
                processing_owner = $5,
                lease_expires_at = $4,
                updated_at = $1
            FROM claimed
            WHERE outbox.id = claimed.id
            RETURNING outbox.id::text AS id,
                      outbox.recipient_email,
                      outbox.provider,
                      outbox.template,
                      outbox.payload,
                      outbox.attempts,
                      outbox.next_attempt_at,
                      outbox.created_at,
                      outbox.updated_at,
                      claimed.reclaimed_after_expiry",
        )
        .bind(now)
        .bind(max_attempts as i32)
        .bind(batch_size as i64)
        .bind(lease_expires_at)
        .bind(worker_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| "outbox fetch due failed".to_string())?;

        let mut messages = Vec::with_capacity(rows.len());
        let mut reclaimed_after_expiry_count: u64 = 0;
        for row in rows {
            let template_value: String = row
                .try_get("template")
                .map_err(|_| "invalid outbox template".to_string())?;
            let template = EmailTemplate::from_str(template_value.as_str())
                .ok_or_else(|| "unknown outbox template".to_string())?;
            let payload: serde_json::Value = row
                .try_get("payload")
                .map_err(|_| "invalid outbox payload".to_string())?;
            let payload = serde_json::from_value(payload)
                .map_err(|_| "outbox payload decode failed".to_string())?;
            let attempts: i32 = row
                .try_get("attempts")
                .map_err(|_| "invalid outbox attempts".to_string())?;

            messages.push(EmailOutboxMessage {
                id: row
                    .try_get("id")
                    .map_err(|_| "invalid outbox id".to_string())?,
                recipient_email: row
                    .try_get("recipient_email")
                    .map_err(|_| "invalid outbox recipient".to_string())?,
                provider: row
                    .try_get("provider")
                    .map_err(|_| "invalid outbox provider".to_string())?,
                template,
                payload,
                attempts: attempts.max(0) as u32,
                next_attempt_at: row
                    .try_get("next_attempt_at")
                    .map_err(|_| "invalid outbox next_attempt_at".to_string())?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|_| "invalid outbox created_at".to_string())?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|_| "invalid outbox updated_at".to_string())?,
            });

            let reclaimed_after_expiry: bool = row
                .try_get("reclaimed_after_expiry")
                .map_err(|_| "invalid outbox reclaim flag".to_string())?;
            if reclaimed_after_expiry {
                reclaimed_after_expiry_count = reclaimed_after_expiry_count.saturating_add(1);
            }
        }

        Ok(EmailOutboxFetchResult {
            claimed_count: messages.len() as u64,
            reclaimed_after_expiry_count,
            messages,
        })
    }

    async fn mark_sent(
        &self,
        message_id: &str,
        worker_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let result = sqlx::query(
            "UPDATE email_outbox
             SET status = 'sent',
                 attempts = attempts + 1,
                 last_attempt_at = $2,
                 sent_at = $2,
                 failed_at = NULL,
                 last_error = NULL,
                 processing_owner = NULL,
                 lease_expires_at = NULL,
                 next_attempt_at = NULL,
                 updated_at = $2
             WHERE id = $1::uuid
               AND status = 'processing'
               AND processing_owner = $3",
        )
        .bind(message_id)
        .bind(now)
        .bind(worker_id)
        .execute(&self.pool)
        .await
        .map_err(|_| "outbox mark sent failed".to_string())?;

        if result.rows_affected() == 0 {
            return Err("outbox mark sent lease no longer owned".to_string());
        }

        Ok(())
    }

    async fn mark_failed_backoff(
        &self,
        message_id: &str,
        worker_id: &str,
        next_attempt_at: Option<DateTime<Utc>>,
        last_error: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let result = sqlx::query(
            "UPDATE email_outbox
              SET status = 'failed',
                  attempts = attempts + 1,
                  last_attempt_at = $3,
                  next_attempt_at = $2,
                  last_error = $4,
                  processing_owner = NULL,
                  lease_expires_at = NULL,
                  failed_at = CASE WHEN $2 IS NULL THEN $3 ELSE failed_at END,
                  updated_at = $3
              WHERE id = $1::uuid
                AND status = 'processing'
                AND processing_owner = $5",
        )
        .bind(message_id)
        .bind(next_attempt_at)
        .bind(now)
        .bind(last_error)
        .bind(worker_id)
        .execute(&self.pool)
        .await
        .map_err(|_| "outbox mark failed failed".to_string())?;

        if result.rows_affected() == 0 {
            return Err("outbox mark failed lease no longer owned".to_string());
        }

        Ok(())
    }

    async fn queue_snapshot(&self, now: DateTime<Utc>) -> Result<EmailOutboxQueueSnapshot, String> {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS pending_count,
                    COALESCE(
                        GREATEST(EXTRACT(EPOCH FROM ($1 - MIN(created_at))), 0),
                        0
                    )::bigint AS oldest_pending_age_seconds,
                    COALESCE(
                        GREATEST(
                            EXTRACT(
                                EPOCH FROM (
                                    $1 - MIN(created_at) FILTER (WHERE next_attempt_at <= $1)
                                )
                            ),
                            0
                        ),
                        0
                    )::bigint AS oldest_due_age_seconds
             FROM email_outbox
             WHERE status IN ('pending', 'failed')
                AND next_attempt_at IS NOT NULL",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| "outbox queue snapshot query failed".to_string())?;

        let pending_count: i64 = row
            .try_get("pending_count")
            .map_err(|_| "invalid outbox queue depth".to_string())?;
        let oldest_pending_age_seconds: i64 = row
            .try_get("oldest_pending_age_seconds")
            .map_err(|_| "invalid outbox oldest pending age".to_string())?;
        let oldest_due_age_seconds: i64 = row
            .try_get("oldest_due_age_seconds")
            .map_err(|_| "invalid outbox oldest due age".to_string())?;

        Ok(EmailOutboxQueueSnapshot {
            pending_count: pending_count.max(0) as u64,
            oldest_pending_age_seconds: oldest_pending_age_seconds.max(0) as u64,
            oldest_due_age_seconds: oldest_due_age_seconds.max(0) as u64,
        })
    }
}

#[derive(Clone)]
pub struct OutboxTransactionalEmailSender {
    repository: Arc<dyn EmailOutboxRepository>,
    provider: String,
}

impl OutboxTransactionalEmailSender {
    pub fn new(repository: Arc<dyn EmailOutboxRepository>, provider: String) -> Self {
        Self {
            repository,
            provider,
        }
    }
}

#[async_trait]
impl TransactionalEmailSender for OutboxTransactionalEmailSender {
    async fn send_verification_email(
        &self,
        recipient_email: &str,
        verification_token: &str,
        expires_in_seconds: i64,
    ) -> Result<(), String> {
        self.repository
            .enqueue(
                recipient_email,
                &self.provider,
                EmailTemplate::Verification,
                EmailOutboxPayload::Verification {
                    verification_token: verification_token.to_string(),
                    expires_in_seconds,
                },
                Utc::now(),
            )
            .await
    }

    async fn send_password_reset_email(
        &self,
        recipient_email: &str,
        reset_token: &str,
        expires_in_seconds: i64,
    ) -> Result<(), String> {
        self.repository
            .enqueue(
                recipient_email,
                &self.provider,
                EmailTemplate::PasswordReset,
                EmailOutboxPayload::PasswordReset {
                    reset_token: reset_token.to_string(),
                    expires_in_seconds,
                },
                Utc::now(),
            )
            .await
    }
}

#[derive(Clone, Debug)]
pub struct OutboxWorkerConfig {
    pub poll_interval: Duration,
    pub batch_size: u32,
    pub max_attempts: u32,
    pub lease_duration: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
}

#[derive(Clone)]
pub struct OutboxDispatcher {
    repository: Arc<dyn EmailOutboxRepository>,
    sender: Arc<dyn TransactionalEmailSender>,
    config: OutboxWorkerConfig,
    worker_id: String,
}

impl OutboxDispatcher {
    pub fn new(
        repository: Arc<dyn EmailOutboxRepository>,
        sender: Arc<dyn TransactionalEmailSender>,
        config: OutboxWorkerConfig,
    ) -> Self {
        Self {
            repository,
            sender,
            config,
            worker_id: Uuid::new_v4().to_string(),
        }
    }

    pub async fn run_until_shutdown(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            self.dispatch_once().await;

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = sleep(self.config.poll_interval) => {}
            }
        }
    }

    pub async fn dispatch_once(&self) {
        let now = Utc::now();
        let lease_expires_at = now
            + chrono::Duration::from_std(self.config.lease_duration)
                .unwrap_or_else(|_| chrono::Duration::milliseconds(i64::MAX));
        match self
            .repository
            .fetch_due(
                now,
                self.config.batch_size,
                self.config.max_attempts,
                lease_expires_at,
                &self.worker_id,
            )
            .await
        {
            Ok(fetch_result) => {
                observability::record_email_outbox_claim_poll(
                    fetch_result.claimed_count,
                    fetch_result.reclaimed_after_expiry_count,
                );
                for message in fetch_result.messages {
                    self.dispatch_message(message).await;
                }
            }
            Err(error) => {
                observability::record_email_outbox_claim_failure();
                tracing::warn!(error = %error, "email outbox fetch failed");
            }
        }

        if let Ok(queue_snapshot) = self.repository.queue_snapshot(Utc::now()).await {
            observability::set_email_outbox_queue_depth(queue_snapshot.pending_count);
            observability::set_email_outbox_oldest_pending_age_seconds(
                queue_snapshot.oldest_pending_age_seconds,
            );
            observability::set_email_outbox_oldest_due_age_seconds(
                queue_snapshot.oldest_due_age_seconds,
            );
        }
    }

    async fn dispatch_message(&self, message: EmailOutboxMessage) {
        let attempt_number = message.attempts.saturating_add(1);
        let template = message.template.as_str();
        let provider = message.provider.as_str();
        let delivery = match &message.payload {
            EmailOutboxPayload::Verification {
                verification_token,
                expires_in_seconds,
            } => {
                self.sender
                    .send_verification_email(
                        &message.recipient_email,
                        verification_token,
                        *expires_in_seconds,
                    )
                    .await
            }
            EmailOutboxPayload::PasswordReset {
                reset_token,
                expires_in_seconds,
            } => {
                self.sender
                    .send_password_reset_email(
                        &message.recipient_email,
                        reset_token,
                        *expires_in_seconds,
                    )
                    .await
            }
        };

        let now = Utc::now();
        match delivery {
            Ok(()) => {
                if let Err(error) = self
                    .repository
                    .mark_sent(&message.id, &self.worker_id, now)
                    .await
                {
                    tracing::warn!(message_id = %message.id, error = %error, "email outbox mark sent failed");
                    return;
                }
                observability::record_email_outbox_dispatch(
                    provider,
                    template,
                    "sent",
                    attempt_number,
                );
            }
            Err(error) => {
                let next_attempt_at = next_attempt_at(
                    attempt_number,
                    self.config.max_attempts,
                    now,
                    self.config.backoff_base,
                    self.config.backoff_max,
                );
                if let Err(mark_error) = self
                    .repository
                    .mark_failed_backoff(&message.id, &self.worker_id, next_attempt_at, &error, now)
                    .await
                {
                    tracing::warn!(message_id = %message.id, error = %mark_error, "email outbox mark failed failed");
                    return;
                }

                let outcome = if next_attempt_at.is_some() {
                    "failed_retryable"
                } else {
                    "failed_exhausted"
                };
                observability::record_email_outbox_dispatch(
                    provider,
                    template,
                    outcome,
                    attempt_number,
                );
                tracing::warn!(
                    message_id = %message.id,
                    attempt = attempt_number,
                    max_attempts = self.config.max_attempts,
                    error = %error,
                    "email outbox dispatch failed"
                );
            }
        }
    }
}

fn next_attempt_at(
    attempt_number: u32,
    max_attempts: u32,
    now: DateTime<Utc>,
    backoff_base: Duration,
    backoff_max: Duration,
) -> Option<DateTime<Utc>> {
    if attempt_number >= max_attempts {
        return None;
    }

    let exponent = attempt_number.saturating_sub(1).min(16);
    let multiplier = 1_u128 << exponent;
    let backoff_ms =
        (backoff_base.as_millis().saturating_mul(multiplier)).min(backoff_max.as_millis());
    let backoff_ms = i64::try_from(backoff_ms).unwrap_or(i64::MAX);
    Some(now + chrono::Duration::milliseconds(backoff_ms))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use sqlx::{postgres::PgPoolOptions, PgPool};

    use crate::modules::auth::{
        domain::{EmailOutboxPayload, EmailTemplate},
        ports::EmailOutboxRepository,
    };

    use super::{next_attempt_at, PostgresEmailOutboxRepository};

    #[test]
    fn next_attempt_at_reschedules_before_max_attempts() {
        let now = chrono::Utc::now();
        let retry_at = next_attempt_at(
            1,
            5,
            now,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(60),
        )
        .expect("first failure should be retryable");

        assert_eq!((retry_at - now).num_seconds(), 1);
    }

    #[test]
    fn next_attempt_at_caps_exponential_backoff() {
        let now = chrono::Utc::now();
        let retry_at = next_attempt_at(
            10,
            20,
            now,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(30),
        )
        .expect("attempt should still be retryable");

        assert_eq!((retry_at - now).num_seconds(), 30);
    }

    #[test]
    fn next_attempt_at_stops_when_max_attempts_reached() {
        let now = chrono::Utc::now();
        let retry_at = next_attempt_at(
            5,
            5,
            now,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(30),
        );

        assert!(retry_at.is_none());
    }

    #[tokio::test]
    async fn claimed_rows_are_not_reclaimed_before_lease_expiry() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresEmailOutboxRepository { pool: pool.clone() };

        let now = Utc::now();
        repo.enqueue(
            "lease-test-before-expiry@example.com",
            "sendgrid",
            EmailTemplate::Verification,
            EmailOutboxPayload::Verification {
                verification_token: "token-a".to_string(),
                expires_in_seconds: 900,
            },
            now,
        )
        .await
        .expect("outbox enqueue should succeed");

        let claimed = repo
            .fetch_due(now, 10, 8, now + ChronoDuration::seconds(30), "worker-a")
            .await
            .expect("first worker should claim message");
        assert_eq!(claimed.messages.len(), 1);
        assert_eq!(claimed.claimed_count, 1);
        assert_eq!(claimed.reclaimed_after_expiry_count, 0);

        let second_claim = repo
            .fetch_due(
                now + ChronoDuration::seconds(5),
                10,
                8,
                now + ChronoDuration::seconds(35),
                "worker-b",
            )
            .await
            .expect("second claim attempt should succeed");
        assert!(second_claim.messages.is_empty());
        assert_eq!(second_claim.claimed_count, 0);
        assert_eq!(second_claim.reclaimed_after_expiry_count, 0);
    }

    #[tokio::test]
    async fn expired_leases_become_claimable_again() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresEmailOutboxRepository { pool: pool.clone() };

        let now = Utc::now();
        repo.enqueue(
            "lease-test-expired@example.com",
            "sendgrid",
            EmailTemplate::PasswordReset,
            EmailOutboxPayload::PasswordReset {
                reset_token: "token-b".to_string(),
                expires_in_seconds: 900,
            },
            now,
        )
        .await
        .expect("outbox enqueue should succeed");

        let initial_claim = repo
            .fetch_due(now, 10, 8, now + ChronoDuration::seconds(10), "worker-a")
            .await
            .expect("first worker should claim message");
        assert_eq!(initial_claim.messages.len(), 1);
        let claimed_id = initial_claim.messages[0].id.clone();

        let reclaimed = repo
            .fetch_due(
                now + ChronoDuration::seconds(11),
                10,
                8,
                now + ChronoDuration::seconds(21),
                "worker-b",
            )
            .await
            .expect("expired lease should be reclaimable");
        assert_eq!(reclaimed.messages.len(), 1);
        assert_eq!(reclaimed.messages[0].id, claimed_id);
        assert_eq!(reclaimed.reclaimed_after_expiry_count, 1);
    }

    #[tokio::test]
    async fn queue_snapshot_tracks_oldest_due_separately_from_oldest_pending() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PostgresEmailOutboxRepository { pool: pool.clone() };

        let now = Utc::now();
        repo.enqueue(
            "snapshot-scheduled@example.com",
            "sendgrid",
            EmailTemplate::Verification,
            EmailOutboxPayload::Verification {
                verification_token: "token-c".to_string(),
                expires_in_seconds: 900,
            },
            now,
        )
        .await
        .expect("outbox enqueue should succeed");

        repo.enqueue(
            "snapshot-due@example.com",
            "sendgrid",
            EmailTemplate::PasswordReset,
            EmailOutboxPayload::PasswordReset {
                reset_token: "token-d".to_string(),
                expires_in_seconds: 900,
            },
            now,
        )
        .await
        .expect("outbox enqueue should succeed");

        sqlx::query(
            "UPDATE email_outbox
             SET created_at = $1,
                 next_attempt_at = $2,
                 updated_at = $3
             WHERE recipient_email = 'snapshot-scheduled@example.com'",
        )
        .bind(now - ChronoDuration::minutes(40))
        .bind(now + ChronoDuration::minutes(30))
        .bind(now)
        .execute(&pool)
        .await
        .expect("scheduled row should update");

        sqlx::query(
            "UPDATE email_outbox
             SET created_at = $1,
                 next_attempt_at = $2,
                 updated_at = $3
             WHERE recipient_email = 'snapshot-due@example.com'",
        )
        .bind(now - ChronoDuration::minutes(10))
        .bind(now - ChronoDuration::minutes(1))
        .bind(now)
        .execute(&pool)
        .await
        .expect("due row should update");

        let snapshot = repo
            .queue_snapshot(now)
            .await
            .expect("queue snapshot should succeed");

        assert_eq!(snapshot.pending_count, 2);
        assert_eq!(snapshot.oldest_pending_age_seconds, 40 * 60);
        assert_eq!(snapshot.oldest_due_age_seconds, 10 * 60);
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

        crate::adapters::postgres::run_migrations(&pool)
            .await
            .map_err(|_| "postgres test migrations failed".to_string())?;

        sqlx::query("TRUNCATE TABLE email_outbox")
            .execute(&pool)
            .await
            .map_err(|_| "postgres test cleanup failed".to_string())?;

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
}
