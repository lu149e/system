use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::config::AuthRuntime;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ComponentState {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ComponentState {
    fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            detail: None,
        }
    }

    fn not_configured() -> Self {
        Self {
            status: "not_configured".to_string(),
            detail: None,
        }
    }

    fn failure(detail: String) -> Self {
        Self {
            status: "error".to_string(),
            detail: Some(detail),
        }
    }

    fn degraded(detail: String) -> Self {
        Self {
            status: "degraded".to_string(),
            detail: Some(detail),
        }
    }
}

#[derive(Debug, Default)]
struct PasskeyChallengeJanitorTimeline {
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    last_failure_detail: Option<String>,
}

#[derive(Debug)]
pub struct PasskeyChallengeJanitorHealth {
    enabled: bool,
    stale_after: chrono::Duration,
    timeline: Mutex<PasskeyChallengeJanitorTimeline>,
}

impl PasskeyChallengeJanitorHealth {
    pub fn new(enabled: bool, stale_after: Duration) -> Self {
        let stale_after =
            chrono::Duration::from_std(stale_after).unwrap_or_else(|_| chrono::Duration::hours(24));
        Self {
            enabled,
            stale_after,
            timeline: Mutex::new(PasskeyChallengeJanitorTimeline::default()),
        }
    }

    pub fn record_success(&self, now: DateTime<Utc>) {
        if let Ok(mut timeline) = self.timeline.lock() {
            timeline.last_success_at = Some(now);
        }
    }

    pub fn record_failure(&self, now: DateTime<Utc>, detail: String) {
        if let Ok(mut timeline) = self.timeline.lock() {
            timeline.last_failure_at = Some(now);
            timeline.last_failure_detail = Some(detail);
        }
    }

    fn as_component_state(&self) -> ComponentState {
        if !self.enabled {
            return ComponentState::not_configured();
        }

        let Ok(timeline) = self.timeline.lock() else {
            return ComponentState::degraded(
                "passkey janitor health state is unavailable".to_string(),
            );
        };

        let last_success_at = timeline.last_success_at;
        let last_failure_at = timeline.last_failure_at;
        let last_failure_detail = timeline.last_failure_detail.clone();

        if last_success_at.is_none() && last_failure_at.is_none() {
            return ComponentState {
                status: "starting".to_string(),
                detail: Some("waiting for first passkey janitor execution".to_string()),
            };
        }

        let last_success_display = last_success_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "never".to_string());
        let last_failure_display = last_failure_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "never".to_string());
        let last_failure_detail_display = last_failure_detail
            .unwrap_or_else(|| "none".to_string())
            .replace('\n', " ");
        let detail = format!(
            "last_success_at={last_success_display}; last_failure_at={last_failure_display}; last_failure_detail={last_failure_detail_display}"
        );

        if let Some(last_failure_at) = last_failure_at {
            let failure_is_newer_than_success = last_success_at
                .map(|success| last_failure_at > success)
                .unwrap_or(true);
            if failure_is_newer_than_success {
                return ComponentState::degraded(detail);
            }
        }

        if let Some(last_success_at) = last_success_at {
            let staleness = Utc::now().signed_duration_since(last_success_at);
            if staleness > self.stale_after {
                return ComponentState::degraded(format!(
                    "{detail}; stale_for_seconds={}",
                    staleness.num_seconds().max(0)
                ));
            }
        }

        ComponentState {
            status: "ok".to_string(),
            detail: Some(detail),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessComponents {
    pub app: ComponentState,
    pub database: ComponentState,
    pub redis: ComponentState,
    pub passkey_challenge_janitor: ComponentState,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessPayload {
    pub status: String,
    pub runtime: String,
    pub components: ReadinessComponents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessReport {
    pub is_ready: bool,
    pub payload: ReadinessPayload,
}

#[async_trait]
pub trait ReadinessChecker: Send + Sync {
    async fn check(&self) -> ReadinessReport;
}

#[async_trait]
trait DependencyProbe: Send + Sync {
    fn component_name(&self) -> &'static str;
    async fn ping(&self) -> Result<(), String>;
}

struct PostgresProbe {
    pool: PgPool,
}

#[async_trait]
impl DependencyProbe for PostgresProbe {
    fn component_name(&self) -> &'static str {
        "database"
    }

    async fn ping(&self) -> Result<(), String> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| format!("db ping failed: {error}"))
    }
}

struct RedisProbe {
    client: redis::Client,
}

#[async_trait]
impl DependencyProbe for RedisProbe {
    fn component_name(&self) -> &'static str {
        "redis"
    }

    async fn ping(&self) -> Result<(), String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|error| format!("redis connect failed: {error}"))?;

        let pong = redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|error| format!("redis ping failed: {error}"))?;
        if pong == "PONG" {
            Ok(())
        } else {
            Err(format!("redis ping returned unexpected response: {pong}"))
        }
    }
}

pub struct RuntimeReadinessChecker {
    runtime: AuthRuntime,
    timeout: Duration,
    dependencies: Vec<Arc<dyn DependencyProbe>>,
    passkey_challenge_janitor_health: Arc<PasskeyChallengeJanitorHealth>,
}

impl RuntimeReadinessChecker {
    pub fn inmemory(
        passkey_challenge_janitor_health: Arc<PasskeyChallengeJanitorHealth>,
    ) -> Arc<dyn ReadinessChecker> {
        Arc::new(Self {
            runtime: AuthRuntime::InMemory,
            timeout: Duration::from_secs(1),
            dependencies: Vec::new(),
            passkey_challenge_janitor_health,
        })
    }

    pub fn postgres_redis(
        pool: PgPool,
        redis_client: Option<redis::Client>,
        timeout: Duration,
        passkey_challenge_janitor_health: Arc<PasskeyChallengeJanitorHealth>,
    ) -> Arc<dyn ReadinessChecker> {
        let mut dependencies: Vec<Arc<dyn DependencyProbe>> = Vec::new();
        dependencies.push(Arc::new(PostgresProbe { pool }));

        if let Some(client) = redis_client {
            dependencies.push(Arc::new(RedisProbe { client }));
        }

        Arc::new(Self {
            runtime: AuthRuntime::PostgresRedis,
            timeout,
            dependencies,
            passkey_challenge_janitor_health,
        })
    }
}

#[async_trait]
impl ReadinessChecker for RuntimeReadinessChecker {
    async fn check(&self) -> ReadinessReport {
        let mut components = ReadinessComponents {
            app: ComponentState::ok(),
            database: ComponentState::not_configured(),
            redis: ComponentState::not_configured(),
            passkey_challenge_janitor: ComponentState::not_configured(),
        };
        let mut is_ready = true;

        for dependency in &self.dependencies {
            let state = match tokio::time::timeout(self.timeout, dependency.ping()).await {
                Ok(Ok(())) => ComponentState::ok(),
                Ok(Err(error)) => {
                    is_ready = false;
                    ComponentState::failure(error)
                }
                Err(_) => {
                    is_ready = false;
                    ComponentState::failure(format!("{} timed out", dependency.component_name()))
                }
            };

            match dependency.component_name() {
                "database" => components.database = state,
                "redis" => components.redis = state,
                _ => {
                    is_ready = false;
                }
            }
        }

        components.passkey_challenge_janitor =
            self.passkey_challenge_janitor_health.as_component_state();

        let payload = ReadinessPayload {
            status: if is_ready {
                "ok".to_string()
            } else {
                "error".to_string()
            },
            runtime: match self.runtime {
                AuthRuntime::InMemory => "inmemory".to_string(),
                AuthRuntime::PostgresRedis => "postgres_redis".to_string(),
            },
            components,
        };

        ReadinessReport { is_ready, payload }
    }
}

#[cfg(test)]
mod tests {
    use super::{PasskeyChallengeJanitorHealth, RuntimeReadinessChecker};
    use chrono::{Duration, Utc};
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    #[test]
    fn passkey_janitor_reports_not_configured_when_disabled() {
        let health = PasskeyChallengeJanitorHealth::new(false, StdDuration::from_secs(60));

        let state = health.as_component_state();

        assert_eq!(state.status, "not_configured");
        assert!(state.detail.is_none());
    }

    #[test]
    fn passkey_janitor_reports_degraded_when_failure_is_newer_than_success() {
        let health = PasskeyChallengeJanitorHealth::new(true, StdDuration::from_secs(60));
        let now = Utc::now();
        health.record_success(now - Duration::seconds(30));
        health.record_failure(now, "db timeout".to_string());

        let state = health.as_component_state();

        assert_eq!(state.status, "degraded");
        assert!(state
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("db timeout"));
    }

    #[tokio::test]
    async fn readiness_payload_includes_passkey_janitor_component() {
        let checker = RuntimeReadinessChecker::inmemory(Arc::new(
            PasskeyChallengeJanitorHealth::new(true, StdDuration::from_secs(60)),
        ));

        let report = checker.check().await;

        assert!(report.is_ready);
        assert_eq!(
            report.payload.components.passkey_challenge_janitor.status,
            "starting"
        );
    }

    #[test]
    fn passkey_janitor_reports_degraded_when_success_is_stale() {
        let health = PasskeyChallengeJanitorHealth::new(true, StdDuration::from_secs(60));
        let now = Utc::now();
        health.record_success(now - Duration::seconds(180));

        let state = health.as_component_state();

        assert_eq!(state.status, "degraded");
        assert!(state
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("stale_for_seconds="));
    }
}
