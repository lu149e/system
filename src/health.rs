use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
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
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessComponents {
    pub app: ComponentState,
    pub database: ComponentState,
    pub redis: ComponentState,
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
}

impl RuntimeReadinessChecker {
    pub fn inmemory() -> Arc<dyn ReadinessChecker> {
        Arc::new(Self {
            runtime: AuthRuntime::InMemory,
            timeout: Duration::from_secs(1),
            dependencies: Vec::new(),
        })
    }

    pub fn postgres_redis(
        pool: PgPool,
        redis_client: Option<redis::Client>,
        timeout: Duration,
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
