use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use redis::AsyncCommands;

use crate::{
    config::{LoginAbuseBucketMode, LoginAbuseRedisFailMode},
    modules::auth::ports::{LoginAbuseProtector, LoginGateDecision},
};

#[derive(Clone)]
pub struct RedisLoginAbuseProtector {
    client: redis::Client,
    max_attempts: u32,
    window_seconds: i64,
    lockout_base_seconds: i64,
    lockout_max_seconds: i64,
    attempts_prefix: String,
    lock_prefix: String,
    strikes_prefix: String,
    fail_mode: LoginAbuseRedisFailMode,
    bucket_mode: LoginAbuseBucketMode,
}

impl RedisLoginAbuseProtector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        redis_url: &str,
        max_attempts: u32,
        window_seconds: i64,
        lockout_base_seconds: i64,
        lockout_max_seconds: i64,
        attempts_prefix: String,
        lock_prefix: String,
        strikes_prefix: String,
        fail_mode: LoginAbuseRedisFailMode,
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
        if attempts_prefix.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "LOGIN_ABUSE_ATTEMPTS_PREFIX must not be empty"
            ));
        }
        if lock_prefix.trim().is_empty() {
            return Err(anyhow::anyhow!("LOGIN_ABUSE_LOCK_PREFIX must not be empty"));
        }
        if strikes_prefix.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "LOGIN_ABUSE_STRIKES_PREFIX must not be empty"
            ));
        }

        Ok(Self {
            client: redis::Client::open(redis_url)?,
            max_attempts,
            window_seconds,
            lockout_base_seconds,
            lockout_max_seconds,
            attempts_prefix,
            lock_prefix,
            strikes_prefix,
            fail_mode,
            bucket_mode,
        })
    }

    fn source_bucket_key(&self, email: &str, source_ip: Option<&str>) -> String {
        let ip_part = source_ip
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("no-ip")
            .to_ascii_lowercase();
        format!("{}|{}", email.to_ascii_lowercase(), ip_part)
    }

    fn abuse_keys(&self, email: &str, source_ip: Option<&str>) -> Vec<String> {
        let source_bucket_key = self.source_bucket_key(email, source_ip);
        match self.bucket_mode {
            LoginAbuseBucketMode::IpOnly => vec![source_bucket_key],
            LoginAbuseBucketMode::EmailAndIp => {
                vec![
                    format!("{}|any", email.to_ascii_lowercase()),
                    source_bucket_key,
                ]
            }
        }
    }

    fn attempts_key(&self, abuse_key: &str) -> String {
        format!("{}:{}", self.attempts_prefix, abuse_key)
    }

    fn lock_key(&self, abuse_key: &str) -> String {
        format!("{}:{}", self.lock_prefix, abuse_key)
    }

    fn strikes_key(&self, abuse_key: &str) -> String {
        format!("{}:{}", self.strikes_prefix, abuse_key)
    }

    fn fail_closed_until(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::seconds(self.lockout_base_seconds)
    }

    fn fail_closed_decision(&self, now: DateTime<Utc>) -> LoginGateDecision {
        LoginGateDecision::Locked {
            until: self.fail_closed_until(now),
        }
    }

    fn should_fail_closed(&self) -> bool {
        self.fail_mode == LoginAbuseRedisFailMode::FailClosed
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

    pub fn health_client(&self) -> redis::Client {
        self.client.clone()
    }
}

#[async_trait]
impl LoginAbuseProtector for RedisLoginAbuseProtector {
    async fn check(
        &self,
        email: &str,
        source_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> LoginGateDecision {
        let abuse_keys = self.abuse_keys(email, source_ip);
        let mut conn = match self.client.get_multiplexed_async_connection().await {
            Ok(conn) => conn,
            Err(error) => {
                if self.should_fail_closed() {
                    tracing::error!(?error, "redis unavailable during login abuse check");
                    return self.fail_closed_decision(now);
                }
                tracing::warn!(
                    ?error,
                    "redis unavailable during login abuse check, fail-open active"
                );
                return LoginGateDecision::Allowed;
            }
        };

        let mut locked_until: Option<DateTime<Utc>> = None;
        for abuse_key in abuse_keys {
            let lock_key = self.lock_key(&abuse_key);
            let locked_until_ts = match conn.get::<_, Option<i64>>(lock_key).await {
                Ok(value) => value,
                Err(error) => {
                    if self.should_fail_closed() {
                        tracing::error!(?error, "redis read failed during login abuse check");
                        return self.fail_closed_decision(now);
                    }
                    tracing::warn!(
                        ?error,
                        "redis read failed during login abuse check, fail-open active"
                    );
                    return LoginGateDecision::Allowed;
                }
            };

            let Some(locked_until_ts) = locked_until_ts else {
                continue;
            };
            let Some(until) = Utc.timestamp_opt(locked_until_ts, 0).single() else {
                continue;
            };

            if until > now {
                locked_until = Some(match locked_until {
                    Some(current) if current > until => current,
                    _ => until,
                });
            }
        }

        if let Some(until) = locked_until {
            return LoginGateDecision::Locked { until };
        }

        LoginGateDecision::Allowed
    }

    async fn register_failure(
        &self,
        email: &str,
        source_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let abuse_keys = self.abuse_keys(email, source_ip);

        let mut conn = match self.client.get_multiplexed_async_connection().await {
            Ok(conn) => conn,
            Err(error) => {
                if self.should_fail_closed() {
                    let until = self.fail_closed_until(now);
                    tracing::error!(
                        ?error,
                        "redis unavailable during login abuse register failure"
                    );
                    return Some(until);
                }
                tracing::warn!(
                    ?error,
                    "redis unavailable during login abuse register failure, fail-open active"
                );
                return None;
            }
        };

        let mut lock_until: Option<DateTime<Utc>> = None;

        for abuse_key in abuse_keys {
            let attempts_key = self.attempts_key(&abuse_key);
            let lock_key = self.lock_key(&abuse_key);
            let strikes_key = self.strikes_key(&abuse_key);

            let attempts = match redis::pipe()
                .cmd("INCR")
                .arg(&attempts_key)
                .cmd("EXPIRE")
                .arg(&attempts_key)
                .arg(self.window_seconds)
                .query_async::<(u32, i32)>(&mut conn)
                .await
            {
                Ok((attempts, _)) => attempts,
                Err(error) => {
                    if self.should_fail_closed() {
                        let until = self.fail_closed_until(now);
                        tracing::error!(
                            ?error,
                            "redis write failed during login abuse register failure"
                        );
                        return Some(until);
                    }
                    tracing::warn!(
                        ?error,
                        "redis write failed during login abuse register failure, fail-open active"
                    );
                    continue;
                }
            };

            if attempts < self.max_attempts {
                continue;
            }

            let strikes = match redis::pipe()
                .cmd("INCR")
                .arg(&strikes_key)
                .cmd("EXPIRE")
                .arg(&strikes_key)
                .arg(self.lockout_max_seconds.max(self.window_seconds))
                .query_async::<(u32, i32)>(&mut conn)
                .await
            {
                Ok((strikes, _)) => strikes,
                Err(error) => {
                    if self.should_fail_closed() {
                        let until = self.fail_closed_until(now);
                        tracing::error!(
                            ?error,
                            "redis write failed while incrementing lockout strikes"
                        );
                        return Some(until);
                    }
                    tracing::warn!(
                        ?error,
                        "redis write failed while incrementing lockout strikes, fail-open active"
                    );
                    continue;
                }
            };

            let lockout_seconds = self.lockout_seconds_for_strikes(strikes);
            let until = now + Duration::seconds(lockout_seconds);
            let set_result = redis::pipe()
                .cmd("SET")
                .arg(&lock_key)
                .arg(until.timestamp())
                .arg("EX")
                .arg(lockout_seconds)
                .ignore()
                .cmd("DEL")
                .arg(&attempts_key)
                .ignore()
                .query_async::<()>(&mut conn)
                .await;

            if let Err(error) = set_result {
                if self.should_fail_closed() {
                    let fallback_until = self.fail_closed_until(now);
                    tracing::error!(?error, "redis write failed while setting login lockout");
                    return Some(fallback_until);
                }
                tracing::warn!(
                    ?error,
                    "redis write failed while setting login lockout, fail-open active"
                );
                continue;
            }

            lock_until = Some(match lock_until {
                Some(current) if current > until => current,
                _ => until,
            });
        }

        lock_until
    }

    async fn register_success(&self, email: &str, source_ip: Option<&str>) {
        let abuse_keys = self.abuse_keys(email, source_ip);
        let mut conn = match self.client.get_multiplexed_async_connection().await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::error!(
                    ?error,
                    "redis unavailable during login abuse register success"
                );
                return;
            }
        };

        for abuse_key in abuse_keys {
            let attempts_key = self.attempts_key(&abuse_key);
            let lock_key = self.lock_key(&abuse_key);
            let strikes_key = self.strikes_key(&abuse_key);
            if let Err(error) = redis::pipe()
                .cmd("DEL")
                .arg(attempts_key)
                .arg(lock_key)
                .arg(strikes_key)
                .query_async::<()>(&mut conn)
                .await
            {
                tracing::error!(
                    ?error,
                    "redis write failed during login abuse register success"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::{
        config::{LoginAbuseBucketMode, LoginAbuseRedisFailMode},
        modules::auth::ports::{LoginAbuseProtector, LoginGateDecision},
    };

    use super::RedisLoginAbuseProtector;

    #[tokio::test]
    async fn redis_check_fails_closed_when_configured_and_unavailable() {
        let protector = RedisLoginAbuseProtector::new(
            "redis://127.0.0.1:1",
            5,
            300,
            900,
            7200,
            "test:attempts".to_string(),
            "test:lock".to_string(),
            "test:strikes".to_string(),
            LoginAbuseRedisFailMode::FailClosed,
            LoginAbuseBucketMode::EmailAndIp,
        )
        .expect("redis protector should initialize");

        let now = Utc::now();
        let decision = protector
            .check("user@example.com", Some("203.0.113.10"), now)
            .await;

        match decision {
            LoginGateDecision::Locked { until } => {
                assert_eq!(until, now + Duration::seconds(900));
            }
            LoginGateDecision::Allowed => panic!("fail-closed mode should lock when redis is down"),
        }
    }

    #[tokio::test]
    async fn redis_check_fails_open_when_configured_and_unavailable() {
        let protector = RedisLoginAbuseProtector::new(
            "redis://127.0.0.1:1",
            5,
            300,
            900,
            7200,
            "test:attempts".to_string(),
            "test:lock".to_string(),
            "test:strikes".to_string(),
            LoginAbuseRedisFailMode::FailOpen,
            LoginAbuseBucketMode::EmailAndIp,
        )
        .expect("redis protector should initialize");

        let decision = protector
            .check("user@example.com", Some("203.0.113.10"), Utc::now())
            .await;
        assert!(matches!(decision, LoginGateDecision::Allowed));
    }

    #[tokio::test]
    async fn redis_register_failure_fails_closed_when_unavailable() {
        let protector = RedisLoginAbuseProtector::new(
            "redis://127.0.0.1:1",
            5,
            300,
            900,
            7200,
            "test:attempts".to_string(),
            "test:lock".to_string(),
            "test:strikes".to_string(),
            LoginAbuseRedisFailMode::FailClosed,
            LoginAbuseBucketMode::EmailAndIp,
        )
        .expect("redis protector should initialize");

        let now = Utc::now();
        let lock_until = protector
            .register_failure("user@example.com", Some("203.0.113.10"), now)
            .await;

        assert_eq!(lock_until, Some(now + Duration::seconds(900)));
    }

    #[tokio::test]
    async fn redis_register_failure_fails_open_when_unavailable() {
        let protector = RedisLoginAbuseProtector::new(
            "redis://127.0.0.1:1",
            5,
            300,
            900,
            7200,
            "test:attempts".to_string(),
            "test:lock".to_string(),
            "test:strikes".to_string(),
            LoginAbuseRedisFailMode::FailOpen,
            LoginAbuseBucketMode::EmailAndIp,
        )
        .expect("redis protector should initialize");

        let lock_until = protector
            .register_failure("user@example.com", Some("203.0.113.10"), Utc::now())
            .await;

        assert!(lock_until.is_none());
    }
}
