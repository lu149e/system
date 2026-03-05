mod adapters;
mod api;
mod config;
mod health;
mod jwks;
mod modules;
mod observability;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use adapters::{
    email::{NoopTransactionalEmailSender, SendGridTransactionalEmailSender},
    inmemory::{InMemoryAdapters, JwtEdDsaService, RefreshCryptoHmacService},
    outbox::{OutboxDispatcher, OutboxTransactionalEmailSender, OutboxWorkerConfig},
    postgres::PostgresAdapters,
    redis::RedisLoginAbuseProtector,
};
use anyhow::Context;
use axum::{
    routing::{delete, get, post},
    Router,
};
use config::{AppConfig, AuthRuntime, EmailDeliveryMode, EmailProviderConfig};
use ipnet::IpNet;
use modules::auth::application::AuthService;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower_http::{request_id::MakeRequestUuid, trace::TraceLayer};
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub jwks: jwks::JwksDocument,
    pub readiness_checker: Arc<dyn health::ReadinessChecker>,
    pub metrics_bearer_token: Option<String>,
    pub metrics_allowed_cidrs: Vec<IpNet>,
    pub trust_x_forwarded_for: bool,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Server,
    Migrate,
}

fn parse_run_mode(args: Vec<String>, run_mode_env: Option<String>) -> anyhow::Result<RunMode> {
    if let Some(command) = args.first() {
        return match command.as_str() {
            "migrate" => {
                if args.len() > 1 {
                    anyhow::bail!("`auth migrate` does not accept additional arguments");
                }
                Ok(RunMode::Migrate)
            }
            _ => anyhow::bail!("unknown command `{}`; supported command: migrate", command),
        };
    }

    parse_run_mode_env(run_mode_env)
}

fn parse_run_mode_env(run_mode_env: Option<String>) -> anyhow::Result<RunMode> {
    match run_mode_env
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("server") => Ok(RunMode::Server),
        Some("migrate") => Ok(RunMode::Migrate),
        Some(_) => anyhow::bail!("AUTH_RUN_MODE must be one of: server, migrate"),
    }
}

fn ensure_migrations_supported(auth_runtime: AuthRuntime) -> anyhow::Result<()> {
    if auth_runtime == AuthRuntime::InMemory {
        anyhow::bail!(
            "migrations are not applicable for AUTH_RUNTIME=inmemory; switch to AUTH_RUNTIME=postgres_redis for migration mode"
        );
    }

    Ok(())
}

async fn run_migration_mode() -> anyhow::Result<()> {
    let auth_runtime = config::auth_runtime_from_env()?;
    ensure_migrations_supported(auth_runtime)?;

    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required when AUTH_RUNTIME=postgres_redis")?;
    let database_max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u32>()
        .context("DATABASE_MAX_CONNECTIONS must be numeric")?;
    let pool = PgPoolOptions::new()
        .max_connections(database_max_connections)
        .connect(&database_url)
        .await?;

    adapters::postgres::run_migrations(&pool).await?;
    info!("database migrations completed successfully");

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let run_mode = parse_run_mode(
        std::env::args().skip(1).collect(),
        std::env::var("AUTH_RUN_MODE").ok(),
    )?;
    if run_mode == RunMode::Migrate {
        return run_migration_mode().await;
    }

    let cfg = AppConfig::from_env()?;
    observability::configure_email_metrics(cfg.email_metrics_latency_enabled);
    let jwks_inputs = cfg
        .jwt_keys
        .iter()
        .map(|key| jwks::JwksPublicKeyInput {
            kid: &key.kid,
            public_key_pem: &key.public_key_pem,
        })
        .collect::<Vec<_>>();
    let jwks = jwks::JwksDocument::from_ed25519_public_keys(&jwks_inputs)?;
    let jwt = Arc::new(JwtEdDsaService::new(
        cfg.jwt_keys.clone(),
        cfg.jwt_primary_kid.clone(),
        cfg.jwt_issuer.clone(),
        cfg.jwt_audience.clone(),
    )?);
    let refresh_crypto = Arc::new(RefreshCryptoHmacService::new(cfg.refresh_pepper.clone()));
    let direct_email_sender = match cfg.email_provider.clone() {
        EmailProviderConfig::Noop => Arc::new(NoopTransactionalEmailSender)
            as Arc<dyn modules::auth::ports::TransactionalEmailSender>,
        EmailProviderConfig::SendGrid(sendgrid_cfg) => Arc::new(
            SendGridTransactionalEmailSender::new(sendgrid_cfg).map_err(anyhow::Error::msg)?,
        )
            as Arc<dyn modules::auth::ports::TransactionalEmailSender>,
    };
    let email_provider_label = match &cfg.email_provider {
        EmailProviderConfig::Noop => "noop".to_string(),
        EmailProviderConfig::SendGrid(_) => "sendgrid".to_string(),
    };

    let (
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
        outbox_repository,
        dispatcher,
        readiness_checker,
    ) = match cfg.auth_runtime {
        AuthRuntime::PostgresRedis => {
            let pg = PostgresAdapters::bootstrap(&cfg).await?;
            let redis = RedisLoginAbuseProtector::new(
                &cfg.redis_url,
                cfg.login_max_attempts,
                cfg.login_attempt_window_seconds,
                cfg.login_lockout_seconds,
                cfg.login_lockout_max_seconds,
                cfg.login_abuse_attempts_prefix.clone(),
                cfg.login_abuse_lock_prefix.clone(),
                cfg.login_abuse_strikes_prefix.clone(),
                cfg.login_abuse_redis_fail_mode,
                cfg.login_abuse_bucket_mode,
            )?;
            let readiness_checker = health::RuntimeReadinessChecker::postgres_redis(
                pg.pool.clone(),
                Some(redis.health_client()),
                std::time::Duration::from_secs(2),
            );
            let outbox_repository = Arc::new(pg.email_outbox.clone())
                as Arc<dyn modules::auth::ports::EmailOutboxRepository>;
            let dispatcher = if cfg.email_delivery_mode == EmailDeliveryMode::Outbox {
                Some(OutboxDispatcher::new(
                    outbox_repository.clone(),
                    direct_email_sender.clone(),
                    OutboxWorkerConfig {
                        poll_interval: std::time::Duration::from_millis(
                            cfg.email_outbox.poll_interval_ms,
                        ),
                        batch_size: cfg.email_outbox.batch_size,
                        max_attempts: cfg.email_outbox.max_attempts,
                        lease_duration: std::time::Duration::from_millis(cfg.email_outbox.lease_ms),
                        backoff_base: std::time::Duration::from_millis(
                            cfg.email_outbox.backoff_base_ms,
                        ),
                        backoff_max: std::time::Duration::from_millis(
                            cfg.email_outbox.backoff_max_ms,
                        ),
                    },
                ))
            } else {
                None
            };
            (
                Arc::new(pg.users) as Arc<dyn modules::auth::ports::UserRepository>,
                Arc::new(redis) as Arc<dyn modules::auth::ports::LoginAbuseProtector>,
                Arc::new(pg.verification_tokens)
                    as Arc<dyn modules::auth::ports::VerificationTokenRepository>,
                Arc::new(pg.password_reset_tokens)
                    as Arc<dyn modules::auth::ports::PasswordResetTokenRepository>,
                Arc::new(pg.mfa_factors) as Arc<dyn modules::auth::ports::MfaFactorRepository>,
                Arc::new(pg.mfa_challenges)
                    as Arc<dyn modules::auth::ports::MfaChallengeRepository>,
                Arc::new(pg.mfa_backup_codes)
                    as Arc<dyn modules::auth::ports::MfaBackupCodeRepository>,
                Arc::new(pg.sessions) as Arc<dyn modules::sessions::ports::SessionRepository>,
                Arc::new(pg.refresh_tokens)
                    as Arc<dyn modules::tokens::ports::RefreshTokenRepository>,
                Arc::new(pg.audit) as Arc<dyn modules::audit::ports::AuditRepository>,
                Some(outbox_repository),
                dispatcher,
                readiness_checker,
            )
        }
        AuthRuntime::InMemory => {
            let adapters = InMemoryAdapters::bootstrap(&cfg)?;
            let readiness_checker = health::RuntimeReadinessChecker::inmemory();
            (
                Arc::new(adapters.users) as Arc<dyn modules::auth::ports::UserRepository>,
                Arc::new(adapters.login_abuse)
                    as Arc<dyn modules::auth::ports::LoginAbuseProtector>,
                Arc::new(adapters.verification_tokens)
                    as Arc<dyn modules::auth::ports::VerificationTokenRepository>,
                Arc::new(adapters.password_reset_tokens)
                    as Arc<dyn modules::auth::ports::PasswordResetTokenRepository>,
                Arc::new(adapters.mfa_factors)
                    as Arc<dyn modules::auth::ports::MfaFactorRepository>,
                Arc::new(adapters.mfa_challenges)
                    as Arc<dyn modules::auth::ports::MfaChallengeRepository>,
                Arc::new(adapters.mfa_backup_codes)
                    as Arc<dyn modules::auth::ports::MfaBackupCodeRepository>,
                Arc::new(adapters.sessions) as Arc<dyn modules::sessions::ports::SessionRepository>,
                Arc::new(adapters.refresh_tokens)
                    as Arc<dyn modules::tokens::ports::RefreshTokenRepository>,
                Arc::new(adapters.audit) as Arc<dyn modules::audit::ports::AuditRepository>,
                None,
                None,
                readiness_checker,
            )
        }
    };

    let auth_email_sender = if cfg.email_delivery_mode == EmailDeliveryMode::Outbox {
        let outbox_repository = outbox_repository
            .clone()
            .context("email outbox repository unavailable for configured runtime")?;
        Arc::new(OutboxTransactionalEmailSender::new(
            outbox_repository,
            email_provider_label,
        )) as Arc<dyn modules::auth::ports::TransactionalEmailSender>
    } else {
        direct_email_sender.clone()
    };

    let auth_service = Arc::new(AuthService::new(
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
        auth_email_sender,
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
    )?);

    let state = AppState {
        auth_service,
        jwks,
        readiness_checker,
        metrics_bearer_token: cfg.metrics_bearer_token,
        metrics_allowed_cidrs: cfg.metrics_allowed_cidrs,
        trust_x_forwarded_for: cfg.trust_x_forwarded_for,
        trusted_proxy_ips: cfg.trusted_proxy_ips,
        trusted_proxy_cidrs: cfg.trusted_proxy_cidrs,
    };

    if let Some(dispatcher) = dispatcher {
        tokio::spawn(async move {
            dispatcher.run_forever().await;
        });
        tracing::info!("email outbox dispatcher started");
    }

    let app = Router::new()
        .route("/healthz", get(api::handlers::healthz))
        .route("/readyz", get(api::handlers::readyz))
        .route("/.well-known/jwks.json", get(api::handlers::jwks))
        .route("/v1/auth/register", post(api::handlers::register))
        .route("/v1/auth/verify-email", post(api::handlers::verify_email))
        .route(
            "/v1/auth/password/forgot",
            post(api::handlers::password_forgot),
        )
        .route(
            "/v1/auth/password/reset",
            post(api::handlers::password_reset),
        )
        .route(
            "/v1/auth/password/change",
            post(api::handlers::password_change),
        )
        .route("/v1/auth/login", post(api::handlers::login))
        .route("/v1/auth/mfa/enroll", post(api::handlers::mfa_enroll))
        .route("/v1/auth/mfa/activate", post(api::handlers::mfa_activate))
        .route("/v1/auth/mfa/verify", post(api::handlers::mfa_verify))
        .route("/v1/auth/mfa/disable", post(api::handlers::mfa_disable))
        .route("/v1/auth/token/refresh", post(api::handlers::refresh))
        .route("/v1/auth/logout", post(api::handlers::logout))
        .route("/v1/auth/logout-all", post(api::handlers::logout_all))
        .route("/v1/auth/sessions", get(api::handlers::sessions))
        .route(
            "/v1/auth/sessions/{session_id}",
            delete(api::handlers::revoke_session),
        )
        .route("/v1/auth/me", get(api::handlers::me))
        .route("/metrics", get(api::handlers::metrics))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::request_id::SetRequestIdLayer::x_request_id(
            MakeRequestUuid,
        ));

    let addr: SocketAddr = cfg.bind_addr.parse().context("invalid APP_ADDR")?;
    let listener = TcpListener::bind(addr).await?;
    info!(address = %addr, "auth api listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_migrations_supported, parse_run_mode, RunMode};
    use crate::config::AuthRuntime;

    #[test]
    fn run_mode_defaults_to_server() {
        let mode = parse_run_mode(vec![], None).expect("default run mode should parse");

        assert_eq!(mode, RunMode::Server);
    }

    #[test]
    fn run_mode_accepts_migrate_subcommand() {
        let mode = parse_run_mode(vec!["migrate".to_string()], None)
            .expect("migrate command should parse");

        assert_eq!(mode, RunMode::Migrate);
    }

    #[test]
    fn run_mode_accepts_auth_run_mode_env() {
        let mode = parse_run_mode(vec![], Some("migrate".to_string()))
            .expect("migrate env mode should parse");

        assert_eq!(mode, RunMode::Migrate);
    }

    #[test]
    fn run_mode_rejects_unknown_subcommand() {
        let error = parse_run_mode(vec!["serve".to_string()], None)
            .expect_err("unknown command should fail");

        assert!(error.to_string().contains("unknown command `serve`"));
    }

    #[test]
    fn run_mode_rejects_unknown_env_mode() {
        let error = parse_run_mode(vec![], Some("worker".to_string()))
            .expect_err("unknown env mode should fail");

        assert!(error
            .to_string()
            .contains("AUTH_RUN_MODE must be one of: server, migrate"));
    }

    #[test]
    fn migrations_are_rejected_for_inmemory_runtime() {
        let error = ensure_migrations_supported(AuthRuntime::InMemory)
            .expect_err("inmemory runtime should reject migrations");

        assert!(error
            .to_string()
            .contains("migrations are not applicable for AUTH_RUNTIME=inmemory"));
    }

    #[test]
    fn migrations_are_supported_for_postgres_runtime() {
        ensure_migrations_supported(AuthRuntime::PostgresRedis)
            .expect("postgres runtime should support migrations");
    }
}
