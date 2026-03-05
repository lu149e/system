use anyhow::{Context, Result};
use base64::Engine as _;
use ipnet::IpNet;
use std::{collections::HashSet, net::IpAddr};

pub struct AppConfig {
    pub bind_addr: String,
    pub auth_runtime: AuthRuntime,
    pub metrics_bearer_token: Option<String>,
    pub metrics_allowed_cidrs: Vec<IpNet>,
    pub trust_x_forwarded_for: bool,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub jwt_keys: Vec<JwtKeyConfig>,
    pub jwt_primary_kid: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub refresh_pepper: String,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
    pub email_verification_ttl_seconds: i64,
    pub password_reset_ttl_seconds: i64,
    pub mfa_challenge_ttl_seconds: i64,
    pub mfa_challenge_max_attempts: u32,
    pub mfa_totp_issuer: String,
    pub mfa_encryption_key: String,
    pub bootstrap_user_email: Option<String>,
    pub bootstrap_user_password: Option<String>,
    pub login_max_attempts: u32,
    pub login_attempt_window_seconds: i64,
    pub login_lockout_seconds: i64,
    pub login_lockout_max_seconds: i64,
    pub login_abuse_attempts_prefix: String,
    pub login_abuse_lock_prefix: String,
    pub login_abuse_strikes_prefix: String,
    pub login_abuse_redis_fail_mode: LoginAbuseRedisFailMode,
    pub login_abuse_bucket_mode: LoginAbuseBucketMode,
    pub email_metrics_latency_enabled: bool,
    pub email_provider: EmailProviderConfig,
    pub email_delivery_mode: EmailDeliveryMode,
    pub email_outbox: EmailOutboxConfig,
}

#[derive(Clone, Debug)]
pub struct JwtKeyConfig {
    pub kid: String,
    pub private_key_pem: Option<String>,
    pub public_key_pem: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRuntime {
    PostgresRedis,
    InMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginAbuseRedisFailMode {
    FailClosed,
    FailOpen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginAbuseBucketMode {
    IpOnly,
    EmailAndIp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmailProviderConfig {
    Noop,
    SendGrid(SendGridEmailProviderConfig),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendGridEmailProviderConfig {
    pub api_base_url: String,
    pub api_key: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub verify_email_url_base: String,
    pub password_reset_url_base: String,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub retry_base_delay_ms: u64,
    pub retry_max_delay_ms: u64,
    pub retry_jitter_percent: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailDeliveryMode {
    Inline,
    Outbox,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailOutboxConfig {
    pub poll_interval_ms: u64,
    pub batch_size: u32,
    pub max_attempts: u32,
    pub lease_ms: u64,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

struct SendGridEnvConfig {
    api_base_url: Option<String>,
    from_email: Option<String>,
    from_name: Option<String>,
    verify_email_url_base: Option<String>,
    password_reset_url_base: Option<String>,
    timeout_ms: Option<String>,
    max_retries: Option<String>,
    retry_base_delay_ms: Option<String>,
    retry_max_delay_ms: Option<String>,
    retry_jitter_percent: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let bind_addr = std::env::var("APP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let auth_runtime = parse_auth_runtime(
            std::env::var("AUTH_RUNTIME").unwrap_or_else(|_| "postgres_redis".to_string()),
        )?;
        let allow_insecure_inmemory = std::env::var("ALLOW_INSECURE_INMEMORY")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .context("ALLOW_INSECURE_INMEMORY must be true or false")?;
        let metrics_bearer_token = resolve_optional_secret_from_env(
            "METRICS_BEARER_TOKEN",
            std::env::var("METRICS_BEARER_TOKEN").ok(),
            "METRICS_BEARER_TOKEN_FILE",
            std::env::var("METRICS_BEARER_TOKEN_FILE").ok(),
        )?;
        let metrics_allowed_cidrs = parse_metrics_allowed_cidrs(
            std::env::var("METRICS_ALLOWED_CIDRS").unwrap_or_default(),
        )?;
        let trust_x_forwarded_for = std::env::var("TRUST_X_FORWARDED_FOR")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .context("TRUST_X_FORWARDED_FOR must be true or false")?;
        let trusted_proxy_ips =
            parse_trusted_proxy_ips(std::env::var("TRUSTED_PROXY_IPS").unwrap_or_default())?;
        let trusted_proxy_cidrs =
            parse_trusted_proxy_cidrs(std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default())?;
        let database_url = std::env::var("DATABASE_URL").unwrap_or_default();
        let database_max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u32>()
            .context("DATABASE_MAX_CONNECTIONS must be numeric")?;
        let redis_url = std::env::var("REDIS_URL").unwrap_or_default();
        let enforce_database_tls = std::env::var("ENFORCE_DATABASE_TLS")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .context("ENFORCE_DATABASE_TLS must be true or false")?;
        let enforce_redis_tls = std::env::var("ENFORCE_REDIS_TLS")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .context("ENFORCE_REDIS_TLS must be true or false")?;
        let jwt_keyset = std::env::var("JWT_KEYSET")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let jwt_primary_kid = std::env::var("JWT_PRIMARY_KID")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let jwt_private_key_pem = std::env::var("JWT_PRIVATE_KEY_PEM").ok();
        let jwt_public_key_pem = std::env::var("JWT_PUBLIC_KEY_PEM").ok();
        let jwt_key_id = std::env::var("JWT_KEY_ID").ok();
        let (jwt_keys, jwt_primary_kid) = resolve_jwt_key_configuration(
            jwt_keyset,
            jwt_primary_kid,
            jwt_private_key_pem,
            jwt_public_key_pem,
            jwt_key_id,
        )?;
        let jwt_issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "auth-api".to_string());
        let jwt_audience =
            std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "auth-clients".to_string());
        let refresh_pepper =
            std::env::var("REFRESH_TOKEN_PEPPER").context("REFRESH_TOKEN_PEPPER is required")?;
        let access_ttl_seconds = std::env::var("ACCESS_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()
            .context("ACCESS_TTL_SECONDS must be numeric")?;
        let refresh_ttl_seconds = std::env::var("REFRESH_TTL_SECONDS")
            .unwrap_or_else(|_| "1209600".to_string())
            .parse::<i64>()
            .context("REFRESH_TTL_SECONDS must be numeric")?;
        let email_verification_ttl_seconds = std::env::var("EMAIL_VERIFICATION_TTL_SECONDS")
            .unwrap_or_else(|_| "86400".to_string())
            .parse::<i64>()
            .context("EMAIL_VERIFICATION_TTL_SECONDS must be numeric")?;
        if email_verification_ttl_seconds <= 0 {
            anyhow::bail!("EMAIL_VERIFICATION_TTL_SECONDS must be greater than 0");
        }
        let password_reset_ttl_seconds = std::env::var("PASSWORD_RESET_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()
            .context("PASSWORD_RESET_TTL_SECONDS must be numeric")?;
        if password_reset_ttl_seconds <= 0 {
            anyhow::bail!("PASSWORD_RESET_TTL_SECONDS must be greater than 0");
        }
        let mfa_challenge_ttl_seconds = std::env::var("MFA_CHALLENGE_TTL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<i64>()
            .context("MFA_CHALLENGE_TTL_SECONDS must be numeric")?;
        if mfa_challenge_ttl_seconds <= 0 {
            anyhow::bail!("MFA_CHALLENGE_TTL_SECONDS must be greater than 0");
        }
        let mfa_challenge_max_attempts = std::env::var("MFA_CHALLENGE_MAX_ATTEMPTS")
            .unwrap_or_else(|_| "3".to_string())
            .parse::<u32>()
            .context("MFA_CHALLENGE_MAX_ATTEMPTS must be numeric")?;
        if mfa_challenge_max_attempts == 0 {
            anyhow::bail!("MFA_CHALLENGE_MAX_ATTEMPTS must be greater than 0");
        }
        let mfa_totp_issuer = std::env::var("MFA_TOTP_ISSUER")
            .unwrap_or_else(|_| "auth-api".to_string())
            .trim()
            .to_string();
        if mfa_totp_issuer.is_empty() {
            anyhow::bail!("MFA_TOTP_ISSUER must not be empty");
        }
        let mfa_encryption_key = std::env::var("MFA_ENCRYPTION_KEY_BASE64")
            .context("MFA_ENCRYPTION_KEY_BASE64 is required")?;
        let decoded_mfa_key = base64::engine::general_purpose::STANDARD
            .decode(mfa_encryption_key.as_bytes())
            .context("MFA_ENCRYPTION_KEY_BASE64 must be valid base64")?;
        if decoded_mfa_key.len() != 32 {
            anyhow::bail!("MFA_ENCRYPTION_KEY_BASE64 must decode to 32 bytes");
        }
        let bootstrap_user_email = std::env::var("BOOTSTRAP_USER_EMAIL")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());
        let bootstrap_user_password = std::env::var("BOOTSTRAP_USER_PASSWORD")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let login_max_attempts = std::env::var("LOGIN_MAX_ATTEMPTS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .context("LOGIN_MAX_ATTEMPTS must be numeric")?;
        let login_attempt_window_seconds = std::env::var("LOGIN_ATTEMPT_WINDOW_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<i64>()
            .context("LOGIN_ATTEMPT_WINDOW_SECONDS must be numeric")?;
        let login_lockout_seconds = std::env::var("LOGIN_LOCKOUT_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()
            .context("LOGIN_LOCKOUT_SECONDS must be numeric")?;
        let login_lockout_max_seconds = std::env::var("LOGIN_LOCKOUT_MAX_SECONDS")
            .unwrap_or_else(|_| "7200".to_string())
            .parse::<i64>()
            .context("LOGIN_LOCKOUT_MAX_SECONDS must be numeric")?;
        let login_abuse_attempts_prefix = std::env::var("LOGIN_ABUSE_ATTEMPTS_PREFIX")
            .unwrap_or_else(|_| "auth:login-abuse:attempts".to_string());
        let login_abuse_lock_prefix = std::env::var("LOGIN_ABUSE_LOCK_PREFIX")
            .unwrap_or_else(|_| "auth:login-abuse:lock".to_string());
        let login_abuse_strikes_prefix = std::env::var("LOGIN_ABUSE_STRIKES_PREFIX")
            .unwrap_or_else(|_| "auth:login-abuse:strikes".to_string());
        let login_abuse_redis_fail_mode = parse_login_abuse_redis_fail_mode(
            std::env::var("LOGIN_ABUSE_REDIS_FAIL_MODE")
                .unwrap_or_else(|_| "fail_closed".to_string()),
        )?;
        let login_abuse_bucket_mode = parse_login_abuse_bucket_mode(
            std::env::var("LOGIN_ABUSE_BUCKET_MODE").unwrap_or_else(|_| "email_and_ip".to_string()),
        )?;
        let email_metrics_latency_enabled = std::env::var("EMAIL_METRICS_LATENCY_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .context("EMAIL_METRICS_LATENCY_ENABLED must be true or false")?;
        let sendgrid_api_key = resolve_optional_secret_from_env(
            "SENDGRID_API_KEY",
            std::env::var("SENDGRID_API_KEY").ok(),
            "SENDGRID_API_KEY_FILE",
            std::env::var("SENDGRID_API_KEY_FILE").ok(),
        )?;
        let email_provider = parse_email_provider_config(
            std::env::var("EMAIL_PROVIDER").unwrap_or_else(|_| "noop".to_string()),
            sendgrid_api_key,
            SendGridEnvConfig {
                api_base_url: std::env::var("SENDGRID_API_BASE_URL").ok(),
                from_email: std::env::var("SENDGRID_FROM_EMAIL").ok(),
                from_name: std::env::var("SENDGRID_FROM_NAME").ok(),
                verify_email_url_base: std::env::var("VERIFY_EMAIL_URL_BASE").ok(),
                password_reset_url_base: std::env::var("PASSWORD_RESET_URL_BASE").ok(),
                timeout_ms: std::env::var("SENDGRID_TIMEOUT_MS").ok(),
                max_retries: std::env::var("SENDGRID_MAX_RETRIES").ok(),
                retry_base_delay_ms: std::env::var("SENDGRID_RETRY_BASE_DELAY_MS").ok(),
                retry_max_delay_ms: std::env::var("SENDGRID_RETRY_MAX_DELAY_MS").ok(),
                retry_jitter_percent: std::env::var("SENDGRID_RETRY_JITTER_PERCENT").ok(),
            },
        )?;
        let email_delivery_mode = parse_email_delivery_mode(
            std::env::var("EMAIL_DELIVERY_MODE").unwrap_or_else(|_| "inline".to_string()),
        )?;
        let email_outbox = EmailOutboxConfig {
            poll_interval_ms: parse_positive_u64_with_default(
                std::env::var("EMAIL_OUTBOX_POLL_INTERVAL_MS").ok(),
                1000,
                "EMAIL_OUTBOX_POLL_INTERVAL_MS",
            )?,
            batch_size: parse_positive_u32_with_default(
                std::env::var("EMAIL_OUTBOX_BATCH_SIZE").ok(),
                25,
                "EMAIL_OUTBOX_BATCH_SIZE",
            )?,
            max_attempts: parse_positive_u32_with_default(
                std::env::var("EMAIL_OUTBOX_MAX_ATTEMPTS").ok(),
                8,
                "EMAIL_OUTBOX_MAX_ATTEMPTS",
            )?,
            lease_ms: parse_positive_u64_with_default(
                std::env::var("EMAIL_OUTBOX_LEASE_MS").ok(),
                30_000,
                "EMAIL_OUTBOX_LEASE_MS",
            )?,
            backoff_base_ms: parse_positive_u64_with_default(
                std::env::var("EMAIL_OUTBOX_BACKOFF_BASE_MS").ok(),
                1_000,
                "EMAIL_OUTBOX_BACKOFF_BASE_MS",
            )?,
            backoff_max_ms: parse_positive_u64_with_default(
                std::env::var("EMAIL_OUTBOX_BACKOFF_MAX_MS").ok(),
                60_000,
                "EMAIL_OUTBOX_BACKOFF_MAX_MS",
            )?,
        };
        if email_outbox.backoff_max_ms < email_outbox.backoff_base_ms {
            anyhow::bail!(
                "EMAIL_OUTBOX_BACKOFF_MAX_MS must be greater than or equal to EMAIL_OUTBOX_BACKOFF_BASE_MS"
            );
        }
        if email_outbox.lease_ms < email_outbox.poll_interval_ms {
            anyhow::bail!(
                "EMAIL_OUTBOX_LEASE_MS must be greater than or equal to EMAIL_OUTBOX_POLL_INTERVAL_MS"
            );
        }

        match auth_runtime {
            AuthRuntime::PostgresRedis => {
                if database_url.trim().is_empty() {
                    anyhow::bail!("DATABASE_URL is required when AUTH_RUNTIME=postgres_redis");
                }
                if redis_url.trim().is_empty() {
                    anyhow::bail!("REDIS_URL is required when AUTH_RUNTIME=postgres_redis");
                }
            }
            AuthRuntime::InMemory => {
                if !allow_insecure_inmemory {
                    anyhow::bail!(
                        "AUTH_RUNTIME=inmemory is disabled by default; set ALLOW_INSECURE_INMEMORY=true to enable"
                    );
                }
            }
        }

        if email_delivery_mode == EmailDeliveryMode::Outbox
            && auth_runtime != AuthRuntime::PostgresRedis
        {
            anyhow::bail!(
                "EMAIL_DELIVERY_MODE=outbox requires AUTH_RUNTIME=postgres_redis for persistent storage"
            );
        }

        validate_backend_transport_security(
            auth_runtime,
            &database_url,
            &redis_url,
            enforce_database_tls,
            enforce_redis_tls,
        )?;

        if trust_x_forwarded_for && trusted_proxy_ips.is_empty() && trusted_proxy_cidrs.is_empty() {
            anyhow::bail!(
                "TRUST_X_FORWARDED_FOR=true requires TRUSTED_PROXY_IPS or TRUSTED_PROXY_CIDRS"
            );
        }

        if login_lockout_seconds <= 0 {
            anyhow::bail!("LOGIN_LOCKOUT_SECONDS must be greater than 0");
        }
        if login_lockout_max_seconds < login_lockout_seconds {
            anyhow::bail!(
                "LOGIN_LOCKOUT_MAX_SECONDS must be greater than or equal to LOGIN_LOCKOUT_SECONDS"
            );
        }

        Ok(Self {
            bind_addr,
            auth_runtime,
            metrics_bearer_token,
            metrics_allowed_cidrs,
            trust_x_forwarded_for,
            trusted_proxy_ips,
            trusted_proxy_cidrs,
            database_url,
            database_max_connections,
            redis_url,
            jwt_keys,
            jwt_primary_kid,
            jwt_issuer,
            jwt_audience,
            refresh_pepper,
            access_ttl_seconds,
            refresh_ttl_seconds,
            email_verification_ttl_seconds,
            password_reset_ttl_seconds,
            mfa_challenge_ttl_seconds,
            mfa_challenge_max_attempts,
            mfa_totp_issuer,
            mfa_encryption_key,
            bootstrap_user_email,
            bootstrap_user_password,
            login_max_attempts,
            login_attempt_window_seconds,
            login_lockout_seconds,
            login_lockout_max_seconds,
            login_abuse_attempts_prefix,
            login_abuse_lock_prefix,
            login_abuse_strikes_prefix,
            login_abuse_redis_fail_mode,
            login_abuse_bucket_mode,
            email_metrics_latency_enabled,
            email_provider,
            email_delivery_mode,
            email_outbox,
        })
    }
}

fn parse_email_delivery_mode(value: String) -> Result<EmailDeliveryMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inline" => Ok(EmailDeliveryMode::Inline),
        "outbox" => Ok(EmailDeliveryMode::Outbox),
        _ => anyhow::bail!("EMAIL_DELIVERY_MODE must be one of: inline, outbox"),
    }
}

fn resolve_jwt_key_configuration(
    jwt_keyset: Option<String>,
    jwt_primary_kid: Option<String>,
    legacy_private_key_pem: Option<String>,
    legacy_public_key_pem: Option<String>,
    legacy_key_id: Option<String>,
) -> Result<(Vec<JwtKeyConfig>, String)> {
    if let Some(keyset) = jwt_keyset {
        if legacy_private_key_pem.is_some()
            || legacy_public_key_pem.is_some()
            || legacy_key_id.is_some()
        {
            anyhow::bail!(
                "JWT_KEYSET cannot be combined with legacy JWT_PRIVATE_KEY_PEM/JWT_PUBLIC_KEY_PEM/JWT_KEY_ID"
            );
        }

        let key_entries = parse_jwt_keyset(&keyset)?;
        if key_entries.is_empty() {
            anyhow::bail!("JWT_KEYSET must define at least one key");
        }

        let mut seen_kids = HashSet::new();
        for entry in &key_entries {
            if !seen_kids.insert(entry.kid.clone()) {
                anyhow::bail!("JWT_KEYSET contains duplicated kid: {}", entry.kid);
            }
        }

        let primary_kid = jwt_primary_kid.unwrap_or_else(|| key_entries[0].kid.clone());
        if !seen_kids.contains(&primary_kid) {
            anyhow::bail!("JWT_PRIMARY_KID does not match any JWT_KEYSET kid");
        }

        let mut jwt_keys = Vec::with_capacity(key_entries.len());
        for entry in key_entries {
            let public_key_pem =
                read_jwt_key_file("JWT_KEYSET public key path", &entry.public_key_path)
                    .with_context(|| {
                        format!("failed to read JWT_KEYSET public key for kid {}", entry.kid)
                    })?;
            let private_key_pem = match entry.private_key_path {
                Some(path) => Some(
                    read_jwt_key_file("JWT_KEYSET private key path", &path).with_context(|| {
                        format!(
                            "failed to read JWT_KEYSET private key for kid {}",
                            entry.kid
                        )
                    })?,
                ),
                None => None,
            };

            jwt_keys.push(JwtKeyConfig {
                kid: entry.kid,
                private_key_pem,
                public_key_pem,
            });
        }

        let primary_key = jwt_keys
            .iter()
            .find(|candidate| candidate.kid == primary_kid)
            .expect("primary kid was validated");
        if primary_key.private_key_pem.is_none() {
            anyhow::bail!(
                "JWT primary signing key '{}' must include private key material",
                primary_kid
            );
        }

        return Ok((jwt_keys, primary_kid));
    }

    let jwt_private_key_pem = legacy_private_key_pem
        .context("JWT_PRIVATE_KEY_PEM is required when JWT_KEYSET is not set")?;
    let jwt_public_key_pem = legacy_public_key_pem
        .context("JWT_PUBLIC_KEY_PEM is required when JWT_KEYSET is not set")?;
    let jwt_key_id = legacy_key_id.unwrap_or_else(|| "auth-ed25519-v1".to_string());

    Ok((
        vec![JwtKeyConfig {
            kid: jwt_key_id.clone(),
            private_key_pem: Some(normalize_pem(jwt_private_key_pem)),
            public_key_pem: normalize_pem(jwt_public_key_pem),
        }],
        jwt_key_id,
    ))
}

struct JwtKeysetEntry {
    kid: String,
    private_key_path: Option<String>,
    public_key_path: String,
}

fn parse_jwt_keyset(value: &str) -> Result<Vec<JwtKeysetEntry>> {
    let mut entries = Vec::new();

    for raw_entry in value
        .split(',')
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
    {
        let parts: Vec<_> = raw_entry.split('|').map(str::trim).collect();
        if parts.len() != 3 {
            anyhow::bail!(
                "invalid JWT_KEYSET entry: {raw_entry}; expected format kid|private_key_path|public_key_path"
            );
        }

        let kid = parts[0].to_string();
        if kid.is_empty() {
            anyhow::bail!("JWT_KEYSET entry has empty kid");
        }

        let private_key_path = if parts[1].is_empty() {
            None
        } else {
            Some(parts[1].to_string())
        };

        let public_key_path = parts[2].to_string();
        if public_key_path.is_empty() {
            anyhow::bail!("JWT_KEYSET entry '{kid}' must include a public key path");
        }

        entries.push(JwtKeysetEntry {
            kid,
            private_key_path,
            public_key_path,
        });
    }

    Ok(entries)
}

fn read_jwt_key_file(kind: &str, path: &str) -> Result<String> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("{kind} is unreadable: {path}"))?
        .trim()
        .to_string();
    if value.is_empty() {
        anyhow::bail!("{kind} file must not be empty: {path}");
    }

    Ok(normalize_pem(value))
}

fn parse_auth_runtime(value: String) -> Result<AuthRuntime> {
    match value.to_ascii_lowercase().as_str() {
        "postgres_redis" => Ok(AuthRuntime::PostgresRedis),
        "inmemory" => Ok(AuthRuntime::InMemory),
        _ => anyhow::bail!("AUTH_RUNTIME must be one of: postgres_redis, inmemory"),
    }
}

fn parse_login_abuse_redis_fail_mode(value: String) -> Result<LoginAbuseRedisFailMode> {
    match value.to_ascii_lowercase().as_str() {
        "fail_closed" => Ok(LoginAbuseRedisFailMode::FailClosed),
        "fail_open" => Ok(LoginAbuseRedisFailMode::FailOpen),
        _ => anyhow::bail!("LOGIN_ABUSE_REDIS_FAIL_MODE must be one of: fail_closed, fail_open"),
    }
}

fn parse_login_abuse_bucket_mode(value: String) -> Result<LoginAbuseBucketMode> {
    match value.to_ascii_lowercase().as_str() {
        "ip_only" => Ok(LoginAbuseBucketMode::IpOnly),
        "email_and_ip" => Ok(LoginAbuseBucketMode::EmailAndIp),
        _ => anyhow::bail!("LOGIN_ABUSE_BUCKET_MODE must be one of: ip_only, email_and_ip"),
    }
}

fn parse_email_provider_config(
    value: String,
    sendgrid_api_key: Option<String>,
    sendgrid: SendGridEnvConfig,
) -> Result<EmailProviderConfig> {
    match value.trim().to_ascii_lowercase().as_str() {
        "noop" => Ok(EmailProviderConfig::Noop),
        "sendgrid" => {
            let api_key = sendgrid_api_key
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .context("SENDGRID_API_KEY or SENDGRID_API_KEY_FILE is required when EMAIL_PROVIDER=sendgrid")?;
            let api_base_url = sendgrid
                .api_base_url
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "https://api.sendgrid.com".to_string());
            if !api_base_url.starts_with("http://") && !api_base_url.starts_with("https://") {
                anyhow::bail!("SENDGRID_API_BASE_URL must start with http:// or https://");
            }

            let from_email = sendgrid
                .from_email
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .context("SENDGRID_FROM_EMAIL is required when EMAIL_PROVIDER=sendgrid")?;
            let from_name = sendgrid
                .from_name
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            let verify_email_url_base = sendgrid
                .verify_email_url_base
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .context("VERIFY_EMAIL_URL_BASE is required when EMAIL_PROVIDER=sendgrid")?;
            let password_reset_url_base = sendgrid
                .password_reset_url_base
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .context("PASSWORD_RESET_URL_BASE is required when EMAIL_PROVIDER=sendgrid")?;
            let timeout_ms =
                parse_sendgrid_u64_with_default(sendgrid.timeout_ms, 3000, "SENDGRID_TIMEOUT_MS")?;
            let max_retries =
                parse_sendgrid_u32_with_default(sendgrid.max_retries, 2, "SENDGRID_MAX_RETRIES")?;
            let retry_base_delay_ms = parse_sendgrid_u64_with_default(
                sendgrid.retry_base_delay_ms,
                200,
                "SENDGRID_RETRY_BASE_DELAY_MS",
            )?;
            let retry_max_delay_ms = parse_sendgrid_u64_with_default(
                sendgrid.retry_max_delay_ms,
                2000,
                "SENDGRID_RETRY_MAX_DELAY_MS",
            )?;
            let retry_jitter_percent = parse_sendgrid_u8_with_default(
                sendgrid.retry_jitter_percent,
                20,
                "SENDGRID_RETRY_JITTER_PERCENT",
            )?;

            if retry_max_delay_ms < retry_base_delay_ms {
                anyhow::bail!(
                    "SENDGRID_RETRY_MAX_DELAY_MS must be greater than or equal to SENDGRID_RETRY_BASE_DELAY_MS"
                );
            }

            Ok(EmailProviderConfig::SendGrid(SendGridEmailProviderConfig {
                api_base_url: api_base_url.trim_end_matches('/').to_string(),
                api_key,
                from_email,
                from_name,
                verify_email_url_base,
                password_reset_url_base,
                timeout_ms,
                max_retries,
                retry_base_delay_ms,
                retry_max_delay_ms,
                retry_jitter_percent,
            }))
        }
        _ => anyhow::bail!("EMAIL_PROVIDER must be one of: noop, sendgrid"),
    }
}

fn parse_sendgrid_u64_with_default(
    value: Option<String>,
    default: u64,
    variable_name: &'static str,
) -> Result<u64> {
    let parsed = value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<u64>()
                .with_context(|| format!("{variable_name} must be numeric"))
        })
        .transpose()?
        .unwrap_or(default);

    if parsed == 0 {
        anyhow::bail!("{variable_name} must be greater than 0");
    }

    Ok(parsed)
}

fn parse_sendgrid_u32_with_default(
    value: Option<String>,
    default: u32,
    variable_name: &'static str,
) -> Result<u32> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<u32>()
                .with_context(|| format!("{variable_name} must be numeric"))
        })
        .transpose()
        .map(|parsed| parsed.unwrap_or(default))
}

fn parse_sendgrid_u8_with_default(
    value: Option<String>,
    default: u8,
    variable_name: &'static str,
) -> Result<u8> {
    let parsed = value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<u8>()
                .with_context(|| format!("{variable_name} must be numeric"))
        })
        .transpose()?
        .unwrap_or(default);

    if parsed > 100 {
        anyhow::bail!("{variable_name} must be between 0 and 100");
    }

    Ok(parsed)
}

fn parse_positive_u64_with_default(
    value: Option<String>,
    default: u64,
    variable_name: &'static str,
) -> Result<u64> {
    let parsed = value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<u64>()
                .with_context(|| format!("{variable_name} must be numeric"))
        })
        .transpose()?
        .unwrap_or(default);

    if parsed == 0 {
        anyhow::bail!("{variable_name} must be greater than 0");
    }

    Ok(parsed)
}

fn parse_positive_u32_with_default(
    value: Option<String>,
    default: u32,
    variable_name: &'static str,
) -> Result<u32> {
    let parsed = value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<u32>()
                .with_context(|| format!("{variable_name} must be numeric"))
        })
        .transpose()?
        .unwrap_or(default);

    if parsed == 0 {
        anyhow::bail!("{variable_name} must be greater than 0");
    }

    Ok(parsed)
}

fn parse_trusted_proxy_ips(value: String) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();

    for candidate in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let ip = candidate
            .parse::<IpAddr>()
            .with_context(|| format!("invalid TRUSTED_PROXY_IPS entry: {candidate}"))?;
        ips.push(ip);
    }

    Ok(ips)
}

fn parse_trusted_proxy_cidrs(value: String) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();

    for candidate in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let cidr = candidate
            .parse::<IpNet>()
            .with_context(|| format!("invalid TRUSTED_PROXY_CIDRS entry: {candidate}"))?;
        cidrs.push(cidr);
    }

    Ok(cidrs)
}

fn parse_metrics_allowed_cidrs(value: String) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();

    for candidate in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let cidr = candidate
            .parse::<IpNet>()
            .with_context(|| format!("invalid METRICS_ALLOWED_CIDRS entry: {candidate}"))?;
        cidrs.push(cidr);
    }

    Ok(cidrs)
}

fn validate_backend_transport_security(
    auth_runtime: AuthRuntime,
    database_url: &str,
    redis_url: &str,
    enforce_database_tls: bool,
    enforce_redis_tls: bool,
) -> Result<()> {
    if auth_runtime != AuthRuntime::PostgresRedis {
        return Ok(());
    }

    if enforce_database_tls && !database_url_uses_secure_transport(database_url) {
        anyhow::bail!(
            "DATABASE_URL must enforce TLS when ENFORCE_DATABASE_TLS=true. Add sslmode=require (or verify-ca/verify-full), e.g. postgres://user:pass@db:5432/auth?sslmode=require"
        );
    }

    if enforce_redis_tls && !redis_url_uses_secure_transport(redis_url) {
        anyhow::bail!(
            "REDIS_URL must enforce TLS when ENFORCE_REDIS_TLS=true. Use rediss://... or set REDIS_URL query parameter tls=true"
        );
    }

    Ok(())
}

fn database_url_uses_secure_transport(database_url: &str) -> bool {
    let sslmode_values = query_param_values(database_url, "sslmode");
    if sslmode_values.iter().any(|value| {
        matches!(
            value.as_str(),
            "require" | "verify-ca" | "verify-full" | "verify_ca" | "verify_full"
        )
    }) {
        return true;
    }

    query_param_values(database_url, "ssl")
        .iter()
        .any(|value| is_truthy(value))
}

fn redis_url_uses_secure_transport(redis_url: &str) -> bool {
    if redis_url
        .trim()
        .to_ascii_lowercase()
        .starts_with("rediss://")
    {
        return true;
    }

    query_param_values(redis_url, "tls")
        .iter()
        .any(|value| is_truthy(value))
        || query_param_values(redis_url, "ssl")
            .iter()
            .any(|value| is_truthy(value))
}

fn query_param_values(url: &str, key: &str) -> Vec<String> {
    let Some((_, query)) = url.split_once('?') else {
        return Vec::new();
    };

    query
        .split('&')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if name.trim().eq_ignore_ascii_case(key) {
                Some(value.trim().to_ascii_lowercase())
            } else {
                None
            }
        })
        .collect()
}

fn is_truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes")
}

fn resolve_optional_secret_from_env(
    secret_name: &str,
    secret_value: Option<String>,
    secret_file_name: &str,
    secret_file_value: Option<String>,
) -> Result<Option<String>> {
    let secret_value = secret_value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let secret_file_value = secret_file_value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    if secret_value.is_some() && secret_file_value.is_some() {
        anyhow::bail!("{secret_name} and {secret_file_name} cannot both be set");
    }

    if let Some(secret_file_path) = secret_file_value {
        let secret = std::fs::read_to_string(&secret_file_path).with_context(|| {
            format!("{secret_file_name} points to unreadable file: {secret_file_path}")
        })?;
        let secret = secret.trim().to_string();
        if secret.is_empty() {
            anyhow::bail!("{secret_file_name} file must not be empty");
        }
        return Ok(Some(secret));
    }

    Ok(secret_value)
}

fn normalize_pem(value: String) -> String {
    if value.contains("\\n") && !value.contains('\n') {
        return value.replace("\\n", "\n");
    }

    value
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        database_url_uses_secure_transport, parse_email_delivery_mode, parse_email_provider_config,
        parse_metrics_allowed_cidrs, parse_positive_u64_with_default,
        redis_url_uses_secure_transport, resolve_jwt_key_configuration,
        resolve_optional_secret_from_env, validate_backend_transport_security, AuthRuntime,
        EmailDeliveryMode, EmailProviderConfig,
    };

    #[test]
    fn parse_metrics_allowed_cidrs_accepts_csv_input() {
        let cidrs = parse_metrics_allowed_cidrs("127.0.0.0/8,10.10.0.0/16".to_string())
            .expect("csv cidrs should parse");

        assert_eq!(cidrs.len(), 2);
        assert_eq!(cidrs[0].to_string(), "127.0.0.0/8");
        assert_eq!(cidrs[1].to_string(), "10.10.0.0/16");
    }

    #[test]
    fn parse_metrics_allowed_cidrs_rejects_invalid_entry() {
        let error = parse_metrics_allowed_cidrs("127.0.0.0/8,not-a-cidr".to_string())
            .expect_err("invalid cidr entry should fail");

        assert!(error
            .to_string()
            .contains("invalid METRICS_ALLOWED_CIDRS entry: not-a-cidr"));
    }

    #[test]
    fn resolve_optional_secret_uses_env_value_when_file_is_not_set() {
        let secret = resolve_optional_secret_from_env(
            "METRICS_BEARER_TOKEN",
            Some("  metrics-env-token  ".to_string()),
            "METRICS_BEARER_TOKEN_FILE",
            None,
        )
        .expect("secret resolution should succeed");

        assert_eq!(secret.as_deref(), Some("metrics-env-token"));
    }

    #[test]
    fn resolve_optional_secret_reads_token_from_file() {
        let secret_path = write_temp_secret_file("metrics-file-token\n");

        let secret = resolve_optional_secret_from_env(
            "METRICS_BEARER_TOKEN",
            None,
            "METRICS_BEARER_TOKEN_FILE",
            Some(secret_path.to_string_lossy().to_string()),
        )
        .expect("secret file should be readable");

        assert_eq!(secret.as_deref(), Some("metrics-file-token"));
    }

    #[test]
    fn resolve_optional_secret_rejects_env_and_file_set_together() {
        let secret_path = write_temp_secret_file("metrics-file-token\n");

        let error = resolve_optional_secret_from_env(
            "METRICS_BEARER_TOKEN",
            Some("metrics-env-token".to_string()),
            "METRICS_BEARER_TOKEN_FILE",
            Some(secret_path.to_string_lossy().to_string()),
        )
        .expect_err("setting env and file should be rejected");

        assert!(error
            .to_string()
            .contains("METRICS_BEARER_TOKEN and METRICS_BEARER_TOKEN_FILE cannot both be set"));
    }

    #[test]
    fn resolve_optional_secret_rejects_empty_file_content() {
        let secret_path = write_temp_secret_file("   \n");

        let error = resolve_optional_secret_from_env(
            "METRICS_BEARER_TOKEN",
            None,
            "METRICS_BEARER_TOKEN_FILE",
            Some(secret_path.to_string_lossy().to_string()),
        )
        .expect_err("empty file content should be rejected");

        assert!(error
            .to_string()
            .contains("METRICS_BEARER_TOKEN_FILE file must not be empty"));
    }

    #[test]
    fn resolve_jwt_key_configuration_parses_keyset_and_primary_selection() {
        let primary_private = write_temp_secret_file(TEST_PRIVATE_KEY_PEM);
        let primary_public = write_temp_secret_file(TEST_PUBLIC_KEY_PEM);
        let secondary_public = write_temp_secret_file(TEST_PUBLIC_KEY_PEM);

        let keyset = format!(
            "primary|{}|{},secondary||{}",
            primary_private.to_string_lossy(),
            primary_public.to_string_lossy(),
            secondary_public.to_string_lossy()
        );

        let (keys, primary_kid) = resolve_jwt_key_configuration(
            Some(keyset),
            Some("primary".to_string()),
            None,
            None,
            None,
        )
        .expect("keyset config should parse");

        assert_eq!(primary_kid, "primary");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid, "primary");
        assert!(keys[0].private_key_pem.is_some());
        assert_eq!(keys[1].kid, "secondary");
        assert!(keys[1].private_key_pem.is_none());
    }

    #[test]
    fn resolve_jwt_key_configuration_rejects_duplicate_kids() {
        let primary_private = write_temp_secret_file(TEST_PRIVATE_KEY_PEM);
        let primary_public = write_temp_secret_file(TEST_PUBLIC_KEY_PEM);
        let duplicate_public = write_temp_secret_file(TEST_PUBLIC_KEY_PEM);

        let keyset = format!(
            "dup|{}|{},dup||{}",
            primary_private.to_string_lossy(),
            primary_public.to_string_lossy(),
            duplicate_public.to_string_lossy()
        );

        let error = resolve_jwt_key_configuration(Some(keyset), None, None, None, None)
            .expect_err("duplicated kid should fail");
        assert!(error.to_string().contains("duplicated kid: dup"));
    }

    #[test]
    fn resolve_jwt_key_configuration_rejects_primary_without_private_material() {
        let primary_public = write_temp_secret_file(TEST_PUBLIC_KEY_PEM);
        let keyset = format!("primary||{}", primary_public.to_string_lossy());

        let error = resolve_jwt_key_configuration(Some(keyset), None, None, None, None)
            .expect_err("primary signing key must include private key material");
        assert!(error
            .to_string()
            .contains("JWT primary signing key 'primary' must include private key material"));
    }

    #[test]
    fn transport_security_validation_is_permissive_in_local_mode_by_default() {
        let result = validate_backend_transport_security(
            AuthRuntime::PostgresRedis,
            "postgres://auth:auth@127.0.0.1:5432/auth",
            "redis://127.0.0.1:6379",
            false,
            false,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn transport_security_validation_rejects_insecure_database_url_when_enforced() {
        let error = validate_backend_transport_security(
            AuthRuntime::PostgresRedis,
            "postgres://auth:auth@127.0.0.1:5432/auth",
            "rediss://127.0.0.1:6379",
            true,
            false,
        )
        .expect_err("insecure DATABASE_URL should fail when enforcement is enabled");

        assert!(error
            .to_string()
            .contains("DATABASE_URL must enforce TLS when ENFORCE_DATABASE_TLS=true"));
    }

    #[test]
    fn transport_security_validation_accepts_secure_database_url_when_enforced() {
        let result = validate_backend_transport_security(
            AuthRuntime::PostgresRedis,
            "postgres://auth:auth@127.0.0.1:5432/auth?sslmode=verify-full",
            "redis://127.0.0.1:6379",
            true,
            false,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn transport_security_validation_rejects_insecure_redis_url_when_enforced() {
        let error = validate_backend_transport_security(
            AuthRuntime::PostgresRedis,
            "postgres://auth:auth@127.0.0.1:5432/auth?sslmode=require",
            "redis://127.0.0.1:6379",
            false,
            true,
        )
        .expect_err("insecure REDIS_URL should fail when enforcement is enabled");

        assert!(error
            .to_string()
            .contains("REDIS_URL must enforce TLS when ENFORCE_REDIS_TLS=true"));
    }

    #[test]
    fn transport_security_validation_accepts_secure_redis_url_when_enforced() {
        let result = validate_backend_transport_security(
            AuthRuntime::PostgresRedis,
            "postgres://auth:auth@127.0.0.1:5432/auth",
            "redis://127.0.0.1:6379?tls=true",
            false,
            true,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn transport_security_validation_is_ignored_for_inmemory_runtime() {
        let result = validate_backend_transport_security(
            AuthRuntime::InMemory,
            "postgres://auth:auth@127.0.0.1:5432/auth",
            "redis://127.0.0.1:6379",
            true,
            true,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn database_secure_transport_detection_accepts_strict_sslmode_values() {
        assert!(database_url_uses_secure_transport(
            "postgres://db/auth?sslmode=require"
        ));
        assert!(database_url_uses_secure_transport(
            "postgres://db/auth?sslmode=verify-ca"
        ));
        assert!(database_url_uses_secure_transport(
            "postgres://db/auth?sslmode=verify-full"
        ));
        assert!(!database_url_uses_secure_transport(
            "postgres://db/auth?sslmode=disable"
        ));
    }

    #[test]
    fn redis_secure_transport_detection_accepts_rediss_and_tls_query_flag() {
        assert!(redis_url_uses_secure_transport("rediss://127.0.0.1:6379"));
        assert!(redis_url_uses_secure_transport(
            "redis://127.0.0.1:6379?tls=true"
        ));
        assert!(!redis_url_uses_secure_transport("redis://127.0.0.1:6379"));
    }

    #[test]
    fn email_provider_defaults_to_noop_without_sendgrid_config() {
        let provider = parse_email_provider_config("noop".to_string(), None, sendgrid_env())
            .expect("noop provider should parse");

        assert!(matches!(provider, EmailProviderConfig::Noop));
    }

    #[test]
    fn email_provider_sendgrid_requires_secret_and_required_fields() {
        let mut env = sendgrid_env();
        env.from_email = Some("noreply@example.com".to_string());
        env.verify_email_url_base = Some("https://app.example.com/verify-email".to_string());
        env.password_reset_url_base = Some("https://app.example.com/reset-password".to_string());

        let error = parse_email_provider_config("sendgrid".to_string(), None, env)
            .expect_err("sendgrid provider without api key should fail");

        assert!(error
            .to_string()
            .contains("SENDGRID_API_KEY or SENDGRID_API_KEY_FILE is required"));
    }

    #[test]
    fn email_provider_sendgrid_parses_complete_configuration() {
        let mut env = sendgrid_env();
        env.api_base_url = Some("https://api.sendgrid.com/".to_string());
        env.from_email = Some("NoReply@Example.com".to_string());
        env.from_name = Some("Auth API".to_string());
        env.verify_email_url_base = Some("https://app.example.com/verify-email".to_string());
        env.password_reset_url_base = Some("https://app.example.com/reset-password".to_string());

        let provider =
            parse_email_provider_config("sendgrid".to_string(), Some("sg-key".to_string()), env)
                .expect("sendgrid provider should parse with all required settings");

        let EmailProviderConfig::SendGrid(sendgrid) = provider else {
            panic!("expected sendgrid provider");
        };
        assert_eq!(sendgrid.api_base_url, "https://api.sendgrid.com");
        assert_eq!(sendgrid.from_email, "noreply@example.com");
        assert_eq!(sendgrid.from_name.as_deref(), Some("Auth API"));
        assert_eq!(
            sendgrid.verify_email_url_base,
            "https://app.example.com/verify-email"
        );
        assert_eq!(
            sendgrid.password_reset_url_base,
            "https://app.example.com/reset-password"
        );
        assert_eq!(sendgrid.timeout_ms, 3000);
        assert_eq!(sendgrid.max_retries, 2);
        assert_eq!(sendgrid.retry_base_delay_ms, 200);
        assert_eq!(sendgrid.retry_max_delay_ms, 2000);
        assert_eq!(sendgrid.retry_jitter_percent, 20);
    }

    #[test]
    fn email_provider_sendgrid_parses_retry_timeout_overrides() {
        let mut env = sendgrid_env();
        env.api_base_url = Some("https://api.sendgrid.com".to_string());
        env.from_email = Some("noreply@example.com".to_string());
        env.from_name = Some("Auth API".to_string());
        env.verify_email_url_base = Some("https://app.example.com/verify-email".to_string());
        env.password_reset_url_base = Some("https://app.example.com/reset-password".to_string());
        env.timeout_ms = Some("4500".to_string());
        env.max_retries = Some("4".to_string());
        env.retry_base_delay_ms = Some("150".to_string());
        env.retry_max_delay_ms = Some("900".to_string());
        env.retry_jitter_percent = Some("35".to_string());

        let provider =
            parse_email_provider_config("sendgrid".to_string(), Some("sg-key".to_string()), env)
                .expect("sendgrid retry and timeout overrides should parse");

        let EmailProviderConfig::SendGrid(sendgrid) = provider else {
            panic!("expected sendgrid provider");
        };

        assert_eq!(sendgrid.timeout_ms, 4500);
        assert_eq!(sendgrid.max_retries, 4);
        assert_eq!(sendgrid.retry_base_delay_ms, 150);
        assert_eq!(sendgrid.retry_max_delay_ms, 900);
        assert_eq!(sendgrid.retry_jitter_percent, 35);
    }

    #[test]
    fn email_provider_sendgrid_rejects_invalid_retry_jitter_percent() {
        let mut env = sendgrid_env();
        env.api_base_url = Some("https://api.sendgrid.com".to_string());
        env.from_email = Some("noreply@example.com".to_string());
        env.verify_email_url_base = Some("https://app.example.com/verify-email".to_string());
        env.password_reset_url_base = Some("https://app.example.com/reset-password".to_string());
        env.retry_jitter_percent = Some("120".to_string());

        let error =
            parse_email_provider_config("sendgrid".to_string(), Some("sg-key".to_string()), env)
                .expect_err("retry jitter percent above 100 should be rejected");

        assert!(error
            .to_string()
            .contains("SENDGRID_RETRY_JITTER_PERCENT must be between 0 and 100"));
    }

    #[test]
    fn email_provider_sendgrid_rejects_invalid_api_base_url() {
        let mut env = sendgrid_env();
        env.api_base_url = Some("api.sendgrid.com".to_string());
        env.from_email = Some("noreply@example.com".to_string());
        env.verify_email_url_base = Some("https://app.example.com/verify-email".to_string());
        env.password_reset_url_base = Some("https://app.example.com/reset-password".to_string());

        let error =
            parse_email_provider_config("sendgrid".to_string(), Some("sg-key".to_string()), env)
                .expect_err("invalid sendgrid api url should fail");

        assert!(error
            .to_string()
            .contains("SENDGRID_API_BASE_URL must start with http:// or https://"));
    }

    #[test]
    fn email_provider_sendgrid_rejects_invalid_retry_window() {
        let mut env = sendgrid_env();
        env.api_base_url = Some("https://api.sendgrid.com".to_string());
        env.from_email = Some("noreply@example.com".to_string());
        env.verify_email_url_base = Some("https://app.example.com/verify-email".to_string());
        env.password_reset_url_base = Some("https://app.example.com/reset-password".to_string());
        env.timeout_ms = Some("3000".to_string());
        env.max_retries = Some("2".to_string());
        env.retry_base_delay_ms = Some("1000".to_string());
        env.retry_max_delay_ms = Some("200".to_string());

        let error =
            parse_email_provider_config("sendgrid".to_string(), Some("sg-key".to_string()), env)
                .expect_err("retry max below retry base should be rejected");

        assert!(error.to_string().contains(
            "SENDGRID_RETRY_MAX_DELAY_MS must be greater than or equal to SENDGRID_RETRY_BASE_DELAY_MS"
        ));
    }

    #[test]
    fn email_delivery_mode_defaults_to_inline() {
        let mode =
            parse_email_delivery_mode("inline".to_string()).expect("inline mode should parse");

        assert_eq!(mode, EmailDeliveryMode::Inline);
    }

    #[test]
    fn email_delivery_mode_accepts_outbox() {
        let mode =
            parse_email_delivery_mode("outbox".to_string()).expect("outbox mode should parse");

        assert_eq!(mode, EmailDeliveryMode::Outbox);
    }

    #[test]
    fn email_delivery_mode_rejects_unknown_values() {
        let error =
            parse_email_delivery_mode("queue".to_string()).expect_err("unknown mode should fail");

        assert!(error
            .to_string()
            .contains("EMAIL_DELIVERY_MODE must be one of: inline, outbox"));
    }

    #[test]
    fn parse_positive_u64_with_default_rejects_zero() {
        let error = parse_positive_u64_with_default(
            Some("0".to_string()),
            1000,
            "EMAIL_OUTBOX_POLL_INTERVAL_MS",
        )
        .expect_err("zero outbox interval should fail");

        assert!(error
            .to_string()
            .contains("EMAIL_OUTBOX_POLL_INTERVAL_MS must be greater than 0"));
    }

    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIMn3Wcxxd4JzzjbshVFXz8jSGuF9ErqngPTzYhbfm6hd\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdIROjbNDN9NHACJMCdMbdRjmUZp05u0E+QVRzrqB6eM=\n-----END PUBLIC KEY-----\n";

    fn write_temp_secret_file(content: &str) -> PathBuf {
        let file_path =
            std::env::temp_dir().join(format!("auth-metrics-secret-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&file_path, content).expect("temp secret file should be written");
        file_path
    }

    fn sendgrid_env() -> super::SendGridEnvConfig {
        super::SendGridEnvConfig {
            api_base_url: None,
            from_email: None,
            from_name: None,
            verify_email_url_base: None,
            password_reset_url_base: None,
            timeout_ms: None,
            max_retries: None,
            retry_base_delay_ms: None,
            retry_max_delay_ms: None,
            retry_jitter_percent: None,
        }
    }
}
