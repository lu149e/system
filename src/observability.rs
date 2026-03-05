use std::{
    sync::{atomic::AtomicBool, atomic::Ordering, OnceLock},
    time::Duration,
};

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
};

use crate::modules::auth::application::AuthError;

struct MetricsRegistry {
    registry: Registry,
    login_risk_decisions_total: IntCounterVec,
    passkey_requests_total: IntCounterVec,
    passkey_login_rejected_total: IntCounterVec,
    passkey_register_rejected_total: IntCounterVec,
    passkey_challenge_janitor_enabled: IntGauge,
    passkey_challenge_prune_interval_seconds: IntGauge,
    passkey_challenge_prune_runs_total: IntCounterVec,
    passkey_challenge_prune_last_success_unixtime: IntGauge,
    passkey_challenge_prune_last_failure_unixtime: IntGauge,
    passkey_challenge_pruned_total: IntCounter,
    passkey_challenge_prune_errors_total: IntCounter,
    refresh_requests_total: IntCounterVec,
    refresh_rejected_total: IntCounterVec,
    refresh_duration_seconds: HistogramVec,
    problem_responses_total: IntCounterVec,
    email_delivery_total: IntCounterVec,
    email_delivery_duration_seconds: HistogramVec,
    email_retry_attempts_total: IntCounterVec,
    email_retry_attempts: HistogramVec,
    email_outbox_queue_depth: IntGauge,
    email_outbox_oldest_pending_age_seconds: IntGauge,
    email_outbox_oldest_due_age_seconds: IntGauge,
    email_outbox_dispatch_total: IntCounterVec,
    email_outbox_claimed_per_poll: Histogram,
    email_outbox_reclaimed_after_expiry_total: IntCounter,
    email_outbox_claim_failures_total: IntCounter,
}

impl MetricsRegistry {
    fn new() -> Self {
        let registry = Registry::new();

        let refresh_requests_total = IntCounterVec::new(
            Opts::new(
                "auth_refresh_requests_total",
                "Total refresh requests partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("refresh requests metric should initialize");

        let login_risk_decisions_total = IntCounterVec::new(
            Opts::new(
                "auth_login_risk_decisions_total",
                "Total login risk engine decisions partitioned by decision and reason",
            ),
            &["decision", "reason"],
        )
        .expect("login risk decisions metric should initialize");

        let passkey_requests_total = IntCounterVec::new(
            Opts::new(
                "auth_passkey_requests_total",
                "Total passkey API requests partitioned by operation and outcome",
            ),
            &["operation", "outcome"],
        )
        .expect("passkey requests metric should initialize");

        let passkey_login_rejected_total = IntCounterVec::new(
            Opts::new(
                "auth_passkey_login_rejected_total",
                "Total passkey login rejections partitioned by reason",
            ),
            &["reason"],
        )
        .expect("passkey login rejected metric should initialize");

        let passkey_register_rejected_total = IntCounterVec::new(
            Opts::new(
                "auth_passkey_register_rejected_total",
                "Total passkey registration rejections partitioned by reason",
            ),
            &["reason"],
        )
        .expect("passkey register rejected metric should initialize");

        let passkey_challenge_janitor_enabled = IntGauge::new(
            "auth_passkey_challenge_janitor_enabled",
            "Whether passkey challenge janitor is enabled (1=true, 0=false)",
        )
        .expect("passkey challenge janitor enabled metric should initialize");

        let passkey_challenge_prune_interval_seconds = IntGauge::new(
            "auth_passkey_challenge_prune_interval_seconds",
            "Configured passkey challenge janitor prune interval in seconds",
        )
        .expect("passkey challenge prune interval metric should initialize");

        let passkey_challenge_prune_runs_total = IntCounterVec::new(
            Opts::new(
                "auth_passkey_challenge_prune_runs_total",
                "Total janitor prune runs partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("passkey challenge prune runs metric should initialize");

        let passkey_challenge_prune_last_success_unixtime = IntGauge::new(
            "auth_passkey_challenge_prune_last_success_unixtime",
            "Unix timestamp (seconds) of the last successful passkey challenge prune run",
        )
        .expect("passkey challenge prune last success metric should initialize");

        let passkey_challenge_prune_last_failure_unixtime = IntGauge::new(
            "auth_passkey_challenge_prune_last_failure_unixtime",
            "Unix timestamp (seconds) of the last failed passkey challenge prune run",
        )
        .expect("passkey challenge prune last failure metric should initialize");

        let passkey_challenge_pruned_total = IntCounter::new(
            "auth_passkey_challenge_pruned_total",
            "Total expired passkey challenges pruned by background janitor",
        )
        .expect("passkey challenge pruned metric should initialize");

        let passkey_challenge_prune_errors_total = IntCounter::new(
            "auth_passkey_challenge_prune_errors_total",
            "Total passkey challenge janitor prune failures",
        )
        .expect("passkey challenge prune errors metric should initialize");

        let refresh_rejected_total = IntCounterVec::new(
            Opts::new(
                "auth_refresh_rejected_total",
                "Total rejected refresh attempts partitioned by reason",
            ),
            &["reason"],
        )
        .expect("refresh rejected metric should initialize");

        let refresh_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "auth_refresh_duration_seconds",
                "Refresh request duration in seconds partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("refresh duration metric should initialize");

        let problem_responses_total = IntCounterVec::new(
            Opts::new(
                "auth_problem_responses_total",
                "Total problem+json responses partitioned by status and problem type",
            ),
            &["status", "type"],
        )
        .expect("problem responses metric should initialize");

        let email_delivery_total = IntCounterVec::new(
            Opts::new(
                "auth_email_delivery_total",
                "Total transactional email attempts partitioned by provider, template, and outcome",
            ),
            &["provider", "template", "outcome"],
        )
        .expect("email delivery metric should initialize");

        let email_delivery_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "auth_email_delivery_duration_seconds",
                "Transactional email delivery duration in seconds partitioned by provider, template, and outcome",
            ),
            &["provider", "template", "outcome"],
        )
        .expect("email delivery latency metric should initialize");

        let email_retry_attempts_total = IntCounterVec::new(
            Opts::new(
                "auth_email_retry_attempts_total",
                "Total transactional email retry attempts partitioned by provider, template, and outcome",
            ),
            &["provider", "template", "outcome"],
        )
        .expect("email retry attempts metric should initialize");

        let email_retry_attempts = HistogramVec::new(
            HistogramOpts::new(
                "auth_email_retry_attempts",
                "Transactional email retry attempts per send partitioned by provider, template, and outcome",
            )
            .buckets(vec![0.0, 1.0, 2.0, 3.0, 5.0, 8.0]),
            &["provider", "template", "outcome"],
        )
        .expect("email retry attempts histogram should initialize");

        let email_outbox_queue_depth = IntGauge::new(
            "auth_email_outbox_queue_depth",
            "Current transactional email outbox queue depth",
        )
        .expect("email outbox queue depth metric should initialize");

        let email_outbox_dispatch_total = IntCounterVec::new(
            Opts::new(
                "auth_email_outbox_dispatch_total",
                "Total outbox dispatch outcomes partitioned by provider, template, and outcome",
            ),
            &["provider", "template", "outcome"],
        )
        .expect("email outbox dispatch metric should initialize");

        let email_outbox_oldest_pending_age_seconds = IntGauge::new(
            "auth_email_outbox_oldest_pending_age_seconds",
            "Age in seconds of the oldest pending email outbox entry",
        )
        .expect("email outbox oldest pending age metric should initialize");

        let email_outbox_oldest_due_age_seconds = IntGauge::new(
            "auth_email_outbox_oldest_due_age_seconds",
            "Age in seconds of the oldest due retryable email outbox entry",
        )
        .expect("email outbox oldest due age metric should initialize");

        let email_outbox_claimed_per_poll = Histogram::with_opts(
            HistogramOpts::new(
                "auth_email_outbox_claimed_per_poll",
                "Outbox messages claimed per dispatcher poll cycle",
            )
            .buckets(vec![0.0, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0]),
        )
        .expect("email outbox claimed per poll metric should initialize");

        let email_outbox_reclaimed_after_expiry_total = IntCounter::new(
            "auth_email_outbox_reclaimed_after_expiry_total",
            "Total outbox rows reclaimed after lease expiry",
        )
        .expect("email outbox reclaimed metric should initialize");

        let email_outbox_claim_failures_total = IntCounter::new(
            "auth_email_outbox_claim_failures_total",
            "Total outbox claim/fetch failures in dispatcher poll cycles",
        )
        .expect("email outbox claim failures metric should initialize");

        registry
            .register(Box::new(login_risk_decisions_total.clone()))
            .expect("login risk decisions metric should register");
        registry
            .register(Box::new(passkey_requests_total.clone()))
            .expect("passkey requests metric should register");
        registry
            .register(Box::new(passkey_login_rejected_total.clone()))
            .expect("passkey login rejected metric should register");
        registry
            .register(Box::new(passkey_register_rejected_total.clone()))
            .expect("passkey register rejected metric should register");
        registry
            .register(Box::new(passkey_challenge_janitor_enabled.clone()))
            .expect("passkey challenge janitor enabled metric should register");
        registry
            .register(Box::new(passkey_challenge_prune_interval_seconds.clone()))
            .expect("passkey challenge prune interval metric should register");
        registry
            .register(Box::new(passkey_challenge_prune_runs_total.clone()))
            .expect("passkey challenge prune runs metric should register");
        registry
            .register(Box::new(
                passkey_challenge_prune_last_success_unixtime.clone(),
            ))
            .expect("passkey challenge prune last success metric should register");
        registry
            .register(Box::new(
                passkey_challenge_prune_last_failure_unixtime.clone(),
            ))
            .expect("passkey challenge prune last failure metric should register");
        registry
            .register(Box::new(passkey_challenge_pruned_total.clone()))
            .expect("passkey challenge pruned metric should register");
        registry
            .register(Box::new(passkey_challenge_prune_errors_total.clone()))
            .expect("passkey challenge prune errors metric should register");
        registry
            .register(Box::new(refresh_requests_total.clone()))
            .expect("refresh requests metric should register");
        registry
            .register(Box::new(refresh_rejected_total.clone()))
            .expect("refresh rejected metric should register");
        registry
            .register(Box::new(refresh_duration_seconds.clone()))
            .expect("refresh duration metric should register");
        registry
            .register(Box::new(problem_responses_total.clone()))
            .expect("problem responses metric should register");
        registry
            .register(Box::new(email_delivery_total.clone()))
            .expect("email delivery metric should register");
        registry
            .register(Box::new(email_delivery_duration_seconds.clone()))
            .expect("email delivery latency metric should register");
        registry
            .register(Box::new(email_retry_attempts_total.clone()))
            .expect("email retry attempts metric should register");
        registry
            .register(Box::new(email_retry_attempts.clone()))
            .expect("email retry attempts histogram should register");
        registry
            .register(Box::new(email_outbox_queue_depth.clone()))
            .expect("email outbox queue depth metric should register");
        registry
            .register(Box::new(email_outbox_dispatch_total.clone()))
            .expect("email outbox dispatch metric should register");
        registry
            .register(Box::new(email_outbox_oldest_pending_age_seconds.clone()))
            .expect("email outbox oldest pending age metric should register");
        registry
            .register(Box::new(email_outbox_oldest_due_age_seconds.clone()))
            .expect("email outbox oldest due age metric should register");
        registry
            .register(Box::new(email_outbox_claimed_per_poll.clone()))
            .expect("email outbox claimed per poll metric should register");
        registry
            .register(Box::new(email_outbox_reclaimed_after_expiry_total.clone()))
            .expect("email outbox reclaimed metric should register");
        registry
            .register(Box::new(email_outbox_claim_failures_total.clone()))
            .expect("email outbox claim failures metric should register");

        Self {
            registry,
            login_risk_decisions_total,
            passkey_requests_total,
            passkey_login_rejected_total,
            passkey_register_rejected_total,
            passkey_challenge_janitor_enabled,
            passkey_challenge_prune_interval_seconds,
            passkey_challenge_prune_runs_total,
            passkey_challenge_prune_last_success_unixtime,
            passkey_challenge_prune_last_failure_unixtime,
            passkey_challenge_pruned_total,
            passkey_challenge_prune_errors_total,
            refresh_requests_total,
            refresh_rejected_total,
            refresh_duration_seconds,
            problem_responses_total,
            email_delivery_total,
            email_delivery_duration_seconds,
            email_retry_attempts_total,
            email_retry_attempts,
            email_outbox_queue_depth,
            email_outbox_oldest_pending_age_seconds,
            email_outbox_oldest_due_age_seconds,
            email_outbox_dispatch_total,
            email_outbox_claimed_per_poll,
            email_outbox_reclaimed_after_expiry_total,
            email_outbox_claim_failures_total,
        }
    }
}

static METRICS: OnceLock<MetricsRegistry> = OnceLock::new();
static EMAIL_LATENCY_ENABLED: AtomicBool = AtomicBool::new(false);

fn metrics() -> &'static MetricsRegistry {
    METRICS.get_or_init(MetricsRegistry::new)
}

pub fn record_refresh_success(duration: Duration) {
    let metrics = metrics();

    metrics
        .refresh_requests_total
        .with_label_values(&["success"])
        .inc();
    metrics
        .refresh_duration_seconds
        .with_label_values(&["success"])
        .observe(duration.as_secs_f64());
}

pub fn record_login_risk_decision(decision: &str, reason: &str) {
    metrics()
        .login_risk_decisions_total
        .with_label_values(&[decision, reason])
        .inc();
}

pub fn record_passkey_request(operation: &str, outcome: &str) {
    metrics()
        .passkey_requests_total
        .with_label_values(&[operation, outcome])
        .inc();
}

pub fn record_passkey_login_rejected(reason: &str) {
    metrics()
        .passkey_login_rejected_total
        .with_label_values(&[normalize_passkey_login_rejection_reason(reason)])
        .inc();
}

pub fn record_passkey_register_rejected(reason: &str) {
    metrics()
        .passkey_register_rejected_total
        .with_label_values(&[normalize_passkey_register_rejection_reason(reason)])
        .inc();
}

pub fn set_passkey_challenge_janitor_enabled(enabled: bool) {
    metrics()
        .passkey_challenge_janitor_enabled
        .set(if enabled { 1 } else { 0 });
}

pub fn set_passkey_challenge_prune_interval_seconds(interval_seconds: u64) {
    metrics()
        .passkey_challenge_prune_interval_seconds
        .set(interval_seconds as i64);
}

pub fn record_passkey_challenge_prune_run(outcome: &str) {
    metrics()
        .passkey_challenge_prune_runs_total
        .with_label_values(&[outcome])
        .inc();
}

pub fn set_passkey_challenge_prune_last_success_unixtime(unix_time_seconds: i64) {
    metrics()
        .passkey_challenge_prune_last_success_unixtime
        .set(unix_time_seconds);
}

pub fn set_passkey_challenge_prune_last_failure_unixtime(unix_time_seconds: i64) {
    metrics()
        .passkey_challenge_prune_last_failure_unixtime
        .set(unix_time_seconds);
}

pub fn record_passkey_challenge_pruned(pruned: u64) {
    if pruned == 0 {
        return;
    }

    metrics().passkey_challenge_pruned_total.inc_by(pruned);
}

pub fn record_passkey_challenge_prune_error() {
    metrics().passkey_challenge_prune_errors_total.inc();
}

pub fn record_refresh_error(error: &AuthError, duration: Duration) {
    let metrics = metrics();
    let reason = refresh_error_reason(error);

    metrics
        .refresh_requests_total
        .with_label_values(&["error"])
        .inc();
    metrics
        .refresh_rejected_total
        .with_label_values(&[reason])
        .inc();
    metrics
        .refresh_duration_seconds
        .with_label_values(&["error"])
        .observe(duration.as_secs_f64());
}

pub fn render_prometheus() -> Result<String, String> {
    let mut buffer = Vec::new();
    let metric_families = metrics().registry.gather();

    TextEncoder::new()
        .encode(&metric_families, &mut buffer)
        .map_err(|_| "metrics encode failed".to_string())?;

    String::from_utf8(buffer).map_err(|_| "metrics utf8 encoding failed".to_string())
}

pub fn configure_email_metrics(latency_enabled: bool) {
    EMAIL_LATENCY_ENABLED.store(latency_enabled, Ordering::Relaxed);
}

pub fn record_email_delivery(
    provider: &'static str,
    template: &'static str,
    success: bool,
    duration: Duration,
) {
    let metrics = metrics();
    let outcome = if success { "success" } else { "failure" };

    metrics
        .email_delivery_total
        .with_label_values(&[provider, template, outcome])
        .inc();

    if EMAIL_LATENCY_ENABLED.load(Ordering::Relaxed) {
        metrics
            .email_delivery_duration_seconds
            .with_label_values(&[provider, template, outcome])
            .observe(duration.as_secs_f64());
    }
}

pub fn record_email_retry_intensity(
    provider: &'static str,
    template: &'static str,
    success: bool,
    retries: u32,
) {
    let metrics = metrics();
    let outcome = if success { "success" } else { "failure" };

    metrics
        .email_retry_attempts_total
        .with_label_values(&[provider, template, outcome])
        .inc_by(u64::from(retries));
    metrics
        .email_retry_attempts
        .with_label_values(&[provider, template, outcome])
        .observe(f64::from(retries));
}

pub fn record_problem_response(status_code: u16, problem_type: &str) {
    let metrics = metrics();
    let status = status_code.to_string();

    metrics
        .problem_responses_total
        .with_label_values(&[status.as_str(), problem_type])
        .inc();
}

pub fn set_email_outbox_queue_depth(depth: u64) {
    metrics().email_outbox_queue_depth.set(depth as i64);
}

pub fn record_email_outbox_dispatch(
    provider: &str,
    template: &str,
    outcome: &str,
    _attempt_number: u32,
) {
    metrics()
        .email_outbox_dispatch_total
        .with_label_values(&[provider, template, outcome])
        .inc();
}

pub fn set_email_outbox_oldest_pending_age_seconds(age_seconds: u64) {
    metrics()
        .email_outbox_oldest_pending_age_seconds
        .set(age_seconds as i64);
}

pub fn set_email_outbox_oldest_due_age_seconds(age_seconds: u64) {
    metrics()
        .email_outbox_oldest_due_age_seconds
        .set(age_seconds as i64);
}

pub fn record_email_outbox_claim_poll(claimed_count: u64, reclaimed_after_expiry_count: u64) {
    let metrics = metrics();
    metrics
        .email_outbox_claimed_per_poll
        .observe(claimed_count as f64);
    if reclaimed_after_expiry_count > 0 {
        metrics
            .email_outbox_reclaimed_after_expiry_total
            .inc_by(reclaimed_after_expiry_count);
    }
}

pub fn record_email_outbox_claim_failure() {
    metrics().email_outbox_claim_failures_total.inc();
}

fn refresh_error_reason(error: &AuthError) -> &'static str {
    match error {
        AuthError::InvalidToken => "invalid_token",
        AuthError::TokenExpired => "token_expired",
        AuthError::RefreshReuseDetected => "refresh_reuse_detected",
        AuthError::Internal => "internal",
        AuthError::LoginLocked { .. } => "login_locked",
        _ => "other",
    }
}

fn normalize_passkey_login_rejection_reason(reason: &str) -> &'static str {
    match reason {
        "invalid_or_expired_challenge" => "invalid_or_expired_challenge",
        "account_not_active" => "account_not_active",
        "passkey_not_registered" => "passkey_not_registered",
        "invalid_passkey_response" => "invalid_passkey_response",
        _ => "other",
    }
}

fn normalize_passkey_register_rejection_reason(reason: &str) -> &'static str {
    match reason {
        "account_not_active" => "account_not_active",
        "invalid_or_expired_challenge" => "invalid_or_expired_challenge",
        "challenge_user_mismatch" => "challenge_user_mismatch",
        "invalid_passkey_response" => "invalid_passkey_response",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        configure_email_metrics, record_email_delivery, record_email_outbox_claim_failure,
        record_email_outbox_claim_poll, record_email_outbox_dispatch, record_email_retry_intensity,
        record_login_risk_decision, record_passkey_challenge_prune_error,
        record_passkey_challenge_prune_run, record_passkey_challenge_pruned,
        record_passkey_login_rejected, record_passkey_register_rejected, record_passkey_request,
        record_problem_response, record_refresh_error, record_refresh_success, render_prometheus,
        set_email_outbox_oldest_due_age_seconds, set_email_outbox_oldest_pending_age_seconds,
        set_email_outbox_queue_depth, set_passkey_challenge_janitor_enabled,
        set_passkey_challenge_prune_interval_seconds,
        set_passkey_challenge_prune_last_failure_unixtime,
        set_passkey_challenge_prune_last_success_unixtime,
    };
    use crate::modules::auth::application::AuthError;

    #[test]
    fn prometheus_render_exposes_refresh_metrics() {
        configure_email_metrics(true);
        record_refresh_success(std::time::Duration::from_millis(15));
        record_refresh_error(
            &AuthError::RefreshReuseDetected,
            std::time::Duration::from_millis(5),
        );
        record_login_risk_decision("block", "blocked_source_ip");
        record_passkey_request("login_finish", "success");
        record_passkey_login_rejected("invalid_passkey_response");
        record_passkey_login_rejected("unexpected_future_reason");
        record_passkey_register_rejected("invalid_or_expired_challenge");
        record_passkey_register_rejected("challenge_user_mismatch");
        record_passkey_register_rejected("future_register_reason");
        set_passkey_challenge_janitor_enabled(true);
        set_passkey_challenge_prune_interval_seconds(60);
        record_passkey_challenge_prune_run("success");
        set_passkey_challenge_prune_last_success_unixtime(1_700_000_000);
        record_passkey_challenge_pruned(2);
        record_passkey_challenge_prune_run("error");
        set_passkey_challenge_prune_last_failure_unixtime(1_700_000_030);
        record_passkey_challenge_prune_error();
        record_problem_response(429, "https://example.com/problems/login-locked");
        record_email_delivery(
            "sendgrid",
            "verification",
            true,
            std::time::Duration::from_millis(9),
        );
        record_email_retry_intensity("sendgrid", "verification", true, 2);
        set_email_outbox_queue_depth(7);
        set_email_outbox_oldest_pending_age_seconds(42);
        set_email_outbox_oldest_due_age_seconds(21);
        record_email_outbox_dispatch("sendgrid", "verification", "sent", 1);
        record_email_outbox_claim_poll(3, 1);
        record_email_outbox_claim_failure();

        let payload = render_prometheus().expect("metrics payload should be rendered");

        assert!(payload.contains("auth_refresh_requests_total"));
        assert!(payload.contains("auth_login_risk_decisions_total"));
        assert!(payload.contains("auth_passkey_requests_total"));
        assert!(payload.contains("auth_passkey_login_rejected_total"));
        assert!(payload.contains("auth_passkey_register_rejected_total"));
        assert!(payload.contains("auth_passkey_challenge_janitor_enabled"));
        assert!(payload.contains("auth_passkey_challenge_prune_interval_seconds"));
        assert!(payload.contains("auth_passkey_challenge_prune_runs_total"));
        assert!(payload.contains("auth_passkey_challenge_prune_last_success_unixtime"));
        assert!(payload.contains("auth_passkey_challenge_prune_last_failure_unixtime"));
        assert!(payload.contains("auth_passkey_challenge_pruned_total"));
        assert!(payload.contains("auth_passkey_challenge_prune_errors_total"));
        assert!(payload.contains("auth_refresh_rejected_total"));
        assert!(payload.contains("auth_refresh_duration_seconds"));
        assert!(payload.contains("auth_problem_responses_total"));
        assert!(payload.contains("auth_email_delivery_total"));
        assert!(payload.contains("auth_email_delivery_duration_seconds"));
        assert!(payload.contains("auth_email_retry_attempts_total"));
        assert!(payload.contains("auth_email_retry_attempts_bucket"));
        assert!(payload.contains("auth_email_outbox_queue_depth"));
        assert!(payload.contains("auth_email_outbox_oldest_pending_age_seconds"));
        assert!(payload.contains("auth_email_outbox_oldest_due_age_seconds"));
        assert!(payload.contains("auth_email_outbox_dispatch_total"));
        assert!(payload.contains("auth_email_outbox_claimed_per_poll_bucket"));
        assert!(payload.contains("auth_email_outbox_reclaimed_after_expiry_total"));
        assert!(payload.contains("auth_email_outbox_claim_failures_total"));
        assert!(payload.contains("reason=\"refresh_reuse_detected\""));
        assert!(payload.contains("status=\"429\""));
        assert!(payload.contains("provider=\"sendgrid\""));
        assert!(payload.contains("reason=\"blocked_source_ip\""));
        assert!(payload.contains("reason=\"invalid_passkey_response\""));
        assert!(payload.contains("reason=\"other\""));
        assert!(payload.contains("reason=\"invalid_or_expired_challenge\""));
        assert!(payload.contains("reason=\"challenge_user_mismatch\""));
    }
}
