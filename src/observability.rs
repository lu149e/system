use std::{
    sync::{atomic::AtomicBool, atomic::Ordering, OnceLock},
    time::Duration,
};

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

use crate::config::resolve_auth_v2_cohort;
use crate::modules::auth::{application::AuthError, ports::AuthFlowMetricsSnapshot};

struct MetricsRegistry {
    registry: Registry,
    login_risk_decisions_total: IntCounterVec,
    login_risk_penalty_total: IntCounterVec,
    auth_v2_methods_requests_total: IntCounterVec,
    auth_v2_methods_rejected_total: IntCounterVec,
    auth_v2_methods_duration_seconds: HistogramVec,
    auth_v2_password_start_requests_total: IntCounterVec,
    auth_v2_password_start_duration_seconds: HistogramVec,
    auth_v2_password_finish_requests_total: IntCounterVec,
    auth_v2_password_finish_duration_seconds: HistogramVec,
    auth_v2_password_upgrade_requests_total: IntCounterVec,
    auth_v2_password_upgrade_duration_seconds: HistogramVec,
    auth_v2_password_rejected_total: IntCounterVec,
    auth_v2_legacy_fallback_total: IntCounterVec,
    passkey_requests_total: IntCounterVec,
    passkey_login_rejected_total: IntCounterVec,
    passkey_register_rejected_total: IntCounterVec,
    password_forgot_accepted_total: IntCounterVec,
    password_reset_rejected_total: IntCounterVec,
    passkey_challenge_janitor_enabled: IntGauge,
    passkey_challenge_prune_interval_seconds: IntGauge,
    passkey_challenge_prune_runs_total: IntCounterVec,
    passkey_challenge_prune_last_success_unixtime: IntGauge,
    passkey_challenge_prune_last_failure_unixtime: IntGauge,
    passkey_challenge_pruned_total: IntCounter,
    passkey_challenge_prune_errors_total: IntCounter,
    auth_v2_auth_flow_janitor_enabled: IntGauge,
    auth_v2_auth_flow_prune_interval_seconds: IntGauge,
    auth_v2_auth_flow_prune_runs_total: IntCounterVec,
    auth_v2_auth_flow_prune_last_success_unixtime: IntGauge,
    auth_v2_auth_flow_prune_last_failure_unixtime: IntGauge,
    auth_v2_auth_flow_pruned_total: IntCounter,
    auth_v2_auth_flow_prune_errors_total: IntCounter,
    auth_v2_auth_flows_active: IntGaugeVec,
    auth_v2_auth_flows_expired_pending_total: IntGauge,
    auth_v2_auth_flows_oldest_expired_pending_age_seconds: IntGauge,
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

        let login_risk_penalty_total = IntCounterVec::new(
            Opts::new(
                "auth_login_risk_penalty_total",
                "Total login abuse penalty units applied from risk decisions",
            ),
            &["profile", "reason"],
        )
        .expect("login risk penalty metric should initialize");

        let auth_v2_methods_requests_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_methods_requests_total",
                "Total auth v2 method discovery requests partitioned by outcome and channel",
            ),
            &["outcome", "channel"],
        )
        .expect("auth v2 methods requests metric should initialize");

        let auth_v2_methods_rejected_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_methods_rejected_total",
                "Total auth v2 method discovery rejections partitioned by reason",
            ),
            &["reason"],
        )
        .expect("auth v2 methods rejected metric should initialize");

        let auth_v2_methods_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "auth_v2_methods_duration_seconds",
                "Auth v2 method discovery latency in seconds partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("auth v2 methods duration metric should initialize");

        let auth_v2_password_start_requests_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_password_start_requests_total",
                "Total auth v2 password login start requests partitioned by outcome and channel",
            ),
            &["outcome", "channel"],
        )
        .expect("auth v2 password start requests metric should initialize");

        let auth_v2_password_start_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "auth_v2_password_start_duration_seconds",
                "Auth v2 password login start latency in seconds partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("auth v2 password start duration metric should initialize");

        let auth_v2_password_finish_requests_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_password_finish_requests_total",
                "Total auth v2 password login finish requests partitioned by outcome and channel",
            ),
            &["outcome", "channel"],
        )
        .expect("auth v2 password finish requests metric should initialize");

        let auth_v2_password_finish_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "auth_v2_password_finish_duration_seconds",
                "Auth v2 password login finish latency in seconds partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("auth v2 password finish duration metric should initialize");

        let auth_v2_password_upgrade_requests_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_password_upgrade_requests_total",
                "Total auth v2 password upgrade requests partitioned by operation and outcome",
            ),
            &["operation", "outcome"],
        )
        .expect("auth v2 password upgrade requests metric should initialize");

        let auth_v2_password_upgrade_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "auth_v2_password_upgrade_duration_seconds",
                "Auth v2 password upgrade latency in seconds partitioned by operation and outcome",
            ),
            &["operation", "outcome"],
        )
        .expect("auth v2 password upgrade duration metric should initialize");

        let auth_v2_password_rejected_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_password_rejected_total",
                "Total auth v2 password rejections partitioned by reason",
            ),
            &["reason"],
        )
        .expect("auth v2 password rejected metric should initialize");

        let auth_v2_legacy_fallback_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_legacy_fallback_total",
                "Total auth v2 legacy fallback policy evaluations partitioned by reason and channel",
            ),
            &["reason", "channel"],
        )
        .expect("auth v2 legacy fallback metric should initialize");

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

        let password_forgot_accepted_total = IntCounterVec::new(
            Opts::new(
                "auth_password_forgot_accepted_total",
                "Total accepted password forgot requests partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("password forgot accepted metric should initialize");

        let password_reset_rejected_total = IntCounterVec::new(
            Opts::new(
                "auth_password_reset_rejected_total",
                "Total password reset rejections partitioned by reason",
            ),
            &["reason"],
        )
        .expect("password reset rejected metric should initialize");

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

        let auth_v2_auth_flow_janitor_enabled = IntGauge::new(
            "auth_v2_auth_flow_janitor_enabled",
            "Whether auth v2 auth flow janitor is enabled (1=true, 0=false)",
        )
        .expect("auth flow janitor enabled metric should initialize");

        let auth_v2_auth_flow_prune_interval_seconds = IntGauge::new(
            "auth_v2_auth_flow_prune_interval_seconds",
            "Configured auth v2 auth flow janitor prune interval in seconds",
        )
        .expect("auth flow prune interval metric should initialize");

        let auth_v2_auth_flow_prune_runs_total = IntCounterVec::new(
            Opts::new(
                "auth_v2_auth_flow_prune_runs_total",
                "Total auth v2 auth flow janitor prune runs partitioned by outcome",
            ),
            &["outcome"],
        )
        .expect("auth flow prune runs metric should initialize");

        let auth_v2_auth_flow_prune_last_success_unixtime = IntGauge::new(
            "auth_v2_auth_flow_prune_last_success_unixtime",
            "Unix timestamp (seconds) of the last successful auth v2 auth flow prune run",
        )
        .expect("auth flow prune last success metric should initialize");

        let auth_v2_auth_flow_prune_last_failure_unixtime = IntGauge::new(
            "auth_v2_auth_flow_prune_last_failure_unixtime",
            "Unix timestamp (seconds) of the last failed auth v2 auth flow prune run",
        )
        .expect("auth flow prune last failure metric should initialize");

        let auth_v2_auth_flow_pruned_total = IntCounter::new(
            "auth_v2_auth_flow_pruned_total",
            "Total expired auth v2 auth flows pruned by background janitor",
        )
        .expect("auth flow pruned metric should initialize");

        let auth_v2_auth_flow_prune_errors_total = IntCounter::new(
            "auth_v2_auth_flow_prune_errors_total",
            "Total auth v2 auth flow janitor prune failures",
        )
        .expect("auth flow prune errors metric should initialize");

        let auth_v2_auth_flows_active = IntGaugeVec::new(
            Opts::new(
                "auth_v2_auth_flows_active",
                "Current active auth v2 auth flows partitioned by flow kind",
            ),
            &["flow_kind"],
        )
        .expect("auth flow active gauge should initialize");

        let auth_v2_auth_flows_expired_pending_total = IntGauge::new(
            "auth_v2_auth_flows_expired_pending_total",
            "Current expired pending auth v2 auth flows awaiting janitor cleanup",
        )
        .expect("auth flow expired backlog gauge should initialize");

        let auth_v2_auth_flows_oldest_expired_pending_age_seconds = IntGauge::new(
            "auth_v2_auth_flows_oldest_expired_pending_age_seconds",
            "Age in seconds of the oldest expired pending auth v2 auth flow awaiting janitor cleanup",
        )
        .expect("auth flow oldest expired backlog gauge should initialize");

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
            .register(Box::new(login_risk_penalty_total.clone()))
            .expect("login risk penalty metric should register");
        registry
            .register(Box::new(auth_v2_methods_requests_total.clone()))
            .expect("auth v2 methods requests metric should register");
        registry
            .register(Box::new(auth_v2_methods_rejected_total.clone()))
            .expect("auth v2 methods rejected metric should register");
        registry
            .register(Box::new(auth_v2_methods_duration_seconds.clone()))
            .expect("auth v2 methods duration metric should register");
        registry
            .register(Box::new(auth_v2_password_start_requests_total.clone()))
            .expect("auth v2 password start requests metric should register");
        registry
            .register(Box::new(auth_v2_password_start_duration_seconds.clone()))
            .expect("auth v2 password start duration metric should register");
        registry
            .register(Box::new(auth_v2_password_finish_requests_total.clone()))
            .expect("auth v2 password finish requests metric should register");
        registry
            .register(Box::new(auth_v2_password_finish_duration_seconds.clone()))
            .expect("auth v2 password finish duration metric should register");
        registry
            .register(Box::new(auth_v2_password_upgrade_requests_total.clone()))
            .expect("auth v2 password upgrade requests metric should register");
        registry
            .register(Box::new(auth_v2_password_upgrade_duration_seconds.clone()))
            .expect("auth v2 password upgrade duration metric should register");
        registry
            .register(Box::new(auth_v2_password_rejected_total.clone()))
            .expect("auth v2 password rejected metric should register");
        registry
            .register(Box::new(auth_v2_legacy_fallback_total.clone()))
            .expect("auth v2 legacy fallback metric should register");
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
            .register(Box::new(password_forgot_accepted_total.clone()))
            .expect("password forgot accepted metric should register");
        registry
            .register(Box::new(password_reset_rejected_total.clone()))
            .expect("password reset rejected metric should register");
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
            .register(Box::new(auth_v2_auth_flow_janitor_enabled.clone()))
            .expect("auth flow janitor enabled metric should register");
        registry
            .register(Box::new(auth_v2_auth_flow_prune_interval_seconds.clone()))
            .expect("auth flow prune interval metric should register");
        registry
            .register(Box::new(auth_v2_auth_flow_prune_runs_total.clone()))
            .expect("auth flow prune runs metric should register");
        registry
            .register(Box::new(
                auth_v2_auth_flow_prune_last_success_unixtime.clone(),
            ))
            .expect("auth flow prune last success metric should register");
        registry
            .register(Box::new(
                auth_v2_auth_flow_prune_last_failure_unixtime.clone(),
            ))
            .expect("auth flow prune last failure metric should register");
        registry
            .register(Box::new(auth_v2_auth_flow_pruned_total.clone()))
            .expect("auth flow pruned metric should register");
        registry
            .register(Box::new(auth_v2_auth_flow_prune_errors_total.clone()))
            .expect("auth flow prune errors metric should register");
        registry
            .register(Box::new(auth_v2_auth_flows_active.clone()))
            .expect("auth flow active gauge should register");
        registry
            .register(Box::new(auth_v2_auth_flows_expired_pending_total.clone()))
            .expect("auth flow expired backlog gauge should register");
        registry
            .register(Box::new(
                auth_v2_auth_flows_oldest_expired_pending_age_seconds.clone(),
            ))
            .expect("auth flow oldest expired backlog gauge should register");
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
            login_risk_penalty_total,
            auth_v2_methods_requests_total,
            auth_v2_methods_rejected_total,
            auth_v2_methods_duration_seconds,
            auth_v2_password_start_requests_total,
            auth_v2_password_start_duration_seconds,
            auth_v2_password_finish_requests_total,
            auth_v2_password_finish_duration_seconds,
            auth_v2_password_upgrade_requests_total,
            auth_v2_password_upgrade_duration_seconds,
            auth_v2_password_rejected_total,
            auth_v2_legacy_fallback_total,
            passkey_requests_total,
            passkey_login_rejected_total,
            passkey_register_rejected_total,
            password_forgot_accepted_total,
            password_reset_rejected_total,
            passkey_challenge_janitor_enabled,
            passkey_challenge_prune_interval_seconds,
            passkey_challenge_prune_runs_total,
            passkey_challenge_prune_last_success_unixtime,
            passkey_challenge_prune_last_failure_unixtime,
            passkey_challenge_pruned_total,
            passkey_challenge_prune_errors_total,
            auth_v2_auth_flow_janitor_enabled,
            auth_v2_auth_flow_prune_interval_seconds,
            auth_v2_auth_flow_prune_runs_total,
            auth_v2_auth_flow_prune_last_success_unixtime,
            auth_v2_auth_flow_prune_last_failure_unixtime,
            auth_v2_auth_flow_pruned_total,
            auth_v2_auth_flow_prune_errors_total,
            auth_v2_auth_flows_active,
            auth_v2_auth_flows_expired_pending_total,
            auth_v2_auth_flows_oldest_expired_pending_age_seconds,
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

pub fn record_login_risk_penalty(profile: &str, reason: &str, units: u64) {
    if units == 0 {
        return;
    }

    metrics()
        .login_risk_penalty_total
        .with_label_values(&[profile, reason])
        .inc_by(units);
}

pub fn record_auth_v2_methods_request(channel: &str, outcome: &str) {
    metrics()
        .auth_v2_methods_requests_total
        .with_label_values(&[
            normalize_auth_v2_request_outcome(outcome),
            normalize_auth_v2_rollout_channel(channel),
        ])
        .inc();
}

pub fn observe_auth_v2_methods_duration(outcome: &str, duration: Duration) {
    metrics()
        .auth_v2_methods_duration_seconds
        .with_label_values(&[normalize_auth_v2_request_outcome(outcome)])
        .observe(duration.as_secs_f64());
}

pub fn record_auth_v2_methods_rejected(reason: &str) {
    metrics()
        .auth_v2_methods_rejected_total
        .with_label_values(&[normalize_auth_v2_rejection_reason(reason)])
        .inc();
}

pub fn record_auth_v2_password_request(operation: &str, outcome: &str, channel: &str) {
    let metrics = metrics();
    let outcome = normalize_auth_v2_request_outcome(outcome);
    let channel = normalize_auth_v2_rollout_channel(channel);
    match operation {
        "login_start" => metrics
            .auth_v2_password_start_requests_total
            .with_label_values(&[outcome, channel])
            .inc(),
        "login_finish" => metrics
            .auth_v2_password_finish_requests_total
            .with_label_values(&[outcome, channel])
            .inc(),
        "upgrade_start" => metrics
            .auth_v2_password_upgrade_requests_total
            .with_label_values(&["start", outcome])
            .inc(),
        "upgrade_finish" => metrics
            .auth_v2_password_upgrade_requests_total
            .with_label_values(&["finish", outcome])
            .inc(),
        _ => {}
    }
}

pub fn observe_auth_v2_password_duration(operation: &str, outcome: &str, duration: Duration) {
    let metrics = metrics();
    let outcome = normalize_auth_v2_request_outcome(outcome);
    match operation {
        "login_start" => metrics
            .auth_v2_password_start_duration_seconds
            .with_label_values(&[outcome])
            .observe(duration.as_secs_f64()),
        "login_finish" => metrics
            .auth_v2_password_finish_duration_seconds
            .with_label_values(&[outcome])
            .observe(duration.as_secs_f64()),
        "upgrade_start" => metrics
            .auth_v2_password_upgrade_duration_seconds
            .with_label_values(&["start", outcome])
            .observe(duration.as_secs_f64()),
        "upgrade_finish" => metrics
            .auth_v2_password_upgrade_duration_seconds
            .with_label_values(&["finish", outcome])
            .observe(duration.as_secs_f64()),
        _ => {}
    }
}

pub fn record_auth_v2_legacy_fallback(reason: &str, channel: &str) {
    metrics()
        .auth_v2_legacy_fallback_total
        .with_label_values(&[
            normalize_auth_v2_fallback_reason(reason),
            normalize_auth_v2_rollout_channel(channel),
        ])
        .inc();
}

pub fn record_auth_v2_password_rejected(reason: &str) {
    metrics()
        .auth_v2_password_rejected_total
        .with_label_values(&[normalize_auth_v2_rejection_reason(reason)])
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

pub fn record_password_forgot_accepted(outcome: &str) {
    metrics()
        .password_forgot_accepted_total
        .with_label_values(&[normalize_password_forgot_outcome(outcome)])
        .inc();
}

pub fn record_password_reset_rejected(reason: &str) {
    metrics()
        .password_reset_rejected_total
        .with_label_values(&[normalize_password_reset_rejection_reason(reason)])
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

pub fn set_auth_v2_auth_flow_janitor_enabled(enabled: bool) {
    metrics()
        .auth_v2_auth_flow_janitor_enabled
        .set(if enabled { 1 } else { 0 });
}

pub fn set_auth_v2_auth_flow_prune_interval_seconds(interval_seconds: u64) {
    metrics()
        .auth_v2_auth_flow_prune_interval_seconds
        .set(interval_seconds as i64);
}

pub fn record_auth_v2_auth_flow_prune_run(outcome: &str) {
    metrics()
        .auth_v2_auth_flow_prune_runs_total
        .with_label_values(&[outcome])
        .inc();
}

pub fn set_auth_v2_auth_flow_prune_last_success_unixtime(unix_time_seconds: i64) {
    metrics()
        .auth_v2_auth_flow_prune_last_success_unixtime
        .set(unix_time_seconds);
}

pub fn set_auth_v2_auth_flow_prune_last_failure_unixtime(unix_time_seconds: i64) {
    metrics()
        .auth_v2_auth_flow_prune_last_failure_unixtime
        .set(unix_time_seconds);
}

pub fn record_auth_v2_auth_flow_pruned(pruned: u64) {
    if pruned == 0 {
        return;
    }

    metrics().auth_v2_auth_flow_pruned_total.inc_by(pruned);
}

pub fn record_auth_v2_auth_flow_prune_error() {
    metrics().auth_v2_auth_flow_prune_errors_total.inc();
}

pub fn set_auth_v2_auth_flow_metrics(snapshot: &AuthFlowMetricsSnapshot) {
    let metrics = metrics();
    for flow_kind in [
        "methods_discovery",
        "password_login",
        "password_upgrade",
        "passkey_login",
        "passkey_register",
    ] {
        metrics
            .auth_v2_auth_flows_active
            .with_label_values(&[flow_kind])
            .set(0);
    }

    for bucket in &snapshot.active_by_kind {
        metrics
            .auth_v2_auth_flows_active
            .with_label_values(&[auth_flow_kind_metric_label(&bucket.flow_kind)])
            .set(bucket.pending_total as i64);
    }

    metrics
        .auth_v2_auth_flows_expired_pending_total
        .set(snapshot.expired_pending_total as i64);
    metrics
        .auth_v2_auth_flows_oldest_expired_pending_age_seconds
        .set(snapshot.oldest_expired_pending_age_seconds as i64);
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
        "invalid-token" | "invalid_token" | "https://example.com/problems/invalid-token" => {
            "invalid_token"
        }
        "login-locked" | "login_locked" | "https://example.com/problems/login-locked" => {
            "login_locked"
        }
        "recovery-required"
        | "recovery_required"
        | "https://example.com/problems/recovery-required" => "recovery_required",
        "rollout_denied"
        | "auth-v2-rollout-denied"
        | "auth_v2_rollout_denied"
        | "https://example.com/problems/auth-v2-rollout-denied" => "rollout_denied",
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

fn normalize_password_forgot_outcome(outcome: &str) -> &'static str {
    match outcome {
        "existing" => "existing",
        "existing_not_active" => "existing_not_active",
        "unknown" => "unknown",
        _ => "other",
    }
}

fn normalize_password_reset_rejection_reason(reason: &str) -> &'static str {
    match reason {
        "weak_password" => "weak_password",
        "token_not_found" => "token_not_found",
        "token_already_used" => "token_already_used",
        "token_expired" => "token_expired",
        "user_not_found" => "user_not_found",
        "account_not_active" => "account_not_active",
        _ => "other",
    }
}

fn normalize_auth_v2_rollout_channel(channel: &str) -> &str {
    match channel {
        "unknown" => "unknown",
        "shadow" => "shadow",
        "internal" => "internal",
        "canary_web" => "canary_web",
        "canary_mobile" => "canary_mobile",
        "beta_external" => "beta_external",
        "broad_general" => "broad_general",
        "legacy_holdout" => "legacy_holdout",
        value => resolve_auth_v2_cohort(value)
            .map(|cohort| cohort.as_str())
            .unwrap_or("other"),
    }
}

fn normalize_auth_v2_request_outcome(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "error" => "error",
        "invalid_request" => "invalid_request",
        "rollout_denied" => "rollout_denied",
        "shadow_hidden" => "shadow_hidden",
        _ => "other",
    }
}

fn normalize_auth_v2_rejection_reason(reason: &str) -> &'static str {
    match reason {
        "invalid-request" | "invalid_request" | "https://example.com/problems/invalid-request" => {
            "invalid_request"
        }
        "rollout_denied"
        | "auth-v2-rollout-denied"
        | "auth_v2_rollout_denied"
        | "https://example.com/problems/auth-v2-rollout-denied" => "rollout_denied",
        "shadow_hidden" => "shadow_hidden",
        "invalid-token" | "invalid_token" | "https://example.com/problems/invalid-token" => {
            "invalid_token"
        }
        "recovery-required"
        | "recovery_required"
        | "https://example.com/problems/recovery-required" => "recovery_required",
        "invalid-recovery-bridge"
        | "invalid_recovery_bridge"
        | "https://example.com/problems/invalid-recovery-bridge" => "invalid_recovery_bridge",
        "invalid-credentials"
        | "invalid_credentials"
        | "https://example.com/problems/invalid-credentials" => "invalid_credentials",
        "login-locked" | "login_locked" | "https://example.com/problems/login-locked" => {
            "login_locked"
        }
        "pake-unavailable"
        | "pake_unavailable"
        | "https://example.com/problems/pake-unavailable" => "pake_unavailable",
        "opaque-credential-already-active"
        | "opaque_credential_already_active"
        | "https://example.com/problems/opaque-credential-already-active" => {
            "opaque_credential_already_active"
        }
        "invalid-opaque-registration"
        | "invalid_opaque_registration"
        | "https://example.com/problems/invalid-opaque-registration" => {
            "invalid_opaque_registration"
        }
        "internal-error" | "internal_error" | "https://example.com/problems/internal-error" => {
            "internal_error"
        }
        _ => "other",
    }
}

fn normalize_auth_v2_fallback_reason(reason: &str) -> &'static str {
    match reason {
        "allowlisted" => "allowlisted",
        "broad" => "broad",
        "client_not_allowlisted" => "client_not_allowlisted",
        "no_legacy_password" => "no_legacy_password",
        "legacy_login_disabled" => "legacy_login_disabled",
        "policy_disabled" => "policy_disabled",
        _ => "other",
    }
}

fn auth_flow_kind_metric_label(kind: &crate::modules::auth::domain::AuthFlowKind) -> &'static str {
    match kind {
        crate::modules::auth::domain::AuthFlowKind::MethodsDiscovery => "methods_discovery",
        crate::modules::auth::domain::AuthFlowKind::PasswordLogin => "password_login",
        crate::modules::auth::domain::AuthFlowKind::RecoveryUpgradeBridge => {
            "recovery_upgrade_bridge"
        }
        crate::modules::auth::domain::AuthFlowKind::PasswordUpgrade => "password_upgrade",
        crate::modules::auth::domain::AuthFlowKind::PasskeyLogin => "passkey_login",
        crate::modules::auth::domain::AuthFlowKind::PasskeyRegister => "passkey_register",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        configure_email_metrics, observe_auth_v2_methods_duration,
        observe_auth_v2_password_duration, record_auth_v2_auth_flow_prune_error,
        record_auth_v2_auth_flow_prune_run, record_auth_v2_auth_flow_pruned,
        record_auth_v2_legacy_fallback, record_auth_v2_methods_rejected,
        record_auth_v2_methods_request, record_auth_v2_password_rejected,
        record_auth_v2_password_request, record_email_delivery, record_email_outbox_claim_failure,
        record_email_outbox_claim_poll, record_email_outbox_dispatch, record_email_retry_intensity,
        record_login_risk_decision, record_login_risk_penalty,
        record_passkey_challenge_prune_error, record_passkey_challenge_prune_run,
        record_passkey_challenge_pruned, record_passkey_login_rejected,
        record_passkey_register_rejected, record_passkey_request, record_password_forgot_accepted,
        record_password_reset_rejected, record_problem_response, record_refresh_error,
        record_refresh_success, render_prometheus, set_auth_v2_auth_flow_janitor_enabled,
        set_auth_v2_auth_flow_metrics, set_auth_v2_auth_flow_prune_interval_seconds,
        set_auth_v2_auth_flow_prune_last_failure_unixtime,
        set_auth_v2_auth_flow_prune_last_success_unixtime, set_email_outbox_oldest_due_age_seconds,
        set_email_outbox_oldest_pending_age_seconds, set_email_outbox_queue_depth,
        set_passkey_challenge_janitor_enabled, set_passkey_challenge_prune_interval_seconds,
        set_passkey_challenge_prune_last_failure_unixtime,
        set_passkey_challenge_prune_last_success_unixtime,
    };
    use crate::modules::auth::application::AuthError;
    use crate::modules::auth::{
        domain::AuthFlowKind,
        ports::{AuthFlowMetricBucket, AuthFlowMetricsSnapshot},
    };

    #[test]
    fn prometheus_render_exposes_refresh_metrics() {
        configure_email_metrics(true);
        record_refresh_success(std::time::Duration::from_millis(15));
        record_refresh_error(
            &AuthError::RefreshReuseDetected,
            std::time::Duration::from_millis(5),
        );
        record_login_risk_decision("block", "blocked_source_ip");
        record_login_risk_penalty("aggressive", "blocked_source_ip", 5);
        record_auth_v2_methods_request("web", "success");
        record_auth_v2_methods_request("shadow", "shadow_hidden");
        observe_auth_v2_methods_duration("success", std::time::Duration::from_millis(8));
        record_auth_v2_methods_rejected("https://example.com/problems/auth-v2-rollout-denied");
        record_auth_v2_password_request("login_start", "success", "web");
        record_auth_v2_password_request("login_finish", "error", "android");
        record_auth_v2_password_request("upgrade_start", "success", "ios");
        record_auth_v2_password_request("upgrade_finish", "error", "ios");
        record_auth_v2_password_rejected("https://example.com/problems/recovery-required");
        record_auth_v2_password_rejected("https://example.com/problems/invalid-recovery-bridge");
        observe_auth_v2_password_duration(
            "login_start",
            "success",
            std::time::Duration::from_millis(11),
        );
        observe_auth_v2_password_duration(
            "login_finish",
            "error",
            std::time::Duration::from_millis(13),
        );
        observe_auth_v2_password_duration(
            "upgrade_start",
            "success",
            std::time::Duration::from_millis(17),
        );
        observe_auth_v2_password_duration(
            "upgrade_finish",
            "error",
            std::time::Duration::from_millis(19),
        );
        record_auth_v2_legacy_fallback("allowlisted", "internal-web");
        record_auth_v2_legacy_fallback("client_not_allowlisted", "android");
        record_passkey_request("login_finish", "success");
        record_passkey_login_rejected("invalid_passkey_response");
        record_passkey_login_rejected("unexpected_future_reason");
        record_passkey_register_rejected("invalid_or_expired_challenge");
        record_passkey_register_rejected("challenge_user_mismatch");
        record_passkey_register_rejected("future_register_reason");
        record_password_forgot_accepted("existing_not_active");
        record_password_forgot_accepted("future_outcome_value");
        record_password_reset_rejected("account_not_active");
        record_password_reset_rejected("future_rejection_reason");
        set_passkey_challenge_janitor_enabled(true);
        set_passkey_challenge_prune_interval_seconds(60);
        record_passkey_challenge_prune_run("success");
        set_passkey_challenge_prune_last_success_unixtime(1_700_000_000);
        record_passkey_challenge_pruned(2);
        record_passkey_challenge_prune_run("error");
        set_passkey_challenge_prune_last_failure_unixtime(1_700_000_030);
        record_passkey_challenge_prune_error();
        set_auth_v2_auth_flow_janitor_enabled(true);
        set_auth_v2_auth_flow_prune_interval_seconds(45);
        record_auth_v2_auth_flow_prune_run("success");
        set_auth_v2_auth_flow_prune_last_success_unixtime(1_700_000_060);
        record_auth_v2_auth_flow_pruned(3);
        record_auth_v2_auth_flow_prune_run("error");
        set_auth_v2_auth_flow_prune_last_failure_unixtime(1_700_000_090);
        record_auth_v2_auth_flow_prune_error();
        set_auth_v2_auth_flow_metrics(&AuthFlowMetricsSnapshot {
            active_by_kind: vec![
                AuthFlowMetricBucket {
                    flow_kind: AuthFlowKind::MethodsDiscovery,
                    pending_total: 2,
                },
                AuthFlowMetricBucket {
                    flow_kind: AuthFlowKind::PasswordLogin,
                    pending_total: 1,
                },
            ],
            expired_pending_total: 3,
            oldest_expired_pending_age_seconds: 120,
        });
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
        assert!(payload.contains("auth_login_risk_penalty_total"));
        assert!(payload.contains("auth_v2_methods_requests_total"));
        assert!(payload.contains("auth_v2_methods_rejected_total"));
        assert!(payload.contains("auth_v2_methods_duration_seconds"));
        assert!(payload.contains("auth_passkey_requests_total"));
        assert!(payload.contains("auth_passkey_login_rejected_total"));
        assert!(payload.contains("auth_passkey_register_rejected_total"));
        assert!(payload.contains("auth_password_forgot_accepted_total"));
        assert!(payload.contains("auth_password_reset_rejected_total"));
        assert!(payload.contains("auth_passkey_challenge_janitor_enabled"));
        assert!(payload.contains("auth_passkey_challenge_prune_interval_seconds"));
        assert!(payload.contains("auth_passkey_challenge_prune_runs_total"));
        assert!(payload.contains("auth_passkey_challenge_prune_last_success_unixtime"));
        assert!(payload.contains("auth_passkey_challenge_prune_last_failure_unixtime"));
        assert!(payload.contains("auth_passkey_challenge_pruned_total"));
        assert!(payload.contains("auth_passkey_challenge_prune_errors_total"));
        assert!(payload.contains("auth_v2_auth_flow_janitor_enabled"));
        assert!(payload.contains("auth_v2_password_start_requests_total"));
        assert!(payload.contains("auth_v2_password_start_duration_seconds"));
        assert!(payload.contains("auth_v2_password_finish_requests_total"));
        assert!(payload.contains("auth_v2_password_finish_duration_seconds"));
        assert!(payload.contains("auth_v2_password_upgrade_requests_total"));
        assert!(payload.contains("auth_v2_password_upgrade_duration_seconds"));
        assert!(!payload.contains("auth_v2_password_requests_total"));
        assert!(payload.contains("auth_v2_legacy_fallback_total"));
        assert!(payload.contains("auth_v2_auth_flow_prune_interval_seconds"));
        assert!(payload.contains("auth_v2_auth_flow_prune_runs_total"));
        assert!(payload.contains("auth_v2_auth_flow_prune_last_success_unixtime"));
        assert!(payload.contains("auth_v2_auth_flow_prune_last_failure_unixtime"));
        assert!(payload.contains("auth_v2_auth_flow_pruned_total"));
        assert!(payload.contains("auth_v2_auth_flow_prune_errors_total"));
        assert!(payload.contains("auth_v2_auth_flows_active"));
        assert!(payload.contains("auth_v2_auth_flows_expired_pending_total"));
        assert!(payload.contains("auth_v2_auth_flows_oldest_expired_pending_age_seconds"));
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
        assert!(payload.contains("channel=\"canary_web\""));
        assert!(payload.contains("channel=\"canary_mobile\""));
        assert!(payload.contains("channel=\"internal\""));
        assert!(payload.contains("reason=\"refresh_reuse_detected\""));
        assert!(payload.contains("status=\"429\""));
        assert!(payload.contains("provider=\"sendgrid\""));
        assert!(payload.contains("reason=\"blocked_source_ip\""));
        assert!(payload.contains("profile=\"aggressive\""));
        assert!(payload.contains("reason=\"invalid_passkey_response\""));
        assert!(payload.contains("reason=\"other\""));
        assert!(payload.contains("reason=\"invalid_or_expired_challenge\""));
        assert!(payload.contains("reason=\"challenge_user_mismatch\""));
        assert!(payload.contains("reason=\"account_not_active\""));
        assert!(payload.contains("reason=\"recovery_required\""));
        assert!(payload.contains("reason=\"invalid_recovery_bridge\""));
        assert!(payload.contains("outcome=\"existing_not_active\""));
        assert!(payload.contains("channel=\"canary_web\""));
        assert!(payload.contains("channel=\"canary_mobile\""));
        assert!(payload.contains("outcome=\"shadow_hidden\""));
        assert!(payload.contains("reason=\"rollout_denied\""));
        assert!(payload.contains("flow_kind=\"methods_discovery\""));
        assert!(payload.contains("flow_kind=\"password_login\""));
        assert!(payload.contains("reason=\"allowlisted\""));
        assert!(payload.contains("reason=\"client_not_allowlisted\""));
    }
}
