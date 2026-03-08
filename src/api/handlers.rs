use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::Instant,
};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::{
    api::problem::{from_auth_error, ApiProblem, ProblemDetails},
    config::resolve_auth_v2_cohort,
    health::ComponentState,
    modules::auth::application::{
        auth_v2_allows_external_access, evaluate_auth_v2_rollout, AuthError, AuthMethodsCommand,
        AuthMethodsResponse, AuthV2RolloutDecision, LoginCommand, LoginResult, LogoutCommand,
        MfaActivateCommand, MfaDisableCommand, MfaVerifyCommand, PakeLoginFinishCommand,
        PakeLoginStartCommand, PakeLoginStartResponse, PasskeyChallenge, PasswordChangeCommand,
        PasswordForgotCommand, PasswordResetCommand, PasswordUpgradeFinishCommand,
        PasswordUpgradeFinishResponse, PasswordUpgradeStartCommand, PasswordUpgradeStartResponse,
        Principal, RefreshCommand, RegisterCommand, RequestContext, VerifyEmailCommand,
    },
    observability, AppState,
};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub device_info: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub mfa_required: bool,
    pub challenge_id: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MfaActivateRequest {
    pub totp_code: String,
}

#[derive(Debug, Serialize)]
pub struct MfaActivateResponse {
    pub backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub challenge_id: String,
    pub totp_code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    pub current_password: String,
    pub totp_code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginStartRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginStartV2Request {
    pub identifier: String,
    pub discovery_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub flow_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginFinishRequest {
    pub flow_id: String,
    pub credential: PublicKeyCredential,
    pub device_info: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyChallengeResponse {
    pub flow_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterStartV2Request {
    #[serde(default)]
    #[allow(dead_code)]
    pub label: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub authenticator_preference: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PasskeyChallengeV2Response {
    pub flow_id: String,
    pub flow_kind: String,
    pub protocol: String,
    pub options: serde_json::Value,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterFinishV2Response {
    pub enrolled: bool,
    pub passkey_count: usize,
    pub recommended_login_method: String,
}

#[derive(Debug)]
pub struct NoStoreJson<T>(pub T);

impl<T> IntoResponse for NoStoreJson<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        let mut response = Json(self.0).into_response();
        apply_no_store_headers(response.headers_mut());
        response
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthMethodsRequest {
    pub identifier: String,
    pub channel: Option<String>,
    pub client: AuthClientCapabilitiesRequest,
}

#[derive(Debug, Deserialize)]
pub struct AuthClientCapabilitiesRequest {
    pub supports_pake: bool,
    pub supports_passkeys: bool,
    #[allow(dead_code)]
    pub supports_conditional_mediation: Option<bool>,
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthMethodsContractResponse {
    pub request_id: String,
    pub discovery_token: String,
    pub discovery_expires_in: i64,
    pub methods: Vec<AuthMethodContractResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_recovery: Option<AccountRecoveryContractResponse>,
    pub recommended_method: Option<String>,
    pub legacy_password_fallback: LegacyPasswordFallbackResponse,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountRecoveryContractResponse {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthMethodContractResponse {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
    pub action: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_mediation: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LegacyPasswordFallbackResponse {
    pub possible: bool,
    pub user_visible: bool,
}

#[derive(Debug, Deserialize)]
pub struct PasswordLoginStartRequest {
    pub identifier: String,
    pub discovery_token: String,
    #[serde(default)]
    pub client_message: Option<serde_json::Value>,
    pub client: PasswordLoginStartClientRequest,
}

#[derive(Debug, Deserialize)]
pub struct PasswordLoginStartClientRequest {
    pub supports_pake: bool,
    pub platform: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasswordLoginStartContractResponse {
    pub flow_id: String,
    pub flow_kind: String,
    pub protocol: String,
    pub server_message: serde_json::Value,
    pub expires_in: i64,
    pub next: NextActionResponse,
}

#[derive(Debug, Serialize)]
pub struct NextActionResponse {
    pub action: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordLoginFinishRequest {
    pub flow_id: String,
    pub client_message: serde_json::Value,
    pub device_info: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordUpgradeStartRequest {
    pub upgrade_context: String,
    #[serde(default)]
    pub client_message: Option<serde_json::Value>,
    pub client: PasswordUpgradeStartClientRequest,
}

#[derive(Debug, Deserialize)]
pub struct PasswordUpgradeStartClientRequest {
    pub supports_pake: bool,
    pub platform: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasswordUpgradeStartContractResponse {
    pub flow_id: String,
    pub flow_kind: String,
    pub protocol: String,
    pub server_message: serde_json::Value,
    pub expires_in: i64,
    pub next: NextActionResponse,
}

#[derive(Debug, Deserialize)]
pub struct PasswordUpgradeFinishRequest {
    pub flow_id: String,
    pub client_message: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct PasswordUpgradeFinishContractResponse {
    pub upgraded: bool,
    pub opaque_version: String,
    pub legacy_password: LegacyPasswordUpgradeContractResponse,
}

#[derive(Debug, Serialize)]
pub struct LegacyPasswordUpgradeContractResponse {
    pub login_allowed: bool,
    pub deprecation_window: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordLoginFinishResponse {
    pub authenticated: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub mfa_required: bool,
    pub challenge_id: Option<String>,
    pub message: Option<String>,
    pub upgrade_required: bool,
}

#[derive(Debug, Serialize)]
pub struct MfaEnrollResponse {
    pub secret: String,
    pub otpauth_url: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordForgotRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordForgotResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_flow_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasswordChangeResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub device_info: Option<String>,
    pub ip: Option<String>,
    pub status: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub is_current: bool,
}

#[derive(Debug, Serialize)]
pub struct LivenessComponents {
    pub app: ComponentState,
}

#[derive(Debug, Serialize)]
pub struct LivenessResponse {
    pub status: String,
    pub components: LivenessComponents,
}

pub async fn healthz() -> (StatusCode, Json<LivenessResponse>) {
    (
        StatusCode::OK,
        Json(LivenessResponse {
            status: "ok".to_string(),
            components: LivenessComponents {
                app: ComponentState {
                    status: "ok".to_string(),
                    detail: None,
                },
            },
        }),
    )
}

pub async fn readyz(
    State(state): State<AppState>,
) -> (StatusCode, Json<crate::health::ReadinessPayload>) {
    let report = state.readiness_checker.check().await;
    let status = if report.is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(report.payload))
}

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .register(
            RegisterCommand {
                email: payload.email,
                password: payload.password,
            },
            ctx,
        )
        .await
    {
        Ok(result) => Ok(Json(RegisterResponse {
            message: result.message,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn verify_email(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .verify_email(
            VerifyEmailCommand {
                token: payload.token,
            },
            ctx,
        )
        .await
    {
        Ok(()) => Ok(Json(VerifyEmailResponse {
            message: "Email successfully verified".to_string(),
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn password_forgot(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordForgotRequest>,
) -> Result<Json<PasswordForgotResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .password_forgot(
            PasswordForgotCommand {
                email: payload.email,
            },
            ctx,
        )
        .await
    {
        Ok(result) => Ok(Json(PasswordForgotResponse {
            message: result.message,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn password_reset(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordResetRequest>,
) -> Result<Json<PasswordResetResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .password_reset(
            PasswordResetCommand {
                token: payload.token,
                new_password: payload.new_password,
            },
            ctx,
        )
        .await
    {
        Ok(result) => Ok(Json(PasswordResetResponse {
            message: result.message,
            recovery_flow_id: result.recovery_flow_id,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn password_change(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordChangeRequest>,
) -> Result<Json<PasswordChangeResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .password_change(
            PasswordChangeCommand {
                user_id: principal.user_id,
                current_password: payload.current_password,
                new_password: payload.new_password,
            },
            ctx,
        )
        .await
    {
        Ok(result) => Ok(Json(PasswordChangeResponse {
            message: result.message,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn mfa_enroll(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<MfaEnrollResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state.auth_service.mfa_enroll(&principal.user_id, ctx).await {
        Ok(result) => Ok(Json(MfaEnrollResponse {
            secret: result.secret,
            otpauth_url: result.otpauth_url,
            algorithm: result.algorithm,
            digits: result.digits,
            period: result.period,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn mfa_activate(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<MfaActivateRequest>,
) -> Result<Json<MfaActivateResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .mfa_activate(
            MfaActivateCommand {
                user_id: principal.user_id,
                totp_code: payload.totp_code,
            },
            ctx,
        )
        .await
    {
        Ok(result) => Ok(Json(MfaActivateResponse {
            backup_codes: result.backup_codes,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn mfa_verify(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<MfaVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .mfa_verify(
            MfaVerifyCommand {
                challenge_id: payload.challenge_id,
                totp_code: payload.totp_code,
                backup_code: payload.backup_code,
            },
            ctx,
        )
        .await
    {
        Ok((tokens, _principal)) => Ok(Json(LoginResponse {
            access_token: Some(tokens.access_token),
            refresh_token: Some(tokens.refresh_token),
            token_type: Some(tokens.token_type),
            expires_in: Some(tokens.expires_in),
            mfa_required: false,
            challenge_id: None,
            message: None,
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn mfa_disable(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<MfaDisableRequest>,
) -> Result<StatusCode, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    state
        .auth_service
        .mfa_disable(
            MfaDisableCommand {
                user_id: principal.user_id,
                current_password: payload.current_password,
                totp_code: payload.totp_code,
                backup_code: payload.backup_code,
            },
            ctx,
        )
        .await
        .map_err(|err| from_auth_error(err, trace_id))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn passkey_register_start(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<PasskeyChallengeResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let result = state
        .auth_service
        .passkey_register_start(&principal.user_id, ctx)
        .await;

    let result = match result {
        Ok(result) => {
            observability::record_passkey_request("register_start", "success");
            result
        }
        Err(err) => {
            observability::record_passkey_request("register_start", "error");
            return Err(from_auth_error(err, trace_id));
        }
    };

    Ok(Json(passkey_challenge_response(result)))
}

pub async fn passkey_register_finish(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyRegisterFinishRequest>,
) -> Result<StatusCode, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let result = state
        .auth_service
        .passkey_register_finish(
            &principal.user_id,
            &payload.flow_id,
            payload.credential,
            ctx,
        )
        .await;

    match result {
        Ok(()) => observability::record_passkey_request("register_finish", "success"),
        Err(err) => {
            observability::record_passkey_request("register_finish", "error");
            return Err(from_auth_error(err, trace_id));
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn passkey_login_start(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyLoginStartRequest>,
) -> Result<Json<PasskeyChallengeResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let result = state
        .auth_service
        .passkey_login_start(&payload.email, ctx)
        .await;

    let result = match result {
        Ok(result) => {
            observability::record_passkey_request("login_start", "success");
            result
        }
        Err(err) => {
            observability::record_passkey_request("login_start", "error");
            return Err(from_auth_error(err, trace_id));
        }
    };

    Ok(Json(passkey_challenge_response(result)))
}

pub async fn passkey_login_finish(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> Result<Json<LoginResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let result = state
        .auth_service
        .passkey_login_finish(
            &payload.flow_id,
            payload.credential,
            payload.device_info,
            ctx,
        )
        .await;

    let result = match result {
        Ok(result) => {
            observability::record_passkey_request("login_finish", "success");
            result
        }
        Err(err) => {
            observability::record_passkey_request("login_finish", "error");
            return Err(from_auth_error(err, trace_id));
        }
    };

    match result {
        LoginResult::Authenticated { tokens, .. } => Ok(Json(LoginResponse {
            access_token: Some(tokens.access_token),
            refresh_token: Some(tokens.refresh_token),
            token_type: Some(tokens.token_type),
            expires_in: Some(tokens.expires_in),
            mfa_required: false,
            challenge_id: None,
            message: None,
        })),
        LoginResult::MfaRequired(challenge) => Ok(Json(LoginResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            expires_in: None,
            mfa_required: true,
            challenge_id: Some(challenge.challenge_id),
            message: Some(challenge.message),
        })),
    }
}

pub async fn auth_methods_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<AuthMethodsRequest>,
) -> Result<NoStoreJson<AuthMethodsContractResponse>, ApiProblem> {
    let started_at = Instant::now();
    let trace_id = trace_id(&headers);
    let client_id = payload
        .channel
        .clone()
        .or_else(|| payload.client.platform.clone());
    let rollout = auth_v2_rollout_for_request(&state, client_id.as_deref(), &trace_id)
        .map_err(|problem| *problem)?;
    let cohort_label = rollout.cohort_label().to_string();
    if !auth_v2_allows_external_access(&rollout) {
        let rejection_reason = auth_v2_gate_rejection_reason(&state);
        observability::record_auth_v2_methods_request(&cohort_label, rejection_reason);
        observability::observe_auth_v2_methods_duration(rejection_reason, started_at.elapsed());
        observability::record_auth_v2_methods_rejected(rejection_reason);
        return Err(from_auth_error(AuthError::AuthV2RolloutDenied, trace_id));
    }
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let response = state
        .auth_service
        .discover_auth_methods_v2(
            AuthMethodsCommand {
                identifier: payload.identifier,
                client_id,
                supports_passkeys: payload.client.supports_passkeys,
                supports_pake: payload.client.supports_pake,
            },
            ctx,
        )
        .await;

    match response {
        Ok(response) => {
            observability::record_auth_v2_methods_request(&cohort_label, "success");
            observability::observe_auth_v2_methods_duration("success", started_at.elapsed());

            Ok(NoStoreJson(auth_methods_contract_response(
                trace_id, response,
            )))
        }
        Err(err) => {
            let problem = from_auth_error(err, trace_id.clone());
            observability::record_auth_v2_methods_request(&cohort_label, "error");
            observability::observe_auth_v2_methods_duration("error", started_at.elapsed());
            observability::record_auth_v2_methods_rejected(&problem.body.type_url);
            Err(problem)
        }
    }
}

pub async fn password_login_start_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordLoginStartRequest>,
) -> Result<NoStoreJson<PasswordLoginStartContractResponse>, ApiProblem> {
    let started_at = Instant::now();
    let trace_id = trace_id(&headers);
    let cohort_label = auth_v2_metric_cohort_label(payload.client.platform.as_deref());
    if !payload.client.supports_pake {
        observability::record_auth_v2_password_request(
            "login_start",
            "invalid_request",
            &cohort_label,
        );
        observability::observe_auth_v2_password_duration(
            "login_start",
            "invalid_request",
            started_at.elapsed(),
        );
        observability::record_auth_v2_password_rejected("invalid-request");
        return Err(from_auth_error(AuthError::InvalidRequest, trace_id));
    }

    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let response = state
        .auth_service
        .start_password_login_v2(
            PakeLoginStartCommand {
                identifier: payload.identifier,
                discovery_token: payload.discovery_token,
                request: merge_pake_start_request(
                    payload.client_message,
                    serde_json::json!({
                        "supports_pake": payload.client.supports_pake,
                        "platform": payload.client.platform,
                    }),
                ),
            },
            ctx,
        )
        .await
        .map_err(|err| {
            let problem = from_auth_error(err, trace_id.clone());
            observability::record_auth_v2_password_rejected(&problem.body.type_url);
            problem
        })?;

    Ok(NoStoreJson(password_login_start_contract_response(
        response,
    )))
}

pub async fn password_login_finish_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordLoginFinishRequest>,
) -> Result<NoStoreJson<PasswordLoginFinishResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let result = state
        .auth_service
        .finish_password_login_v2(
            PakeLoginFinishCommand {
                flow_id: payload.flow_id,
                client_message: payload.client_message,
                device_info: payload.device_info,
            },
            ctx,
        )
        .await
        .map_err(|err| {
            let problem = from_auth_error(err, trace_id.clone());
            observability::record_auth_v2_password_rejected(&problem.body.type_url);
            problem
        })?;

    Ok(NoStoreJson(password_login_finish_response(result)))
}

pub async fn password_upgrade_start_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordUpgradeStartRequest>,
) -> Result<NoStoreJson<PasswordUpgradeStartContractResponse>, ApiProblem> {
    let started_at = Instant::now();
    let trace_id = trace_id(&headers);
    let cohort_label = auth_v2_metric_cohort_label(payload.client.platform.as_deref());
    if !payload.client.supports_pake {
        observability::record_auth_v2_password_request(
            "upgrade_start",
            "invalid_request",
            &cohort_label,
        );
        observability::observe_auth_v2_password_duration(
            "upgrade_start",
            "invalid_request",
            started_at.elapsed(),
        );
        observability::record_auth_v2_password_rejected("invalid-request");
        return Err(from_auth_error(AuthError::InvalidRequest, trace_id));
    }

    let (user_id, upgrade_context) = match payload.upgrade_context.as_str() {
        "session" => {
            let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
            (
                Some(principal.user_id),
                crate::modules::auth::domain::PasswordUpgradeContext::session(),
            )
        }
        "recovery_bridge" => {
            let recovery_flow_id =
                recovery_flow_id_from_client_message(payload.client_message.as_ref())
                    .ok_or_else(|| from_auth_error(AuthError::InvalidRequest, trace_id.clone()))?;
            (
                None,
                crate::modules::auth::domain::PasswordUpgradeContext::recovery_bridge(
                    recovery_flow_id,
                ),
            )
        }
        _ => return Err(from_auth_error(AuthError::InvalidRequest, trace_id)),
    };

    let client_id = payload.client.platform.clone();
    let rollout = auth_v2_rollout_for_request(&state, client_id.as_deref(), &trace_id)
        .map_err(|problem| *problem)?;
    let rollout_cohort_label = rollout.cohort_label().to_string();
    if !auth_v2_allows_external_access(&rollout) {
        let rejection_reason = auth_v2_gate_rejection_reason(&state);
        observability::record_auth_v2_password_request(
            "upgrade_start",
            rejection_reason,
            &rollout_cohort_label,
        );
        observability::observe_auth_v2_password_duration(
            "upgrade_start",
            rejection_reason,
            started_at.elapsed(),
        );
        observability::record_auth_v2_password_rejected(rejection_reason);
        return Err(from_auth_error(AuthError::AuthV2RolloutDenied, trace_id));
    }
    let mut ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );
    ctx.client_id = client_id;

    let response = state
        .auth_service
        .start_password_upgrade_v2(
            PasswordUpgradeStartCommand {
                user_id,
                context: upgrade_context,
                request: merge_pake_start_request(
                    payload.client_message,
                    serde_json::json!({
                        "upgrade_context": payload.upgrade_context,
                        "supports_pake": payload.client.supports_pake,
                        "platform": payload.client.platform,
                    }),
                ),
            },
            ctx,
        )
        .await
        .map_err(|err| {
            let problem = from_auth_error(err, trace_id.clone());
            observability::record_auth_v2_password_rejected(&problem.body.type_url);
            problem
        })?;

    Ok(NoStoreJson(password_upgrade_start_contract_response(
        response,
    )))
}

pub async fn password_upgrade_finish_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasswordUpgradeFinishRequest>,
) -> Result<NoStoreJson<PasswordUpgradeFinishContractResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let response = state
        .auth_service
        .finish_password_upgrade_v2(
            PasswordUpgradeFinishCommand {
                flow_id: payload.flow_id,
                client_message: payload.client_message,
            },
            ctx,
        )
        .await
        .map_err(|err| {
            let problem = from_auth_error(err, trace_id.clone());
            observability::record_auth_v2_password_rejected(&problem.body.type_url);
            problem
        })?;

    Ok(NoStoreJson(password_upgrade_finish_contract_response(
        response,
    )))
}

pub async fn passkey_login_start_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyLoginStartV2Request>,
) -> Result<NoStoreJson<PasskeyChallengeV2Response>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = RequestContext {
        auth_api_surface: crate::modules::auth::application::AuthApiSurface::V2,
        ..request_context(
            &headers,
            trace_id.clone(),
            state.trust_x_forwarded_for,
            &state.trusted_proxy_ips,
            &state.trusted_proxy_cidrs,
            Some(connect_addr),
        )
    };

    let result = state
        .auth_service
        .passkey_login_start_v2(&payload.identifier, &payload.discovery_token, ctx)
        .await
        .map_err(|err| {
            observability::record_passkey_request("login_start_v2", "error");
            from_auth_error(err, trace_id)
        })?;

    observability::record_passkey_request("login_start_v2", "success");

    Ok(NoStoreJson(passkey_challenge_v2_response(
        result,
        "passkey_login",
    )))
}

pub async fn passkey_login_finish_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> Result<NoStoreJson<PasswordLoginFinishResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = RequestContext {
        auth_api_surface: crate::modules::auth::application::AuthApiSurface::V2,
        ..request_context(
            &headers,
            trace_id.clone(),
            state.trust_x_forwarded_for,
            &state.trusted_proxy_ips,
            &state.trusted_proxy_cidrs,
            Some(connect_addr),
        )
    };

    let result = state
        .auth_service
        .passkey_login_finish(
            &payload.flow_id,
            payload.credential,
            payload.device_info,
            ctx,
        )
        .await
        .map_err(|err| {
            observability::record_passkey_request("login_finish_v2", "error");
            from_auth_error(err, trace_id)
        })?;

    observability::record_passkey_request("login_finish_v2", "success");

    Ok(NoStoreJson(password_login_finish_response(result)))
}

pub async fn passkey_register_start_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(_payload): Json<PasskeyRegisterStartV2Request>,
) -> Result<NoStoreJson<PasskeyChallengeV2Response>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = RequestContext {
        auth_api_surface: crate::modules::auth::application::AuthApiSurface::V2,
        ..request_context(
            &headers,
            trace_id.clone(),
            state.trust_x_forwarded_for,
            &state.trusted_proxy_ips,
            &state.trusted_proxy_cidrs,
            Some(connect_addr),
        )
    };

    let result = state
        .auth_service
        .passkey_register_start(&principal.user_id, ctx)
        .await
        .map_err(|err| {
            observability::record_passkey_request("register_start_v2", "error");
            from_auth_error(err, trace_id)
        })?;

    observability::record_passkey_request("register_start_v2", "success");

    Ok(NoStoreJson(passkey_challenge_v2_response(
        result,
        "passkey_register",
    )))
}

pub async fn passkey_register_finish_v2(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyRegisterFinishRequest>,
) -> Result<NoStoreJson<PasskeyRegisterFinishV2Response>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = RequestContext {
        auth_api_surface: crate::modules::auth::application::AuthApiSurface::V2,
        ..request_context(
            &headers,
            trace_id.clone(),
            state.trust_x_forwarded_for,
            &state.trusted_proxy_ips,
            &state.trusted_proxy_cidrs,
            Some(connect_addr),
        )
    };

    state
        .auth_service
        .passkey_register_finish(
            &principal.user_id,
            &payload.flow_id,
            payload.credential,
            ctx,
        )
        .await
        .map_err(|err| {
            observability::record_passkey_request("register_finish_v2", "error");
            from_auth_error(err, trace_id.clone())
        })?;

    observability::record_passkey_request("register_finish_v2", "success");

    let passkey_count = state
        .auth_service
        .passkey_count_for_user(&principal.user_id)
        .await
        .map_err(|err| from_auth_error(err, trace_id))?;

    Ok(NoStoreJson(PasskeyRegisterFinishV2Response {
        enrolled: true,
        passkey_count,
        recommended_login_method: "passkey".to_string(),
    }))
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    let result = state
        .auth_service
        .login(
            LoginCommand {
                email: payload.email,
                password: payload.password,
                device_info: payload.device_info,
            },
            ctx,
        )
        .await;

    match result {
        Ok(LoginResult::Authenticated { tokens, .. }) => Ok(Json(LoginResponse {
            access_token: Some(tokens.access_token),
            refresh_token: Some(tokens.refresh_token),
            token_type: Some(tokens.token_type),
            expires_in: Some(tokens.expires_in),
            mfa_required: false,
            challenge_id: None,
            message: None,
        })),
        Ok(LoginResult::MfaRequired(challenge)) => Ok(Json(LoginResponse {
            access_token: None,
            refresh_token: None,
            token_type: None,
            expires_in: None,
            mfa_required: true,
            challenge_id: Some(challenge.challenge_id),
            message: Some(challenge.message),
        })),
        Err(err) => Err(from_auth_error(err, trace_id)),
    }
}

pub async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let started_at = Instant::now();
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    match state
        .auth_service
        .refresh(
            RefreshCommand {
                refresh_token: payload.refresh_token,
            },
            ctx,
        )
        .await
    {
        Ok((tokens, _principal)) => {
            observability::record_refresh_success(started_at.elapsed());
            Ok(Json(LoginResponse {
                access_token: Some(tokens.access_token),
                refresh_token: Some(tokens.refresh_token),
                token_type: Some(tokens.token_type),
                expires_in: Some(tokens.expires_in),
                mfa_required: false,
                challenge_id: None,
                message: None,
            }))
        }
        Err(err) => {
            observability::record_refresh_error(&err, started_at.elapsed());
            Err(from_auth_error(err, trace_id))
        }
    }
}

pub async fn metrics(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiProblem> {
    let trace_id = trace_id(&headers);

    if !state.metrics_allowed_cidrs.is_empty() {
        let client_ip = resolve_client_ip(
            &headers,
            state.trust_x_forwarded_for,
            &state.trusted_proxy_ips,
            &state.trusted_proxy_cidrs,
            Some(connect_addr),
        )
        .and_then(|value| value.parse::<IpAddr>().ok());

        let Some(client_ip) = client_ip else {
            return Err(metrics_access_denied(trace_id));
        };

        if !state
            .metrics_allowed_cidrs
            .iter()
            .any(|allowed| allowed.contains(&client_ip))
        {
            return Err(metrics_access_denied(trace_id));
        }
    }

    if let Some(expected_token) = state.metrics_bearer_token.as_deref() {
        let Some(provided_token) = bearer_token_from_headers(&headers) else {
            return Err(metrics_auth_required(trace_id));
        };

        if provided_token != expected_token {
            return Err(metrics_auth_required(trace_id));
        }
    }

    match observability::render_prometheus() {
        Ok(payload) => Ok((
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            )],
            payload,
        )),
        Err(_) => Err(from_auth_error(AuthError::Internal, trace_id)),
    }
}

pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id,
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    state
        .auth_service
        .logout(
            LogoutCommand {
                session_id: principal.session_id,
                user_id: principal.user_id,
            },
            ctx,
        )
        .await;

    Ok(StatusCode::OK)
}

pub async fn logout_all(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id,
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    state.auth_service.logout_all(&principal.user_id, ctx).await;

    Ok(StatusCode::OK)
}

pub async fn sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionResponse>>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id).await?;

    let sessions = state
        .auth_service
        .list_active_sessions(&principal.user_id)
        .await;

    let response = sessions
        .into_iter()
        .map(|session| SessionResponse {
            id: session.id.clone(),
            device_info: session.device_info,
            ip: session.ip,
            status: session_status_label(&session.status).to_string(),
            created_at: session.created_at.to_rfc3339(),
            last_seen_at: session.last_seen_at.to_rfc3339(),
            is_current: session.id == principal.session_id,
        })
        .collect();

    Ok(Json(response))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<StatusCode, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id.clone()).await?;
    let ctx = request_context(
        &headers,
        trace_id.clone(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
        Some(connect_addr),
    );

    state
        .auth_service
        .revoke_session_by_id(&principal.user_id, &session_id, ctx)
        .await
        .map_err(|err| from_auth_error(err, trace_id))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, ApiProblem> {
    let trace_id = trace_id(&headers);
    let principal = extract_principal(&state, &headers, trace_id).await?;

    Ok(Json(MeResponse {
        user_id: principal.user_id,
        session_id: principal.session_id,
    }))
}

pub async fn jwks(State(state): State<AppState>) -> Json<crate::jwks::JwksDocument> {
    Json(state.jwks)
}

async fn extract_principal(
    state: &AppState,
    headers: &HeaderMap,
    trace_id: String,
) -> Result<Principal, ApiProblem> {
    let token = bearer_token_from_headers(headers).ok_or_else(|| {
        from_auth_error(
            crate::modules::auth::application::AuthError::InvalidToken,
            trace_id.clone(),
        )
    })?;

    state
        .auth_service
        .authenticate_access_token(token)
        .await
        .map_err(|err| from_auth_error(err, trace_id))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn metrics_access_denied(trace_id: String) -> ApiProblem {
    const TYPE_URL: &str = "https://example.com/problems/metrics-access-denied";
    observability::record_problem_response(StatusCode::FORBIDDEN.as_u16(), TYPE_URL);

    ApiProblem {
        status: StatusCode::FORBIDDEN,
        retry_after_seconds: None,
        body: ProblemDetails {
            type_url: TYPE_URL.to_string(),
            title: "Metrics access denied".to_string(),
            status: StatusCode::FORBIDDEN.as_u16(),
            detail: "Metrics endpoint access is denied".to_string(),
            trace_id,
        },
    }
}

fn metrics_auth_required(trace_id: String) -> ApiProblem {
    const TYPE_URL: &str = "https://example.com/problems/metrics-auth-required";
    observability::record_problem_response(StatusCode::UNAUTHORIZED.as_u16(), TYPE_URL);

    ApiProblem {
        status: StatusCode::UNAUTHORIZED,
        retry_after_seconds: None,
        body: ProblemDetails {
            type_url: TYPE_URL.to_string(),
            title: "Metrics authentication required".to_string(),
            status: StatusCode::UNAUTHORIZED.as_u16(),
            detail: "Metrics endpoint requires a valid bearer token".to_string(),
            trace_id,
        },
    }
}

fn passkey_challenge_response(challenge: PasskeyChallenge) -> PasskeyChallengeResponse {
    PasskeyChallengeResponse {
        flow_id: challenge.flow_id,
        options: challenge.options,
    }
}

fn passkey_challenge_v2_response(
    challenge: PasskeyChallenge,
    flow_kind: &str,
) -> PasskeyChallengeV2Response {
    PasskeyChallengeV2Response {
        flow_id: challenge.flow_id,
        flow_kind: flow_kind.to_string(),
        protocol: "webauthn_v1".to_string(),
        options: challenge.options,
        expires_in: challenge.expires_in,
    }
}

fn apply_no_store_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

fn auth_methods_contract_response(
    trace_id: String,
    response: AuthMethodsResponse,
) -> AuthMethodsContractResponse {
    AuthMethodsContractResponse {
        request_id: trace_id,
        discovery_token: response.discovery_token,
        discovery_expires_in: response.expires_in,
        methods: response
            .methods
            .into_iter()
            .map(auth_method_contract_response)
            .collect(),
        account_recovery: response.account_recovery.map(|recovery| {
            AccountRecoveryContractResponse {
                kind: recovery.kind,
                path: recovery.path,
            }
        }),
        recommended_method: response.recommended_method,
        legacy_password_fallback: LegacyPasswordFallbackResponse {
            possible: false,
            user_visible: false,
        },
    }
}

fn auth_method_contract_response(
    method: crate::modules::auth::application::AuthMethodResponse,
) -> AuthMethodContractResponse {
    let (version, client_mediation) = match method.kind.as_str() {
        "password_pake" => ("opaque_v1", None),
        "password_upgrade" => ("opaque_v1", None),
        "passkey" => ("webauthn_v1", Some("conditional_if_available".to_string())),
        "legacy_password" => ("legacy_v1", None),
        _ => ("unknown", None),
    };

    AuthMethodContractResponse {
        kind: method.kind,
        version: version.to_string(),
        action: "start".to_string(),
        path: method.path,
        client_mediation,
    }
}

fn password_login_start_contract_response(
    response: PakeLoginStartResponse,
) -> PasswordLoginStartContractResponse {
    PasswordLoginStartContractResponse {
        flow_id: response.flow_id,
        flow_kind: "password_login".to_string(),
        protocol: response.protocol,
        server_message: response.server_message,
        expires_in: response.expires_in,
        next: NextActionResponse {
            action: "finish".to_string(),
            path: "/v2/auth/password/login/finish".to_string(),
        },
    }
}

fn merge_pake_start_request(
    client_message: Option<serde_json::Value>,
    fallback: serde_json::Value,
) -> serde_json::Value {
    match (client_message, fallback) {
        (Some(serde_json::Value::Object(mut client)), serde_json::Value::Object(fallback)) => {
            client.extend(fallback);
            serde_json::Value::Object(client)
        }
        (Some(client_message), _) => client_message,
        (None, fallback) => fallback,
    }
}

fn recovery_flow_id_from_client_message(
    client_message: Option<&serde_json::Value>,
) -> Option<&str> {
    client_message
        .and_then(|value| value.get("recovery_flow_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn password_upgrade_start_contract_response(
    response: PasswordUpgradeStartResponse,
) -> PasswordUpgradeStartContractResponse {
    PasswordUpgradeStartContractResponse {
        flow_id: response.flow_id,
        flow_kind: "password_upgrade".to_string(),
        protocol: response.protocol,
        server_message: response.server_message,
        expires_in: response.expires_in,
        next: NextActionResponse {
            action: "finish".to_string(),
            path: "/v2/auth/password/upgrade/finish".to_string(),
        },
    }
}

fn password_login_finish_response(result: LoginResult) -> PasswordLoginFinishResponse {
    match result {
        LoginResult::Authenticated { tokens, .. } => PasswordLoginFinishResponse {
            authenticated: true,
            access_token: Some(tokens.access_token),
            refresh_token: Some(tokens.refresh_token),
            token_type: Some(tokens.token_type),
            expires_in: Some(tokens.expires_in),
            mfa_required: false,
            challenge_id: None,
            message: None,
            upgrade_required: false,
        },
        LoginResult::MfaRequired(challenge) => PasswordLoginFinishResponse {
            authenticated: false,
            access_token: None,
            refresh_token: None,
            token_type: None,
            expires_in: None,
            mfa_required: true,
            challenge_id: Some(challenge.challenge_id),
            message: Some(challenge.message),
            upgrade_required: false,
        },
    }
}

fn password_upgrade_finish_contract_response(
    response: PasswordUpgradeFinishResponse,
) -> PasswordUpgradeFinishContractResponse {
    PasswordUpgradeFinishContractResponse {
        upgraded: response.upgraded,
        opaque_version: response.opaque_version,
        legacy_password: LegacyPasswordUpgradeContractResponse {
            login_allowed: response.legacy_password.login_allowed,
            deprecation_window: response.legacy_password.deprecation_window,
        },
    }
}

fn session_status_label(status: &crate::modules::sessions::domain::SessionStatus) -> &'static str {
    match status {
        crate::modules::sessions::domain::SessionStatus::Active => "active",
        crate::modules::sessions::domain::SessionStatus::Revoked => "revoked",
        crate::modules::sessions::domain::SessionStatus::Compromised => "compromised",
    }
}

fn trace_id(headers: &HeaderMap) -> String {
    headers
        .get("x-trace-id")
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn request_context(
    headers: &HeaderMap,
    trace_id: String,
    trust_x_forwarded_for: bool,
    trusted_proxy_ips: &[IpAddr],
    trusted_proxy_cidrs: &[IpNet],
    socket_addr: Option<SocketAddr>,
) -> RequestContext {
    let ip = resolve_client_ip(
        headers,
        trust_x_forwarded_for,
        trusted_proxy_ips,
        trusted_proxy_cidrs,
        socket_addr,
    );

    RequestContext {
        trace_id,
        ip,
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string()),
        client_id: None,
        auth_api_surface: crate::modules::auth::application::AuthApiSurface::V1,
    }
}

fn auth_v2_rollout_for_request(
    state: &AppState,
    client_id: Option<&str>,
    trace_id: &str,
) -> Result<AuthV2RolloutDecision, Box<ApiProblem>> {
    let Some(config) = state.auth_service.auth_v2_config() else {
        return Err(Box::new(from_auth_error(
            AuthError::Internal,
            trace_id.to_string(),
        )));
    };

    Ok(evaluate_auth_v2_rollout(&config, client_id, None))
}

fn auth_v2_gate_rejection_reason(state: &AppState) -> &'static str {
    state
        .auth_service
        .auth_v2_config()
        .filter(|config| config.shadow_audit_only)
        .map(|_| "shadow_hidden")
        .unwrap_or("rollout_denied")
}

fn auth_v2_metric_cohort_label(client_id: Option<&str>) -> String {
    client_id
        .and_then(|value| resolve_auth_v2_cohort(value).ok())
        .map(|cohort| cohort.as_str().to_string())
        .or_else(|| crate::config::AuthV2Config::normalized_client_id(client_id))
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_x_forwarded_for(value: &str) -> Option<String> {
    let ip = value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .and_then(|ip| ip.parse::<IpAddr>().ok())?;

    Some(ip.to_string())
}

fn resolve_client_ip(
    headers: &HeaderMap,
    trust_x_forwarded_for: bool,
    trusted_proxy_ips: &[IpAddr],
    trusted_proxy_cidrs: &[IpNet],
    socket_addr: Option<SocketAddr>,
) -> Option<String> {
    let socket_ip = socket_addr.map(|addr| addr.ip());

    if !trust_x_forwarded_for {
        return socket_ip.map(|ip| ip.to_string());
    }

    let proxy_ip = socket_ip?;

    if !is_trusted_proxy(proxy_ip, trusted_proxy_ips, trusted_proxy_cidrs) {
        return Some(proxy_ip.to_string());
    }

    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_x_forwarded_for)
        .or_else(|| Some(proxy_ip.to_string()))
}

fn is_trusted_proxy(
    proxy_ip: IpAddr,
    trusted_proxy_ips: &[IpAddr],
    trusted_proxy_cidrs: &[IpNet],
) -> bool {
    trusted_proxy_ips.contains(&proxy_ip)
        || trusted_proxy_cidrs
            .iter()
            .any(|trusted_proxy_cidr| trusted_proxy_cidr.contains(&proxy_ip))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::{
        body::to_bytes,
        extract::{ConnectInfo, State},
        http::{header, HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
        Json,
    };
    use base32::Alphabet;
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use rand::{rngs::OsRng, RngCore};
    use sha1::Sha1;
    use uuid::Uuid;
    use webauthn_rs::prelude::{
        AuthenticationResult, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
        PublicKeyCredential, RegisterPublicKeyCredential, Webauthn,
    };

    use crate::{
        adapters::{
            inmemory::{InMemoryAdapters, JwtEdDsaService, RefreshCryptoHmacService},
            postgres::PostgresAdapters,
        },
        config::{
            AppConfig, AuthRuntime, JwtKeyConfig, LoginAbuseBucketMode, LoginAbuseRedisFailMode,
        },
        modules::{
            auth::{
                application::{
                    AuthError, AuthService, LoginCommand, LoginResult, MfaActivateCommand,
                    RequestContext,
                },
                ports::{
                    AuthFlowRepository, PasskeyCredentialRepository, PasskeyService, UserRepository,
                },
            },
            tokens::{domain::AccessTokenClaims, ports::JwtService},
        },
        AppState,
    };

    use super::{
        AuthMethodsRequest, LoginRequest, MfaVerifyRequest, PasskeyLoginFinishRequest,
        PasskeyRegisterFinishRequest, PasswordLoginFinishRequest, PasswordLoginStartRequest,
        RefreshRequest,
    };

    type HmacSha1 = Hmac<Sha1>;

    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIMn3Wcxxd4JzzjbshVFXz8jSGuF9ErqngPTzYhbfm6hd\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdIROjbNDN9NHACJMCdMbdRjmUZp05u0E+QVRzrqB6eM=\n-----END PUBLIC KEY-----\n";
    const TEST_PRIVATE_KEY_PEM_V2: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHKXEA5E1r7pR80Ucu171MabNn+ku13GSavWIB/BKqmv\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM_V2: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA3Pt04RjQQMO4XZTq01rN87smwi6wkOTzBX7P5z6DI/M=\n-----END PUBLIC KEY-----\n";

    struct HandlerHarness {
        state: AppState,
        auth_flows: Arc<StaticAuthFlowRepository>,
        passkeys: Arc<dyn PasskeyCredentialRepository>,
        bootstrap_email: String,
        bootstrap_password: String,
    }

    #[derive(Clone)]
    struct SuccessfulFinishPasskeyService {
        inner: Webauthn,
    }

    impl SuccessfulFinishPasskeyService {
        fn new(inner: Webauthn) -> Self {
            Self { inner }
        }
    }

    impl PasskeyService for SuccessfulFinishPasskeyService {
        fn start_registration(
            &self,
            user_unique_id: Uuid,
            user_name: &str,
            user_display_name: &str,
            exclude_credentials: Option<Vec<CredentialID>>,
        ) -> Result<
            (
                webauthn_rs::prelude::CreationChallengeResponse,
                PasskeyRegistration,
            ),
            String,
        > {
            self.inner
                .start_passkey_registration(
                    user_unique_id,
                    user_name,
                    user_display_name,
                    exclude_credentials,
                )
                .map_err(|err| err.to_string())
        }

        fn finish_registration(
            &self,
            credential: &RegisterPublicKeyCredential,
            state: &PasskeyRegistration,
        ) -> Result<Passkey, String> {
            if credential.id == "success-register-credential" {
                return Ok(dummy_passkey());
            }

            self.inner
                .finish_passkey_registration(credential, state)
                .map_err(|err| err.to_string())
        }

        fn start_authentication(
            &self,
            passkeys: &[Passkey],
        ) -> Result<
            (
                webauthn_rs::prelude::RequestChallengeResponse,
                PasskeyAuthentication,
            ),
            String,
        > {
            self.inner
                .start_passkey_authentication(passkeys)
                .map_err(|err| err.to_string())
        }

        fn finish_authentication(
            &self,
            credential: &PublicKeyCredential,
            state: &PasskeyAuthentication,
        ) -> Result<AuthenticationResult, String> {
            if credential.id == "success-login-credential" {
                return serde_json::from_value(serde_json::json!({
                    "cred_id": "AQID",
                    "needs_update": false,
                    "user_verified": true,
                    "backup_state": false,
                    "backup_eligible": false,
                    "counter": 0,
                    "extensions": {}
                }))
                .map_err(|err| err.to_string());
            }

            self.inner
                .finish_passkey_authentication(credential, state)
                .map_err(|err| err.to_string())
        }
    }

    struct FailingReadinessChecker;

    #[async_trait]
    impl crate::health::ReadinessChecker for FailingReadinessChecker {
        async fn check(&self) -> crate::health::ReadinessReport {
            crate::health::ReadinessReport {
                is_ready: false,
                payload: crate::health::ReadinessPayload {
                    status: "error".to_string(),
                    runtime: "postgres_redis".to_string(),
                    components: crate::health::ReadinessComponents {
                        app: crate::health::ComponentState {
                            status: "ok".to_string(),
                            detail: None,
                        },
                        database: crate::health::ComponentState {
                            status: "error".to_string(),
                            detail: Some("db ping failed: connection refused".to_string()),
                        },
                        redis: crate::health::ComponentState {
                            status: "ok".to_string(),
                            detail: None,
                        },
                        passkey_challenge_janitor: crate::health::ComponentState {
                            status: "not_configured".to_string(),
                            detail: None,
                        },
                        auth_flow_janitor: crate::health::ComponentState {
                            status: "not_configured".to_string(),
                            detail: None,
                        },
                    },
                },
            }
        }
    }

    #[tokio::test]
    async fn healthz_handler_always_returns_ok() {
        let (status, body) = super::healthz().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0.status, "ok");
        assert_eq!(body.0.components.app.status, "ok");
    }

    #[tokio::test]
    async fn readyz_handler_returns_ok_for_inmemory_runtime() {
        let harness = build_harness();
        let (status, body) = super::readyz(State(harness.state.clone())).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0.status, "ok");
        assert_eq!(body.0.runtime, "inmemory");
        assert_eq!(body.0.components.app.status, "ok");
        assert_eq!(body.0.components.database.status, "not_configured");
        assert_eq!(body.0.components.redis.status, "not_configured");
        assert_eq!(
            body.0.components.passkey_challenge_janitor.status,
            "not_configured"
        );
        assert_eq!(body.0.components.auth_flow_janitor.status, "not_configured");
    }

    #[tokio::test]
    async fn readyz_handler_returns_service_unavailable_on_dependency_failure() {
        let mut harness = build_harness();
        harness.state.readiness_checker = Arc::new(FailingReadinessChecker);

        let (status, body) = super::readyz(State(harness.state.clone())).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0.status, "error");
        assert_eq!(body.0.components.database.status, "error");
        assert!(body.0.components.database.detail.is_some());
    }

    #[tokio::test]
    async fn login_handler_returns_mfa_challenge_payload_when_mfa_enabled() {
        let harness = build_harness();
        enable_mfa(&harness).await;

        let response = match super::login(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-login-mfa-required"),
            Json(LoginRequest {
                email: harness.bootstrap_email.clone(),
                password: harness.bootstrap_password.clone(),
                device_info: Some("handler-device".to_string()),
            }),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => panic!("login handler should return mfa challenge payload"),
        };

        let body = response.0;
        assert!(body.mfa_required);
        assert!(body.challenge_id.is_some());
        assert!(body.access_token.is_none());
        assert!(body.refresh_token.is_none());
        assert!(body.expires_in.is_none());
    }

    #[tokio::test]
    async fn mfa_verify_handler_returns_problem_contract_for_invalid_code_and_exhausted_challenge()
    {
        let harness = build_harness();
        enable_mfa(&harness).await;

        let login_result = match super::login(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-login-for-mfa-verify"),
            Json(LoginRequest {
                email: harness.bootstrap_email.clone(),
                password: harness.bootstrap_password.clone(),
                device_info: Some("handler-verify-device".to_string()),
            }),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => panic!("login handler should succeed"),
        };
        let challenge_id = login_result
            .0
            .challenge_id
            .expect("challenge id should be present when mfa is required");

        let max_attempts = test_config().mfa_challenge_max_attempts;
        for _ in 0..max_attempts {
            let invalid_code = super::mfa_verify(
                State(harness.state.clone()),
                connect_info(),
                headers_with_trace("handler-mfa-verify-invalid-code"),
                Json(MfaVerifyRequest {
                    challenge_id: challenge_id.clone(),
                    totp_code: Some("000000".to_string()),
                    backup_code: None,
                }),
            )
            .await
            .expect_err("invalid code should be rejected");

            assert_eq!(invalid_code.status, StatusCode::UNAUTHORIZED);
            assert_eq!(
                invalid_code.body.type_url,
                "https://example.com/problems/invalid-mfa-code"
            );

            let invalid_code_response = invalid_code.into_response();
            assert_eq!(
                invalid_code_response.headers().get(header::CONTENT_TYPE),
                Some(&HeaderValue::from_static("application/problem+json"))
            );
        }

        let exhausted_challenge = super::mfa_verify(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-mfa-verify-challenge-exhausted"),
            Json(MfaVerifyRequest {
                challenge_id,
                totp_code: Some("000000".to_string()),
                backup_code: None,
            }),
        )
        .await
        .expect_err("challenge should be invalid after max failed attempts");

        assert_eq!(exhausted_challenge.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            exhausted_challenge.body.type_url,
            "https://example.com/problems/invalid-mfa-challenge"
        );
    }

    #[tokio::test]
    async fn refresh_handler_rotates_token_and_replay_returns_reuse_problem_contract() {
        let harness = build_harness();

        let login = login_success(&harness, "handler-refresh-login").await;
        let original_refresh = login
            .refresh_token
            .expect("login should return refresh token");

        let rotated = match super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-refresh-rotate"),
            Json(RefreshRequest {
                refresh_token: original_refresh.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("refresh handler should rotate token"),
        };

        assert!(!rotated.mfa_required);
        assert!(rotated.access_token.is_some());
        assert!(rotated.refresh_token.is_some());
        assert_eq!(rotated.token_type.as_deref(), Some("Bearer"));

        let replay = super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-refresh-replay"),
            Json(RefreshRequest {
                refresh_token: original_refresh,
            }),
        )
        .await
        .expect_err("replaying refresh token should be rejected");

        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay.body.type_url,
            "https://example.com/problems/refresh-reuse"
        );

        let replay_response = replay.into_response();
        assert_eq!(
            replay_response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/problem+json"))
        );

        let rotated_access = rotated
            .access_token
            .expect("rotated response should include access token");
        let access_after_replay = harness
            .state
            .auth_service
            .authenticate_access_token(&rotated_access)
            .await;
        assert!(matches!(access_after_replay, Err(AuthError::InvalidToken)));
    }

    #[tokio::test]
    async fn logout_handler_revokes_session_and_invalidates_access_token() {
        let harness = build_harness();
        let login = login_success(&harness, "handler-logout-login").await;
        let access_token = login
            .access_token
            .expect("login should return access token");

        let status = match super::logout(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-logout", &access_token),
        )
        .await
        {
            Ok(status) => status,
            Err(_) => panic!("logout handler should succeed with valid bearer token"),
        };

        assert_eq!(status, StatusCode::OK);

        let access_after_logout = harness
            .state
            .auth_service
            .authenticate_access_token(&access_token)
            .await;
        assert!(matches!(access_after_logout, Err(AuthError::InvalidToken)));
    }

    #[tokio::test]
    async fn logout_all_handler_revokes_all_active_sessions_for_user() {
        let harness = build_harness();

        let first_login = login_success(&harness, "handler-logout-all-login-1").await;
        let second_login = login_success(&harness, "handler-logout-all-login-2").await;
        let first_access = first_login
            .access_token
            .expect("first login should return access token");
        let second_access = second_login
            .access_token
            .expect("second login should return access token");

        let status = match super::logout_all(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-logout-all", &first_access),
        )
        .await
        {
            Ok(status) => status,
            Err(_) => panic!("logout-all handler should succeed with valid bearer token"),
        };

        assert_eq!(status, StatusCode::OK);

        let first_after = harness
            .state
            .auth_service
            .authenticate_access_token(&first_access)
            .await;
        assert!(matches!(first_after, Err(AuthError::InvalidToken)));

        let second_after = harness
            .state
            .auth_service
            .authenticate_access_token(&second_access)
            .await;
        assert!(matches!(second_after, Err(AuthError::InvalidToken)));
    }

    #[tokio::test]
    async fn logout_handler_rejects_missing_bearer_token_with_problem_contract() {
        let harness = build_harness();

        let rejected = super::logout(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-logout-missing-bearer"),
        )
        .await
        .expect_err("logout should reject requests without bearer token");

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-token"
        );
    }

    #[tokio::test]
    async fn metrics_handler_exposes_prometheus_payload() {
        let harness = build_harness();
        crate::observability::record_refresh_success(std::time::Duration::from_millis(1));
        crate::observability::record_refresh_error(
            &AuthError::InvalidToken,
            std::time::Duration::from_millis(1),
        );

        let body = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-metrics-open"),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(_) => panic!("metrics handler should return payload when no token is configured"),
        };
        assert_eq!(body.status(), StatusCode::OK);
        assert_eq!(
            body.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static(
                "text/plain; version=0.0.4; charset=utf-8"
            ))
        );

        let bytes = to_bytes(body.into_body(), 1024 * 1024)
            .await
            .expect("metrics response body should be readable");
        let payload =
            String::from_utf8(bytes.to_vec()).expect("metrics response should be valid utf-8 text");

        assert!(payload.contains("auth_refresh_requests_total"));
        assert!(payload.contains("auth_refresh_rejected_total"));
        assert!(payload.contains("auth_refresh_duration_seconds"));
    }

    #[tokio::test]
    async fn passkey_login_finish_handler_invalid_challenge_returns_problem_and_metrics() {
        let harness = build_passkey_harness();

        let rejected = super::passkey_login_finish(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-passkey-login-finish-invalid-challenge"),
            Json(PasskeyLoginFinishRequest {
                flow_id: "missing-passkey-flow".to_string(),
                credential: dummy_passkey_login_credential(),
                device_info: Some("handler-passkey-device".to_string()),
            }),
        )
        .await
        .expect_err("passkey login finish should reject invalid challenge");

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-passkey-challenge"
        );
        assert_eq!(
            rejected.body.trace_id,
            "handler-passkey-login-finish-invalid-challenge"
        );

        let metrics_response = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-passkey-login-finish-metrics"),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(_) => panic!("metrics handler should expose runtime metrics"),
        };

        let metrics_bytes = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_bytes.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_passkey_requests_total"));
        assert!(metrics_payload.contains("operation=\"login_finish\",outcome=\"error\""));
        assert!(metrics_payload.contains("auth_passkey_login_rejected_total"));
        assert!(metrics_payload.contains("reason=\"invalid_or_expired_challenge\""));
    }

    #[tokio::test]
    async fn passkey_register_finish_handler_invalid_challenge_returns_problem_and_metrics() {
        let harness = build_passkey_harness();
        let login = login_success(
            &harness,
            "handler-passkey-register-finish-invalid-challenge-login",
        )
        .await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let rejected = super::passkey_register_finish(
            State(harness.state.clone()),
            connect_info(),
            auth_headers(
                "handler-passkey-register-finish-invalid-challenge",
                &access_token,
            ),
            Json(PasskeyRegisterFinishRequest {
                flow_id: "missing-passkey-register-flow".to_string(),
                credential: dummy_passkey_register_credential(),
            }),
        )
        .await
        .expect_err("passkey register finish should reject invalid challenge");

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-passkey-challenge"
        );

        let metrics_response = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-passkey-register-finish-metrics"),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(_) => panic!("metrics handler should expose runtime metrics"),
        };

        let metrics_bytes = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_bytes.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_passkey_requests_total"));
        assert!(metrics_payload.contains("operation=\"register_finish\",outcome=\"error\""));
        assert!(metrics_payload.contains("auth_passkey_register_rejected_total"));
        assert!(metrics_payload.contains("reason=\"invalid_or_expired_challenge\""));
    }

    #[tokio::test]
    async fn passkey_register_finish_handler_invalid_response_returns_problem_and_metrics() {
        let harness = build_passkey_harness();
        let login = login_success(
            &harness,
            "handler-passkey-register-finish-invalid-response-login",
        )
        .await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let start_response = match super::passkey_register_start(
            State(harness.state.clone()),
            connect_info(),
            auth_headers(
                "handler-passkey-register-start-for-invalid-response",
                &access_token,
            ),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("passkey register start should issue challenge"),
        };

        let rejected = super::passkey_register_finish(
            State(harness.state.clone()),
            connect_info(),
            auth_headers(
                "handler-passkey-register-finish-invalid-response",
                &access_token,
            ),
            Json(PasskeyRegisterFinishRequest {
                flow_id: start_response.flow_id,
                credential: dummy_passkey_register_credential(),
            }),
        )
        .await
        .expect_err("passkey register finish should reject invalid passkey response");

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-passkey-response"
        );

        let metrics_response = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-passkey-register-finish-invalid-response-metrics"),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err(_) => panic!("metrics handler should expose runtime metrics"),
        };

        let metrics_bytes = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_bytes.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_passkey_requests_total"));
        assert!(metrics_payload.contains("operation=\"register_finish\",outcome=\"error\""));
        assert!(metrics_payload.contains("auth_passkey_register_rejected_total"));
        assert!(metrics_payload.contains("reason=\"invalid_passkey_response\""));
    }

    #[tokio::test]
    async fn passkey_login_start_handler_rejects_when_passkey_is_disabled() {
        let harness = build_harness();

        let rejected = super::passkey_login_start(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-passkey-login-start-disabled"),
            Json(super::PasskeyLoginStartRequest {
                email: harness.bootstrap_email.clone(),
            }),
        )
        .await
        .expect_err("passkey login start should reject when passkey is disabled");

        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/passkey-disabled"
        );
    }

    #[tokio::test]
    async fn passkey_register_start_handler_rejects_when_passkey_is_disabled() {
        let harness = build_harness();
        let login = login_success(&harness, "handler-passkey-register-start-disabled-login").await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let rejected = super::passkey_register_start(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-passkey-register-start-disabled", &access_token),
        )
        .await
        .expect_err("passkey register start should reject when passkey is disabled");

        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/passkey-disabled"
        );
    }

    #[tokio::test]
    async fn passkey_login_finish_handler_rejects_when_passkey_is_disabled() {
        let harness = build_harness();

        let rejected = super::passkey_login_finish(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-passkey-login-finish-disabled"),
            Json(PasskeyLoginFinishRequest {
                flow_id: "disabled-passkey-flow".to_string(),
                credential: dummy_passkey_login_credential(),
                device_info: Some("handler-passkey-device".to_string()),
            }),
        )
        .await
        .expect_err("passkey login finish should reject when passkey is disabled");

        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/passkey-disabled"
        );
    }

    #[tokio::test]
    async fn passkey_register_finish_handler_rejects_when_passkey_is_disabled() {
        let harness = build_harness();
        let login = login_success(&harness, "handler-passkey-register-finish-disabled-login").await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let rejected = super::passkey_register_finish(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-passkey-register-finish-disabled", &access_token),
            Json(PasskeyRegisterFinishRequest {
                flow_id: "disabled-register-flow".to_string(),
                credential: dummy_passkey_register_credential(),
            }),
        )
        .await
        .expect_err("passkey register finish should reject when passkey is disabled");

        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/passkey-disabled"
        );
    }

    #[tokio::test]
    async fn jwks_handler_exposes_ed25519_key_material() {
        let harness = build_harness();

        let response = super::jwks(State(harness.state.clone())).await.0;
        assert_eq!(response.keys.len(), 1);
        let key = &response.keys[0];

        assert_eq!(key.kty, "OKP");
        assert_eq!(key.crv, "Ed25519");
        assert_eq!(key.alg, "EdDSA");
        assert_eq!(key.key_use, "sig");
        assert_eq!(key.kid, "handler-tests-ed25519-v1");
        assert!(!key.x.is_empty());
    }

    #[tokio::test]
    async fn jwks_handler_exposes_multiple_active_keys() {
        let mut harness = build_harness();
        harness.state.jwks = crate::jwks::JwksDocument::from_ed25519_public_keys(&[
            crate::jwks::JwksPublicKeyInput {
                kid: "handler-tests-ed25519-v1",
                public_key_pem: TEST_PUBLIC_KEY_PEM,
            },
            crate::jwks::JwksPublicKeyInput {
                kid: "handler-tests-ed25519-v2",
                public_key_pem: TEST_PUBLIC_KEY_PEM_V2,
            },
        ])
        .expect("jwks with multiple keys should build");

        let response = super::jwks(State(harness.state.clone())).await.0;
        assert_eq!(response.keys.len(), 2);
        assert_eq!(response.keys[0].kid, "handler-tests-ed25519-v1");
        assert_eq!(response.keys[1].kid, "handler-tests-ed25519-v2");
    }

    #[tokio::test]
    async fn jwt_rotation_overlap_keeps_old_tokens_valid_and_exposes_both_jwks_kids() {
        let old_key_id = "handler-tests-ed25519-v1";
        let new_key_id = "handler-tests-ed25519-v2";
        let overlap_harness = build_harness_with_jwt_keys(
            vec![
                jwt_key_config(
                    new_key_id,
                    Some(TEST_PRIVATE_KEY_PEM_V2),
                    TEST_PUBLIC_KEY_PEM_V2,
                ),
                jwt_key_config(old_key_id, None, TEST_PUBLIC_KEY_PEM),
            ],
            new_key_id,
        );

        let overlap_login = match super::login(
            State(overlap_harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-rotation-overlap-login"),
            Json(LoginRequest {
                email: overlap_harness.bootstrap_email.clone(),
                password: overlap_harness.bootstrap_password.clone(),
                device_info: Some("handler-rotation-overlap-device".to_string()),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("login should succeed during overlap setup"),
        };
        let overlap_access_token = overlap_login
            .access_token
            .expect("login should issue access token");

        let principal = overlap_harness
            .state
            .auth_service
            .authenticate_access_token(&overlap_access_token)
            .await
            .expect("token from overlap login should authenticate");

        let now = Utc::now();
        let old_signer = JwtEdDsaService::new(
            vec![jwt_key_config(
                old_key_id,
                Some(TEST_PRIVATE_KEY_PEM),
                TEST_PUBLIC_KEY_PEM,
            )],
            old_key_id.to_string(),
            "handler-tests".to_string(),
            "handler-tests-clients".to_string(),
        )
        .expect("old key signer should initialize");
        let old_access_token = old_signer
            .issue_access_token(&AccessTokenClaims {
                sub: principal.user_id,
                sid: principal.session_id,
                iss: "handler-tests".to_string(),
                aud: "handler-tests-clients".to_string(),
                iat: now.timestamp(),
                exp: (now + chrono::Duration::minutes(5)).timestamp(),
            })
            .await
            .expect("old access token should be issued");

        let jwks = super::jwks(State(overlap_harness.state.clone())).await.0;
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, new_key_id);
        assert_eq!(jwks.keys[1].kid, old_key_id);
        let jwks_payload = serde_json::to_value(&jwks).expect("jwks payload should serialize");
        let keys = jwks_payload
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .expect("jwks payload should expose keys array");
        assert!(
            keys.iter().all(|key| {
                key.get("kid").is_some()
                    && key.get("kty") == Some(&serde_json::Value::String("OKP".to_string()))
                    && key.get("alg") == Some(&serde_json::Value::String("EdDSA".to_string()))
                    && key.get("x").and_then(serde_json::Value::as_str).is_some()
            }),
            "jwks keys should expose expected payload fields"
        );

        let me = super::me(
            State(overlap_harness.state.clone()),
            auth_headers("handler-rotation-overlap-me-old-token", &old_access_token),
        )
        .await;
        assert!(me.is_ok());
    }

    #[tokio::test]
    async fn jwt_rotation_retirement_rejects_old_tokens_and_hides_old_jwks_kid() {
        let old_key_id = "handler-tests-ed25519-v1";
        let new_key_id = "handler-tests-ed25519-v2";
        let retired_harness = build_harness_with_jwt_keys(
            vec![jwt_key_config(
                new_key_id,
                Some(TEST_PRIVATE_KEY_PEM_V2),
                TEST_PUBLIC_KEY_PEM_V2,
            )],
            new_key_id,
        );

        let retired_login = match super::login(
            State(retired_harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-rotation-retirement-login"),
            Json(LoginRequest {
                email: retired_harness.bootstrap_email.clone(),
                password: retired_harness.bootstrap_password.clone(),
                device_info: Some("handler-rotation-retirement-device".to_string()),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("login should succeed during retirement setup"),
        };
        let retired_access_token = retired_login
            .access_token
            .expect("login should issue access token");

        let principal = retired_harness
            .state
            .auth_service
            .authenticate_access_token(&retired_access_token)
            .await
            .expect("token from retirement login should authenticate");

        let now = Utc::now();
        let old_signer = JwtEdDsaService::new(
            vec![jwt_key_config(
                old_key_id,
                Some(TEST_PRIVATE_KEY_PEM),
                TEST_PUBLIC_KEY_PEM,
            )],
            old_key_id.to_string(),
            "handler-tests".to_string(),
            "handler-tests-clients".to_string(),
        )
        .expect("old key signer should initialize");
        let old_access_token = old_signer
            .issue_access_token(&AccessTokenClaims {
                sub: principal.user_id,
                sid: principal.session_id,
                iss: "handler-tests".to_string(),
                aud: "handler-tests-clients".to_string(),
                iat: now.timestamp(),
                exp: (now + chrono::Duration::minutes(5)).timestamp(),
            })
            .await
            .expect("old access token should be issued");

        let jwks = super::jwks(State(retired_harness.state.clone())).await.0;
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, new_key_id);
        let jwks_payload = serde_json::to_value(&jwks).expect("jwks payload should serialize");
        let keys = jwks_payload
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .expect("jwks payload should expose keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].get("kid"),
            Some(&serde_json::Value::String(new_key_id.to_string()))
        );

        let rejected = super::me(
            State(retired_harness.state.clone()),
            auth_headers(
                "handler-rotation-retirement-me-old-token",
                &old_access_token,
            ),
        )
        .await
        .expect_err("old token should fail once old key is retired");
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-token"
        );
    }

    #[tokio::test]
    async fn metrics_handler_rejects_missing_bearer_when_token_is_configured() {
        let harness = build_harness_with_metrics_token(Some("metrics-secret-token"));

        let rejected = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-metrics-protected-missing"),
        )
        .await
        {
            Ok(_) => panic!("metrics should reject missing token when protected"),
            Err(problem) => problem,
        };

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/metrics-auth-required"
        );
    }

    #[tokio::test]
    async fn metrics_handler_rejects_wrong_bearer_when_token_is_configured() {
        let harness = build_harness_with_metrics_token(Some("metrics-secret-token"));

        let rejected = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-metrics-protected-wrong", "wrong-token"),
        )
        .await
        {
            Ok(_) => panic!("metrics should reject wrong token when protected"),
            Err(problem) => problem,
        };

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/metrics-auth-required"
        );
    }

    #[tokio::test]
    async fn metrics_handler_accepts_valid_bearer_when_token_is_configured() {
        let harness = build_harness_with_metrics_token(Some("metrics-secret-token"));

        let response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-metrics-protected-valid", "metrics-secret-token"),
        )
        .await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn metrics_handler_rejects_source_ip_outside_allowed_cidrs() {
        let harness = build_harness_with_metrics_policy(None, vec!["10.0.0.0/8"]);

        let rejected = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-metrics-cidr-reject"),
        )
        .await
        {
            Ok(_) => panic!("metrics should reject source IP outside allowed cidrs"),
            Err(problem) => problem,
        };

        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/metrics-access-denied"
        );
    }

    #[tokio::test]
    async fn metrics_handler_accepts_source_ip_inside_allowed_cidrs() {
        let harness = build_harness_with_metrics_policy(None, vec!["127.0.0.0/8"]);

        let response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-metrics-cidr-accept"),
        )
        .await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn metrics_handler_accepts_xff_from_trusted_proxy_when_cidr_matches() {
        let mut harness = build_harness_with_metrics_policy(None, vec!["10.20.0.0/16"]);
        harness.state.trust_x_forwarded_for = true;
        harness.state.trusted_proxy_ips =
            vec!["127.0.0.1".parse().expect("trusted proxy ip should parse")];

        let response = super::metrics(
            State(harness.state.clone()),
            connect_info_for([127, 0, 0, 1], 41000),
            headers_with_trace_and_xff(
                "handler-metrics-xff-trusted-allow",
                "10.20.12.50, 198.51.100.77",
            ),
        )
        .await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn metrics_handler_rejects_xff_from_untrusted_proxy() {
        let mut harness = build_harness_with_metrics_policy(None, vec!["10.20.0.0/16"]);
        harness.state.trust_x_forwarded_for = true;

        let rejected = match super::metrics(
            State(harness.state.clone()),
            connect_info_for([127, 0, 0, 1], 41000),
            headers_with_trace_and_xff(
                "handler-metrics-xff-untrusted-reject",
                "10.20.12.50, 198.51.100.77",
            ),
        )
        .await
        {
            Ok(_) => panic!("metrics should reject xff from untrusted proxy"),
            Err(problem) => problem,
        };

        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/metrics-access-denied"
        );
    }

    #[tokio::test]
    async fn end_to_end_auth_flow_smoke_with_metrics_protection() {
        let harness =
            build_harness_with_metrics_policy(Some("metrics-secret-token"), vec!["127.0.0.0/8"]);

        let login = match super::login(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-login"),
            Json(LoginRequest {
                email: harness.bootstrap_email.clone(),
                password: harness.bootstrap_password.clone(),
                device_info: Some("handler-full-flow-device".to_string()),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("login should succeed in full flow"),
        };

        assert!(!login.mfa_required);
        let access_token = login
            .access_token
            .expect("login response should include access token");
        let refresh_token = login
            .refresh_token
            .expect("login response should include refresh token");

        let me = match super::me(
            State(harness.state.clone()),
            auth_headers("handler-full-flow-me", &access_token),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("me endpoint should succeed"),
        };
        assert!(!me.user_id.is_empty());
        assert!(!me.session_id.is_empty());

        let sessions = match super::sessions(
            State(harness.state.clone()),
            auth_headers("handler-full-flow-sessions", &access_token),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("sessions endpoint should succeed"),
        };
        assert!(!sessions.is_empty());

        let refresh = match super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-refresh"),
            Json(RefreshRequest {
                refresh_token: refresh_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("refresh should succeed"),
        };

        let refreshed_access = refresh
            .access_token
            .expect("refresh response should include access token");
        let refreshed_refresh = refresh
            .refresh_token
            .expect("refresh response should include refresh token");

        let logout_all_status = match super::logout_all(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-full-flow-logout-all", &refreshed_access),
        )
        .await
        {
            Ok(status) => status,
            Err(_) => panic!("logout-all should succeed"),
        };
        assert_eq!(logout_all_status, StatusCode::OK);

        let me_after_logout = match super::me(
            State(harness.state.clone()),
            auth_headers("handler-full-flow-me-after-logout", &refreshed_access),
        )
        .await
        {
            Ok(_) => panic!("access token should be invalid after logout-all"),
            Err(problem) => problem,
        };
        assert_eq!(me_after_logout.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            me_after_logout.body.type_url,
            "https://example.com/problems/invalid-token"
        );

        let refresh_after_logout = match super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-refresh-after-logout"),
            Json(RefreshRequest {
                refresh_token: refreshed_refresh,
            }),
        )
        .await
        {
            Ok(_) => panic!("refresh token should be invalid after logout-all"),
            Err(problem) => problem,
        };
        assert_eq!(refresh_after_logout.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            refresh_after_logout.body.type_url,
            "https://example.com/problems/invalid-token"
        );

        let replay_login = match super::login(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-replay-login"),
            Json(LoginRequest {
                email: harness.bootstrap_email.clone(),
                password: harness.bootstrap_password.clone(),
                device_info: Some("handler-full-flow-replay-device".to_string()),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("replay login should succeed"),
        };
        let replay_refresh_token = replay_login
            .refresh_token
            .expect("replay login should include refresh token");

        let replay_rotation = match super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-replay-rotate"),
            Json(RefreshRequest {
                refresh_token: replay_refresh_token.clone(),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("replay rotation should succeed"),
        };
        assert!(replay_rotation.access_token.is_some());

        let replay = match super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-refresh-replay"),
            Json(RefreshRequest {
                refresh_token: replay_refresh_token,
            }),
        )
        .await
        {
            Ok(_) => panic!("refresh replay should be rejected"),
            Err(problem) => problem,
        };
        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay.body.type_url,
            "https://example.com/problems/refresh-reuse"
        );

        let metrics_ok = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-full-flow-metrics-ok", "metrics-secret-token"),
        )
        .await;
        assert!(metrics_ok.is_ok());

        let metrics_missing_token = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-full-flow-metrics-missing"),
        )
        .await
        {
            Ok(_) => panic!("metrics should reject missing token in full flow"),
            Err(problem) => problem,
        };
        assert_eq!(metrics_missing_token.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            metrics_missing_token.body.type_url,
            "https://example.com/problems/metrics-auth-required"
        );
    }

    #[tokio::test]
    async fn postgres_backed_auth_flow_smoke_with_metrics_protection() {
        let Some(harness) = build_postgres_harness_with_metrics_policy(
            Some("metrics-secret-token"),
            vec!["127.0.0.0/8"],
        )
        .await
        else {
            return;
        };

        let login = match super::login(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-postgres-flow-login"),
            Json(LoginRequest {
                email: harness.bootstrap_email.clone(),
                password: harness.bootstrap_password.clone(),
                device_info: Some("handler-postgres-flow-device".to_string()),
            }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("postgres login should succeed"),
        };
        assert!(!login.mfa_required);

        let access_token = login
            .access_token
            .expect("postgres login should include access token");
        let refresh_token = login
            .refresh_token
            .expect("postgres login should include refresh token");

        let me = match super::me(
            State(harness.state.clone()),
            auth_headers("handler-postgres-flow-me", &access_token),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("postgres me should succeed"),
        };
        assert!(!me.user_id.is_empty());

        let refresh = match super::refresh(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-postgres-flow-refresh"),
            Json(RefreshRequest { refresh_token }),
        )
        .await
        {
            Ok(response) => response.0,
            Err(_) => panic!("postgres refresh should succeed"),
        };

        let refreshed_access = refresh
            .access_token
            .expect("postgres refresh should include access token");

        let logout_all_status = match super::logout_all(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-postgres-flow-logout-all", &refreshed_access),
        )
        .await
        {
            Ok(status) => status,
            Err(_) => panic!("postgres logout-all should succeed"),
        };
        assert_eq!(logout_all_status, StatusCode::OK);

        let me_after_logout = match super::me(
            State(harness.state.clone()),
            auth_headers("handler-postgres-flow-me-after-logout", &refreshed_access),
        )
        .await
        {
            Ok(_) => panic!("postgres access should be invalid after logout-all"),
            Err(problem) => problem,
        };
        assert_eq!(me_after_logout.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            me_after_logout.body.type_url,
            "https://example.com/problems/invalid-token"
        );

        let metrics_ok = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-postgres-flow-metrics-ok", "metrics-secret-token"),
        )
        .await;
        assert!(metrics_ok.is_ok());

        let metrics_missing_token = match super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-postgres-flow-metrics-missing"),
        )
        .await
        {
            Ok(_) => panic!("postgres metrics should reject missing token"),
            Err(problem) => problem,
        };
        assert_eq!(metrics_missing_token.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            metrics_missing_token.body.type_url,
            "https://example.com/problems/metrics-auth-required"
        );
    }

    async fn login_success(harness: &HandlerHarness, trace_id: &str) -> super::LoginResponse {
        let response = match super::login(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace(trace_id),
            Json(LoginRequest {
                email: harness.bootstrap_email.clone(),
                password: harness.bootstrap_password.clone(),
                device_info: Some(format!("{trace_id}-device")),
            }),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => panic!("login should succeed"),
        };

        response.0
    }

    async fn enable_mfa(harness: &HandlerHarness) {
        let login = harness
            .state
            .auth_service
            .login(
                LoginCommand {
                    email: harness.bootstrap_email.clone(),
                    password: harness.bootstrap_password.clone(),
                    device_info: Some("handler-mfa-enable".to_string()),
                },
                test_context("handler-mfa-enable-login"),
            )
            .await
            .expect("bootstrap login should succeed");

        let user_id = match login {
            LoginResult::Authenticated { principal, .. } => principal.user_id,
            LoginResult::MfaRequired(_) => panic!("bootstrap user should not require mfa yet"),
        };

        let enroll = harness
            .state
            .auth_service
            .mfa_enroll(&user_id, test_context("handler-mfa-enroll"))
            .await
            .expect("mfa enroll should succeed");

        harness
            .state
            .auth_service
            .mfa_activate(
                MfaActivateCommand {
                    user_id,
                    totp_code: current_totp_code(&enroll.secret),
                },
                test_context("handler-mfa-activate"),
            )
            .await
            .expect("mfa activate should succeed");
    }

    #[tokio::test]
    async fn auth_methods_v2_handler_returns_neutral_contract() {
        let harness = build_v2_harness().await;

        let response = super::auth_methods_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-methods"),
            Json(AuthMethodsRequest {
                identifier: harness.bootstrap_email.clone(),
                channel: Some("web".to_string()),
                client: super::AuthClientCapabilitiesRequest {
                    supports_pake: true,
                    supports_passkeys: true,
                    supports_conditional_mediation: Some(true),
                    platform: Some("canary_web".to_string()),
                },
            }),
        )
        .await
        .expect("v2 methods handler should succeed");

        let http_response = response.into_response();
        assert_eq!(
            http_response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, max-age=0"))
        );
        let body = to_bytes(http_response.into_body(), 1024 * 1024)
            .await
            .expect("v2 methods body should be readable");
        let response: super::AuthMethodsContractResponse =
            serde_json::from_slice(&body).expect("v2 methods body should deserialize");

        assert_eq!(response.request_id, "handler-v2-methods");
        assert_eq!(response.discovery_expires_in, 300);
        assert_eq!(response.recommended_method.as_deref(), Some("passkey"));
        let recovery = response
            .account_recovery
            .expect("v2 methods contract should include account recovery guidance");
        assert_eq!(recovery.kind, "password_reset");
        assert_eq!(recovery.path, "/v1/auth/password/forgot");
        assert_eq!(response.methods.len(), 2);
        assert_eq!(response.methods[0].path, "/v2/auth/password/login/start");
        assert_eq!(
            response.methods[1].client_mediation.as_deref(),
            Some("conditional_if_available")
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-methods-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_body = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_body.to_vec()).expect("metrics payload should be utf-8");
        assert!(metrics_payload.contains("auth_v2_methods_requests_total"));
        assert!(metrics_payload.contains("channel=\"canary_web\""));
        assert!(metrics_payload.contains("outcome=\"success\""));
    }

    #[tokio::test]
    async fn auth_methods_v2_handler_rejects_non_allowlisted_channel() {
        let harness = build_v2_harness_with_client_allowlist(&["canary_web"]).await;

        let problem = super::auth_methods_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-methods-denied"),
            Json(AuthMethodsRequest {
                identifier: harness.bootstrap_email.clone(),
                channel: Some("android".to_string()),
                client: super::AuthClientCapabilitiesRequest {
                    supports_pake: true,
                    supports_passkeys: true,
                    supports_conditional_mediation: Some(true),
                    platform: Some("android".to_string()),
                },
            }),
        )
        .await
        .expect_err("non-allowlisted clients should be denied");

        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/auth-v2-rollout-denied"
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-methods-denied-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_body = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_body.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_v2_methods_rejected_total"));
        assert!(metrics_payload.contains("channel=\"canary_mobile\""));
        assert!(metrics_payload.contains("reason=\"rollout_denied\""));
        assert!(metrics_payload.contains("outcome=\"rollout_denied\""));
    }

    #[tokio::test]
    async fn auth_methods_v2_handler_rejects_requests_in_shadow_audit_mode() {
        let harness = build_v2_harness_in_shadow_audit_mode().await;

        let problem = super::auth_methods_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-methods-shadow"),
            Json(AuthMethodsRequest {
                identifier: harness.bootstrap_email.clone(),
                channel: Some("web".to_string()),
                client: super::AuthClientCapabilitiesRequest {
                    supports_pake: true,
                    supports_passkeys: true,
                    supports_conditional_mediation: Some(true),
                    platform: Some("web".to_string()),
                },
            }),
        )
        .await
        .expect_err("shadow audit mode should deny external v2 requests");

        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        assert_eq!(problem.body.title, "Auth v2 rollout denied");
        assert_eq!(
            problem.body.detail,
            "Auth v2 is not available for this client cohort"
        );
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/auth-v2-rollout-denied"
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-methods-shadow-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_body = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_body.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_v2_methods_rejected_total"));
        assert!(metrics_payload.contains("channel=\"canary_web\""));
        assert!(metrics_payload.contains("reason=\"shadow_hidden\""));
        assert!(metrics_payload.contains("outcome=\"shadow_hidden\""));
    }

    #[tokio::test]
    async fn password_login_v2_handlers_complete_authenticated_flow() {
        let harness = build_v2_harness().await;

        let discovery = super::auth_methods_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-discovery"),
            Json(AuthMethodsRequest {
                identifier: harness.bootstrap_email.clone(),
                channel: Some("web".to_string()),
                client: super::AuthClientCapabilitiesRequest {
                    supports_pake: true,
                    supports_passkeys: false,
                    supports_conditional_mediation: None,
                    platform: Some("canary_web".to_string()),
                },
            }),
        )
        .await
        .expect("v2 discovery should succeed")
        .0;

        let start = super::password_login_start_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-start"),
            Json(PasswordLoginStartRequest {
                identifier: harness.bootstrap_email.clone(),
                discovery_token: discovery.discovery_token,
                client_message: None,
                client: super::PasswordLoginStartClientRequest {
                    supports_pake: true,
                    platform: Some("firefox-linux".to_string()),
                },
            }),
        )
        .await
        .expect("v2 start should succeed")
        .0;

        let finish = super::password_login_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-finish"),
            Json(PasswordLoginFinishRequest {
                flow_id: start.flow_id.clone(),
                client_message: serde_json::json!({
                    "opaque_message": format!("ok:{}", start.flow_id),
                }),
                device_info: Some("Firefox on Linux".to_string()),
            }),
        )
        .await
        .expect("v2 finish should authenticate")
        .0;

        assert!(finish.authenticated);
        assert!(!finish.mfa_required);
        assert!(finish.access_token.is_some());
        assert!(finish.refresh_token.is_some());
        assert!(!finish.upgrade_required);
    }

    #[tokio::test]
    async fn password_login_start_v2_handler_rejects_clients_without_pake_support() {
        let harness = build_v2_harness().await;

        let problem = super::password_login_start_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-start-invalid"),
            Json(PasswordLoginStartRequest {
                identifier: harness.bootstrap_email.clone(),
                discovery_token: "ignored".to_string(),
                client_message: None,
                client: super::PasswordLoginStartClientRequest {
                    supports_pake: false,
                    platform: None,
                },
            }),
        )
        .await
        .expect_err("non-PAKE clients should be rejected");

        assert_eq!(problem.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-request"
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-start-invalid-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_body = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_body.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_v2_password_start_requests_total"));
        assert!(metrics_payload.contains("outcome=\"invalid_request\""));
        assert!(metrics_payload.contains("auth_v2_password_rejected_total"));
        assert!(metrics_payload.contains("reason=\"invalid_request\""));
    }

    #[tokio::test]
    async fn passkey_login_start_v2_handler_rejects_invalid_discovery_token() {
        let harness = build_v2_harness().await;

        let problem = super::passkey_login_start_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-start-invalid"),
            Json(super::PasskeyLoginStartV2Request {
                identifier: harness.bootstrap_email.clone(),
                discovery_token: "missing-discovery-token".to_string(),
            }),
        )
        .await
        .expect_err("invalid discovery token should be rejected");

        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-token"
        );
    }

    #[tokio::test]
    async fn passkey_register_start_v2_handler_returns_contract() {
        let harness = build_v2_harness().await;
        let login = login_success(&harness, "handler-v2-passkey-register-start-login").await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let response = super::passkey_register_start_v2(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-v2-passkey-register-start", &access_token),
            Json(super::PasskeyRegisterStartV2Request {
                label: Some("Personal laptop".to_string()),
                authenticator_preference: Some("platform_or_cross_platform".to_string()),
            }),
        )
        .await
        .expect("v2 passkey register start should succeed");

        let http_response = response.into_response();
        assert_eq!(
            http_response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, max-age=0"))
        );
        let body = to_bytes(http_response.into_body(), 1024 * 1024)
            .await
            .expect("v2 passkey register start body should be readable");
        let payload: super::PasskeyChallengeV2Response =
            serde_json::from_slice(&body).expect("v2 passkey register start should deserialize");

        assert_eq!(payload.flow_kind, "passkey_register");
        assert_eq!(payload.protocol, "webauthn_v1");
        assert_eq!(payload.expires_in, 300);
    }

    #[tokio::test]
    async fn password_upgrade_v2_handlers_complete_upgrade_flow() {
        let harness = build_v2_harness_with_options(true, true, false).await;
        let login = login_success(&harness, "handler-v2-password-upgrade-login").await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let start = super::password_upgrade_start_v2(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-v2-password-upgrade-start", &access_token),
            Json(super::PasswordUpgradeStartRequest {
                upgrade_context: "session".to_string(),
                client_message: None,
                client: super::PasswordUpgradeStartClientRequest {
                    supports_pake: true,
                    platform: Some("canary_web".to_string()),
                },
            }),
        )
        .await
        .expect("v2 password upgrade start should succeed")
        .0;

        assert_eq!(start.flow_kind, "password_upgrade");
        assert_eq!(start.next.path, "/v2/auth/password/upgrade/finish");

        let finish = super::password_upgrade_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-password-upgrade-finish"),
            Json(super::PasswordUpgradeFinishRequest {
                flow_id: start.flow_id.clone(),
                client_message: serde_json::json!({
                    "registration_upload": format!("ok-reg:{}", start.flow_id),
                }),
            }),
        )
        .await
        .expect("v2 password upgrade finish should succeed")
        .0;

        assert!(finish.upgraded);
        assert_eq!(finish.opaque_version, "opaque_v1");
        assert!(finish.legacy_password.login_allowed);
    }

    #[tokio::test]
    async fn password_upgrade_start_v2_handler_accepts_recovery_bridge_context() {
        let harness = build_v2_harness_with_options(true, true, false).await;
        let bootstrap_access_token =
            login_success(&harness, "handler-v2-recovery-bridge-bootstrap")
                .await
                .access_token
                .expect("login should issue access token");
        let bootstrap_user = harness
            .state
            .auth_service
            .authenticate_access_token(&bootstrap_access_token)
            .await
            .expect("bootstrap access token should resolve principal");
        let now = Utc::now();

        harness
            .auth_flows
            .issue(crate::modules::auth::domain::AuthFlowRecord {
                flow_id: "handler-recovery-bridge".to_string(),
                subject_user_id: Some(bootstrap_user.user_id),
                subject_identifier_hash: None,
                flow_kind: crate::modules::auth::domain::AuthFlowKind::RecoveryUpgradeBridge,
                protocol: "recovery_upgrade_bridge_v1".to_string(),
                state: serde_json::json!({"source": "password_reset"}),
                status: crate::modules::auth::domain::AuthFlowStatus::Pending,
                rollout_channel: Some("canary_web".to_string()),
                fallback_policy: Some("disabled".to_string()),
                trace_id: Some("handler-v2-recovery-bridge-trace".to_string()),
                issued_ip: Some("127.0.0.1".to_string()),
                issued_user_agent: Some("unit-test".to_string()),
                attempt_count: 0,
                expires_at: now + chrono::Duration::seconds(300),
                consumed_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("recovery bridge should be stored");

        let start = super::password_upgrade_start_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-password-upgrade-recovery-bridge"),
            Json(super::PasswordUpgradeStartRequest {
                upgrade_context: "recovery_bridge".to_string(),
                client_message: Some(serde_json::json!({
                    "recovery_flow_id": "handler-recovery-bridge",
                })),
                client: super::PasswordUpgradeStartClientRequest {
                    supports_pake: true,
                    platform: Some("canary_web".to_string()),
                },
            }),
        )
        .await
        .expect("recovery bridge upgrade start should succeed")
        .0;

        assert_eq!(start.flow_kind, "password_upgrade");
        assert_eq!(start.next.path, "/v2/auth/password/upgrade/finish");
    }

    #[tokio::test]
    async fn password_upgrade_v2_handlers_complete_recovery_bridge_flow() {
        let harness = build_v2_harness_with_options(true, true, false).await;
        let bootstrap_access_token =
            login_success(&harness, "handler-v2-recovery-bridge-finish-bootstrap")
                .await
                .access_token
                .expect("login should issue access token");
        let bootstrap_user = harness
            .state
            .auth_service
            .authenticate_access_token(&bootstrap_access_token)
            .await
            .expect("bootstrap access token should resolve principal");
        let now = Utc::now();

        harness
            .auth_flows
            .issue(crate::modules::auth::domain::AuthFlowRecord {
                flow_id: "handler-recovery-bridge-finish".to_string(),
                subject_user_id: Some(bootstrap_user.user_id),
                subject_identifier_hash: None,
                flow_kind: crate::modules::auth::domain::AuthFlowKind::RecoveryUpgradeBridge,
                protocol: "recovery_upgrade_bridge_v1".to_string(),
                state: serde_json::json!({"source": "password_reset"}),
                status: crate::modules::auth::domain::AuthFlowStatus::Pending,
                rollout_channel: Some("canary_web".to_string()),
                fallback_policy: Some("disabled".to_string()),
                trace_id: Some("handler-v2-recovery-bridge-finish-trace".to_string()),
                issued_ip: Some("127.0.0.1".to_string()),
                issued_user_agent: Some("unit-test".to_string()),
                attempt_count: 0,
                expires_at: now + chrono::Duration::seconds(300),
                consumed_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("recovery bridge should be stored");

        let start = super::password_upgrade_start_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-password-upgrade-recovery-bridge-finish-start"),
            Json(super::PasswordUpgradeStartRequest {
                upgrade_context: "recovery_bridge".to_string(),
                client_message: Some(serde_json::json!({
                    "recovery_flow_id": "handler-recovery-bridge-finish",
                })),
                client: super::PasswordUpgradeStartClientRequest {
                    supports_pake: true,
                    platform: Some("canary_web".to_string()),
                },
            }),
        )
        .await
        .expect("recovery bridge upgrade start should succeed")
        .0;
        let start_flow_id = start.flow_id.clone();

        let finish = super::password_upgrade_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-password-upgrade-recovery-bridge-finish-complete"),
            Json(super::PasswordUpgradeFinishRequest {
                flow_id: start_flow_id.clone(),
                client_message: serde_json::json!({
                    "registration_upload": format!("ok-reg:{}", start_flow_id),
                }),
            }),
        )
        .await
        .expect("recovery bridge upgrade finish should succeed")
        .0;

        assert!(finish.upgraded);
        assert_eq!(finish.opaque_version, "opaque_v1");
        assert!(finish.legacy_password.login_allowed);
    }

    #[tokio::test]
    async fn password_upgrade_start_v2_handler_rejects_non_allowlisted_client() {
        let harness = build_v2_harness_with_options_and_allowlist(
            true,
            true,
            false,
            false,
            false,
            &["canary_web"],
        )
        .await;
        let login = login_success(&harness, "handler-v2-password-upgrade-denied-login").await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let problem = super::password_upgrade_start_v2(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-v2-password-upgrade-denied", &access_token),
            Json(super::PasswordUpgradeStartRequest {
                upgrade_context: "session".to_string(),
                client_message: None,
                client: super::PasswordUpgradeStartClientRequest {
                    supports_pake: true,
                    platform: Some("ios".to_string()),
                },
            }),
        )
        .await
        .expect_err("non-allowlisted upgrade clients should be denied");

        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/auth-v2-rollout-denied"
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-password-upgrade-denied-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_body = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_body.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_v2_password_upgrade_requests_total"));
        assert!(metrics_payload.contains("operation=\"start\",outcome=\"rollout_denied\""));
        assert!(metrics_payload.contains("auth_v2_password_rejected_total"));
        assert!(metrics_payload.contains("reason=\"rollout_denied\""));
    }

    #[tokio::test]
    async fn passkey_login_finish_v2_handler_invalid_challenge_returns_problem_and_metrics() {
        let harness = build_v2_harness().await;

        let rejected = super::passkey_login_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-login-finish-invalid-challenge"),
            Json(super::PasskeyLoginFinishRequest {
                flow_id: "missing-v2-passkey-flow".to_string(),
                credential: dummy_passkey_login_credential(),
                device_info: Some("handler-v2-passkey-device".to_string()),
            }),
        )
        .await
        .expect_err("v2 passkey login finish should reject invalid challenge");

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-passkey-challenge"
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-login-finish-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_bytes = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_bytes.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_passkey_requests_total"));
        assert!(metrics_payload.contains("operation=\"login_finish_v2\",outcome=\"error\""));
        assert!(metrics_payload.contains("auth_passkey_login_rejected_total"));
        assert!(metrics_payload.contains("reason=\"invalid_or_expired_challenge\""));
    }

    #[tokio::test]
    async fn passkey_register_finish_v2_handler_invalid_challenge_returns_problem_and_metrics() {
        let harness = build_v2_harness().await;
        let login = login_success(&harness, "handler-v2-passkey-register-finish-login").await;
        let access_token = login
            .access_token
            .expect("login should issue access token for authenticated endpoints");

        let rejected = super::passkey_register_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            auth_headers(
                "handler-v2-passkey-register-finish-invalid-challenge",
                &access_token,
            ),
            Json(super::PasskeyRegisterFinishRequest {
                flow_id: "missing-v2-register-flow".to_string(),
                credential: dummy_passkey_register_credential(),
            }),
        )
        .await
        .expect_err("v2 passkey register finish should reject invalid challenge");

        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.body.type_url,
            "https://example.com/problems/invalid-passkey-challenge"
        );

        let metrics_response = super::metrics(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-register-finish-metrics"),
        )
        .await
        .expect("metrics should succeed")
        .into_response();
        let metrics_bytes = to_bytes(metrics_response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body should be readable");
        let metrics_payload =
            String::from_utf8(metrics_bytes.to_vec()).expect("metrics payload should be utf-8");

        assert!(metrics_payload.contains("auth_passkey_requests_total"));
        assert!(metrics_payload.contains("operation=\"register_finish_v2\",outcome=\"error\""));
        assert!(metrics_payload.contains("auth_passkey_register_rejected_total"));
        assert!(metrics_payload.contains("reason=\"invalid_or_expired_challenge\""));
    }

    #[tokio::test]
    async fn passkey_login_finish_v2_handler_returns_authenticated_contract() {
        let harness = build_v2_harness_with_successful_finish_passkey_service().await;
        let bootstrap_user = harness
            .state
            .auth_service
            .authenticate_access_token(
                &login_success(&harness, "handler-v2-passkey-login-bootstrap")
                    .await
                    .access_token
                    .expect("login should return access token"),
            )
            .await
            .expect("bootstrap access token should authenticate");
        harness
            .passkeys
            .upsert_for_user(&bootstrap_user.user_id, dummy_passkey(), Utc::now())
            .await
            .expect("dummy passkey should be inserted");

        let discovery = super::auth_methods_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-login-discovery"),
            Json(super::AuthMethodsRequest {
                identifier: harness.bootstrap_email.clone(),
                channel: Some("canary_web".to_string()),
                client: super::AuthClientCapabilitiesRequest {
                    supports_pake: true,
                    supports_passkeys: true,
                    supports_conditional_mediation: Some(true),
                    platform: Some("firefox-linux".to_string()),
                },
            }),
        )
        .await
        .expect("v2 auth methods should succeed")
        .0;

        let start = super::passkey_login_start_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-login-start"),
            Json(super::PasskeyLoginStartV2Request {
                identifier: harness.bootstrap_email.clone(),
                discovery_token: discovery.discovery_token,
            }),
        )
        .await
        .expect("v2 passkey login start should succeed")
        .0;

        let finish = super::passkey_login_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            headers_with_trace("handler-v2-passkey-login-finish-success"),
            Json(super::PasskeyLoginFinishRequest {
                flow_id: start.flow_id,
                credential: successful_passkey_login_credential(),
                device_info: Some("Firefox on Linux".to_string()),
            }),
        )
        .await
        .expect("v2 passkey login finish should succeed")
        .0;

        assert!(finish.authenticated);
        assert!(finish.access_token.is_some());
        assert!(finish.refresh_token.is_some());
        assert!(!finish.mfa_required);
        assert!(!finish.upgrade_required);
    }

    #[tokio::test]
    async fn passkey_register_finish_v2_handler_returns_enrollment_contract() {
        let harness = build_v2_harness_with_successful_finish_passkey_service().await;
        let access_token = login_success(&harness, "handler-v2-passkey-register-success-login")
            .await
            .access_token
            .expect("login should return access token");

        let start = super::passkey_register_start_v2(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-v2-passkey-register-start-success", &access_token),
            Json(super::PasskeyRegisterStartV2Request {
                label: Some("Personal laptop".to_string()),
                authenticator_preference: Some("platform_or_cross_platform".to_string()),
            }),
        )
        .await
        .expect("v2 passkey register start should succeed")
        .0;

        let finish = super::passkey_register_finish_v2(
            State(harness.state.clone()),
            connect_info(),
            auth_headers("handler-v2-passkey-register-finish-success", &access_token),
            Json(super::PasskeyRegisterFinishRequest {
                flow_id: start.flow_id,
                credential: successful_passkey_register_credential(),
            }),
        )
        .await
        .expect("v2 passkey register finish should succeed")
        .0;

        assert!(finish.enrolled);
        assert_eq!(finish.passkey_count, 1);
        assert_eq!(finish.recommended_login_method, "passkey");
    }

    #[tokio::test]
    async fn auth_methods_v2_route_rejects_get_with_405() {
        use axum::{
            body::{to_bytes, Body},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let harness = build_v2_harness().await;
        let auth_v2_config = harness
            .state
            .auth_service
            .auth_v2_config()
            .expect("v2 config should be available for router tests");
        let app = crate::build_api_router(&auth_v2_config).with_state(harness.state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/auth/methods")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let allow = response
            .headers()
            .get(header::ALLOW)
            .expect("405 response should advertise allowed methods");
        assert_eq!(allow, "POST");

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("405 body should be readable");
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn shadow_audit_only_router_hides_v2_methods_but_keeps_v1_login_route() {
        use axum::{
            body::Body,
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let harness = build_v2_harness_in_shadow_audit_mode().await;
        let auth_v2_config = harness
            .state
            .auth_service
            .auth_v2_config()
            .expect("v2 config should be available for router tests");
        let app = crate::build_api_router(&auth_v2_config).with_state(harness.state.clone());

        let v2_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/auth/methods")
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(v2_response.status(), StatusCode::NOT_FOUND);

        let v1_response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/auth/login")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(v1_response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let allow = v1_response
            .headers()
            .get(header::ALLOW)
            .expect("405 response should advertise allowed methods");
        assert_eq!(allow, "POST");
    }

    async fn build_v2_harness() -> HandlerHarness {
        build_v2_harness_with_options(false, true, true).await
    }

    async fn build_v2_harness_in_shadow_audit_mode() -> HandlerHarness {
        build_v2_harness_with_options_and_allowlist(false, true, true, false, true, &["canary_web"])
            .await
    }

    async fn build_v2_harness_with_client_allowlist(client_allowlist: &[&str]) -> HandlerHarness {
        build_v2_harness_with_options_and_allowlist(
            false,
            true,
            true,
            false,
            false,
            client_allowlist,
        )
        .await
    }

    async fn build_v2_harness_with_successful_finish_passkey_service() -> HandlerHarness {
        build_v2_harness_with_options_and_passkey_service(
            false,
            true,
            true,
            true,
            false,
            &["canary_web"],
        )
        .await
    }

    async fn build_v2_harness_with_options(
        password_upgrade_enabled: bool,
        auth_flows_enabled: bool,
        include_active_opaque_credential: bool,
    ) -> HandlerHarness {
        build_v2_harness_with_options_and_allowlist(
            password_upgrade_enabled,
            auth_flows_enabled,
            include_active_opaque_credential,
            false,
            false,
            &["canary_web"],
        )
        .await
    }

    async fn build_v2_harness_with_options_and_allowlist(
        password_upgrade_enabled: bool,
        auth_flows_enabled: bool,
        include_active_opaque_credential: bool,
        stub_successful_finish: bool,
        shadow_audit_only: bool,
        client_allowlist: &[&str],
    ) -> HandlerHarness {
        build_v2_harness_with_options_and_passkey_service(
            password_upgrade_enabled,
            auth_flows_enabled,
            include_active_opaque_credential,
            stub_successful_finish,
            shadow_audit_only,
            client_allowlist,
        )
        .await
    }

    async fn build_v2_harness_with_options_and_passkey_service(
        password_upgrade_enabled: bool,
        auth_flows_enabled: bool,
        include_active_opaque_credential: bool,
        stub_successful_finish: bool,
        shadow_audit_only: bool,
        client_allowlist: &[&str],
    ) -> HandlerHarness {
        let mut cfg = test_config();
        cfg.passkey_enabled = true;
        cfg.passkey_rp_id = Some("example.com".to_string());
        cfg.passkey_rp_origin = Some("https://auth.example.com".to_string());
        let bootstrap_email = cfg
            .bootstrap_user_email
            .clone()
            .expect("bootstrap email should be present");
        let bootstrap_password = cfg
            .bootstrap_user_password
            .clone()
            .expect("bootstrap password should be present");
        let adapters =
            InMemoryAdapters::bootstrap(&cfg).expect("in-memory adapters should bootstrap");
        let bootstrap_user = adapters
            .users
            .find_by_email(&bootstrap_email)
            .await
            .expect("bootstrap user should exist");
        let passkeys = Arc::new(adapters.passkeys);

        let passkey_webauthn = build_test_passkey_webauthn(&cfg);
        let passkey_service = if stub_successful_finish {
            build_test_passkey_webauthn(&cfg).map(|webauthn| {
                Arc::new(SuccessfulFinishPasskeyService::new(webauthn)) as Arc<dyn PasskeyService>
            })
        } else {
            None
        };

        let (v2_dependencies, auth_flows) = build_test_v2_dependencies(
            &bootstrap_user,
            password_upgrade_enabled,
            auth_flows_enabled,
            include_active_opaque_credential,
            shadow_audit_only,
            client_allowlist,
        );
        let auth_service = Arc::new(
            AuthService::new(
                Arc::new(adapters.users),
                Arc::new(adapters.login_abuse),
                Arc::new(crate::adapters::risk::AllowAllLoginRiskAnalyzer),
                Arc::new(adapters.verification_tokens),
                Arc::new(adapters.password_reset_tokens),
                Arc::new(adapters.mfa_factors),
                Arc::new(adapters.mfa_challenges),
                Arc::new(adapters.mfa_backup_codes),
                passkeys.clone(),
                Arc::new(adapters.passkey_challenges),
                Arc::new(adapters.sessions),
                Arc::new(adapters.refresh_tokens),
                Arc::new(adapters.audit),
                Arc::new(crate::adapters::email::NoopTransactionalEmailSender),
                Arc::new(
                    JwtEdDsaService::new(
                        cfg.jwt_keys.clone(),
                        cfg.jwt_primary_kid.clone(),
                        cfg.jwt_issuer.clone(),
                        cfg.jwt_audience.clone(),
                    )
                    .expect("jwt service should initialize"),
                ),
                Arc::new(RefreshCryptoHmacService::new(cfg.refresh_pepper.clone())),
                cfg.access_ttl_seconds,
                cfg.refresh_ttl_seconds,
                cfg.email_verification_ttl_seconds,
                cfg.password_reset_ttl_seconds,
                cfg.mfa_challenge_ttl_seconds,
                cfg.mfa_challenge_max_attempts,
                cfg.mfa_totp_issuer.clone(),
                cfg.mfa_encryption_key.clone(),
                passkey_webauthn,
                cfg.jwt_issuer.clone(),
                cfg.jwt_audience.clone(),
            )
            .expect("auth service should initialize")
            .with_passkey_service_for_tests(passkey_service)
            .with_v2(v2_dependencies),
        );

        HandlerHarness {
            state: AppState {
                auth_service,
                jwks: crate::jwks::JwksDocument::from_ed25519_public_keys(
                    &cfg.jwt_keys
                        .iter()
                        .map(|key| crate::jwks::JwksPublicKeyInput {
                            kid: &key.kid,
                            public_key_pem: &key.public_key_pem,
                        })
                        .collect::<Vec<_>>(),
                )
                .expect("jwks document should be built"),
                readiness_checker: crate::health::RuntimeReadinessChecker::inmemory(
                    Arc::new(crate::health::PasskeyChallengeJanitorHealth::new(
                        false,
                        std::time::Duration::from_secs(60),
                    )),
                    Arc::new(crate::health::AuthFlowJanitorHealth::new(
                        false,
                        std::time::Duration::from_secs(60),
                    )),
                ),
                enforce_secure_transport: false,
                metrics_bearer_token: None,
                metrics_allowed_cidrs: Vec::new(),
                trust_x_forwarded_for: false,
                trusted_proxy_ips: Vec::new(),
                trusted_proxy_cidrs: Vec::new(),
            },
            auth_flows,
            passkeys,
            bootstrap_email,
            bootstrap_password,
        }
    }

    fn build_test_v2_dependencies(
        bootstrap_user: &crate::modules::auth::domain::User,
        password_upgrade_enabled: bool,
        auth_flows_enabled: bool,
        include_active_opaque_credential: bool,
        shadow_audit_only: bool,
        client_allowlist: &[&str],
    ) -> (
        crate::modules::auth::application::AuthV2Dependencies,
        Arc<StaticAuthFlowRepository>,
    ) {
        let now = Utc::now();
        let auth_flows = Arc::new(StaticAuthFlowRepository::new());

        (
            crate::modules::auth::application::AuthV2Dependencies {
                config: crate::config::AuthV2Config {
                    enabled: true,
                    methods_enabled: true,
                    password_pake_enabled: true,
                    password_upgrade_enabled,
                    pake_provider: crate::config::AuthV2PakeProvider::Unavailable,
                    opaque_server_setup: None,
                    opaque_server_key_ref: None,
                    passkey_namespace_enabled: true,
                    auth_flows_enabled,
                    legacy_fallback_mode: crate::config::AuthV2LegacyFallbackMode::Allowlisted,
                    client_allowlist: client_allowlist
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect(),
                    shadow_audit_only,
                },
                accounts: Arc::new(StaticAccountRepository::new(vec![
                    crate::modules::auth::domain::AccountRecord {
                        id: bootstrap_user.id.clone(),
                        email: bootstrap_user.email.clone(),
                        status: crate::modules::auth::domain::AccountStatus::Active,
                        created_at: now,
                        updated_at: now,
                    },
                ])),
                legacy_passwords: Arc::new(StaticLegacyPasswordRepository::new(vec![
                    crate::modules::auth::domain::LegacyPasswordRecord {
                        user_id: bootstrap_user.id.clone(),
                        password_hash: bootstrap_user.password_hash.clone(),
                        legacy_login_allowed: true,
                        migrated_to_opaque_at: None,
                        last_legacy_verified_at: None,
                        legacy_deprecation_at: None,
                    },
                ])),
                opaque_credentials: Arc::new(StaticOpaqueCredentialRepository::new(
                    if include_active_opaque_credential {
                        vec![crate::modules::auth::domain::OpaqueCredentialRecord {
                            user_id: bootstrap_user.id.clone(),
                            protocol: "opaque_v1".to_string(),
                            credential_blob: b"opaque-credential".to_vec(),
                            server_key_ref: None,
                            envelope_kms_key_id: None,
                            state: crate::modules::auth::domain::OpaqueCredentialState::Active,
                            migrated_from_legacy_at: None,
                            last_verified_at: None,
                            created_at: now,
                            updated_at: now,
                        }]
                    } else {
                        Vec::new()
                    },
                )),
                auth_flows: auth_flows.clone(),
                pake_service: Arc::new(DeterministicPakeService {
                    default_device_info: Some("Firefox on Linux".to_string()),
                }),
            },
            auth_flows,
        )
    }

    #[derive(Default)]
    struct StaticAccountRepository {
        by_email: std::collections::HashMap<String, crate::modules::auth::domain::AccountRecord>,
        by_id: std::collections::HashMap<String, crate::modules::auth::domain::AccountRecord>,
    }

    impl StaticAccountRepository {
        fn new(records: Vec<crate::modules::auth::domain::AccountRecord>) -> Self {
            let by_email = records
                .iter()
                .map(|record| (record.email.clone(), record.clone()))
                .collect();
            let by_id = records
                .into_iter()
                .map(|record| (record.id.clone(), record))
                .collect();

            Self { by_email, by_id }
        }
    }

    #[async_trait]
    impl crate::modules::auth::ports::AccountRepository for StaticAccountRepository {
        async fn find_by_email(
            &self,
            email: &str,
        ) -> Option<crate::modules::auth::domain::AccountRecord> {
            self.by_email.get(email).cloned()
        }

        async fn find_by_id(
            &self,
            user_id: &str,
        ) -> Option<crate::modules::auth::domain::AccountRecord> {
            self.by_id.get(user_id).cloned()
        }

        async fn create_pending(
            &self,
            _email: &str,
            _now: chrono::DateTime<Utc>,
        ) -> Result<Option<crate::modules::auth::domain::AccountRecord>, String> {
            Ok(None)
        }

        async fn activate(
            &self,
            _user_id: &str,
            _now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct StaticLegacyPasswordRepository {
        by_user_id: std::sync::Mutex<
            std::collections::HashMap<String, crate::modules::auth::domain::LegacyPasswordRecord>,
        >,
    }

    impl StaticLegacyPasswordRepository {
        fn new(records: Vec<crate::modules::auth::domain::LegacyPasswordRecord>) -> Self {
            Self {
                by_user_id: std::sync::Mutex::new(
                    records
                        .into_iter()
                        .map(|record| (record.user_id.clone(), record))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl crate::modules::auth::ports::LegacyPasswordRepository for StaticLegacyPasswordRepository {
        async fn find_by_user_id(
            &self,
            user_id: &str,
        ) -> Result<Option<crate::modules::auth::domain::LegacyPasswordRecord>, String> {
            Ok(self
                .by_user_id
                .lock()
                .map_err(|_| "legacy password storage unavailable".to_string())?
                .get(user_id)
                .cloned())
        }

        async fn upsert_hash(
            &self,
            _user_id: &str,
            _password_hash: &str,
            _now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn mark_verified(
            &self,
            _user_id: &str,
            _now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn mark_upgraded_to_opaque(
            &self,
            user_id: &str,
            now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            let mut guard = self
                .by_user_id
                .lock()
                .map_err(|_| "legacy password storage unavailable".to_string())?;
            let Some(record) = guard.get_mut(user_id) else {
                return Err("legacy password not found".to_string());
            };
            record.migrated_to_opaque_at = record.migrated_to_opaque_at.or(Some(now));
            record.last_legacy_verified_at = Some(now);
            Ok(())
        }

        async fn set_legacy_login_allowed(
            &self,
            _user_id: &str,
            _allowed: bool,
            _now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct StaticOpaqueCredentialRepository {
        by_user_id: std::sync::Mutex<
            std::collections::HashMap<String, crate::modules::auth::domain::OpaqueCredentialRecord>,
        >,
    }

    impl StaticOpaqueCredentialRepository {
        fn new(records: Vec<crate::modules::auth::domain::OpaqueCredentialRecord>) -> Self {
            Self {
                by_user_id: std::sync::Mutex::new(
                    records
                        .into_iter()
                        .map(|record| (record.user_id.clone(), record))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl crate::modules::auth::ports::OpaqueCredentialRepository for StaticOpaqueCredentialRepository {
        async fn find_by_user_id(
            &self,
            user_id: &str,
        ) -> Result<Option<crate::modules::auth::domain::OpaqueCredentialRecord>, String> {
            Ok(self
                .by_user_id
                .lock()
                .map_err(|_| "opaque credential storage unavailable".to_string())?
                .get(user_id)
                .cloned())
        }

        async fn upsert_for_user(
            &self,
            record: crate::modules::auth::domain::OpaqueCredentialRecord,
        ) -> Result<(), String> {
            self.by_user_id
                .lock()
                .map_err(|_| "opaque credential storage unavailable".to_string())?
                .insert(record.user_id.clone(), record);
            Ok(())
        }

        async fn mark_verified(
            &self,
            user_id: &str,
            now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            if let Some(record) = self
                .by_user_id
                .lock()
                .map_err(|_| "opaque credential storage unavailable".to_string())?
                .get_mut(user_id)
            {
                record.last_verified_at = Some(now);
                record.updated_at = now;
            }
            Ok(())
        }

        async fn revoke_for_user(
            &self,
            _user_id: &str,
            _now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct StaticAuthFlowRepository {
        flows: std::sync::Mutex<
            std::collections::HashMap<String, crate::modules::auth::domain::AuthFlowRecord>,
        >,
    }

    impl StaticAuthFlowRepository {
        fn new() -> Self {
            Self {
                flows: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl crate::modules::auth::ports::AuthFlowRepository for StaticAuthFlowRepository {
        async fn issue(
            &self,
            flow: crate::modules::auth::domain::AuthFlowRecord,
        ) -> Result<(), String> {
            self.flows
                .lock()
                .map_err(|_| "auth flow storage unavailable".to_string())?
                .insert(flow.flow_id.clone(), flow);
            Ok(())
        }

        async fn consume(
            &self,
            flow_id: &str,
            now: chrono::DateTime<Utc>,
        ) -> Result<crate::modules::auth::ports::AuthFlowConsumeState, String> {
            let mut flows = self
                .flows
                .lock()
                .map_err(|_| "auth flow storage unavailable".to_string())?;
            let Some(flow) = flows.get_mut(flow_id) else {
                return Ok(crate::modules::auth::ports::AuthFlowConsumeState::NotFound);
            };
            if flow.consumed_at.is_some() {
                return Ok(crate::modules::auth::ports::AuthFlowConsumeState::AlreadyConsumed);
            }
            if flow.expires_at <= now {
                return Ok(crate::modules::auth::ports::AuthFlowConsumeState::Expired);
            }
            if matches!(
                flow.status,
                crate::modules::auth::domain::AuthFlowStatus::Cancelled
            ) {
                return Ok(crate::modules::auth::ports::AuthFlowConsumeState::Cancelled);
            }

            flow.consumed_at = Some(now);
            flow.updated_at = now;
            Ok(crate::modules::auth::ports::AuthFlowConsumeState::Active(
                Box::new(flow.clone()),
            ))
        }

        async fn increment_attempts(
            &self,
            flow_id: &str,
            now: chrono::DateTime<Utc>,
        ) -> Result<(), String> {
            if let Some(flow) = self
                .flows
                .lock()
                .map_err(|_| "auth flow storage unavailable".to_string())?
                .get_mut(flow_id)
            {
                flow.attempt_count += 1;
                flow.updated_at = now;
            }
            Ok(())
        }

        async fn cancel_active_for_subject(
            &self,
            subject_user_id: Option<&str>,
            subject_identifier_hash: Option<&str>,
            flow_kind: &str,
            now: chrono::DateTime<Utc>,
        ) -> Result<u64, String> {
            let mut flows = self
                .flows
                .lock()
                .map_err(|_| "auth flow storage unavailable".to_string())?;
            let mut cancelled = 0_u64;
            for flow in flows.values_mut() {
                if flow.status != crate::modules::auth::domain::AuthFlowStatus::Pending
                    || flow.expires_at <= now
                {
                    continue;
                }
                let flow_kind_matches = match flow.flow_kind {
                    crate::modules::auth::domain::AuthFlowKind::MethodsDiscovery => {
                        flow_kind == "methods_discovery"
                    }
                    crate::modules::auth::domain::AuthFlowKind::PasswordLogin => {
                        flow_kind == "password_login"
                    }
                    crate::modules::auth::domain::AuthFlowKind::RecoveryUpgradeBridge => {
                        flow_kind == "recovery_upgrade_bridge"
                    }
                    crate::modules::auth::domain::AuthFlowKind::PasswordUpgrade => {
                        flow_kind == "password_upgrade"
                    }
                    crate::modules::auth::domain::AuthFlowKind::PasskeyLogin => {
                        flow_kind == "passkey_login"
                    }
                    crate::modules::auth::domain::AuthFlowKind::PasskeyRegister => {
                        flow_kind == "passkey_register"
                    }
                };
                if !flow_kind_matches {
                    continue;
                }
                let subject_matches = subject_user_id
                    .is_some_and(|user_id| flow.subject_user_id.as_deref() == Some(user_id))
                    || subject_identifier_hash.is_some_and(|identifier_hash| {
                        flow.subject_identifier_hash.as_deref() == Some(identifier_hash)
                    });
                if !subject_matches {
                    continue;
                }
                flow.status = crate::modules::auth::domain::AuthFlowStatus::Cancelled;
                flow.updated_at = now;
                cancelled += 1;
            }
            Ok(cancelled)
        }

        async fn metrics_snapshot(
            &self,
            now: chrono::DateTime<Utc>,
        ) -> Result<crate::modules::auth::ports::AuthFlowMetricsSnapshot, String> {
            let flows = self
                .flows
                .lock()
                .map_err(|_| "auth flow storage unavailable".to_string())?;
            let mut active_counts = [0_u64; 6];
            let mut expired_pending_total = 0_u64;
            let mut oldest_expired_pending_age_seconds = 0_u64;

            for flow in flows.values() {
                if flow.status != crate::modules::auth::domain::AuthFlowStatus::Pending {
                    continue;
                }

                if flow.expires_at > now {
                    let index = match flow.flow_kind {
                        crate::modules::auth::domain::AuthFlowKind::MethodsDiscovery => 0,
                        crate::modules::auth::domain::AuthFlowKind::PasswordLogin => 1,
                        crate::modules::auth::domain::AuthFlowKind::RecoveryUpgradeBridge => 2,
                        crate::modules::auth::domain::AuthFlowKind::PasswordUpgrade => 3,
                        crate::modules::auth::domain::AuthFlowKind::PasskeyLogin => 4,
                        crate::modules::auth::domain::AuthFlowKind::PasskeyRegister => 5,
                    };
                    active_counts[index] += 1;
                    continue;
                }

                expired_pending_total += 1;
                let age_seconds = (now - flow.expires_at).num_seconds().max(0) as u64;
                oldest_expired_pending_age_seconds =
                    oldest_expired_pending_age_seconds.max(age_seconds);
            }

            let active_by_kind = [
                crate::modules::auth::domain::AuthFlowKind::MethodsDiscovery,
                crate::modules::auth::domain::AuthFlowKind::PasswordLogin,
                crate::modules::auth::domain::AuthFlowKind::RecoveryUpgradeBridge,
                crate::modules::auth::domain::AuthFlowKind::PasswordUpgrade,
                crate::modules::auth::domain::AuthFlowKind::PasskeyLogin,
                crate::modules::auth::domain::AuthFlowKind::PasskeyRegister,
            ]
            .into_iter()
            .zip(active_counts)
            .filter(|(_, pending_total)| *pending_total > 0)
            .map(
                |(flow_kind, pending_total)| crate::modules::auth::ports::AuthFlowMetricBucket {
                    flow_kind,
                    pending_total,
                },
            )
            .collect::<Vec<_>>();

            Ok(crate::modules::auth::ports::AuthFlowMetricsSnapshot {
                active_by_kind,
                expired_pending_total,
                oldest_expired_pending_age_seconds,
            })
        }

        async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> Result<u64, String> {
            let mut flows = self
                .flows
                .lock()
                .map_err(|_| "auth flow storage unavailable".to_string())?;
            let original = flows.len();
            flows.retain(|_, flow| flow.expires_at > now);
            Ok((original - flows.len()) as u64)
        }
    }

    struct DeterministicPakeService {
        default_device_info: Option<String>,
    }

    #[async_trait]
    impl crate::modules::auth::ports::PasswordPakeService for DeterministicPakeService {
        async fn start_login(
            &self,
            credential: crate::modules::auth::ports::PakeLoginCredentialView,
            request: crate::modules::auth::ports::PakeStartRequest,
        ) -> Result<crate::modules::auth::ports::PakeStartResult, String> {
            let session_user_id = credential
                .user_id
                .ok_or_else(|| "missing user".to_string())?;

            Ok(crate::modules::auth::ports::PakeStartResult {
                response: serde_json::json!({
                    "opaque_message": format!("server:{}", request.flow_id),
                }),
                server_state: serde_json::json!({
                    "flow_id": request.flow_id,
                    "session_user_id": session_user_id,
                }),
            })
        }

        async fn finish_login(
            &self,
            server_state: serde_json::Value,
            client_message: serde_json::Value,
        ) -> Result<crate::modules::auth::ports::PakeFinishResult, String> {
            let flow_id = server_state
                .get("flow_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "missing flow id".to_string())?;
            let expected = format!("ok:{flow_id}");
            let actual = client_message
                .get("opaque_message")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "missing opaque message".to_string())?;
            if actual != expected {
                return Err("invalid opaque message".to_string());
            }

            Ok(crate::modules::auth::ports::PakeFinishResult {
                session_user_id: server_state
                    .get("session_user_id")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| "missing session user id".to_string())?
                    .to_string(),
                session_device_info: self.default_device_info.clone(),
            })
        }

        async fn start_registration(
            &self,
            request: crate::modules::auth::ports::PakeRegistrationStartRequest,
        ) -> Result<crate::modules::auth::ports::PakeStartResult, String> {
            Ok(crate::modules::auth::ports::PakeStartResult {
                response: serde_json::json!({
                    "registration_response": format!("reg:{}", request.flow_id),
                }),
                server_state: serde_json::json!({
                    "flow_id": request.flow_id,
                    "user_id": request.user_id,
                }),
            })
        }

        async fn finish_registration(
            &self,
            server_state: serde_json::Value,
            client_message: serde_json::Value,
        ) -> Result<crate::modules::auth::ports::PakeRegistrationFinishResult, String> {
            let flow_id = server_state
                .get("flow_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "missing flow id".to_string())?;
            let expected = format!("ok-reg:{flow_id}");
            let actual = client_message
                .get("registration_upload")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "missing registration upload".to_string())?;
            if actual != expected {
                return Err("invalid registration upload".to_string());
            }

            Ok(crate::modules::auth::ports::PakeRegistrationFinishResult {
                credential_blob: format!("opaque:{flow_id}").into_bytes(),
                server_key_ref: Some("test-server-key".to_string()),
                envelope_kms_key_id: None,
            })
        }
    }

    fn build_harness() -> HandlerHarness {
        build_harness_with_metrics_policy(None, Vec::new())
    }

    fn build_harness_with_metrics_token(metrics_bearer_token: Option<&str>) -> HandlerHarness {
        build_harness_with_metrics_policy(metrics_bearer_token, Vec::new())
    }

    fn build_harness_with_metrics_policy(
        metrics_bearer_token: Option<&str>,
        metrics_allowed_cidrs: Vec<&str>,
    ) -> HandlerHarness {
        build_harness_from_config(test_config(), metrics_bearer_token, metrics_allowed_cidrs)
    }

    fn build_harness_with_jwt_keys(
        jwt_keys: Vec<JwtKeyConfig>,
        jwt_primary_kid: &str,
    ) -> HandlerHarness {
        let mut cfg = test_config();
        cfg.jwt_keys = jwt_keys;
        cfg.jwt_primary_kid = jwt_primary_kid.to_string();
        build_harness_from_config(cfg, None, Vec::new())
    }

    fn build_passkey_harness() -> HandlerHarness {
        let mut cfg = test_config();
        cfg.passkey_enabled = true;
        cfg.passkey_rp_id = Some("example.com".to_string());
        cfg.passkey_rp_origin = Some("https://auth.example.com".to_string());
        build_harness_from_config(cfg, None, Vec::new())
    }

    fn build_harness_from_config(
        cfg: AppConfig,
        metrics_bearer_token: Option<&str>,
        metrics_allowed_cidrs: Vec<&str>,
    ) -> HandlerHarness {
        let bootstrap_email = cfg
            .bootstrap_user_email
            .clone()
            .expect("bootstrap email should be present");
        let bootstrap_password = cfg
            .bootstrap_user_password
            .clone()
            .expect("bootstrap password should be present");

        let adapters =
            InMemoryAdapters::bootstrap(&cfg).expect("in-memory adapters should bootstrap");
        let passkeys = Arc::new(adapters.passkeys);
        let passkey_webauthn = build_test_passkey_webauthn(&cfg);

        let auth_service = Arc::new(
            AuthService::new(
                Arc::new(adapters.users),
                Arc::new(adapters.login_abuse),
                Arc::new(crate::adapters::risk::AllowAllLoginRiskAnalyzer),
                Arc::new(adapters.verification_tokens),
                Arc::new(adapters.password_reset_tokens),
                Arc::new(adapters.mfa_factors),
                Arc::new(adapters.mfa_challenges),
                Arc::new(adapters.mfa_backup_codes),
                passkeys.clone(),
                Arc::new(adapters.passkey_challenges),
                Arc::new(adapters.sessions),
                Arc::new(adapters.refresh_tokens),
                Arc::new(adapters.audit),
                Arc::new(crate::adapters::email::NoopTransactionalEmailSender),
                Arc::new(
                    JwtEdDsaService::new(
                        cfg.jwt_keys.clone(),
                        cfg.jwt_primary_kid.clone(),
                        cfg.jwt_issuer.clone(),
                        cfg.jwt_audience.clone(),
                    )
                    .expect("jwt service should initialize"),
                ),
                Arc::new(RefreshCryptoHmacService::new(cfg.refresh_pepper.clone())),
                cfg.access_ttl_seconds,
                cfg.refresh_ttl_seconds,
                cfg.email_verification_ttl_seconds,
                cfg.password_reset_ttl_seconds,
                cfg.mfa_challenge_ttl_seconds,
                cfg.mfa_challenge_max_attempts,
                cfg.mfa_totp_issuer,
                cfg.mfa_encryption_key,
                passkey_webauthn,
                cfg.jwt_issuer,
                cfg.jwt_audience,
            )
            .expect("auth service should initialize"),
        );

        HandlerHarness {
            state: AppState {
                auth_service,
                jwks: crate::jwks::JwksDocument::from_ed25519_public_keys(
                    &cfg.jwt_keys
                        .iter()
                        .map(|key| crate::jwks::JwksPublicKeyInput {
                            kid: &key.kid,
                            public_key_pem: &key.public_key_pem,
                        })
                        .collect::<Vec<_>>(),
                )
                .expect("jwks document should be built"),
                readiness_checker: crate::health::RuntimeReadinessChecker::inmemory(
                    Arc::new(crate::health::PasskeyChallengeJanitorHealth::new(
                        false,
                        std::time::Duration::from_secs(60),
                    )),
                    Arc::new(crate::health::AuthFlowJanitorHealth::new(
                        false,
                        std::time::Duration::from_secs(60),
                    )),
                ),
                enforce_secure_transport: false,
                metrics_bearer_token: metrics_bearer_token.map(str::to_string),
                metrics_allowed_cidrs: metrics_allowed_cidrs
                    .into_iter()
                    .map(|cidr| {
                        cidr.parse::<ipnet::IpNet>()
                            .expect("metrics allowed cidr should be valid")
                    })
                    .collect(),
                trust_x_forwarded_for: false,
                trusted_proxy_ips: Vec::new(),
                trusted_proxy_cidrs: Vec::new(),
            },
            auth_flows: Arc::new(StaticAuthFlowRepository::new()),
            passkeys,
            bootstrap_email,
            bootstrap_password,
        }
    }

    fn jwt_key_config(
        kid: &str,
        private_key_pem: Option<&str>,
        public_key_pem: &str,
    ) -> JwtKeyConfig {
        JwtKeyConfig {
            kid: kid.to_string(),
            private_key_pem: private_key_pem.map(str::to_string),
            public_key_pem: public_key_pem.to_string(),
        }
    }

    async fn build_postgres_harness_with_metrics_policy(
        metrics_bearer_token: Option<&str>,
        metrics_allowed_cidrs: Vec<&str>,
    ) -> Option<HandlerHarness> {
        let database_url = test_postgres_database_url_from_env()?;

        let mut cfg = test_config();
        cfg.auth_runtime = AuthRuntime::PostgresRedis;
        cfg.database_url = database_url;
        cfg.bootstrap_user_email =
            Some(format!("bootstrap-pg-{}@example.com", uuid::Uuid::new_v4()));
        cfg.bootstrap_user_password = Some(generated_test_password());
        cfg.login_abuse_attempts_prefix =
            format!("handler:pg:test:attempts:{}", uuid::Uuid::new_v4());
        cfg.login_abuse_lock_prefix = format!("handler:pg:test:lock:{}", uuid::Uuid::new_v4());
        cfg.login_abuse_strikes_prefix =
            format!("handler:pg:test:strikes:{}", uuid::Uuid::new_v4());

        let bootstrap_email = cfg.bootstrap_user_email.clone()?;
        let bootstrap_password = cfg.bootstrap_user_password.clone()?;

        let adapters = match PostgresAdapters::bootstrap(&cfg).await {
            Ok(adapters) => adapters,
            Err(_) => return None,
        };
        let in_memory_adapters = match InMemoryAdapters::bootstrap(&cfg) {
            Ok(adapters) => adapters,
            Err(_) => return None,
        };
        let passkey_webauthn = build_test_passkey_webauthn(&cfg);
        let passkeys = Arc::new(adapters.passkeys);
        let jwt = match JwtEdDsaService::new(
            cfg.jwt_keys.clone(),
            cfg.jwt_primary_kid.clone(),
            cfg.jwt_issuer.clone(),
            cfg.jwt_audience.clone(),
        ) {
            Ok(jwt) => jwt,
            Err(_) => return None,
        };

        let auth_service = match AuthService::new(
            Arc::new(adapters.users),
            Arc::new(in_memory_adapters.login_abuse),
            Arc::new(crate::adapters::risk::AllowAllLoginRiskAnalyzer),
            Arc::new(adapters.verification_tokens),
            Arc::new(adapters.password_reset_tokens),
            Arc::new(adapters.mfa_factors),
            Arc::new(adapters.mfa_challenges),
            Arc::new(adapters.mfa_backup_codes),
            passkeys.clone(),
            Arc::new(adapters.passkey_challenges),
            Arc::new(adapters.sessions),
            Arc::new(adapters.refresh_tokens),
            Arc::new(adapters.audit),
            Arc::new(crate::adapters::email::NoopTransactionalEmailSender),
            Arc::new(jwt),
            Arc::new(RefreshCryptoHmacService::new(cfg.refresh_pepper.clone())),
            cfg.access_ttl_seconds,
            cfg.refresh_ttl_seconds,
            cfg.email_verification_ttl_seconds,
            cfg.password_reset_ttl_seconds,
            cfg.mfa_challenge_ttl_seconds,
            cfg.mfa_challenge_max_attempts,
            cfg.mfa_totp_issuer,
            cfg.mfa_encryption_key,
            passkey_webauthn,
            cfg.jwt_issuer,
            cfg.jwt_audience,
        ) {
            Ok(service) => Arc::new(service),
            Err(_) => return None,
        };
        let readiness_checker = crate::health::RuntimeReadinessChecker::postgres_redis(
            adapters.pool.clone(),
            None,
            std::time::Duration::from_millis(500),
            Arc::new(crate::health::PasskeyChallengeJanitorHealth::new(
                false,
                std::time::Duration::from_secs(60),
            )),
            Arc::new(crate::health::AuthFlowJanitorHealth::new(
                false,
                std::time::Duration::from_secs(60),
            )),
        );

        Some(HandlerHarness {
            state: AppState {
                auth_service,
                jwks: crate::jwks::JwksDocument::from_ed25519_public_keys(
                    &cfg.jwt_keys
                        .iter()
                        .map(|key| crate::jwks::JwksPublicKeyInput {
                            kid: &key.kid,
                            public_key_pem: &key.public_key_pem,
                        })
                        .collect::<Vec<_>>(),
                )
                .expect("jwks document should be built"),
                readiness_checker,
                enforce_secure_transport: false,
                metrics_bearer_token: metrics_bearer_token.map(str::to_string),
                metrics_allowed_cidrs: metrics_allowed_cidrs
                    .into_iter()
                    .map(|cidr| {
                        cidr.parse::<ipnet::IpNet>()
                            .expect("metrics allowed cidr should be valid")
                    })
                    .collect(),
                trust_x_forwarded_for: false,
                trusted_proxy_ips: Vec::new(),
                trusted_proxy_cidrs: Vec::new(),
            },
            auth_flows: Arc::new(StaticAuthFlowRepository::new()),
            passkeys,
            bootstrap_email,
            bootstrap_password,
        })
    }

    fn test_postgres_database_url_from_env() -> Option<String> {
        std::env::var("AUTH_TEST_DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn test_context(trace_id: &str) -> RequestContext {
        RequestContext {
            trace_id: trace_id.to_string(),
            ip: Some("127.0.0.1".to_string()),
            user_agent: Some("handler-tests".to_string()),
            client_id: None,
            auth_api_surface: crate::modules::auth::application::AuthApiSurface::V1,
        }
    }

    fn headers_with_trace(trace_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-trace-id",
            HeaderValue::from_str(trace_id).expect("trace id should fit"),
        );
        headers
    }

    fn headers_with_trace_and_xff(trace_id: &str, xff: &str) -> HeaderMap {
        let mut headers = headers_with_trace(trace_id);
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(xff).expect("x-forwarded-for should fit"),
        );
        headers
    }

    fn auth_headers(trace_id: &str, access_token: &str) -> HeaderMap {
        let mut headers = headers_with_trace(trace_id);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {access_token}"))
                .expect("authorization header should fit"),
        );
        headers
    }

    fn connect_info() -> ConnectInfo<std::net::SocketAddr> {
        connect_info_for([127, 0, 0, 1], 41000)
    }

    fn connect_info_for(octets: [u8; 4], port: u16) -> ConnectInfo<std::net::SocketAddr> {
        ConnectInfo(std::net::SocketAddr::from((octets, port)))
    }

    fn test_config() -> AppConfig {
        AppConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            auth_runtime: AuthRuntime::InMemory,
            auth_v2: crate::config::AuthV2Config {
                enabled: false,
                methods_enabled: false,
                password_pake_enabled: false,
                password_upgrade_enabled: false,
                pake_provider: crate::config::AuthV2PakeProvider::Unavailable,
                opaque_server_setup: None,
                opaque_server_key_ref: None,
                passkey_namespace_enabled: false,
                auth_flows_enabled: false,
                legacy_fallback_mode: crate::config::AuthV2LegacyFallbackMode::Disabled,
                client_allowlist: Vec::new(),
                shadow_audit_only: false,
            },
            enforce_secure_transport: false,
            passkey_enabled: false,
            passkey_rp_id: None,
            passkey_rp_origin: None,
            passkey_challenge_prune_interval_seconds: 60,
            auth_v2_auth_flow_prune_interval_seconds: 60,
            jwt_keys: vec![crate::config::JwtKeyConfig {
                kid: "handler-tests-ed25519-v1".to_string(),
                private_key_pem: Some(TEST_PRIVATE_KEY_PEM.to_string()),
                public_key_pem: TEST_PUBLIC_KEY_PEM.to_string(),
            }],
            jwt_primary_kid: "handler-tests-ed25519-v1".to_string(),
            metrics_bearer_token: None,
            metrics_allowed_cidrs: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_ips: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
            database_url: "".to_string(),
            database_max_connections: 1,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            jwt_issuer: "handler-tests".to_string(),
            jwt_audience: "handler-tests-clients".to_string(),
            refresh_pepper: "handler-tests-refresh-pepper".to_string(),
            access_ttl_seconds: 900,
            refresh_ttl_seconds: 1209600,
            email_verification_ttl_seconds: 86400,
            password_reset_ttl_seconds: 900,
            mfa_challenge_ttl_seconds: 300,
            mfa_challenge_max_attempts: 3,
            mfa_totp_issuer: "handler-tests".to_string(),
            mfa_encryption_key: generated_test_mfa_encryption_key_base64(),
            bootstrap_user_email: Some("bootstrap@example.com".to_string()),
            bootstrap_user_password: Some(generated_test_password()),
            login_max_attempts: 5,
            login_attempt_window_seconds: 300,
            login_lockout_seconds: 900,
            login_lockout_max_seconds: 7200,
            login_abuse_attempts_prefix: "handler:test:attempts".to_string(),
            login_abuse_lock_prefix: "handler:test:lock".to_string(),
            login_abuse_strikes_prefix: "handler:test:strikes".to_string(),
            login_abuse_redis_fail_mode: LoginAbuseRedisFailMode::FailClosed,
            login_abuse_bucket_mode: LoginAbuseBucketMode::EmailAndIp,
            login_risk_mode: crate::config::LoginRiskMode::AllowAll,
            login_risk_blocked_cidrs: Vec::new(),
            login_risk_blocked_user_agent_substrings: Vec::new(),
            login_risk_blocked_email_domains: Vec::new(),
            login_risk_challenge_cidrs: Vec::new(),
            login_risk_challenge_user_agent_substrings: Vec::new(),
            login_risk_challenge_email_domains: Vec::new(),
            email_metrics_latency_enabled: false,
            email_provider: crate::config::EmailProviderConfig::Noop,
            email_delivery_mode: crate::config::EmailDeliveryMode::Inline,
            email_outbox: crate::config::EmailOutboxConfig {
                poll_interval_ms: 1000,
                batch_size: 25,
                max_attempts: 8,
                lease_ms: 30_000,
                backoff_base_ms: 1000,
                backoff_max_ms: 60_000,
            },
        }
    }

    fn current_totp_code(secret: &str) -> String {
        let secret_bytes = base32::decode(Alphabet::RFC4648 { padding: false }, secret)
            .expect("secret should be valid base32");
        let step = (Utc::now().timestamp() / 30) as u64;
        totp_code_for_step(&secret_bytes, step).expect("totp generation should succeed")
    }

    fn generated_test_password() -> String {
        format!("Aa!9z{}", Uuid::new_v4().simple())
    }

    fn generated_test_mfa_encryption_key_base64() -> String {
        let mut key_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        BASE64_STANDARD.encode(key_bytes)
    }

    fn build_test_passkey_webauthn(cfg: &AppConfig) -> Option<webauthn_rs::prelude::Webauthn> {
        if !cfg.passkey_enabled {
            return None;
        }

        let rp_id = cfg
            .passkey_rp_id
            .as_deref()
            .expect("passkey rp id should be configured in tests");
        let rp_origin = cfg
            .passkey_rp_origin
            .as_deref()
            .expect("passkey rp origin should be configured in tests");

        let rp_origin = webauthn_rs::prelude::Url::parse(rp_origin)
            .expect("passkey rp origin should parse in tests");
        let webauthn = webauthn_rs::prelude::WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("passkey webauthn builder should initialize in tests")
            .build()
            .expect("passkey webauthn should build in tests");

        Some(webauthn)
    }

    fn dummy_passkey_login_credential() -> PublicKeyCredential {
        serde_json::from_str(
            r#"{
  "id": "dummy-credential",
  "rawId": "",
  "response": {
    "authenticatorData": "",
    "clientDataJSON": "",
    "signature": "",
    "userHandle": null
  },
  "extensions": {},
  "type": "public-key"
}"#,
        )
        .expect("dummy passkey credential should deserialize in tests")
    }

    fn successful_passkey_login_credential() -> PublicKeyCredential {
        serde_json::from_str(
            r#"{
  "id": "success-login-credential",
  "rawId": "AQID",
  "response": {
    "authenticatorData": "",
    "clientDataJSON": "",
    "signature": "",
    "userHandle": null
  },
  "extensions": {},
  "type": "public-key"
}"#,
        )
        .expect("successful passkey login credential should deserialize in tests")
    }

    fn dummy_passkey_register_credential() -> RegisterPublicKeyCredential {
        serde_json::from_str(
            r#"{
  "id": "dummy-register-credential",
  "rawId": "",
  "response": {
    "attestationObject": "",
    "clientDataJSON": "",
    "transports": null
  },
  "extensions": {},
  "type": "public-key"
}"#,
        )
        .expect("dummy passkey register credential should deserialize in tests")
    }

    fn successful_passkey_register_credential() -> RegisterPublicKeyCredential {
        serde_json::from_str(
            r#"{
  "id": "success-register-credential",
  "rawId": "AQID",
  "response": {
    "attestationObject": "",
    "clientDataJSON": "",
    "transports": null
  },
  "extensions": {},
  "type": "public-key"
}"#,
        )
        .expect("successful passkey register credential should deserialize in tests")
    }

    fn dummy_passkey() -> Passkey {
        serde_json::from_str(
            r#"{
  "cred": {
    "cred_id": "AQID",
    "cred": {
      "type_": "EDDSA",
      "key": {
        "EC_OKP": {
          "curve": "ED25519",
          "x": ""
        }
      }
    },
    "counter": 0,
    "transports": null,
    "user_verified": true,
    "backup_eligible": false,
    "backup_state": false,
    "registration_policy": "required",
    "extensions": {},
    "attestation": {
      "data": "None",
      "metadata": "None"
    },
    "attestation_format": "none"
  }
}"#,
        )
        .expect("dummy passkey should deserialize in tests")
    }

    fn totp_code_for_step(secret: &[u8], step: u64) -> Option<String> {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).ok()?;
        mac.update(&step.to_be_bytes());
        let digest = mac.finalize().into_bytes();

        let offset = (digest[19] & 0x0f) as usize;
        if offset + 3 >= digest.len() {
            return None;
        }

        let binary = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);

        Some(format!("{:06}", binary % 1_000_000))
    }
}
