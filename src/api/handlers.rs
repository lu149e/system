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

use crate::{
    api::problem::{from_auth_error, ApiProblem, ProblemDetails},
    health::ComponentState,
    modules::auth::application::{
        AuthError, LoginCommand, LoginResult, LogoutCommand, MfaActivateCommand, MfaDisableCommand,
        MfaVerifyCommand, PasswordChangeCommand, PasswordForgotCommand, PasswordResetCommand,
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
    }
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
    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    use crate::{
        adapters::{
            inmemory::{InMemoryAdapters, JwtEdDsaService, RefreshCryptoHmacService},
            postgres::PostgresAdapters,
        },
        config::{
            AppConfig, AuthRuntime, JwtKeyConfig, LoginAbuseBucketMode, LoginAbuseRedisFailMode,
        },
        modules::auth::application::{
            AuthError, AuthService, LoginCommand, LoginResult, MfaActivateCommand, RequestContext,
        },
        modules::tokens::{domain::AccessTokenClaims, ports::JwtService},
        AppState,
    };

    use super::{LoginRequest, MfaVerifyRequest, RefreshRequest};

    type HmacSha1 = Hmac<Sha1>;

    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIMn3Wcxxd4JzzjbshVFXz8jSGuF9ErqngPTzYhbfm6hd\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdIROjbNDN9NHACJMCdMbdRjmUZp05u0E+QVRzrqB6eM=\n-----END PUBLIC KEY-----\n";
    const TEST_PRIVATE_KEY_PEM_V2: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHKXEA5E1r7pR80Ucu171MabNn+ku13GSavWIB/BKqmv\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY_PEM_V2: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA3Pt04RjQQMO4XZTq01rN87smwi6wkOTzBX7P5z6DI/M=\n-----END PUBLIC KEY-----\n";

    struct HandlerHarness {
        state: AppState,
        bootstrap_email: String,
        bootstrap_password: String,
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

        let auth_service = Arc::new(
            AuthService::new(
                Arc::new(adapters.users),
                Arc::new(adapters.login_abuse),
                Arc::new(adapters.verification_tokens),
                Arc::new(adapters.password_reset_tokens),
                Arc::new(adapters.mfa_factors),
                Arc::new(adapters.mfa_challenges),
                Arc::new(adapters.mfa_backup_codes),
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
                readiness_checker: crate::health::RuntimeReadinessChecker::inmemory(),
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
        cfg.bootstrap_user_password = Some("StartPass!1234".to_string());
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
            Arc::new(adapters.verification_tokens),
            Arc::new(adapters.password_reset_tokens),
            Arc::new(adapters.mfa_factors),
            Arc::new(adapters.mfa_challenges),
            Arc::new(adapters.mfa_backup_codes),
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
            mfa_encryption_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string(),
            bootstrap_user_email: Some("bootstrap@example.com".to_string()),
            bootstrap_user_password: Some("StartPass!1234".to_string()),
            login_max_attempts: 5,
            login_attempt_window_seconds: 300,
            login_lockout_seconds: 900,
            login_lockout_max_seconds: 7200,
            login_abuse_attempts_prefix: "handler:test:attempts".to_string(),
            login_abuse_lock_prefix: "handler:test:lock".to_string(),
            login_abuse_strikes_prefix: "handler:test:strikes".to_string(),
            login_abuse_redis_fail_mode: LoginAbuseRedisFailMode::FailClosed,
            login_abuse_bucket_mode: LoginAbuseBucketMode::EmailAndIp,
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
