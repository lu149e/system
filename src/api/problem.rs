use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_url: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub trace_id: String,
}

pub struct ApiProblem {
    pub status: StatusCode,
    pub body: ProblemDetails,
    pub retry_after_seconds: Option<i64>,
}

impl IntoResponse for ApiProblem {
    fn into_response(self) -> axum::response::Response {
        let status = self.status;
        let mut response = (status, Json(self.body)).into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );

        if let Some(retry_after_seconds) = self.retry_after_seconds {
            if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, value);
            }
        }

        response
    }
}

pub fn from_auth_error(
    err: crate::modules::auth::application::AuthError,
    trace_id: String,
) -> ApiProblem {
    use crate::modules::auth::application::AuthError;

    let (status, title, detail, type_url, retry_after_seconds) = match err {
        AuthError::WeakPassword => (
            StatusCode::BAD_REQUEST,
            "Weak password".to_string(),
            "Password does not meet security policy".to_string(),
            "https://example.com/problems/weak-password".to_string(),
            None,
        ),
        AuthError::InvalidVerificationToken => (
            StatusCode::BAD_REQUEST,
            "Invalid verification token".to_string(),
            "Verification token is invalid or expired".to_string(),
            "https://example.com/problems/invalid-verification-token".to_string(),
            None,
        ),
        AuthError::InvalidPasswordResetToken => (
            StatusCode::BAD_REQUEST,
            "Invalid password reset token".to_string(),
            "Password reset token is invalid or expired".to_string(),
            "https://example.com/problems/invalid-password-reset-token".to_string(),
            None,
        ),
        AuthError::InvalidCurrentPassword => (
            StatusCode::BAD_REQUEST,
            "Invalid current password".to_string(),
            "Current password is invalid".to_string(),
            "https://example.com/problems/invalid-current-password".to_string(),
            None,
        ),
        AuthError::InvalidMfaChallenge => (
            StatusCode::UNAUTHORIZED,
            "Invalid MFA challenge".to_string(),
            "MFA challenge is invalid or expired".to_string(),
            "https://example.com/problems/invalid-mfa-challenge".to_string(),
            None,
        ),
        AuthError::InvalidMfaCode => (
            StatusCode::UNAUTHORIZED,
            "Invalid MFA code".to_string(),
            "Provided MFA verification code is invalid".to_string(),
            "https://example.com/problems/invalid-mfa-code".to_string(),
            None,
        ),
        AuthError::MfaEnrollmentNotFound => (
            StatusCode::NOT_FOUND,
            "MFA enrollment not found".to_string(),
            "No MFA enrollment is pending for this user".to_string(),
            "https://example.com/problems/mfa-enrollment-not-found".to_string(),
            None,
        ),
        AuthError::MfaAlreadyEnabled => (
            StatusCode::CONFLICT,
            "MFA already enabled".to_string(),
            "MFA is already enabled for this account".to_string(),
            "https://example.com/problems/mfa-already-enabled".to_string(),
            None,
        ),
        AuthError::MfaNotEnabled => (
            StatusCode::FORBIDDEN,
            "MFA not enabled".to_string(),
            "MFA is not enabled for this account".to_string(),
            "https://example.com/problems/mfa-not-enabled".to_string(),
            None,
        ),
        AuthError::PasskeyDisabled => (
            StatusCode::FORBIDDEN,
            "Passkey disabled".to_string(),
            "Passkey authentication is not enabled for this service".to_string(),
            "https://example.com/problems/passkey-disabled".to_string(),
            None,
        ),
        AuthError::InvalidPasskeyChallenge => (
            StatusCode::UNAUTHORIZED,
            "Invalid passkey challenge".to_string(),
            "Passkey challenge is invalid or expired".to_string(),
            "https://example.com/problems/invalid-passkey-challenge".to_string(),
            None,
        ),
        AuthError::InvalidPasskeyResponse => (
            StatusCode::UNAUTHORIZED,
            "Invalid passkey response".to_string(),
            "Provided passkey response is invalid".to_string(),
            "https://example.com/problems/invalid-passkey-response".to_string(),
            None,
        ),
        AuthError::SessionNotFound => (
            StatusCode::NOT_FOUND,
            "Session not found".to_string(),
            "Session does not exist".to_string(),
            "https://example.com/problems/session-not-found".to_string(),
            None,
        ),
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            "Invalid credentials".to_string(),
            "Authentication failed".to_string(),
            "https://example.com/problems/invalid-credentials".to_string(),
            None,
        ),
        AuthError::LoginLocked {
            retry_after_seconds,
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            "Login temporarily locked".to_string(),
            format!(
                "Too many failed attempts. Retry in {} seconds",
                retry_after_seconds
            ),
            "https://example.com/problems/login-locked".to_string(),
            Some(retry_after_seconds),
        ),
        AuthError::AccountNotActive => (
            StatusCode::UNAUTHORIZED,
            "Invalid credentials".to_string(),
            "Authentication failed".to_string(),
            "https://example.com/problems/invalid-credentials".to_string(),
            None,
        ),
        AuthError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            "Invalid token".to_string(),
            "Provided token is invalid".to_string(),
            "https://example.com/problems/invalid-token".to_string(),
            None,
        ),
        AuthError::TokenExpired => (
            StatusCode::UNAUTHORIZED,
            "Token expired".to_string(),
            "Provided token is expired".to_string(),
            "https://example.com/problems/token-expired".to_string(),
            None,
        ),
        AuthError::RefreshReuseDetected => (
            StatusCode::UNAUTHORIZED,
            "Refresh token reuse detected".to_string(),
            "Session family has been revoked due to replay detection".to_string(),
            "https://example.com/problems/refresh-reuse".to_string(),
            None,
        ),
        AuthError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
            "Unexpected server error".to_string(),
            "https://example.com/problems/internal-error".to_string(),
            None,
        ),
    };

    crate::observability::record_problem_response(status.as_u16(), &type_url);

    ApiProblem {
        status,
        retry_after_seconds,
        body: ProblemDetails {
            type_url,
            title,
            status: status.as_u16(),
            detail,
            trace_id,
        },
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        http::{header, StatusCode},
        response::IntoResponse,
    };

    use super::from_auth_error;
    use crate::modules::auth::application::AuthError;

    #[test]
    fn invalid_mfa_challenge_maps_to_expected_problem_contract() {
        let problem = from_auth_error(
            AuthError::InvalidMfaChallenge,
            "trace-mfa-challenge".to_string(),
        );

        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem.body.status, 401);
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-mfa-challenge"
        );
        assert_eq!(problem.body.trace_id, "trace-mfa-challenge");
        assert_eq!(problem.retry_after_seconds, None);
    }

    #[test]
    fn invalid_mfa_code_maps_to_expected_problem_contract() {
        let problem = from_auth_error(AuthError::InvalidMfaCode, "trace-mfa-code".to_string());

        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem.body.status, 401);
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-mfa-code"
        );
        assert_eq!(problem.body.trace_id, "trace-mfa-code");
        assert_eq!(problem.retry_after_seconds, None);
    }

    #[test]
    fn login_locked_response_sets_retry_after_header() {
        let response = from_auth_error(
            AuthError::LoginLocked {
                retry_after_seconds: 90,
            },
            "trace-login-locked".to_string(),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&axum::http::HeaderValue::from_static(
                "application/problem+json"
            ))
        );
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("90"))
        );
    }

    #[test]
    fn account_not_active_maps_to_generic_invalid_credentials_contract() {
        let problem = from_auth_error(
            AuthError::AccountNotActive,
            "trace-account-not-active".to_string(),
        );

        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem.body.status, 401);
        assert_eq!(problem.body.title, "Invalid credentials");
        assert_eq!(problem.body.detail, "Authentication failed");
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-credentials"
        );
    }

    #[test]
    fn passkey_disabled_maps_to_expected_problem_contract() {
        let problem = from_auth_error(
            AuthError::PasskeyDisabled,
            "trace-passkey-disabled".to_string(),
        );

        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        assert_eq!(problem.body.status, 403);
        assert_eq!(problem.body.title, "Passkey disabled");
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/passkey-disabled"
        );
    }

    #[test]
    fn invalid_passkey_challenge_maps_to_expected_problem_contract() {
        let problem = from_auth_error(
            AuthError::InvalidPasskeyChallenge,
            "trace-passkey-challenge".to_string(),
        );

        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem.body.status, 401);
        assert_eq!(problem.body.title, "Invalid passkey challenge");
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-passkey-challenge"
        );
    }

    #[test]
    fn invalid_passkey_response_maps_to_expected_problem_contract() {
        let problem = from_auth_error(
            AuthError::InvalidPasskeyResponse,
            "trace-passkey-response".to_string(),
        );

        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem.body.status, 401);
        assert_eq!(problem.body.title, "Invalid passkey response");
        assert_eq!(
            problem.body.type_url,
            "https://example.com/problems/invalid-passkey-response"
        );
    }
}
