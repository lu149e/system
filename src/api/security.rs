use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;

use crate::{
    api::problem::{ApiProblem, ProblemDetails},
    AppState,
};

const INSECURE_TRANSPORT_TYPE_URL: &str = "https://example.com/problems/insecure-transport";

pub async fn enforce_secure_transport(
    State(state): State<AppState>,
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if !state.enforce_secure_transport {
        return next.run(request).await;
    }

    let path = request.uri().path();
    if path != "/v1/auth" && !path.starts_with("/v1/auth/") {
        return next.run(request).await;
    }

    let forwarded_proto = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok());

    if request_uses_secure_transport(
        forwarded_proto,
        connect_addr.ip(),
        state.trust_x_forwarded_for,
        &state.trusted_proxy_ips,
        &state.trusted_proxy_cidrs,
    ) {
        return next.run(request).await;
    }

    let trace_id = trace_id_from_headers(request.headers());
    crate::observability::record_problem_response(
        StatusCode::BAD_REQUEST.as_u16(),
        INSECURE_TRANSPORT_TYPE_URL,
    );

    ApiProblem {
        status: StatusCode::BAD_REQUEST,
        retry_after_seconds: None,
        body: ProblemDetails {
            type_url: INSECURE_TRANSPORT_TYPE_URL.to_string(),
            title: "Insecure transport".to_string(),
            status: StatusCode::BAD_REQUEST.as_u16(),
            detail: "Authentication endpoints require HTTPS termination by a trusted proxy"
                .to_string(),
            trace_id,
        },
    }
    .into_response()
}

fn request_uses_secure_transport(
    forwarded_proto_header: Option<&str>,
    proxy_ip: IpAddr,
    trust_x_forwarded_for: bool,
    trusted_proxy_ips: &[IpAddr],
    trusted_proxy_cidrs: &[IpNet],
) -> bool {
    if !trust_x_forwarded_for {
        return false;
    }

    if !is_trusted_proxy(proxy_ip, trusted_proxy_ips, trusted_proxy_cidrs) {
        return false;
    }

    let Some(forwarded_proto_header) = forwarded_proto_header else {
        return false;
    };

    forwarded_proto_header
        .split(',')
        .next()
        .map(|value| value.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
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

fn trace_id_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use ipnet::IpNet;

    use super::request_uses_secure_transport;

    #[test]
    fn secure_transport_requires_trusted_forwarded_proxy_mode() {
        let result = request_uses_secure_transport(
            Some("https"),
            IpAddr::from_str("10.0.0.10").expect("ip should parse"),
            false,
            &[IpAddr::from_str("10.0.0.10").expect("ip should parse")],
            &[],
        );

        assert!(!result);
    }

    #[test]
    fn secure_transport_rejects_untrusted_proxy_even_when_proto_is_https() {
        let result = request_uses_secure_transport(
            Some("https"),
            IpAddr::from_str("10.0.0.10").expect("ip should parse"),
            true,
            &[IpAddr::from_str("10.0.0.11").expect("ip should parse")],
            &[],
        );

        assert!(!result);
    }

    #[test]
    fn secure_transport_accepts_https_from_trusted_proxy_ip() {
        let result = request_uses_secure_transport(
            Some("https"),
            IpAddr::from_str("10.0.0.10").expect("ip should parse"),
            true,
            &[IpAddr::from_str("10.0.0.10").expect("ip should parse")],
            &[],
        );

        assert!(result);
    }

    #[test]
    fn secure_transport_accepts_https_when_proxy_matches_trusted_cidr() {
        let result = request_uses_secure_transport(
            Some("https, http"),
            IpAddr::from_str("10.1.5.12").expect("ip should parse"),
            true,
            &[],
            &[IpNet::from_str("10.1.0.0/16").expect("cidr should parse")],
        );

        assert!(result);
    }

    #[test]
    fn secure_transport_rejects_non_https_forwarded_proto() {
        let result = request_uses_secure_transport(
            Some("http"),
            IpAddr::from_str("10.0.0.10").expect("ip should parse"),
            true,
            &[IpAddr::from_str("10.0.0.10").expect("ip should parse")],
            &[],
        );

        assert!(!result);
    }
}
