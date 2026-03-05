use async_trait::async_trait;
use rand::Rng;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::{
    config::SendGridEmailProviderConfig, modules::auth::ports::TransactionalEmailSender,
    observability,
};

#[derive(Default)]
pub struct NoopTransactionalEmailSender;

#[async_trait]
impl TransactionalEmailSender for NoopTransactionalEmailSender {
    async fn send_verification_email(
        &self,
        _recipient_email: &str,
        _verification_token: &str,
        _expires_in_seconds: i64,
    ) -> Result<(), String> {
        observability::record_email_delivery("noop", "verification", true, Duration::from_secs(0));
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        _recipient_email: &str,
        _reset_token: &str,
        _expires_in_seconds: i64,
    ) -> Result<(), String> {
        observability::record_email_delivery(
            "noop",
            "password_reset",
            true,
            Duration::from_secs(0),
        );
        Ok(())
    }
}

pub struct SendGridTransactionalEmailSender {
    http: Client,
    config: SendGridEmailProviderConfig,
    jitter_sampler: JitterSampler,
}

type JitterSampler = Arc<dyn Fn(u64, u64) -> u64 + Send + Sync>;

impl SendGridTransactionalEmailSender {
    pub fn new(config: SendGridEmailProviderConfig) -> Result<Self, String> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| format!("failed to initialize sendgrid http client: {error}"))?;

        Ok(Self {
            http,
            config,
            jitter_sampler: Arc::new(sample_uniform_jitter),
        })
    }

    #[cfg(test)]
    fn new_with_jitter_sampler(
        config: SendGridEmailProviderConfig,
        jitter_sampler: JitterSampler,
    ) -> Result<Self, String> {
        let mut sender = Self::new(config)?;
        sender.jitter_sampler = jitter_sampler;
        Ok(sender)
    }

    async fn send_email(
        &self,
        template: &'static str,
        recipient_email: &str,
        subject: &str,
        body_text: String,
    ) -> Result<(), String> {
        let started_at = Instant::now();
        let mut attempts = 0_u32;
        let max_attempts = self.config.max_retries.saturating_add(1);

        loop {
            attempts += 1;
            match self
                .send_email_once(recipient_email, subject, body_text.as_str())
                .await
            {
                Ok(()) => {
                    observability::record_email_retry_intensity(
                        "sendgrid",
                        template,
                        true,
                        attempts.saturating_sub(1),
                    );
                    observability::record_email_delivery(
                        "sendgrid",
                        template,
                        true,
                        started_at.elapsed(),
                    );
                    return Ok(());
                }
                Err(AttemptError::NonRetryable(message)) => {
                    observability::record_email_retry_intensity(
                        "sendgrid",
                        template,
                        false,
                        attempts.saturating_sub(1),
                    );
                    observability::record_email_delivery(
                        "sendgrid",
                        template,
                        false,
                        started_at.elapsed(),
                    );
                    return Err(message);
                }
                Err(AttemptError::Retryable(message)) => {
                    if attempts >= max_attempts {
                        observability::record_email_retry_intensity(
                            "sendgrid",
                            template,
                            false,
                            attempts.saturating_sub(1),
                        );
                        observability::record_email_delivery(
                            "sendgrid",
                            template,
                            false,
                            started_at.elapsed(),
                        );
                        return Err(format!(
                            "sendgrid delivery failed after {} attempts: {message}",
                            attempts
                        ));
                    }

                    let backoff = self.retry_backoff(attempts);
                    tracing::warn!(
                        template,
                        attempt = attempts,
                        retry_in_ms = backoff.as_millis(),
                        error = %message,
                        "sendgrid retryable email failure"
                    );
                    sleep(backoff).await;
                }
            }
        }
    }

    async fn send_email_once(
        &self,
        recipient_email: &str,
        subject: &str,
        body_text: &str,
    ) -> Result<(), AttemptError> {
        let endpoint = format!("{}/v3/mail/send", self.config.api_base_url);
        let payload = SendGridMailRequest {
            personalizations: vec![SendGridPersonalization {
                to: vec![SendGridEmailAddress {
                    email: recipient_email,
                }],
            }],
            from: SendGridFromAddress {
                email: self.config.from_email.as_str(),
                name: self.config.from_name.as_deref(),
            },
            subject,
            content: vec![SendGridContent {
                content_type: "text/plain",
                value: body_text,
            }],
        };

        let response = self
            .http
            .post(endpoint)
            .bearer_auth(&self.config.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|error| {
                AttemptError::Retryable(format!("sendgrid request failed: {error}"))
            })?;

        if response.status() == StatusCode::ACCEPTED {
            return Ok(());
        }

        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());

        let message = format!("sendgrid rejected email request with status {status}: {body}");
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(AttemptError::Retryable(message));
        }

        Err(AttemptError::NonRetryable(message))
    }

    fn retry_backoff(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(10);
        let exponential_multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let base_backoff_ms = self
            .config
            .retry_base_delay_ms
            .saturating_mul(exponential_multiplier)
            .min(self.config.retry_max_delay_ms);
        let jitter_range_ms =
            base_backoff_ms.saturating_mul(u64::from(self.config.retry_jitter_percent)) / 100;
        let lower_bound_ms = base_backoff_ms.saturating_sub(jitter_range_ms);
        let upper_bound_ms = base_backoff_ms
            .saturating_add(jitter_range_ms)
            .min(self.config.retry_max_delay_ms);
        let sampled_backoff_ms = if lower_bound_ms >= upper_bound_ms {
            lower_bound_ms
        } else {
            (self.jitter_sampler)(lower_bound_ms, upper_bound_ms)
                .clamp(lower_bound_ms, upper_bound_ms)
        };

        Duration::from_millis(sampled_backoff_ms)
    }
}

fn sample_uniform_jitter(lower_bound_ms: u64, upper_bound_ms: u64) -> u64 {
    rand::thread_rng().gen_range(lower_bound_ms..=upper_bound_ms)
}

enum AttemptError {
    Retryable(String),
    NonRetryable(String),
}

#[async_trait]
impl TransactionalEmailSender for SendGridTransactionalEmailSender {
    async fn send_verification_email(
        &self,
        recipient_email: &str,
        verification_token: &str,
        expires_in_seconds: i64,
    ) -> Result<(), String> {
        let verification_link = append_token_query(
            &self.config.verify_email_url_base,
            verification_token,
            "token",
        );
        let body = format!(
            "Verify your account by opening this link: {verification_link}\n\nThis link expires in {expires_in_seconds} seconds."
        );
        self.send_email("verification", recipient_email, "Verify your email", body)
            .await
    }

    async fn send_password_reset_email(
        &self,
        recipient_email: &str,
        reset_token: &str,
        expires_in_seconds: i64,
    ) -> Result<(), String> {
        let reset_link =
            append_token_query(&self.config.password_reset_url_base, reset_token, "token");
        let body = format!(
            "Reset your password by opening this link: {reset_link}\n\nThis link expires in {expires_in_seconds} seconds."
        );
        self.send_email(
            "password_reset",
            recipient_email,
            "Reset your password",
            body,
        )
        .await
    }
}

#[derive(Serialize)]
struct SendGridMailRequest<'a> {
    personalizations: Vec<SendGridPersonalization<'a>>,
    from: SendGridFromAddress<'a>,
    subject: &'a str,
    content: Vec<SendGridContent<'a>>,
}

#[derive(Serialize)]
struct SendGridPersonalization<'a> {
    to: Vec<SendGridEmailAddress<'a>>,
}

#[derive(Serialize)]
struct SendGridEmailAddress<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct SendGridFromAddress<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Serialize)]
struct SendGridContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    value: &'a str,
}

fn append_token_query(base_url: &str, token: &str, token_query_param: &str) -> String {
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!(
        "{base_url}{separator}{token_query_param}={}",
        urlencoding::encode(token)
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::{mpsc, oneshot},
    };

    use super::{SendGridTransactionalEmailSender, TransactionalEmailSender};
    use crate::config::SendGridEmailProviderConfig;

    #[tokio::test]
    async fn sendgrid_shapes_verification_request_payload() {
        let (server_url, request_rx) = spawn_capture_server("HTTP/1.1 202 Accepted\r\n\r\n").await;
        let sender = SendGridTransactionalEmailSender::new(test_sendgrid_config(server_url))
            .expect("sendgrid sender should initialize");

        sender
            .send_verification_email("user@example.com", "verification-token", 3600)
            .await
            .expect("sendgrid adapter should accept 202 responses");

        let captured = request_rx
            .await
            .expect("mock server should capture sendgrid request");
        assert!(captured.starts_with("POST /v3/mail/send HTTP/1.1\r\n"));
        assert!(captured
            .to_ascii_lowercase()
            .contains("authorization: bearer sendgrid-test-key\r\n"));

        let body = request_body(&captured);
        let payload: Value = serde_json::from_str(body).expect("request body should be valid json");
        assert_eq!(
            payload["personalizations"][0]["to"][0]["email"],
            Value::String("user@example.com".to_string())
        );
        assert_eq!(
            payload["from"]["email"],
            Value::String("noreply@example.com".to_string())
        );
        assert_eq!(
            payload["subject"],
            Value::String("Verify your email".to_string())
        );
        assert!(payload["content"][0]["value"]
            .as_str()
            .expect("content value should be string")
            .contains("https://app.example.com/verify-email?token=verification-token"));
    }

    #[tokio::test]
    async fn sendgrid_surfaces_non_accepted_responses() {
        let (server_url, _request_rx) =
            spawn_capture_server("HTTP/1.1 401 Unauthorized\r\nContent-Length: 3\r\n\r\nbad").await;
        let mut config = test_sendgrid_config(server_url);
        config.max_retries = 1;
        let sender = SendGridTransactionalEmailSender::new(config)
            .expect("sendgrid sender should initialize");

        let error = sender
            .send_password_reset_email("user@example.com", "reset-token", 1200)
            .await
            .expect_err("non-202 responses should return an error");

        assert!(error.contains("status 401 Unauthorized"));
    }

    #[tokio::test]
    async fn sendgrid_retries_retryable_failure_then_succeeds() {
        let (server_url, requests_rx) = spawn_sequence_server(vec![
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nbad",
            "HTTP/1.1 202 Accepted\r\n\r\n",
        ])
        .await;

        let mut config = test_sendgrid_config(server_url);
        config.max_retries = 2;
        config.retry_base_delay_ms = 1;
        config.retry_max_delay_ms = 2;
        let sender = SendGridTransactionalEmailSender::new(config)
            .expect("sendgrid sender should initialize");

        sender
            .send_verification_email("user@example.com", "verification-token", 3600)
            .await
            .expect("retryable error should be retried until success");

        let requests = requests_rx
            .await
            .expect("server should capture all requests");
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn sendgrid_stops_after_retry_budget_exhausted() {
        let (server_url, requests_rx) = spawn_sequence_server(vec![
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\n\r\nslow",
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\n\r\nslow",
        ])
        .await;

        let mut config = test_sendgrid_config(server_url);
        config.max_retries = 1;
        config.retry_base_delay_ms = 1;
        config.retry_max_delay_ms = 1;
        let sender = SendGridTransactionalEmailSender::new(config)
            .expect("sendgrid sender should initialize");

        let error = sender
            .send_password_reset_email("user@example.com", "reset-token", 1200)
            .await
            .expect_err("retry budget exhaustion should return error");

        assert!(error.contains("failed after 2 attempts"));
        let requests = requests_rx
            .await
            .expect("server should capture requests before stop");
        assert_eq!(requests.len(), 2);
    }

    fn test_sendgrid_config(api_base_url: String) -> SendGridEmailProviderConfig {
        SendGridEmailProviderConfig {
            api_base_url,
            api_key: "sendgrid-test-key".to_string(),
            from_email: "noreply@example.com".to_string(),
            from_name: Some("Auth API".to_string()),
            verify_email_url_base: "https://app.example.com/verify-email".to_string(),
            password_reset_url_base: "https://app.example.com/reset-password".to_string(),
            timeout_ms: 1_000,
            max_retries: 2,
            retry_base_delay_ms: 5,
            retry_max_delay_ms: 20,
            retry_jitter_percent: 20,
        }
    }

    #[test]
    fn sendgrid_retry_backoff_uses_injected_jitter_sampler_deterministically() {
        let mut config = test_sendgrid_config("http://127.0.0.1:65535".to_string());
        config.retry_base_delay_ms = 200;
        config.retry_max_delay_ms = 2_000;
        config.retry_jitter_percent = 25;
        let sender = SendGridTransactionalEmailSender::new_with_jitter_sampler(
            config,
            Arc::new(|_lower, upper| upper),
        )
        .expect("sender should initialize for deterministic jitter test");

        assert_eq!(sender.retry_backoff(1), Duration::from_millis(250));
        assert_eq!(sender.retry_backoff(4), Duration::from_millis(2_000));
    }

    #[test]
    fn sendgrid_retry_backoff_clamps_out_of_range_injected_jitter_value() {
        let mut config = test_sendgrid_config("http://127.0.0.1:65535".to_string());
        config.retry_base_delay_ms = 400;
        config.retry_max_delay_ms = 2_000;
        config.retry_jitter_percent = 50;
        let sender = SendGridTransactionalEmailSender::new_with_jitter_sampler(
            config,
            Arc::new(|_lower, upper| upper.saturating_add(999)),
        )
        .expect("sender should initialize for jitter clamp test");

        assert_eq!(sender.retry_backoff(1), Duration::from_millis(600));
    }

    #[test]
    fn sendgrid_retry_backoff_is_unchanged_when_jitter_is_disabled() {
        let mut config = test_sendgrid_config("http://127.0.0.1:65535".to_string());
        config.retry_base_delay_ms = 200;
        config.retry_max_delay_ms = 2_000;
        config.retry_jitter_percent = 0;
        let sender = SendGridTransactionalEmailSender::new_with_jitter_sampler(
            config,
            Arc::new(|_lower, upper| upper),
        )
        .expect("sender should initialize for no-jitter test");

        assert_eq!(sender.retry_backoff(1), Duration::from_millis(200));
        assert_eq!(sender.retry_backoff(2), Duration::from_millis(400));
    }

    async fn spawn_capture_server(response: &str) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let address = listener
            .local_addr()
            .expect("test listener should expose local addr");
        let response = response.as_bytes().to_vec();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .expect("test listener should accept one request");
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];

            loop {
                let bytes = socket
                    .read(&mut buffer)
                    .await
                    .expect("request read should succeed");
                if bytes == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes]);
                if request_contains_full_http_payload(&request) {
                    break;
                }
            }

            let captured = String::from_utf8(request).expect("request should be utf8 for test");
            let _ = tx.send(captured);
            socket
                .write_all(&response)
                .await
                .expect("response write should succeed");
        });

        (format!("http://{address}"), rx)
    }

    async fn spawn_sequence_server(
        responses: Vec<&str>,
    ) -> (String, oneshot::Receiver<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let address = listener
            .local_addr()
            .expect("test listener should expose local addr");
        let response_payloads = responses
            .into_iter()
            .map(|response| response.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let expected_requests = response_payloads.len();
            let (request_tx, mut request_rx) = mpsc::channel(expected_requests);

            for response in response_payloads {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .expect("test listener should accept request");
                let request_tx = request_tx.clone();

                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];

                    loop {
                        let bytes = socket
                            .read(&mut buffer)
                            .await
                            .expect("request read should succeed");
                        if bytes == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..bytes]);
                        if request_contains_full_http_payload(&request) {
                            break;
                        }
                    }

                    let captured =
                        String::from_utf8(request).expect("request should be utf8 for test");
                    request_tx
                        .send(captured)
                        .await
                        .expect("request should be sent to collector");
                    socket
                        .write_all(&response)
                        .await
                        .expect("response write should succeed");
                })
                .await
                .expect("request handling task should complete");
            }

            drop(request_tx);
            let mut captured_requests = Vec::with_capacity(expected_requests);
            while let Some(request) = request_rx.recv().await {
                captured_requests.push(request);
            }
            let _ = tx.send(captured_requests);
        });

        (format!("http://{address}"), rx)
    }

    fn request_contains_full_http_payload(request: &[u8]) -> bool {
        let Some(headers_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let body_start = headers_end + 4;
        let header_text = String::from_utf8_lossy(&request[..headers_end]);
        let content_length = header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        request.len() >= body_start + content_length
    }

    fn request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("request should contain headers and body")
    }
}
