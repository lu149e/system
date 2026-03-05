use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use std::{net::IpAddr, str::FromStr};

use crate::modules::auth::ports::{LoginRiskAnalyzer, LoginRiskDecision};

#[derive(Debug, Default)]
pub struct AllowAllLoginRiskAnalyzer;

#[async_trait]
impl LoginRiskAnalyzer for AllowAllLoginRiskAnalyzer {
    async fn evaluate_login(
        &self,
        _email: &str,
        _user_id: &str,
        _source_ip: Option<&str>,
        _user_agent: Option<&str>,
        _now: DateTime<Utc>,
    ) -> LoginRiskDecision {
        LoginRiskDecision::Allow
    }
}

#[derive(Debug, Default)]
pub struct ConfigurableLoginRiskAnalyzer {
    blocked_source_cidrs: Vec<IpNet>,
    blocked_user_agent_substrings: Vec<String>,
    blocked_email_domains: Vec<String>,
    challenge_source_cidrs: Vec<IpNet>,
    challenge_user_agent_substrings: Vec<String>,
    challenge_email_domains: Vec<String>,
}

impl ConfigurableLoginRiskAnalyzer {
    pub fn new(
        blocked_source_cidrs: Vec<IpNet>,
        blocked_user_agent_substrings: Vec<String>,
        blocked_email_domains: Vec<String>,
        challenge_source_cidrs: Vec<IpNet>,
        challenge_user_agent_substrings: Vec<String>,
        challenge_email_domains: Vec<String>,
    ) -> Self {
        Self {
            blocked_source_cidrs,
            blocked_user_agent_substrings: blocked_user_agent_substrings
                .into_iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            blocked_email_domains: blocked_email_domains
                .into_iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            challenge_source_cidrs,
            challenge_user_agent_substrings: challenge_user_agent_substrings
                .into_iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            challenge_email_domains: challenge_email_domains
                .into_iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }

    fn email_domain_matches(email: &str, blocked_domain: &str) -> bool {
        email
            .rsplit_once('@')
            .map(|(_, domain)| domain.eq_ignore_ascii_case(blocked_domain))
            .unwrap_or(false)
    }

    fn decision_for(
        &self,
        email: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> LoginRiskDecision {
        if self
            .blocked_email_domains
            .iter()
            .any(|blocked_domain| Self::email_domain_matches(email, blocked_domain))
        {
            return LoginRiskDecision::Block {
                reason: "blocked_email_domain".to_string(),
            };
        }

        if let Some(source_ip) = source_ip {
            if let Ok(parsed_ip) = IpAddr::from_str(source_ip) {
                if self
                    .blocked_source_cidrs
                    .iter()
                    .any(|blocked_cidr| blocked_cidr.contains(&parsed_ip))
                {
                    return LoginRiskDecision::Block {
                        reason: "blocked_source_ip".to_string(),
                    };
                }
            }
        }

        if let Some(user_agent) = user_agent {
            let normalized_user_agent = user_agent.to_ascii_lowercase();
            if self
                .blocked_user_agent_substrings
                .iter()
                .any(|blocked_substring| normalized_user_agent.contains(blocked_substring))
            {
                return LoginRiskDecision::Block {
                    reason: "blocked_user_agent".to_string(),
                };
            }
        }

        if self
            .challenge_email_domains
            .iter()
            .any(|blocked_domain| Self::email_domain_matches(email, blocked_domain))
        {
            return LoginRiskDecision::Challenge {
                reason: "challenge_email_domain".to_string(),
            };
        }

        if let Some(source_ip) = source_ip {
            if let Ok(parsed_ip) = IpAddr::from_str(source_ip) {
                if self
                    .challenge_source_cidrs
                    .iter()
                    .any(|challenge_cidr| challenge_cidr.contains(&parsed_ip))
                {
                    return LoginRiskDecision::Challenge {
                        reason: "challenge_source_ip".to_string(),
                    };
                }
            }
        }

        if let Some(user_agent) = user_agent {
            let normalized_user_agent = user_agent.to_ascii_lowercase();
            if self
                .challenge_user_agent_substrings
                .iter()
                .any(|blocked_substring| normalized_user_agent.contains(blocked_substring))
            {
                return LoginRiskDecision::Challenge {
                    reason: "challenge_user_agent".to_string(),
                };
            }
        }

        LoginRiskDecision::Allow
    }
}

#[async_trait]
impl LoginRiskAnalyzer for ConfigurableLoginRiskAnalyzer {
    async fn evaluate_login(
        &self,
        email: &str,
        _user_id: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
        _now: DateTime<Utc>,
    ) -> LoginRiskDecision {
        self.decision_for(email, source_ip, user_agent)
    }
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;
    use std::str::FromStr;

    use super::ConfigurableLoginRiskAnalyzer;
    use crate::modules::auth::ports::{LoginRiskAnalyzer, LoginRiskDecision};

    #[tokio::test]
    async fn blocks_configured_source_cidr() {
        let analyzer = ConfigurableLoginRiskAnalyzer::new(
            vec![IpNet::from_str("203.0.113.0/24").expect("cidr should parse")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let decision = analyzer
            .evaluate_login(
                "user@example.com",
                "user-1",
                Some("203.0.113.44"),
                Some("Mozilla/5.0"),
                chrono::Utc::now(),
            )
            .await;

        assert_eq!(
            decision,
            LoginRiskDecision::Block {
                reason: "blocked_source_ip".to_string()
            }
        );
    }

    #[tokio::test]
    async fn blocks_configured_user_agent_substring() {
        let analyzer = ConfigurableLoginRiskAnalyzer::new(
            Vec::new(),
            vec!["selenium".to_string()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let decision = analyzer
            .evaluate_login(
                "user@example.com",
                "user-1",
                Some("198.51.100.10"),
                Some("SeleniumBot/1.0"),
                chrono::Utc::now(),
            )
            .await;

        assert_eq!(
            decision,
            LoginRiskDecision::Block {
                reason: "blocked_user_agent".to_string()
            }
        );
    }

    #[tokio::test]
    async fn blocks_configured_email_domain() {
        let analyzer = ConfigurableLoginRiskAnalyzer::new(
            Vec::new(),
            Vec::new(),
            vec!["disposable.example".to_string()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let decision = analyzer
            .evaluate_login(
                "user@disposable.example",
                "user-1",
                Some("198.51.100.10"),
                Some("Mozilla/5.0"),
                chrono::Utc::now(),
            )
            .await;

        assert_eq!(
            decision,
            LoginRiskDecision::Block {
                reason: "blocked_email_domain".to_string()
            }
        );
    }

    #[tokio::test]
    async fn allows_when_no_block_rule_matches() {
        let analyzer = ConfigurableLoginRiskAnalyzer::new(
            vec![IpNet::from_str("203.0.113.0/24").expect("cidr should parse")],
            vec!["selenium".to_string()],
            vec!["disposable.example".to_string()],
            vec![IpNet::from_str("198.18.0.0/15").expect("cidr should parse")],
            vec!["webdriver".to_string()],
            vec!["challenge.example".to_string()],
        );

        let decision = analyzer
            .evaluate_login(
                "user@example.com",
                "user-1",
                Some("198.51.100.10"),
                Some("Mozilla/5.0"),
                chrono::Utc::now(),
            )
            .await;

        assert_eq!(decision, LoginRiskDecision::Allow);
    }

    #[tokio::test]
    async fn challenges_configured_source_cidr() {
        let analyzer = ConfigurableLoginRiskAnalyzer::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![IpNet::from_str("198.51.100.0/24").expect("cidr should parse")],
            Vec::new(),
            Vec::new(),
        );

        let decision = analyzer
            .evaluate_login(
                "user@example.com",
                "user-1",
                Some("198.51.100.10"),
                Some("Mozilla/5.0"),
                chrono::Utc::now(),
            )
            .await;

        assert_eq!(
            decision,
            LoginRiskDecision::Challenge {
                reason: "challenge_source_ip".to_string()
            }
        );
    }

    #[tokio::test]
    async fn block_rules_take_precedence_over_challenge_rules() {
        let analyzer = ConfigurableLoginRiskAnalyzer::new(
            vec![IpNet::from_str("203.0.113.0/24").expect("cidr should parse")],
            Vec::new(),
            Vec::new(),
            vec![IpNet::from_str("203.0.113.0/24").expect("cidr should parse")],
            Vec::new(),
            Vec::new(),
        );

        let decision = analyzer
            .evaluate_login(
                "user@example.com",
                "user-1",
                Some("203.0.113.10"),
                Some("Mozilla/5.0"),
                chrono::Utc::now(),
            )
            .await;

        assert_eq!(
            decision,
            LoginRiskDecision::Block {
                reason: "blocked_source_ip".to_string()
            }
        );
    }
}
