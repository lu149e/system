use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::modules::tokens::domain::{AccessTokenClaims, RefreshTokenRecord};

#[async_trait]
pub trait JwtService: Send + Sync {
    async fn issue_access_token(&self, claims: &AccessTokenClaims) -> Result<String, String>;
    async fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims, String>;
}

#[async_trait]
pub trait RefreshCryptoService: Send + Sync {
    async fn generate_refresh_token(&self) -> String;
    async fn hash_refresh_token(&self, token: &str) -> String;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn insert(&self, token: RefreshTokenRecord);
    async fn find_by_hash(&self, token_hash: &str) -> Option<RefreshTokenRecord>;
    async fn rotate_strong(
        &self,
        current_hash: &str,
        next_token: RefreshTokenRecord,
        now: DateTime<Utc>,
    ) -> Result<RefreshRotationState, String>;
    async fn rotate(
        &self,
        current_hash: &str,
        next_token: RefreshTokenRecord,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), String>;
    async fn revoke_by_session_ids(&self, session_ids: &[String], revoked_at: DateTime<Utc>);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshRotationState {
    Rotated,
    NotFound,
    AlreadyRevoked,
    Expired,
}
