use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub sid: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub id: String,
    pub session_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<String>,
    pub created_at: DateTime<Utc>,
}
