use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Revoked,
    Compromised,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub device_info: Option<String>,
    pub ip: Option<String>,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}
