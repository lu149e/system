use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub actor_user_id: Option<String>,
    pub trace_id: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}
