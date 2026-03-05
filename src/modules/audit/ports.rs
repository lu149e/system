use async_trait::async_trait;

use crate::modules::audit::domain::AuditEvent;

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn append(&self, event: AuditEvent);
}
