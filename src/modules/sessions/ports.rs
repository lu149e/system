use async_trait::async_trait;

use crate::modules::sessions::domain::Session;

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(&self, session: Session);
    async fn find_by_id(&self, session_id: &str) -> Option<Session>;
    async fn list_active_for_user(&self, user_id: &str) -> Vec<Session>;
    async fn update(&self, session: Session);
    async fn revoke_session(&self, session_id: &str);
    async fn revoke_all_for_user(&self, user_id: &str) -> Vec<String>;
    async fn mark_compromised_and_revoke_all_for_user(&self, user_id: &str) -> Vec<String>;
}
