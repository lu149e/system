use std::sync::Arc;

use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn,
};

use crate::modules::auth::ports::PasskeyService;

#[derive(Clone)]
pub struct WebauthnPasskeyService {
    inner: Webauthn,
}

impl WebauthnPasskeyService {
    pub fn new(inner: Webauthn) -> Self {
        Self { inner }
    }
}

impl PasskeyService for WebauthnPasskeyService {
    fn start_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), String> {
        self.inner
            .start_passkey_registration(
                user_unique_id,
                user_name,
                user_display_name,
                exclude_credentials,
            )
            .map_err(|err| err.to_string())
    }

    fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, String> {
        self.inner
            .finish_passkey_registration(credential, state)
            .map_err(|err| err.to_string())
    }

    fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), String> {
        self.inner
            .start_passkey_authentication(passkeys)
            .map_err(|err| err.to_string())
    }

    fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, String> {
        self.inner
            .finish_passkey_authentication(credential, state)
            .map_err(|err| err.to_string())
    }
}

pub fn build_passkey_service(webauthn: Option<Webauthn>) -> Option<Arc<dyn PasskeyService>> {
    webauthn.map(|inner| Arc::new(WebauthnPasskeyService::new(inner)) as Arc<dyn PasskeyService>)
}
