use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opaque_ke::{
    argon2::Argon2, ciphersuite::CipherSuite, rand::rngs::OsRng, CredentialFinalization,
    CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};
use serde_json::{json, Value};

use crate::{
    config::AuthV2PakeProvider,
    modules::auth::ports::{
        PakeFinishResult, PakeLoginCredentialView, PakeRegistrationFinishResult,
        PakeRegistrationStartRequest, PakeStartRequest, PakeStartResult, PasswordPakeService,
    },
};

const LOGIN_MESSAGE_FIELD: &str = "opaque_message";
const REGISTRATION_MESSAGE_FIELD: &str = "registration_response";
const REGISTRATION_UPLOAD_FIELD: &str = "registration_upload";
const SERVER_STATE_FIELD: &str = "opaque_server_state";
const USER_ID_FIELD: &str = "user_id";
const SERVER_KEY_REF_DEFAULT: &str = "opaque-ke";

struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub fn build_password_pake_service(
    pake_provider: AuthV2PakeProvider,
    opaque_server_setup: Option<&str>,
    opaque_server_key_ref: Option<String>,
) -> anyhow::Result<std::sync::Arc<dyn PasswordPakeService>> {
    match pake_provider {
        AuthV2PakeProvider::Unavailable => Ok(std::sync::Arc::new(UnavailablePasswordPakeService)),
        AuthV2PakeProvider::OpaqueKe => {
            let serialized_setup = opaque_server_setup.ok_or_else(|| {
                anyhow::anyhow!(
                    "opaque-ke server setup is required when AUTH_V2_PAKE_PROVIDER=opaque_ke"
                )
            })?;

            let service = OpaqueKePasswordPakeService::from_base64_server_setup(
                serialized_setup,
                opaque_server_key_ref,
            )?;

            Ok(std::sync::Arc::new(service))
        }
    }
}

#[derive(Clone, Default)]
pub struct UnavailablePasswordPakeService;

#[async_trait]
impl PasswordPakeService for UnavailablePasswordPakeService {
    async fn start_login(
        &self,
        _credential: PakeLoginCredentialView,
        _request: PakeStartRequest,
    ) -> Result<PakeStartResult, String> {
        Err("pake unavailable".to_string())
    }

    async fn finish_login(
        &self,
        _server_state: Value,
        _client_message: Value,
    ) -> Result<PakeFinishResult, String> {
        Err("pake unavailable".to_string())
    }

    async fn start_registration(
        &self,
        _request: PakeRegistrationStartRequest,
    ) -> Result<PakeStartResult, String> {
        Err("pake unavailable".to_string())
    }

    async fn finish_registration(
        &self,
        _server_state: Value,
        _client_message: Value,
    ) -> Result<PakeRegistrationFinishResult, String> {
        Err("pake unavailable".to_string())
    }
}

#[derive(Clone)]
pub struct OpaqueKePasswordPakeService {
    server_setup: ServerSetup<OpaqueCipherSuite>,
    server_key_ref: Option<String>,
}

impl OpaqueKePasswordPakeService {
    pub fn from_base64_server_setup(
        encoded_setup: &str,
        server_key_ref: Option<String>,
    ) -> anyhow::Result<Self> {
        let setup_bytes = decode_base64url(encoded_setup)
            .map_err(|_| anyhow::anyhow!("opaque-ke server setup must be valid base64url"))?;
        let server_setup = ServerSetup::<OpaqueCipherSuite>::deserialize(&setup_bytes)
            .map_err(|_| anyhow::anyhow!("opaque-ke server setup is invalid"))?;

        Ok(Self {
            server_setup,
            server_key_ref: normalize_server_key_ref(server_key_ref),
        })
    }

    #[cfg(test)]
    fn new_for_tests() -> Self {
        let mut rng = OsRng;
        Self {
            server_setup: ServerSetup::<OpaqueCipherSuite>::new(&mut rng),
            server_key_ref: Some("test-server-key".to_string()),
        }
    }

    #[cfg(test)]
    fn server_setup_base64(&self) -> String {
        encode_base64url(self.server_setup.serialize().as_slice())
    }
}

#[async_trait]
impl PasswordPakeService for OpaqueKePasswordPakeService {
    async fn start_login(
        &self,
        credential: PakeLoginCredentialView,
        request: PakeStartRequest,
    ) -> Result<PakeStartResult, String> {
        let credential_request = CredentialRequest::<OpaqueCipherSuite>::deserialize(
            &decode_message_field(&request.request, LOGIN_MESSAGE_FIELD)?,
        )
        .map_err(|_| "invalid pake credential request".to_string())?;

        let password_file = credential
            .opaque_credential
            .as_deref()
            .map(ServerRegistration::<OpaqueCipherSuite>::deserialize)
            .transpose()
            .map_err(|_| "invalid stored opaque credential".to_string())?;

        let credential_identifier = credential_identifier_for_login(&credential, &request.flow_id);
        let mut rng = OsRng;
        let start = ServerLogin::<OpaqueCipherSuite>::start(
            &mut rng,
            &self.server_setup,
            password_file,
            credential_request,
            credential_identifier.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| "invalid pake credential request".to_string())?;

        Ok(PakeStartResult {
            response: json!({
                LOGIN_MESSAGE_FIELD: encode_base64url(start.message.serialize().as_slice()),
            }),
            server_state: json!({
                SERVER_STATE_FIELD: encode_base64url(start.state.serialize().as_slice()),
                USER_ID_FIELD: credential.user_id,
            }),
        })
    }

    async fn finish_login(
        &self,
        server_state: Value,
        client_message: Value,
    ) -> Result<PakeFinishResult, String> {
        let state = decode_server_login_state(&server_state)?;
        let finalization = CredentialFinalization::<OpaqueCipherSuite>::deserialize(
            &decode_message_field(&client_message, LOGIN_MESSAGE_FIELD)?,
        )
        .map_err(|_| "invalid pake finalization".to_string())?;

        state
            .finish(finalization, ServerLoginParameters::default())
            .map_err(|_| "invalid pake finalization".to_string())?;

        let session_user_id = server_state
            .get(USER_ID_FIELD)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "unknown pake account".to_string())?;

        Ok(PakeFinishResult {
            session_user_id: session_user_id.to_string(),
            session_device_info: None,
        })
    }

    async fn start_registration(
        &self,
        request: PakeRegistrationStartRequest,
    ) -> Result<PakeStartResult, String> {
        let registration_request = RegistrationRequest::<OpaqueCipherSuite>::deserialize(
            &decode_message_field(&request.request, LOGIN_MESSAGE_FIELD)?,
        )
        .map_err(|_| "invalid pake registration request".to_string())?;

        let start = ServerRegistration::<OpaqueCipherSuite>::start(
            &self.server_setup,
            registration_request,
            request.user_id.as_bytes(),
        )
        .map_err(|_| "invalid pake registration request".to_string())?;

        Ok(PakeStartResult {
            response: json!({
                REGISTRATION_MESSAGE_FIELD: encode_base64url(start.message.serialize().as_slice()),
            }),
            server_state: json!({
                USER_ID_FIELD: request.user_id,
            }),
        })
    }

    async fn finish_registration(
        &self,
        server_state: Value,
        client_message: Value,
    ) -> Result<PakeRegistrationFinishResult, String> {
        let user_id = server_state
            .get(USER_ID_FIELD)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing user id".to_string())?;
        let upload = RegistrationUpload::<OpaqueCipherSuite>::deserialize(&decode_message_field(
            &client_message,
            REGISTRATION_UPLOAD_FIELD,
        )?)
        .map_err(|_| "invalid pake registration upload".to_string())?;

        let registration = ServerRegistration::<OpaqueCipherSuite>::finish(upload);

        Ok(PakeRegistrationFinishResult {
            credential_blob: registration.serialize().to_vec(),
            server_key_ref: Some(
                self.server_key_ref
                    .clone()
                    .unwrap_or_else(|| format!("{SERVER_KEY_REF_DEFAULT}:{user_id}")),
            ),
            envelope_kms_key_id: None,
        })
    }
}

fn credential_identifier_for_login(credential: &PakeLoginCredentialView, flow_id: &str) -> String {
    credential
        .user_id
        .clone()
        .unwrap_or_else(|| format!("anon:{flow_id}"))
}

fn normalize_server_key_ref(server_key_ref: Option<String>) -> Option<String> {
    server_key_ref
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn decode_server_login_state(
    server_state: &Value,
) -> Result<ServerLogin<OpaqueCipherSuite>, String> {
    let encoded = server_state
        .get(SERVER_STATE_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(|| "missing opaque server state".to_string())?;
    let bytes = decode_base64url(encoded).map_err(|_| "invalid opaque server state".to_string())?;
    ServerLogin::<OpaqueCipherSuite>::deserialize(&bytes)
        .map_err(|_| "invalid opaque server state".to_string())
}

fn decode_message_field(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    let encoded = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {field}"))?;

    decode_base64url(encoded).map_err(|_| format!("invalid {field}"))
}

fn decode_base64url(encoded: &str) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(anyhow::Error::from)
}

fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };

    #[tokio::test]
    async fn opaque_ke_service_round_trips_registration_and_login() {
        let service = OpaqueKePasswordPakeService::new_for_tests();
        let user_id = "user-123".to_string();
        let password = b"correct horse battery staple";

        let mut client_rng = OsRng;
        let registration_start =
            ClientRegistration::<OpaqueCipherSuite>::start(&mut client_rng, password)
                .expect("client registration should start");
        let server_registration_start = service
            .start_registration(PakeRegistrationStartRequest {
                flow_id: "flow-reg".to_string(),
                user_id: user_id.clone(),
                request: json!({
                    LOGIN_MESSAGE_FIELD: encode_base64url(
                        registration_start.message.serialize().as_slice(),
                    ),
                }),
            })
            .await
            .expect("server registration should start");
        let registration_response = RegistrationResponse::<OpaqueCipherSuite>::deserialize(
            &decode_message_field(
                &server_registration_start.response,
                REGISTRATION_MESSAGE_FIELD,
            )
            .expect("registration response should decode"),
        )
        .expect("registration response should deserialize");
        let registration_finish = registration_start
            .state
            .finish(
                &mut client_rng,
                password,
                registration_response,
                ClientRegistrationFinishParameters::default(),
            )
            .expect("client registration should finish");
        let registration_result = service
            .finish_registration(
                server_registration_start.server_state,
                json!({
                    REGISTRATION_UPLOAD_FIELD: encode_base64url(
                        registration_finish.message.serialize().as_slice(),
                    ),
                }),
            )
            .await
            .expect("server registration should finish");

        let login_start = ClientLogin::<OpaqueCipherSuite>::start(&mut client_rng, password)
            .expect("client login should start");
        let server_login_start = service
            .start_login(
                PakeLoginCredentialView {
                    user_id: Some(user_id.clone()),
                    opaque_credential: Some(registration_result.credential_blob.clone()),
                    legacy_password_allowed: false,
                },
                PakeStartRequest {
                    flow_id: "flow-login".to_string(),
                    request: json!({
                        LOGIN_MESSAGE_FIELD: encode_base64url(
                            login_start.message.serialize().as_slice(),
                        ),
                    }),
                },
            )
            .await
            .expect("server login should start");
        let credential_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(
            &decode_message_field(&server_login_start.response, LOGIN_MESSAGE_FIELD)
                .expect("credential response should decode"),
        )
        .expect("credential response should deserialize");
        let login_finish = login_start
            .state
            .finish(
                &mut client_rng,
                password,
                credential_response,
                ClientLoginFinishParameters::default(),
            )
            .expect("client login should finish");
        let authenticated = service
            .finish_login(
                server_login_start.server_state,
                json!({
                    LOGIN_MESSAGE_FIELD: encode_base64url(
                        login_finish.message.serialize().as_slice(),
                    ),
                }),
            )
            .await
            .expect("server login should authenticate");

        assert_eq!(authenticated.session_user_id, user_id);
        assert!(registration_result.server_key_ref.is_some());
    }

    #[tokio::test]
    async fn opaque_ke_service_accepts_serialized_server_setup_from_config() {
        let service = OpaqueKePasswordPakeService::new_for_tests();
        let encoded = service.server_setup_base64();

        let restored = OpaqueKePasswordPakeService::from_base64_server_setup(
            &encoded,
            Some("configured-key".to_string()),
        )
        .expect("serialized setup should restore service");

        assert_eq!(restored.server_key_ref.as_deref(), Some("configured-key"));
    }

    #[tokio::test]
    async fn opaque_ke_service_rejects_invalid_login_finalization() {
        let service = OpaqueKePasswordPakeService::new_for_tests();
        let start = service
            .start_login(
                PakeLoginCredentialView {
                    user_id: None,
                    opaque_credential: None,
                    legacy_password_allowed: false,
                },
                PakeStartRequest {
                    flow_id: "flow-bad".to_string(),
                    request: json!({
                        LOGIN_MESSAGE_FIELD: encode_base64url(
                            ClientLogin::<OpaqueCipherSuite>::start(&mut OsRng, b"password")
                                .expect("client login should start")
                                .message
                                .serialize()
                                .as_slice(),
                        ),
                    }),
                },
            )
            .await
            .expect("server login should return dummy response");

        let error = service
            .finish_login(
                start.server_state,
                json!({
                    LOGIN_MESSAGE_FIELD: encode_base64url(b"bogus"),
                }),
            )
            .await
            .expect_err("invalid finalization should be rejected");

        assert!(error.contains("invalid"));
    }
}
