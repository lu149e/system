use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{pkcs8::DecodePublicKey, VerifyingKey};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct JwksDocument {
    pub keys: Vec<JwkKey>,
}

pub struct JwksPublicKeyInput<'a> {
    pub kid: &'a str,
    pub public_key_pem: &'a str,
}

#[derive(Clone, Serialize)]
pub struct JwkKey {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub x: String,
}

impl JwksDocument {
    pub fn from_ed25519_public_keys(keys: &[JwksPublicKeyInput<'_>]) -> anyhow::Result<Self> {
        let mut jwk_keys = Vec::with_capacity(keys.len());

        for key in keys {
            let verifying_key = VerifyingKey::from_public_key_pem(key.public_key_pem)
                .with_context(|| {
                    format!(
                        "JWT public key for kid '{}' must be a valid Ed25519 PEM public key",
                        key.kid
                    )
                })?;

            let x = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
            jwk_keys.push(JwkKey {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                alg: "EdDSA".to_string(),
                key_use: "sig".to_string(),
                kid: key.kid.to_string(),
                x,
            });
        }

        Ok(Self { keys: jwk_keys })
    }
}

#[cfg(test)]
mod tests {
    use super::JwksDocument;

    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdIROjbNDN9NHACJMCdMbdRjmUZp05u0E+QVRzrqB6eM=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn jwks_document_builds_expected_ed25519_shape() {
        let jwks = JwksDocument::from_ed25519_public_keys(&[super::JwksPublicKeyInput {
            kid: "auth-ed25519-v1",
            public_key_pem: TEST_PUBLIC_KEY_PEM,
        }])
        .expect("jwks should be built from test key");

        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "OKP");
        assert_eq!(key.crv, "Ed25519");
        assert_eq!(key.alg, "EdDSA");
        assert_eq!(key.key_use, "sig");
        assert_eq!(key.kid, "auth-ed25519-v1");
        assert!(!key.x.is_empty());
    }

    #[test]
    fn jwks_document_supports_multiple_active_keys() {
        let jwks = JwksDocument::from_ed25519_public_keys(&[
            super::JwksPublicKeyInput {
                kid: "auth-ed25519-v1",
                public_key_pem: TEST_PUBLIC_KEY_PEM,
            },
            super::JwksPublicKeyInput {
                kid: "auth-ed25519-v2",
                public_key_pem: TEST_PUBLIC_KEY_PEM,
            },
        ])
        .expect("jwks should include all active keys");

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, "auth-ed25519-v1");
        assert_eq!(jwks.keys[1].kid, "auth-ed25519-v2");
    }
}
