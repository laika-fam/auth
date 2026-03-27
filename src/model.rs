use anyhow::Context;
use axum::http::StatusCode;
use chrono::Utc;
use jsonwebkey::KeyUse;
use jsonwebkey::RsaPrivate;
use rand::SeedableRng;
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) type Result<T> = core::result::Result<T, AnyhowBridge>;

#[derive(Debug)]
pub(crate) struct AnyhowBridge(Box<(anyhow::Error, StatusCode)>);

impl core::fmt::Display for AnyhowBridge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.0.fmt(f)
    }
}

impl<T> From<T> for AnyhowBridge
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        Self(Box::new((value.into(), StatusCode::INTERNAL_SERVER_ERROR)))
    }
}

pub(crate) trait WithStatusCode<T> {
    fn with_status_code(self, code: StatusCode) -> Result<T>;
}

impl<T, E> WithStatusCode<T> for core::result::Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn with_status_code(self, code: StatusCode) -> Result<T> {
        self.map_err(|err| AnyhowBridge(Box::new((err.into(), code))))
    }
}

impl axum::response::IntoResponse for AnyhowBridge {
    fn into_response(self) -> axum::response::Response {
        (
            self.0.1,
            axum::Json(serde_json::json!({
                "error": self.0.0.to_string(),
            })),
        )
            .into_response()
    }
}

pub(crate) trait ToFromAws: Sized + Serialize + DeserializeOwned {
    const S3_KEY: &'static str;

    async fn from_aws(aws: &aws_sdk_s3::Client, bucket_name: &str) -> anyhow::Result<Option<Self>> {
        let mut dl_buf = Vec::new();
        Ok(
            match aws
                .get_object()
                .bucket(bucket_name)
                .key(Self::S3_KEY)
                .send()
                .await
            {
                Ok(mut stream) => {
                    while let Some(bytes) = stream
                        .body
                        .try_next()
                        .await
                        .with_context(|| format!("next from {bucket_name} download stream"))?
                    {
                        dl_buf.extend(bytes);
                    }
                    Some(
                        serde_json::from_slice(&dl_buf)
                            .with_context(|| format!("parse {bucket_name}"))?,
                    )
                }
                Err(aws_sdk_s3::error::SdkError::ServiceError(e)) if e.err().is_no_such_key() => {
                    None
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "can't download {bucket_name} from bucket (does it exist?)"
                    )));
                }
            },
        )
    }

    async fn to_aws(&self, aws: &aws_sdk_s3::Client, bucket_name: &str) -> anyhow::Result<()> {
        aws.put_object()
            .bucket(bucket_name)
            .key(Self::S3_KEY)
            .body(
                serde_json::to_vec_pretty(self)
                    .context("serialize to s3")?
                    .into(),
            )
            .send()
            .await
            .context("upload new state to s3")?;

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Jwks {
    pub key_id: uuid::Uuid,
    pub public: jsonwebkey::JsonWebKey,
    pub private: jsonwebkey::JsonWebKey,
}

impl ToFromAws for Jwks {
    const S3_KEY: &'static str = "jwks.json";
}

impl Jwks {
    pub(crate) async fn new() -> Self {
        let mut rng = rand::rngs::ChaCha20Rng::from_rng(&mut rand::rng());
        let private_gen = rsa::RsaPrivateKey::new(&mut rng, 4096).unwrap();
        assert_eq!(
            *private_gen.e_bytes(),
            [0x01, 0x00, 0x01],
            "generated RSA key should have exponent 65537"
        );

        let rsa = jsonwebkey::Key::RSA {
            public: jsonwebkey::RsaPublic {
                e: jsonwebkey::PublicExponent,
                n: private_gen.n_bytes().into(),
            },
            private: Some(RsaPrivate {
                d: private_gen.d().to_be_bytes_trimmed_vartime().into(),
                p: private_gen
                    .primes()
                    .get(0)
                    .map(|v| v.to_be_bytes_trimmed_vartime().into()),
                q: private_gen
                    .primes()
                    .get(1)
                    .map(|v| v.to_be_bytes_trimmed_vartime().into()),
                dp: private_gen
                    .dp()
                    .map(|v| v.to_be_bytes_trimmed_vartime().into()),
                dq: private_gen
                    .dq()
                    .map(|v| v.to_be_bytes_trimmed_vartime().into()),
                qi: private_gen
                    .qinv()
                    .map(|v| v.retrieve().to_be_bytes_trimmed_vartime().into()),
            }),
        };

        let key_id = uuid::Uuid::new_v4();

        let mut public_jwk = jsonwebkey::JsonWebKey::new(
            rsa.clone()
                .to_public()
                .expect("there is a public part")
                .into_owned(),
        );
        public_jwk
            .set_algorithm(jsonwebkey::Algorithm::RS256)
            .expect("RS256 is correct for an RSA key");
        public_jwk.key_use = Some(KeyUse::Signing);
        public_jwk.key_id = Some(key_id.to_string());

        let mut private_jwk = jsonwebkey::JsonWebKey::new(rsa);
        private_jwk
            .set_algorithm(jsonwebkey::Algorithm::RS256)
            .expect("RS256 is correct for an RSA key");
        private_jwk.key_id = Some(key_id.to_string());

        Self {
            key_id,
            public: public_jwk,
            private: private_jwk,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BackingOauthState {
    pub client_id: String,
    pub redirect_uri: url::Url,
    pub state: Option<String>,
    pub code_challenge: String,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthCode {
    pub session: std::sync::Arc<Session>,
    pub client_id: String,
    pub redirect_uri: url::Url,
    pub code_challenge: String,
}

pub(crate) const SESSION_COOKIE_NAME: &'static str = "sess";

#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub scope: String,
    pub google_access_token: Option<String>,
    pub google_refresh_token: Option<String>,
    pub google_token_expiry: Option<chrono::DateTime<Utc>>,
}

#[derive(Copy, Clone)]
pub(crate) struct SimpleUuidBuf([u8; uuid::fmt::Simple::LENGTH]);

impl From<uuid::Uuid> for SimpleUuidBuf {
    fn from(value: uuid::Uuid) -> Self {
        let mut buf = [0u8; uuid::fmt::Simple::LENGTH];
        value.simple().encode_lower(&mut buf);
        Self(buf)
    }
}

impl AsRef<str> for SimpleUuidBuf {
    fn as_ref(&self) -> &str {
        // safety: uuid crate wrote ASCII
        unsafe { str::from_utf8_unchecked(&self.0) }
    }
}
