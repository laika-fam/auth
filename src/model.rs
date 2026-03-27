use axum::http::StatusCode;
use bincode_next::BorrowDecode;
use bincode_next::Decode;
use bincode_next::Encode;
use bincode_next::de::BorrowDecoder;
use bincode_next::de::Decoder;
use bincode_next::enc::Encoder;
use bincode_next::error::DecodeError;
use bincode_next::error::EncodeError;
use chrono::Utc;
use jsonwebkey::KeyUse;
use jsonwebkey::RsaPrivate;
use rand::SeedableRng;
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use serde::Serialize;

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

impl<T> WithStatusCode<T> for anyhow::Result<T> {
    fn with_status_code(self, code: StatusCode) -> Result<T> {
        self.map_err(|err| AnyhowBridge(Box::new((err, code))))
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Jwks {
    #[serde(with = "uuid::serde::compact")]
    pub key_id: uuid::Uuid,
    pub public: jsonwebkey::JsonWebKey,
    pub private: jsonwebkey::JsonWebKey,
}

pub(crate) const BASE64_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct BincodableUrl(pub url::Url);

impl From<url::Url> for BincodableUrl {
    fn from(url: url::Url) -> Self {
        Self(url)
    }
}

impl<Context> Decode<Context> for BincodableUrl {
    fn decode<D>(decoder: &mut D) -> core::result::Result<Self, DecodeError>
    where
        D: Decoder<Context = Context>,
    {
        Ok(Self(
            String::decode(decoder)?
                .parse()
                .ok()
                .ok_or(DecodeError::Other("invalid url"))?,
        ))
    }
}

impl<'de, Context> BorrowDecode<'de, Context> for BincodableUrl {
    fn borrow_decode<D>(decoder: &mut D) -> core::result::Result<Self, DecodeError>
    where
        D: BorrowDecoder<'de, Context = Context>,
    {
        Ok(Self(
            String::borrow_decode(decoder)?
                .parse()
                .ok()
                .ok_or(DecodeError::Other("invalid url"))?,
        ))
    }
}

impl Encode for BincodableUrl {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> core::result::Result<(), EncodeError> {
        self.0.to_string().encode(encoder)
    }
}

#[derive(Debug, Decode, Encode)]
pub(crate) struct PassedAuthState {
    pub client_id: String,
    pub redirect_uri: BincodableUrl,
    pub state: Option<String>,
    pub code_challenge: String,
    pub scope: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Session {
    pub user_id: String,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "chrono::serde::ts_milliseconds_option")]
    pub google_token_expiry: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AuthCode {
    pub session: Session,
    pub client_id: String,
    pub redirect_uri: url::Url,
    pub code_challenge: String,
}
