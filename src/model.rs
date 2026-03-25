use axum::http::StatusCode;
use base64::Engine as _;
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
use serde::Deserialize;
use serde::Serialize;
use web_sys::js_sys;
use web_sys::js_sys::Array;
use web_sys::js_sys::Reflect;
use web_sys::js_sys::Uint8Array;
use web_sys::wasm_bindgen::JsCast as _;
use web_sys::wasm_bindgen::JsValue;
use web_sys::wasm_bindgen::UnwrapThrowExt as _;
use worker::wasm_bindgen_futures::JsFuture;

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
    pub key_id: uuid::Uuid,
    pub public: jsonwebkey::JsonWebKey,
    pub private: jsonwebkey::JsonWebKey,
}

pub(crate) const BASE64_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

impl Jwks {
    pub(crate) async fn new() -> Self {
        let subtle = js_sys::global()
            .unchecked_into::<web_sys::WorkerGlobalScope>()
            .crypto()
            .unwrap_throw()
            .subtle();

        let pair = JsFuture::from(
            subtle
                .generate_key_with_object(
                    &{
                        let obj = js_sys::Object::new();
                        for (k, v) in [
                            ("name", JsValue::from_str("RSASSA-PKCS1-v1_5")),
                            ("hash", JsValue::from_str("SHA-256")),
                            (
                                "publicExponent",
                                Uint8Array::new_from_slice(&[0x01, 0x00, 0x01]).into(),
                            ),
                            ("modulusLength", JsValue::from_f64(4096.0)),
                        ] {
                            Reflect::set(&obj, &JsValue::from_str(k), &v).unwrap_throw();
                        }

                        obj
                    },
                    true,
                    &*{
                        let arr = Array::new_with_length(2);
                        arr.set(0, JsValue::from("sign"));
                        arr.set(1, JsValue::from("verify"));
                        arr
                    },
                )
                .unwrap_throw(),
        )
        .await
        .unwrap_throw()
        .unchecked_into::<::web_sys::CryptoKeyPair>();

        let key_id = uuid::Uuid::new_v4();

        let public = JsFuture::from(
            subtle
                .export_key("jwk", &pair.get_public_key())
                .unwrap_throw(),
        )
        .await
        .unwrap_throw();
        let private = JsFuture::from(
            subtle
                .export_key("jwk", &pair.get_private_key())
                .unwrap_throw(),
        )
        .await
        .unwrap_throw();

        let rsa = jsonwebkey::Key::RSA {
            public: jsonwebkey::RsaPublic {
                e: jsonwebkey::PublicExponent,
                n: BASE64_ENGINE
                    .decode(
                        Reflect::get(&public, &JsValue::from("n"))
                            .unwrap_throw()
                            .as_string()
                            .unwrap_throw()
                            .as_bytes(),
                    )
                    .unwrap_throw()
                    .into(),
            },
            private: Some(RsaPrivate {
                d: BASE64_ENGINE
                    .decode(
                        Reflect::get(&private, &JsValue::from("d"))
                            .unwrap_throw()
                            .as_string()
                            .unwrap_throw()
                            .as_bytes(),
                    )
                    .unwrap_throw()
                    .into(),
                p: Reflect::get(&private, &JsValue::from("d"))
                    .unwrap_throw()
                    .as_string()
                    .map(|s| BASE64_ENGINE.decode(s.as_bytes()).unwrap_throw().into()),
                q: Reflect::get(&private, &JsValue::from("q"))
                    .unwrap_throw()
                    .as_string()
                    .map(|s| BASE64_ENGINE.decode(s.as_bytes()).unwrap_throw().into()),
                dp: Reflect::get(&private, &JsValue::from("dp"))
                    .unwrap_throw()
                    .as_string()
                    .map(|s| BASE64_ENGINE.decode(s.as_bytes()).unwrap_throw().into()),
                dq: Reflect::get(&private, &JsValue::from("dq"))
                    .unwrap_throw()
                    .as_string()
                    .map(|s| BASE64_ENGINE.decode(s.as_bytes()).unwrap_throw().into()),
                qi: Reflect::get(&private, &JsValue::from("qi"))
                    .unwrap_throw()
                    .as_string()
                    .map(|s| BASE64_ENGINE.decode(s.as_bytes()).unwrap_throw().into()),
            }),
        };

        let mut public_jwk =
            jsonwebkey::JsonWebKey::new(rsa.clone().to_public().unwrap_throw().into_owned());
        public_jwk
            .set_algorithm(jsonwebkey::Algorithm::RS256)
            .expect_throw("RS256 is correct for an RSA key");
        public_jwk.key_use = Some(KeyUse::Signing);
        public_jwk.key_id = Some(key_id.to_string());

        let mut private_jwk = jsonwebkey::JsonWebKey::new(rsa);
        private_jwk
            .set_algorithm(jsonwebkey::Algorithm::RS256)
            .expect_throw("RS256 is correct for an RSA key");
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
    pub(crate) client_id: String,
    pub(crate) redirect_uri: BincodableUrl,
    pub(crate) state: Option<String>,
    pub(crate) code_challenge: String,
    pub(crate) scope: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Session {
    pub(crate) user_id: String,
    pub(crate) email: String,
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) picture: Option<String>,
    pub(crate) scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) google_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) google_refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "chrono::serde::ts_milliseconds_option")]
    pub(crate) google_token_expiry: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AuthCode {
    pub(crate) session: Session,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: url::Url,
    pub(crate) code_challenge: String,
}
