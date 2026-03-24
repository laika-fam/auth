use base64::Engine as _;
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Jwks {
    pub key_id: uuid::Uuid,
    pub public: jsonwebkey::JsonWebKey,
    pub private: jsonwebkey::JsonWebKey,
}

const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

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
