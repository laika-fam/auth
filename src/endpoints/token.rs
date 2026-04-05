use crate::model::AccessToken;
use crate::model::RefreshTokenDataView;
use crate::model::WithStatusCode as _;
use crate::AppState;
use anyhow::anyhow;
use anyhow::Context as _;
use axum::extract::State;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use axum::Json;
use base64::Engine as _;
use chrono::Utc;
use core::ops::Add as _;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest as _;
use std::sync::Arc;

const BASE64_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Deserialize)]
#[serde(tag = "grant_type")]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenExchangeBody {
    AuthorizationCode {
        #[serde(with = "uuid::serde::simple")]
        code: uuid::Uuid,
        redirect_uri: url::Url,
        client_id: Option<String>,
        code_verifier: String,
    },
    RefreshToken {
        #[serde(with = "uuid::serde::simple")]
        refresh_token: uuid::Uuid,
        client_id: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims<'o> {
    // subject
    sub: &'o str,
    email: &'o str,
    name: &'o str,
    picture: Option<&'o str>,
    // audience
    aud: &'o str,
    // issuer
    iss: &'o str,
    // issued at
    #[serde(with = "chrono::serde::ts_seconds")]
    iat: chrono::DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    exp: chrono::DateTime<Utc>,
}

#[axum_macros::debug_handler]
pub(crate) async fn get(
    State(state): State<AppState>,
    Json(body): Json<TokenExchangeBody>,
) -> crate::Result<Response<axum::body::Body>> {
    match body {
        TokenExchangeBody::AuthorizationCode {
            code,
            redirect_uri,
            client_id,
            code_verifier,
        } => {
            let auth_code = state
                .auth_codes
                .get(&code)
                .await
                .context("bad auth code")
                .with_status_code(StatusCode::BAD_REQUEST)?;

            if client_id.is_some_and(|i| *auth_code.client_id != i)
                || redirect_uri != *auth_code.redirect_uri
                || code_verifier
                    != BASE64_ENGINE.encode(sha2::Sha256::digest(&*auth_code.code_challenge))
            {
                return Err(anyhow!("bad auth code")).with_status_code(StatusCode::BAD_REQUEST)?;
            }
            state.auth_codes.invalidate(&code).await;

            // should always unwrap, but just in case
            let auth_code = Arc::unwrap_or_clone(auth_code);

            let access_token_id = uuid::Uuid::new_v4();
            let refresh_token_id = uuid::Uuid::new_v4();

            let issued_at = Utc::now();

            let access_token_expires_at = issued_at.add(state.access_token_ttl);
            let access_jwt = jsonwebtoken::encode(
                &{
                    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                    h.kid = Some(state.keys.key_id.to_string());
                    h
                },
                &AccessTokenClaims {
                    sub: &auth_code.session.user_id,
                    email: &auth_code.session.email,
                    name: &auth_code.session.name,
                    picture: auth_code.session.picture.as_deref(),
                    aud: &auth_code.client_id,
                    iss: &state.issuer,
                    iat: issued_at,
                    exp: access_token_expires_at,
                },
                &state.keys.private.key.to_encoding_key(),
            )
            .context("issue and sign access token")?;

            state
                .access_tokens
                .insert(
                    access_token_id,
                    Arc::new(AccessToken {
                        user_id: auth_code.session.user_id.clone(),
                        email: auth_code.session.email.clone(),
                        name: auth_code.session.name.clone(),
                        picture: auth_code.session.picture.clone(),
                        scope: auth_code.session.scope.clone(),
                        exp: access_token_expires_at,
                    }),
                )
                .await;

            let mut redis = state
                .redis
                .get_multiplexed_async_connection()
                .await
                .context("acquire redis")?;

            redis::pipe()
                .atomic()
                .json_set(
                    refresh_token_id,
                    "$",
                    &RefreshTokenDataView {
                        user_id: &auth_code.session.user_id,
                        email: &auth_code.session.email,
                        name: &auth_code.session.name,
                        picture: auth_code.session.picture.as_deref(),
                        client_id: &auth_code.client_id,
                        scope: &auth_code.session.scope,
                        google_refresh_token: auth_code.session.google_refresh_token.as_deref(),
                    },
                )
                .context("serialize refresh token data")?
                .ignore()
                .expire(
                    refresh_token_id,
                    state.refresh_token_ttl.as_secs().cast_signed(),
                )
                .exec_async(&mut redis)
                .await
                .context("EXPIRE refresh token")?;

            #[derive(Debug, Serialize)]
            struct CodeGrant<'o> {
                token_type: &'static str,
                #[serde(with = "uuid::serde::simple")]
                access_token: uuid::Uuid,
                #[serde(with = "uuid::serde::simple")]
                refresh_token: uuid::Uuid,
                id_token: &'o str,
                expires_in: u64,
                google_access_token: Option<&'o str>,
                google_refresh_token: Option<&'o str>,
                #[serde(with = "chrono::serde::ts_milliseconds_option")]
                google_token_expiry: Option<chrono::DateTime<Utc>>,
            }

            let mut r = Json(CodeGrant {
                token_type: "Bearer",
                access_token: access_token_id,
                refresh_token: refresh_token_id,
                id_token: &access_jwt,
                expires_in: state.access_token_ttl.as_secs(),
                google_access_token: auth_code.session.google_access_token.as_deref(),
                google_refresh_token: auth_code.session.google_refresh_token.as_deref(),
                google_token_expiry: auth_code.session.google_token_expiry,
            })
            .into_response();

            r.headers_mut().insert(
                const { HeaderName::from_static("cache-control") },
                const { HeaderValue::from_static("no-store") },
            );
            Ok(r)
        }
        TokenExchangeBody::RefreshToken { .. } => {
            todo!()
        }
    }
}
