use crate::model::AuthCode;
use crate::model::PassedAuthState;
use crate::model::Session;
use crate::model::WithStatusCode as _;
use crate::model::BASE64_ENGINE;
use crate::{AppState, EXTREMELY_LOUD_INCORRECT_BUZZER};
use crate::BINCODE_CONFIG;
use anyhow::anyhow;
use anyhow::Context as _;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::HashSet;
use worker::wasm_bindgen::UnwrapThrowExt as _;
use crate::endpoints::callback::goog;

struct ClientDef {}

static CLIENTS: phf::Map<&'static str, ClientDef> = phf::phf_map! {
    "test" => ClientDef {},
};

fn allowed(client_id: &str, _redirect_url: &str) -> bool {
    // TODO: check redirect
    CLIENTS.contains_key(client_id)
}

#[derive(Debug, Deserialize, Copy, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum PromptType {
    None,
    Consent,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: url::Url,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    prompt: Option<PromptType>,
}

pub fn found_redirect(location: &str) -> Response {
    Response::builder()
        .header(
            const { axum::http::HeaderName::from_static("location") },
            // safety: url crate enforces no NUL
            unsafe { axum::http::HeaderValue::from_str(location).unwrap_unchecked() },
        )
        .status(StatusCode::FOUND)
        .body(axum::body::Body::empty())
        .unwrap_throw()
}

#[worker::send]
#[axum_macros::debug_handler]
pub(crate) async fn get(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Query(query): Query<AuthorizeQuery>,
) -> crate::Result<Response<axum::body::Body>> {
    if !(query.response_type == "code" && query.code_challenge_method == "S256") {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    }

    if !allowed(&query.client_id, query.redirect_uri.as_str()) {
        return Err(anyhow!("nuh uh")).with_status_code(StatusCode::BAD_REQUEST);
    }

    let sess = cookies.get("sess");
    if let Some(sess) = sess
        && let Some(sess_state) = state
            .sessions
            .get(sess.value())
            .json::<Session>()
            .await
            .unwrap_throw()
        && query.prompt != Some(PromptType::Consent)
        && {
            let session_scopes = sess_state.scope.split(' ').collect::<HashSet<&str>>();
            query.scope.split(' ').all(|s| session_scopes.contains(s))
        }
    {
        let auth_code = uuid::Uuid::new_v4();
        let mut uuid_buf = [0; uuid::fmt::Simple::LENGTH];

        state
            .auth_codes
            .put(
                auth_code.simple().encode_lower(&mut uuid_buf),
                AuthCode {
                    session: Session {
                        scope: query.scope,
                        ..sess_state
                    },
                    client_id: query.client_id,
                    redirect_uri: query.redirect_uri.clone(),
                    code_challenge: query.code_challenge,
                },
            )
            .unwrap_throw()
            .expiration_ttl(state.auth_code_ttl)
            .execute()
            .await
            .unwrap_throw();

        let mut ret = query.redirect_uri;
        {
            let mut query_pairs = ret.query_pairs_mut();
            // safety: uuid crate wrote ASCII
            query_pairs.append_pair("code", unsafe { str::from_utf8_unchecked(&uuid_buf) });
            if let Some(ref state) = query.state {
                query_pairs.append_pair("state", state);
            }
        }

        return Ok(found_redirect(ret.as_str()));
    }

    if query.prompt == Some(PromptType::None) {
        let mut ret = query.redirect_uri;
        {
            let mut query_pairs = ret.query_pairs_mut();
            query_pairs.append_pair("error", "login_required");
            if let Some(ref state) = query.state {
                query_pairs.append_pair("state", state);
            }
        }

        return Ok(found_redirect(ret.as_str()));
    }

    let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .context("parse base google oauth url")?;
    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("client_id", &state.google_client_id);
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("redirect_uri", &goog::redirect_url(&state));
        query_pairs.append_pair("scope", &query.scope);
        query_pairs.append_pair(
            "state",
            // sign me! https://github.com/icssc/auth/pull/6
            &BASE64_ENGINE.encode(
                bincode_next::encode_to_vec(
                    PassedAuthState {
                        client_id: query.client_id,
                        redirect_uri: query.redirect_uri.into(),
                        state: query.state,
                        code_challenge: query.code_challenge,
                        scope: query.scope,
                    },
                    BINCODE_CONFIG,
                )
                    .unwrap_throw(),
            ),
        );
        query_pairs.append_pair("access_type", "offline");
        query_pairs.append_pair("prompt", "select_account");
        query_pairs.append_pair("hl", "en-GB");
    }

    Ok(found_redirect(url.as_str()))
}
