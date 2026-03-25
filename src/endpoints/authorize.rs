use crate::AppState;
use crate::BINCODE_CONFIG;
use crate::model::AuthCode;
use crate::model::BASE64_ENGINE;
use crate::model::PassedAuthState;
use crate::model::Session;
use crate::model::WithStatusCode as _;
use anyhow::Context as _;
use anyhow::anyhow;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::HashSet;
use worker::wasm_bindgen::UnwrapThrowExt as _;

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

const EXTREMELY_LOUD_INCORRECT_BUZZER: &str = "[\u{1d404}\u{1d417}\u{1d413}\u{1d411}\u{1d404}\u{1d40c}\u{1d404}\u{1d40b}\u{1d418} \u{1d40b}\u{1d40e}\u{1d414}\u{1d403} \u{1d408}\u{1d40d}\u{1d402}\u{1d40e}\u{1d411}\u{1d411}\u{1d404}\u{1d402}\u{1d413} \u{1d401}\u{1d414}\u{1d419}\u{1d419}\u{1d404}\u{1d411}]";

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
        return Err(anyhow!("GET OUT")).with_status_code(StatusCode::BAD_REQUEST);
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
        state
            .auth_codes
            .put(
                // TODO: no alloc here
                &auth_code.to_string(),
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
            // TODO: no alloc here
            query_pairs.append_pair("code", &auth_code.to_string());
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
        query_pairs.append_pair("access_type", "offline");
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("client_id", &state.google_client_id);
        query_pairs.append_pair("redirect_uri", &format!("{}/oauth/cb/goog", &state.issuer));
        query_pairs.append_pair("scope", &query.scope);
        query_pairs.append_pair("prompt", "consent");
        query_pairs.append_pair(
            "state",
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
    }

    Ok(found_redirect(url.as_str()))
}
