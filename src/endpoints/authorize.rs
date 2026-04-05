use crate::AppState;
use crate::EXTREMELY_LOUD_INCORRECT_BUZZER;
use crate::endpoints::callback::goog;
use crate::model::AuthCode;
use crate::model::BackingOauthState;
use crate::model::SESSION_COOKIE_NAME;
use crate::model::Session;
use crate::model::SimpleUuidBuf;
use crate::model::WithStatusCode as _;
use anyhow::Context as _;
use anyhow::anyhow;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use crate::endpoints::callback::goog::redirect_url;

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
    response_type: Box<str>,
    client_id: Arc<str>,
    redirect_uri: Arc<url::Url>,
    scope: Arc<str>,
    state: Option<Arc<str>>,
    code_challenge: Arc<str>,
    code_challenge_method: Box<str>,
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
        .unwrap()
}

#[axum_macros::debug_handler]
pub(crate) async fn get(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Query(mut query): Query<AuthorizeQuery>,
) -> crate::Result<Response<axum::body::Body>> {
    if !(&*query.response_type == "code" && &*query.code_challenge_method == "S256") {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    }

    if !allowed(&query.client_id, query.redirect_uri.as_str()) {
        return Err(anyhow!("nuh uh")).with_status_code(StatusCode::BAD_REQUEST);
    }

    let sess_id = cookies
        .get(SESSION_COOKIE_NAME)
        .map(|c| c.value().parse::<uuid::Uuid>());

    if let Some(Ok(sess_id)) = sess_id
        && let Some(sess_state) = state.sessions.get(&sess_id).await
        && query.prompt != Some(PromptType::Consent)
        && {
            let session_scopes = sess_state.scope.split(' ').collect::<HashSet<&str>>();
            query.scope.split(' ').all(|s| session_scopes.contains(s))
        }
    {
        let auth_code = uuid::Uuid::new_v4();

        state
            .auth_codes
            .insert(
                auth_code,
                Arc::new(AuthCode {
                    session: Arc::new(Session {
                        scope: Arc::from(query.scope),
                        ..(*sess_state).clone()
                    }),
                    client_id: query.client_id.clone(),
                    redirect_uri: query.redirect_uri.clone(),
                    code_challenge: query.code_challenge.clone(),
                }),
            )
            .await;
        
        let ret = Arc::make_mut(&mut query.redirect_uri);
        {
            let mut query_pairs = ret.query_pairs_mut();
            query_pairs.append_pair("code", SimpleUuidBuf::from(auth_code).as_ref());
            if let Some(ref state) = query.state {
                query_pairs.append_pair("state", state);
            }
        }

        return Ok(found_redirect(ret.as_str()));
    }

    if query.prompt == Some(PromptType::None) {
        let ret = Arc::make_mut(&mut query.redirect_uri);
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

    let state_id = {
        let backing_state = BackingOauthState {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri.into(),
            state: query.state,
            code_challenge: query.code_challenge,
            scope: query.scope.clone(),
        };
        let id = uuid::Uuid::new_v4();
        state
            .backing_oauth_states
            .insert(id, backing_state)
            .await;
        id.to_string()
    };
    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("client_id", &state.google_client_id);
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("redirect_uri", &goog::redirect_url(&state));
        query_pairs.append_pair("scope", &query.scope);
        query_pairs.append_pair("state", &state_id);
        query_pairs.append_pair("access_type", "offline");
        query_pairs.append_pair("prompt", "select_account");
        query_pairs.append_pair("hl", "en-GB");
    }

    Ok(found_redirect(url.as_str()))
}
