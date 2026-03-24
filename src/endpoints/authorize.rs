use crate::AppState;
use crate::error::WithStatusCode;
use anyhow::Context;
use anyhow::anyhow;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use worker::wasm_bindgen::UnwrapThrowExt;

struct ClientDef {}

static CLIENTS: phf::Map<&'static str, ClientDef> = phf::phf_map! {
    "test" => ClientDef {},
};

fn allowed(client_id: &str, redirect_url: &str) -> bool {
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

const EXTREMELY_LOUD_INCORRECT_BUZZER: &str = "[𝐄𝐗𝐓𝐑𝐄𝐌𝐄𝐋𝐘 𝐋𝐎𝐔𝐃 𝐈𝐍𝐂𝐎𝐑𝐑𝐄𝐂𝐓 𝐁𝐔𝐙𝐙𝐄𝐑]";

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
    Query(mut query): Query<AuthorizeQuery>,
) -> crate::Result<Response<axum::body::Body>> {
    if !(query.response_type == "code" && query.code_challenge_method == "S256") {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    }

    if !allowed(&query.client_id, query.redirect_uri.as_str()) {
        return Err(anyhow!("GET OUT")).with_status_code(StatusCode::BAD_REQUEST);
    }

    let sid = cookies.get("sid");
    if let Some(sid) = sid
        && state
            .sessions
            .get(&sid.value())
            .bytes()
            .await
            .unwrap_throw()
            .is_some()
    {
        todo!("can't handle existing sessions yet :(")
        // scope check
    }

    if query.prompt == Some(PromptType::None) {
        {
            let mut query_pairs = query.redirect_uri.query_pairs_mut();
            query_pairs.append_pair("error", "login_required");
            if let Some(ref state) = query.state {
                query_pairs.append_pair("state", state);
            }
        }
        return Ok(found_redirect(query.redirect_uri.as_str()));
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
            &serde_json::to_string(&serde_json::json!({
                "client_id": state.google_client_id,
                "redirect_uri": query.redirect_uri,
                "state": query.state,
                "code_challenge": query.code_challenge,
                "scope": query.scope,
            }))
            .context("create oauth state string to goog")?,
        );
    }

    Ok(found_redirect(url.as_str()))
}
