use crate::model::PassedAuthState;
use crate::model::WithStatusCode;
use crate::model::BASE64_ENGINE;
use crate::AppState;
use crate::BINCODE_CONFIG;
use crate::EXTREMELY_LOUD_INCORRECT_BUZZER;
use anyhow::anyhow;
use anyhow::Context;
use axum::extract::Query;
use axum::extract::State;
use axum::http::Response;
use axum::http::StatusCode;
use base64::Engine;
use serde::Deserialize;

pub(crate) fn redirect_url(state: &AppState) -> String {
    format!("{}/oauth/cb/goog", state.issuer)
}

#[derive(Debug, Deserialize)]
pub(crate) struct GoogQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

// https://github.com/laggycomputer/pushflow
#[derive(Debug, Deserialize)]
struct GoogleExchangeResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: String,
    // we don't yet deal with time-based access
    // https://developers.google.com/identity/protocols/oauth2/web-server#time-based-access
    refresh_token_expires_in: u64,
    scope: String,
    // always Bearer, for now (https://developers.google.com/identity/protocols/oauth2/web-server)
    token_type: String,
}

#[axum_macros::debug_handler]
pub(super) async fn get(
    State(state): State<AppState>,
    Query(query): Query<GoogQuery>,
) -> crate::Result<Response<axum::body::Body>> {
    if query.error.is_some() {
        return Err(anyhow!("google oauth died"))?;
    }

    let Some((query_code, query_state)) = query.code.zip(query.state) else {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))?;
    };

    let query_state_decoded = BASE64_ENGINE
        .decode(query_state.as_bytes())
        .ok()
        .and_then(|bytes| {
            bincode_next::decode_from_slice::<PassedAuthState, _>(&bytes, BINCODE_CONFIG).ok()
        })
        .context("unpack state")
        .with_status_code(StatusCode::BAD_REQUEST)?
        .0;

    drop(query_state);

    // https://developers.google.com/identity/openid-connect/openid-connect#exchangecode
    let tokens = match state
        .http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", query_code.as_str()),
            ("client_id", &state.google_client_id),
            ("client_secret", &state.google_client_secret),
            ("redirect_uri", &redirect_url(&state)),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
    {
        Err(e) if e.is_status() => {
            return Err(anyhow!("goog said no"))?;
        }
        Err(e) => {
            return Err(anyhow!(e))?;
        }
        Ok(response) => response,
    }
    .json::<GoogleExchangeResponse>()
    .await?;

    // surely the token has not expired already?
    // let r = state
    //     .http
    //     .get("https://www.googleapis.com/oauth2/v2/userinfo")
    //     .bearer_auth(&tokens.access_token)
    //     .query(&[
    //
    //     ]);

    todo!()
}
