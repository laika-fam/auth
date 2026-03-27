use crate::AppState;
use crate::EXTREMELY_LOUD_INCORRECT_BUZZER;
use crate::model::WithStatusCode;
use anyhow::anyhow;
use axum::extract::Query;
use axum::extract::State;
use axum::http::Response;
use axum::http::StatusCode;
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

    // https://developers.google.com/identity/openid-connect/openid-connect#exchangecode
    let tokens = state
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
        .await?
        .error_for_status()
        .with_status_code(StatusCode::BAD_REQUEST)?
        .json::<GoogleExchangeResponse>()
        .await?;

    // don't reorder this earlier; make sure google agrees this is valid
    // before we destroy our own data
    let backing_state = if let Ok(k) = query_code.parse::<uuid::Uuid>()
        && let Some(passed) = state.backing_oauth_state_ttl.remove(&k).await
    {
        passed
    } else {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))?;
    };

    drop(query_state);

    // surely the token has not expired already?
    let r = state
        .http
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&tokens.access_token)
        .send()
        .await?
        .error_for_status()
        .with_status_code(StatusCode::BAD_REQUEST);

    todo!()
}
