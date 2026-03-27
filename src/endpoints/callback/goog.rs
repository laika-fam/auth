use crate::AppState;
use crate::EXTREMELY_LOUD_INCORRECT_BUZZER;
use crate::endpoints::authorize::found_redirect;
use crate::model::AuthCode;
use crate::model::SESSION_COOKIE_NAME;
use crate::model::Session;
use crate::model::SimpleUuidBuf;
use crate::model::WithStatusCode;
use anyhow::Context;
use anyhow::anyhow;
use axum::extract::OriginalUri;
use axum::extract::Query;
use axum::extract::State;
use axum::http::Response;
use axum::http::StatusCode;
use serde::Deserialize;
use std::ops::Add;
use std::sync::Arc;
use tower_cookies::Cookie;

pub(crate) fn redirect_url(state: &AppState) -> String {
    format!("{}/oauth/cb/goog", state.issuer)
}

#[derive(Debug, Deserialize)]
pub(crate) struct GoogQuery {
    code: Option<uuid::Uuid>,
    state: Option<String>,
    error: Option<String>,
}

#[axum_macros::debug_handler]
pub(super) async fn get(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Query(query): Query<GoogQuery>,
    OriginalUri(uri): OriginalUri,
) -> crate::Result<Response<axum::body::Body>> {
    if query.error.is_some() {
        return Err(anyhow!("google oauth died"))?;
    }

    let Some((query_code, query_state)) = query.code.zip(query.state) else {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))?;
    };

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

    let got_tokens_at = chrono::Utc::now();

    // https://developers.google.com/identity/openid-connect/openid-connect#exchangecode
    let tokens = state
        .http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            // silently enforces that state has to be in this format, not any UUID, which is fine
            ("code", SimpleUuidBuf::from(query_code).as_ref()),
            ("client_id", &state.google_client_id),
            ("client_secret", &state.google_client_secret),
            ("redirect_uri", &redirect_url(&state)),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await?
        .error_for_status()
        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
        .json::<GoogleExchangeResponse>()
        .await?;

    // don't reorder this earlier; make sure google agrees this is valid
    // before we destroy our own data
    let backing_state =
        if let Some(passed) = state.backing_oauth_state_ttl.remove(&query_code).await {
            passed
        } else {
            return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))?;
        };

    drop(query_state);

    // https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
    #[derive(Debug, Deserialize)]
    struct GoogleUserInfoResponse {
        id: String,
        email: String,
        name: String,
        picture: Option<String>,
    }

    // surely the token has not expired already?
    let userinfo = state
        .http
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&tokens.access_token)
        .send()
        .await?
        .error_for_status()?
        .json::<GoogleUserInfoResponse>()
        .await?;

    let session_id = uuid::Uuid::new_v4();
    let session = Arc::new(Session {
        user_id: format!("google_{}", userinfo.id),
        email: userinfo.email,
        name: userinfo.name,
        picture: userinfo.picture,
        scope: backing_state.scope,
        google_access_token: Some(tokens.access_token),
        google_refresh_token: Some(tokens.refresh_token),
        google_token_expiry: Some(
            got_tokens_at.add(
                chrono::Duration::new(tokens.expires_in.cast_signed(), 0)
                    .context("duration overflow")?,
            ),
        ),
    });
    state.sessions.insert(session_id, session.clone()).await;
    let mut cookie = Cookie::new(
        SESSION_COOKIE_NAME,
        SimpleUuidBuf::from(session_id).as_ref().to_owned(),
    );

    cookie.set_http_only(true);
    cookie.set_expires(
        time::OffsetDateTime::from_unix_timestamp(
            chrono::Utc::now().add(state.session_ttl).timestamp(),
        )
        .context("this shouldn't overflow because it was valid in chrono")?,
    );
    cookie.set_path("/");

    if uri.scheme() == Some(&axum::http::uri::Scheme::HTTPS) {
        cookie.set_domain(
            uri.host()
                .context("there should be a host part of the request URI")?
                .to_owned(),
        );
        cookie.set_secure(true);
        cookie.set_same_site(tower_cookies::cookie::SameSite::None);
    } else {
        cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
    }

    cookies.add(cookie);

    let auth_code_id = uuid::Uuid::new_v4();
    state
        .auth_codes
        .insert(
            auth_code_id,
            AuthCode {
                session,
                client_id: backing_state.client_id,
                redirect_uri: backing_state.redirect_uri.clone(),
                code_challenge: backing_state.code_challenge,
            },
        )
        .await;

    let mut redirect_url = backing_state.redirect_uri;
    {
        let mut query_pairs = redirect_url.query_pairs_mut();
        query_pairs.append_pair("code", SimpleUuidBuf::from(auth_code_id).as_ref());
        if let Some(passed_state) = backing_state.state {
            query_pairs.append_pair("state", &passed_state);
        }
    }
    Ok(found_redirect(redirect_url.as_str()))
}
