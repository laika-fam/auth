use crate::AppState;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::Response;
use axum::response::IntoResponse as _;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use chrono::Utc;
use reqwest::StatusCode;
use serde::Serialize;

#[axum_macros::debug_handler]
pub(crate) async fn get(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Response<axum::body::Body> {
    let bearer = bearer.token();
    if bearer.len() != 32 {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Ok(bearer_uuid) = bearer.parse::<uuid::Uuid>() else {
        return StatusCode::FORBIDDEN.into_response();
    };

    let Some(access_token_stored) = state.access_tokens.get(&bearer_uuid).await else {
        return StatusCode::FORBIDDEN.into_response();
    };

    if access_token_stored.exp < Utc::now() {
        // this is probably a very short span of time
        // but kill the key anyway
        state.access_tokens.invalidate(&bearer_uuid).await;
        return StatusCode::FORBIDDEN.into_response();
    }

    #[derive(Debug, Serialize)]
    struct UserinfoResponse<'o> {
        sub: &'o str,
        picture: Option<&'o str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'o str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'o str>,
    }

    let mut scope_profile = false;
    let mut scope_email = false;
    for scope in access_token_stored.scope.split(' ') {
        if scope == "profile" {
            scope_profile = true;
        }
        if scope == "email" {
            scope_email = true;
        }
    }

    let mut r = axum::Json(&UserinfoResponse {
        sub: &access_token_stored.user_id,
        picture: access_token_stored.picture.as_deref(),
        name: scope_profile.then_some(&*access_token_stored.name),
        email: scope_email.then_some(&*access_token_stored.email),
    })
    .into_response();

    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        const { HeaderValue::from_static("no-store") },
    );
    r
}
