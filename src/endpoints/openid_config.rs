use crate::AppState;
use axum::extract::State;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::response::IntoResponse as _;

#[worker::send]
#[axum_macros::debug_handler]
pub(crate) async fn get(State(state): State<AppState>) -> axum::http::Response<axum::body::Body> {
    let issuer = &state.issuer;

    let mut r = axum::Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "jwks_uri": format!("{}/jwks.json", issuer),
        "scopes_supported": [
            "openid",
            "profile",
            "email",
        ],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email"],
    }))
    .into_response();

    r.headers_mut().insert(
        const { HeaderName::from_static("cache-control") },
        const { HeaderValue::from_static("no-store") },
    );
    r
}
