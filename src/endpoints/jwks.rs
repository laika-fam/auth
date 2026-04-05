use crate::AppState;
use crate::model::Jwks;
use axum::extract::State;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::Response;
use axum::response::IntoResponse as _;

#[expect(clippy::unused_async, reason = "required by axum")]
#[axum_macros::debug_handler]
pub(crate) async fn get(State(state): State<AppState>) -> Response<axum::body::Body> {
    let Jwks { ref public, .. } = state.keys;

    let mut r = axum::Json(public).into_response();
    r.headers_mut().insert(
        const { HeaderName::from_static("cache-control") },
        const { HeaderValue::from_static("no-store") },
    );
    r
}
