use crate::AppState;
use crate::model::Jwks;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::Response;
use axum::response::IntoResponse as _;

#[axum_macros::debug_handler]
pub(crate) async fn get(State(state): State<AppState>) -> Response<axum::body::Body> {
    let Jwks { ref public, .. } = state.keys;

    let mut r = axum::Json(public).into_response();
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        const { HeaderValue::from_static("no-store") },
    );
    r
}
