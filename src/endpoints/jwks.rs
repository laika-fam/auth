use crate::AppState;
use crate::keys::Jwks;
use axum::extract::State;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::Response;
use axum::response::IntoResponse;
use web_sys::wasm_bindgen::UnwrapThrowExt;

#[worker::send]
#[axum_macros::debug_handler]
pub(crate) async fn get(State(state): State<AppState>) -> Response<axum::body::Body> {
    let Jwks { public, .. } = state.keys().await;

    let mut json = serde_json::to_value(&public).unwrap_throw();
    let object_handle = json.as_object_mut().unwrap_throw();
    object_handle["alg"] = "RS256".into();
    object_handle["use"] = "sig".into();

    let mut r = axum::Json(json).into_response();

    r.headers_mut().insert(
        const { HeaderName::from_static("cache-control") },
        const { HeaderValue::from_static("no-store") },
    );
    r
}
