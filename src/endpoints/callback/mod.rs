pub(crate) mod goog;

use crate::AppState;
use axum::routing::get;
use axum::Router;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/goog", get(goog::get))
}
