pub(crate) mod goog;

use crate::AppState;
use axum::Router;
use axum::routing::get;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/goog", get(goog::get))
}
