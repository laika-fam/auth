use axum::http::StatusCode;

pub(crate) type Result<T> = core::result::Result<T, AnyhowBridge>;

#[derive(Debug)]
pub(crate) struct AnyhowBridge(Box<(anyhow::Error, StatusCode)>);

impl core::fmt::Display for AnyhowBridge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.0.fmt(f)
    }
}

impl<T> From<T> for AnyhowBridge
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        Self(Box::new((
            value.into(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )))
    }
}

pub(crate) trait WithStatusCode<T> {
    fn with_status_code(self, code: StatusCode) -> Result<T>;
}

impl<T> WithStatusCode<T> for anyhow::Result<T> {
    fn with_status_code(self, code: StatusCode) -> Result<T> {
        self.map_err(|err| AnyhowBridge(Box::new((err, code))))
    }
}

impl axum::response::IntoResponse for AnyhowBridge {
    fn into_response(self) -> axum::response::Response {
        (self.0.1, axum::Json(serde_json::json!({
            "error": self.0.0.to_string(),
        }))).into_response()
    }
}