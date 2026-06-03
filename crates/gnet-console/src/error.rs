use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// Valkey hop failed — surfaced from the ratelimit and session
    /// modules. The message body is short on purpose; the operator-
    /// facing detail lives in the structured trace event we emit
    /// in `IntoResponse`.
    #[error("cache error: {0}")]
    Cache(#[from] redis::RedisError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}
