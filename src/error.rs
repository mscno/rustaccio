use axum::{
    Json,
    body::Body,
    http::StatusCode,
    http::header,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{message}")]
    Http { status: StatusCode, message: String },
    #[error("internal server error")]
    Internal,
}

impl RegistryError {
    pub fn http(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Http {
            status,
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        match self {
            RegistryError::Http { status, message } => {
                let body = serde_json::to_vec(&ErrorBody { error: &message })
                    .unwrap_or_else(|_| b"{\"error\":\"unknown error\"}".to_vec());
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, crate::constants::HEADER_JSON)
                    .body(Body::from(body))
                    .unwrap_or_else(|_| {
                        let fallback = Json(ErrorBody {
                            error: "unknown error",
                        });
                        (StatusCode::INTERNAL_SERVER_ERROR, fallback).into_response()
                    })
            }
            RegistryError::Internal => {
                let body = serde_json::to_vec(&ErrorBody {
                    error: "unknown error",
                })
                .unwrap_or_else(|_| b"{\"error\":\"unknown error\"}".to_vec());
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, crate::constants::HEADER_JSON)
                    .body(Body::from(body))
                    .unwrap_or_else(|_| {
                        let fallback = Json(ErrorBody {
                            error: "unknown error",
                        });
                        (StatusCode::INTERNAL_SERVER_ERROR, fallback).into_response()
                    })
            }
        }
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(_: std::io::Error) -> Self {
        RegistryError::Internal
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(_: serde_json::Error) -> Self {
        RegistryError::Internal
    }
}
