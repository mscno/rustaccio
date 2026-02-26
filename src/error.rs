use axum::{
    Json,
    body::Body,
    http::StatusCode,
    http::header,
    response::{IntoResponse, Response},
};
use serde::Serialize;

pub mod code {
    pub const AUTH_UNAUTHORIZED: &str = "AUTH_UNAUTHORIZED";
    pub const AUTH_FORBIDDEN: &str = "AUTH_FORBIDDEN";
    pub const POLICY_DENIED: &str = "POLICY_DENIED";
    pub const POLICY_BACKEND_UNAVAILABLE: &str = "POLICY_BACKEND_UNAVAILABLE";
    pub const STORAGE_BAD_REQUEST: &str = "STORAGE_BAD_REQUEST";
    pub const STORAGE_CONFLICT: &str = "STORAGE_CONFLICT";
    pub const STORAGE_NOT_FOUND: &str = "STORAGE_NOT_FOUND";
    pub const STORAGE_UNPROCESSABLE: &str = "STORAGE_UNPROCESSABLE";
    pub const UPSTREAM_BAD_GATEWAY: &str = "UPSTREAM_BAD_GATEWAY";
    pub const UPSTREAM_UNAVAILABLE: &str = "UPSTREAM_UNAVAILABLE";
    pub const UPSTREAM_TIMEOUT: &str = "UPSTREAM_TIMEOUT";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{message}")]
    Http {
        status: StatusCode,
        code: String,
        message: String,
    },
    #[error("internal server error")]
    Internal,
}

impl RegistryError {
    pub fn http(status: StatusCode, message: impl Into<String>) -> Self {
        Self::http_code(status, default_code(status), message)
    }

    pub fn http_code(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Http {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn auth_unauthorized(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::UNAUTHORIZED, code::AUTH_UNAUTHORIZED, message)
    }

    pub fn auth_forbidden(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::FORBIDDEN, code::AUTH_FORBIDDEN, message)
    }

    pub fn policy_denied(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::UNAUTHORIZED, code::POLICY_DENIED, message)
    }

    pub fn policy_backend_unavailable(message: impl Into<String>) -> Self {
        Self::http_code(
            StatusCode::BAD_GATEWAY,
            code::POLICY_BACKEND_UNAVAILABLE,
            message,
        )
    }

    pub fn upstream_unavailable(message: impl Into<String>) -> Self {
        Self::http_code(
            StatusCode::SERVICE_UNAVAILABLE,
            code::UPSTREAM_UNAVAILABLE,
            message,
        )
    }

    pub fn upstream_bad_gateway(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::BAD_GATEWAY, code::UPSTREAM_BAD_GATEWAY, message)
    }

    pub fn storage_bad_request(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::BAD_REQUEST, code::STORAGE_BAD_REQUEST, message)
    }

    pub fn storage_not_found(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::NOT_FOUND, code::STORAGE_NOT_FOUND, message)
    }

    pub fn storage_conflict(message: impl Into<String>) -> Self {
        Self::http_code(StatusCode::CONFLICT, code::STORAGE_CONFLICT, message)
    }

    pub fn storage_unprocessable(message: impl Into<String>) -> Self {
        Self::http_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::STORAGE_UNPROCESSABLE,
            message,
        )
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'a str>,
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        match self {
            RegistryError::Http {
                status,
                code,
                message,
            } => {
                tracing::warn!(
                    status = status.as_u16(),
                    code = code.as_str(),
                    error = %message,
                    "request failed"
                );
                let body = serde_json::to_vec(&ErrorBody {
                    error: &message,
                    code: &code,
                    hint: hint_for_code(&code),
                })
                .unwrap_or_else(|_| b"{\"error\":\"unknown error\"}".to_vec());
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, crate::constants::HEADER_JSON)
                    .body(Body::from(body))
                    .unwrap_or_else(|_| {
                        let fallback = Json(ErrorBody {
                            error: "unknown error",
                            code: code::INTERNAL_ERROR,
                            hint: None,
                        });
                        (StatusCode::INTERNAL_SERVER_ERROR, fallback).into_response()
                    })
            }
            RegistryError::Internal => {
                tracing::error!(code = code::INTERNAL_ERROR, "internal server error");
                let body = serde_json::to_vec(&ErrorBody {
                    error: "unknown error",
                    code: code::INTERNAL_ERROR,
                    hint: None,
                })
                .unwrap_or_else(|_| b"{\"error\":\"unknown error\"}".to_vec());
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, crate::constants::HEADER_JSON)
                    .body(Body::from(body))
                    .unwrap_or_else(|_| {
                        let fallback = Json(ErrorBody {
                            error: "unknown error",
                            code: code::INTERNAL_ERROR,
                            hint: None,
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

fn default_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => code::AUTH_UNAUTHORIZED,
        StatusCode::FORBIDDEN => code::AUTH_FORBIDDEN,
        StatusCode::NOT_FOUND => code::STORAGE_NOT_FOUND,
        StatusCode::CONFLICT => code::STORAGE_CONFLICT,
        StatusCode::UNPROCESSABLE_ENTITY => code::STORAGE_UNPROCESSABLE,
        StatusCode::BAD_GATEWAY => code::UPSTREAM_BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE => code::UPSTREAM_UNAVAILABLE,
        StatusCode::GATEWAY_TIMEOUT => code::UPSTREAM_TIMEOUT,
        _ => code::STORAGE_BAD_REQUEST,
    }
}

fn hint_for_code(code: &str) -> Option<&'static str> {
    match code {
        code::AUTH_UNAUTHORIZED | code::POLICY_DENIED => Some(
            "Provide a valid Bearer token. For npm, run `npm login --registry <registry-url>` or set `//<registry-host>/:_authToken=<token>` in .npmrc.",
        ),
        code::AUTH_FORBIDDEN => Some(
            "Authenticated, but missing required permissions. Verify user/group access policy.",
        ),
        code::POLICY_BACKEND_UNAVAILABLE => Some(
            "Authorization backend is unavailable. Retry shortly or check policy service health.",
        ),
        _ => None,
    }
}
