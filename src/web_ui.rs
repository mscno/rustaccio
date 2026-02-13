use crate::app::AppState;
use axum::{
    body::Body,
    http::{Method, Response, StatusCode, header},
};
use serde_json::json;

const INDEX_TEMPLATE: &str = include_str!("../webui/index.html");
const APP_JS: &str = include_str!("../webui/app.js");
const STYLES_CSS: &str = include_str!("../webui/styles.css");

pub fn maybe_handle_request(
    state: &AppState,
    method: &Method,
    path: &str,
) -> Option<Response<Body>> {
    if *method != Method::GET {
        return None;
    }

    if path == "/" {
        if state.web_enabled {
            return Some(index_response(state));
        }
        return Some(not_found_response());
    }

    if path == "/-/web/static/app.js" {
        return if state.web_enabled {
            Some(text_response(
                StatusCode::OK,
                "application/javascript; charset=utf-8",
                APP_JS,
            ))
        } else {
            Some(not_found_response())
        };
    }

    if path == "/-/web/static/styles.css" {
        return if state.web_enabled {
            Some(text_response(
                StatusCode::OK,
                "text/css; charset=utf-8",
                STYLES_CSS,
            ))
        } else {
            Some(not_found_response())
        };
    }

    if path == "/-/web" || path == "/-/web/" || path.starts_with("/-/web/") {
        return if state.web_enabled {
            Some(index_response(state))
        } else {
            Some(not_found_response())
        };
    }

    None
}

fn index_response(state: &AppState) -> Response<Body> {
    let asset_base = if state.url_prefix == "/" {
        String::new()
    } else {
        state.url_prefix.clone()
    };

    let config = json!({
        "title": state.web_title,
        "urlPrefix": state.url_prefix,
        "webLoginEnabled": state.web_login_enabled,
        "externalAuthMode": state.auth_external_mode,
    });

    let title = escape_html(&state.web_title);
    let config_json = serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string());

    let html = INDEX_TEMPLATE
        .replace("{{TITLE}}", &title)
        .replace("{{ASSET_BASE}}", &asset_base)
        .replace("{{CONFIG_JSON}}", &config_json);

    text_response(StatusCode::OK, "text/html; charset=utf-8", &html)
}

fn text_response(status: StatusCode, content_type: &str, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from(String::new())))
}

fn not_found_response() -> Response<Body> {
    text_response(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        "not found",
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
