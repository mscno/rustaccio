use crate::{
    app::AppState,
    constants::{
        ANONYMOUS_USER, API_ERROR_ONLY_OWNER, HEADER_JSON, HEADER_JSON_INSTALL, HEADER_OCTET,
    },
    error::RegistryError,
    storage::{
        Store, bad_request, default_profile, forbidden, make_search_object, parse_authorization,
        parse_json_body, parse_json_string_body, unauthorized,
    },
};
use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::{
        HeaderMap, Method, Request, Response, StatusCode,
        header::{self, HeaderName, HeaderValue},
    },
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub async fn dispatch(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, RegistryError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().map(ToOwned::to_owned);
    let headers = req.headers().clone();

    let auth_user = resolve_auth_user(&state.store, &headers, &path).await?;

    if method == Method::GET && path == "/-/ping" {
        return Ok(json_response(StatusCode::OK, json!({}), HEADER_JSON));
    }

    if method == Method::GET && path == "/-/whoami" {
        let Some(username) = auth_user else {
            return Err(RegistryError::http(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
            ));
        };
        return Ok(json_response(
            StatusCode::OK,
            json!({ "username": username }),
            HEADER_JSON,
        ));
    }

    if path == "/-/all" || path == "/-/all/since" {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            json!({"error": "not found, endpoint was removed"}),
            HEADER_JSON,
        ));
    }

    if path == "/-/v1/search" && method == Method::GET {
        return handle_search(&state, query.as_deref(), auth_user.as_deref()).await;
    }

    if path == "/-/npm/v1/security/advisories/bulk" && method == Method::POST {
        let payload = parse_json_body(&read_body(req).await?)?;
        if let Some(upstream) = select_default_uplink(&state)
            && let Some(body) = upstream.post_security_advisories_bulk(&payload).await?
        {
            return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
        }
        return Ok(json_response(StatusCode::OK, json!({}), HEADER_JSON));
    }

    if path == "/-/npm/v1/security/audits/quick" && method == Method::POST {
        let payload = parse_json_body(&read_body(req).await?)?;
        if let Some(upstream) = select_default_uplink(&state)
            && let Some(body) = upstream.post_security_audits_quick(&payload).await?
        {
            return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
        }
        return Ok(json_response(
            StatusCode::OK,
            empty_quick_audit_response(),
            HEADER_JSON,
        ));
    }

    if path == "/-/npm/v1/security/audits" && method == Method::POST {
        let payload = parse_json_body(&read_body(req).await?)?;
        if let Some(upstream) = select_default_uplink(&state)
            && let Some(body) = upstream.post_security_audits(&payload).await?
        {
            return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
        }
        return Ok(json_response(
            StatusCode::OK,
            empty_audit_response(),
            HEADER_JSON,
        ));
    }

    if path == "/-/_view/starredByUser" && method == Method::GET {
        let params = query_params(query.as_deref());
        let Some(raw_key) = params.get("key") else {
            return Err(bad_request("missing query key username"));
        };
        let key = Store::parse_star_key(raw_key);
        let rows = state.store.starred_packages(&key).await;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "rows": rows.into_iter().map(|name| json!({"value": name})).collect::<Vec<_>>()
            }),
            HEADER_JSON,
        ));
    }

    if let Some((package_name, tag)) = parse_canonical_dist_tags_path(&path) {
        if method == Method::GET && tag.is_none() {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            let tags = state.store.dist_tags(&package_name).await?;
            return Ok(json_response(StatusCode::OK, tags, HEADER_JSON));
        }

        if method == Method::PUT {
            ensure_publish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let bytes = read_body(req).await?;
            let version = parse_json_string_body(&bytes)?;
            let message = state
                .store
                .merge_dist_tag(
                    &package_name,
                    tag.as_deref().unwrap_or_default(),
                    Some(&version),
                )
                .await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }

        if method == Method::DELETE {
            ensure_publish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state
                .store
                .merge_dist_tag(&package_name, tag.as_deref().unwrap_or_default(), None)
                .await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    if path == "/-/npm/v1/user" {
        if method == Method::GET {
            let Some(name) = auth_user else {
                return Ok(json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({ "message": Store::login_required_message() }),
                    HEADER_JSON,
                ));
            };
            return Ok(json_response(
                StatusCode::OK,
                default_profile(&name),
                HEADER_JSON,
            ));
        }

        if method == Method::POST {
            let Some(name) = auth_user else {
                return Ok(json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({ "message": Store::login_required_message() }),
                    HEADER_JSON,
                ));
            };

            let body = parse_json_body(&read_body(req).await?)?;
            let password_obj = body.get("password").and_then(Value::as_object);
            let old = password_obj
                .and_then(|obj| obj.get("old"))
                .and_then(Value::as_str);
            let new = password_obj
                .and_then(|obj| obj.get("new"))
                .and_then(Value::as_str);
            let tfa_present = body.get("tfa").is_some();

            Store::ensure_profile_body_valid(old, new, tfa_present, 3)?;
            state
                .store
                .change_password(&name, old.unwrap_or_default(), new.unwrap_or_default())
                .await?;
            return Ok(json_response(
                StatusCode::OK,
                default_profile(&name),
                HEADER_JSON,
            ));
        }
    }

    if path == "/-/npm/v1/tokens" {
        let user = auth_user
            .clone()
            .ok_or_else(crate::storage::no_credentials)?;
        if method == Method::GET {
            let tokens = state.store.list_npm_tokens(&user).await;
            let body = state.store.token_list_response(tokens);
            return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
        }

        if method == Method::POST {
            let body = parse_json_body(&read_body(req).await?)?;
            let password = body
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let readonly = body.get("readonly").and_then(Value::as_bool);
            let cidr_whitelist =
                body.get("cidr_whitelist")
                    .and_then(Value::as_array)
                    .map(|array| {
                        array
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned)
                            .collect::<Vec<_>>()
                    });

            let (readonly, cidr_whitelist) =
                Store::normalize_support_errors(readonly, cidr_whitelist)?;

            let (saved, raw) = state
                .store
                .create_npm_token(&user, password, readonly, cidr_whitelist)
                .await?;
            let body = Store::normalize_token_response(&saved, Some(raw));
            return Ok(json_response_with_header(
                StatusCode::OK,
                body,
                HEADER_JSON,
                header::CACHE_CONTROL,
                "no-cache, no-store",
            ));
        }
    }

    if let Some(token_key) = path.strip_prefix("/-/npm/v1/tokens/token/")
        && method == Method::DELETE
    {
        let user = auth_user
            .clone()
            .ok_or_else(crate::storage::no_credentials)?;
        state.store.delete_npm_token(&user, token_key).await?;
        return Ok(json_response(StatusCode::OK, json!({}), HEADER_JSON));
    }

    if path == "/-/v1/login" && method == Method::POST {
        if !state.web_login_enabled {
            return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
        }
        let session_id = state.store.create_login_session().await?;
        let base = request_base_url(&headers);
        let response = json!({
            "loginUrl": format!("{base}/-/web/login?next=/-/v1/login_cli/{session_id}"),
            "doneUrl": format!("{base}/-/v1/done/{session_id}"),
        });
        return Ok(json_response(StatusCode::OK, response, HEADER_JSON));
    }

    if let Some(session_id) = path.strip_prefix("/-/v1/done/")
        && method == Method::GET
    {
        if !state.web_login_enabled {
            return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
        }
        Store::ensure_session_id(Some(session_id))?;
        match state.store.poll_login_session(session_id).await? {
            Some(token) => {
                return Ok(json_response(
                    StatusCode::OK,
                    json!({ "token": token }),
                    HEADER_JSON,
                ));
            }
            None => {
                return Ok(json_response_with_header(
                    StatusCode::ACCEPTED,
                    json!({}),
                    HEADER_JSON,
                    header::RETRY_AFTER,
                    "5",
                ));
            }
        }
    }

    if let Some(session_id) = path.strip_prefix("/-/v1/login_cli/")
        && method == Method::POST
    {
        if !state.web_login_enabled {
            return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
        }
        Store::ensure_session_id(Some(session_id))?;
        let body = parse_json_body(&read_body(req).await?)?;
        let username = body
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let password = body
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let token = state.store.login_user(username, password).await?;
        state
            .store
            .set_login_session_token(session_id, token.clone())
            .await?;

        return Ok(json_response_with_header(
            StatusCode::CREATED,
            json!({
                "ok": Store::format_logged_user(username),
                "token": token,
            }),
            HEADER_JSON,
            header::CACHE_CONTROL,
            "no-cache, no-store",
        ));
    }

    if let Some(rest) = path.strip_prefix("/-/user/") {
        if method == Method::DELETE && rest.starts_with("token/") {
            return Ok(json_response(
                StatusCode::OK,
                json!({"ok": Store::logged_out_message()}),
                HEADER_JSON,
            ));
        }

        let org_user = rest.split('/').next().unwrap_or_default();

        if method == Method::GET {
            if auth_user.is_none() {
                return Ok(json_response(
                    StatusCode::OK,
                    json!({"ok": false}),
                    HEADER_JSON,
                ));
            }

            let requested = org_user.split_once(':').map(|(_, n)| n).unwrap_or_default();
            let logged = auth_user.unwrap_or_default();
            return Ok(json_response(
                StatusCode::OK,
                json!({
                    "name": requested,
                    "email": "",
                    "ok": Store::format_logged_user(&logged),
                }),
                HEADER_JSON,
            ));
        }

        if method == Method::PUT {
            let body = parse_json_body(&read_body(req).await?)?;
            let name = body.get("name").and_then(Value::as_str).unwrap_or_default();
            let password = body.get("password").and_then(Value::as_str);

            if !Store::validate_user_name(org_user, name) {
                return Err(bad_request(Store::username_mismatch_message()));
            }

            if auth_user.as_deref() == Some(name) {
                let token = state
                    .store
                    .login_user(name, password.unwrap_or_default())
                    .await?;
                return Ok(json_response_with_header(
                    StatusCode::CREATED,
                    json!({
                        "ok": Store::format_logged_user(name),
                        "token": token,
                    }),
                    HEADER_JSON,
                    header::CACHE_CONTROL,
                    "no-cache, no-store",
                ));
            }

            state.store.validate_password_length(password)?;
            let token = state
                .store
                .create_user(name, password.unwrap_or_default())
                .await?;
            return Ok(json_response_with_header(
                StatusCode::CREATED,
                json!({
                    "ok": format!("user '{name}' created"),
                    "token": token,
                }),
                HEADER_JSON,
                header::CACHE_CONTROL,
                "no-cache, no-store",
            ));
        }
    }

    if let Some((package_name, tail)) = parse_package_path(&path) {
        return handle_package_routes(PackageRouteContext {
            state,
            method,
            headers,
            query,
            auth_user,
            package_name,
            tail,
            req,
        })
        .await;
    }

    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

struct PackageRouteContext {
    state: AppState,
    method: Method,
    headers: HeaderMap,
    query: Option<String>,
    auth_user: Option<String>,
    package_name: String,
    tail: Vec<String>,
    req: Request<Body>,
}

async fn handle_package_routes(ctx: PackageRouteContext) -> Result<Response<Body>, RegistryError> {
    let PackageRouteContext {
        state,
        method,
        headers,
        query,
        auth_user,
        package_name,
        tail,
        req,
    } = ctx;

    if method == Method::GET {
        if tail.is_empty() {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            return handle_get_package(
                &state,
                &headers,
                query.as_deref(),
                &package_name,
                auth_user.as_deref(),
            )
            .await;
        }

        if tail.len() == 1 {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            return handle_get_package_version(&state, &headers, &package_name, &tail[0]).await;
        }

        if tail.len() == 2 && tail[0] == "-" {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            return handle_get_tarball(&state, &package_name, &tail[1]).await;
        }
    }

    if method == Method::HEAD {
        if tail.is_empty() {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            let resp = handle_get_package(
                &state,
                &headers,
                query.as_deref(),
                &package_name,
                auth_user.as_deref(),
            )
            .await?;
            return Ok(head_response(resp));
        }

        if tail.len() == 1 {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            let resp =
                handle_get_package_version(&state, &headers, &package_name, &tail[0]).await?;
            return Ok(head_response(resp));
        }

        if tail.len() == 2 && tail[0] == "-" {
            ensure_access_permission(&state, &package_name, auth_user.as_deref())?;
            let resp = handle_get_tarball(&state, &package_name, &tail[1]).await?;
            return Ok(head_response(resp));
        }
    }

    if method == Method::PUT {
        if tail.is_empty() {
            ensure_publish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let user = auth_user.as_deref().unwrap_or(ANONYMOUS_USER);
            let body = parse_json_body(&read_body(req).await?)?;
            let message = state
                .store
                .publish_manifest(&package_name, body, user)
                .await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({"success": true, "ok": message}),
                HEADER_JSON,
            ));
        }

        if tail.len() == 2 && tail[0] == "-rev" {
            ensure_unpublish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let user = auth_user.as_deref().unwrap_or(ANONYMOUS_USER);
            let body = parse_json_body(&read_body(req).await?)?;
            let message = state
                .store
                .publish_manifest(&package_name, body, user)
                .await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({"success": true, "ok": message}),
                HEADER_JSON,
            ));
        }

        if tail.len() == 1 {
            ensure_publish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let version = parse_json_string_body(&read_body(req).await?)?;
            let message = state
                .store
                .merge_dist_tag(&package_name, &tail[0], Some(&version))
                .await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    if method == Method::DELETE {
        if tail.len() == 2 && tail[0] == "-rev" {
            ensure_unpublish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state.store.remove_package(&package_name).await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }

        if tail.len() == 4 && tail[0] == "-" && tail[2] == "-rev" {
            ensure_unpublish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_publish_permission(&state, &package_name, auth_user.as_deref())?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state.store.remove_tarball(&package_name, &tail[1]).await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

async fn handle_get_package(
    state: &AppState,
    headers: &HeaderMap,
    query: Option<&str>,
    package_name: &str,
    auth_user: Option<&str>,
) -> Result<Response<Body>, RegistryError> {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let abbreviated = accept.contains("application/vnd.npm.install-v1+json");
    let base = request_base_url(headers);

    ensure_package_cached(state, headers, package_name).await?;
    let local = state.store.get_package_record(package_name).await;
    let Some(record) = local else {
        return Err(RegistryError::http(
            StatusCode::NOT_FOUND,
            Store::no_package_message(),
        ));
    };

    let (normalized, _) =
        state
            .store
            .normalize_package_response(&record.manifest, package_name, &base);

    let write = crate::storage::parse_write_query(query);
    if write && auth_user.is_none() {
        return Err(bad_request(Store::login_required_message()));
    }
    if write {
        ensure_package_owner_permission(state, package_name, auth_user).await?;
    }

    if abbreviated {
        let body = state.store.abbreviated_manifest(&normalized);
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON_INSTALL));
    }

    Ok(json_response(StatusCode::OK, normalized, HEADER_JSON))
}

async fn handle_get_package_version(
    state: &AppState,
    headers: &HeaderMap,
    package_name: &str,
    query_version: &str,
) -> Result<Response<Body>, RegistryError> {
    ensure_package_cached(state, headers, package_name).await?;
    let base = request_base_url(headers);
    let Some(record) = state.store.get_package_record(package_name).await else {
        return Err(RegistryError::http(
            StatusCode::NOT_FOUND,
            Store::no_package_message(),
        ));
    };
    let (normalized, _) =
        state
            .store
            .normalize_package_response(&record.manifest, package_name, &base);

    let Some(version) = Store::package_version_by_query(&normalized, query_version) else {
        return Err(crate::storage::version_not_found(query_version));
    };

    Ok(json_response(StatusCode::OK, version, HEADER_JSON))
}

async fn handle_get_tarball(
    state: &AppState,
    package_name: &str,
    filename: &str,
) -> Result<Response<Body>, RegistryError> {
    if let Some(bytes) = state
        .store
        .read_local_tarball(package_name, filename)
        .await?
    {
        return Ok(bytes_response(StatusCode::OK, bytes));
    }

    if !state.store.is_known_package(package_name).await {
        let headers = HeaderMap::new();
        ensure_package_cached(state, &headers, package_name).await?;
        if let Some(bytes) = state
            .store
            .read_local_tarball(package_name, filename)
            .await?
        {
            return Ok(bytes_response(StatusCode::OK, bytes));
        }
        if !state.store.is_known_package(package_name).await {
            return Ok(bytes_response(StatusCode::NOT_FOUND, Vec::new()));
        }
    }

    if let Some(upstream) = select_uplink_for_package(state, package_name) {
        let url = state
            .store
            .upstream_tarball_url(package_name, filename)
            .await
            .unwrap_or_else(|| upstream.default_tarball_url(package_name, filename));

        if let Some(bytes) = upstream.fetch_tarball(&url).await? {
            state
                .store
                .set_upstream_tarball_url(package_name, filename, url)
                .await?;
            state
                .store
                .cache_tarball(package_name, filename, &bytes)
                .await?;
            return Ok(bytes_response(StatusCode::OK, bytes));
        }
    }

    Ok(bytes_response(StatusCode::NOT_FOUND, Vec::new()))
}

async fn ensure_package_cached(
    state: &AppState,
    headers: &HeaderMap,
    package_name: &str,
) -> Result<(), RegistryError> {
    if state.store.get_package_record(package_name).await.is_some() {
        return Ok(());
    }

    let Some(upstream) = select_uplink_for_package(state, package_name) else {
        return Ok(());
    };
    let Some(manifest) = upstream.fetch_package(package_name).await? else {
        return Ok(());
    };

    let base = request_base_url(headers);
    let (normalized, upstream_map) =
        state
            .store
            .normalize_package_response(&manifest, package_name, &base);
    state
        .store
        .upsert_upstream_package(package_name, normalized, upstream_map)
        .await?;
    Ok(())
}

async fn handle_search(
    state: &AppState,
    query: Option<&str>,
    auth_user: Option<&str>,
) -> Result<Response<Body>, RegistryError> {
    let params = query_params(query);
    let text = params
        .get("text")
        .cloned()
        .unwrap_or_default()
        .to_lowercase();
    let size = params
        .get("size")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20);
    let from = params
        .get("from")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let mut objects = Vec::new();

    for package in state.store.all_packages().await {
        if let Some(item) = make_search_object(&package.manifest) {
            let name = item
                .get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let name_lc = name.to_lowercase();

            if state.acl.can_access(&name, auth_user)
                && (text.is_empty() || name_lc.contains(&text))
            {
                objects.push(item);
            }
        }
    }

    for upstream in state.uplinks.values() {
        let remote = upstream.fetch_search(query.unwrap_or_default()).await?;
        for item in remote {
            let package_name = item
                .get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !package_name.is_empty() && state.acl.can_access(&package_name, auth_user) {
                objects.push(item);
            }
        }
    }

    let mut seen = HashSet::new();
    objects.retain(|item| {
        let key = item
            .get("package")
            .and_then(|pkg| pkg.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if key.is_empty() {
            return false;
        }
        if seen.contains(&key) {
            return false;
        }
        seen.insert(key)
    });

    let start = from.min(objects.len());
    let end = (start + size).min(objects.len());
    let sliced = objects[start..end].to_vec();

    Ok(json_response(
        StatusCode::OK,
        json!({
            "objects": sliced,
            "total": sliced.len(),
            "time": Store::search_response_time(),
        }),
        HEADER_JSON,
    ))
}

async fn resolve_auth_user(
    store: &Store,
    headers: &HeaderMap,
    path: &str,
) -> Result<Option<String>, RegistryError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let header_present = raw.is_some();
    let token = parse_authorization(raw);

    match token {
        Some(token) => {
            let Some(user) = store.username_from_auth_token(&token).await else {
                return Err(unauthorized_message_for_path(path));
            };
            Ok(Some(user))
        }
        None if header_present => Err(unauthorized_message_for_path(path)),
        None => Ok(None),
    }
}

fn unauthorized_message_for_path(path: &str) -> RegistryError {
    if let Some((package_name, _)) = parse_package_path(path) {
        return unauthorized(&format!(
            "authorization required to access package {package_name}"
        ));
    }
    unauthorized(Store::unauthorized_access_message())
}

fn ensure_access_permission(
    state: &AppState,
    package_name: &str,
    user: Option<&str>,
) -> Result<(), RegistryError> {
    if state.acl.can_access(package_name, user) {
        return Ok(());
    }
    Err(unauthorized(&format!(
        "authorization required to access package {package_name}"
    )))
}

fn ensure_publish_permission(
    state: &AppState,
    package_name: &str,
    user: Option<&str>,
) -> Result<(), RegistryError> {
    if state.acl.can_publish(package_name, user) {
        return Ok(());
    }
    Err(unauthorized(&format!(
        "authorization required to publish package {package_name}"
    )))
}

fn ensure_unpublish_permission(
    state: &AppState,
    package_name: &str,
    user: Option<&str>,
) -> Result<(), RegistryError> {
    if state.acl.can_unpublish(package_name, user) {
        return Ok(());
    }
    Err(unauthorized(&format!(
        "authorization required to unpublish package {package_name}"
    )))
}

async fn ensure_package_owner_permission(
    state: &AppState,
    package_name: &str,
    user: Option<&str>,
) -> Result<(), RegistryError> {
    if !state.publish_check_owners {
        return Ok(());
    }

    let Some(record) = state.store.get_package_record(package_name).await else {
        return Ok(());
    };

    let username = user.unwrap_or(ANONYMOUS_USER);
    if is_package_owner(&record.manifest, username) {
        return Ok(());
    }

    Err(forbidden(API_ERROR_ONLY_OWNER))
}

fn is_package_owner(manifest: &Value, username: &str) -> bool {
    let Some(maintainers) = manifest.get("maintainers").and_then(Value::as_array) else {
        return true;
    };
    if maintainers.is_empty() {
        return true;
    }

    maintainers.iter().any(|maintainer| {
        maintainer.as_str() == Some(username)
            || maintainer.get("name").and_then(Value::as_str) == Some(username)
    })
}

fn select_uplink_for_package<'a>(
    state: &'a AppState,
    package_name: &str,
) -> Option<&'a crate::upstream::Upstream> {
    if let Some(proxy_name) = state.acl.proxy_for(package_name) {
        return state.uplinks.get(proxy_name);
    }
    state
        .uplinks
        .get("default")
        .or_else(|| state.uplinks.values().next())
}

fn select_default_uplink(state: &AppState) -> Option<&crate::upstream::Upstream> {
    state
        .uplinks
        .get("default")
        .or_else(|| state.uplinks.values().next())
}

fn empty_quick_audit_response() -> Value {
    json!({
        "auditReportVersion": 2,
        "actions": [],
        "advisories": {},
        "vulnerabilities": {},
        "muted": [],
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 0,
                "critical": 0,
            },
            "dependencies": 0,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 0,
        }
    })
}

fn empty_audit_response() -> Value {
    let mut body = empty_quick_audit_response();
    if let Some(obj) = body.as_object_mut() {
        obj.insert("runId".to_string(), Value::String("0".to_string()));
    }
    body
}

fn query_params(query: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(query) = query else {
        return out;
    };

    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let key = urlencoding::decode(key)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| key.to_string());
        let value = urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string());
        out.insert(key, value);
    }

    out
}

fn parse_canonical_dist_tags_path(path: &str) -> Option<(String, Option<String>)> {
    let rest = path.strip_prefix("/-/package/")?;
    let idx = rest.find("/dist-tags")?;
    let pkg = decode_path_component(&rest[..idx]);
    let suffix = &rest[idx + "/dist-tags".len()..];
    if suffix.is_empty() {
        return Some((pkg, None));
    }
    let tag = suffix.strip_prefix('/').map(decode_path_component);
    Some((pkg, tag))
}

fn parse_package_path(path: &str) -> Option<(String, Vec<String>)> {
    if path.starts_with("/-/") {
        return None;
    }

    let clean = path.trim_start_matches('/');
    if clean.is_empty() {
        return None;
    }

    let segments: Vec<String> = clean.split('/').map(decode_path_component).collect();

    if segments.is_empty() {
        return None;
    }

    if segments[0].starts_with('@') && !segments[0].contains('/') {
        if segments.len() < 2 {
            return None;
        }
        let package = format!("{}/{}", segments[0], segments[1]);
        let tail = segments[2..].to_vec();
        return Some((package, tail));
    }

    let package = segments[0].clone();
    let tail = segments[1..].to_vec();
    Some((package, tail))
}

fn decode_path_component(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn request_base_url(headers: &HeaderMap) -> String {
    let protocol = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost:4873");

    format!("{protocol}://{host}")
}

fn json_response(status: StatusCode, body: Value, content_type: &str) -> Response<Body> {
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::from("{}")))
}

fn json_response_with_header(
    status: StatusCode,
    body: Value,
    content_type: &str,
    header_name: HeaderName,
    header_value: &str,
) -> Response<Body> {
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let header_value = HeaderValue::from_str(header_value)
        .unwrap_or_else(|_| HeaderValue::from_static("no-cache, no-store"));

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header_name, header_value)
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::from("{}")))
}

fn bytes_response(status: StatusCode, bytes: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, HEADER_OCTET)
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::from(Vec::<u8>::new())))
}

fn head_response(mut response: Response<Body>) -> Response<Body> {
    *response.body_mut() = Body::empty();
    response
}

async fn read_body(req: Request<Body>) -> Result<Vec<u8>, RegistryError> {
    to_bytes(req.into_body(), 50 * 1024 * 1024)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|_| RegistryError::Internal)
}
