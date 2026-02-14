use crate::{
    app::AppState,
    constants::{
        ANONYMOUS_USER, API_ERROR_ONLY_OWNER, API_ERROR_SERVER_TIME_OUT, HEADER_JSON,
        HEADER_JSON_INSTALL, HEADER_OCTET,
    },
    error::RegistryError,
    governance::{GovernanceAction, GovernanceContext},
    models::{AuthIdentity, TenantContext},
    policy::{PolicyAction, RequestContext},
    storage::{
        Store, bad_request, default_profile, forbidden, make_search_object, parse_authorization,
        parse_json_body, parse_json_string_body, unauthorized,
    },
};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{
        HeaderMap, Method, Response, StatusCode,
        header::{self, HeaderName, HeaderValue},
    },
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use tracing::{debug, instrument, warn};

pub async fn dispatch(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, RegistryError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let raw_path = uri.path().to_string();
    let Some(path) = normalize_incoming_path(&raw_path, &state.url_prefix) else {
        warn!(
            raw_path,
            url_prefix = state.url_prefix.as_str(),
            "request path did not match configured url_prefix"
        );
        return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
    };
    let query = uri.query().map(ToOwned::to_owned);
    let headers = req.headers().clone();
    let request_context = RequestContext {
        method: method.to_string(),
        path: path.clone(),
        tenant: tenant_context_from_headers(&headers),
    };
    let span = tracing::Span::current();
    span.record("method", tracing::field::display(&method));
    span.record("path", tracing::field::display(&raw_path));
    debug!(has_query = query.is_some(), "dispatching request");

    if let Some(response) = crate::web_ui::maybe_handle_request(&state, &method, &path) {
        return Ok(response);
    }

    let auth_identity = resolve_auth_identity(&state.store, &headers, &method, &path).await?;
    let auth_user = auth_identity_primary_name(auth_identity.as_ref()).map(ToOwned::to_owned);

    if method == Method::GET
        && let Some(metrics_path) = state.governance.metrics_path()
        && path == metrics_path
    {
        if state.governance.metrics_require_admin() {
            ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        }
        if let Some(metrics) = state.governance.render_metrics().await {
            return Ok(text_response(
                StatusCode::OK,
                "text/plain; version=0.0.4",
                metrics,
            ));
        }
        return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
    }

    let governance_context = governance_context_for_request(
        &method,
        &path,
        &headers,
        auth_identity.as_ref(),
        &request_context.tenant,
    );
    state.governance.enforce(&governance_context).await?;

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

    if method == Method::POST && path == "/-/admin/reindex" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        let body = state.store.reindex_from_backend().await?;
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
    }

    if method == Method::GET && path == "/-/admin/storage-health" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        let body = state.store.storage_health().await?;
        return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
    }

    if method == Method::POST && path == "/-/admin/policy-cache/invalidate" {
        ensure_admin_authenticated(&state, auth_identity.as_ref())?;
        state.policy.invalidate_cache().await?;
        return Ok(json_response(
            StatusCode::OK,
            json!({ "ok": "policy cache invalidated" }),
            HEADER_JSON,
        ));
    }

    if method == Method::GET && (path == "/-/all" || path == "/-/all/since") {
        return local_database_response(
            &state,
            query.as_deref(),
            auth_identity.as_ref(),
            &request_context,
        )
        .await;
    }

    if path == "/-/v1/search" && method == Method::GET {
        return handle_search(
            &state,
            query.as_deref(),
            auth_identity.as_ref(),
            &request_context,
        )
        .await;
    }

    if path == "/-/npm/v1/security/advisories/bulk" && method == Method::POST {
        ensure_audit_enabled(&state)?;
        let payload = parse_json_body(&read_body(req, state.max_body_size).await?)?;
        for upstream in select_default_uplinks(&state) {
            match upstream.post_security_advisories_bulk(&payload).await {
                Ok(Some(body)) => return Ok(json_response(StatusCode::OK, body, HEADER_JSON)),
                Ok(None) => continue,
                Err(err) if is_uplink_transient_error(&err) => continue,
                Err(err) => return Err(err),
            }
        }
        return Ok(json_response(StatusCode::OK, json!({}), HEADER_JSON));
    }

    if path == "/-/npm/v1/security/audits/quick" && method == Method::POST {
        ensure_audit_enabled(&state)?;
        let payload = parse_json_body(&read_body(req, state.max_body_size).await?)?;
        for upstream in select_default_uplinks(&state) {
            match upstream.post_security_audits_quick(&payload).await {
                Ok(Some(body)) => return Ok(json_response(StatusCode::OK, body, HEADER_JSON)),
                Ok(None) => continue,
                Err(err) if is_uplink_transient_error(&err) => continue,
                Err(err) => return Err(err),
            }
        }
        return Ok(json_response(
            StatusCode::OK,
            empty_quick_audit_response(),
            HEADER_JSON,
        ));
    }

    if path == "/-/npm/v1/security/audits" && method == Method::POST {
        ensure_audit_enabled(&state)?;
        let payload = parse_json_body(&read_body(req, state.max_body_size).await?)?;
        for upstream in select_default_uplinks(&state) {
            match upstream.post_security_audits(&payload).await {
                Ok(Some(body)) => return Ok(json_response(StatusCode::OK, body, HEADER_JSON)),
                Ok(None) => continue,
                Err(err) if is_uplink_transient_error(&err) => continue,
                Err(err) => return Err(err),
            }
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
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            let tags = state.store.dist_tags(&package_name).await?;
            return Ok(json_response(StatusCode::OK, tags, HEADER_JSON));
        }

        if method == Method::PUT {
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let bytes = read_body(req, state.max_body_size).await?;
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
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
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
        ensure_local_auth_routes_enabled(&state)?;
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

            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
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
        ensure_local_auth_routes_enabled(&state)?;
        let user = auth_user
            .clone()
            .ok_or_else(crate::storage::no_credentials)?;
        if method == Method::GET {
            let tokens = state.store.list_npm_tokens(&user).await;
            let body = state.store.token_list_response(tokens);
            return Ok(json_response(StatusCode::OK, body, HEADER_JSON));
        }

        if method == Method::POST {
            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
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
        ensure_local_auth_routes_enabled(&state)?;
        let user = auth_user
            .clone()
            .ok_or_else(crate::storage::no_credentials)?;
        state.store.delete_npm_token(&user, token_key).await?;
        return Ok(json_response(StatusCode::OK, json!({}), HEADER_JSON));
    }

    if path == "/-/v1/login" && method == Method::POST {
        ensure_local_auth_routes_enabled(&state)?;
        if !state.web_login_enabled {
            return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
        }
        let session_id = state.store.create_login_session().await?;
        let base = request_registry_base_url(&headers, state.trust_proxy, &state.url_prefix);
        let next = prefixed_route_path(&state.url_prefix, &format!("/-/v1/login_cli/{session_id}"));
        let response = json!({
            "loginUrl": format!("{base}/-/web/login?next={next}"),
            "doneUrl": format!("{base}/-/v1/done/{session_id}"),
        });
        return Ok(json_response(StatusCode::OK, response, HEADER_JSON));
    }

    if let Some(session_id) = path.strip_prefix("/-/v1/done/")
        && method == Method::GET
    {
        ensure_local_auth_routes_enabled(&state)?;
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
        ensure_local_auth_routes_enabled(&state)?;
        if !state.web_login_enabled {
            return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
        }
        Store::ensure_session_id(Some(session_id))?;
        let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
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
        ensure_local_auth_routes_enabled(&state)?;
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
            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
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
            request_context,
            query,
            auth_user,
            auth_identity,
            package_name,
            tail,
            req,
        })
        .await;
    }

    let mut upstream_error = false;
    for upstream in select_default_uplinks(&state) {
        match upstream
            .passthrough_request(&method, &path, query.as_deref())
            .await
        {
            Ok(Some(proxy)) if is_transient_uplink_status(proxy.status) => {
                upstream_error = true;
                continue;
            }
            Ok(Some(proxy)) => return Ok(proxy_response(proxy)),
            Ok(None) => continue,
            Err(err) if is_uplink_transient_error(&err) => {
                upstream_error = true;
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    if upstream_error {
        return Err(RegistryError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            API_ERROR_SERVER_TIME_OUT,
        ));
    }

    warn!("route not found");
    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

struct PackageRouteContext {
    state: AppState,
    method: Method,
    headers: HeaderMap,
    request_context: RequestContext,
    query: Option<String>,
    auth_user: Option<String>,
    auth_identity: Option<AuthIdentity>,
    package_name: String,
    tail: Vec<String>,
    req: Request<Body>,
}

#[instrument(skip(ctx))]
async fn handle_package_routes(ctx: PackageRouteContext) -> Result<Response<Body>, RegistryError> {
    let PackageRouteContext {
        state,
        method,
        headers,
        request_context,
        query,
        auth_user,
        auth_identity,
        package_name,
        tail,
        req,
    } = ctx;
    debug!(
        package = package_name,
        method = %method,
        tail_len = tail.len(),
        authenticated = auth_identity.is_some(),
        "handling package route"
    );

    if method == Method::GET {
        if tail.is_empty() {
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
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
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            return handle_get_package_version(&state, &headers, &package_name, &tail[0]).await;
        }

        if tail.len() == 2 && tail[0] == "-" {
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            return handle_get_tarball(&state, &package_name, &tail[1]).await;
        }
    }

    if method == Method::HEAD {
        if tail.is_empty() {
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
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
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            let resp =
                handle_get_package_version(&state, &headers, &package_name, &tail[0]).await?;
            return Ok(head_response(resp));
        }

        if tail.len() == 2 && tail[0] == "-" {
            ensure_access_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            let resp = handle_get_tarball(&state, &package_name, &tail[1]).await?;
            return Ok(head_response(resp));
        }
    }

    if method == Method::PUT {
        if tail.is_empty() {
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let user = auth_user.as_deref().unwrap_or(ANONYMOUS_USER);
            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
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
            ensure_unpublish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_cached(&state, &headers, &package_name).await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let user = auth_user.as_deref().unwrap_or(ANONYMOUS_USER);
            let body = parse_json_body(&read_body(req, state.max_body_size).await?)?;
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
            ensure_publish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let version = parse_json_string_body(&read_body(req, state.max_body_size).await?)?;
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
            ensure_unpublish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state.store.remove_package(&package_name).await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }

        if tail.len() == 4 && tail[0] == "-" && tail[2] == "-rev" {
            ensure_unpublish_permission(
                &state,
                &package_name,
                auth_identity.as_ref(),
                &request_context,
            )
            .await?;
            ensure_package_owner_permission(&state, &package_name, auth_user.as_deref()).await?;
            let message = state.store.remove_tarball(&package_name, &tail[1]).await?;
            return Ok(json_response(
                StatusCode::CREATED,
                json!({ "ok": message }),
                HEADER_JSON,
            ));
        }
    }

    warn!(package = package_name, method = %method, "package route not found");
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
    let base = request_registry_base_url(headers, state.trust_proxy, &state.url_prefix);

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
    let base = request_registry_base_url(headers, state.trust_proxy, &state.url_prefix);
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

    let mut upstream_error = false;
    for upstream in select_uplinks_for_package(state, package_name) {
        let url = state
            .store
            .upstream_tarball_url(package_name, filename)
            .await
            .unwrap_or_else(|| upstream.default_tarball_url(package_name, filename));

        match upstream.fetch_tarball(&url).await {
            Ok(Some(bytes)) => {
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
            Ok(None) => continue,
            Err(err) if is_uplink_transient_error(&err) => {
                upstream_error = true;
            }
            Err(err) => return Err(err),
        }
    }
    if upstream_error {
        return Err(RegistryError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            API_ERROR_SERVER_TIME_OUT,
        ));
    }

    Ok(bytes_response(StatusCode::NOT_FOUND, Vec::new()))
}

#[instrument(skip(state, headers), fields(package = package_name))]
async fn ensure_package_cached(
    state: &AppState,
    headers: &HeaderMap,
    package_name: &str,
) -> Result<(), RegistryError> {
    if state.store.get_package_record(package_name).await.is_some() {
        debug!("package already cached");
        return Ok(());
    }

    let uplinks = select_uplinks_for_package(state, package_name);
    if uplinks.is_empty() {
        debug!("no upstream configured for package");
        return Ok(());
    }

    let mut had_upstream_error = false;
    for upstream in uplinks {
        let Some(manifest) = (match upstream.fetch_package(package_name).await {
            Ok(manifest) => manifest,
            Err(err) if is_uplink_transient_error(&err) => {
                had_upstream_error = true;
                continue;
            }
            Err(err) => return Err(err),
        }) else {
            continue;
        };

        let base = request_registry_base_url(headers, state.trust_proxy, &state.url_prefix);
        let (normalized, upstream_map) =
            state
                .store
                .normalize_package_response(&manifest, package_name, &base);
        state
            .store
            .upsert_upstream_package(package_name, normalized, upstream_map)
            .await?;
        debug!("cached package manifest from upstream");
        return Ok(());
    }

    if had_upstream_error {
        return Err(RegistryError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            API_ERROR_SERVER_TIME_OUT,
        ));
    }
    debug!("package missing on upstream");
    Ok(())
}

#[instrument(skip(state), fields(has_query = query.is_some(), authenticated = auth_identity.is_some()))]
async fn handle_search(
    state: &AppState,
    query: Option<&str>,
    auth_identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
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
        .unwrap_or(20)
        .min(250);
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

            let allowed = state
                .policy
                .authorize(PolicyAction::Access, &name, auth_identity, request_context)
                .await?;
            if allowed && (text.is_empty() || name_lc.contains(&text)) {
                objects.push(item);
            }
        }
    }

    for upstream in select_default_uplinks(state) {
        let remote = match upstream.fetch_search(query.unwrap_or_default()).await {
            Ok(remote) => remote,
            Err(err) if is_uplink_transient_error(&err) => continue,
            Err(err) => return Err(err),
        };
        for item in remote {
            let package_name = item
                .get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if package_name.is_empty() {
                continue;
            }
            let allowed = state
                .policy
                .authorize(
                    PolicyAction::Access,
                    &package_name,
                    auth_identity,
                    request_context,
                )
                .await?;
            if allowed {
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
    debug!(
        results = sliced.len(),
        total_before_paging = objects.len(),
        "search completed"
    );

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

#[instrument(skip(store, headers), fields(method = %method, path))]
async fn resolve_auth_identity(
    store: &Store,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
) -> Result<Option<AuthIdentity>, RegistryError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let header_present = raw.is_some();
    let auth_scheme = raw.and_then(|value| value.split_whitespace().next());
    let token = parse_authorization(raw);
    debug!(
        authorization_header = header_present,
        authorization_scheme = auth_scheme.unwrap_or("<none>"),
        "resolving auth identity"
    );

    match token {
        Some(token) => {
            let Some(identity) = store
                .authenticate_request(&token, method.as_str(), path)
                .await?
            else {
                warn!(
                    method = method.as_str(),
                    path, "authorization token rejected by auth backends"
                );
                return Err(unauthorized_message_for_path(path));
            };
            if identity.username.is_none() && identity.groups.is_empty() {
                warn!("auth identity did not contain a user");
                return Err(unauthorized_message_for_path(path));
            }
            debug!("token accepted");
            Ok(Some(identity))
        }
        None if header_present => {
            warn!(
                authorization_scheme = auth_scheme.unwrap_or("<unknown>"),
                "malformed authorization header (expected 'Bearer <token>')"
            );
            Err(unauthorized_message_for_path(path))
        }
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

async fn ensure_access_permission(
    state: &AppState,
    package_name: &str,
    identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<(), RegistryError> {
    let allowed = state
        .policy
        .authorize(
            PolicyAction::Access,
            package_name,
            identity,
            request_context,
        )
        .await?;
    if allowed {
        return Ok(());
    }
    warn!(
        package = package_name,
        user = auth_identity_primary_name(identity).unwrap_or(ANONYMOUS_USER),
        "access denied by policy engine"
    );
    Err(unauthorized(&format!(
        "authorization required to access package {package_name}"
    )))
}

async fn ensure_publish_permission(
    state: &AppState,
    package_name: &str,
    identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<(), RegistryError> {
    let allowed = state
        .policy
        .authorize(
            PolicyAction::Publish,
            package_name,
            identity,
            request_context,
        )
        .await?;
    if allowed {
        return Ok(());
    }
    warn!(
        package = package_name,
        user = auth_identity_primary_name(identity).unwrap_or(ANONYMOUS_USER),
        "publish denied by policy engine"
    );
    Err(unauthorized(&format!(
        "authorization required to publish package {package_name}"
    )))
}

async fn ensure_unpublish_permission(
    state: &AppState,
    package_name: &str,
    identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<(), RegistryError> {
    let allowed = state
        .policy
        .authorize(
            PolicyAction::Unpublish,
            package_name,
            identity,
            request_context,
        )
        .await?;
    if allowed {
        return Ok(());
    }
    warn!(
        package = package_name,
        user = auth_identity_primary_name(identity).unwrap_or(ANONYMOUS_USER),
        "unpublish denied by policy engine"
    );
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

fn auth_identity_primary_name(identity: Option<&AuthIdentity>) -> Option<&str> {
    let identity = identity?;
    identity
        .username
        .as_deref()
        .or_else(|| identity.groups.first().map(String::as_str))
}

fn select_uplinks_for_package<'a>(
    state: &'a AppState,
    package_name: &str,
) -> Vec<&'a crate::upstream::Upstream> {
    if !state.acl.uplinks_look_for(package_name) {
        return Vec::new();
    }

    let mut selected_names = Vec::new();
    if let Some(proxy_name) = state.acl.proxy_for(package_name) {
        selected_names.push(proxy_name.to_string());
    }
    if !selected_names.iter().any(|name| name == "default") {
        selected_names.push("default".to_string());
    }

    let mut remaining: Vec<String> = state.uplinks.keys().cloned().collect();
    remaining.sort();
    for name in remaining {
        if !selected_names.iter().any(|selected| selected == &name) {
            selected_names.push(name);
        }
    }

    selected_names
        .into_iter()
        .filter_map(|name| state.uplinks.get(&name))
        .collect()
}

fn select_default_uplinks(state: &AppState) -> Vec<&crate::upstream::Upstream> {
    let mut selected_names = vec!["default".to_string()];
    let mut remaining: Vec<String> = state.uplinks.keys().cloned().collect();
    remaining.sort();
    for name in remaining {
        if !selected_names.iter().any(|selected| selected == &name) {
            selected_names.push(name);
        }
    }

    selected_names
        .into_iter()
        .filter_map(|name| state.uplinks.get(&name))
        .collect()
}

fn is_uplink_transient_error(err: &RegistryError) -> bool {
    match err {
        RegistryError::Http { status, .. } => is_transient_uplink_status(*status),
        RegistryError::Internal => false,
    }
}

fn is_transient_uplink_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
            | StatusCode::REQUEST_TIMEOUT
    )
}

async fn local_database_response(
    state: &AppState,
    query: Option<&str>,
    auth_identity: Option<&AuthIdentity>,
    request_context: &RequestContext,
) -> Result<Response<Body>, RegistryError> {
    let params = query_params(query);
    let start_key = params
        .get("since")
        .or_else(|| params.get("startkey"))
        .cloned();

    let mut rows: Vec<(String, Value)> = Vec::new();
    for record in state.store.all_packages().await {
        let Some(name) = record
            .manifest
            .get("name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };

        let allowed = state
            .policy
            .authorize(PolicyAction::Access, &name, auth_identity, request_context)
            .await?;
        if !allowed {
            continue;
        }

        let latest = record
            .manifest
            .get("dist-tags")
            .and_then(|tags| tags.get("latest"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        rows.push((
            name.clone(),
            json!({
                "name": name,
                "version": latest,
            }),
        ));
    }
    rows.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut out = serde_json::Map::new();
    for (name, row) in rows {
        if let Some(start) = &start_key
            && name <= *start
        {
            continue;
        }
        out.insert(name, row);
    }

    Ok(json_response(
        StatusCode::OK,
        Value::Object(out),
        HEADER_JSON,
    ))
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

fn governance_context_for_request(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    identity: Option<&AuthIdentity>,
    tenant: &TenantContext,
) -> GovernanceContext {
    let (package_name, action) = if let Some((package_name, tail)) = parse_package_path(path) {
        let action = match method {
            &Method::GET | &Method::HEAD if tail.len() == 2 && tail[0] == "-" => {
                GovernanceAction::Download
            }
            &Method::GET | &Method::HEAD => GovernanceAction::Access,
            &Method::PUT if tail.is_empty() => GovernanceAction::Publish,
            &Method::PUT if tail.len() == 2 && tail[0] == "-rev" => GovernanceAction::Unpublish,
            &Method::DELETE if tail.len() == 2 && tail[0] == "-rev" => GovernanceAction::Unpublish,
            &Method::DELETE if tail.len() == 4 && tail[0] == "-" && tail[2] == "-rev" => {
                GovernanceAction::Unpublish
            }
            &Method::PUT if tail.len() == 1 => GovernanceAction::Publish,
            &Method::DELETE if tail.len() == 1 => GovernanceAction::Publish,
            _ => GovernanceAction::Other,
        };
        (Some(package_name), action)
    } else if let Some((package_name, tag)) = parse_canonical_dist_tags_path(path) {
        let action = match *method {
            Method::GET => GovernanceAction::Access,
            Method::PUT => GovernanceAction::Publish,
            Method::DELETE if tag.is_some() => GovernanceAction::Publish,
            _ => GovernanceAction::Other,
        };
        (Some(package_name), action)
    } else if method == Method::GET
        && (path == "/-/v1/search" || path == "/-/all" || path == "/-/all/since")
    {
        (None, GovernanceAction::Search)
    } else if path.starts_with("/-/admin/") {
        (None, GovernanceAction::Admin)
    } else {
        (None, GovernanceAction::Other)
    };

    GovernanceContext::from_identity(
        action,
        method.as_str(),
        path,
        package_name,
        identity,
        tenant.clone(),
        first_header_value(headers, &["x-forwarded-for"]).and_then(first_csv_token),
    )
}

fn first_csv_token(value: String) -> Option<String> {
    value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn tenant_context_from_headers(headers: &HeaderMap) -> TenantContext {
    TenantContext {
        org_id: first_header_value(headers, &["x-rustaccio-org-id", "x-org-id"]),
        project_id: first_header_value(headers, &["x-rustaccio-project-id", "x-project-id"]),
    }
}

fn first_header_value(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        headers
            .get(*name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn text_response(status: StatusCode, content_type: &str, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from(String::new())))
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

fn request_base_url(headers: &HeaderMap, trust_proxy: bool) -> String {
    let protocol = if trust_proxy {
        headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("http")
    } else {
        "http"
    };

    let host = if trust_proxy {
        headers
            .get("x-forwarded-host")
            .or_else(|| headers.get(header::HOST))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("localhost:4873")
    } else {
        headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("localhost:4873")
    };

    format!("{protocol}://{host}")
}

fn request_registry_base_url(headers: &HeaderMap, trust_proxy: bool, url_prefix: &str) -> String {
    let origin = request_base_url(headers, trust_proxy);
    if url_prefix == "/" {
        origin
    } else {
        format!("{origin}{url_prefix}")
    }
}

fn normalize_incoming_path(path: &str, url_prefix: &str) -> Option<String> {
    if url_prefix == "/" {
        return Some(path.to_string());
    }

    if path == url_prefix {
        return Some("/".to_string());
    }

    let prefix_with_slash = format!("{url_prefix}/");
    if let Some(stripped) = path.strip_prefix(&prefix_with_slash) {
        return Some(format!("/{stripped}"));
    }

    None
}

fn prefixed_route_path(url_prefix: &str, path: &str) -> String {
    if url_prefix == "/" {
        path.to_string()
    } else {
        format!("{}{}", url_prefix.trim_end_matches('/'), path)
    }
}

fn proxy_response(proxy: crate::upstream::UpstreamPassthroughResponse) -> Response<Body> {
    let mut builder = Response::builder().status(proxy.status);
    if let Some(content_type) = proxy.content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder
        .body(Body::from(proxy.body))
        .unwrap_or_else(|_| Response::new(Body::from(Vec::<u8>::new())))
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

fn ensure_local_auth_routes_enabled(state: &AppState) -> Result<(), RegistryError> {
    if state.auth_external_mode {
        return Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"));
    }
    Ok(())
}

fn ensure_audit_enabled(state: &AppState) -> Result<(), RegistryError> {
    if state.audit_enabled {
        return Ok(());
    }
    Err(RegistryError::http(StatusCode::NOT_FOUND, "not found"))
}

fn ensure_admin_authenticated(
    state: &AppState,
    identity: Option<&AuthIdentity>,
) -> Result<(), RegistryError> {
    let Some(identity) = identity else {
        return Err(RegistryError::http(
            StatusCode::UNAUTHORIZED,
            "authorization required",
        ));
    };

    if state.admin_access.allow_any_authenticated {
        return Ok(());
    }

    let is_user_admin = identity
        .username
        .as_deref()
        .map(|username| {
            state
                .admin_access
                .users
                .iter()
                .any(|allowed| allowed == username)
        })
        .unwrap_or(false);
    let is_group_admin = identity.groups.iter().any(|group| {
        state
            .admin_access
            .groups
            .iter()
            .any(|allowed| allowed == group)
    });

    if is_user_admin || is_group_admin {
        return Ok(());
    }

    Err(RegistryError::http(
        StatusCode::FORBIDDEN,
        "admin authorization required",
    ))
}

async fn read_body(req: Request<Body>, max_body_size: usize) -> Result<Vec<u8>, RegistryError> {
    to_bytes(req.into_body(), max_body_size)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|_| RegistryError::http(StatusCode::PAYLOAD_TOO_LARGE, "request entity too large"))
}
