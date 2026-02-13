use crate::{
    auth::AuthHook,
    auth_plugin::HttpAuthPlugin,
    config::AuthBackend,
    config::Config,
    constants::{
        API_ERROR_BAD_USERNAME_PASSWORD, API_ERROR_MUST_BE_LOGGED, API_ERROR_NO_PACKAGE,
        API_ERROR_NO_SUCH_FILE, API_ERROR_PACKAGE_EXIST, API_ERROR_PARAMETERS_NOT_VALID,
        API_ERROR_PASSWORD_SHORT, API_ERROR_PROFILE_ERROR, API_ERROR_SESSION_ID_INVALID,
        API_ERROR_SESSION_ID_REQUIRED, API_ERROR_SESSION_TOKEN_EXPIRED, API_ERROR_TFA_DISABLED,
        API_ERROR_UNAUTHORIZED_ACCESS, API_ERROR_UNSUPPORTED_REGISTRY_CALL,
        API_ERROR_USERNAME_ALREADY_REGISTERED, API_ERROR_USERNAME_MISMATCH,
        API_ERROR_VERSION_NOT_EXIST, API_MESSAGE_LOGGED_OUT, API_MESSAGE_PKG_CHANGED,
        API_MESSAGE_PKG_CREATED, API_MESSAGE_PKG_REMOVED, API_MESSAGE_TAG_ADDED,
        API_MESSAGE_TAG_REMOVED, API_MESSAGE_TARBALL_REMOVED,
    },
    error::RegistryError,
    models::{
        AuthIdentity, AuthTokenRecord, LoginSessionRecord, NpmTokenRecord, PackageRecord,
        PersistedState, UserRecord,
    },
    tarball_backend::TarballBackend,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use password_hash::{SaltString, rand_core::OsRng};
use rand::RngCore;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

#[derive(Default)]
pub struct StoreOptions {
    pub auth_hook: Option<Arc<dyn AuthHook>>,
}

pub struct Store {
    state: RwLock<PersistedState>,
    state_file: PathBuf,
    tarball_backend: TarballBackend,
    auth_plugin: Option<HttpAuthPlugin>,
    auth_hook: Option<Arc<dyn AuthHook>>,
    password_min_length: usize,
    login_session_ttl_seconds: i64,
}

impl Store {
    #[instrument(skip(config), fields(data_dir = %config.data_dir.display(), auth_backend = ?config.auth_plugin.backend))]
    pub async fn open(config: &Config) -> Result<Self, RegistryError> {
        Self::open_with_options(config, StoreOptions::default()).await
    }

    #[instrument(skip(config, options), fields(data_dir = %config.data_dir.display(), auth_backend = ?config.auth_plugin.backend, embedded_auth_hook = options.auth_hook.is_some()))]
    pub async fn open_with_options(
        config: &Config,
        options: StoreOptions,
    ) -> Result<Self, RegistryError> {
        tokio::fs::create_dir_all(&config.data_dir).await?;
        let tarball_backend = TarballBackend::from_config(config).await?;

        let state_file = config.data_dir.join("state.json");
        let mut state = if tarball_backend.supports_shared_state_snapshot() {
            if let Some(remote) = Self::read_shared_state_snapshot(&tarball_backend).await? {
                Self::write_local_snapshot(&state_file, &remote).await?;
                remote
            } else {
                Self::read_local_snapshot(&state_file).await?
            }
        } else {
            Self::read_local_snapshot(&state_file).await?
        };
        let pruned_legacy_uplink_cache_entries =
            Self::prune_legacy_uplink_snapshot_entries(&mut state);

        let auth_plugin = match config.auth_plugin.backend {
            AuthBackend::Local => None,
            AuthBackend::Http => {
                let plugin_cfg = config.auth_plugin.http.as_ref().ok_or_else(|| {
                    RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "auth backend http requires auth.http config",
                    )
                })?;
                Some(HttpAuthPlugin::new(plugin_cfg)?)
            }
        };

        let reindexed_from_backend =
            Self::hydrate_from_tarball_backend(&mut state, &tarball_backend).await?;

        let store = Self {
            state: RwLock::new(state),
            state_file,
            tarball_backend,
            auth_plugin,
            auth_hook: options.auth_hook,
            password_min_length: config.password_min_length,
            login_session_ttl_seconds: config.login_session_ttl_seconds,
        };
        if reindexed_from_backend || pruned_legacy_uplink_cache_entries > 0 {
            let snapshot = {
                let guard = store.state.read().await;
                guard.clone()
            };
            store.persist_snapshot(&snapshot).await?;
        }
        debug!(
            reindexed_from_backend,
            pruned_legacy_uplink_cache_entries, "store initialized"
        );
        Ok(store)
    }

    fn now_ms() -> i64 {
        Utc::now().timestamp_millis()
    }

    fn now_http() -> String {
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    async fn hydrate_from_tarball_backend(
        state: &mut PersistedState,
        tarball_backend: &TarballBackend,
    ) -> Result<bool, RegistryError> {
        let references = tarball_backend.list().await?;
        let discovered_packages = tarball_backend.list_packages().await?;
        let legacy_packages = tarball_backend
            .load_legacy_package_index()
            .await?
            .unwrap_or_default();

        let mut tarballs_by_package: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for reference in references {
            let Some(version) = Self::infer_version_from_filename(&reference.filename) else {
                continue;
            };
            tarballs_by_package
                .entry(reference.package)
                .or_default()
                .push((reference.filename, version));
        }

        let mut package_names = HashSet::new();
        package_names.extend(discovered_packages);
        package_names.extend(legacy_packages.iter().cloned());
        package_names.extend(tarballs_by_package.keys().cloned());

        if package_names.is_empty() {
            return Ok(false);
        }

        let mut ordered_packages = package_names.into_iter().collect::<Vec<_>>();
        ordered_packages.sort();

        let now_ms = Self::now_ms();
        let now_rfc3339 = Utc::now().to_rfc3339();
        let mut changed = false;
        let mut indexed_packages = 0usize;
        let mut indexed_versions = 0usize;
        let mut metadata_enriched_versions = 0usize;
        let before_package_count = state.packages.len();
        state.packages.retain(|package, record| {
            record.cached_from_uplink || ordered_packages.binary_search(package).is_ok()
        });
        let removed_stale_packages = before_package_count.saturating_sub(state.packages.len());
        if removed_stale_packages > 0 {
            changed = true;
        }
        let mut package_metadata_cache: HashMap<String, Option<Value>> = HashMap::new();

        for package_name in ordered_packages {
            if !package_metadata_cache.contains_key(&package_name) {
                let package_metadata = tarball_backend.read_package_metadata(&package_name).await?;
                package_metadata_cache.insert(package_name.clone(), package_metadata);
            }
            let package_metadata = package_metadata_cache
                .get(&package_name)
                .and_then(|value| value.as_ref());
            let package_tarballs = tarballs_by_package
                .remove(&package_name)
                .unwrap_or_default();

            if !state.packages.contains_key(&package_name) {
                let manifest = package_metadata
                    .cloned()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| {
                        Value::Object(Self::inferred_manifest_shell(&package_name, &now_rfc3339))
                    });
                state.packages.insert(
                    package_name.clone(),
                    PackageRecord {
                        manifest,
                        upstream_tarballs: HashMap::new(),
                        updated_at: now_ms,
                        cached_from_uplink: false,
                    },
                );
                indexed_packages += 1;
                changed = true;
            }

            let Some(record) = state.packages.get_mut(&package_name) else {
                continue;
            };
            let mut record_changed = false;
            if record.cached_from_uplink {
                record.cached_from_uplink = false;
                record_changed = true;
            }
            if let Some(metadata) = package_metadata.and_then(Value::as_object) {
                if !record.manifest.is_object() {
                    record.manifest = Value::Object(Map::new());
                    record_changed = true;
                }
                if let Some(manifest) = record.manifest.as_object_mut() {
                    for (key, value) in metadata {
                        if manifest.get(key) != Some(value) {
                            manifest.insert(key.clone(), value.clone());
                            record_changed = true;
                        }
                    }
                }
            } else if !record.manifest.is_object() {
                record.manifest =
                    Value::Object(Self::inferred_manifest_shell(&package_name, &now_rfc3339));
                record_changed = true;
            }

            let Some(manifest) = record.manifest.as_object_mut() else {
                continue;
            };

            if manifest.get("_id").and_then(Value::as_str) != Some(package_name.as_str()) {
                manifest.insert("_id".to_string(), Value::String(package_name.clone()));
                record_changed = true;
            }
            if manifest.get("name").and_then(Value::as_str) != Some(package_name.as_str()) {
                manifest.insert("name".to_string(), Value::String(package_name.clone()));
                record_changed = true;
            }
            if !manifest.contains_key("_rev") {
                manifest.insert("_rev".to_string(), Value::String(Self::initial_revision()));
                record_changed = true;
            }
            if let Some(metadata) = package_metadata
                && Self::merge_startup_manifest_metadata(manifest, metadata, &package_name)
            {
                record_changed = true;
            }

            {
                let versions = Self::ensure_object_field(manifest, "versions");
                for (filename, version) in &package_tarballs {
                    let was_known = versions.contains_key(version);
                    let payload = versions
                        .entry(version.clone())
                        .or_insert_with(|| Value::Object(Map::new()));
                    if !payload.is_object() {
                        *payload = Value::Object(Map::new());
                        record_changed = true;
                    }
                    if let Some(sidecar_version) =
                        Self::startup_metadata_for_version(package_metadata, version)
                    {
                        if let (Some(target), Some(source)) =
                            (payload.as_object_mut(), sidecar_version.as_object())
                        {
                            for (key, value) in source {
                                if target.get(key) != Some(value) {
                                    target.insert(key.clone(), value.clone());
                                    record_changed = true;
                                }
                            }
                        }
                    }
                    if let Some(target) = payload.as_object_mut() {
                        let expected_id = format!("{package_name}@{version}");
                        if target.get("_id").and_then(Value::as_str) != Some(expected_id.as_str()) {
                            target.insert("_id".to_string(), Value::String(expected_id));
                            record_changed = true;
                        }
                        if target.get("name").and_then(Value::as_str) != Some(package_name.as_str())
                        {
                            target.insert("name".to_string(), Value::String(package_name.clone()));
                            record_changed = true;
                        }
                        if target.get("version").and_then(Value::as_str) != Some(version.as_str()) {
                            target.insert("version".to_string(), Value::String(version.clone()));
                            record_changed = true;
                        }

                        let expected_tarball = Self::inferred_tarball_url(&package_name, filename);
                        let dist = target
                            .entry("dist".to_string())
                            .or_insert_with(|| Value::Object(Map::new()));
                        if !dist.is_object() {
                            *dist = Value::Object(Map::new());
                            record_changed = true;
                        }
                        if let Some(dist_obj) = dist.as_object_mut()
                            && dist_obj.get("tarball").and_then(Value::as_str)
                                != Some(expected_tarball.as_str())
                        {
                            dist_obj.insert("tarball".to_string(), Value::String(expected_tarball));
                            record_changed = true;
                        }
                    }
                    if !was_known {
                        indexed_versions += 1;
                        if Self::startup_metadata_for_version(package_metadata, version).is_some() {
                            metadata_enriched_versions += 1;
                        }
                    }
                }
            }

            let version_keys = manifest
                .get("versions")
                .and_then(Value::as_object)
                .map(|versions| versions.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let latest_version = manifest
                .get("versions")
                .and_then(Value::as_object)
                .and_then(Self::select_latest_version);

            let attachments = Self::ensure_object_field(manifest, "_attachments");
            for (filename, version) in &package_tarballs {
                let expected_attachment = json!({ "version": version });
                if attachments.get(filename) != Some(&expected_attachment) {
                    attachments.insert(filename.clone(), expected_attachment);
                    record_changed = true;
                }
            }

            let dist_tags = Self::ensure_object_field(manifest, "dist-tags");
            let latest_valid = dist_tags
                .get("latest")
                .and_then(Value::as_str)
                .is_some_and(|tag| version_keys.iter().any(|version| version == tag));
            if !latest_valid && let Some(latest) = latest_version {
                dist_tags.insert("latest".to_string(), Value::String(latest));
                record_changed = true;
            }

            if !manifest
                .get("maintainers")
                .is_some_and(serde_json::Value::is_array)
            {
                manifest.insert("maintainers".to_string(), Value::Array(Vec::new()));
                record_changed = true;
            }
            if !manifest
                .get("users")
                .is_some_and(serde_json::Value::is_object)
            {
                manifest.insert("users".to_string(), Value::Object(Map::new()));
                record_changed = true;
            }

            let time = Self::ensure_object_field(manifest, "time");
            if !time.contains_key("created") {
                time.insert("created".to_string(), Value::String(now_rfc3339.clone()));
                record_changed = true;
            }
            for version in version_keys {
                if !time.contains_key(&version) {
                    time.insert(version, Value::String(now_rfc3339.clone()));
                    record_changed = true;
                }
            }
            if !time.contains_key("modified") {
                time.insert("modified".to_string(), Value::String(now_rfc3339.clone()));
                record_changed = true;
            } else if record_changed {
                time.insert("modified".to_string(), Value::String(now_rfc3339.clone()));
            }

            if record_changed {
                record.updated_at = now_ms;
                changed = true;
            }
        }
        debug!(
            indexed_packages,
            indexed_versions,
            metadata_enriched_versions,
            legacy_seed_packages = legacy_packages.len(),
            removed_stale_packages,
            changed,
            "indexed tarball backend during startup"
        );
        Ok(changed)
    }

    fn inferred_manifest_shell(package_name: &str, now_rfc3339: &str) -> Map<String, Value> {
        let mut manifest = Map::new();
        manifest.insert("_id".to_string(), Value::String(package_name.to_string()));
        manifest.insert("name".to_string(), Value::String(package_name.to_string()));
        manifest.insert("_rev".to_string(), Value::String(Self::initial_revision()));
        manifest.insert("versions".to_string(), Value::Object(Map::new()));
        manifest.insert("dist-tags".to_string(), Value::Object(Map::new()));
        manifest.insert("_attachments".to_string(), Value::Object(Map::new()));
        manifest.insert("maintainers".to_string(), Value::Array(Vec::new()));
        manifest.insert("users".to_string(), Value::Object(Map::new()));
        manifest.insert(
            "time".to_string(),
            json!({
                "created": now_rfc3339,
                "modified": now_rfc3339,
            }),
        );
        manifest
    }

    fn ensure_object_field<'a>(
        manifest: &'a mut Map<String, Value>,
        key: &str,
    ) -> &'a mut Map<String, Value> {
        if !manifest.get(key).is_some_and(serde_json::Value::is_object) {
            manifest.insert(key.to_string(), Value::Object(Map::new()));
        }
        manifest
            .get_mut(key)
            .and_then(Value::as_object_mut)
            .expect("object field was initialized")
    }

    fn inferred_tarball_url(package_name: &str, filename: &str) -> String {
        format!(
            "http://localhost:4873/{}/-/{}",
            package_name_to_encoded(package_name),
            filename
        )
    }

    fn merge_startup_manifest_metadata(
        manifest: &mut Map<String, Value>,
        tarball_metadata: &Value,
        package_name: &str,
    ) -> bool {
        let Some(metadata) = tarball_metadata.as_object() else {
            return false;
        };

        let mut changed = false;
        if !manifest.contains_key("description")
            && let Some(description) = metadata.get("description")
            && description.is_string()
        {
            manifest.insert("description".to_string(), description.clone());
            changed = true;
        }
        if !manifest.contains_key("readme")
            && let Some(readme) = metadata.get("readme")
            && readme.is_string()
        {
            manifest.insert("readme".to_string(), readme.clone());
            changed = true;
        }

        let maintainers_empty = manifest
            .get("maintainers")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        if maintainers_empty
            && let Some(maintainers) = metadata.get("maintainers")
            && maintainers.is_array()
        {
            manifest.insert("maintainers".to_string(), maintainers.clone());
            changed = true;
        }

        manifest.insert("name".to_string(), Value::String(package_name.to_string()));
        manifest.insert("_id".to_string(), Value::String(package_name.to_string()));
        changed
    }

    fn startup_metadata_for_version<'a>(
        package_metadata: Option<&'a Value>,
        version: &str,
    ) -> Option<&'a Value> {
        let metadata = package_metadata?;
        let from_versions = metadata
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(version))
            .filter(|value| value.is_object());
        if from_versions.is_some() {
            return from_versions;
        }

        if metadata.get("version").and_then(Value::as_str) == Some(version) && metadata.is_object()
        {
            return Some(metadata);
        }

        None
    }

    fn select_latest_version(versions: &Map<String, Value>) -> Option<String> {
        let mut latest: Option<String> = None;
        for version in versions.keys() {
            match latest.as_deref() {
                Some(current) if Self::compare_versions(version, current).is_gt() => {
                    latest = Some(version.clone());
                }
                None => latest = Some(version.clone()),
                _ => {}
            }
        }
        latest
    }

    fn infer_version_from_filename(filename: &str) -> Option<String> {
        let stem = filename
            .strip_suffix(".tgz")
            .or_else(|| filename.strip_suffix(".tar.gz"))?;
        let (_, version) = stem.rsplit_once('-')?;
        if version.is_empty() {
            return None;
        }
        if !version
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_digit())
        {
            return None;
        }
        Some(version.to_string())
    }

    fn semverish(version: &str) -> Option<([u64; 3], bool, String)> {
        let without_build = version.split('+').next().unwrap_or(version);
        let (core, prerelease) = without_build
            .split_once('-')
            .map_or((without_build, None), |(core, pre)| (core, Some(pre)));
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((
            [major, minor, patch],
            prerelease.is_none(),
            prerelease.unwrap_or_default().to_string(),
        ))
    }

    fn compare_versions(candidate: &str, current: &str) -> Ordering {
        match (Self::semverish(candidate), Self::semverish(current)) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => candidate.cmp(current),
        }
    }

    fn random_token_hex(bytes: usize) -> String {
        let mut buf = vec![0_u8; bytes];
        rand::thread_rng().fill_bytes(&mut buf);
        hex::encode(buf)
    }

    fn token_key(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn mask_token(token: &str, exposed: usize) -> String {
        if token.len() <= exposed * 2 {
            return "***".to_string();
        }
        format!(
            "{}...{}",
            &token[0..exposed],
            &token[token.len() - exposed..token.len()]
        )
    }

    async fn read_local_snapshot(state_file: &Path) -> Result<PersistedState, RegistryError> {
        if tokio::fs::try_exists(state_file).await.unwrap_or(false) {
            let bytes = tokio::fs::read(state_file).await?;
            if bytes.is_empty() {
                Ok(PersistedState::default())
            } else {
                Ok(serde_json::from_slice(&bytes)?)
            }
        } else {
            Ok(PersistedState::default())
        }
    }

    async fn read_shared_state_snapshot(
        tarball_backend: &TarballBackend,
    ) -> Result<Option<PersistedState>, RegistryError> {
        let Some(bytes) = tarball_backend.load_shared_state_snapshot().await? else {
            return Ok(None);
        };
        if bytes.is_empty() {
            return Ok(Some(PersistedState::default()));
        }
        let snapshot = serde_json::from_slice::<PersistedState>(&bytes)?;
        Ok(Some(snapshot))
    }

    async fn write_local_snapshot(
        state_file: &Path,
        snapshot: &PersistedState,
    ) -> Result<(), RegistryError> {
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        Self::write_local_snapshot_bytes(state_file, &bytes).await
    }

    async fn write_local_snapshot_bytes(
        state_file: &Path,
        bytes: &[u8],
    ) -> Result<(), RegistryError> {
        let tmp_file = state_file.with_extension("json.tmp");
        tokio::fs::write(&tmp_file, bytes).await?;
        tokio::fs::rename(&tmp_file, state_file).await?;
        Ok(())
    }

    async fn persist_snapshot(&self, snapshot: &PersistedState) -> Result<(), RegistryError> {
        let mut persisted = snapshot.clone();
        Self::prune_ephemeral_uplink_cache_entries(&mut persisted);
        let bytes = serde_json::to_vec_pretty(&persisted)?;
        Self::write_local_snapshot_bytes(&self.state_file, &bytes).await?;
        if self.tarball_backend.supports_shared_state_snapshot() {
            self.tarball_backend
                .save_shared_state_snapshot(&bytes)
                .await?;
        }
        Ok(())
    }

    async fn sync_all_package_sidecars_from_snapshot(
        &self,
        snapshot: &PersistedState,
    ) -> Result<usize, RegistryError> {
        let mut synced = 0usize;
        for (package_name, record) in &snapshot.packages {
            if record.cached_from_uplink || !record.manifest.is_object() {
                continue;
            }
            self.tarball_backend
                .write_package_metadata(package_name, &record.manifest)
                .await?;
            synced += 1;
        }
        Ok(synced)
    }

    async fn sync_package_sidecar_from_snapshot(
        &self,
        snapshot: &PersistedState,
        package_name: &str,
    ) -> Result<(), RegistryError> {
        let Some(record) = snapshot.packages.get(package_name) else {
            return Ok(());
        };
        if record.cached_from_uplink || !record.manifest.is_object() {
            return Ok(());
        }
        self.tarball_backend
            .write_package_metadata(package_name, &record.manifest)
            .await
    }

    fn prune_ephemeral_uplink_cache_entries(state: &mut PersistedState) {
        state
            .packages
            .retain(|_, record| !record.cached_from_uplink);
    }

    fn prune_legacy_uplink_snapshot_entries(state: &mut PersistedState) -> usize {
        let before = state.packages.len();
        state.packages.retain(|_, record| {
            let attachments_empty = record
                .manifest
                .get("_attachments")
                .and_then(Value::as_object)
                .is_none_or(|attachments| attachments.is_empty());
            let looks_like_uplink_cache = attachments_empty && !record.upstream_tarballs.is_empty();
            !looks_like_uplink_cache
        });
        before.saturating_sub(state.packages.len())
    }

    async fn write_tarball_file(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        self.tarball_backend.put(package, filename, content).await
    }

    pub async fn read_local_tarball(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        self.tarball_backend.get(package, filename).await
    }

    pub async fn is_known_package(&self, package: &str) -> bool {
        let state = self.state.read().await;
        state.packages.contains_key(package)
    }

    pub async fn username_from_auth_token(&self, token: &str) -> Option<String> {
        let state = self.state.read().await;
        state
            .auth_tokens
            .get(token)
            .map(|record| record.user.clone())
    }

    pub async fn authenticate_request(
        &self,
        token: &str,
        method: &str,
        path: &str,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        if let Some(hook) = &self.auth_hook {
            debug!(method, path, "attempting request auth via embedded auth hook");
            if let Some(identity) = hook.authenticate_request(token, method, path).await? {
                debug!(
                    method,
                    path,
                    source = "embedded_auth_hook",
                    has_username = identity.username.is_some(),
                    group_count = identity.groups.len(),
                    "request auth accepted"
                );
                return Ok(Some(identity));
            }
        }
        if let Some(plugin) = &self.auth_plugin {
            debug!(method, path, "attempting request auth via external auth plugin");
            if let Some(identity) = plugin.authenticate_request(token, method, path).await? {
                debug!(
                    method,
                    path,
                    source = "external_auth_plugin",
                    has_username = identity.username.is_some(),
                    group_count = identity.groups.len(),
                    "request auth accepted"
                );
                return Ok(Some(identity));
            }
        }

        let local_identity = self
            .username_from_auth_token(token)
            .await
            .map(|username| AuthIdentity {
                username: Some(username),
                groups: Vec::new(),
            });
        if local_identity.is_some() {
            debug!(method, path, source = "local_token_store", "request auth accepted");
        } else {
            debug!(method, path, "request auth yielded no identity");
        }
        Ok(local_identity)
    }

    pub async fn allow_access(
        &self,
        identity: Option<&AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        if let Some(hook) = &self.auth_hook
            && let Some(allowed) = hook.allow_access(identity.cloned(), package_name).await?
        {
            return Ok(Some(allowed));
        }
        if let Some(plugin) = &self.auth_plugin
            && let Some(allowed) = plugin.allow_access(identity.cloned(), package_name).await?
        {
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    pub async fn allow_publish(
        &self,
        identity: Option<&AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        if let Some(hook) = &self.auth_hook
            && let Some(allowed) = hook.allow_publish(identity.cloned(), package_name).await?
        {
            return Ok(Some(allowed));
        }
        if let Some(plugin) = &self.auth_plugin
            && let Some(allowed) = plugin
                .allow_publish(identity.cloned(), package_name)
                .await?
        {
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    pub async fn allow_unpublish(
        &self,
        identity: Option<&AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        if let Some(hook) = &self.auth_hook
            && let Some(allowed) = hook
                .allow_unpublish(identity.cloned(), package_name)
                .await?
        {
            return Ok(Some(allowed));
        }
        if let Some(plugin) = &self.auth_plugin
            && let Some(allowed) = plugin
                .allow_unpublish(identity.cloned(), package_name)
                .await?
        {
            return Ok(Some(allowed));
        }
        Ok(None)
    }

    #[instrument(skip(self, password), fields(username = name))]
    pub async fn create_user(&self, name: &str, password: &str) -> Result<String, RegistryError> {
        if password.len() < self.password_min_length {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_PASSWORD_SHORT,
            ));
        }

        if let Some(hook) = &self.auth_hook {
            debug!("delegating user creation to embedded auth hook");
            hook.add_user(name, password, self.password_min_length)
                .await?;

            let snapshot = {
                let mut state = self.state.write().await;
                let token = Self::random_token_hex(24);
                state.auth_tokens.insert(
                    token.clone(),
                    AuthTokenRecord {
                        user: name.to_string(),
                        created_at: Self::now_ms(),
                    },
                );
                (state.clone(), token)
            };

            self.persist_snapshot(&snapshot.0).await?;
            debug!("created user via embedded auth hook");
            return Ok(snapshot.1);
        }

        if let Some(plugin) = &self.auth_plugin {
            debug!("delegating user creation to auth plugin");
            plugin
                .add_user(name, password, self.password_min_length)
                .await?;

            let snapshot = {
                let mut state = self.state.write().await;
                let token = Self::random_token_hex(24);
                state.auth_tokens.insert(
                    token.clone(),
                    AuthTokenRecord {
                        user: name.to_string(),
                        created_at: Self::now_ms(),
                    },
                );
                (state.clone(), token)
            };

            self.persist_snapshot(&snapshot.0).await?;
            debug!("created user via auth plugin");
            return Ok(snapshot.1);
        }

        let snapshot = {
            let mut state = self.state.write().await;
            if state.users.contains_key(name) {
                return Err(RegistryError::http(
                    StatusCode::CONFLICT,
                    API_ERROR_USERNAME_ALREADY_REGISTERED,
                ));
            }

            let hash = hash_password(password)?;
            state.users.insert(
                name.to_string(),
                UserRecord {
                    password_hash: hash,
                    created_at: Self::now_ms(),
                },
            );

            let token = Self::random_token_hex(24);
            state.auth_tokens.insert(
                token.clone(),
                AuthTokenRecord {
                    user: name.to_string(),
                    created_at: Self::now_ms(),
                },
            );

            let snapshot = state.clone();
            (snapshot, token)
        };

        self.persist_snapshot(&snapshot.0).await?;
        debug!("created local user");
        Ok(snapshot.1)
    }

    #[instrument(skip(self, password), fields(username = name))]
    pub async fn login_user(&self, name: &str, password: &str) -> Result<String, RegistryError> {
        if let Some(hook) = &self.auth_hook {
            debug!("delegating login to embedded auth hook");
            hook.authenticate(name, password).await?;
        } else if let Some(plugin) = &self.auth_plugin {
            debug!("delegating login to auth plugin");
            plugin.authenticate(name, password).await?;
        } else {
            let state = self.state.read().await;
            let Some(user) = state.users.get(name) else {
                return Err(RegistryError::http(
                    StatusCode::UNAUTHORIZED,
                    API_ERROR_BAD_USERNAME_PASSWORD,
                ));
            };
            verify_password(&user.password_hash, password)?;
        }

        let snapshot = {
            let mut state = self.state.write().await;
            let token = Self::random_token_hex(24);
            state.auth_tokens.insert(
                token.clone(),
                AuthTokenRecord {
                    user: name.to_string(),
                    created_at: Self::now_ms(),
                },
            );
            (state.clone(), token)
        };

        self.persist_snapshot(&snapshot.0).await?;
        debug!("user login succeeded");
        Ok(snapshot.1)
    }

    pub async fn verify_credentials(
        &self,
        name: &str,
        password: &str,
    ) -> Result<(), RegistryError> {
        if let Some(hook) = &self.auth_hook {
            return hook.authenticate(name, password).await;
        }
        if let Some(plugin) = &self.auth_plugin {
            return plugin.authenticate(name, password).await;
        }

        let state = self.state.read().await;
        let Some(user) = state.users.get(name) else {
            return Err(RegistryError::http(
                StatusCode::UNAUTHORIZED,
                API_ERROR_BAD_USERNAME_PASSWORD,
            ));
        };
        verify_password(&user.password_hash, password)
    }

    #[instrument(skip(self, old, new), fields(username = name))]
    pub async fn change_password(
        &self,
        name: &str,
        old: &str,
        new: &str,
    ) -> Result<(), RegistryError> {
        if let Some(hook) = &self.auth_hook {
            return hook
                .change_password(name, old, new, self.password_min_length)
                .await;
        }
        if let Some(plugin) = &self.auth_plugin {
            return plugin
                .change_password(name, old, new, self.password_min_length)
                .await;
        }

        if new.len() < self.password_min_length {
            return Err(RegistryError::http(
                StatusCode::UNAUTHORIZED,
                API_ERROR_PASSWORD_SHORT,
            ));
        }

        let snapshot = {
            let mut state = self.state.write().await;
            let Some(user) = state.users.get_mut(name) else {
                return Err(RegistryError::http(
                    StatusCode::UNAUTHORIZED,
                    API_ERROR_BAD_USERNAME_PASSWORD,
                ));
            };
            verify_password(&user.password_hash, old).map_err(|_| {
                RegistryError::http(StatusCode::FORBIDDEN, API_ERROR_BAD_USERNAME_PASSWORD)
            })?;
            user.password_hash = hash_password(new)?;
            state.clone()
        };

        self.persist_snapshot(&snapshot).await?;
        debug!("password changed");
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn create_login_session(&self) -> Result<String, RegistryError> {
        let session_id = Uuid::new_v4().to_string();
        let snapshot = {
            let mut state = self.state.write().await;
            state.login_sessions.insert(
                session_id.clone(),
                LoginSessionRecord {
                    token: String::new(),
                    created_at: Self::now_ms(),
                },
            );
            state.clone()
        };
        self.persist_snapshot(&snapshot).await?;
        debug!("created login session");
        Ok(session_id)
    }

    pub async fn set_login_session_token(
        &self,
        session_id: &str,
        token: String,
    ) -> Result<(), RegistryError> {
        let snapshot = {
            let mut state = self.state.write().await;
            let Some(session) = state.login_sessions.get_mut(session_id) else {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_SESSION_ID_INVALID,
                ));
            };
            session.token = token;
            session.created_at = Self::now_ms();
            state.clone()
        };
        self.persist_snapshot(&snapshot).await?;
        Ok(())
    }

    #[instrument(skip(self), fields(session_id))]
    pub async fn poll_login_session(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, RegistryError> {
        let snapshot_result = {
            let mut state = self.state.write().await;
            let Some(session) = state.login_sessions.get(session_id) else {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_SESSION_ID_INVALID,
                ));
            };

            if session.token.is_empty() {
                return Ok(None);
            }

            let token = session.token.clone();
            let created_at = session.created_at;
            state.login_sessions.remove(session_id);
            let snapshot = state.clone();
            (snapshot, token, created_at)
        };

        self.persist_snapshot(&snapshot_result.0).await?;

        let oldest = Self::now_ms() - (self.login_session_ttl_seconds * 1000);
        if snapshot_result.2 < oldest {
            warn!("login session token expired");
            return Err(RegistryError::http(
                StatusCode::UNAUTHORIZED,
                API_ERROR_SESSION_TOKEN_EXPIRED,
            ));
        }

        debug!("login session completed");
        Ok(Some(snapshot_result.1))
    }

    pub async fn list_npm_tokens(&self, user: &str) -> Vec<NpmTokenRecord> {
        let state = self.state.read().await;
        state
            .npm_tokens
            .iter()
            .filter(|token| token.user == user)
            .cloned()
            .collect()
    }

    #[instrument(skip(self, password, cidr_whitelist), fields(username = user, readonly))]
    pub async fn create_npm_token(
        &self,
        user: &str,
        password: &str,
        readonly: bool,
        cidr_whitelist: Vec<String>,
    ) -> Result<(NpmTokenRecord, String), RegistryError> {
        self.verify_credentials(user, password).await?;

        let raw_token = Self::random_token_hex(24);
        let token_key = Self::token_key(&raw_token);

        let token = NpmTokenRecord {
            user: user.to_string(),
            token: Self::mask_token(&raw_token, 5),
            key: token_key.clone(),
            auth_key: token_key.clone(),
            cidr: cidr_whitelist,
            readonly,
            created: Self::now_ms(),
        };

        let snapshot = {
            let mut state = self.state.write().await;
            state.npm_tokens.push(token.clone());
            state.clone()
        };

        self.persist_snapshot(&snapshot).await?;
        debug!("created npm token");
        Ok((token, raw_token))
    }

    #[instrument(skip(self), fields(username = user))]
    pub async fn delete_npm_token(&self, user: &str, token_key: &str) -> Result<(), RegistryError> {
        let snapshot = {
            let mut state = self.state.write().await;
            let before = state.npm_tokens.len();
            state
                .npm_tokens
                .retain(|token| !(token.user == user && token.key == token_key));
            if before == state.npm_tokens.len() {
                return Ok(());
            }
            state.clone()
        };

        self.persist_snapshot(&snapshot).await?;
        debug!("deleted npm token");
        Ok(())
    }

    fn package_record<'a>(
        state: &'a mut PersistedState,
        package: &str,
    ) -> Result<&'a mut PackageRecord, RegistryError> {
        state
            .packages
            .get_mut(package)
            .ok_or_else(|| RegistryError::http(StatusCode::NOT_FOUND, API_ERROR_NO_PACKAGE))
    }

    fn bump_revision(manifest: &mut Map<String, Value>) {
        let next = manifest
            .get("_rev")
            .and_then(Value::as_str)
            .and_then(|rev| rev.split_once('-').map(|(n, _)| n))
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        manifest.insert("_rev".to_string(), Value::String(Self::revision(next)));
    }

    fn initial_revision() -> String {
        Self::revision(1)
    }

    fn revision(counter: u64) -> String {
        format!("{counter}-{}", Self::random_token_hex(16))
    }

    fn remove_attachment_data(value: &Value) -> Value {
        let mut obj = value.as_object().cloned().unwrap_or_default();
        obj.remove("data");
        Value::Object(obj)
    }

    fn ensure_manifest_defaults(
        manifest: &mut Map<String, Value>,
        package_name: &str,
        username: &str,
    ) {
        manifest.insert("_id".to_string(), Value::String(package_name.to_string()));
        manifest.insert("name".to_string(), Value::String(package_name.to_string()));

        if manifest.get("maintainers").is_none() {
            manifest.insert(
                "maintainers".to_string(),
                json!([
                    {
                        "name": username,
                        "email": ""
                    }
                ]),
            );
        }

        if manifest.get("users").is_none() {
            manifest.insert("users".to_string(), Value::Object(Map::new()));
        }

        if manifest.get("dist-tags").is_none() {
            if let Some(versions) = manifest.get("versions").and_then(Value::as_object) {
                if let Some((first, _)) = versions.iter().next() {
                    manifest.insert("dist-tags".to_string(), json!({"latest": first}));
                } else {
                    manifest.insert("dist-tags".to_string(), Value::Object(Map::new()));
                }
            } else {
                manifest.insert("dist-tags".to_string(), Value::Object(Map::new()));
            }
        }

        let now = Utc::now().to_rfc3339();
        let time = manifest
            .entry("time")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(time_obj) = time.as_object_mut() {
            time_obj
                .entry("modified".to_string())
                .or_insert_with(|| Value::String(now.clone()));
            time_obj
                .entry("created".to_string())
                .or_insert_with(|| Value::String(now));
        }
    }

    fn has_attachment_data(body: &Value) -> bool {
        body.get("_attachments")
            .and_then(Value::as_object)
            .map(|attachments| {
                !attachments.is_empty()
                    && attachments
                        .values()
                        .all(|attachment| attachment.get("data").and_then(Value::as_str).is_some())
            })
            .unwrap_or(false)
    }

    fn merge_metadata_only_manifest(
        manifest: &mut Map<String, Value>,
        body: &Value,
    ) -> Result<(), RegistryError> {
        let incoming_versions =
            body.get("versions")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    RegistryError::http(
                        StatusCode::BAD_REQUEST,
                        API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                    )
                })?;

        let dst_versions = manifest
            .entry("versions".to_string())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(RegistryError::Internal)?;

        if incoming_versions
            .keys()
            .any(|version| !dst_versions.contains_key(version))
        {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_UNSUPPORTED_REGISTRY_CALL,
            ));
        }

        let existing_versions: Vec<String> = dst_versions.keys().cloned().collect();
        let mut removed_versions = HashSet::new();
        for version in existing_versions {
            let Some(incoming_version) = incoming_versions.get(&version) else {
                dst_versions.remove(&version);
                removed_versions.insert(version);
                continue;
            };

            let Some(incoming_obj) = incoming_version.as_object() else {
                continue;
            };
            if !incoming_obj.contains_key("deprecated") {
                continue;
            }

            let Some(local_obj) = dst_versions
                .get_mut(&version)
                .and_then(Value::as_object_mut)
            else {
                return Err(RegistryError::Internal);
            };

            match incoming_obj.get("deprecated") {
                Some(Value::String(value)) if !value.is_empty() => {
                    local_obj.insert("deprecated".to_string(), Value::String(value.clone()));
                }
                Some(Value::String(_)) | Some(Value::Null) | None => {
                    local_obj.remove("deprecated");
                }
                Some(other) => {
                    local_obj.insert("deprecated".to_string(), other.clone());
                }
            }
        }

        if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
            for removed in &removed_versions {
                time_obj.remove(removed);
            }
        }

        if let Some(tags) = body.get("dist-tags").and_then(Value::as_object) {
            manifest.insert("dist-tags".to_string(), Value::Object(tags.clone()));
        }

        if let Some(users) = body.get("users") {
            manifest.insert("users".to_string(), users.clone());
        }
        if let Some(maintainers) = body.get("maintainers") {
            manifest.insert("maintainers".to_string(), maintainers.clone());
        }

        if let Some(attachments) = body.get("_attachments").and_then(Value::as_object) {
            let mut new_attachments = Map::new();
            for (name, attachment) in attachments {
                new_attachments.insert(name.clone(), Self::remove_attachment_data(attachment));
            }
            manifest.insert("_attachments".to_string(), Value::Object(new_attachments));
        }

        if !removed_versions.is_empty()
            && let Some(tags) = manifest.get_mut("dist-tags").and_then(Value::as_object_mut)
        {
            let stale_tags: Vec<String> = tags
                .iter()
                .filter_map(|(tag, version)| {
                    let version = version.as_str().unwrap_or_default();
                    if removed_versions.contains(version) {
                        Some(tag.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for tag in stale_tags {
                tags.remove(&tag);
            }
        }

        Ok(())
    }

    #[instrument(skip(self, body), fields(package = package_name, username))]
    pub async fn publish_manifest(
        &self,
        package_name: &str,
        body: Value,
        username: &str,
    ) -> Result<String, RegistryError> {
        let is_owner_or_star_update = body.get("versions").is_none()
            && (body.get("users").is_some() || body.get("maintainers").is_some());

        if is_owner_or_star_update {
            let snapshot = {
                let mut state = self.state.write().await;
                let record = Self::package_record(&mut state, package_name)?;
                let Some(manifest) = record.manifest.as_object_mut() else {
                    return Err(RegistryError::Internal);
                };

                if let Some(users) = body.get("users") {
                    manifest.insert("users".to_string(), users.clone());
                }
                if let Some(maintainers) = body.get("maintainers") {
                    manifest.insert("maintainers".to_string(), maintainers.clone());
                }

                Self::ensure_manifest_defaults(manifest, package_name, username);
                Self::bump_revision(manifest);
                record.updated_at = Self::now_ms();
                record.cached_from_uplink = false;
                state.clone()
            };

            self.persist_snapshot(&snapshot).await?;
            self.sync_package_sidecar_from_snapshot(&snapshot, package_name)
                .await?;
            debug!("updated package owner/star metadata");
            return Ok(API_MESSAGE_PKG_CHANGED.to_string());
        }

        let versions = body
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;

        if !Self::has_attachment_data(&body) {
            let snapshot = {
                let mut state = self.state.write().await;
                let Some(record) = state.packages.get_mut(package_name) else {
                    return Err(RegistryError::http(
                        StatusCode::BAD_REQUEST,
                        API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                    ));
                };
                let Some(manifest) = record.manifest.as_object_mut() else {
                    return Err(RegistryError::Internal);
                };

                Self::merge_metadata_only_manifest(manifest, &body)?;
                Self::ensure_manifest_defaults(manifest, package_name, username);
                Self::bump_revision(manifest);

                if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
                    time_obj.insert(
                        "modified".to_string(),
                        Value::String(Utc::now().to_rfc3339()),
                    );
                }

                record.updated_at = Self::now_ms();
                record.cached_from_uplink = false;
                state.clone()
            };

            self.persist_snapshot(&snapshot).await?;
            self.sync_package_sidecar_from_snapshot(&snapshot, package_name)
                .await?;
            debug!("applied metadata-only publish update");
            return Ok(API_MESSAGE_PKG_CHANGED.to_string());
        }

        let attachments = body
            .get("_attachments")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;
        if attachments.is_empty() {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_UNSUPPORTED_REGISTRY_CALL,
            ));
        }

        for (filename, attachment) in attachments {
            let Some(data_b64) = attachment.get("data").and_then(Value::as_str) else {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                ));
            };
            let data = B64.decode(data_b64).map_err(|_| {
                RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
            })?;
            self.write_tarball_file(package_name, filename, &data)
                .await?;
        }

        let snapshot_and_message = {
            let mut state = self.state.write().await;

            let message;
            if let Some(record) = state.packages.get_mut(package_name) {
                let Some(manifest) = record.manifest.as_object_mut() else {
                    return Err(RegistryError::Internal);
                };

                let dst_versions = manifest
                    .entry("versions".to_string())
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .ok_or(RegistryError::Internal)?;

                for version in versions.keys() {
                    if dst_versions.contains_key(version) {
                        return Err(RegistryError::http(
                            StatusCode::CONFLICT,
                            API_ERROR_PACKAGE_EXIST,
                        ));
                    }
                }

                for (version, payload) in versions {
                    dst_versions.insert(version.clone(), payload.clone());
                }

                if let Some(tags) = body.get("dist-tags").and_then(Value::as_object) {
                    let dst_tags = manifest
                        .entry("dist-tags".to_string())
                        .or_insert_with(|| Value::Object(Map::new()))
                        .as_object_mut()
                        .ok_or(RegistryError::Internal)?;
                    for (tag, value) in tags {
                        dst_tags.insert(tag.clone(), value.clone());
                    }
                }

                let dst_attachments = manifest
                    .entry("_attachments".to_string())
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .ok_or(RegistryError::Internal)?;

                for (name, attachment) in attachments {
                    dst_attachments.insert(name.clone(), Self::remove_attachment_data(attachment));
                }

                if let Some(users) = body.get("users") {
                    manifest.insert("users".to_string(), users.clone());
                }
                if let Some(maintainers) = body.get("maintainers") {
                    manifest.insert("maintainers".to_string(), maintainers.clone());
                }

                Self::ensure_manifest_defaults(manifest, package_name, username);
                Self::bump_revision(manifest);

                if let Some(time_obj) = manifest.get_mut("time").and_then(Value::as_object_mut) {
                    time_obj.insert(
                        "modified".to_string(),
                        Value::String(Utc::now().to_rfc3339()),
                    );
                }

                record.updated_at = Self::now_ms();
                record.cached_from_uplink = false;
                message = API_MESSAGE_PKG_CHANGED.to_string();
            } else {
                let mut manifest = body.as_object().cloned().ok_or_else(|| {
                    RegistryError::http(
                        StatusCode::BAD_REQUEST,
                        API_ERROR_UNSUPPORTED_REGISTRY_CALL,
                    )
                })?;

                if let Some(attachments_obj) = manifest
                    .get_mut("_attachments")
                    .and_then(Value::as_object_mut)
                {
                    let keys: Vec<String> = attachments_obj.keys().cloned().collect();
                    for key in keys {
                        if let Some(value) = attachments_obj.get(&key).cloned() {
                            attachments_obj.insert(key, Self::remove_attachment_data(&value));
                        }
                    }
                }

                Self::ensure_manifest_defaults(&mut manifest, package_name, username);
                manifest.insert("_rev".to_string(), Value::String(Self::initial_revision()));

                state.packages.insert(
                    package_name.to_string(),
                    PackageRecord {
                        manifest: Value::Object(manifest),
                        upstream_tarballs: HashMap::new(),
                        updated_at: Self::now_ms(),
                        cached_from_uplink: false,
                    },
                );
                message = API_MESSAGE_PKG_CREATED.to_string();
            }

            (state.clone(), message)
        };

        self.persist_snapshot(&snapshot_and_message.0).await?;
        self.sync_package_sidecar_from_snapshot(&snapshot_and_message.0, package_name)
            .await?;
        debug!(
            message = snapshot_and_message.1.as_str(),
            "published package manifest"
        );
        Ok(snapshot_and_message.1)
    }

    #[instrument(skip(self), fields(package = package_name))]
    pub async fn remove_package(&self, package_name: &str) -> Result<String, RegistryError> {
        let snapshot = {
            let mut state = self.state.write().await;
            if state.packages.remove(package_name).is_none() {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_PACKAGE,
                ));
            }
            state.clone()
        };

        let _ = self.tarball_backend.delete_package(package_name).await;

        self.persist_snapshot(&snapshot).await?;
        debug!("removed package");
        Ok(API_MESSAGE_PKG_REMOVED.to_string())
    }

    #[instrument(skip(self), fields(package = package_name, filename))]
    pub async fn remove_tarball(
        &self,
        package_name: &str,
        filename: &str,
    ) -> Result<String, RegistryError> {
        {
            let state = self.state.read().await;
            if !state.packages.contains_key(package_name) {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_PACKAGE,
                ));
            }
        }

        let removed_file = self.tarball_backend.delete(package_name, filename).await?;
        let snapshot = {
            let mut state = self.state.write().await;
            let record = Self::package_record(&mut state, package_name)?;
            let Some(manifest) = record.manifest.as_object_mut() else {
                return Err(RegistryError::Internal);
            };

            let mut removed_versions = HashSet::new();
            if let Some(versions) = manifest.get_mut("versions").and_then(Value::as_object_mut) {
                let mut to_delete = Vec::new();
                for (version, data) in versions.iter() {
                    let tarball = data
                        .get("dist")
                        .and_then(|dist| dist.get("tarball"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let found = tarball.rsplit('/').next().unwrap_or_default();
                    if found == filename {
                        to_delete.push(version.clone());
                    }
                }
                for version in to_delete {
                    versions.remove(&version);
                    removed_versions.insert(version);
                }
            }

            if let Some(tags) = manifest.get_mut("dist-tags").and_then(Value::as_object_mut) {
                let to_remove: Vec<String> = tags
                    .iter()
                    .filter_map(|(tag, version)| {
                        let version = version.as_str().unwrap_or_default();
                        if removed_versions.contains(version) {
                            Some(tag.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                for tag in to_remove {
                    tags.remove(&tag);
                }
            }

            if let Some(attachments) = manifest
                .get_mut("_attachments")
                .and_then(Value::as_object_mut)
            {
                attachments.remove(filename);
            }

            let removed_upstream = record.upstream_tarballs.remove(filename).is_some();

            if !removed_file && !removed_upstream && removed_versions.is_empty() {
                return Err(RegistryError::http(
                    StatusCode::NOT_FOUND,
                    API_ERROR_NO_SUCH_FILE,
                ));
            }

            Self::bump_revision(manifest);
            record.updated_at = Self::now_ms();
            state.clone()
        };

        self.persist_snapshot(&snapshot).await?;
        self.sync_package_sidecar_from_snapshot(&snapshot, package_name)
            .await?;
        debug!("removed tarball");
        Ok(API_MESSAGE_TARBALL_REMOVED.to_string())
    }

    pub async fn merge_dist_tag(
        &self,
        package_name: &str,
        tag: &str,
        version: Option<&str>,
    ) -> Result<String, RegistryError> {
        let snapshot = {
            let mut state = self.state.write().await;
            let record = Self::package_record(&mut state, package_name)?;
            let Some(manifest) = record.manifest.as_object_mut() else {
                return Err(RegistryError::Internal);
            };
            let tags = manifest
                .entry("dist-tags".to_string())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or(RegistryError::Internal)?;

            let response = if let Some(version) = version {
                tags.insert(tag.to_string(), Value::String(version.to_string()));
                API_MESSAGE_TAG_ADDED
            } else {
                tags.remove(tag);
                API_MESSAGE_TAG_REMOVED
            };

            Self::bump_revision(manifest);
            record.updated_at = Self::now_ms();
            record.cached_from_uplink = false;

            (state.clone(), response.to_string())
        };

        self.persist_snapshot(&snapshot.0).await?;
        self.sync_package_sidecar_from_snapshot(&snapshot.0, package_name)
            .await?;
        Ok(snapshot.1)
    }

    pub async fn dist_tags(&self, package_name: &str) -> Result<Value, RegistryError> {
        let state = self.state.read().await;
        let Some(record) = state.packages.get(package_name) else {
            return Err(RegistryError::http(
                StatusCode::NOT_FOUND,
                API_ERROR_NO_PACKAGE,
            ));
        };
        let tags = record
            .manifest
            .get("dist-tags")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        Ok(tags)
    }

    pub async fn get_package_record(&self, package_name: &str) -> Option<PackageRecord> {
        let state = self.state.read().await;
        state.packages.get(package_name).cloned()
    }

    #[instrument(skip(self, manifest, upstream_tarballs), fields(package = package_name, upstream_tarball_count = upstream_tarballs.len()))]
    pub async fn upsert_upstream_package(
        &self,
        package_name: &str,
        manifest: Value,
        upstream_tarballs: HashMap<String, String>,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.write().await;
        state.packages.insert(
            package_name.to_string(),
            PackageRecord {
                manifest,
                upstream_tarballs,
                updated_at: Self::now_ms(),
                cached_from_uplink: true,
            },
        );

        debug!("upserted upstream package cache");
        Ok(())
    }

    pub async fn upstream_tarball_url(&self, package_name: &str, filename: &str) -> Option<String> {
        let state = self.state.read().await;
        state
            .packages
            .get(package_name)
            .and_then(|record| record.upstream_tarballs.get(filename).cloned())
    }

    pub async fn set_upstream_tarball_url(
        &self,
        package_name: &str,
        filename: &str,
        url: String,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.write().await;
        if let Some(record) = state.packages.get_mut(package_name) {
            record.upstream_tarballs.insert(filename.to_string(), url);
        }
        Ok(())
    }

    #[instrument(skip(self, content), fields(package = package_name, filename, bytes = content.len()))]
    pub async fn cache_tarball(
        &self,
        package_name: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        self.write_tarball_file(package_name, filename, content)
            .await
    }

    pub async fn all_packages(&self) -> Vec<PackageRecord> {
        let state = self.state.read().await;
        state
            .packages
            .values()
            .filter(|record| !record.cached_from_uplink)
            .cloned()
            .collect()
    }

    pub async fn reindex_from_backend(&self) -> Result<Value, RegistryError> {
        let (snapshot, changed, before_packages, after_packages) = {
            let mut state = self.state.write().await;
            let before_packages = state.packages.len();
            let changed =
                Self::hydrate_from_tarball_backend(&mut state, &self.tarball_backend).await?;
            let after_packages = state.packages.len();
            (state.clone(), changed, before_packages, after_packages)
        };
        if changed {
            self.persist_snapshot(&snapshot).await?;
        }
        let sidecars_synced = if changed {
            self.sync_all_package_sidecars_from_snapshot(&snapshot)
                .await?
        } else {
            0
        };

        Ok(json!({
            "ok": true,
            "changed": changed,
            "packagesBefore": before_packages,
            "packagesAfter": after_packages,
            "sidecarsSynced": sidecars_synced,
        }))
    }

    pub async fn storage_health(&self) -> Result<Value, RegistryError> {
        let references = self.tarball_backend.list().await?;
        let backend_packages = self.tarball_backend.list_packages().await?;
        let legacy_index_package_count = self
            .tarball_backend
            .load_legacy_package_index()
            .await?
            .map(|packages| packages.len())
            .unwrap_or(0);

        let mut backend_tarballs: HashMap<String, HashSet<String>> = HashMap::new();
        for reference in references {
            if Self::infer_version_from_filename(&reference.filename).is_none() {
                continue;
            }
            backend_tarballs
                .entry(reference.package)
                .or_default()
                .insert(reference.filename);
        }

        let backend_package_set = backend_packages.into_iter().collect::<HashSet<_>>();
        let mut sidecar_packages = HashSet::new();
        for package in &backend_package_set {
            if self
                .tarball_backend
                .read_package_metadata(package)
                .await?
                .is_some()
            {
                sidecar_packages.insert(package.clone());
            }
        }

        let (state_package_set, state_attachments) = {
            let state = self.state.read().await;
            let mut packages = HashSet::new();
            let mut attachments: HashMap<String, HashSet<String>> = HashMap::new();
            for (package, record) in &state.packages {
                if record.cached_from_uplink {
                    continue;
                }
                packages.insert(package.clone());
                let filenames = record
                    .manifest
                    .get("_attachments")
                    .and_then(Value::as_object)
                    .map(|object| {
                        object
                            .keys()
                            .filter(|filename| {
                                Self::infer_version_from_filename(filename).is_some()
                            })
                            .cloned()
                            .collect::<HashSet<_>>()
                    })
                    .unwrap_or_default();
                attachments.insert(package.clone(), filenames);
            }
            (packages, attachments)
        };

        let mut tarballs_without_sidecar = backend_tarballs
            .keys()
            .filter(|package| !sidecar_packages.contains(*package))
            .cloned()
            .collect::<Vec<_>>();
        tarballs_without_sidecar.sort();

        let mut sidecars_without_tarballs = sidecar_packages
            .iter()
            .filter(|package| backend_tarballs.get(*package).is_none_or(HashSet::is_empty))
            .cloned()
            .collect::<Vec<_>>();
        sidecars_without_tarballs.sort();

        let mut tarballs_missing_from_manifest = Vec::new();
        for (package, files) in &backend_tarballs {
            let Some(manifest_files) = state_attachments.get(package) else {
                for file in files {
                    tarballs_missing_from_manifest.push(format!("{package}/-/{}", file));
                }
                continue;
            };
            for file in files {
                if !manifest_files.contains(file) {
                    tarballs_missing_from_manifest.push(format!("{package}/-/{}", file));
                }
            }
        }
        tarballs_missing_from_manifest.sort();

        let mut manifest_attachments_missing_blob = Vec::new();
        for (package, files) in &state_attachments {
            let Some(backend_files) = backend_tarballs.get(package) else {
                for file in files {
                    manifest_attachments_missing_blob.push(format!("{package}/-/{}", file));
                }
                continue;
            };
            for file in files {
                if !backend_files.contains(file) {
                    manifest_attachments_missing_blob.push(format!("{package}/-/{}", file));
                }
            }
        }
        manifest_attachments_missing_blob.sort();

        let mut stale_state_packages = state_package_set
            .iter()
            .filter(|package| !backend_package_set.contains(*package))
            .cloned()
            .collect::<Vec<_>>();
        stale_state_packages.sort();

        Ok(json!({
            "ok": true,
            "summary": {
                "backendPackages": backend_package_set.len(),
                "backendTarballs": backend_tarballs.values().map(HashSet::len).sum::<usize>(),
                "sidecarPackages": sidecar_packages.len(),
                "statePackages": state_package_set.len(),
                "legacyVerdaccioIndexPackages": legacy_index_package_count,
            },
            "problems": {
                "tarballsWithoutSidecar": tarballs_without_sidecar,
                "sidecarsWithoutTarballs": sidecars_without_tarballs,
                "tarballsMissingFromManifest": tarballs_missing_from_manifest,
                "manifestAttachmentsMissingBlob": manifest_attachments_missing_blob,
                "staleStatePackages": stale_state_packages,
            }
        }))
    }

    pub async fn starred_packages(&self, user_key: &str) -> Vec<String> {
        let state = self.state.read().await;
        let mut rows = Vec::new();
        for record in state.packages.values() {
            let Some(name) = record
                .manifest
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            if let Some(users) = record.manifest.get("users").and_then(Value::as_object)
                && users.get(user_key).and_then(Value::as_bool) == Some(true)
            {
                rows.push(name);
            }
        }
        rows.sort();
        rows
    }

    pub fn normalize_package_response(
        &self,
        manifest: &Value,
        package_name: &str,
        base_url: &str,
    ) -> (Value, HashMap<String, String>) {
        let mut clone = manifest.clone();
        let mut upstream_tarballs = HashMap::new();

        if let Some(versions) = clone.get_mut("versions").and_then(Value::as_object_mut) {
            for (_version, payload) in versions.iter_mut() {
                if let Some(dist) = payload.get_mut("dist").and_then(Value::as_object_mut)
                    && let Some(raw) = dist.get("tarball").and_then(Value::as_str)
                {
                    let filename = raw.rsplit('/').next().unwrap_or_default().to_string();
                    if !filename.is_empty() {
                        upstream_tarballs.insert(filename.clone(), raw.to_string());
                        dist.insert(
                            "tarball".to_string(),
                            Value::String(format!(
                                "{}/{}/-/{}",
                                base_url.trim_end_matches('/'),
                                urlencoding::encode(package_name),
                                filename
                            )),
                        );
                    }
                }
            }
        }

        (clone, upstream_tarballs)
    }

    pub fn abbreviated_manifest(&self, manifest: &Value) -> Value {
        let mut out = manifest.clone();
        if let Some(obj) = out.as_object_mut() {
            obj.remove("users");
            obj.remove("_attachments");
            obj.remove("_uplinks");
            obj.remove("_distfiles");
            obj.remove("readme");
            if let Some(versions) = obj.get_mut("versions").and_then(Value::as_object_mut) {
                for version in versions.values_mut() {
                    if let Some(version_obj) = version.as_object_mut() {
                        version_obj.retain(|key, _| {
                            matches!(
                                key.as_str(),
                                "name"
                                    | "version"
                                    | "deprecated"
                                    | "bin"
                                    | "dist"
                                    | "engines"
                                    | "funding"
                                    | "directories"
                                    | "dependencies"
                                    | "devDependencies"
                                    | "peerDependencies"
                                    | "optionalDependencies"
                                    | "bundleDependencies"
                                    | "cpu"
                                    | "os"
                                    | "peerDependenciesMeta"
                                    | "acceptDependencies"
                                    | "_hasShrinkwrap"
                                    | "hasInstallScript"
                            )
                        });
                    }
                }
            }
            if !obj.contains_key("time") {
                obj.insert("time".to_string(), Value::Object(Map::new()));
            }
            obj.insert(
                "modified".to_string(),
                Value::String(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            );
        }
        out
    }

    pub fn normalize_token_response(token: &NpmTokenRecord, raw_token: Option<String>) -> Value {
        json!({
            "token": raw_token.unwrap_or_else(|| token.token.clone()),
            "key": token.key,
            "cidr": token.cidr,
            "cidr_whitelist": token.cidr,
            "readonly": token.readonly,
            "created": chrono::DateTime::from_timestamp_millis(token.created)
                .unwrap_or_else(Utc::now)
                .to_rfc3339(),
            "user": token.user,
        })
    }

    pub fn format_logged_user(name: &str) -> String {
        format!("you are authenticated as '{name}'")
    }

    pub fn validate_user_name(route_param: &str, body_name: &str) -> bool {
        route_param
            .split_once(':')
            .map(|(_, n)| n == body_name)
            .unwrap_or(false)
    }

    pub fn validate_password_length(&self, password: Option<&str>) -> Result<(), RegistryError> {
        let Some(password) = password else {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_PASSWORD_SHORT,
            ));
        };
        if password.len() < self.password_min_length {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_PASSWORD_SHORT,
            ));
        }
        Ok(())
    }

    pub fn token_list_response(&self, tokens: Vec<NpmTokenRecord>) -> Value {
        let objects: Vec<Value> = tokens
            .iter()
            .map(|token| Self::normalize_token_response(token, None))
            .collect();
        json!({
            "objects": objects,
            "urls": {
                "next": ""
            }
        })
    }

    pub fn parse_star_key(raw: &str) -> String {
        raw.trim_matches('"').trim_matches('\'').to_string()
    }

    pub fn package_version_by_query(manifest: &Value, query: &str) -> Option<Value> {
        let versions = manifest.get("versions")?.as_object()?;
        if let Some(version) = versions.get(query) {
            return Some(version.clone());
        }

        let tags = manifest.get("dist-tags").and_then(Value::as_object)?;
        let target = tags.get(query).and_then(Value::as_str)?;
        versions.get(target).cloned()
    }

    pub fn search_response_time() -> String {
        Self::now_http()
    }

    pub fn normalize_support_errors(
        readonly: Option<bool>,
        cidr_whitelist: Option<Vec<String>>,
    ) -> Result<(bool, Vec<String>), RegistryError> {
        let Some(readonly) = readonly else {
            return Err(RegistryError::http(
                StatusCode::UNPROCESSABLE_ENTITY,
                API_ERROR_PARAMETERS_NOT_VALID,
            ));
        };
        let Some(cidr_whitelist) = cidr_whitelist else {
            return Err(RegistryError::http(
                StatusCode::UNPROCESSABLE_ENTITY,
                API_ERROR_PARAMETERS_NOT_VALID,
            ));
        };
        Ok((readonly, cidr_whitelist))
    }

    pub fn ensure_session_id(session_id: Option<&str>) -> Result<&str, RegistryError> {
        let Some(session_id) = session_id else {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_SESSION_ID_REQUIRED,
            ));
        };
        if session_id.len() != 36 {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_SESSION_ID_INVALID,
            ));
        }
        Ok(session_id)
    }

    pub fn ensure_profile_body_valid(
        password_old: Option<&str>,
        password_new: Option<&str>,
        tfa_present: bool,
        min_len: usize,
    ) -> Result<(), RegistryError> {
        if tfa_present {
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                API_ERROR_TFA_DISABLED,
            ));
        }

        if let Some(new) = password_new {
            if new.len() < min_len {
                return Err(RegistryError::http(
                    StatusCode::UNAUTHORIZED,
                    API_ERROR_PASSWORD_SHORT,
                ));
            }
            if password_old.unwrap_or_default().is_empty() {
                return Err(RegistryError::http(
                    StatusCode::BAD_REQUEST,
                    "old password is required",
                ));
            }
            return Ok(());
        }

        Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            API_ERROR_PROFILE_ERROR,
        ))
    }

    pub fn login_required_message() -> &'static str {
        API_ERROR_MUST_BE_LOGGED
    }

    pub fn unauthorized_access_message() -> &'static str {
        API_ERROR_UNAUTHORIZED_ACCESS
    }

    pub fn bad_username_password_message() -> &'static str {
        API_ERROR_BAD_USERNAME_PASSWORD
    }

    pub fn username_mismatch_message() -> &'static str {
        API_ERROR_USERNAME_MISMATCH
    }

    pub fn logged_out_message() -> &'static str {
        API_MESSAGE_LOGGED_OUT
    }

    pub fn session_expired_message() -> &'static str {
        API_ERROR_SESSION_TOKEN_EXPIRED
    }

    pub fn package_removed_message() -> &'static str {
        API_MESSAGE_PKG_REMOVED
    }

    pub fn tag_added_message() -> &'static str {
        API_MESSAGE_TAG_ADDED
    }

    pub fn tag_removed_message() -> &'static str {
        API_MESSAGE_TAG_REMOVED
    }

    pub fn tarball_removed_message() -> &'static str {
        API_MESSAGE_TARBALL_REMOVED
    }

    pub fn no_package_message() -> &'static str {
        API_ERROR_NO_PACKAGE
    }

    pub fn no_such_file_message() -> &'static str {
        API_ERROR_NO_SUCH_FILE
    }

    pub fn unsupported_registry_call_message() -> &'static str {
        API_ERROR_UNSUPPORTED_REGISTRY_CALL
    }
}

fn hash_password(password: &str) -> Result<String, RegistryError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| RegistryError::Internal)
}

fn verify_password(hash: &str, password: &str) -> Result<(), RegistryError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| RegistryError::Internal)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| RegistryError::http(StatusCode::UNAUTHORIZED, API_ERROR_BAD_USERNAME_PASSWORD))
}

pub fn default_profile(name: &str) -> Value {
    json!({
        "tfa": false,
        "name": name,
        "email": "",
        "email_verified": false,
        "created": "",
        "updated": "",
        "cidr_whitelist": null,
        "fullname": "",
    })
}

pub fn make_search_object(package: &Value) -> Option<Value> {
    let name = package.get("name")?.as_str()?.to_string();
    let dist_tags = package.get("dist-tags")?.as_object()?;
    let latest = dist_tags.get("latest")?.as_str()?.to_string();
    let version = package.get("versions")?.get(&latest)?;

    let author = version.get("author").cloned().unwrap_or_else(|| json!({}));
    let description = version
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let keywords = version
        .get("keywords")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let maintainers = package
        .get("maintainers")
        .cloned()
        .unwrap_or_else(|| json!([]));

    let scope = name
        .strip_prefix('@')
        .and_then(|rest| rest.split('/').next())
        .map(|part| format!("@{part}"))
        .unwrap_or_default();

    Some(json!({
        "package": {
            "name": name,
            "version": latest,
            "description": description,
            "keywords": keywords,
            "date": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "links": { "npm": "" },
            "author": author,
            "publisher": {},
            "maintainers": maintainers,
            "scope": scope,
        },
        "score": {
            "final": 1,
            "detail": {
                "quality": 1,
                "popularity": 1,
                "maintenance": 0,
            }
        },
        "searchScore": 1,
        "verdaccioPkgCached": false,
        "verdaccioPrivate": true,
    }))
}

pub fn has_write_auth(user: Option<&str>) -> Result<&str, RegistryError> {
    user.ok_or_else(|| RegistryError::http(StatusCode::UNAUTHORIZED, API_ERROR_MUST_BE_LOGGED))
}

pub fn no_credentials() -> RegistryError {
    RegistryError::http(StatusCode::UNAUTHORIZED, "no credentials provided")
}

pub fn unauthorized(msg: &str) -> RegistryError {
    RegistryError::http(StatusCode::UNAUTHORIZED, msg)
}

pub fn forbidden(msg: &str) -> RegistryError {
    RegistryError::http(StatusCode::FORBIDDEN, msg)
}

pub fn bad_request(msg: &str) -> RegistryError {
    RegistryError::http(StatusCode::BAD_REQUEST, msg)
}

pub fn unprocessable(msg: &str) -> RegistryError {
    RegistryError::http(StatusCode::UNPROCESSABLE_ENTITY, msg)
}

pub fn is_json_request(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

pub fn parse_json_body(bytes: &[u8]) -> Result<Value, RegistryError> {
    serde_json::from_slice(bytes).map_err(|_| {
        RegistryError::http(StatusCode::BAD_REQUEST, API_ERROR_UNSUPPORTED_REGISTRY_CALL)
    })
}

pub fn parse_json_string_body(bytes: &[u8]) -> Result<String, RegistryError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| RegistryError::http(StatusCode::BAD_REQUEST, "version is missing"))?;
    let Some(text) = value.as_str() else {
        return Err(RegistryError::http(
            StatusCode::BAD_REQUEST,
            "version is missing",
        ));
    };
    Ok(text.to_string())
}

pub fn package_filename_from_tarball_url(url: &str) -> Option<String> {
    url.rsplit('/').next().map(|s| s.to_string())
}

pub fn package_name_from_path_or_encoded(path_part: &str) -> String {
    match urlencoding::decode(path_part) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => path_part.to_string(),
    }
}

pub fn package_name_to_encoded(package: &str) -> String {
    urlencoding::encode(package).into_owned()
}

pub fn version_not_found(query: &str) -> RegistryError {
    RegistryError::http(
        StatusCode::NOT_FOUND,
        format!("{API_ERROR_VERSION_NOT_EXIST}: {query}"),
    )
}

pub fn path_exists(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

pub fn parse_write_query(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(k, v)| k == "write" && v == "true")
}

pub fn route_user_param(path: &str) -> Option<&str> {
    path.strip_prefix("/-/user/")
}

pub fn normalize_scope_path(parts: &[&str]) -> String {
    parts.join("/")
}

pub fn parse_authorization(header: Option<&str>) -> Option<String> {
    let value = header?.trim();
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.trim().to_string());
    }
    if let Some(token) = value.strip_prefix("bearer ") {
        return Some(token.trim().to_string());
    }
    None
}

pub fn unauthorized_on_invalid_token(header_present: bool) -> Result<(), RegistryError> {
    if header_present {
        return Err(RegistryError::http(
            StatusCode::UNAUTHORIZED,
            API_ERROR_UNAUTHORIZED_ACCESS,
        ));
    }
    Ok(())
}

pub fn ok_object() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::config::Config;
    use std::{io::Write, path::Path};

    fn config_for_data_dir(data_dir: &Path) -> Config {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(file, "storage: {}", data_dir.display()).expect("write yaml config");
        Config::from_yaml_file(file.path().to_path_buf()).expect("parse config")
    }

    #[tokio::test]
    async fn hydrates_unindexed_local_tarballs_on_startup() {
        let temp = tempfile::tempdir().expect("temp dir");
        let data_dir = temp.path().join("registry");
        let package_dir = data_dir.join("tarballs").join("demo");
        tokio::fs::create_dir_all(&package_dir)
            .await
            .expect("create tarball dir");
        tokio::fs::write(package_dir.join("demo-1.0.0.tgz"), b"one")
            .await
            .expect("write tarball");
        tokio::fs::write(package_dir.join("demo-1.2.0.tgz"), b"two")
            .await
            .expect("write tarball");

        let config = config_for_data_dir(&data_dir);
        let store = Store::open(&config).await.expect("open store");
        let package = store
            .get_package_record("demo")
            .await
            .expect("package discovered");
        let versions = package
            .manifest
            .get("versions")
            .and_then(serde_json::Value::as_object)
            .expect("versions object");
        assert!(versions.contains_key("1.0.0"));
        assert!(versions.contains_key("1.2.0"));
        assert_eq!(
            package
                .manifest
                .get("dist-tags")
                .and_then(|tags| tags.get("latest"))
                .and_then(serde_json::Value::as_str),
            Some("1.2.0")
        );

        let state_file = data_dir.join("state.json");
        assert!(
            tokio::fs::try_exists(&state_file)
                .await
                .expect("state file existence"),
            "startup hydration should persist state"
        );
    }

    #[tokio::test]
    async fn hydrates_scoped_package_tarballs_on_startup() {
        let temp = tempfile::tempdir().expect("temp dir");
        let data_dir = temp.path().join("registry");
        let package_dir = data_dir.join("tarballs").join("@scope__pkg");
        tokio::fs::create_dir_all(&package_dir)
            .await
            .expect("create scoped tarball dir");
        tokio::fs::write(package_dir.join("pkg-2.3.4.tgz"), b"pkg")
            .await
            .expect("write scoped tarball");

        let config = config_for_data_dir(&data_dir);
        let store = Store::open(&config).await.expect("open store");
        let package = store
            .get_package_record("@scope/pkg")
            .await
            .expect("scoped package discovered");
        assert!(
            package
                .manifest
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|versions| versions.contains_key("2.3.4"))
        );
    }
}
