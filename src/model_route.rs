//! Детерминированный резолвер маршрутов провайдеров и моделей без утечки ключей.
//!
//! Используется командами оператора (`/advisor`, `rcode advisor`, `--advisor`)
//! и локальным разбором параметра `route` в `spawn_agent`. Сетевые запросы к
//! `/models` никогда не выполняются из `resolve_local_only`.
use crate::{
    config::{ConfigStore, CredentialState, Effort, ProviderKind, ProviderSettings, Settings},
    local::{endpoint_identity, validate_profile_name},
    local_app,
    protocol::ModelInfo,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MAX_PUBLISHED_ROUTES: usize = 8;
pub const MAX_PUBLISHED_ROUTES_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoutePurpose {
    /// Advisor calls run with `tools = []`, so pure reasoning models without
    /// function calling are valid candidates.
    Advisor,
    /// Subagents execute tools through the host broker, so models explicitly
    /// declaring `supports_tools = false` are excluded from catalog matching.
    Subagent,
}

/// Полная идентичность маршрута для однократного за сессию согласия оператора
/// и защиты от подмены endpoint/TLS/профиля после подтверждения.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteIdentity {
    pub kind: ProviderKind,
    pub local_profile: Option<String>,
    pub endpoint_id: Option<String>,
    pub auth_url: Option<String>,
    pub scope: Option<String>,
    pub folder_id: Option<String>,
    pub ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_sha256: Option<String>,
    pub model: String,
}

fn strip_cur_dir_only(path: &std::path::Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        if component != std::path::Component::CurDir {
            out.push(component.as_os_str());
        }
    }
    out
}

pub fn normalize_ca_path(path: &std::path::Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let raw_str = path.as_os_str().to_string_lossy();
    let has_trailing_sep = raw_str.ends_with('/') || raw_str.ends_with('\\');
    if !has_trailing_sep
        && matches!(
            abs.components().next_back(),
            Some(std::path::Component::Normal(_))
        )
        && let (Some(raw_parent), Some(file_name)) = (abs.parent(), abs.file_name())
    {
        if let Ok(canon_parent) = std::fs::canonicalize(raw_parent) {
            return canon_parent.join(file_name);
        }
        return strip_cur_dir_only(&abs);
    }
    std::fs::canonicalize(&abs).unwrap_or_else(|_| strip_cur_dir_only(&abs))
}

pub fn read_regular_ca_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    const MAX_CA_BYTES: u64 = 4 * 1024 * 1024;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_CA_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_CA_BYTES + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= MAX_CA_BYTES).then_some(bytes)
}

pub fn ca_file_sha256_hex(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    match read_regular_ca_bytes(path) {
        Some(bytes) => format!("{:x}", Sha256::digest(&bytes)),
        None => "<unreadable>".into(),
    }
}

/// Проверяет, что `ca_file` является абсолютным путём к обычному файлу до 4 МиБ
/// и содержит хотя бы один корректный PEM/DER X.509 сертификат, принимаемый TLS-бэкендом
/// `reqwest` (совпадая с проверкой `ProviderClient::new`).
pub fn is_usable_ca_file(path: &std::path::Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Some(pem) = read_regular_ca_bytes(path) else {
        return false;
    };
    if pem.is_empty() {
        return false;
    }
    let Ok(certs) = reqwest::Certificate::from_pem_bundle(&pem) else {
        return false;
    };
    if certs.is_empty() {
        return false;
    }
    let mut builder = reqwest::Client::builder().tls_built_in_root_certs(false);
    for cert in certs {
        builder = builder.add_root_certificate(cert);
    }
    builder.build().is_ok()
}

impl RouteIdentity {
    pub fn with_ca_sha256(provider: &ProviderSettings, ca_sha256: Option<String>) -> Self {
        let ca_file = provider.ca_file.as_deref().map(normalize_ca_path);
        let ca_sha256 = ca_file.as_ref().and(ca_sha256);
        if provider.kind == ProviderKind::Local {
            Self {
                kind: ProviderKind::Local,
                local_profile: provider.local.as_ref().map(|local| local.profile.clone()),
                endpoint_id: provider.base_url.as_deref().and_then(endpoint_identity),
                auth_url: None,
                scope: None,
                folder_id: None,
                ca_file,
                ca_sha256,
                model: provider.model.clone(),
            }
        } else {
            Self {
                kind: provider.kind,
                local_profile: None,
                endpoint_id: provider.base_url.clone(),
                auth_url: provider.auth_url.clone(),
                scope: provider.scope.clone(),
                folder_id: provider.folder_id.clone(),
                ca_file,
                ca_sha256,
                model: provider.model.clone(),
            }
        }
    }

    pub fn of(provider: &ProviderSettings) -> Self {
        Self::with_ca_sha256(
            provider,
            provider.ca_file.as_deref().map(ca_file_sha256_hex),
        )
    }

    pub fn same_as_identity(
        a: &ProviderSettings,
        a_ca_sha256: Option<&str>,
        b: &ProviderSettings,
        b_id: &Self,
    ) -> bool {
        if a.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
            || b.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
            || a_ca_sha256 == Some("<unreadable>")
            || b_id.ca_sha256.as_deref() == Some("<unreadable>")
        {
            return false;
        }
        &Self::with_ca_sha256(a, a_ca_sha256.map(str::to_owned)) == b_id
    }

    pub fn same_as_with_primary_ca(
        a: &ProviderSettings,
        a_ca_sha256: Option<&str>,
        b: &ProviderSettings,
    ) -> bool {
        Self::same_as_identity(a, a_ca_sha256, b, &Self::of(b))
    }

    pub fn same_as(a: &ProviderSettings, b: &ProviderSettings) -> bool {
        if a.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
            || b.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return false;
        }
        let left = Self::of(a);
        let right = Self::of(b);
        left.ca_sha256.as_deref() != Some("<unreadable>")
            && right.ca_sha256.as_deref() != Some("<unreadable>")
            && left == right
    }

    /// Проверяет, совпадает ли соединение маршрута (провайдер, профиль, endpoint,
    /// TLS, folder_id/scope), игнорируя только `model` и `effort`, используя уже
    /// вычисленный `b_id` без повторного чтения `ca_file` с диска.
    pub fn same_connection_identity(
        a: &ProviderSettings,
        a_ca_sha256: Option<&str>,
        b: &ProviderSettings,
        b_id: &Self,
    ) -> bool {
        if a.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
            || b.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
            || a_ca_sha256 == Some("<unreadable>")
            || b_id.ca_sha256.as_deref() == Some("<unreadable>")
        {
            return false;
        }
        let mut left = Self::with_ca_sha256(a, a_ca_sha256.map(str::to_owned));
        let mut right = b_id.clone();
        left.model.clear();
        right.model.clear();
        left == right
    }

    /// Проверяет, совпадает ли соединение маршрута (провайдер, профиль, endpoint,
    /// TLS, folder_id/scope), игнорируя только `model` и `effort`, с фиксацией
    /// реально загруженного `ca_sha256` основного клиента.
    pub fn same_connection_with_primary_ca(
        a: &ProviderSettings,
        a_ca_sha256: Option<&str>,
        b: &ProviderSettings,
    ) -> bool {
        Self::same_connection_identity(a, a_ca_sha256, b, &Self::of(b))
    }

    /// Проверяет, совпадает ли соединение маршрута (провайдер, профиль, endpoint,
    /// TLS, folder_id/scope), игнорируя только `model` и `effort`.
    pub fn same_connection(a: &ProviderSettings, b: &ProviderSettings) -> bool {
        if a.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
            || b.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return false;
        }
        let mut left = Self::of(a);
        let mut right = Self::of(b);
        left.model.clear();
        right.model.clear();
        left == right
    }

    /// Проверяет, изменилась ли сохранённая запись на диске между двумя чтениями
    /// `config.json` (включая старые относительные `ca_file`, которые команда
    /// `connect --ca-file` должна уметь исправить, если файл на диске не менялся).
    pub fn disk_unchanged(before: &ProviderSettings, now: &ProviderSettings) -> bool {
        if before.kind != now.kind || before.ca_file != now.ca_file {
            return false;
        }
        if before.kind == ProviderKind::Local {
            before.local.as_ref().map(|l| &l.profile) == now.local.as_ref().map(|l| &l.profile)
                && before.base_url.as_deref().and_then(endpoint_identity)
                    == now.base_url.as_deref().and_then(endpoint_identity)
        } else {
            before.base_url == now.base_url
                && before.auth_url == now.auth_url
                && before.scope == now.scope
                && before.folder_id == now.folder_id
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredRouteSummary {
    pub route: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub model: String,
}

pub fn display_label(provider: &ProviderSettings) -> String {
    if provider.kind == ProviderKind::Local {
        format!(
            "local:{} / {}",
            local_app::profile_name(provider),
            provider.model
        )
    } else {
        format!("{} / {}", provider.kind, provider.model)
    }
}

/// Метка маршрута для панели согласия оператора: включает различимый адрес
/// назначения для `local`, `custom` и переопределённых `base_url` / `auth_url`.
pub fn consent_target_label(provider: &ProviderSettings) -> String {
    let base = display_label(provider);
    let show_endpoint = matches!(provider.kind, ProviderKind::Local | ProviderKind::Custom)
        || provider
            .base_url
            .as_deref()
            .is_some_and(|u| !u.trim().is_empty());
    let mut out = if show_endpoint
        && let Some(url) = provider
            .base_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
    {
        format!("{base} @ {url}")
    } else {
        base
    };
    if provider.kind == ProviderKind::GigaChat
        && let Some(auth) =
            provider.auth_url.as_deref().map(str::trim).filter(|u| {
                !u.is_empty() && *u != "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
            })
    {
        out.push_str(&format!(" (oauth: {auth})"));
    }
    out
}

pub fn is_loopback_or_v4_mapped_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

/// Является ли маршрут локальным (провайдер `local` либо loopback-адрес у `custom`/переопределённого `base_url`,
/// включая IPv4-mapped IPv6 `[::ffff:127.0.0.1]`).
pub fn is_loopback_route(provider: &ProviderSettings) -> bool {
    if provider.kind == ProviderKind::Local {
        return true;
    }
    let effective_url = provider.base_url.as_deref().unwrap_or(match provider.kind {
        ProviderKind::Yandex => "https://ai.api.cloud.yandex.net/v1",
        ProviderKind::GigaChat => "https://api.giga.chat/v1",
        ProviderKind::OpenRouter => "https://openrouter.ai/api/v1",
        ProviderKind::Custom | ProviderKind::Local => "",
    });
    reqwest::Url::parse(effective_url)
        .ok()
        .and_then(|url| url.host_str().map(is_loopback_or_v4_mapped_host))
        .unwrap_or(false)
}

fn loopback_or_v4_mapped_endpoint_identity(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    if !is_loopback_or_v4_mapped_host(host) {
        return None;
    }
    let norm_host = if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_owned()
    } else {
        match host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()?
        {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        }
    };
    Some(format!(
        "{}://{norm_host}:{}{}",
        url.scheme(),
        url.port_or_known_default()?,
        url.path().trim_end_matches('/')
    ))
}

fn loopback_origin_for_kind(kind: ProviderKind, value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    if !is_loopback_or_v4_mapped_host(host) {
        return None;
    }
    let norm_host = if host.eq_ignore_ascii_case("localhost") {
        if kind == ProviderKind::Local {
            "127.0.0.1".to_owned()
        } else {
            "localhost".to_owned()
        }
    } else {
        match host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()?
        {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        }
    };
    Some(format!(
        "{}://{norm_host}:{}",
        url.scheme(),
        url.port_or_known_default()?
    ))
}

fn loopback_exact_url_for_kind(kind: ProviderKind, value: &str) -> Option<String> {
    let origin = loopback_origin_for_kind(kind, value)?;
    let url = reqwest::Url::parse(value).ok()?;
    Some(format!("{origin}{}", url.path()))
}

/// Проверяет, указывают ли два маршрута на один и тот же локальный loopback-сервер
/// (`local`, loopback `custom` или провайдер с переопределённым loopback `base_url`
/// с однозначно совпадающим адресом, схемой, портом, путём и CA). Поскольку клиент
/// `local` закрепляет `localhost` за `127.0.0.1`, а остальные клиенты разрешают
/// `localhost` системным DNS (включая `::1`), не-`local` маршрут с хостом `localhost`
/// совпадает только с другим не-`local` маршрутом с хостом `localhost` (и никогда с `local`).
pub fn same_loopback_endpoint_with_identity(
    primary: &ProviderSettings,
    primary_ca_sha256: Option<&str>,
    target: &ProviderSettings,
    target_id: &RouteIdentity,
) -> bool {
    if !is_loopback_route(primary) || !is_loopback_route(target) {
        return false;
    }
    if primary.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute())
        || target.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute())
        || primary_ca_sha256 == Some("<unreadable>")
        || target_id.ca_sha256.as_deref() == Some("<unreadable>")
    {
        return false;
    }
    let effective_primary_ca = primary.ca_file.as_ref().and(primary_ca_sha256);
    if primary.ca_file.as_deref().map(normalize_ca_path).as_ref() != target_id.ca_file.as_ref()
        || effective_primary_ca != target_id.ca_sha256.as_deref()
    {
        return false;
    }
    let non_local_uses_localhost = |p: &ProviderSettings| {
        p.kind != ProviderKind::Local
            && p.base_url
                .as_deref()
                .and_then(|u| reqwest::Url::parse(u).ok())
                .and_then(|u| u.host_str().map(|h| h.eq_ignore_ascii_case("localhost")))
                .unwrap_or(true)
    };
    let a_sys_lh = non_local_uses_localhost(primary);
    let b_sys_lh = non_local_uses_localhost(target);
    if (a_sys_lh || b_sys_lh)
        && !(primary.kind != ProviderKind::Local
            && target.kind != ProviderKind::Local
            && a_sys_lh
            && b_sys_lh)
    {
        return false;
    }
    let id_a = primary
        .base_url
        .as_deref()
        .and_then(loopback_or_v4_mapped_endpoint_identity);
    let id_b = target
        .base_url
        .as_deref()
        .and_then(loopback_or_v4_mapped_endpoint_identity);
    if id_a.is_none() || id_a != id_b {
        return false;
    }
    if target.kind == ProviderKind::GigaChat {
        let Some(target_oauth_origin) = target
            .auth_url
            .as_deref()
            .and_then(|u| loopback_origin_for_kind(target.kind, u))
        else {
            return false;
        };
        let primary_chat_origin = primary
            .base_url
            .as_deref()
            .and_then(|u| loopback_origin_for_kind(primary.kind, u));
        let same_as_primary_chat = primary_chat_origin.as_ref() == Some(&target_oauth_origin);
        let same_as_primary_oauth = primary.kind == ProviderKind::GigaChat
            && primary
                .auth_url
                .as_deref()
                .and_then(|u| loopback_exact_url_for_kind(primary.kind, u))
                .zip(
                    target
                        .auth_url
                        .as_deref()
                        .and_then(|u| loopback_exact_url_for_kind(target.kind, u)),
                )
                .is_some_and(|(pa, ta)| pa == ta);
        if !same_as_primary_chat && !same_as_primary_oauth {
            return false;
        }
    }
    true
}

pub fn same_loopback_endpoint_with_primary_ca(
    primary: &ProviderSettings,
    primary_ca_sha256: Option<&str>,
    target: &ProviderSettings,
) -> bool {
    same_loopback_endpoint_with_identity(
        primary,
        primary_ca_sha256,
        target,
        &RouteIdentity::of(target),
    )
}

pub fn same_loopback_endpoint(primary: &ProviderSettings, target: &ProviderSettings) -> bool {
    let primary_ca = primary.ca_file.as_deref().map(ca_file_sha256_hex);
    same_loopback_endpoint_with_primary_ca(primary, primary_ca.as_deref(), target)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorConstraint<'a> {
    pub kind: ProviderKind,
    pub local_profile: Option<&'a str>,
    pub subquery: Option<&'a str>,
}

/// Если селектор явно указывает провайдера или префикс (`local:...`, `gigachat:...`,
/// `local`, либо `ПРОФИЛЬ:...`), возвращает ограничение провайдера (и локального профиля,
/// если он назван явно) и правую часть, чтобы интерактивный поиск никогда не переключался
/// молча на другие облачные шлюзы или посторонние профили `local`.
pub fn explicit_selector_constraint<'a>(
    settings: &Settings,
    selector: &'a str,
) -> Option<SelectorConstraint<'a>> {
    let trimmed = selector.trim();
    let lower = trimmed.to_lowercase();
    if lower.starts_with("local:")
        || lower.starts_with("локальная:")
        || lower.starts_with("локальный:")
    {
        let (_, rest) = trimmed.split_once(':')?;
        let non_empty = rest.trim();
        if non_empty.is_empty() {
            return Some(SelectorConstraint {
                kind: ProviderKind::Local,
                local_profile: None,
                subquery: None,
            });
        }
        if let Some((profile_part, model_part)) = non_empty.split_once(':') {
            let prof = profile_part.trim();
            let sub = model_part.trim();
            return Some(SelectorConstraint {
                kind: ProviderKind::Local,
                local_profile: (!prof.is_empty()).then_some(prof),
                subquery: (!sub.is_empty()).then_some(sub),
            });
        }
        if settings.local.profiles.contains_key(non_empty) {
            return Some(SelectorConstraint {
                kind: ProviderKind::Local,
                local_profile: Some(non_empty),
                subquery: None,
            });
        }
        return Some(SelectorConstraint {
            kind: ProviderKind::Local,
            local_profile: None,
            subquery: Some(non_empty),
        });
    }
    if let Some((kind, rest)) = split_explicit_provider_prefix(trimmed) {
        let non_empty = rest.trim();
        return Some(SelectorConstraint {
            kind,
            local_profile: None,
            subquery: (!non_empty.is_empty()).then_some(non_empty),
        });
    }
    if !lower.starts_with("gpt://")
        && !lower.starts_with("http://")
        && !lower.starts_with("https://")
        && let Some((left, right)) = trimmed.split_once(':')
    {
        if let Some(kind) = parse_provider_alias(left) {
            let non_empty = right.trim();
            return Some(SelectorConstraint {
                kind,
                local_profile: None,
                subquery: (!non_empty.is_empty()).then_some(non_empty),
            });
        }
        let left_trimmed = left.trim();
        if settings.local.profiles.contains_key(left_trimmed) {
            let non_empty = right.trim();
            return Some(SelectorConstraint {
                kind: ProviderKind::Local,
                local_profile: Some(left_trimmed),
                subquery: (!non_empty.is_empty()).then_some(non_empty),
            });
        }
    }
    if let Some(kind) = parse_provider_alias(trimmed) {
        return Some(SelectorConstraint {
            kind,
            local_profile: None,
            subquery: None,
        });
    }
    if settings.local.profiles.contains_key(trimmed) {
        return Some(SelectorConstraint {
            kind: ProviderKind::Local,
            local_profile: Some(trimmed),
            subquery: None,
        });
    }
    None
}

pub fn build_route_secret_dictionary_from_raw(
    disk_secrets: impl IntoIterator<Item = String>,
    extra_secrets: &[String],
) -> Result<Option<crate::redaction::SecretDictionary>> {
    let mut raw: Vec<String> = disk_secrets.into_iter().filter(|v| !v.is_empty()).collect();
    raw.extend(crate::config::env_redaction_secrets());
    raw.extend_from_slice(extra_secrets);
    let mut secrets = Vec::new();
    crate::redaction::merge_secret_variants(&mut secrets, &raw);
    if secrets.is_empty() {
        return Ok(None);
    }
    let dict = crate::redaction::SecretDictionary::new(&secrets)
        .context("Не удалось проверить маршрут на отсутствие секретов")?;
    Ok(Some(dict))
}

pub fn build_route_secret_dictionary(
    store: &ConfigStore,
    extra_secrets: &[String],
) -> Result<Option<crate::redaction::SecretDictionary>> {
    build_route_secret_dictionary_from_raw(store.redaction_secrets()?, extra_secrets)
}

pub fn check_route_against_secret_dictionary(
    dict: Option<&crate::redaction::SecretDictionary>,
    provider: &ProviderSettings,
) -> Result<()> {
    let Some(dict) = dict else {
        return Ok(());
    };
    let ca_str = provider.ca_file.as_ref().map(|p| p.to_string_lossy());
    let fields: [Option<&str>; 7] = [
        Some(provider.model.as_str()),
        provider.local.as_ref().map(|l| l.profile.as_str()),
        provider.base_url.as_deref(),
        provider.auth_url.as_deref(),
        provider.scope.as_deref(),
        provider.folder_id.as_deref(),
        ca_str.as_deref(),
    ];
    for field in fields.into_iter().flatten() {
        if field.is_empty() {
            continue;
        }
        let clean = crate::redaction::redact_text_with(dict, field)
            .context("Не удалось проверить параметры маршрута")?;
        if clean != field {
            bail!(
                "Параметры маршрута ({}) содержат секрет ключа доступа; исправьте конфигурацию модели или профиля",
                provider.kind
            );
        }
    }
    Ok(())
}

/// Безопасно редактирует строку пользовательской сводки против секретов диска и окружения.
/// При ошибке чтения `credentials.json` или построения словаря возвращает `"[скрыто]"` (fail-closed).
pub(crate) fn redact_route_display_field(
    store: &ConfigStore,
    extra_secrets: &[String],
    text: &str,
) -> String {
    if text.is_empty() {
        return String::new();
    }
    match build_route_secret_dictionary(store, extra_secrets) {
        Ok(None) => text.to_owned(),
        Ok(Some(dict)) => crate::redaction::redact_text_idempotent_with(&dict, text)
            .unwrap_or_else(|_| "[скрыто]".into()),
        Err(_) => "[скрыто]".into(),
    }
}

/// Проверяет fail-closed, что поля маршрута (`model`, `profile`, `base_url`,
/// `auth_url`, `scope`, `folder_id`) не содержат известных секретов с диска,
/// из окружения или из активной сессии.
pub fn ensure_route_free_of_secrets(
    store: &ConfigStore,
    provider: &ProviderSettings,
    extra_secrets: &[String],
) -> Result<()> {
    let dict = build_route_secret_dictionary(store, extra_secrets)?;
    check_route_against_secret_dictionary(dict.as_ref(), provider)
}

/// Проверяет поля подключения (`profile`, `base_url`, `auth_url`, `scope`,
/// `folder_id`) до первого сетевого запроса `/models` / OAuth, не проверяя ещё
/// не выбранный `model`.
pub fn ensure_connection_free_of_secrets(
    store: &ConfigStore,
    provider: &ProviderSettings,
    extra_secrets: &[String],
) -> Result<()> {
    let mut conn = provider.clone();
    conn.model.clear();
    ensure_route_free_of_secrets(store, &conn, extra_secrets)
}

pub fn short_route_id(provider: &ProviderSettings) -> String {
    if provider.kind == ProviderKind::Local {
        format!("local:{}", local_app::profile_name(provider))
    } else {
        provider.kind.as_str().to_owned()
    }
}

pub fn parse_provider_alias(token: &str) -> Option<ProviderKind> {
    let lower = token.trim().to_lowercase();
    match lower.as_str() {
        "gigachat" | "гигачат" | "гига" | "сбер" | "sber" | "giga" => {
            Some(ProviderKind::GigaChat)
        }
        "yandex" | "яндекс" | "yandexgpt" => Some(ProviderKind::Yandex),
        "openrouter" | "опенроутер" | "router" => Some(ProviderKind::OpenRouter),
        "custom" => Some(ProviderKind::Custom),
        "local" | "локальная" | "локальный" => Some(ProviderKind::Local),
        _ => None,
    }
}

pub(crate) fn is_legacy_synthetic_custom(settings: &Settings, entry: &ProviderSettings) -> bool {
    entry.kind == ProviderKind::Custom
        && !settings.custom_configured
        && settings.active != ProviderKind::Custom
        && *entry == ProviderSettings::new(ProviderKind::Custom)
}

/// Возвращает базовую облачную конфигурацию провайдера единым способом для
/// публикации (`usable_routes`), резолвера (`resolve_local_only`) и проверки
/// свежести (`verify_snapshot_current`): `custom` требует явной записи в
/// `settings.providers`, а официальные шлюзы используют сохранённые или дефолтные параметры.
pub(crate) fn configured_cloud_provider(
    settings: &Settings,
    kind: ProviderKind,
) -> Result<Option<ProviderSettings>> {
    if kind == ProviderKind::Local {
        return Ok(None);
    }
    if let Some(entry) = settings.providers.get(kind.as_str()) {
        if entry.kind != kind {
            bail!(
                "Поле kind ({}) в providers.{} не совпадает с именем провайдера; исправьте config.json",
                entry.kind,
                kind.as_str()
            );
        }
        if kind == ProviderKind::Custom && is_legacy_synthetic_custom(settings, entry) {
            return Ok(None);
        }
        return Ok(Some(entry.clone()));
    }
    match kind {
        ProviderKind::Local | ProviderKind::Custom => Ok(None),
        ProviderKind::Yandex | ProviderKind::GigaChat | ProviderKind::OpenRouter => {
            Ok(Some(ProviderSettings::new(kind)))
        }
    }
}

pub(crate) fn configured_local_profile(
    settings: &Settings,
    name: &str,
) -> Result<Option<ProviderSettings>> {
    validate_profile_name(name)?;
    let Some(entry) = settings.local.profiles.get(name) else {
        return Ok(None);
    };
    if entry.kind != ProviderKind::Local || entry.local.as_ref().is_none_or(|l| l.profile != name) {
        bail!(
            "Повреждённая запись local.profiles.{name}: профиль должен иметь kind = local и совпадающее имя; исправьте config.json"
        );
    }
    Ok(Some(entry.clone()))
}

/// Возвращает `true`, если `kind == Custom` опирается лишь на нетронутый плейсхолдер
/// `Settings::default()` (`http://localhost:11434/v1` / `"local"`) и общий `OPENAI_API_KEY`
/// без явного выбора или настройки `custom` пользователем.
pub fn is_unconfigured_default_custom(
    settings: &Settings,
    kind: ProviderKind,
    cred: &crate::config::Credential,
) -> bool {
    kind == ProviderKind::Custom
        && !settings.custom_configured
        && settings.active != ProviderKind::Custom
        && cred.source == "env:OPENAI_API_KEY"
        && settings
            .providers
            .get(ProviderKind::Custom.as_str())
            .is_none_or(|c| *c == ProviderSettings::new(ProviderKind::Custom))
}

/// Все готовые к работе маршруты (с настроенным ключом и валидной конфигурацией).
pub fn usable_routes(store: &ConfigStore, _settings: &Settings) -> Vec<ProviderSettings> {
    let Ok((disk_settings, providers_creds)) = store.read_consistent_routing_state() else {
        return Vec::new();
    };
    let Ok(route_dict) =
        build_route_secret_dictionary_from_raw(providers_creds.values().cloned(), &[])
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for kind in ProviderKind::all() {
        if kind == ProviderKind::Local {
            continue;
        }
        let Ok(Some(cred)) = ConfigStore::cloud_credential_from_map(kind, &providers_creds) else {
            continue;
        };
        let Ok(Some(candidate)) = configured_cloud_provider(&disk_settings, kind) else {
            continue;
        };
        if is_unconfigured_default_custom(&disk_settings, kind, &cred) {
            continue;
        }
        if candidate.validate().is_ok()
            && candidate
                .ca_file
                .as_ref()
                .is_none_or(|ca| is_usable_ca_file(ca))
            && check_route_against_secret_dictionary(route_dict.as_ref(), &candidate).is_ok()
        {
            out.push(candidate);
        }
    }
    let mut local_names: Vec<&String> = disk_settings.local.profiles.keys().collect();
    if let Some(active) = disk_settings.local.active.as_deref()
        && let Some(pos) = local_names.iter().position(|name| name.as_str() == active)
    {
        local_names[..=pos].rotate_right(1);
    }
    for name in local_names {
        let Ok(Some(profile)) = configured_local_profile(&disk_settings, name) else {
            continue;
        };
        if profile.validate().is_err()
            || profile
                .ca_file
                .as_ref()
                .is_some_and(|ca| !is_usable_ca_file(ca))
            || check_route_against_secret_dictionary(route_dict.as_ref(), &profile).is_err()
        {
            continue;
        }
        if matches!(
            ConfigStore::local_credential_state_from_snapshot(
                &disk_settings,
                &providers_creds,
                &profile,
            ),
            Ok(CredentialState::Present(_) | CredentialState::NotRequired)
        ) {
            out.push(profile);
        }
    }
    out
}

pub fn route_summary_contains_secret(
    item: &ConfiguredRouteSummary,
    dict: &crate::redaction::SecretDictionary,
) -> bool {
    let tainted = |s: &str| {
        crate::redaction::redact_text_with(dict, s)
            .map(|clean| clean != s)
            .unwrap_or(true)
    };
    tainted(&item.route)
        || tainted(&item.provider)
        || item.profile.as_deref().is_some_and(tainted)
        || tainted(&item.model)
}

/// Компактный список альтернативных маршрутов для `<rcode_runtime_context>`
/// (ограничен и числом записей, и общим байтовым бюджетом; без секретов и URL).
pub fn published_routes(
    store: &ConfigStore,
    settings: &Settings,
    current: &ProviderSettings,
) -> Vec<ConfiguredRouteSummary> {
    let Ok(mut raw_secrets) = store.redaction_secrets() else {
        return Vec::new();
    };
    raw_secrets.extend(crate::config::env_redaction_secrets());
    let mut secrets = Vec::new();
    crate::redaction::merge_secret_variants(&mut secrets, &raw_secrets);
    let dict =
        match (!secrets.is_empty()).then(|| crate::redaction::SecretDictionary::new(&secrets)) {
            None => None,
            Some(Ok(d)) => Some(d),
            Some(Err(_)) => return Vec::new(),
        };
    let current_id = RouteIdentity::of(current);
    let mut summaries = Vec::new();
    let mut used_bytes = 2usize;
    for route in usable_routes(store, settings) {
        if summaries.len() >= MAX_PUBLISHED_ROUTES {
            break;
        }
        if RouteIdentity::of(&route) == current_id {
            continue;
        }
        let item = ConfiguredRouteSummary {
            route: short_route_id(&route),
            provider: route.kind.as_str().to_owned(),
            profile: route.local.as_ref().map(|local| local.profile.clone()),
            model: route.model.clone(),
        };
        if let Some(ref d) = dict
            && route_summary_contains_secret(&item, d)
        {
            continue;
        }
        let Ok(encoded) = serde_json::to_string(&item) else {
            continue;
        };
        let added = encoded.len() + usize::from(!summaries.is_empty());
        if used_bytes + added > MAX_PUBLISHED_ROUTES_BYTES {
            continue;
        }
        used_bytes += added;
        summaries.push(item);
    }
    summaries
}

fn split_explicit_provider_prefix(selector: &str) -> Option<(ProviderKind, &str)> {
    let lower = selector.to_ascii_lowercase();
    if lower.starts_with("gpt://") || lower.starts_with("http://") || lower.starts_with("https://")
    {
        return None;
    }
    let (left, right) = selector.split_once(':')?;
    let kind = parse_provider_alias(left)?;
    let rest = right.trim();
    (!rest.is_empty()).then_some((kind, rest))
}

fn ensure_usable(store: &ConfigStore, provider: &ProviderSettings) -> Result<()> {
    if let Some(ref ca) = provider.ca_file {
        if !ca.is_absolute() {
            bail!("Путь ca_file маршрута должен быть абсолютным");
        }
        if !is_usable_ca_file(ca) {
            bail!(
                "Файл корневого сертификата ca_file маршрута недоступен, пуст или не содержит PEM-сертификатов"
            );
        }
    }
    provider.validate()?;
    ensure_route_free_of_secrets(store, provider, &[])?;
    if provider.kind == ProviderKind::Local {
        let name = local_app::profile_name(provider);
        match store.credential_for(provider)? {
            CredentialState::Present(_) | CredentialState::NotRequired => Ok(()),
            CredentialState::Missing => {
                bail!("Сервер профиля local «{name}» требует ключ: rcode local key {name} --stdin")
            }
        }
    } else if store.credential(provider.kind)?.is_none() {
        bail!(
            "Провайдер {} не подключён (нет ключа); выполните rcode connect {}",
            provider.kind,
            provider.kind
        );
    } else {
        Ok(())
    }
}

/// Строго разрешает маршрут для явно зафиксированного `ProviderKind` (флаг `--provider`).
pub fn resolve_for_provider(
    store: &ConfigStore,
    settings: &Settings,
    kind: ProviderKind,
    model_override: Option<&str>,
) -> Result<ProviderSettings> {
    if let Some(m) = model_override {
        let trimmed = m.trim();
        if trimmed.is_empty()
            || trimmed.chars().count() > 256
            || trimmed.chars().any(char::is_control)
        {
            bail!(
                "Укажите корректное непустое имя модели (1–256 символов без управляющих символов)"
            );
        }
    }
    if kind == ProviderKind::Local {
        let active_name = settings.local.active.as_deref().context(
            "Нет активного профиля local; укажите --profile ИМЯ (или активируйте через rcode local use)",
        )?;
        let mut profile = configured_local_profile(settings, active_name)?.with_context(|| {
            format!("Активный профиль local «{active_name}» не найден: rcode local list")
        })?;
        if let Some(m) = model_override {
            profile.model = m.trim().to_owned();
        }
        ensure_usable(store, &profile)?;
        return Ok(profile);
    }
    let mut provider = configured_cloud_provider(settings, kind)?
        .with_context(|| format!("Провайдер {kind} не настроен; выполните rcode connect {kind}"))?;
    if kind == ProviderKind::Custom
        && let Some(cred) = store.credential(ProviderKind::Custom)?
        && is_unconfigured_default_custom(settings, ProviderKind::Custom, &cred)
    {
        bail!("Провайдер custom не настроен; выполните rcode connect custom");
    }
    if let Some(m) = model_override {
        let trimmed = m.trim();
        if trimmed != provider.model {
            provider.effort = Effort::Auto;
            provider.model = trimmed.to_owned();
        }
    }
    ensure_usable(store, &provider)?;
    Ok(provider)
}

/// Возвращает все готовые настроенные маршруты (`local` и облачные), подходящие под `raw_selector`
/// (для интерактивного меню `/advisor <селектор>` при неоднозначном совпадении нескольких профилей).
pub fn matching_configured_routes(
    store: &ConfigStore,
    settings: &Settings,
    raw_selector: &str,
) -> Vec<ProviderSettings> {
    matching_configured_routes_for_kind(store, settings, raw_selector, None)
}

pub fn matching_configured_routes_for_kind(
    store: &ConfigStore,
    settings: &Settings,
    raw_selector: &str,
    kind_filter: Option<ProviderKind>,
) -> Vec<ProviderSettings> {
    let trimmed = raw_selector.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 256 || trimmed.chars().any(char::is_control)
    {
        return Vec::new();
    }
    let lower = trimmed.to_lowercase();
    let routes: Vec<ProviderSettings> = usable_routes(store, settings)
        .into_iter()
        .filter(|r| kind_filter.is_none_or(|k| r.kind == k))
        .collect();
    let exact: Vec<ProviderSettings> = routes
        .iter()
        .filter(|r| r.model.to_lowercase() == lower)
        .cloned()
        .collect();
    if exact.len() > 1 {
        return exact;
    }
    if trimmed.chars().count() < 2 {
        return exact;
    }
    routes
        .into_iter()
        .filter(|r| {
            r.model.to_lowercase().contains(&lower)
                || r.local
                    .as_ref()
                    .is_some_and(|l| l.profile.to_lowercase().contains(&lower))
        })
        .collect()
}

/// Разрешает строковый селектор маршрута строго по локальным настройкам без сети.
pub fn resolve_local_only(
    store: &ConfigStore,
    settings: &Settings,
    raw_selector: &str,
) -> Result<ProviderSettings> {
    let trimmed = raw_selector.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 256 || trimmed.chars().any(char::is_control)
    {
        bail!("Укажите корректный селектор маршрута (1–256 символов без управляющих символов)");
    }

    if let Some((kind, rest)) = split_explicit_provider_prefix(trimmed) {
        if kind == ProviderKind::Local {
            let (profile_name, model_override) = if settings.local.profiles.contains_key(rest) {
                (rest, None)
            } else if let Some((prof, model)) = rest.split_once(':') {
                (prof.trim(), Some(model.trim()))
            } else {
                (rest, None)
            };
            let mut profile =
                configured_local_profile(settings, profile_name)?.with_context(|| {
                    let safe_prof = redact_route_display_field(store, &[], profile_name);
                    format!("Профиль local «{safe_prof}» не найден: rcode local list")
                })?;
            if let Some(model) = model_override {
                if model.is_empty() {
                    let safe_prof = redact_route_display_field(store, &[], profile_name);
                    bail!("Укажите непустой ID модели после local:{safe_prof}:");
                }
                profile.model = model.to_owned();
            }
            ensure_usable(store, &profile)?;
            return Ok(profile);
        }
        return resolve_for_provider(store, settings, kind, Some(rest));
    }

    if let Some(kind) = parse_provider_alias(trimmed) {
        return resolve_for_provider(store, settings, kind, None);
    }

    if settings.local.profiles.contains_key(trimmed) {
        let profile =
            configured_local_profile(settings, trimmed)?.expect("profile key verified above");
        ensure_usable(store, &profile)?;
        return Ok(profile);
    }

    let lower_ascii = trimmed.to_ascii_lowercase();
    if !lower_ascii.starts_with("gpt://")
        && !lower_ascii.starts_with("http://")
        && !lower_ascii.starts_with("https://")
        && let Some((left, right)) = trimmed.split_once(':')
    {
        if let Some(kind) = parse_provider_alias(left) {
            let model = right.trim();
            if model.is_empty() {
                bail!("Укажите непустой селектор после {kind}:");
            }
            return resolve_for_provider(store, settings, kind, Some(model));
        }
        let profile_name = left.trim();
        if settings.local.profiles.contains_key(profile_name) {
            let model = right.trim();
            if model.is_empty() {
                let safe_prof = redact_route_display_field(store, &[], profile_name);
                bail!("Укажите непустой ID модели после {safe_prof}:");
            }
            let mut profile =
                configured_local_profile(settings, profile_name)?.with_context(|| {
                    let safe_prof = redact_route_display_field(store, &[], profile_name);
                    format!("Профиль local «{safe_prof}» не найден: rcode local list")
                })?;
            profile.model = model.to_owned();
            ensure_usable(store, &profile)?;
            return Ok(profile);
        }
    }

    let safe_trimmed = redact_route_display_field(store, &[], trimmed);
    let routes = usable_routes(store, settings);
    let available_hint = if routes.is_empty() {
        "нет других подключённых маршрутов".to_owned()
    } else {
        routes
            .iter()
            .map(|r| {
                format!(
                    "{} ({})",
                    short_route_id(r),
                    redact_route_display_field(store, &[], &r.model)
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    let lower = trimmed.to_lowercase();
    let exact: Vec<&ProviderSettings> = routes
        .iter()
        .filter(|r| r.model.to_lowercase() == lower)
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].clone());
    }
    if exact.len() > 1 {
        let options = exact
            .iter()
            .map(|r| {
                format!(
                    "{}:{}",
                    short_route_id(r),
                    redact_route_display_field(store, &[], &r.model)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "Модель «{safe_trimmed}» настроена сразу у нескольких провайдеров; уточните маршрут: {options}"
        );
    }

    if trimmed.chars().count() >= 2 {
        let partial: Vec<&ProviderSettings> = routes
            .iter()
            .filter(|r| {
                r.model.to_lowercase().contains(&lower)
                    || r.local
                        .as_ref()
                        .is_some_and(|l| l.profile.to_lowercase().contains(&lower))
            })
            .collect();
        if partial.len() == 1 {
            return Ok(partial[0].clone());
        }
        if partial.len() > 1 {
            let options = partial
                .iter()
                .map(|r| {
                    format!(
                        "{}:{}",
                        short_route_id(r),
                        redact_route_display_field(store, &[], &r.model)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "Селектор «{safe_trimmed}» подходит к нескольким маршрутам ({options}); укажите точный маршрут"
            );
        }
    }

    bail!(
        "Маршрут «{safe_trimmed}» не найден среди подключённых по умолчанию ({available_hint}). Укажите ПРОВАЙДЕР:МОДЕЛЬ (например openrouter:MODEL_ID или gigachat)"
    )
}

/// Фильтрует модели из каталога `/models` по подстроке и назначению маршрута.
pub fn filter_catalog_models(
    models: &[ModelInfo],
    query: &str,
    purpose: RoutePurpose,
) -> Vec<ModelInfo> {
    let lower = query.trim().to_lowercase();
    let mut matched: Vec<ModelInfo> = models
        .iter()
        .filter(|model| {
            !model.id.chars().any(char::is_control)
                && (purpose == RoutePurpose::Advisor || model.supports_tools != Some(false))
                && (lower.is_empty()
                    || model.id.to_lowercase().contains(&lower)
                    || model.name.to_lowercase().contains(&lower))
        })
        .cloned()
        .collect();
    matched.sort_by(|a, b| {
        let a_exact = a.id.to_lowercase() == lower;
        let b_exact = b.id.to_lowercase() == lower;
        b_exact.cmp(&a_exact).then_with(|| a.id.cmp(&b.id))
    });
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{LocalRuntime, profile_settings};

    fn fixture_store_and_settings() -> (tempfile::TempDir, ConfigStore, Settings) {
        let tmp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(tmp.path().join("state")).unwrap();
        store
            .save_credential(ProviderKind::GigaChat, "giga-secret-key-12345678")
            .unwrap();
        store
            .save_credential(ProviderKind::OpenRouter, "router-secret-key-12345678")
            .unwrap();
        let mut settings = Settings::default();
        let mut giga = ProviderSettings::new(ProviderKind::GigaChat);
        giga.model = "GigaChat-3-Ultra".into();
        settings.providers.insert("gigachat".into(), giga);

        let mut router = ProviderSettings::new(ProviderKind::OpenRouter);
        router.model = "z-ai/glm-5.3-flash".into();
        settings.providers.insert("openrouter".into(), router);

        let mlx = profile_settings(
            "mlx",
            "http://127.0.0.1:8080/v1",
            LocalRuntime::Mlx,
            "/models/Qwen3.8-27B-MLX-8bit",
        );
        settings.remember_provider(&mlx);
        store.save(&settings).unwrap();
        (tmp, store, settings)
    }

    #[test]
    fn resolves_cyrillic_aliases_substrings_and_explicit_prefixes_without_network() {
        let (_tmp, store, settings) = fixture_store_and_settings();

        let giga = resolve_local_only(&store, &settings, "гигачат").unwrap();
        assert_eq!(giga.kind, ProviderKind::GigaChat);
        assert_eq!(giga.model, "GigaChat-3-Ultra");

        let glm = resolve_local_only(&store, &settings, "glm").unwrap();
        assert_eq!(glm.kind, ProviderKind::OpenRouter);
        assert_eq!(glm.model, "z-ai/glm-5.3-flash");

        let qwen = resolve_local_only(&store, &settings, "qwen").unwrap();
        assert_eq!(qwen.kind, ProviderKind::Local);
        assert_eq!(local_app::profile_name(&qwen), "mlx");

        let custom_router =
            resolve_local_only(&store, &settings, "openrouter:anthropic/claude-opus-4-6").unwrap();
        assert_eq!(custom_router.kind, ProviderKind::OpenRouter);
        assert_eq!(custom_router.model, "anthropic/claude-opus-4-6");

        // Unconfigured Yandex (no key) fails clearly.
        assert!(resolve_local_only(&store, &settings, "яндекс").is_err());
    }

    #[test]
    fn yandex_gpt_uri_and_ollama_colon_model_do_not_misparse() {
        let (_tmp, store, mut settings) = fixture_store_and_settings();
        store
            .save_credential(ProviderKind::Yandex, "yandex-secret-key-12345678")
            .unwrap();
        let mut yandex = ProviderSettings::new(ProviderKind::Yandex);
        yandex.folder_id = Some("b1gfolder".into());
        yandex.model = "gpt://b1gfolder/yandexgpt/latest".into();
        settings.providers.insert("yandex".into(), yandex);

        let ollama = profile_settings(
            "ollama",
            "http://127.0.0.1:11434/v1",
            LocalRuntime::Ollama,
            "qwen3:8b",
        );
        settings.local.profiles.insert("ollama".into(), ollama);
        store.save(&settings).unwrap();

        let resolved_uri =
            resolve_local_only(&store, &settings, "gpt://b1gfolder/yandexgpt/latest").unwrap();
        assert_eq!(resolved_uri.kind, ProviderKind::Yandex);

        let resolved_tag = resolve_local_only(&store, &settings, "local:ollama:qwen3:14b").unwrap();
        assert_eq!(resolved_tag.kind, ProviderKind::Local);
        assert_eq!(resolved_tag.model, "qwen3:14b");
    }

    #[test]
    fn route_identity_distinguishes_profiles_endpoints_and_models() {
        let a = profile_settings("a", "http://127.0.0.1:8080/v1", LocalRuntime::Mlx, "m");
        let b = profile_settings("b", "http://127.0.0.1:8080/v1", LocalRuntime::Mlx, "m");
        let mut a_alias = a.clone();
        a_alias.base_url = Some("http://localhost:8080/v1/".into());
        assert!(RouteIdentity::same_as(&a, &a_alias));
        assert!(!RouteIdentity::same_as(&a, &b), "different profile names");
    }

    #[test]
    fn catalog_filter_allows_toolless_models_for_advisor_but_not_subagent() {
        let models = vec![
            ModelInfo {
                id: "deepseek/deepseek-r1".into(),
                name: "DeepSeek R1".into(),
                supports_tools: Some(false),
                ..ModelInfo::default()
            },
            ModelInfo {
                id: "z-ai/glm-5.3-flash".into(),
                name: "GLM 5.3".into(),
                supports_tools: Some(true),
                ..ModelInfo::default()
            },
        ];
        assert_eq!(
            filter_catalog_models(&models, "deepseek", RoutePurpose::Advisor).len(),
            1
        );
        assert!(filter_catalog_models(&models, "deepseek", RoutePurpose::Subagent).is_empty());
    }

    #[test]
    fn consent_label_shows_gigachat_oauth_override_and_published_routes_skip_oversized() {
        let mut giga = ProviderSettings::new(ProviderKind::GigaChat);
        giga.model = "GigaChat-3-Ultra".into();
        giga.auth_url = Some("https://oauth-proxy.corp.example:9443/api/v2/oauth".into());
        let label = consent_target_label(&giga);
        assert!(
            label.contains("oauth: https://oauth-proxy.corp.example:9443/api/v2/oauth"),
            "unexpected label: {label}"
        );

        let (_tmp, store, mut settings) = fixture_store_and_settings();
        // Make Yandex the first cloud provider with a >512-byte model URI so it exceeds
        // MAX_PUBLISHED_ROUTES_BYTES; subsequent shorter routes (`gigachat`, `openrouter`) must still be published!
        store
            .save_credential(ProviderKind::Yandex, "yandex-secret-key-12345678")
            .unwrap();
        let mut yandex = ProviderSettings::new(ProviderKind::Yandex);
        yandex.model = format!("gpt://folder/{}", "m".repeat(520));
        settings.providers.insert("yandex".into(), yandex);
        store.save(&settings).unwrap();
        let current = settings.local.profiles["mlx"].clone();
        let published = published_routes(&store, &settings, &current);
        assert!(
            published.iter().any(|r| r.provider == "gigachat"),
            "oversized first route must not hide shorter alternatives: {published:?}"
        );

        // Explicit `resolve_for_provider` (`--provider yandex` without key) must NEVER fall back
        // to a local profile named `yandex`.
        let tmp2 = tempfile::tempdir().unwrap();
        let store2 = ConfigStore::at(tmp2.path().join("state")).unwrap();
        let mut settings2 = Settings::default();
        let fake_local = profile_settings(
            "gigachat",
            "http://127.0.0.1:8080/v1",
            LocalRuntime::Mlx,
            "local-model",
        );
        settings2
            .local
            .profiles
            .insert("gigachat".into(), fake_local);
        assert!(
            resolve_for_provider(&store2, &settings2, ProviderKind::GigaChat, None).is_err(),
            "missing GigaChat key must fail instead of falling back to local profile named gigachat"
        );

        // Mismatched `providers.openrouter.kind = gigachat` must be rejected!
        let mut bad_giga = ProviderSettings::new(ProviderKind::GigaChat);
        bad_giga.model = "GigaChat-3-Ultra".into();
        settings2.providers.insert("openrouter".into(), bad_giga);
        store2
            .save_credential(ProviderKind::OpenRouter, "or-secret-key-12345678")
            .unwrap();
        store2
            .save_credential(ProviderKind::GigaChat, "giga-secret-key-12345678")
            .unwrap();
        assert!(
            resolve_for_provider(&store2, &settings2, ProviderKind::OpenRouter, None).is_err(),
            "mismatched kind inside providers.openrouter must fail closed"
        );
    }

    #[test]
    fn custom_localhost_does_not_bypass_local_loopback_consent_and_one_char_exact_model_matches() {
        let local_ip = profile_settings(
            "mlx",
            "http://127.0.0.1:8080/v1",
            LocalRuntime::Mlx,
            "qwen-local",
        );
        let local_host = profile_settings(
            "mlx",
            "http://localhost:8080/v1",
            LocalRuntime::Mlx,
            "qwen-local",
        );
        let mut custom_localhost = ProviderSettings::new(ProviderKind::Custom);
        custom_localhost.base_url = Some("http://localhost:8080/v1".into());
        custom_localhost.model = "qwen-custom".into();

        let mut custom_ip = ProviderSettings::new(ProviderKind::Custom);
        custom_ip.base_url = Some("http://127.0.0.1:8080/v1".into());
        custom_ip.model = "qwen-custom".into();

        assert!(
            !same_loopback_endpoint(&local_ip, &custom_localhost),
            "custom localhost can resolve ::1 via system DNS and must not match pinned 127.0.0.1 local"
        );
        assert!(
            !same_loopback_endpoint(&local_host, &custom_localhost),
            "custom localhost must not match local localhost either"
        );
        assert!(
            same_loopback_endpoint(&local_host, &custom_ip),
            "literal 127.0.0.1 custom matches local localhost (pinned to 127.0.0.1)"
        );
        assert!(
            !same_loopback_endpoint(&custom_localhost, &custom_ip),
            "custom localhost vs custom 127.0.0.1 must not share loopback consent"
        );
        assert!(
            same_loopback_endpoint(&custom_localhost, &custom_localhost),
            "identical custom localhost endpoints match"
        );

        let tmp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(tmp.path().join("state")).unwrap();
        let mut settings = Settings::default();
        let one_char = profile_settings("one", "http://127.0.0.1:8090/v1", LocalRuntime::Mlx, "m");
        let longer = profile_settings(
            "longer",
            "http://127.0.0.1:8091/v1",
            LocalRuntime::Mlx,
            "model-alpha",
        );
        settings.local.profiles.insert("one".into(), one_char);
        settings.local.profiles.insert("longer".into(), longer);
        store.save(&settings).unwrap();

        let matches = matching_configured_routes(&store, &settings, "m");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].model, "m");

        // Deleting a keyless profile from `config.json` must immediately exclude it from `usable_routes`
        // even if the caller still passes an older in-memory `&Settings`!
        let mut on_disk_trimmed = settings.clone();
        on_disk_trimmed.local.profiles.remove("one");
        store.save(&on_disk_trimmed).unwrap();
        assert!(
            matching_configured_routes(&store, &settings, "m").is_empty(),
            "deleted on-disk local profile must not remain in usable_routes"
        );
        store.save(&settings).unwrap();

        // Explicit `<local_profile>:<model>` must resolve to `local`, never to a cloud model named `<profile>:<model>`.
        store
            .save_credential(ProviderKind::OpenRouter, "or-secret-key-12345678")
            .unwrap();
        let mut cloud = ProviderSettings::new(ProviderKind::OpenRouter);
        cloud.model = "one:cloud-trap".into();
        settings.providers.insert("openrouter".into(), cloud);
        let resolved = resolve_local_only(&store, &settings, "one:cloud-trap").unwrap();
        assert_eq!(resolved.kind, ProviderKind::Local);
        assert_eq!(resolved.model, "cloud-trap");

        // Explicit `<profile>:<model>` and `local:<profile>:<model>` carry `local_profile`
        // so `/advisor lab:qwen` never offers unrelated local profiles!
        let c1 = explicit_selector_constraint(&settings, "one:qwen").unwrap();
        assert_eq!(c1.kind, ProviderKind::Local);
        assert_eq!(c1.local_profile, Some("one"));
        assert_eq!(c1.subquery, Some("qwen"));

        let c2 = explicit_selector_constraint(&settings, "local:one:qwen").unwrap();
        assert_eq!(c2.kind, ProviderKind::Local);
        assert_eq!(c2.local_profile, Some("one"));
        assert_eq!(c2.subquery, Some("qwen"));

        let c3 = explicit_selector_constraint(&settings, "local:qwen").unwrap();
        assert_eq!(c3.kind, ProviderKind::Local);
        assert_eq!(c3.local_profile, None);
        assert_eq!(c3.subquery, Some("qwen"));

        let c4 = explicit_selector_constraint(&settings, "ЛОКАЛЬНАЯ:one").unwrap();
        assert_eq!(c4.kind, ProviderKind::Local);
        assert_eq!(c4.local_profile, Some("one"));
        assert_eq!(c4.subquery, None);

        // Two cloud routes with exact model `"qwen"` must NOT hide a local profile `"mlx"` with `"qwen-7b"`
        // when searching `matching_configured_routes_for_kind(..., Some(ProviderKind::Local))`!
        let mut or_qwen = ProviderSettings::new(ProviderKind::OpenRouter);
        or_qwen.model = "qwen".into();
        let mut custom_qwen = ProviderSettings::new(ProviderKind::Custom);
        custom_qwen.base_url = Some("https://api.example.com/v1".into());
        custom_qwen.model = "qwen".into();
        let mlx_qwen = profile_settings(
            "mlx",
            "http://127.0.0.1:8092/v1",
            LocalRuntime::Mlx,
            "qwen-7b",
        );
        settings.providers.insert("openrouter".into(), or_qwen);
        settings.providers.insert("custom".into(), custom_qwen);
        settings.local.profiles.insert("mlx".into(), mlx_qwen);
        store.save(&settings).unwrap();
        store
            .save_credential(ProviderKind::Custom, "custom-secret-key-12345678")
            .unwrap();
        let local_matches = matching_configured_routes_for_kind(
            &store,
            &settings,
            "qwen",
            Some(ProviderKind::Local),
        );
        assert_eq!(local_matches.len(), 1);
        assert_eq!(local_matches[0].model, "qwen-7b");

        // `Session::new_clean` with `"4"` in secrets mints a valid UUID without `'4'`!
        let clean_sess = crate::state::Session::new_clean(
            tmp.path(),
            ProviderSettings::new(ProviderKind::Local),
            &["4".to_string()],
        )
        .unwrap();
        assert!(!clean_sess.id.contains('4'), "{}", clean_sess.id);
        assert!(uuid::Uuid::parse_str(&clean_sess.id).is_ok());
        assert!(
            crate::state::Session::new_clean(
                tmp.path(),
                ProviderSettings::new(ProviderKind::Local),
                &["-".to_string()],
            )
            .is_err(),
            "impossible `-` secret must fail closed instead of returning a poisoned UUID"
        );
    }
}
