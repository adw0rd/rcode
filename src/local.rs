//! Local OpenAI-compatible servers: named profiles, loopback rules and key binding.
//!
//! Profiles are stored in `Settings.local`; keys live in `credentials.json`
//! under `local:<profile>` and are never read from the environment.
use crate::config::{ProviderKind, ProviderSettings};
use anyhow::{Result, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, net::IpAddr};

pub const DEFAULT_CONTEXT_TOKENS: u32 = 32_768;
pub const MIN_CONTEXT_TOKENS: u32 = 2048;
pub const MAX_CONTEXT_TOKENS: u32 = 1_048_576;
pub const MAX_OUTPUT_TOKENS: u32 = 8192;
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 600;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 180;
/// Name of the unsaved profile used when no local profile exists yet.
pub const DRAFT_PROFILE: &str = "local";
pub(crate) const CREDENTIAL_PREFIX: &str = "local:";
const LOOPBACK_ONLY: &str = "Для local допустим только адрес 127.0.0.1/localhost/::1 (http или https); удалённые API подключайте через custom";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LocalRuntime {
    Ollama,
    #[value(name = "llamacpp")]
    LlamaCpp,
    Mlx,
    #[value(name = "lmstudio")]
    LmStudio,
    /// Any other OpenAI-compatible server; no runtime-specific parameters are sent.
    #[default]
    #[value(name = "openai")]
    OpenAi,
}

impl LocalRuntime {
    pub const fn all() -> [Self; 5] {
        [
            Self::Ollama,
            Self::LlamaCpp,
            Self::Mlx,
            Self::LmStudio,
            Self::OpenAi,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::LlamaCpp => "llamacpp",
            Self::Mlx => "mlx",
            Self::LmStudio => "lmstudio",
            Self::OpenAi => "openai",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ollama => "Ollama",
            Self::LlamaCpp => "llama.cpp",
            Self::Mlx => "MLX",
            Self::LmStudio => "LM Studio",
            Self::OpenAi => "OpenAI-совместимый сервер",
        }
    }

    /// `stream_options.include_usage` is documented for these servers; for
    /// MLX and unknown servers compatibility is not confirmed, so it is omitted.
    pub const fn stream_usage(self) -> bool {
        matches!(self, Self::Ollama | Self::LlamaCpp | Self::LmStudio)
    }
}

impl fmt::Display for LocalRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

const fn default_context_tokens() -> u32 {
    DEFAULT_CONTEXT_TOKENS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSettings {
    pub profile: String,
    #[serde(default)]
    pub runtime: LocalRuntime,
    #[serde(default = "default_context_tokens")]
    pub context_tokens: u32,
    /// Set only by an explicit user choice; images are refused otherwise.
    #[serde(default)]
    pub vision: bool,
    #[serde(default)]
    pub key_required: bool,
    /// Explicit `chat_template_kwargs.enable_thinking`; omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalProfiles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProviderSettings>,
}

impl LocalProfiles {
    pub fn is_empty(&self) -> bool {
        self.active.is_none() && self.profiles.is_empty()
    }

    pub fn active_profile(&self) -> Option<&ProviderSettings> {
        self.active
            .as_deref()
            .and_then(|name| self.profiles.get(name))
    }

    /// `base`, then `base-2`, `base-3`… for a profile that does not exist yet.
    pub fn unique_name(&self, base: &str) -> String {
        if !self.profiles.contains_key(base) {
            return base.to_owned();
        }
        (2..)
            .map(|index| format!("{base}-{index}"))
            .find(|name| !self.profiles.contains_key(name))
            .expect("unbounded suffixes")
    }
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let valid = name.len() <= 32
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if !valid {
        bail!(
            "Имя профиля local: 1–32 символа a-z, 0-9, точка, _ или -, начиная с буквы или цифры"
        );
    }
    Ok(())
}

pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub fn is_loopback_url(url: &Url) -> bool {
    url.host_str().is_some_and(is_loopback_host)
}

/// Local endpoints are stricter than custom ones: loopback only, even for HTTPS.
pub fn validate_local_endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("{LOOPBACK_ONLY}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !is_loopback_url(&url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || value.split_once("://").is_some_and(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
    {
        bail!("{LOOPBACK_ONLY}");
    }
    Ok(url)
}

/// Identity of the endpoint a key is bound to. Strict per address literal:
/// `127.0.0.1`, `127.0.0.2` and `[::1]` can be different processes on the same
/// port. Only `localhost` is normalized to `127.0.0.1`, because local clients
/// resolve it to that address alone.
pub fn endpoint_identity(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if !is_loopback_url(&url) {
        return None;
    }
    let host = url.host_str()?;
    let host = if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_owned()
    } else {
        match host.trim_matches(['[', ']']).parse::<IpAddr>().ok()? {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        }
    };
    Some(format!(
        "{}://{host}:{}{}",
        url.scheme(),
        url.port_or_known_default()?,
        url.path().trim_end_matches('/')
    ))
}

pub fn profile_settings(
    name: &str,
    base_url: &str,
    runtime: LocalRuntime,
    model: &str,
) -> ProviderSettings {
    let mut settings = ProviderSettings::new(ProviderKind::Local);
    settings.base_url = Some(base_url.into());
    settings.model = model.into();
    if let Some(local) = settings.local.as_mut() {
        local.profile = name.into();
        local.runtime = runtime;
    }
    settings
}

pub(crate) fn draft_settings() -> LocalSettings {
    LocalSettings {
        profile: DRAFT_PROFILE.into(),
        runtime: LocalRuntime::OpenAi,
        context_tokens: DEFAULT_CONTEXT_TOKENS,
        vision: false,
        key_required: false,
        thinking: None,
    }
}

pub(crate) fn validate(settings: &ProviderSettings) -> Result<()> {
    let Some(local) = &settings.local else {
        bail!("Профиль local повреждён: нет параметров local");
    };
    validate_profile_name(&local.profile)?;
    let Some(base_url) = &settings.base_url else {
        bail!("{LOOPBACK_ONLY}");
    };
    validate_local_endpoint(base_url)?;
    if settings.folder_id.is_some() || settings.auth_url.is_some() || settings.scope.is_some() {
        bail!("Для local не используются folder_id, auth_url и scope");
    }
    if !(MIN_CONTEXT_TOKENS..=MAX_CONTEXT_TOKENS).contains(&local.context_tokens) {
        bail!("Контекст профиля local: от {MIN_CONTEXT_TOKENS} до {MAX_CONTEXT_TOKENS} токенов");
    }
    let cap = MAX_OUTPUT_TOKENS.min(local.context_tokens / 4);
    if settings.max_output_tokens > cap {
        bail!(
            "Для local max_output_tokens не больше {cap}: 8192 и не более четверти контекста профиля ({})",
            local.context_tokens
        );
    }
    if local.thinking.is_some() && local.runtime == LocalRuntime::Ollama {
        bail!("Для ollama rcode не передаёт управление thinking; настройте модель на сервере");
    }
    Ok(())
}

/// Minimum length of a local server key. Every accepted key is a secret and
/// is redacted everywhere, so a short common word cannot be a key.
pub const MIN_KEY_CHARS: usize = 8;

pub fn validate_key(value: &str) -> Result<()> {
    crate::config::validate_credential(value)?;
    if value.trim().chars().count() < MIN_KEY_CHARS {
        bail!(
            "Ключ локального сервера должен быть не короче {MIN_KEY_CHARS} символов; для сервера без ключа ключ не нужен"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_identity_is_strict_per_loopback_address() {
        let base = endpoint_identity("http://127.0.0.1:8080/v1").unwrap();
        assert_eq!(
            endpoint_identity("http://localhost:8080/v1/").unwrap(),
            base
        );
        assert_eq!(endpoint_identity("http://LOCALHOST:8080/v1").unwrap(), base);
        // Another loopback address or family may be another process on that port.
        for other in [
            "http://[::1]:8080/v1",
            "http://127.0.0.2:8080/v1",
            "http://127.0.0.1:8081/v1",
            "https://127.0.0.1:8080/v1",
            "http://127.0.0.1:8080/api/v1",
        ] {
            assert_ne!(endpoint_identity(other).unwrap(), base, "{other}");
        }
        assert!(endpoint_identity("http://192.168.0.2:8080/v1").is_none());
    }

    #[test]
    fn unique_names_add_numeric_suffixes() {
        let mut profiles = LocalProfiles::default();
        assert_eq!(profiles.unique_name("ollama"), "ollama");
        for name in ["ollama", "ollama-2"] {
            profiles.profiles.insert(
                name.into(),
                profile_settings(name, "http://127.0.0.1:11434/v1", LocalRuntime::Ollama, "m"),
            );
        }
        assert_eq!(profiles.unique_name("ollama"), "ollama-3");
    }

    #[test]
    fn short_local_keys_are_rejected_not_silently_unredacted() {
        for value in ["", "   ", "short", "abc\n12345678"] {
            assert!(validate_key(value).is_err(), "{value:?}");
        }
        assert!(
            validate_key("lm-studio").is_ok(),
            "an explicit word is still a secret"
        );
    }

    #[test]
    fn runtime_names_are_stable() {
        for (runtime, name) in LocalRuntime::all()
            .into_iter()
            .zip(["ollama", "llamacpp", "mlx", "lmstudio", "openai"])
        {
            assert_eq!(runtime.as_str(), name);
            assert_eq!(serde_json::to_value(runtime).unwrap(), name);
            assert_eq!(
                <LocalRuntime as clap::ValueEnum>::from_str(name, false).unwrap(),
                runtime
            );
        }
        assert!(LocalRuntime::Ollama.stream_usage());
        assert!(!LocalRuntime::Mlx.stream_usage());
        assert!(!LocalRuntime::OpenAi.stream_usage());
    }
}
