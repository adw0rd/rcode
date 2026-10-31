use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    env, fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Yandex,
    GigaChat,
    OpenRouter,
    Custom,
    Local,
}

impl ProviderKind {
    pub const fn all() -> [Self; 5] {
        [
            Self::Yandex,
            Self::GigaChat,
            Self::OpenRouter,
            Self::Custom,
            Self::Local,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yandex => "yandex",
            Self::GigaChat => "gigachat",
            Self::OpenRouter => "openrouter",
            Self::Custom => "custom",
            Self::Local => "local",
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProviderKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "yandex" => Ok(Self::Yandex),
            "gigachat" => Ok(Self::GigaChat),
            "openrouter" => Ok(Self::OpenRouter),
            "custom" => Ok(Self::Custom),
            "local" => Ok(Self::Local),
            _ => {
                bail!("Неизвестный провайдер: доступны yandex, gigachat, openrouter, custom, local")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    #[default]
    Auto,
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

impl Effort {
    pub const fn all() -> [Self; 8] {
        [
            Self::Auto,
            Self::None,
            Self::Minimal,
            Self::Low,
            Self::Medium,
            Self::High,
            Self::Xhigh,
            Self::Max,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::None => "none",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }

    pub const fn is_auto(&self) -> bool {
        matches!(self, Self::Auto)
    }
}

impl fmt::Display for Effort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Effort {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::all()
            .into_iter()
            .find(|effort| effort.as_str() == value)
            .ok_or_else(|| anyhow::anyhow!("Неизвестный effort: доступны auto, none, minimal, low, medium, high, xhigh, max"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderSettings {
    pub kind: ProviderKind,
    pub model: String,
    #[serde(default, skip_serializing_if = "Effort::is_auto")]
    pub effort: Effort,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub auth_url: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_stream")]
    pub stream: bool,
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
    /// Ожидание HTTP-ответа генерации до получения заголовков.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Present only for `kind = local`; cloud entries serialize exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<crate::local::LocalSettings>,
}

const fn default_stream() -> bool {
    true
}
const fn default_max_output_tokens() -> u32 {
    4096
}
const fn default_request_timeout_secs() -> u64 {
    300
}
const fn default_idle_timeout_secs() -> u64 {
    90
}

impl ProviderSettings {
    pub fn new(kind: ProviderKind) -> Self {
        let (model, base_url) = match kind {
            ProviderKind::Yandex => (
                "deepseek-v4.1-flash/latest",
                "https://ai.api.cloud.yandex.net/v1",
            ),
            ProviderKind::GigaChat => ("GigaChat", "https://api.giga.chat/v1"),
            ProviderKind::OpenRouter => ("z-ai/glm-5.3-flash", "https://openrouter.ai/api/v1"),
            ProviderKind::Custom => ("local", "http://localhost:11434/v1"),
            // A draft: the model comes from the server catalog or --model.
            ProviderKind::Local => ("", "http://127.0.0.1:11434/v1"),
        };
        let local = kind == ProviderKind::Local;
        Self {
            kind,
            model: model.into(),
            effort: Effort::Auto,
            base_url: Some(base_url.into()),
            folder_id: None,
            auth_url: None,
            scope: None,
            ca_file: None,
            stream: default_stream(),
            max_output_tokens: default_max_output_tokens(),
            request_timeout_secs: if local {
                crate::local::DEFAULT_REQUEST_TIMEOUT_SECS
            } else {
                default_request_timeout_secs()
            },
            idle_timeout_secs: if local {
                crate::local::DEFAULT_IDLE_TIMEOUT_SECS
            } else {
                default_idle_timeout_secs()
            },
            local: local.then(crate::local::draft_settings),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_effort()?;
        if self.model.trim().is_empty() || self.model.chars().any(char::is_control) {
            bail!("Укажите непустое имя модели без управляющих символов");
        }
        if self.max_output_tokens == 0
            || self.request_timeout_secs == 0
            || self.idle_timeout_secs == 0
        {
            bail!("Лимит выходных токенов и таймауты должны быть больше нуля");
        }
        if self.kind == ProviderKind::Local {
            return crate::local::validate(self);
        }
        if self.local.is_some() {
            bail!("Параметры local допустимы только для провайдера local");
        }
        for endpoint in [&self.base_url, &self.auth_url].into_iter().flatten() {
            validate_endpoint(endpoint)?;
        }
        if self.kind == ProviderKind::Yandex {
            if self.model.starts_with("gpt://") {
                let uri = reqwest::Url::parse(&self.model)
                    .map_err(|_| anyhow::anyhow!("Некорректный URI модели Yandex"))?;
                if uri.host_str().is_none()
                    || uri.path().trim_matches('/').is_empty()
                    || !uri.username().is_empty()
                    || uri.password().is_some()
                    || uri.query().is_some()
                    || uri.fragment().is_some()
                    || has_userinfo(&self.model)
                {
                    bail!("Требуется полный URI модели Yandex: gpt://folder/model/version");
                }
            } else if self
                .folder_id
                .as_deref()
                .is_none_or(|folder| folder.trim().is_empty())
            {
                bail!(
                    "Для Yandex укажите folder_id или полный URI модели gpt://folder/model/version"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn validate_effort(&self) -> Result<()> {
        if self.kind == ProviderKind::Local && !self.effort.is_auto() {
            bail!("Для local effort не настраивается: используется auto (настройки сервера)");
        }
        if matches!(self.kind, ProviderKind::Yandex | ProviderKind::GigaChat)
            && !matches!(
                self.effort,
                Effort::Auto | Effort::Low | Effort::Medium | Effort::High
            )
        {
            bail!(
                "Для {} доступны effort auto, low, medium, high; поддержка зависит от модели",
                self.kind
            );
        }
        Ok(())
    }
}

fn has_userinfo(value: &str) -> bool {
    value.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}

fn validate_endpoint(value: &str) -> Result<()> {
    if value.trim() != value || value.chars().any(char::is_control) {
        bail!("URL провайдера содержит пробельные или управляющие символы");
    }
    let url =
        reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!("Некорректный URL провайдера"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || has_userinfo(value)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("URL провайдера должен содержать адрес сервера без userinfo, query и fragment");
    }
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("URL провайдера требует HTTPS; HTTP разрешён только для loopback");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    #[default]
    Ask,
    AutoEdit,
    FullAccess,
}

impl ApprovalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::AutoEdit => "auto-edit",
            Self::FullAccess => "full-access",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    pub active: ProviderKind,
    pub providers: BTreeMap<String, ProviderSettings>,
    #[serde(default, skip_serializing_if = "crate::local::LocalProfiles::is_empty")]
    pub local: crate::local::LocalProfiles,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            active: ProviderKind::Yandex,
            providers: ProviderKind::all()
                .into_iter()
                .filter(|kind| *kind != ProviderKind::Local)
                .map(|kind| (kind.as_str().into(), ProviderSettings::new(kind)))
                .collect(),
            local: crate::local::LocalProfiles::default(),
        }
    }
}

impl Settings {
    /// For local: the active profile, or an unsaved draft without a model.
    pub fn provider(&self, kind: ProviderKind) -> ProviderSettings {
        if kind == ProviderKind::Local {
            return self
                .local
                .active_profile()
                .cloned()
                .unwrap_or_else(|| ProviderSettings::new(kind));
        }
        self.providers
            .get(kind.as_str())
            .cloned()
            .unwrap_or_else(|| ProviderSettings::new(kind))
    }

    /// Stores the selected provider and makes it active. Local settings go
    /// into their named profile, never into `providers["local"]`.
    /// A local provider without profile settings is invalid (see `validate`)
    /// and is never stored, in particular not as `providers["local"]`.
    pub fn remember_provider(&mut self, provider: &ProviderSettings) {
        if provider.kind != ProviderKind::Local {
            self.active = provider.kind;
            self.providers
                .insert(provider.kind.to_string(), provider.clone());
            return;
        }
        if let Some(local) = &provider.local {
            self.active = provider.kind;
            self.local
                .profiles
                .insert(local.profile.clone(), provider.clone());
            self.local.active = Some(local.profile.clone());
        }
    }
}

/// Whether a request may proceed, and with which key.
#[derive(Debug)]
pub enum CredentialState {
    Present(Credential),
    /// A local profile without a stored key: no Authorization header is sent.
    NotRequired,
    Missing,
}

impl CredentialState {
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    pub fn into_key(self) -> Option<String> {
        match self {
            Self::Present(credential) => Some(credential.value),
            Self::NotRequired | Self::Missing => None,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Present(credential) => &credential.source,
            Self::NotRequired => "not_required",
            Self::Missing => "missing",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ProjectPermissions {
    version: u32,
    projects: BTreeMap<PathBuf, ApprovalMode>,
}

impl Default for ProjectPermissions {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            projects: BTreeMap::new(),
        }
    }
}

pub struct Credential {
    pub value: String,
    pub source: String,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("value", &"[REDACTED]")
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Credentials {
    version: u32,
    providers: BTreeMap<String, String>,
}

// Deliberately omit all values from error diagnostics, including test failures.
impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("version", &self.version)
            .field("providers", &"[REDACTED]")
            .finish()
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            providers: BTreeMap::new(),
        }
    }
}

impl ConfigStore {
    pub fn new() -> Result<Self> {
        let root = match env::var_os("RCODE_HOME") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            Some(_) => bail!("RCODE_HOME не должен быть пустым"),
            None => directories::ProjectDirs::from("", "", "rcode")
                .context("Не удалось определить каталог настроек; укажите RCODE_HOME")?
                .config_dir()
                .to_path_buf(),
        };
        Self::at(root)
    }

    pub fn at(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            bail!("Путь к каталогу настроек не должен быть пустым");
        }
        let root = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()
                .context("Не удалось определить текущий каталог")?
                .join(path)
        };
        ensure_private_directory(&root)?;
        ensure_private_directory(&root.join("sessions"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    pub fn exists(&self) -> bool {
        self.root.join("config.json").exists()
    }

    pub fn permissions_for(&self, root: &Path) -> Result<ApprovalMode> {
        let root = root.canonicalize()?;
        Ok(self
            .load_permissions()?
            .projects
            .get(&root)
            .copied()
            .unwrap_or_default())
    }

    pub fn save_permissions(&self, root: &Path, mode: ApprovalMode) -> Result<()> {
        let root = root.canonicalize()?;
        let _lock = lock_state_file(&self.root.join("permissions.lock"))?;
        let mut permissions = self.load_permissions()?;
        permissions.projects.insert(root, mode);
        write_private_json(&self.root.join("permissions.json"), &permissions)
    }

    fn load_permissions(&self) -> Result<ProjectPermissions> {
        let permissions =
            read_json::<ProjectPermissions>(&self.root.join("permissions.json"), "разрешений")?
                .unwrap_or_default();
        check_version(permissions.version, "разрешений")?;
        Ok(permissions)
    }

    pub fn load(&self) -> Result<Settings> {
        ensure_directory(&self.root)?;
        let Some(settings) = read_json::<Settings>(&self.root.join("config.json"), "настроек")?
        else {
            return Ok(Settings::default());
        };
        check_version(settings.version, "настроек")?;
        Ok(settings)
    }

    pub fn save(&self, settings: &Settings) -> Result<()> {
        check_version(settings.version, "настроек")?;
        ensure_directory(&self.root)?;
        write_private_json(&self.root.join("config.json"), settings)
    }

    pub fn credential(&self, kind: ProviderKind) -> Result<Option<Credential>> {
        // Local keys are bound to a profile endpoint: see credential_for.
        if kind == ProviderKind::Local {
            return Ok(None);
        }
        if let Some(credential) = credential_from_env(kind, |name| env::var(name).ok())? {
            return Ok(Some(credential));
        }
        let credentials = self.load_credentials()?;
        credentials
            .providers
            .get(kind.as_str())
            .map(|value| {
                validate_credential(value)?;
                Ok(Credential {
                    value: value.clone(),
                    source: "credentials.json".into(),
                })
            })
            .transpose()
    }

    pub fn save_credential(&self, kind: ProviderKind, value: &str) -> Result<()> {
        if kind == ProviderKind::Local {
            // An unscoped "local" entry would never be read or deleted.
            bail!("Ключ local хранится в профиле: rcode local key ИМЯ --stdin");
        }
        validate_credential(value)?;
        let mut credentials = self.load_credentials()?;
        credentials
            .providers
            .insert(kind.as_str().into(), value.into());
        write_private_json(&self.root.join("credentials.json"), &credentials)
    }

    pub fn delete_credential(&self, kind: ProviderKind) -> Result<()> {
        let mut credentials = self.load_credentials()?;
        if credentials.providers.remove(kind.as_str()).is_some() {
            write_private_json(&self.root.join("credentials.json"), &credentials)?;
        }
        Ok(())
    }

    /// The single resolver for a request snapshot. A local key is returned
    /// only when the snapshot endpoint is the endpoint its profile is bound to.
    pub fn credential_for(&self, provider: &ProviderSettings) -> Result<CredentialState> {
        if provider.kind != ProviderKind::Local {
            return Ok(match self.credential(provider.kind)? {
                Some(credential) => CredentialState::Present(credential),
                None => CredentialState::Missing,
            });
        }
        let Some(local) = &provider.local else {
            bail!("Профиль local повреждён: нет параметров local");
        };
        let settings = self.load()?;
        let Some(profile) = settings.local.profiles.get(&local.profile) else {
            // A deleted profile also deleted its key: a server that required
            // one cannot be used until the user chooses a profile again.
            if local.key_required {
                bail!(
                    "Профиль local «{}» удалён вместе с ключом, а его сервер требует ключ. Выберите профиль через /provider или --profile ИМЯ",
                    local.profile
                );
            }
            return Ok(CredentialState::NotRequired);
        };
        let key = self.local_credential(&local.profile)?;
        let same_endpoint = provider
            .base_url
            .as_deref()
            .and_then(crate::local::endpoint_identity)
            .is_some_and(|snapshot| {
                profile
                    .base_url
                    .as_deref()
                    .and_then(crate::local::endpoint_identity)
                    == Some(snapshot)
            });
        if !same_endpoint {
            if key.is_some() || profile.local.as_ref().is_some_and(|l| l.key_required) {
                bail!(
                    "Адрес профиля local «{}» изменился или задан вручную; его ключ не отправляется на другой адрес. Выберите профиль заново через /provider или --profile {}",
                    local.profile,
                    local.profile
                );
            }
            return Ok(CredentialState::NotRequired);
        }
        Ok(match key {
            Some(credential) => CredentialState::Present(credential),
            None if profile.local.as_ref().is_some_and(|l| l.key_required) => {
                CredentialState::Missing
            }
            None => CredentialState::NotRequired,
        })
    }

    pub fn local_credential(&self, profile: &str) -> Result<Option<Credential>> {
        crate::local::validate_profile_name(profile)?;
        self.load_credentials()?
            .providers
            .get(&format!("{}{profile}", crate::local::CREDENTIAL_PREFIX))
            .map(|value| {
                crate::local::validate_key(value).with_context(|| {
                    format!("Сохранённый ключ профиля {profile} не подходит; сохраните его заново: rcode local key {profile} --stdin")
                })?;
                Ok(Credential {
                    value: value.clone(),
                    source: "credentials.json".into(),
                })
            })
            .transpose()
    }

    pub fn save_local_credential(&self, profile: &str, value: &str) -> Result<()> {
        crate::local::validate_profile_name(profile)?;
        crate::local::validate_key(value)?;
        let _lock = lock_state_file(&self.root.join("credentials.lock"))?;
        let mut credentials = self.load_credentials()?;
        credentials.providers.insert(
            format!("{}{profile}", crate::local::CREDENTIAL_PREFIX),
            value.into(),
        );
        write_private_json(&self.root.join("credentials.json"), &credentials)
    }

    pub fn delete_local_credential(&self, profile: &str) -> Result<()> {
        crate::local::validate_profile_name(profile)?;
        let _lock = lock_state_file(&self.root.join("credentials.lock"))?;
        let mut credentials = self.load_credentials()?;
        if credentials
            .providers
            .remove(&format!("{}{profile}", crate::local::CREDENTIAL_PREFIX))
            .is_some()
        {
            write_private_json(&self.root.join("credentials.json"), &credentials)?;
        }
        Ok(())
    }

    /// Removes a profile together with its key; the active choice is cleared.
    pub fn remove_local_profile(&self, settings: &mut Settings, profile: &str) -> Result<()> {
        crate::local::validate_profile_name(profile)?;
        if settings.local.profiles.remove(profile).is_none() {
            bail!("Профиль local «{profile}» не найден");
        }
        if settings.local.active.as_deref() == Some(profile) {
            settings.local.active = None;
        }
        self.delete_local_credential(profile)?;
        self.save(settings)
    }

    fn load_credentials(&self) -> Result<Credentials> {
        ensure_directory(&self.root)?;
        let credentials = read_json::<Credentials>(&self.root.join("credentials.json"), "ключей")?
            .unwrap_or_default();
        check_version(credentials.version, "ключей")?;
        Ok(credentials)
    }
}

fn credential_from_env(
    kind: ProviderKind,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<Option<Credential>> {
    let names: &[&str] = match kind {
        ProviderKind::Yandex => &["RCODE_YANDEX_API_KEY", "YANDEX_API_KEY"],
        ProviderKind::GigaChat => &[
            "RCODE_GIGACHAT_AUTH_KEY",
            "GIGACHAT_AUTH_KEY",
            "GIGACHAT_CREDENTIALS",
        ],
        ProviderKind::OpenRouter => &["RCODE_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"],
        ProviderKind::Custom => &["RCODE_CUSTOM_API_KEY", "OPENAI_API_KEY"],
        // Generic and cloud env keys must never reach a local server.
        ProviderKind::Local => &[],
    };
    for name in names {
        if let Some(value) = lookup(name) {
            validate_credential(&value)
                .with_context(|| format!("Некорректный ключ в переменной {name}"))?;
            return Ok(Some(Credential {
                value,
                source: format!("env:{name}"),
            }));
        }
    }
    Ok(None)
}

pub(crate) fn validate_credential(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        bail!("Ключ должен быть непустым и не содержать управляющих символов");
    }
    Ok(())
}

fn check_version(version: u32, kind: &str) -> Result<()> {
    if version != FORMAT_VERSION {
        bail!("Неподдерживаемая версия файла {kind}: {version} (ожидается {FORMAT_VERSION})");
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("Не удалось проверить каталог приложения")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Каталог приложения должен быть обычным каталогом, а не symlink");
    }
    Ok(())
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return ensure_directory(path),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Не удалось проверить каталог приложения"),
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && !parent.exists()
    {
        ensure_private_directory(parent)?;
    }
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(path) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .context("Не удалось установить права каталога приложения")?;
            }
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => ensure_directory(path),
        Err(error) => Err(error).context("Не удалось создать каталог приложения"),
    }
}

pub(crate) fn lock_state_file(path: &Path) -> Result<fs::File> {
    ensure_private_directory(path.parent().context("Нет каталога файла состояния")?)?;
    check_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("Не удалось открыть блокировку файла состояния")?;
    if !file.metadata()?.is_file() {
        bail!("Блокировка должна быть обычным файлом");
    }
    // Several rcode processes may serialize durable writes on a busy disk.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(file),
            Err(error)
                if error.kind() == fs2::lock_contended_error().kind()
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => {
                return Err(error).context("Файл состояния занят другим процессом или недоступен");
            }
        }
    }
}

pub(crate) fn check_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("Файл состояния должен быть обычным файлом, а не symlink");
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("Не удалось проверить файл состояния"),
    }
}

fn read_json<T: DeserializeOwned>(path: &Path, kind: &str) -> Result<Option<T>> {
    if !check_file(path)? {
        return Ok(None);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .context("Не удалось открыть файл состояния")?;
    serde_json::from_reader(file).map(Some).map_err(|error| {
        anyhow::anyhow!(
            "Некорректный JSON файла {kind}: строка {}, столбец {}",
            error.line(),
            error.column()
        )
    })
}

/// Atomically replaces an application-owned JSON file with a private (0600 on Unix) file.
/// Existing parent directories keep their permissions; symlink destinations are refused.
pub fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| anyhow::anyhow!("Не удалось сериализовать файл состояния"))?;
    bytes.push(b'\n');
    write_private_bytes(path, &bytes)
}

pub(crate) fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_directory(parent)?;
    check_file(path)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("Не удалось создать временный файл состояния")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("Не удалось установить права файла состояния")?;
    }
    temporary
        .write_all(bytes)
        .context("Не удалось записать файл состояния")?;
    temporary
        .as_file()
        .sync_all()
        .context("Не удалось синхронизировать файл состояния")?;
    // Recheck immediately before replacement; rename does not follow a destination symlink.
    check_file(path)?;
    temporary
        .persist(path)
        .map_err(|error| anyhow::anyhow!("Не удалось заменить файл состояния: {}", error.error))?;
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("Не удалось синхронизировать каталог состояния")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, fs};

    #[test]
    fn state_lock_waits_for_a_slow_writer_without_losing_exclusion() {
        use std::{sync::mpsc, time::Duration};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.lock");
        let first = lock_state_file(&path).unwrap();
        let (started, ready) = mpsc::channel();
        let (finished, result) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            let lock = lock_state_file(&path);
            finished.send(lock.is_ok()).unwrap();
            lock.unwrap()
        });
        ready.recv().unwrap();
        // A competing process can spend more than 500 ms flushing its state.
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(650)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        assert!(result.recv_timeout(Duration::from_secs(3)).unwrap());
        drop(worker.join().unwrap());
    }
    #[test]
    fn project_permissions_round_trip_and_legacy_defaults_do_not_enable_full_access_globally() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let store = ConfigStore::at(temp.path().join("state")).unwrap();
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"version":1,"active":"custom","providers":{}}),
        )
        .unwrap();
        store.save(&settings).unwrap();
        assert_eq!(store.permissions_for(&first).unwrap(), ApprovalMode::Ask);
        store
            .save_permissions(&first, ApprovalMode::FullAccess)
            .unwrap();
        let loaded = ConfigStore::at(store.root()).unwrap();
        assert_eq!(
            loaded.permissions_for(&first).unwrap(),
            ApprovalMode::FullAccess
        );
        assert_eq!(loaded.permissions_for(&second).unwrap(), ApprovalMode::Ask);
        use clap::Parser;
        let default = crate::cli::Cli::parse_from(["rcode"]);
        assert_eq!(
            default.for_project(ApprovalMode::FullAccess).permissions(),
            ApprovalMode::FullAccess
        );
        let explicit = crate::cli::Cli::parse_from(["rcode", "--approval-mode", "ask"]);
        assert_eq!(
            explicit.for_project(ApprovalMode::FullAccess).permissions(),
            ApprovalMode::Ask
        );
    }

    #[test]
    fn saving_an_older_provider_snapshot_does_not_restore_revoked_full_access() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let store = ConfigStore::at(temp.path().join("state")).unwrap();
        store.save(&Settings::default()).unwrap();
        store
            .save_permissions(&root, ApprovalMode::FullAccess)
            .unwrap();
        let stale = store.load().unwrap();
        store.save_permissions(&root, ApprovalMode::Ask).unwrap();
        store.save(&stale).unwrap();
        assert_eq!(store.permissions_for(&root).unwrap(), ApprovalMode::Ask);
    }

    #[test]
    fn explicit_effort_survives_config_round_trip_and_defaults_are_omitted() {
        let settings: ProviderSettings = serde_json::from_value(serde_json::json!({
            "kind": "openrouter", "model": "reasoning-model", "effort": "high"
        }))
        .unwrap();
        assert_eq!(serde_json::to_value(&settings).unwrap()["effort"], "high");
        let legacy: ProviderSettings = serde_json::from_value(serde_json::json!({
            "kind": "openrouter", "model": "legacy-model"
        }))
        .unwrap();
        assert!(
            serde_json::to_value(&legacy)
                .unwrap()
                .get("effort")
                .is_none()
        );
        assert_eq!(legacy.effort, Effort::Auto);
        for (effort, name) in Effort::all().into_iter().zip([
            "auto", "none", "minimal", "low", "medium", "high", "xhigh", "max",
        ]) {
            assert_eq!(effort.as_str(), name);
            assert_eq!(effort.to_string(), name);
            assert_eq!(name.parse::<Effort>().unwrap(), effort);
            assert_eq!(serde_json::to_value(effort).unwrap(), name);
        }
        assert!("HIGH".parse::<Effort>().is_err());
        assert!("unknown".parse::<Effort>().is_err());
        assert!(
            serde_json::from_value::<ProviderSettings>(serde_json::json!({
                "kind":"openrouter", "model":"reasoning-model", "effort":"unknown"
            }))
            .is_err()
        );
    }

    #[test]
    fn provider_validation_rejects_effort_outside_documented_baseline() {
        for kind in [ProviderKind::Yandex, ProviderKind::GigaChat] {
            for effort in [
                "auto", "low", "medium", "high", "none", "minimal", "xhigh", "max",
            ] {
                let mut value = serde_json::to_value(ProviderSettings::new(kind)).unwrap();
                value["folder_id"] = serde_json::json!("folder");
                value["effort"] = serde_json::json!(effort);
                let settings: ProviderSettings = serde_json::from_value(value).unwrap();
                assert_eq!(
                    settings.validate().is_ok(),
                    matches!(effort, "auto" | "low" | "medium" | "high"),
                    "{kind} accepted unsupported effort {effort}"
                );
            }
        }
        for kind in [ProviderKind::OpenRouter, ProviderKind::Custom] {
            for effort in Effort::all() {
                let mut settings = ProviderSettings::new(kind);
                settings.effort = effort;
                settings.validate().unwrap();
            }
        }
    }

    #[test]
    fn provider_kinds_and_defaults_are_stable() {
        let names = ["yandex", "gigachat", "openrouter", "custom"];
        for (kind, name) in ProviderKind::all().into_iter().zip(names) {
            assert_eq!(kind.as_str(), name);
            assert_eq!(kind.to_string(), name);
            assert_eq!(name.parse::<ProviderKind>().unwrap(), kind);
            let settings = ProviderSettings::new(kind);
            assert_eq!(settings.kind, kind);
            assert!(settings.stream);
            assert_eq!(settings.max_output_tokens, 4096);
            assert_eq!(settings.request_timeout_secs, 300);
            assert_eq!(settings.idle_timeout_secs, 90);
        }
        assert!("unknown".parse::<ProviderKind>().is_err());
        assert_eq!(
            ProviderSettings::new(ProviderKind::Yandex).model,
            "deepseek-v4.1-flash/latest"
        );
        assert_eq!(
            ProviderSettings::new(ProviderKind::Yandex)
                .base_url
                .as_deref(),
            Some("https://ai.api.cloud.yandex.net/v1")
        );
        assert_eq!(
            ProviderSettings::new(ProviderKind::GigaChat).model,
            "GigaChat"
        );
        assert_eq!(
            ProviderSettings::new(ProviderKind::GigaChat)
                .base_url
                .as_deref(),
            Some("https://api.giga.chat/v1")
        );
        assert_eq!(
            ProviderSettings::new(ProviderKind::OpenRouter).model,
            "z-ai/glm-5.3-flash"
        );
        assert_eq!(
            ProviderSettings::new(ProviderKind::Custom)
                .base_url
                .as_deref(),
            Some("http://localhost:11434/v1")
        );
    }

    #[test]
    fn provider_validation_enforces_safe_urls_and_yandex_folder() {
        let mut settings = ProviderSettings::new(ProviderKind::Custom);
        for endpoint in [
            "https://example.com/v1",
            "http://localhost:8080/v1",
            "http://127.0.0.2/v1",
            "http://[::1]/v1",
        ] {
            settings.base_url = Some(endpoint.into());
            settings.validate().unwrap();
        }
        for endpoint in [
            "http://example.com/v1",
            "http://localhost.evil/v1",
            "ftp://127.0.0.1/v1",
            "https://user:secret@example.com/v1",
            "https://@example.com/v1",
            "https://example.com/v1?key=secret",
            "https://example.com/v1#secret",
            "https://example.com/\n",
        ] {
            settings.base_url = Some(endpoint.into());
            assert!(settings.validate().is_err(), "accepted an unsafe endpoint");
        }
        settings.base_url = None;
        settings.auth_url = Some("http://example.com/oauth".into());
        assert!(settings.validate().is_err());

        let mut yandex = ProviderSettings::new(ProviderKind::Yandex);
        assert!(yandex.validate().is_err());
        yandex.folder_id = Some("folder-id".into());
        yandex.validate().unwrap();
        yandex.folder_id = None;
        yandex.model = "gpt://folder-id/yandexgpt/latest".into();
        yandex.validate().unwrap();
        yandex.model = "gpt://folder-id".into();
        assert!(yandex.validate().is_err());
    }

    #[test]
    fn optional_settings_deserialize_with_defaults() {
        let settings: ProviderSettings =
            serde_json::from_str(r#"{"kind":"openrouter","model":"model"}"#).unwrap();
        assert!(settings.base_url.is_none());
        assert!(settings.folder_id.is_none());
        assert!(settings.auth_url.is_none());
        assert!(settings.scope.is_none());
        assert!(settings.ca_file.is_none());
        assert!(settings.stream);
        assert_eq!(settings.max_output_tokens, 4096);
        assert_eq!(settings.idle_timeout_secs, 90);
        assert_eq!(
            serde_json::to_value(&settings).unwrap()["request_timeout_secs"],
            300
        );
        let mut settings = Settings::default();
        assert_eq!(settings.version, 1);
        assert_eq!(settings.active, ProviderKind::Yandex);
        assert_eq!(settings.providers.len(), 4);
        settings.providers.remove("openrouter");
        assert_eq!(
            settings.provider(ProviderKind::OpenRouter).kind,
            ProviderKind::OpenRouter
        );
    }

    #[test]
    fn request_timeout_defaults_are_backward_compatible_and_explicit_limits_are_validated() {
        let legacy: ProviderSettings = serde_json::from_value(serde_json::json!({
            "kind":"gigachat", "model":"GigaChat-3-Ultra", "idle_timeout_secs":90
        }))
        .unwrap();
        let value = serde_json::to_value(&legacy).unwrap();
        assert_eq!(value["request_timeout_secs"], 300);
        assert_eq!(value["idle_timeout_secs"], 90);
        for seconds in [0, 1, 7] {
            let mut value = value.clone();
            value["request_timeout_secs"] = serde_json::json!(seconds);
            let settings: ProviderSettings = serde_json::from_value(value).unwrap();
            assert_eq!(settings.validate().is_ok(), seconds > 0);
            assert_eq!(
                serde_json::to_value(&settings).unwrap()["request_timeout_secs"],
                seconds
            );
        }
    }

    #[test]
    fn settings_round_trip_and_corruption_are_explicit() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        assert_eq!(store.root(), temp.path().join("rcode"));
        assert_eq!(store.sessions_dir(), store.root().join("sessions"));
        assert!(!store.exists());
        assert_eq!(store.load().unwrap().version, 1);
        let mut settings = Settings {
            active: ProviderKind::Custom,
            ..Settings::default()
        };
        store.save(&settings).unwrap();
        assert!(store.exists());
        assert_eq!(store.load().unwrap().active, ProviderKind::Custom);
        fs::write(store.root().join("config.json"), b"broken-json").unwrap();
        assert!(store.load().is_err());
        fs::write(
            store.root().join("config.json"),
            br#"{"version":99,"active":"custom","providers":{}}"#,
        )
        .unwrap();
        assert!(store.load().unwrap_err().to_string().contains("99"));
        settings.version = 99;
        assert!(store.save(&settings).is_err());
    }

    #[test]
    fn credential_resolution_is_provider_specific_and_ordered() {
        let env: BTreeMap<String, String> = [
            ("RCODE_OPENROUTER_API_KEY", "rcode-router"),
            ("OPENROUTER_API_KEY", "router"),
            ("RCODE_YANDEX_API_KEY", "rcode-yandex"),
            ("YANDEX_API_KEY", "yandex"),
            ("RCODE_GIGACHAT_AUTH_KEY", "rcode-giga"),
            ("GIGACHAT_AUTH_KEY", "giga"),
            ("GIGACHAT_CREDENTIALS", "giga-legacy"),
            ("RCODE_CUSTOM_API_KEY", "rcode-custom"),
            ("OPENAI_API_KEY", "openai"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
        for (kind, expected) in [
            (ProviderKind::OpenRouter, "rcode-router"),
            (ProviderKind::Yandex, "rcode-yandex"),
            (ProviderKind::GigaChat, "rcode-giga"),
            (ProviderKind::Custom, "rcode-custom"),
        ] {
            let credential = credential_from_env(kind, |name| env.get(name).cloned())
                .unwrap()
                .unwrap();
            assert_eq!(credential.value, expected);
            assert!(credential.source.starts_with("env:"));
        }
        for (kind, var, expected) in [
            (ProviderKind::OpenRouter, "OPENROUTER_API_KEY", "router"),
            (ProviderKind::Yandex, "YANDEX_API_KEY", "yandex"),
            (ProviderKind::GigaChat, "GIGACHAT_AUTH_KEY", "giga"),
            (
                ProviderKind::GigaChat,
                "GIGACHAT_CREDENTIALS",
                "giga-legacy",
            ),
            (ProviderKind::Custom, "OPENAI_API_KEY", "openai"),
        ] {
            let credential =
                credential_from_env(kind, |name| (name == var).then(|| env[name].clone()))
                    .unwrap()
                    .unwrap();
            assert_eq!(credential.value, expected);
        }
        for kind in [
            ProviderKind::Yandex,
            ProviderKind::GigaChat,
            ProviderKind::OpenRouter,
        ] {
            assert!(
                credential_from_env(kind, |name| (name == "OPENAI_API_KEY")
                    .then(|| "generic-secret".into()))
                .unwrap()
                .is_none()
            );
        }
        assert!(credential_from_env(ProviderKind::Custom, |_| Some("\nsecret".into())).is_err());
    }

    #[test]
    fn public_store_uses_rcode_home_and_provider_env_without_global_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("portable-rcode");
        let store = ConfigStore::at(&root).unwrap();
        store
            .save_credential(ProviderKind::Yandex, "stored-yandex")
            .unwrap();
        store
            .save_credential(ProviderKind::OpenRouter, "stored-router")
            .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::tests::isolated_environment_entrypoint",
                "--ignored",
            ])
            .env_clear()
            .env("RCODE_HOME", &root)
            .env("RCODE_CONFIG_TEST_CHILD", "1")
            .env("OPENAI_API_KEY", "custom-env")
            .env("OPENROUTER_API_KEY", "router-env")
            .env("RCODE_OPENROUTER_API_KEY", "rcode-router-env")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated credential process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "entrypoint for a test process with an isolated environment"]
    fn isolated_environment_entrypoint() {
        assert_eq!(std::env::var("RCODE_CONFIG_TEST_CHILD").unwrap(), "1");
        let store = ConfigStore::new().unwrap();
        assert_eq!(
            store.root(),
            Path::new(&std::env::var_os("RCODE_HOME").unwrap())
        );
        assert_eq!(
            store
                .credential(ProviderKind::OpenRouter)
                .unwrap()
                .unwrap()
                .value,
            "rcode-router-env"
        );
        assert_eq!(
            store
                .credential(ProviderKind::Custom)
                .unwrap()
                .unwrap()
                .value,
            "custom-env"
        );
        let yandex = store.credential(ProviderKind::Yandex).unwrap().unwrap();
        assert_eq!(yandex.value, "stored-yandex");
        assert_eq!(yandex.source, "credentials.json");
        assert!(store.credential(ProviderKind::GigaChat).unwrap().is_none());
        // Local profiles never inherit OPENAI_API_KEY or another env key, and
        // a stored local key never becomes the custom key.
        let mut settings = store.load().unwrap();
        let profile = crate::local::profile_settings(
            "isolated",
            "http://127.0.0.1:8080/v1",
            crate::local::LocalRuntime::LlamaCpp,
            "m",
        );
        settings.remember_provider(&profile);
        store.save(&settings).unwrap();
        assert!(matches!(
            store.credential_for(&profile).unwrap(),
            CredentialState::NotRequired
        ));
        store
            .save_local_credential("isolated", "isolated-local-key")
            .unwrap();
        assert!(
            store
                .credential(ProviderKind::Custom)
                .unwrap()
                .unwrap()
                .value
                == "custom-env",
            "custom must keep its env key"
        );
        assert!(
            matches!(store.credential_for(&profile).unwrap(), CredentialState::Present(c) if c.value == "isolated-local-key")
        );
        let router = ProviderSettings::new(ProviderKind::GigaChat);
        assert!(matches!(
            store.credential_for(&router).unwrap(),
            CredentialState::Missing
        ));
    }

    #[test]
    fn credentials_are_separate_validated_and_redacted() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let secret = "a-secret-never-log-this";
        store.save(&Settings::default()).unwrap();
        store
            .save_credential(ProviderKind::OpenRouter, secret)
            .unwrap();
        assert!(
            !fs::read_to_string(store.root().join("config.json"))
                .unwrap()
                .contains(secret)
        );
        let saved = store.load_credentials().unwrap();
        assert_eq!(saved.providers.get("openrouter").unwrap(), secret);
        let credential = Credential {
            value: secret.into(),
            source: "credentials.json".into(),
        };
        assert!(!format!("{credential:?}").contains(secret));
        for invalid in ["", "   ", "secret\nsecond", "secret\rsecond"] {
            let error = store
                .save_credential(ProviderKind::OpenRouter, invalid)
                .unwrap_err();
            assert!(!error.to_string().contains("second"));
        }
        store.delete_credential(ProviderKind::OpenRouter).unwrap();
        assert!(
            !store
                .load_credentials()
                .unwrap()
                .providers
                .contains_key("openrouter")
        );
        store.delete_credential(ProviderKind::OpenRouter).unwrap();
        fs::write(
            store.root().join("credentials.json"),
            br#"{"version":1,"providers":{"custom":1234567890}}"#,
        )
        .unwrap();
        let error = store.load_credentials().unwrap_err();
        assert!(!error.to_string().contains("1234567890"));
    }

    #[test]
    fn failed_serialization_does_not_replace_existing_json() {
        struct CannotSerialize;
        impl serde::Serialize for CannotSerialize {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("serialization failed"))
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        write_private_json(&path, &serde_json::json!({"before":true})).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(write_private_json(&path, &CannotSerialize).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn writes_are_private_without_changing_existing_parent_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        store.save(&Settings::default()).unwrap();
        store
            .save_credential(ProviderKind::Custom, "private-key")
            .unwrap();
        for directory in [store.root().to_path_buf(), store.sessions_dir()] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for file in ["config.json", "credentials.json"] {
            assert_eq!(
                fs::metadata(store.root().join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_store_refuses_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"do not touch").unwrap();
        symlink(&outside, store.root().join("credentials.json")).unwrap();
        assert!(store.load_credentials().is_err());
        assert!(store.save_credential(ProviderKind::Custom, "key").is_err());
        assert!(store.delete_credential(ProviderKind::Custom).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"do not touch");
        let linked_root = temp.path().join("linked-root");
        symlink(store.root(), &linked_root).unwrap();
        assert!(ConfigStore::at(linked_root).is_err());
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::local::{LocalRuntime, LocalSettings};

    fn local_profile(name: &str, base_url: &str) -> ProviderSettings {
        crate::local::profile_settings(name, base_url, LocalRuntime::Ollama, "qwen3:8b")
    }

    #[test]
    fn local_kind_round_trips_and_all_has_five() {
        assert_eq!(ProviderKind::all().len(), 5);
        assert_eq!(ProviderKind::Local.as_str(), "local");
        assert_eq!(
            "local".parse::<ProviderKind>().unwrap(),
            ProviderKind::Local
        );
        assert_eq!(
            serde_json::to_value(ProviderKind::Local).unwrap(),
            serde_json::json!("local")
        );
        let defaults = Settings::default();
        assert!(!defaults.providers.contains_key("local"));
        let value = serde_json::to_value(&defaults).unwrap();
        assert!(
            value.get("local").is_none(),
            "empty profiles are not written"
        );
    }

    #[test]
    fn old_config_without_local_loads_and_saves_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let legacy = serde_json::json!({
            "version": 1,
            "active": "openrouter",
            "providers": {
                "openrouter": {"kind":"openrouter","model":"z-ai/glm-5.3-flash","base_url":"https://openrouter.ai/api/v1","folder_id":null,"auth_url":null,"scope":null,"ca_file":null,"stream":true,"max_output_tokens":4096,"request_timeout_secs":300,"idle_timeout_secs":90},
                "custom": {"kind":"custom","model":"local","base_url":"http://localhost:11434/v1","folder_id":null,"auth_url":null,"scope":null,"ca_file":null,"stream":true,"max_output_tokens":4096,"request_timeout_secs":300,"idle_timeout_secs":90}
            }
        });
        fs::write(
            store.root().join("config.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let settings = store.load().unwrap();
        assert!(settings.local.is_empty());
        store.save(&settings).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(store.root().join("config.json")).unwrap()).unwrap();
        assert_eq!(saved, legacy);
    }

    #[test]
    fn local_profiles_round_trip_with_active() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let mut settings = Settings::default();
        settings.remember_provider(&local_profile("qwen-mlx", "http://127.0.0.1:8080/v1"));
        settings.remember_provider(&local_profile("ollama", "http://127.0.0.1:11434/v1"));
        assert_eq!(settings.active, ProviderKind::Local);
        assert_eq!(settings.local.active.as_deref(), Some("ollama"));
        settings.local.active = Some("qwen-mlx".into());
        store.save(&settings).unwrap();
        let loaded = ConfigStore::at(store.root()).unwrap().load().unwrap();
        assert_eq!(loaded.active, ProviderKind::Local);
        let active = loaded.provider(ProviderKind::Local);
        assert_eq!(active.base_url.as_deref(), Some("http://127.0.0.1:8080/v1"));
        assert_eq!(active.local.as_ref().unwrap().profile, "qwen-mlx");
        assert!(!loaded.providers.contains_key("local"));
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(store.root().join("config.json")).unwrap()).unwrap();
        assert_eq!(raw["local"]["active"], "qwen-mlx");
        assert_eq!(
            raw["local"]["profiles"]["qwen-mlx"]["local"]["runtime"],
            "ollama"
        );
        assert!(raw["providers"]["openrouter"].get("local").is_none());
    }

    #[test]
    fn local_without_profiles_is_an_unsaved_invalid_draft() {
        let settings = Settings::default();
        let draft = settings.provider(ProviderKind::Local);
        assert_eq!(draft.kind, ProviderKind::Local);
        assert!(draft.local.is_some());
        assert!(draft.validate().is_err(), "a draft needs a model");
        assert!(
            serde_json::to_value(&settings)
                .unwrap()
                .get("local")
                .is_none()
        );
    }

    #[test]
    fn local_validate_rejects_non_loopback_and_userinfo() {
        for url in [
            "http://192.168.1.10:8080/v1",
            "https://example.com/v1",
            "http://example.com/v1",
            "http://user@127.0.0.1:8080/v1",
            "http://user:pw@localhost:8080/v1",
            "http://127.0.0.1:8080/v1?key=x",
            "http://localhost.evil/v1",
            "http://[::ffff:127.0.0.1]:8080/v1",
            "ftp://127.0.0.1/v1",
        ] {
            let profile = local_profile("p", url);
            let error = profile.validate().unwrap_err().to_string();
            assert!(
                error.contains("127.0.0.1") || error.contains("URL"),
                "{url}: {error}"
            );
        }
        let mut missing = local_profile("p", "http://127.0.0.1:8080/v1");
        missing.base_url = None;
        assert!(missing.validate().is_err());
        let mut wrong = local_profile("p", "http://127.0.0.1:8080/v1");
        wrong.local = None;
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn local_validate_accepts_localhost_127_x_ipv6() {
        for url in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:8080/v1",
            "http://127.0.0.2:1234/v1",
            "http://[::1]:8080/v1",
            "https://localhost:8443/v1",
        ] {
            local_profile("p", url).validate().unwrap();
        }
    }

    #[test]
    fn local_effort_must_be_auto() {
        for effort in Effort::all() {
            let mut profile = local_profile("p", "http://127.0.0.1:8080/v1");
            profile.effort = effort;
            assert_eq!(
                profile.validate().is_ok(),
                effort == Effort::Auto,
                "{effort}"
            );
        }
    }

    #[test]
    fn local_output_cap_8192_and_quarter_ctx() {
        let mut profile = local_profile("p", "http://127.0.0.1:8080/v1");
        assert_eq!(profile.max_output_tokens, 4096);
        assert_eq!(profile.request_timeout_secs, 600);
        assert_eq!(profile.idle_timeout_secs, 180);
        assert_eq!(profile.local.as_ref().unwrap().context_tokens, 32_768);
        profile.max_output_tokens = 8192;
        profile.validate().unwrap();
        profile.max_output_tokens = 8193;
        assert!(profile.validate().is_err());
        profile.local.as_mut().unwrap().context_tokens = 16_384;
        profile.max_output_tokens = 4096;
        profile.validate().unwrap();
        profile.max_output_tokens = 4097;
        assert!(profile.validate().is_err());
        profile.max_output_tokens = 1024;
        profile.local.as_mut().unwrap().context_tokens = 1024;
        assert!(profile.validate().is_err(), "context below the minimum");
    }

    #[test]
    fn profile_name_rules() {
        for name in ["a", "qwen-mlx", "ollama.2", "x_y", "0abc", &"a".repeat(32)] {
            crate::local::validate_profile_name(name).unwrap();
        }
        for name in [
            "",
            "-a",
            ".a",
            "A",
            "имя",
            "a b",
            "a/b",
            "a:b",
            &"a".repeat(33),
        ] {
            assert!(crate::local::validate_profile_name(name).is_err(), "{name}");
        }
        let mut profile = local_profile("Bad Name", "http://127.0.0.1:8080/v1");
        assert!(profile.validate().is_err());
        profile.local = Some(LocalSettings {
            profile: "ok".into(),
            ..profile.local.clone().unwrap()
        });
        profile.validate().unwrap();
    }

    #[test]
    fn cloud_kinds_cannot_carry_local_settings() {
        let mut custom = ProviderSettings::new(ProviderKind::Custom);
        custom.local = local_profile("p", "http://127.0.0.1:8080/v1").local;
        assert!(custom.validate().is_err());
    }

    #[test]
    fn local_credential_never_reads_env() {
        let env: BTreeMap<&str, &str> = [
            ("OPENAI_API_KEY", "generic-secret"),
            ("RCODE_CUSTOM_API_KEY", "custom-secret"),
            ("RCODE_LOCAL_API_KEY", "local-env-secret"),
        ]
        .into_iter()
        .collect();
        assert!(
            credential_from_env(ProviderKind::Local, |name| env
                .get(name)
                .map(|v| (*v).into()))
            .unwrap()
            .is_none()
        );
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let mut settings = Settings::default();
        let profile = local_profile("noauth", "http://127.0.0.1:8080/v1");
        settings.remember_provider(&profile);
        store.save(&settings).unwrap();
        assert!(store.credential(ProviderKind::Local).unwrap().is_none());
        assert!(matches!(
            store.credential_for(&profile).unwrap(),
            CredentialState::NotRequired
        ));
    }

    #[test]
    fn local_key_stored_under_profile_and_deleted_with_profile() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let mut settings = Settings::default();
        let first = local_profile("first", "http://127.0.0.1:8080/v1");
        let second = local_profile("second", "http://localhost:8080/v1");
        settings.remember_provider(&first);
        settings.remember_provider(&second);
        store.save(&settings).unwrap();
        store
            .save_local_credential("first", "first-secret-key")
            .unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(store.root().join("credentials.json")).unwrap())
                .unwrap();
        assert_eq!(raw["providers"]["local:first"], "first-secret-key");
        assert!(raw["providers"].get("local").is_none());
        match store.credential_for(&first).unwrap() {
            CredentialState::Present(credential) => {
                assert_eq!(credential.value, "first-secret-key");
                assert_eq!(credential.source, "credentials.json");
            }
            _ => panic!("profile key expected"),
        }
        assert!(matches!(
            store.credential_for(&second).unwrap(),
            CredentialState::NotRequired
        ));
        // Cloud kinds never see a local profile key (env-independent check;
        // the isolated child process covers resolution with a cleared env).
        assert!(!raw["providers"].as_object().unwrap().contains_key("custom"));
        assert!(store.credential(ProviderKind::Local).unwrap().is_none());
        store.remove_local_profile(&mut settings, "first").unwrap();
        assert!(!settings.local.profiles.contains_key("first"));
        assert!(store.local_credential("first").unwrap().is_none());
        assert!(
            ConfigStore::at(store.root())
                .unwrap()
                .load()
                .unwrap()
                .local
                .profiles
                .contains_key("second")
        );
    }

    #[test]
    fn local_credentials_and_settings_never_use_unscoped_local_entries() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        assert!(
            store
                .save_credential(ProviderKind::Local, "orphan-local-key")
                .is_err()
        );
        assert!(store.save_local_credential("box", "short").is_err());
        let mut settings = Settings::default();
        let mut broken = ProviderSettings::new(ProviderKind::Local);
        broken.local = None;
        settings.remember_provider(&broken);
        assert!(!settings.providers.contains_key("local"));
        assert_eq!(settings.active, ProviderKind::Yandex);
        assert!(
            !fs::read_to_string(store.root().join("credentials.json"))
                .unwrap_or_default()
                .contains("orphan-local-key")
        );
    }

    #[test]
    fn deleted_profile_snapshot_works_without_key_and_fails_when_key_was_required() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let mut settings = Settings::default();
        let open = local_profile("open", "http://127.0.0.1:8080/v1");
        let mut keyed = local_profile("keyed", "http://127.0.0.1:8081/v1");
        keyed.local.as_mut().unwrap().key_required = true;
        settings.remember_provider(&open);
        settings.remember_provider(&keyed);
        store.save(&settings).unwrap();
        store
            .save_local_credential("keyed", "keyed-secret-value")
            .unwrap();
        store.remove_local_profile(&mut settings, "open").unwrap();
        store.remove_local_profile(&mut settings, "keyed").unwrap();
        // Session snapshots outlive their profiles.
        assert!(matches!(
            store.credential_for(&open).unwrap(),
            CredentialState::NotRequired
        ));
        let error = store.credential_for(&keyed).unwrap_err().to_string();
        assert!(error.contains("удалён"), "{error}");
        assert!(!error.contains("keyed-secret-value"));
    }

    #[test]
    fn local_key_is_bound_to_the_snapshot_endpoint() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let mut settings = Settings::default();
        let profile = local_profile("keyed", "http://127.0.0.1:8080/v1");
        settings.remember_provider(&profile);
        store.save(&settings).unwrap();
        store
            .save_local_credential("keyed", "keyed-secret")
            .unwrap();
        // Host aliases of the same loopback endpoint keep the key.
        let mut alias = profile.clone();
        alias.base_url = Some("http://localhost:8080/v1/".into());
        assert!(matches!(
            store.credential_for(&alias).unwrap(),
            CredentialState::Present(_)
        ));
        // A different port is a different server: never send the key there.
        let mut moved = profile.clone();
        moved.base_url = Some("http://127.0.0.1:9090/v1".into());
        let error = store.credential_for(&moved).unwrap_err().to_string();
        assert!(
            error.contains("/provider") || error.contains("--profile"),
            "{error}"
        );
        assert!(!error.contains("keyed-secret"));
        // A deleted profile has no key; a no-auth server still works.
        store.remove_local_profile(&mut settings, "keyed").unwrap();
        assert!(matches!(
            store.credential_for(&profile).unwrap(),
            CredentialState::NotRequired
        ));
    }

    #[test]
    fn key_required_profile_without_key_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        let mut settings = Settings::default();
        let mut profile = local_profile("needs-key", "http://127.0.0.1:8080/v1");
        profile.local.as_mut().unwrap().key_required = true;
        settings.remember_provider(&profile);
        store.save(&settings).unwrap();
        assert!(matches!(
            store.credential_for(&profile).unwrap(),
            CredentialState::Missing
        ));
    }

    #[test]
    fn custom_credential_unchanged() {
        // Values are never printed: developer environments may hold real keys.
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(temp.path().join("rcode")).unwrap();
        store
            .save_credential(ProviderKind::Custom, "custom-stored")
            .unwrap();
        let custom = ProviderSettings::new(ProviderKind::Custom);
        assert!(matches!(
            store.credential_for(&custom).unwrap(),
            CredentialState::Present(_)
        ));
    }
}
