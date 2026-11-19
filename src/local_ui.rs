//! Interactive choice of a local profile: saved profiles, discovery on the
//! fixed loopback ports, or a manual loopback address. Keys are asked only
//! when the server rejects an unauthenticated request.
use crate::{
    config::{ConfigStore, CredentialState, ProviderSettings, Settings},
    local::{LocalRuntime, endpoint_identity, profile_settings, validate_local_endpoint},
    local_runtime::{self, Discovered},
    protocol::{FailureKind, ModelInfo, ProviderFailure},
    provider::ProviderClient,
    terminal::{self, Choice},
    ui,
};
use anyhow::{Result, bail};

/// Short description used by the provider menu.
pub(crate) fn summary_with_secrets(
    settings: &Settings,
    store: &ConfigStore,
    extra_secrets: &[String],
) -> String {
    let Some(profile) = settings.local.active_profile() else {
        return if settings.local.profiles.is_empty() {
            "найти локальный сервер".into()
        } else {
            "выбрать профиль".into()
        };
    };
    profile_detail_with_secrets(profile, store, extra_secrets)
}

fn redact_ui_result(
    text: &str,
    secret_dict: &Result<Option<crate::redaction::SecretDictionary>>,
) -> String {
    if text.is_empty() {
        return String::new();
    }
    match secret_dict {
        Ok(None) => text.to_owned(),
        Ok(Some(dict)) => crate::redaction::redact_text_idempotent_with(dict, text)
            .unwrap_or_else(|_| "[скрыто]".into()),
        Err(_) => "[скрыто]".into(),
    }
}

fn profile_detail_with_secrets(
    profile: &ProviderSettings,
    store: &ConfigStore,
    extra_secrets: &[String],
) -> String {
    let secret_dict = crate::model_route::build_route_secret_dictionary(store, extra_secrets);
    let local = profile.local.as_ref();
    let raw_name = local.map_or("", |local| local.profile.as_str());
    let name = redact_ui_result(raw_name, &secret_dict);
    let raw_address = profile
        .base_url
        .as_deref()
        .and_then(|url| reqwest::Url::parse(url).ok())
        .map(|url| {
            format!(
                "{}:{}",
                url.host_str().unwrap_or_default(),
                url.port_or_known_default().unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let address = redact_ui_result(&raw_address, &secret_dict);
    let key = match store.local_credential(raw_name) {
        Ok(Some(_)) => "ключ сохранён",
        _ if local.is_some_and(|local| local.key_required) => "нужен ключ",
        _ => "без ключа",
    };
    let thinking = match local.and_then(|local| local.thinking) {
        Some(true) => " · thinking on",
        Some(false) => " · thinking off",
        None => "",
    };
    let clean_model = redact_ui_result(&profile.model, &secret_dict);
    format!(
        "профиль {name} · {} · {address} · {key}{}{thinking}",
        local.map_or("", |local| local.runtime.as_str()),
        if profile.model.is_empty() {
            String::new()
        } else {
            format!(" · {clean_model}")
        }
    )
}

fn choose(title: &str, choices: &[Choice], current: usize, rich: bool) -> Result<Option<usize>> {
    if rich && terminal::supported() {
        return terminal::select(title, choices, current);
    }
    let _suspended = crate::screen::suspend()?;
    eprintln!("\n{}", ui::safe(title));
    for (index, choice) in choices.iter().enumerate() {
        eprintln!(
            "  {}) {} · {}",
            index + 1,
            ui::safe(&choice.label),
            ui::safe(&choice.detail)
        );
    }
    loop {
        let answer = ui::line("Номер (0 — отмена)", &(current + 1).to_string())?;
        if answer == "0" {
            return Ok(None);
        }
        if let Some(index) = answer
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .filter(|index| choices.get(*index).is_some_and(|c| c.enabled))
        {
            return Ok(Some(index));
        }
        eprintln!("Выберите номер от 1 до {} или 0 для отмены", choices.len());
    }
}

fn resolve_local_ca(
    existing_ca: Option<&std::path::Path>,
    ca_override: Option<&std::path::Path>,
) -> Result<Option<std::path::PathBuf>> {
    if let Some(ca) = ca_override {
        return Ok(Some(crate::model_route::normalize_ca_path(ca)));
    }
    if existing_ca.is_some_and(|ca| !ca.is_absolute()) {
        let ca_input = ui::line(
            "Абсолютный путь к CA-файлу профиля local (пусто — сбросить на системный)",
            "",
        )?;
        let trimmed = ca_input.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let candidate = std::path::PathBuf::from(trimmed);
        if !candidate.is_absolute() {
            bail!("Путь к CA-файлу должен быть абсолютным");
        }
        return Ok(Some(crate::model_route::normalize_ca_path(&candidate)));
    }
    Ok(existing_ca.map(std::path::Path::to_path_buf))
}

/// Picks or creates a profile. A new profile is saved (not activated) so its
pub(crate) enum ChosenLocalProfile {
    Existing {
        profile: ProviderSettings,
        server_known_protected: bool,
    },
    DraftNew {
        profile: ProviderSettings,
        typed_key: Option<String>,
        auth_challenged: bool,
    },
}

pub(crate) struct CatalogConnectOutcome {
    pub(crate) models: Vec<ModelInfo>,
    pub(crate) newly_entered_key: Option<String>,
    pub(crate) verified_noauth: bool,
}

pub(crate) enum ConnectCatalogError {
    Fatal(anyhow::Error),
    Unreachable(anyhow::Error),
}

/// Picks an existing profile or constructs an unsaved draft for a newly
/// discovered/manual server. Nothing is written to `config.json` or
/// `credentials.json` until `/models` verification and model selection complete.
pub(crate) async fn choose_profile_choice_with_secrets(
    store: &ConfigStore,
    settings: &mut Settings,
    rich: bool,
    ca_override: Option<&std::path::Path>,
    extra_secrets: &[String],
) -> Result<Option<ChosenLocalProfile>> {
    // Another process may have added, moved or removed profiles meanwhile.
    settings.local = store.load()?.local;
    let mut names: Vec<String> = settings.local.profiles.keys().cloned().collect();
    if let Some(active) = &settings.local.active
        && let Some(index) = names.iter().position(|name| name == active)
    {
        names[..=index].rotate_right(1);
    }
    let secret_dict = crate::model_route::build_route_secret_dictionary(store, extra_secrets);
    let mut choices: Vec<Choice> = names
        .iter()
        .map(|name| Choice {
            label: redact_ui_result(name, &secret_dict),
            detail: profile_detail_with_secrets(
                &settings.local.profiles[name],
                store,
                extra_secrets,
            ),
            enabled: true,
        })
        .collect();
    choices.push(Choice {
        label: "Найти локальные серверы".into(),
        detail: "127.0.0.1: Ollama 11434, llama.cpp/MLX 8080, LM Studio 1234".into(),
        enabled: true,
    });
    choices.push(Choice {
        label: "Добавить адрес вручную".into(),
        detail: "OpenAI-совместимый сервер на 127.0.0.1, localhost или ::1".into(),
        enabled: true,
    });
    let Some(index) = choose("Локальная модель · профиль", &choices, 0, rich)?
    else {
        return Ok(None);
    };
    if let Some(name) = names.get(index) {
        let verified = crate::model_route::configured_local_profile(settings, name)?
            .ok_or_else(|| anyhow::anyhow!("Профиль local «{name}» больше не сохранён"))?;
        return Ok(Some(ChosenLocalProfile::Existing {
            profile: verified,
            server_known_protected: false,
        }));
    }
    let mut created = if index == names.len() {
        let Some(found) = discover_and_choose(rich).await? else {
            return Ok(None);
        };
        let latest = store.load()?;
        settings.local = latest.local;
        if let Some(existing_name) = settings
            .local
            .profiles
            .iter()
            .find(|(_, profile)| {
                profile.base_url.as_deref().and_then(endpoint_identity)
                    == endpoint_identity(&found.base_url)
            })
            .map(|(name, _)| name.clone())
        {
            let verified = crate::model_route::configured_local_profile(settings, &existing_name)?
                .ok_or_else(|| {
                    anyhow::anyhow!("Профиль local «{existing_name}» больше не сохранён")
                })?;
            return Ok(Some(ChosenLocalProfile::Existing {
                profile: verified,
                server_known_protected: found.auth_required,
            }));
        }
        let name = settings.local.unique_name(found.runtime.as_str());
        let mut profile = profile_settings(
            &name,
            &found.base_url,
            found.runtime,
            found.models.first().map_or("", String::as_str),
        );
        if let Some(local) = profile.local.as_mut() {
            local.key_required = found.auth_required;
        }
        profile
    } else {
        manual_profile(settings, rich)?
    };
    if let Some(ca) = ca_override {
        created.ca_file = Some(crate::model_route::normalize_ca_path(ca));
    }
    let name = created
        .local
        .as_ref()
        .map(|local| local.profile.clone())
        .unwrap_or_default();
    if store.load()?.local.profiles.contains_key(&name) {
        bail!("Профиль {name} уже существует; повторите подключение");
    }
    let auth_challenged = created
        .local
        .as_ref()
        .is_some_and(|local| local.key_required);
    let typed_key = if auth_challenged {
        let key = ui::password(&format!(
            "Ключ локального сервера для профиля {name} (ввод скрыт): "
        ))?;
        crate::local::validate_key(&key)?;
        if store.load()?.local.profiles.contains_key(&name) {
            bail!("Профиль {name} уже существует; повторите подключение");
        }
        Some(key)
    } else {
        None
    };
    Ok(Some(ChosenLocalProfile::DraftNew {
        profile: created,
        typed_key,
        auth_challenged,
    }))
}

async fn discover_and_choose(rich: bool) -> Result<Option<Discovered>> {
    if let Some(screen) = crate::screen::current() {
        screen.busy("Ищу локальные серверы на 127.0.0.1");
    }
    let found = local_runtime::discover(
        &local_runtime::default_candidates(),
        local_runtime::PROBE_DEADLINE,
    )
    .await;
    if let Some(screen) = crate::screen::current() {
        screen.pause();
    }
    if found.is_empty() {
        crate::screen::notice(
            "Локальные серверы не найдены на 127.0.0.1:11434, :8080, :1234. Запустите сервер или добавьте адрес вручную.",
        );
        return Ok(None);
    }
    let choices: Vec<Choice> = found
        .iter()
        .map(|server| Choice {
            label: format!("{} · {}", server.runtime.label(), server.base_url),
            detail: if server.auth_required {
                "нужен ключ".into()
            } else {
                format!("моделей: {}", server.models.len())
            },
            enabled: true,
        })
        .collect();
    Ok(choose("Найденные локальные серверы", &choices, 0, rich)?.map(|index| found[index].clone()))
}

fn manual_profile(settings: &Settings, rich: bool) -> Result<ProviderSettings> {
    let url = ui::line("Адрес API", "http://127.0.0.1:8080/v1")?;
    validate_local_endpoint(&url)?;
    let runtimes = LocalRuntime::all();
    let choices: Vec<Choice> = runtimes
        .iter()
        .map(|runtime| Choice {
            label: runtime.as_str().into(),
            detail: runtime.label().into(),
            enabled: true,
        })
        .collect();
    let Some(index) = choose("Сервер", &choices, runtimes.len() - 1, rich)? else {
        bail!(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Подключение отменено"
        ));
    };
    let runtime = runtimes[index];
    let name = ui::line("Имя профиля", &settings.local.unique_name(runtime.as_str()))?;
    crate::local::validate_profile_name(&name)?;
    if settings.local.profiles.contains_key(&name) {
        bail!("Профиль {name} уже существует");
    }
    Ok(profile_settings(&name, &url, runtime, ""))
}

pub(crate) async fn catalog_with_key(
    store: &ConfigStore,
    profile: &mut ProviderSettings,
    expected_disk: Option<&ProviderSettings>,
    mut key: Option<String>,
    server_known_protected: bool,
    caller_secrets: &[String],
) -> std::result::Result<(Vec<ModelInfo>, Option<String>), ConnectCatalogError> {
    // A stale snapshot neither reaches its server nor asks for a key.
    crate::local_app::check_current_with_baseline(store, profile, expected_disk.unwrap_or(profile))
        .map_err(ConnectCatalogError::Fatal)?;
    if let Some(expected) = expected_disk {
        let fresh = store.load().map_err(ConnectCatalogError::Fatal)?;
        let name = crate::local_app::profile_name(profile);
        if let Some(disk_p) = crate::model_route::configured_local_profile(&fresh, name)
            .map_err(ConnectCatalogError::Fatal)?
            && !crate::model_route::RouteIdentity::disk_unchanged(expected, &disk_p)
        {
            return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                "Параметры подключения локального профиля «{name}» изменились в другом процессе; переключите профиль через /provider local"
            )));
        }
    }
    let mut typed_new_key: Option<(String, String)> = None;
    let mut auth_challenged = server_known_protected;
    for attempt in 0..2 {
        let mut extra: Vec<String> = caller_secrets.to_vec();
        extra.extend(key.iter().cloned());
        crate::model_route::ensure_connection_free_of_secrets(store, profile, &extra)
            .map_err(ConnectCatalogError::Fatal)?;
        let mut client = ProviderClient::connect(profile.clone(), key.clone())
            .map_err(ConnectCatalogError::Fatal)?;
        let models = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.models_with_origin(),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("Локальный сервер не ответил за 20 секунд")));
        match models {
            Ok((models, verified_by_endpoint)) => {
                if auth_challenged && !verified_by_endpoint {
                    return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                        "Локальный сервер не подтвердил ключ через /models (HTTP 404/405)"
                    )));
                }
                if let Some((ref name, ref value)) = typed_new_key {
                    save_entered_key(store, profile, name, value)
                        .map_err(ConnectCatalogError::Fatal)?;
                }
                return Ok((models, key));
            }
            Err(error)
                if attempt == 0
                    && error
                        .downcast_ref::<ProviderFailure>()
                        .is_some_and(|failure| failure.kind == FailureKind::Auth) =>
            {
                auth_challenged = true;
                let name = crate::local_app::profile_name(profile).to_owned();
                if let Some(expected) = expected_disk
                    && !crate::model_route::RouteIdentity::same_connection(profile, expected)
                {
                    return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                        "Локальный сервер требует ключ; при временном переопределении параметров подключения (--ca-file) сохраните ключ профиля отдельно: rcode local key {name} --stdin"
                    )));
                }
                crate::local_app::check_current_with_baseline(
                    store,
                    profile,
                    expected_disk.unwrap_or(profile),
                )
                .map_err(ConnectCatalogError::Fatal)?;
                let value = ui::password(&format!(
                    "Сервер требует ключ. Ключ профиля {name} (ввод скрыт): "
                ))
                .map_err(ConnectCatalogError::Fatal)?;
                crate::local::validate_key(&value).map_err(ConnectCatalogError::Fatal)?;
                // Re-verify immediately after blocking password input before retrying `/models`.
                crate::local_app::check_current_with_baseline(
                    store,
                    profile,
                    expected_disk.unwrap_or(profile),
                )
                .map_err(ConnectCatalogError::Fatal)?;
                if let Some(expected) = expected_disk {
                    let fresh = store.load().map_err(ConnectCatalogError::Fatal)?;
                    let disk_p = crate::model_route::configured_local_profile(&fresh, &name)
                        .map_err(ConnectCatalogError::Fatal)?
                        .ok_or_else(|| {
                            ConnectCatalogError::Fatal(anyhow::anyhow!(
                                "Профиль local «{name}» больше не сохранён"
                            ))
                        })?;
                    if !crate::model_route::RouteIdentity::disk_unchanged(expected, &disk_p) {
                        return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                            "Параметры подключения локального профиля «{name}» изменились в другом процессе; переключите профиль через /provider local"
                        )));
                    }
                }
                typed_new_key = Some((name, value.clone()));
                key = Some(value);
            }
            Err(error) => {
                return if auth_challenged
                    || error
                        .downcast_ref::<ProviderFailure>()
                        .is_some_and(|failure| failure.kind == FailureKind::Auth)
                {
                    Err(ConnectCatalogError::Fatal(error))
                } else {
                    Err(ConnectCatalogError::Unreachable(error))
                };
            }
        }
    }
    Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
        "Локальный сервер отклонил ключ"
    )))
}

/// Saves a typed key under the profile name only while the saved profile is
/// still bound to the endpoint that asked for it: the profile may have moved
/// or been removed while the key was being typed. The profile is marked as
/// requiring a key first, so a failed key write fails closed.
fn save_entered_key(
    store: &ConfigStore,
    profile: &mut ProviderSettings,
    name: &str,
    key: &str,
) -> Result<()> {
    store.commit_local_profile_key(profile, name, key)?;
    if let Some(local) = profile.local.as_mut() {
        local.key_required = true;
    }
    Ok(())
}

pub(crate) async fn catalog_for_connect(
    store: &ConfigStore,
    expected_existing_disk: Option<&ProviderSettings>,
    profile: &ProviderSettings,
    initial_key: Option<String>,
    pre_challenged_auth: bool,
    server_known_protected: bool,
    caller_secrets: &[String],
) -> std::result::Result<CatalogConnectOutcome, ConnectCatalogError> {
    let verify_unchanged = || -> std::result::Result<String, ConnectCatalogError> {
        let fresh = store.load().map_err(ConnectCatalogError::Fatal)?;
        let name = crate::local_app::profile_name(profile).to_owned();
        if let Some(initial_disk) = expected_existing_disk {
            let current_disk = crate::model_route::configured_local_profile(&fresh, &name)
                .map_err(ConnectCatalogError::Fatal)?
                .ok_or_else(|| {
                    ConnectCatalogError::Fatal(anyhow::anyhow!(
                        "Профиль local «{name}» больше не сохранён"
                    ))
                })?;
            if !crate::model_route::RouteIdentity::disk_unchanged(initial_disk, &current_disk) {
                return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                    "Параметры локального профиля «{name}» изменились в другом процессе; повторите подключение"
                )));
            }
        } else if fresh.local.profiles.contains_key(&name) {
            return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                "Профиль {name} уже существует; повторите подключение"
            )));
        }
        Ok(name)
    };
    let mut candidate_key = initial_key.clone();
    let mut newly_entered_key: Option<String> = if pre_challenged_auth {
        initial_key
    } else {
        None
    };
    let mut auth_challenged = pre_challenged_auth || server_known_protected;
    for attempt in 0..2 {
        verify_unchanged()?;
        let mut extra: Vec<String> = caller_secrets.to_vec();
        extra.extend(candidate_key.iter().cloned());
        crate::model_route::ensure_connection_free_of_secrets(store, profile, &extra)
            .map_err(ConnectCatalogError::Fatal)?;
        let mut client = ProviderClient::connect(profile.clone(), candidate_key.clone())
            .map_err(ConnectCatalogError::Fatal)?;
        let models = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.models_with_origin(),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("Локальный сервер не ответил за 20 секунд")));
        match models {
            Ok((models, verified_by_endpoint)) => {
                if auth_challenged && !verified_by_endpoint {
                    return Err(ConnectCatalogError::Fatal(anyhow::anyhow!(
                        "Локальный сервер не подтвердил авторизацию через /models (HTTP 404/405); задайте ключ через rcode local key ИМЯ --stdin"
                    )));
                }
                return Ok(CatalogConnectOutcome {
                    models,
                    newly_entered_key,
                    verified_noauth: verified_by_endpoint && candidate_key.is_none(),
                });
            }
            Err(error)
                if attempt == 0
                    && !pre_challenged_auth
                    && error
                        .downcast_ref::<ProviderFailure>()
                        .is_some_and(|failure| failure.kind == FailureKind::Auth) =>
            {
                auth_challenged = true;
                let name = verify_unchanged()?;
                let value = ui::password(&format!(
                    "Сервер требует ключ. Ключ профиля {name} (ввод скрыт): "
                ))
                .map_err(ConnectCatalogError::Fatal)?;
                crate::local::validate_key(&value).map_err(ConnectCatalogError::Fatal)?;
                // Re-check disk before sending the newly typed key over loopback!
                verify_unchanged()?;
                candidate_key = Some(value.clone());
                newly_entered_key = Some(value);
            }
            Err(error) => {
                return if auth_challenged
                    || error
                        .downcast_ref::<ProviderFailure>()
                        .is_some_and(|failure| failure.kind == FailureKind::Auth)
                {
                    Err(ConnectCatalogError::Fatal(error))
                } else {
                    Err(ConnectCatalogError::Unreachable(error))
                };
            }
        }
    }
    Err(ConnectCatalogError::Fatal(
        ProviderFailure {
            kind: FailureKind::Auth,
            status: None,
            message: "Локальный сервер отклонил ключ".into(),
            usage: None,
            from_oauth: false,
        }
        .into(),
    ))
}

/// `rcode connect local` and the first-run wizard.
pub(crate) async fn connect_with_secrets(
    store: &ConfigStore,
    settings: &mut Settings,
    rich: bool,
    ca_override: Option<&std::path::Path>,
    caller_secrets: &[String],
    shared_sink: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
) -> Result<ProviderSettings> {
    let Some(chosen) =
        choose_profile_choice_with_secrets(store, settings, rich, ca_override, caller_secrets)
            .await?
    else {
        bail!(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Подключение отменено"
        ));
    };
    let (existing_disk, mut profile, initial_key, pre_challenged_auth, server_known_protected) =
        match chosen {
            ChosenLocalProfile::Existing {
                profile: mut existing,
                server_known_protected,
            } => {
                let initial_disk = existing.clone();
                let resolved_ca = resolve_local_ca(existing.ca_file.as_deref(), ca_override)?;
                let ca_changed = existing.ca_file != resolved_ca;
                existing.ca_file = resolved_ca;
                let key = if ca_changed {
                    None
                } else {
                    let (fresh, cred_state) = store.read_consistent_local(&initial_disk)?;
                    let name = crate::local_app::profile_name(&initial_disk);
                    let current_disk = crate::model_route::configured_local_profile(&fresh, name)?
                        .ok_or_else(|| {
                            anyhow::anyhow!("Профиль local «{name}» больше не сохранён")
                        })?;
                    if !crate::model_route::RouteIdentity::disk_unchanged(
                        &initial_disk,
                        &current_disk,
                    ) {
                        bail!(
                            "Параметры локального профиля «{name}» изменились в другом процессе; повторите подключение"
                        );
                    }
                    cred_state.into_key()
                };
                (
                    Some(initial_disk),
                    existing,
                    key,
                    false,
                    server_known_protected,
                )
            }
            ChosenLocalProfile::DraftNew {
                mut profile,
                typed_key,
                auth_challenged,
            } => {
                profile.ca_file = resolve_local_ca(profile.ca_file.as_deref(), ca_override)?;
                (None, profile, typed_key, auth_challenged, auth_challenged)
            }
        };
    let mut pre_catalog_secrets: Vec<String> = caller_secrets.to_vec();
    if let Some(ref sink) = shared_sink {
        let guard = sink.lock().unwrap_or_else(|e| e.into_inner());
        crate::redaction::merge_secret_variants(&mut pre_catalog_secrets, &guard);
    }
    if let Some(ref k) = initial_key {
        pre_catalog_secrets.push(k.clone());
    }
    if let Some(screen) = crate::screen::current() {
        screen.busy("Получаю список моделей");
    }
    let catalog = catalog_for_connect(
        store,
        existing_disk.as_ref(),
        &profile,
        initial_key,
        pre_challenged_auth,
        server_known_protected,
        &pre_catalog_secrets,
    )
    .await;
    if let Some(screen) = crate::screen::current() {
        screen.pause();
    }
    let mut extra_secrets = pre_catalog_secrets;
    let mut pending_new_key: Option<String> = None;
    let mut verified_noauth = false;
    let fetched = match catalog {
        Ok(out) => {
            if let Some(ref k) = out.newly_entered_key {
                extra_secrets.push(k.clone());
            }
            pending_new_key = out.newly_entered_key;
            verified_noauth = out.verified_noauth;
            out.models
        }
        Err(ConnectCatalogError::Fatal(error)) => return Err(error),
        Err(ConnectCatalogError::Unreachable(error)) => {
            crate::screen::notice(format!(
                "Каталог моделей недоступен: {}. Модель можно ввести вручную; сервер можно запустить позже.",
                ui::safe(&format!("{error:#}"))
            ));
            Vec::new()
        }
    };
    let collect_live_secrets = || {
        let mut live = extra_secrets.clone();
        if let Some(ref sink) = shared_sink {
            let guard = sink.lock().unwrap_or_else(|e| e.into_inner());
            crate::redaction::merge_secret_variants(&mut live, &guard);
        }
        live
    };
    let secret_dict =
        crate::model_route::build_route_secret_dictionary(store, &collect_live_secrets())?;
    let models = local_models_filtered(fetched, &profile.model, secret_dict.as_ref());
    let Some(model) = ui::pick_model(&models, &profile, rich, || {
        crate::model_route::ensure_route_free_of_secrets(store, &profile, &collect_live_secrets())
            .is_ok()
    })?
    else {
        bail!(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Подключение отменено"
        ));
    };
    profile.model = model;
    profile.validate()?;
    crate::model_route::ensure_route_free_of_secrets(store, &profile, &collect_live_secrets())?;
    let name = crate::local_app::profile_name(&profile).to_owned();
    let updated = match existing_disk {
        Some(initial_disk) => store.commit_local_profile_connect_with_secrets(
            &initial_disk,
            &name,
            profile,
            pending_new_key.as_deref(),
            verified_noauth,
            collect_live_secrets,
        )?,
        None => {
            store
                .commit_local_profile_add_with_secrets(
                    &name,
                    false,
                    true,
                    false,
                    profile,
                    pending_new_key.as_deref(),
                    collect_live_secrets,
                )?
                .0
        }
    };
    let committed = updated.local.profiles[&name].clone();
    *settings = updated;
    if matches!(store.credential_for(&committed)?, CredentialState::Missing) {
        bail!("Сервер требует ключ: rcode local key ИМЯ --stdin");
    }
    crate::screen::notice(
        "Локальный профиль сохранён. rcode doctor --check --provider local проверит сервер.",
    );
    Ok(committed)
}

/// Previous model first; models are listed as the server reports them.
pub fn local_models(fetched: Vec<ModelInfo>, current: &str) -> Vec<ModelInfo> {
    local_models_filtered(fetched, current, None)
}

pub(crate) fn filter_local_models_preserving_order(
    fetched: Vec<ModelInfo>,
    secret_dict: Option<&crate::redaction::SecretDictionary>,
) -> Vec<ModelInfo> {
    let contains_secret = |text: &str| -> bool {
        secret_dict.is_some_and(|dict| {
            crate::redaction::redact_text_with(dict, text)
                .ok()
                .as_deref()
                != Some(text)
        })
    };
    fetched
        .into_iter()
        .filter(|model| !model.id.chars().any(char::is_control) && !contains_secret(&model.id))
        .map(|mut model| {
            if let Some(dict) = secret_dict {
                model.name = crate::redaction::redact_text_idempotent_with(dict, &model.name)
                    .unwrap_or_else(|_| "[скрыто]".into());
            }
            model.name = ui::safe(&model.name);
            model
        })
        .collect()
}

pub(crate) fn local_models_filtered(
    fetched: Vec<ModelInfo>,
    current: &str,
    secret_dict: Option<&crate::redaction::SecretDictionary>,
) -> Vec<ModelInfo> {
    let contains_secret = |text: &str| -> bool {
        secret_dict.is_some_and(|dict| {
            crate::redaction::redact_text_with(dict, text)
                .ok()
                .as_deref()
                != Some(text)
        })
    };
    let mut models = filter_local_models_preserving_order(fetched, secret_dict);
    models.sort_by(|a, b| {
        (a.id != current)
            .cmp(&(b.id != current))
            .then(a.id.cmp(&b.id))
    });
    if !current.is_empty()
        && !contains_secret(current)
        && !models.iter().any(|model| model.id == current)
    {
        models.insert(
            0,
            ModelInfo {
                id: current.into(),
                name: "Модель из профиля · сервер её не сообщил".into(),
                ..ModelInfo::default()
            },
        );
    }
    models
}
