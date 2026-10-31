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
pub fn summary(settings: &Settings, store: &ConfigStore) -> String {
    let Some(profile) = settings.local.active_profile() else {
        return if settings.local.profiles.is_empty() {
            "найти локальный сервер".into()
        } else {
            "выбрать профиль".into()
        };
    };
    profile_detail(profile, store)
}

fn profile_detail(profile: &ProviderSettings, store: &ConfigStore) -> String {
    let local = profile.local.as_ref();
    let name = local.map_or("", |local| local.profile.as_str());
    let address = profile
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
    let key = match store.local_credential(name) {
        Ok(Some(_)) => "ключ сохранён",
        _ if local.is_some_and(|local| local.key_required) => "нужен ключ",
        _ => "без ключа",
    };
    format!(
        "профиль {name} · {} · {address} · {key}{}",
        local.map_or("", |local| local.runtime.as_str()),
        if profile.model.is_empty() {
            String::new()
        } else {
            format!(" · {}", profile.model)
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

/// Picks or creates a profile. A new profile is saved (not activated) so its
/// key can be stored under its name; activation happens with the model choice.
pub async fn choose_profile(
    store: &ConfigStore,
    settings: &mut Settings,
    rich: bool,
) -> Result<Option<ProviderSettings>> {
    // Another process may have added, moved or removed profiles meanwhile.
    settings.local = store.load()?.local;
    let mut names: Vec<String> = settings.local.profiles.keys().cloned().collect();
    if let Some(active) = &settings.local.active
        && let Some(index) = names.iter().position(|name| name == active)
    {
        names[..=index].rotate_right(1);
    }
    let mut choices: Vec<Choice> = names
        .iter()
        .map(|name| Choice {
            label: name.clone(),
            detail: profile_detail(&settings.local.profiles[name], store),
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
        return Ok(Some(settings.local.profiles[name].clone()));
    }
    let created = if index == names.len() {
        let Some(found) = discover_and_choose(rich).await? else {
            return Ok(None);
        };
        if let Some(existing) = settings.local.profiles.values().find(|profile| {
            profile.base_url.as_deref().and_then(endpoint_identity)
                == endpoint_identity(&found.base_url)
        }) {
            return Ok(Some(existing.clone()));
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
    let name = created
        .local
        .as_ref()
        .map(|local| local.profile.clone())
        .unwrap_or_default();
    let key = if created
        .local
        .as_ref()
        .is_some_and(|local| local.key_required)
    {
        let key = ui::password(&format!(
            "Ключ локального сервера для профиля {name} (ввод скрыт): "
        ))?;
        crate::local::validate_key(&key)?;
        Some(key)
    } else {
        None
    };
    let mut updated = store.load()?;
    if updated.local.profiles.contains_key(&name) {
        bail!("Профиль {name} уже существует");
    }
    // A new profile starts without a key: one left under this name by a
    // removed profile was entered for another endpoint.
    store.delete_local_credential(&name)?;
    updated.local.profiles.insert(name.clone(), created.clone());
    store.save(&updated)?;
    settings.local = updated.local;
    if let Some(key) = key {
        store.save_local_credential(&name, &key)?;
    }
    Ok(Some(created))
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

/// Fetches the model catalog; on 401/403 asks for the key once and retries.
pub async fn catalog(
    store: &ConfigStore,
    profile: &mut ProviderSettings,
) -> Result<(Vec<ModelInfo>, Option<String>)> {
    // A stale snapshot neither reaches its server nor asks for a key.
    crate::local_app::check_current(store, profile)?;
    let mut key = store.credential_for(profile)?.into_key();
    for attempt in 0..2 {
        let mut client = ProviderClient::connect(profile.clone(), key.clone())?;
        let models = tokio::time::timeout(std::time::Duration::from_secs(20), client.models())
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("Локальный сервер не ответил за 20 секунд")));
        match models {
            Ok(models) => return Ok((models, key)),
            Err(error)
                if attempt == 0
                    && error
                        .downcast_ref::<ProviderFailure>()
                        .is_some_and(|failure| failure.kind == FailureKind::Auth) =>
            {
                crate::local_app::check_current(store, profile)?;
                let name = crate::local_app::profile_name(profile).to_owned();
                let value = ui::password(&format!(
                    "Сервер требует ключ. Ключ профиля {name} (ввод скрыт): "
                ))?;
                crate::local::validate_key(&value)?;
                save_entered_key(store, profile, &name, &value)?;
                key = Some(value);
            }
            Err(error) => return Err(error),
        }
    }
    bail!("Локальный сервер отклонил ключ")
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
    let mut saved = crate::local_app::check_current(store, profile)?;
    for local in [
        profile.local.as_mut(),
        saved
            .local
            .profiles
            .get_mut(name)
            .and_then(|saved| saved.local.as_mut()),
    ]
    .into_iter()
    .flatten()
    {
        local.key_required = true;
    }
    store.save(&saved)?;
    store.save_local_credential(name, key)
}

/// `rcode connect local` and the first-run wizard.
pub async fn connect(
    store: &ConfigStore,
    settings: &mut Settings,
    rich: bool,
) -> Result<ProviderSettings> {
    let Some(mut profile) = choose_profile(store, settings, rich).await? else {
        bail!(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Подключение отменено"
        ));
    };
    if let Some(screen) = crate::screen::current() {
        screen.busy("Получаю список моделей");
    }
    let catalog = catalog(store, &mut profile).await;
    if let Some(screen) = crate::screen::current() {
        screen.pause();
    }
    let fetched = match catalog {
        Ok((models, _)) => models,
        Err(error) => {
            crate::screen::notice(format!(
                "Каталог моделей недоступен: {}. Модель можно ввести вручную; сервер можно запустить позже.",
                ui::safe(&format!("{error:#}"))
            ));
            Vec::new()
        }
    };
    let models = local_models(fetched, &profile.model);
    let Some(model) = ui::pick_model(&models, &profile, rich)? else {
        bail!(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Подключение отменено"
        ));
    };
    profile.model = model;
    profile.validate()?;
    let mut updated = store.load()?;
    crate::local_app::check_commit(&updated, &profile)?;
    updated.remember_provider(&profile);
    store.save(&updated)?;
    *settings = updated;
    if matches!(store.credential_for(&profile)?, CredentialState::Missing) {
        bail!("Сервер требует ключ: rcode local key ИМЯ --stdin");
    }
    crate::screen::notice(
        "Локальный профиль сохранён. rcode doctor --check --provider local проверит сервер.",
    );
    Ok(profile)
}

/// Previous model first; models are listed as the server reports them.
pub fn local_models(fetched: Vec<ModelInfo>, current: &str) -> Vec<ModelInfo> {
    let mut models: Vec<ModelInfo> = fetched
        .into_iter()
        .filter(|model| !model.id.chars().any(char::is_control))
        .collect();
    models.sort_by(|a, b| {
        (a.id != current)
            .cmp(&(b.id != current))
            .then(a.id.cmp(&b.id))
    });
    if !current.is_empty() && !models.iter().any(|model| model.id == current) {
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
