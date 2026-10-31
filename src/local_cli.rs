//! Headless `rcode local …` commands. Keys are read from stdin only and are
//! never printed; profile output reports only whether a key is stored.
use crate::{
    app::Events,
    cli::{Cli, LocalCommand, Toggle},
    config::{ConfigStore, ProviderSettings, Settings},
    local::{LocalRuntime, endpoint_identity, profile_settings, validate_local_endpoint},
    local_runtime::{self, Candidate},
    protocol::{FailureKind, ProviderFailure},
    provider::ProviderClient,
    ui,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::{IsTerminal, Read};

pub async fn run(
    command: &LocalCommand,
    cli: &Cli,
    store: &ConfigStore,
    events: &mut Events,
) -> Result<i32> {
    if cli.profile.is_some() {
        bail!("Для rcode local укажите имя профиля аргументом, а не --profile");
    }
    let mut settings = store.load()?;
    match command {
        LocalCommand::Discover => discover(cli, events).await,
        LocalCommand::List => {
            if settings.local.profiles.is_empty() && !cli.json {
                println!(
                    "Профилей local нет. Добавьте: rcode local add ИМЯ --base-url http://127.0.0.1:11434/v1"
                );
            }
            for (name, profile) in &settings.local.profiles {
                let row = profile_row(store, &settings, name, profile);
                if cli.json {
                    events.emit("local_profile", row);
                } else {
                    println!("{}", plain_row(&row));
                }
            }
            Ok(0)
        }
        LocalCommand::Add {
            name,
            runtime,
            context_tokens,
            max_output_tokens,
            vision,
            thinking,
            api_key_stdin,
            activate,
            force,
        } => {
            crate::local::validate_profile_name(name)?;
            let existing = settings.local.profiles.get(name).cloned();
            if existing.is_some() && !force {
                bail!(
                    "Профиль {name} уже существует; замените его с --force или выберите другое имя"
                );
            }
            let base_url = cli
                .base_url
                .clone()
                .context("Укажите адрес сервера: --base-url http://127.0.0.1:ПОРТ/v1")?;
            let url = validate_local_endpoint(&base_url)?;
            let key = if *api_key_stdin {
                Some(read_key()?)
            } else {
                None
            };
            if let Some(key) = &key {
                crate::local_app::remember_key(events, key);
            }
            let runtime = match runtime {
                Some(runtime) => *runtime,
                None => guess_runtime(&url, &base_url).await,
            };
            let mut profile = profile_settings(
                name,
                &base_url,
                runtime,
                cli.model.as_deref().unwrap_or_default(),
            );
            let moved = existing.as_ref().is_some_and(|old| {
                old.base_url.as_deref().and_then(endpoint_identity) != endpoint_identity(&base_url)
            });
            // A replaced profile keeps its key only for the same address.
            let kept_key = existing.is_some()
                && !moved
                && key.is_none()
                && store.local_credential(name)?.is_some();
            if let Some(local) = profile.local.as_mut() {
                if let Some(tokens) = context_tokens {
                    local.context_tokens = *tokens;
                }
                local.vision = *vision;
                local.thinking = thinking.map(|toggle| toggle == Toggle::On);
                local.key_required = key.is_some() || kept_key;
            }
            profile.ca_file = cli.ca_file.clone();
            if let Some(tokens) = max_output_tokens {
                profile.max_output_tokens = *tokens;
            } else if let Some(local) = &profile.local {
                profile.max_output_tokens = profile.max_output_tokens.min(local.context_tokens / 4);
            }
            if profile.model.is_empty() {
                profile.model = first_model(&profile, key.clone()).await?;
                if !cli.json {
                    println!("Модель из /models сервера: {}", ui::safe(&profile.model));
                }
            }
            profile.validate()?;
            settings
                .local
                .profiles
                .insert(name.clone(), profile.clone());
            if *activate {
                settings.remember_provider(&profile);
            } else if settings.local.active.is_none() {
                settings.local.active = Some(name.clone());
            }
            // A key belongs to the address it was entered for: a new profile
            // never inherits a key left under its name, a moved one loses it.
            // Deleted before the profile is saved, so it never coexists with it.
            if !kept_key {
                store.delete_local_credential(name)?;
            }
            store.save(&settings)?;
            if let Some(key) = &key {
                store.save_local_credential(name, key)?;
            }
            let row = profile_row(store, &settings, name, &profile);
            if cli.json {
                events.emit("local_profile", row);
            } else {
                println!("✓ Профиль сохранён: {}", plain_row(&row));
                if moved && key.is_none() {
                    println!("Адрес изменился: ключ прежнего адреса удалён.");
                }
            }
            Ok(0)
        }
        LocalCommand::Use { name } => {
            let mut profile = settings
                .local
                .profiles
                .get(name)
                .cloned()
                .with_context(|| format!("Профиль local «{name}» не найден: rcode local list"))?;
            if cli.base_url.is_some() {
                bail!(
                    "Адрес профиля меняется командой rcode local add {name} --base-url URL --force"
                );
            }
            if let Some(model) = &cli.model {
                profile.model = model.clone();
            }
            profile.validate()?;
            settings.remember_provider(&profile);
            store.save(&settings)?;
            let row = profile_row(store, &settings, name, &profile);
            if cli.json {
                events.emit("local_profile", row);
            } else {
                println!("✓ Активен local: {}", plain_row(&row));
            }
            Ok(0)
        }
        LocalCommand::Key {
            name,
            stdin: _,
            delete,
        } => {
            if !settings.local.profiles.contains_key(name) {
                bail!("Профиль local «{name}» не найден: rcode local list");
            }
            if *delete {
                // The profile still expects a key: requests stop before the
                // network until a new key is stored or the profile is re-added.
                store.delete_local_credential(name)?;
            } else {
                let key = read_key()?;
                crate::local_app::remember_key(events, &key);
                store.save_local_credential(name, &key)?;
                if let Some(local) = settings
                    .local
                    .profiles
                    .get_mut(name)
                    .and_then(|profile| profile.local.as_mut())
                    .filter(|local| !local.key_required)
                {
                    local.key_required = true;
                    store.save(&settings)?;
                }
            }
            let message = if *delete {
                format!("Ключ профиля {name} удалён")
            } else {
                format!("Ключ профиля {name} сохранён")
            };
            if cli.json {
                events.emit(
                    "local_key",
                    json!({"profile":name,"key":if *delete {"none"} else {"stored"}}),
                );
            } else {
                println!("✓ {message}");
            }
            Ok(0)
        }
        LocalCommand::Remove { name } => {
            store.remove_local_profile(&mut settings, name)?;
            if cli.json {
                events.emit("local_profile_removed", json!({"profile":name}));
            } else {
                println!("✓ Профиль {name} и его ключ удалены");
            }
            Ok(0)
        }
    }
}

async fn discover(cli: &Cli, events: &Events) -> Result<i32> {
    let found = local_runtime::discover(
        &local_runtime::default_candidates(),
        local_runtime::PROBE_DEADLINE,
    )
    .await;
    if found.is_empty() && !cli.json {
        println!(
            "Локальные серверы не найдены на 127.0.0.1:11434, :8080, :1234. Запустите сервер или добавьте адрес: rcode local add ИМЯ --base-url URL"
        );
    }
    for server in found {
        if cli.json {
            events.emit("local_server", serde_json::to_value(&server)?);
        } else {
            println!(
                "{}  {}  {}",
                server.runtime,
                server.base_url,
                if server.auth_required {
                    "нужен ключ".into()
                } else {
                    format!("моделей: {}", server.models.len())
                }
            );
        }
    }
    Ok(0)
}

async fn guess_runtime(url: &reqwest::Url, base_url: &str) -> LocalRuntime {
    match url.port_or_known_default() {
        Some(11434) => LocalRuntime::Ollama,
        Some(1234) => LocalRuntime::LmStudio,
        Some(8080) => local_runtime::discover(
            &[Candidate {
                base_url: base_url.into(),
                runtime: None,
            }],
            local_runtime::PROBE_DEADLINE,
        )
        .await
        .first()
        .map_or(LocalRuntime::OpenAi, |found| found.runtime),
        _ => LocalRuntime::OpenAi,
    }
}

async fn first_model(profile: &ProviderSettings, key: Option<String>) -> Result<String> {
    let mut client = ProviderClient::connect(profile.clone(), key.clone())?;
    let models = tokio::time::timeout(std::time::Duration::from_secs(10), client.models())
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("Локальный сервер не ответил за 10 секунд")));
    match models {
        Ok(models) if !models.is_empty() => Ok(models[0].id.clone()),
        Ok(_) => bail!("Сервер не сообщил ни одной модели; укажите --model ID"),
        Err(error)
            if key.is_none()
                && error
                    .downcast_ref::<ProviderFailure>()
                    .is_some_and(|failure| failure.kind == FailureKind::Auth) =>
        {
            bail!("Сервер требует ключ: повторите с --api-key-stdin (ключ читается из stdin)")
        }
        Err(error) => Err(error.context(
            "Не удалось получить список моделей; если сервер ещё не запущен, укажите --model ID — профиль сохранится",
        )),
    }
}

fn read_key() -> Result<String> {
    let key = if std::io::stdin().is_terminal() {
        ui::password("Ключ локального сервера (ввод скрыт): ")?
    } else {
        let mut text = String::new();
        std::io::stdin()
            .take(16 * 1024)
            .read_to_string(&mut text)
            .context("Не удалось прочитать ключ из stdin")?;
        text.trim_end_matches(['\r', '\n']).to_owned()
    };
    crate::local::validate_key(&key)?;
    Ok(key)
}

fn profile_row(
    store: &ConfigStore,
    settings: &Settings,
    name: &str,
    profile: &ProviderSettings,
) -> Value {
    let local = profile
        .local
        .clone()
        .unwrap_or_else(crate::local::draft_settings);
    json!({
        "profile": name,
        "runtime": local.runtime,
        "base_url": profile.base_url,
        "model": profile.model,
        "active": settings.local.active.as_deref() == Some(name),
        "default_provider": settings.active == crate::config::ProviderKind::Local
            && settings.local.active.as_deref() == Some(name),
        "key": if matches!(store.local_credential(name), Ok(Some(_))) { "stored" } else { "none" },
        "context_tokens": local.context_tokens,
        "context_source": "profile",
        "max_output_tokens": profile.max_output_tokens,
        "vision": local.vision,
        "thinking": local.thinking,
    })
}

fn plain_row(row: &Value) -> String {
    format!(
        "{}{}  {}  {}  {}  ключ: {}  ctx {}",
        if row["active"] == true { "* " } else { "  " },
        row["profile"].as_str().unwrap_or_default(),
        row["runtime"].as_str().unwrap_or_default(),
        row["base_url"].as_str().unwrap_or_default(),
        ui::safe(row["model"].as_str().unwrap_or_default()),
        if row["key"] == "stored" {
            "сохранён"
        } else {
            "нет"
        },
        row["context_tokens"]
    )
}
