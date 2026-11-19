//! Headless `rcode local …` commands. Keys are read from stdin only and are
//! never printed; profile output reports only whether a key is stored.
use crate::{
    app::Events,
    cli::{Cli, LocalCommand},
    config::{ConfigStore, ProviderSettings, Settings},
    local::{
        LocalRuntime, ThinkingMode, endpoint_identity, profile_settings, validate_local_endpoint,
    },
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
    if cli.effort.is_some() {
        bail!("Для local глубина effort не настраивается; используйте --thinking auto|on|off");
    }
    if cli.thinking.is_some()
        && !matches!(command, LocalCommand::Add { .. } | LocalCommand::Use { .. })
    {
        bail!(
            "Флаг --thinking применяется в rcode local add и rcode local use, а также при запуске сессии или rcode exec"
        );
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
            let extra_secrets: Vec<String> = key.iter().cloned().collect();
            let mut precheck =
                profile_settings(name, &base_url, runtime.unwrap_or(LocalRuntime::OpenAi), "");
            precheck.ca_file = cli
                .ca_file
                .as_deref()
                .map(crate::model_route::normalize_ca_path);
            crate::model_route::ensure_connection_free_of_secrets(
                store,
                &precheck,
                &extra_secrets,
            )?;
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
                local.thinking = cli.thinking.and_then(ThinkingMode::into_option);
                local.key_required = key.is_some() || kept_key;
            }
            profile.ca_file = cli
                .ca_file
                .as_deref()
                .map(crate::model_route::normalize_ca_path);
            if let Some(tokens) = max_output_tokens {
                profile.max_output_tokens = *tokens;
            } else if let Some(local) = &profile.local {
                profile.max_output_tokens = profile.max_output_tokens.min(local.context_tokens / 4);
            }
            crate::local::validate(&profile)?;
            let auto_selected_model = profile.model.is_empty();
            if auto_selected_model {
                profile.model = first_model(store, &profile, key.clone()).await?;
            }
            profile.validate()?;
            crate::model_route::ensure_route_free_of_secrets(store, &profile, &extra_secrets)?;
            if auto_selected_model && !cli.json {
                println!("Модель из /models сервера: {}", ui::safe(&profile.model));
            }
            let (committed_settings, committed_moved) = store
                .commit_local_profile_add_with_secrets(
                    name,
                    *force,
                    *activate,
                    false,
                    profile,
                    key.as_deref(),
                    || events.secret_snapshot(),
                )?;
            settings = committed_settings;
            let saved_profile = settings.local.profiles[name].clone();
            let row = profile_row(store, &settings, name, &saved_profile);
            if cli.json {
                events.emit("local_profile", row);
            } else {
                println!("✓ Профиль сохранён: {}", plain_row(&row));
                if (moved || committed_moved) && key.is_none() {
                    println!("Адрес изменился: ключ прежнего адреса удалён.");
                }
            }
            Ok(0)
        }
        LocalCommand::Use { name } => {
            let profile = crate::model_route::configured_local_profile(&settings, name)?
                .with_context(|| format!("Профиль local «{name}» не найден: rcode local list"))?;
            if cli.base_url.is_some() || cli.ca_file.is_some() || cli.folder_id.is_some() {
                bail!(
                    "Адрес профиля меняется командой rcode local add {name} --base-url URL --force"
                );
            }
            let _ = events.refresh_keys(store);
            let mut saved_profile = profile;
            settings = store.update_settings_with_credentials(|current, providers_creds| {
                let live_extra = events.secret_snapshot();
                let route_dict = crate::model_route::build_route_secret_dictionary_from_raw(
                    providers_creds.values().cloned(),
                    &live_extra,
                )?;
                let mut p = crate::model_route::configured_local_profile(current, name)?
                    .with_context(|| {
                        let safe_name = match route_dict.as_ref() {
                            Some(dict) => crate::redaction::redact_text_idempotent_with(dict, name)
                                .unwrap_or_else(|_| "[скрыто]".into()),
                            None => name.to_owned(),
                        };
                        format!("Профиль local «{safe_name}» не найден: rcode local list")
                    })?;
                if let Some(model) = &cli.model {
                    p.model = model.clone();
                }
                if let Some(thinking) = cli.thinking
                    && let Some(local) = p.local.as_mut()
                {
                    local.thinking = thinking.into_option();
                }
                p.validate()?;
                crate::model_route::check_route_against_secret_dictionary(route_dict.as_ref(), &p)?;
                current.remember_provider(&p);
                saved_profile = p;
                Ok(())
            })?;
            let row = profile_row(store, &settings, name, &saved_profile);
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
            let expected_profile =
                settings
                    .local
                    .profiles
                    .get(name)
                    .cloned()
                    .with_context(|| {
                        let safe_name = crate::model_route::redact_route_display_field(
                            store,
                            &events.secret_snapshot(),
                            name,
                        );
                        format!("Профиль local «{safe_name}» не найден: rcode local list")
                    })?;
            if *delete {
                // The profile still expects a key: requests stop before the
                // network until a new key is stored or the profile is re-added.
                store.delete_local_credential(name)?;
            } else {
                let key = read_key()?;
                crate::local_app::remember_key(events, &key);
                let _ = events.refresh_keys(store);
                crate::model_route::ensure_route_free_of_secrets(
                    store,
                    &expected_profile,
                    &events.secret_snapshot(),
                )?;
                let _ = store.commit_local_profile_key(&expected_profile, name, &key)?;
            }
            let _ = events.refresh_keys(store);
            let clean_name = crate::model_route::redact_route_display_field(
                store,
                &events.secret_snapshot(),
                name,
            );
            let message = if *delete {
                format!("Ключ профиля {clean_name} удалён")
            } else {
                format!("Ключ профиля {clean_name} сохранён")
            };
            if cli.json {
                events.emit(
                    "local_key",
                    json!({"profile":clean_name,"key":if *delete {"none"} else {"stored"}}),
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

async fn first_model(
    store: &ConfigStore,
    profile: &ProviderSettings,
    key: Option<String>,
) -> Result<String> {
    let mut initial_extra = Vec::new();
    if let Some(ref k) = key {
        crate::redaction::push_secret_variants(&mut initial_extra, k);
    }
    crate::model_route::ensure_connection_free_of_secrets(store, profile, &initial_extra)?;
    let mut client = ProviderClient::connect(profile.clone(), key.clone())?;
    let sink = std::sync::Arc::new(std::sync::Mutex::new(initial_extra));
    client.bind_secret_sink(std::sync::Arc::clone(&sink));
    let models = tokio::time::timeout(std::time::Duration::from_secs(10), client.models())
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("Локальный сервер не ответил за 10 секунд")));
    match models {
        Ok(models) => {
            let mut extra = sink.lock().unwrap_or_else(|e| e.into_inner()).clone();
            for s in client.redaction_secrets() {
                crate::redaction::push_secret_variants(&mut extra, &s);
            }
            let dict = crate::model_route::build_route_secret_dictionary(store, &extra)?;
            let clean = crate::local_ui::filter_local_models_preserving_order(models, dict.as_ref());
            if let Some(first) = clean.first() {
                Ok(first.id.clone())
            } else {
                bail!("Сервер не сообщил ни одной допустимой модели; укажите --model ID")
            }
        }
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
    let dict_res = crate::model_route::build_route_secret_dictionary(store, &[]);
    let redact_field = |text: &str| -> String {
        if text.is_empty() {
            return String::new();
        }
        match &dict_res {
            Ok(None) => text.to_owned(),
            Ok(Some(d)) => crate::redaction::redact_text_idempotent_with(d, text)
                .unwrap_or_else(|_| "[скрыто]".into()),
            Err(_) => "[скрыто]".into(),
        }
    };
    let local = profile
        .local
        .clone()
        .unwrap_or_else(crate::local::draft_settings);
    let clean_name = redact_field(name);
    let clean_base_url = profile.base_url.as_deref().map(&redact_field);
    let clean_model = redact_field(&profile.model);
    json!({
        "profile": clean_name,
        "runtime": local.runtime,
        "base_url": clean_base_url,
        "model": clean_model,
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
    let thinking = match row["thinking"].as_bool() {
        Some(true) => "on",
        Some(false) => "off",
        None => "auto",
    };
    format!(
        "{}{}  {}  {}  {}  ключ: {}  ctx {}  thinking: {}",
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
        row["context_tokens"],
        thinking,
    )
}
