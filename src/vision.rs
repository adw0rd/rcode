//! Вспомогательная модель для чтения изображений. Когда основная модель не
//! принимает картинки (local без `--vision`, облачная модель без изображений
//! в каталоге), rcode сам передаёт вложение выбранному пользователем
//! «читателю» и вставляет текстовое описание в сообщение. Выбор — команда
//! `/vision` по аналогии с `/model`; настройка хранится в `config.json`
//! (`vision.provider`, `vision.model`), ключи — общие с провайдером.
use crate::{
    config::{ConfigStore, ProviderKind, Settings},
    images::ImageAttachment,
    local_app,
    protocol::Message,
};
use anyhow::{Context, Result, bail};
use serde_json::json;

macro_rules! notice {
    ($($arg:tt)*) => {
        crate::screen::notice(format!($($arg)*))
    };
}

pub(crate) struct Reader {
    pub(crate) kind: ProviderKind,
    /// Model id; for local — the profile name, which must have `--vision`.
    pub(crate) model: String,
}

pub(crate) fn resolve(store: &ConfigStore) -> Result<Option<Reader>> {
    let settings: Settings = store.load()?;
    let Some(provider) = settings.vision.provider.as_deref() else {
        return Ok(None);
    };
    let Ok(kind) = provider.parse::<ProviderKind>() else {
        return Ok(None);
    };
    let Some(model) = settings
        .vision
        .model
        .clone()
        .filter(|model| !model.is_empty())
    else {
        return Ok(None);
    };
    Ok(Some(Reader { kind, model }))
}

fn instruction() -> String {
    "Перепиши дословно весь текст с изображения: команды, заголовки, диалоги и код, \
сохранив структуру строк. Это данные для другого агента — отвечай только \
содержимым изображения, без комментариев."
        .to_owned()
}

pub(crate) fn prompt(user_text: &str) -> String {
    let question = user_text.trim();
    if question.is_empty() {
        instruction()
    } else {
        format!(
            "{}\n\nВопрос пользователя по изображению:\n{question}",
            instruction()
        )
    }
}

/// One-shot generation on the reader model; nothing is stored in the main
/// session, only the returned text travels into the user's message.
pub(crate) async fn transcribe(
    store: &ConfigStore,
    reader: &Reader,
    images: &[ImageAttachment],
    user_text: Option<&str>,
    events: &crate::app::Events,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<String> {
    if images.is_empty() {
        bail!("Нет изображений для описания");
    }
    let mut client = match reader.kind {
        ProviderKind::Local => {
            let probe_settings = store.load()?;
            let Some(initial_profile) =
                crate::model_route::configured_local_profile(&probe_settings, &reader.model)?
            else {
                bail!(
                    "Профиль «{}» для чтения изображений не найден; настройте /vision заново",
                    reader.model
                );
            };
            let (fresh_settings, cred_state) = store.read_consistent_local(&initial_profile)?;
            let Some(profile) =
                crate::model_route::configured_local_profile(&fresh_settings, &reader.model)?
            else {
                bail!(
                    "Профиль «{}» для чтения изображений не найден; настройте /vision заново",
                    reader.model
                );
            };
            if !crate::model_route::RouteIdentity::same_connection(&initial_profile, &profile) {
                bail!(
                    "Параметры профиля «{}» для чтения изображений изменились в другом процессе; повторите команду",
                    reader.model
                );
            }
            if !profile.local.as_ref().is_some_and(|local| local.vision) {
                bail!(
                    "Профиль «{}» не объявляет изображения (--vision); настройте /vision заново",
                    reader.model
                );
            }
            match cred_state {
                crate::config::CredentialState::Present(credential) => {
                    events.remember(credential.value.clone());
                    crate::provider::ProviderClient::connect(profile, Some(credential.value))?
                }
                crate::config::CredentialState::NotRequired => {
                    crate::provider::ProviderClient::connect(profile, None)?
                }
                crate::config::CredentialState::Missing => bail!(
                    "У профиля «{}» нет ключа; задайте его через rcode local key {} --stdin",
                    reader.model,
                    reader.model
                ),
            }
        }
        kind => {
            let (fresh_settings, cred_opt) = store.read_consistent_cloud(kind)?;
            let credential = cred_opt.context("Нет ключа провайдера для чтения изображений")?;
            if crate::model_route::is_unconfigured_default_custom(
                &fresh_settings,
                kind,
                &credential,
            ) {
                bail!("Провайдер custom не настроен; выполните /connect custom");
            }
            let mut provider =
                crate::model_route::configured_cloud_provider(&fresh_settings, kind)?
                    .with_context(|| {
                        format!("Провайдер {kind} не настроен; выполните /connect {kind}")
                    })?;
            provider.model = reader.model.clone();
            events.remember(credential.value.clone());
            crate::provider::ProviderClient::new(provider, credential.value)?
        }
    };
    client.bind_secret_sink(events.shared_secrets());
    for secret in client.redaction_secrets() {
        events.remember(secret);
    }
    let snapshot = events
        .refresh_and_check_route(store, client.settings())
        .context("Не удалось обновить словарь секретов или проверить маршрут чтения изображений")?;
    let clean_user_text = match user_text {
        Some(raw) if !raw.is_empty() => events
            .frozen_at(&snapshot)
            .redact_idempotent_checked(raw)
            .context("Не удалось применить маскирование секретов к подписи изображения")?,
        _ => String::new(),
    };
    let prompt = prompt(&clean_user_text);
    let mut message = Message::user(&prompt);
    message.images = images.to_vec();
    let messages = [message];
    let no_tools: [crate::protocol::ToolDefinition; 0] = [];
    let mut sink = |_: &str| {};
    let completion = tokio::select! {
        completion = client.complete(&messages, &no_tools, &mut sink) => completion,
        _ = cancel.cancelled() => bail!("Чтение изображения отменено"),
    }?;
    for secret in client.redaction_secrets() {
        events.remember(secret);
    }
    let _ = events.refresh_keys(store);
    let raw_text = completion.content.trim();
    if raw_text.is_empty() {
        bail!("Модель чтения изображений вернула пустой ответ");
    }
    let clean_text = events
        .redact_checked(raw_text)
        .context("Не удалось применить маскирование секретов к описанию изображения")?;
    let trimmed = clean_text.trim().to_owned();
    if trimmed.is_empty() {
        bail!("Модель чтения изображений вернула пустой ответ");
    }
    Ok(trimmed)
}

/// Rewrites the outgoing user message: images are replaced by the reader's
/// transcription so a text-only model never receives image parts.
pub(crate) fn apply_transcription(
    message: &mut Message,
    reader: &Reader,
    description: &str,
    events: &crate::app::Events,
) {
    let raw_prev = message.content.take().unwrap_or_default();
    let mut text = events.redact_idempotent(&raw_prev);
    let safe_model = events.redact(&reader.model);
    text.push_str(&format!(
        "\n\n[Изображения описаны моделью «{safe_model}»]\n"
    ));
    text.push_str(events.redact_idempotent(description.trim()).trim());
    message.content = Some(text);
    message.images.clear();
}

pub(crate) fn settings_text(settings: &Settings) -> String {
    match (&settings.vision.provider, &settings.vision.model) {
        (Some(provider), Some(model)) => format!("{provider} · {model}"),
        _ => "не настроено".to_owned(),
    }
}

/// `/vision`: выбор провайдера и модели для чтения изображений, по аналогии
/// с `/model`. Сохраняет `Settings.vision`; «Выключить» сбрасывает настройку.
pub(crate) async fn choose(
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    events: &mut crate::app::Events,
) -> Result<()> {
    let _ = events.refresh_keys(store);
    notice!(
        "Чтение изображений: {}",
        crate::ui::safe(&events.redact(&settings_text(settings)))
    );
    let kinds = [
        ProviderKind::Local,
        ProviderKind::OpenRouter,
        ProviderKind::Yandex,
        ProviderKind::GigaChat,
        ProviderKind::Custom,
    ];
    let mut choices: Vec<crate::terminal::Choice> = kinds
        .iter()
        .map(|kind| {
            let detail = match kind {
                ProviderKind::Local => format!("профилей: {}", settings.local.profiles.len()),
                _ => match store.credential(*kind) {
                    Ok(Some(_)) => "ключ подключён".to_owned(),
                    _ => "нет ключа — сначала /connect".to_owned(),
                },
            };
            crate::terminal::Choice {
                label: kind.as_str().to_owned(),
                detail,
                enabled: true,
            }
        })
        .collect();
    choices.push(crate::terminal::Choice {
        label: "Выключить чтение изображений".into(),
        detail: "скрины снова пойдут основной модели".into(),
        enabled: true,
    });
    let Some(selected) =
        crate::interactive::choose("Модель чтения изображений · провайдер", &choices, 0, rich)?
    else {
        return Ok(());
    };
    if selected == kinds.len() {
        let updated = store.update_settings(|current| {
            current.vision = crate::config::VisionSettings::default();
            Ok(())
        })?;
        *settings = updated;
        events.emit(
            "vision",
            json!({"version": 1, "provider": null, "model": null}),
        );
        notice!("Чтение изображений выключено.");
        return Ok(());
    }
    let kind = kinds[selected];
    let mut expected_cloud_disk: Option<crate::config::ProviderSettings> = None;
    let mut expected_local_disk: Option<crate::config::ProviderSettings> = None;
    let model = if kind == ProviderKind::Local {
        *settings = store.load()?;
        let _ = events.refresh_keys(store);
        let secret_snap = events.secret_snapshot();
        let mut entries: Vec<(crate::terminal::Choice, crate::config::ProviderSettings)> = settings
            .local
            .profiles
            .keys()
            .filter_map(|name| {
                let profile = crate::model_route::configured_local_profile(settings, name)
                    .ok()
                    .flatten()?;
                if profile.validate().is_err()
                    || profile.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute())
                    || events.redact(name) != *name
                    || events.redact(&profile.model) != profile.model
                    || crate::model_route::ensure_route_free_of_secrets(
                        store,
                        &profile,
                        &secret_snap,
                    )
                    .is_err()
                {
                    return None;
                }
                let has_vision = profile.local.as_ref().is_some_and(|local| local.vision);
                let has_cred = !matches!(
                    store.credential_for(&profile).ok(),
                    None | Some(crate::config::CredentialState::Missing)
                );
                let choice = crate::terminal::Choice {
                    label: name.clone(),
                    detail: if !has_vision {
                        "без --vision (недоступно)".into()
                    } else if !has_cred {
                        "нет ключа (недоступно)".into()
                    } else {
                        "изображения".into()
                    },
                    enabled: has_vision && has_cred,
                };
                Some((choice, profile))
            })
            .collect();
        entries.sort_by(|a, b| a.0.label.cmp(&b.0.label));
        if entries.is_empty() {
            notice!("Локальных профилей нет: rcode local add ИМЯ --vision");
            return Ok(());
        }
        let choices: Vec<crate::terminal::Choice> =
            entries.iter().map(|(c, _)| c.clone()).collect();
        let Some(index) = crate::interactive::choose("Модель чтения · профиль", &choices, 0, rich)?
        else {
            return Ok(());
        };
        expected_local_disk = Some(entries[index].1.clone());
        entries[index].0.label.clone()
    } else {
        let (fresh_settings, cred_opt) = store.read_consistent_cloud(kind)?;
        *settings = fresh_settings;
        let Some(cred) = cred_opt else {
            notice!("У провайдера нет ключа: /connect {}", kind.as_str());
            return Ok(());
        };
        if crate::model_route::is_unconfigured_default_custom(settings, kind, &cred) {
            notice!("Провайдер custom не настроен: /connect custom");
            return Ok(());
        }
        let Some(provider) = crate::model_route::configured_cloud_provider(settings, kind)? else {
            notice!("Провайдер {} не настроен: /connect {}", kind, kind.as_str());
            return Ok(());
        };
        expected_cloud_disk = Some(provider.clone());
        let mut client = local_app::client_with_credential(
            &provider,
            crate::config::CredentialState::Present(cred),
            events,
            "Нет ключа выбранного провайдера",
        )?;
        let _ = events.refresh_keys(store);
        crate::model_route::ensure_connection_free_of_secrets(
            store,
            &provider,
            &events.secret_snapshot(),
        )?;
        let models = tokio::select! {
            models = client.models()=>models?,
            _ = tokio::signal::ctrl_c()=>return Ok(()),
        };
        for secret in client.redaction_secrets() {
            events.remember(secret);
        }
        let _ = events.refresh_keys(store);
        let models: Vec<crate::protocol::ModelInfo> = models
            .into_iter()
            .filter(|m| !m.id.chars().any(char::is_control) && events.redact(&m.id) == m.id)
            .map(|mut m| {
                m.name = crate::ui::safe(&events.redact(&m.name));
                m
            })
            .collect();
        let chosen_id = if models.is_empty() {
            notice!("Каталог моделей пуст; введите ID вручную:");
            crate::ui::line("ID модели", "")?
        } else {
            let mut choices: Vec<crate::terminal::Choice> = models
                .iter()
                .map(|model| crate::terminal::Choice {
                    label: model.name.clone(),
                    detail: match model.supports_images {
                        Some(true) => "изображения".into(),
                        Some(false) => "без изображений".into(),
                        None => String::new(),
                    },
                    enabled: true,
                })
                .collect();
            choices.push(crate::terminal::Choice {
                label: "Ввести ID модели вручную".into(),
                detail: String::new(),
                enabled: true,
            });
            let Some(index) = crate::interactive::choose(
                "Модель чтения изображений · модель",
                &choices,
                0,
                rich,
            )?
            else {
                return Ok(());
            };
            if index == models.len() {
                crate::ui::line("ID модели", "")?
            } else {
                models[index].id.clone()
            }
        };
        let mut check_p = provider.clone();
        check_p.model = chosen_id.clone();
        check_p.validate()?;
        crate::model_route::ensure_route_free_of_secrets(
            store,
            &check_p,
            &events.secret_snapshot(),
        )?;
        chosen_id
    };
    let _ = events.refresh_keys(store);
    let updated = store.update_settings_with_credentials(|current, providers_creds| {
        let live_extra = events.secret_snapshot();
        let route_dict = crate::model_route::build_route_secret_dictionary_from_raw(
            providers_creds.values().cloned(),
            &live_extra,
        )?;
        let safe_model_label = match route_dict.as_ref() {
            Some(dict) => crate::redaction::redact_text_with(dict, &model)
                .unwrap_or_else(|_| "[скрыто]".into()),
            None => model.clone(),
        };
        if kind == ProviderKind::Local {
            let prof = crate::model_route::configured_local_profile(current, &model)?
                .with_context(|| format!("Профиль local «{safe_model_label}» больше не сохранён"))?;
            if !prof.local.as_ref().is_some_and(|local| local.vision) {
                bail!("Профиль local «{safe_model_label}» больше не объявляет --vision");
            }
            if let Some(ref expected) = expected_local_disk
                && !crate::model_route::RouteIdentity::same_connection(expected, &prof)
            {
                bail!(
                    "Параметры подключения локального профиля «{safe_model_label}» изменились в другом процессе; повторите /vision"
                );
            }
            crate::model_route::check_route_against_secret_dictionary(route_dict.as_ref(), &prof)?;
            let cred_state = ConfigStore::local_credential_state_from_snapshot(
                current,
                providers_creds,
                &prof,
            )?;
            if matches!(cred_state, crate::config::CredentialState::Missing) {
                bail!(
                    "Для локального профиля «{safe_model_label}» не настроен ключ: rcode local key {safe_model_label} --stdin"
                );
            }
        } else {
            let mut cur_p = crate::model_route::configured_cloud_provider(current, kind)?
                .unwrap_or_else(|| current.provider(kind));
            if let Some(ref expected) = expected_cloud_disk
                && !crate::model_route::RouteIdentity::same_connection(expected, &cur_p)
            {
                bail!(
                    "Параметры подключения провайдера {kind} изменились в другом процессе; повторите /vision"
                );
            }
            if ConfigStore::cloud_credential_from_map(kind, providers_creds)?.is_none() {
                bail!("Не настроен ключ доступа для провайдера {kind}");
            }
            cur_p.model = model.clone();
            cur_p.validate()?;
            crate::model_route::check_route_against_secret_dictionary(
                route_dict.as_ref(),
                &cur_p,
            )?;
        }
        current.vision = crate::config::VisionSettings {
            provider: Some(kind.as_str().to_owned()),
            model: Some(model.clone()),
        };
        Ok(())
    })?;
    *settings = updated;
    let _ = events.refresh_keys(store);
    events.emit(
        "vision",
        json!({"version": 1, "provider": kind.as_str(), "model": model}),
    );
    notice!(
        "✓ Скрины будут читать: {} · {}",
        kind.as_str(),
        crate::ui::safe(&events.redact(&model))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn yandex_declares_no_images_without_network() {
        let settings = Settings::default().provider(ProviderKind::Yandex);
        let mut client =
            crate::provider::ProviderClient::connect(settings, Some("test".into())).unwrap();
        assert!(!client.declares_images().await);
    }
}
