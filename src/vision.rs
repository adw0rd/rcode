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
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<String> {
    if images.is_empty() {
        bail!("Нет изображений для описания");
    }
    let settings: Settings = store.load()?;
    let mut client = match reader.kind {
        ProviderKind::Local => {
            let Some(profile) = settings.local.profiles.get(&reader.model) else {
                bail!(
                    "Профиль «{}» для чтения изображений не найден; настройте /vision заново",
                    reader.model
                );
            };
            if !profile.local.as_ref().is_some_and(|local| local.vision) {
                bail!(
                    "Профиль «{}» не объявляет изображения (--vision); настройте /vision заново",
                    reader.model
                );
            }
            match store.credential_for(profile)? {
                crate::config::CredentialState::Present(credential) => {
                    crate::provider::ProviderClient::connect(
                        profile.clone(),
                        Some(credential.value),
                    )?
                }
                crate::config::CredentialState::NotRequired => {
                    crate::provider::ProviderClient::connect(profile.clone(), None)?
                }
                crate::config::CredentialState::Missing => bail!(
                    "У профиля «{}» нет ключа; задайте его через rcode local key {} --stdin",
                    reader.model,
                    reader.model
                ),
            }
        }
        kind => {
            let mut provider = settings.provider(kind);
            provider.model = reader.model.clone();
            let credential = store
                .credential(kind)?
                .context("Нет ключа провайдера для чтения изображений")?;
            crate::provider::ProviderClient::new(provider, credential.value)?
        }
    };
    let prompt = prompt(user_text.unwrap_or_default());
    let mut message = Message::user(&prompt);
    message.images = images.to_vec();
    let messages = [message];
    let no_tools: [crate::protocol::ToolDefinition; 0] = [];
    let mut sink = |_: &str| {};
    let completion = tokio::select! {
        completion = client.complete(&messages, &no_tools, &mut sink) => completion,
        _ = cancel.cancelled() => bail!("Чтение изображения отменено"),
    }?;
    let text = completion.content.trim().to_owned();
    if text.is_empty() {
        bail!("Модель чтения изображений вернула пустой ответ");
    }
    Ok(text)
}

/// Rewrites the outgoing user message: images are replaced by the reader's
/// transcription so a text-only model never receives image parts.
pub(crate) fn apply_transcription(message: &mut Message, reader: &Reader, description: &str) {
    let mut text = message.content.take().unwrap_or_default();
    text.push_str(&format!(
        "\n\n[Изображения описаны моделью «{}»]\n",
        reader.model
    ));
    text.push_str(description.trim());
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
    notice!(
        "Чтение изображений: {}",
        crate::ui::safe(&settings_text(settings))
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
        settings.vision = crate::config::VisionSettings::default();
        store.save(settings)?;
        events.emit(
            "vision",
            json!({"version": 1, "provider": null, "model": null}),
        );
        notice!("Чтение изображений выключено.");
        return Ok(());
    }
    let kind = kinds[selected];
    let model = if kind == ProviderKind::Local {
        let mut profiles: Vec<crate::terminal::Choice> = settings
            .local
            .profiles
            .iter()
            .map(|(name, profile)| crate::terminal::Choice {
                label: name.clone(),
                detail: if profile.local.as_ref().is_some_and(|local| local.vision) {
                    "изображения".into()
                } else {
                    "без --vision (недоступно)".into()
                },
                enabled: profile.local.as_ref().is_some_and(|local| local.vision),
            })
            .collect();
        profiles.sort_by(|a, b| a.label.cmp(&b.label));
        if profiles.is_empty() {
            notice!("Локальных профилей нет: rcode local add ИМЯ --vision");
            return Ok(());
        }
        let Some(index) =
            crate::interactive::choose("Модель чтения · профиль", &profiles, 0, rich)?
        else {
            return Ok(());
        };
        profiles[index].label.clone()
    } else {
        if store.credential(kind)?.is_none() {
            notice!("У провайдера нет ключа: /connect {}", kind.as_str());
            return Ok(());
        }
        let provider = settings.provider(kind);
        let mut client =
            local_app::client(store, &provider, events, "Нет ключа выбранного провайдера")?;
        let models = tokio::select! {
            models = client.models()=>models?,
            _ = tokio::signal::ctrl_c()=>return Ok(()),
        };
        if models.is_empty() {
            notice!("Каталог моделей пуст; введите ID вручную:");
            return Ok(());
        }
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
        let Some(index) =
            crate::interactive::choose("Модель чтения изображений · модель", &choices, 0, rich)?
        else {
            return Ok(());
        };
        if index == models.len() {
            crate::ui::line("ID модели", "")?
        } else {
            models[index].id.clone()
        }
    };
    settings.vision = crate::config::VisionSettings {
        provider: Some(kind.as_str().to_owned()),
        model: Some(model.clone()),
    };
    store.save(settings)?;
    events.emit(
        "vision",
        json!({"version": 1, "provider": kind.as_str(), "model": model}),
    );
    notice!(
        "✓ Скрины будут читать: {} · {}",
        kind.as_str(),
        crate::ui::safe(&model)
    );
    Ok(())
}
