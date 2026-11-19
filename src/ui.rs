use crate::{
    config::{ConfigStore, Effort, ProviderKind, ProviderSettings, Settings},
    protocol::ModelInfo,
    provider::ProviderClient,
    terminal::{self, Choice},
};
use anyhow::{Result, bail};
use std::io::{self, IsTerminal};

pub fn safe(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if matches!(c as u32,0x00ad|0x061c|0x200b..=0x200f|0x2028..=0x202e|0x2060..=0x206f|0xfeff|0xfff9..=0xfffb|0x110bd|0x110cd|0x13430..=0x1343f|0x1bca0..=0x1bca3|0x1d173..=0x1d17a|0xe0001|0xe0020..=0xe007f)
        {
            result.extend(c.escape_unicode());
        } else if !c.is_control() || c == '\n' || c == '\t' {
            result.push(c);
        }
    }
    result
}
pub fn terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}
pub fn line(label: &str, default: &str) -> Result<String> {
    let _suspended = crate::screen::suspend()?;
    let prompt = format!(
        "{}{}: ",
        safe(label),
        if default.is_empty() {
            String::new()
        } else {
            format!(" [{}]", safe(default))
        }
    );
    let mut editor = rustyline::DefaultEditor::new()?;
    let input = editor.readline(&prompt).map_err(|e| match e {
        rustyline::error::ReadlineError::Interrupted => {
            anyhow::Error::new(io::Error::new(io::ErrorKind::Interrupted, "Ввод прерван"))
        }
        other => anyhow::Error::new(other),
    })?;
    let input = input.trim();
    Ok(if input.is_empty() {
        default.to_owned()
    } else {
        input.to_owned()
    })
}
pub fn select_provider() -> Result<ProviderKind> {
    let _suspended = crate::screen::suspend()?;
    eprintln!(
        "\nПровайдер: 1) Yandex AI Studio  2) GigaChat  3) OpenRouter  4) свой OpenAI API  5) локальная модель (Ollama, llama.cpp, MLX, LM Studio)"
    );
    match line("Выбор", "1")?.as_str() {
        "1" | "yandex" => Ok(ProviderKind::Yandex),
        "2" | "gigachat" => Ok(ProviderKind::GigaChat),
        "3" | "openrouter" => Ok(ProviderKind::OpenRouter),
        "4" | "custom" => Ok(ProviderKind::Custom),
        "5" | "local" => Ok(ProviderKind::Local),
        _ => bail!("Выберите номер от 1 до 5"),
    }
}
pub async fn connect(
    store: &ConfigStore,
    settings: &mut Settings,
    kind: Option<ProviderKind>,
    rich: bool,
    ca_override: Option<&std::path::Path>,
) -> Result<ProviderSettings> {
    connect_with_secrets(store, settings, kind, rich, ca_override, &[], None).await
}

pub(crate) async fn connect_with_secrets(
    store: &ConfigStore,
    settings: &mut Settings,
    kind: Option<ProviderKind>,
    rich: bool,
    ca_override: Option<&std::path::Path>,
    caller_secrets: &[String],
    shared_sink: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
) -> Result<ProviderSettings> {
    if !terminal() {
        bail!(
            "Для настройки откройте rcode connect в терминале или задайте ключ через переменную окружения"
        );
    }
    let kind = match kind {
        Some(kind) => kind,
        None => {
            let _suspended = crate::screen::suspend()?;
            select_provider()?
        }
    };
    if kind == ProviderKind::Local {
        return crate::local_ui::connect_with_secrets(
            store,
            settings,
            rich,
            ca_override,
            caller_secrets,
            shared_sink,
        )
        .await;
    }
    // Only the legacy line/password forms own the suspended terminal. The
    // searchable picker below needs Screen's input and renderer running.
    *settings = store.load()?;
    let initial_disk = crate::model_route::configured_cloud_provider(settings, kind)?
        .unwrap_or_else(|| settings.provider(kind));
    let (mut p, key, save_key) = {
        let _suspended = crate::screen::suspend()?;
        let mut p = initial_disk.clone();
        if let Some(ca) = ca_override {
            p.ca_file = Some(crate::model_route::normalize_ca_path(ca));
        } else if p.ca_file.as_ref().is_some_and(|ca| !ca.is_absolute()) {
            let ca_input = line(
                "Абсолютный путь к CA-файлу (пусто — сбросить на системный)",
                "",
            )?;
            let trimmed = ca_input.trim();
            if trimmed.is_empty() {
                p.ca_file = None;
            } else {
                let candidate = std::path::PathBuf::from(trimmed);
                if !candidate.is_absolute() {
                    anyhow::bail!("Путь к CA-файлу должен быть абсолютным");
                }
                p.ca_file = Some(crate::model_route::normalize_ca_path(&candidate));
            }
        }
        let link = match kind {
            ProviderKind::Yandex => "https://aistudio.yandex.cloud/ — создать API-ключ AI Studio",
            ProviderKind::GigaChat => {
                "https://developers.sber.ru/studio/ — GigaChat API: ключ авторизации (Authorization key)"
            }
            ProviderKind::OpenRouter => "https://openrouter.ai/settings/keys — создать API key",
            ProviderKind::Custom => {
                "OpenAI-совместимый сервер: /v1/chat/completions с function calling"
            }
            ProviderKind::Local => "Локальный OpenAI-совместимый сервер на 127.0.0.1",
        };
        eprintln!(
            "\n{}\nКлюч вводится скрыто и хранится локально отдельно от настроек.",
            link
        );
        if kind == ProviderKind::Yandex {
            eprintln!(
                "\nИз окна создания API-ключа понадобится «Секретный ключ».\n\
             «Идентификатор API-ключа» вводить не нужно: это не ID каталога.\n\
             Для API также нужен ID каталога Yandex Cloud, в котором создан ключ.\n\
             Модель выберете из списка после авторизации. Можно также указать полный gpt:// URI."
            );
        }
        let safe_prompt_default = |candidate: &str, fallback: &str| -> String {
            if candidate.is_empty() {
                return fallback.to_owned();
            }
            let redacted =
                crate::model_route::redact_route_display_field(store, caller_secrets, candidate);
            if redacted == candidate {
                candidate.to_owned()
            } else {
                fallback.to_owned()
            }
        };
        if kind == ProviderKind::Yandex {
            eprintln!(
                "\nОткройте https://console.yandex.cloud/ и выберите каталог, в котором создан ключ.\n\
             Скопируйте ID под названием каталога или из адреса .../folders/<ID каталога>.\n\
             Инструкция: https://yandex.cloud/ru/docs/resource-manager/operations/folder/get-id"
            );
            let uri = reqwest::Url::parse(&p.model)
                .ok()
                .filter(|u| u.scheme() == "gpt");
            let raw_folder_default = p
                .folder_id
                .as_deref()
                .or_else(|| uri.as_ref().and_then(|u| u.host_str()))
                .unwrap_or_default();
            let folder_default = safe_prompt_default(raw_folder_default, "");
            let folder = line(
                "ID каталога (Folder ID) или полный gpt:// URI",
                &folder_default,
            )?;
            if folder.starts_with("gpt://") {
                p.model = folder;
                p.validate()?;
                p.folder_id = reqwest::Url::parse(&p.model)?.host_str().map(str::to_owned);
            } else {
                if let Some(uri) = uri {
                    p.model = uri.path().trim_start_matches('/').into();
                }
                p.folder_id = Some(folder);
            }
        }
        if kind == ProviderKind::Custom {
            let base_default = safe_prompt_default(
                p.base_url.as_deref().unwrap_or_default(),
                "http://localhost:11434/v1",
            );
            p.base_url = Some(line("Адрес API", &base_default)?);
        }
        if kind == ProviderKind::GigaChat {
            eprintln!(
                "\nИз Sber Studio понадобится Authorization Key; Client ID отдельно не нужен."
            );
            let scope_default = safe_prompt_default(
                p.scope.as_deref().unwrap_or("GIGACHAT_API_PERS"),
                "GIGACHAT_API_PERS",
            );
            let scope = line("Scope", &scope_default)?;
            p.scope = Some(scope);
            eprintln!(
                "Сертификат для GigaChat настраивается автоматически. Собственный CA можно задать через --ca-file."
            );
        }
        p.validate()?;
        let (latest_disk, existing_cred, persisted_on_disk) =
            store.read_consistent_cloud_with_presence(kind)?;
        let configured_on_disk = crate::model_route::configured_cloud_provider(&latest_disk, kind)?;
        let current_disk = configured_on_disk
            .clone()
            .unwrap_or_else(|| latest_disk.provider(kind));
        if !crate::model_route::RouteIdentity::disk_unchanged(&initial_disk, &current_disk) {
            anyhow::bail!(
                "Конфигурация провайдера {kind} изменилась в другом процессе; повторите /connect"
            );
        }
        let connection_changed = !persisted_on_disk
            || configured_on_disk
                .as_ref()
                .is_none_or(|saved| !crate::model_route::RouteIdentity::same_connection(saved, &p));
        let (key, save_key) = match existing_cred {
            Some(existing) if !(connection_changed && existing.source == "credentials.json") => {
                eprintln!("Ключ уже доступен: {}", safe(&existing.source));
                if existing.source == "credentials.json"
                    && line("Заменить сохранённый ключ? y/N", "n")?.eq_ignore_ascii_case("y")
                {
                    (password("Новый ключ: ")?, true)
                } else {
                    (existing.value, false)
                }
            }
            _ => {
                if connection_changed {
                    eprintln!(
                        "Параметры подключения изменились; сохранённый ключ прежнего адреса не переносится."
                    );
                }
                let key = password(if kind == ProviderKind::Yandex {
                    "Секретный ключ AI Studio (ввод скрыт): "
                } else {
                    "Ключ (ввод скрыт): "
                })?;
                (key, true)
            }
        };
        crate::config::validate_credential(&key)?;
        let after_prompt_settings = store.load()?;
        let after_prompt_disk =
            crate::model_route::configured_cloud_provider(&after_prompt_settings, kind)?
                .unwrap_or_else(|| after_prompt_settings.provider(kind));
        if !crate::model_route::RouteIdentity::disk_unchanged(&initial_disk, &after_prompt_disk) {
            anyhow::bail!(
                "Конфигурация провайдера {kind} изменилась в другом процессе; повторите /connect"
            );
        }
        (p, key, save_key)
    };

    let mut client = ProviderClient::new(p.clone(), key.clone())?;
    let connect_secrets =
        shared_sink.unwrap_or_else(|| std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    {
        let mut guard = connect_secrets.lock().unwrap_or_else(|e| e.into_inner());
        crate::redaction::merge_secret_variants(&mut guard, caller_secrets);
        crate::redaction::push_secret_variants(&mut guard, &key);
    }
    client.bind_secret_sink(std::sync::Arc::clone(&connect_secrets));
    let initial_extra = connect_secrets
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    crate::model_route::ensure_connection_free_of_secrets(store, &p, &initial_extra)?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let screen = crate::screen::current();
    if let Some(screen) = &screen {
        screen.bind_cancel(cancel.clone());
        screen.busy("Получаю список моделей");
    } else {
        eprintln!("Получаю список моделей…");
    }
    let catalog = tokio::select! {
        value = tokio::time::timeout(std::time::Duration::from_secs(20), client.models()) =>
            Some(value.unwrap_or_else(|_| Err(anyhow::anyhow!("API не ответил за 20 секунд")))),
        _ = tokio::signal::ctrl_c() => None,
        _ = cancel.cancelled() => None,
    };
    if let Some(screen) = &screen {
        screen.pause();
    }
    let fetched = match catalog {
        None => return Err(connection_cancelled()),
        Some(Ok(models)) => models,
        Some(Err(error)) => {
            crate::screen::notice(format!(
                "Каталог моделей недоступен: {}. Доступ к выбранной вручную модели не проверен.",
                safe(&format!("{error:#}").replace(&key, "[скрыто]"))
            ));
            Vec::new()
        }
    };
    let client_secrets = client.redaction_secrets();
    let collect_live_secrets = || {
        let mut live = connect_secrets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for secret in &client_secrets {
            crate::redaction::push_secret_variants(&mut live, secret);
        }
        crate::redaction::push_secret_variants(&mut live, &key);
        live
    };
    let secret_dict =
        crate::model_route::build_route_secret_dictionary(store, &collect_live_secrets())?;
    let models = connection_models_filtered(fetched, &p.model, &key, secret_dict.as_ref());
    let Some(model) = pick_model(&models, &p, rich, || {
        crate::model_route::ensure_route_free_of_secrets(store, &p, &collect_live_secrets()).is_ok()
    })?
    else {
        return Err(connection_cancelled());
    };
    if model != p.model {
        p.effort = Effort::Auto;
    }
    p.model = model;
    p.validate()?;
    crate::model_route::ensure_route_free_of_secrets(store, &p, &collect_live_secrets())?;
    let updated = store.commit_cloud_connection_with_secrets(
        &initial_disk,
        &p,
        &key,
        save_key,
        collect_live_secrets,
    )?;
    let saved = crate::model_route::configured_cloud_provider(&updated, p.kind)?.unwrap_or(p);
    *settings = updated;
    crate::screen::notice("Подключение сохранено. rcode doctor --check проверит доступ к API.");
    Ok(saved)
}

fn connection_cancelled() -> anyhow::Error {
    io::Error::new(io::ErrorKind::Interrupted, "Подключение отменено").into()
}

#[cfg(test)]
fn connection_models(fetched: Vec<ModelInfo>, current: &str, key: &str) -> Vec<ModelInfo> {
    connection_models_filtered(fetched, current, key, None)
}

fn connection_models_filtered(
    fetched: Vec<ModelInfo>,
    current: &str,
    key: &str,
    secret_dict: Option<&crate::redaction::SecretDictionary>,
) -> Vec<ModelInfo> {
    let contains_secret = |text: &str| -> bool {
        text.contains(key)
            || secret_dict.is_some_and(|dict| {
                crate::redaction::redact_text_with(dict, text)
                    .ok()
                    .as_deref()
                    != Some(text)
            })
    };
    let mut models = std::collections::BTreeMap::new();
    for mut model in fetched {
        let id = model.id.to_ascii_lowercase();
        let name = reqwest::Url::parse(&id)
            .ok()
            .filter(|uri| uri.scheme() == "gpt")
            .map(|uri| uri.path().trim_start_matches('/').to_owned())
            .unwrap_or_else(|| id.rsplit('/').next().unwrap_or(&id).to_owned());
        if model.id.chars().any(char::is_control)
            || contains_secret(&model.id)
            || id.starts_with("embeddings")
            || id.starts_with("emb://")
            || id.starts_with("art://")
            || name.starts_with("speech-realtime")
            || [
                "text-embedding-",
                "whisper-",
                "tts-",
                "dall-e-",
                "gpt-image-",
                "sora-",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let masked_name = if let Some(dict) = secret_dict {
            crate::redaction::redact_text_idempotent_with(
                dict,
                &model.name.replace(key, "[скрыто]"),
            )
            .unwrap_or_else(|_| "[скрыто]".into())
        } else {
            model.name.replace(key, "[скрыто]")
        };
        model.name = safe(&masked_name);
        models.insert(model.id.clone(), model);
    }
    let mut models = models.into_values().collect::<Vec<_>>();
    if let Some(index) = models.iter().position(|m| m.id == current) {
        models[..=index].rotate_right(1);
    } else if !current.is_empty() && !contains_secret(current) {
        models.insert(
            0,
            ModelInfo {
                id: current.into(),
                name: "Модель из настроек · доступ не проверен".into(),
                ..ModelInfo::default()
            },
        );
    }
    models
}

pub(crate) fn pick_model(
    models: &[ModelInfo],
    provider: &ProviderSettings,
    rich: bool,
    is_safe_default: impl FnOnce() -> bool,
) -> Result<Option<String>> {
    let mut choices = models
        .iter()
        .map(|m| {
            let mut detail = m.id.clone();
            if let Some(context) = m.context_length {
                detail.push_str(&format!(" · контекст {context}"));
            }
            if m.supports_tools == Some(false) {
                detail.push_str(" · нет вызова инструментов");
            }
            Choice {
                label: m.name.clone(),
                detail,
                enabled: m.supports_tools != Some(false),
            }
        })
        .collect::<Vec<_>>();
    choices.push(Choice {
        label: "Ввести ID модели вручную".into(),
        detail: "для новых или отсутствующих в каталоге моделей".into(),
        enabled: true,
    });
    let current = models
        .iter()
        .position(|m| m.id == provider.model)
        .unwrap_or_default();
    let title = format!("Выберите модель · {}", provider.kind);
    let selected = if rich && terminal::supported() {
        terminal::select(&title, &choices, current)?
    } else {
        // Keep all numbered-form output in the same suspended terminal.
        let _suspended = crate::screen::suspend()?;
        eprintln!("\n{title}");
        for (i, choice) in choices.iter().enumerate() {
            eprintln!(
                "  {}) {} · {}{}",
                i + 1,
                safe(&choice.label),
                safe(&choice.detail),
                if choice.enabled {
                    ""
                } else {
                    " (недоступно)"
                }
            );
        }
        loop {
            let answer = line("Номер (0 — отмена)", &(current + 1).to_string())?;
            if answer == "0" {
                break None;
            }
            if let Ok(number) = answer.parse::<usize>()
                && let Some(index) = number.checked_sub(1)
                && choices.get(index).is_some_and(|c| c.enabled)
            {
                break Some(index);
            }
            eprintln!(
                "Выберите доступный номер от 1 до {} или 0 для отмены",
                choices.len()
            );
        }
    };
    let Some(index) = selected else {
        return Ok(None);
    };
    Ok(Some(if index == models.len() {
        let manual_default = if models.iter().any(|m| m.id == provider.model) && is_safe_default() {
            provider.model.as_str()
        } else {
            ""
        };
        line("ID модели", manual_default)?
    } else {
        models[index].id.clone()
    }))
}
pub enum Approval {
    Yes,
    No,
    /// «Разрешить похожие»: сохранить правило для этого проекта.
    Always,
    Cancel,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalPreview {
    before: String,
    code: Option<String>,
    after: String,
}
impl ApprovalPreview {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            before: text.into(),
            code: None,
            after: String::new(),
        }
    }
    pub(crate) fn shell(before: String, code: String, after: String) -> Self {
        Self {
            before,
            code: Some(code),
            after,
        }
    }
    pub(crate) fn prepend_before(&mut self, text: &str) {
        if self.before.is_empty() {
            self.before.push_str(text);
        } else {
            self.before = format!("{text}\n{}", self.before);
        }
    }
    pub(crate) fn append_after(&mut self, text: &str) {
        if self.after.is_empty() {
            self.after.push_str(text);
        } else {
            self.after.push('\n');
            self.after.push_str(text);
        }
    }
    pub(crate) fn redact(mut self, mut redact: impl FnMut(&str) -> String) -> Self {
        self.before = redact(&self.before);
        self.code = self.code.map(|code| redact(&code));
        self.after = redact(&self.after);
        self
    }
    pub(crate) fn before(&self) -> &str {
        &self.before
    }
    pub(crate) fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
    pub(crate) fn after(&self) -> &str {
        &self.after
    }
    pub(crate) fn display(&self) -> String {
        let Some(code) = &self.code else {
            return format!("{}{}", self.before, self.after);
        };
        let fence = code_fence(code);
        let command_end = if code.is_empty() || code.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        format!(
            "{}\n{fence}sh\n{code}{command_end}{fence}{}",
            self.before,
            if self.after.is_empty() {
                String::new()
            } else {
                format!("\n{}", self.after)
            }
        )
    }
}
pub(crate) fn code_block_markdown(language: &str, code: &str) -> String {
    let fence = code_fence(code);
    let command_end = if code.is_empty() || code.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    format!("{fence}{language}\n{code}{command_end}{fence}\n")
}
fn code_fence(code: &str) -> String {
    let longest_backticks = code
        .split('\n')
        .map(|line| {
            let mut longest = 0;
            let mut run = 0;
            for character in line.chars() {
                if character == '`' {
                    run += 1;
                    longest = longest.max(run);
                } else {
                    run = 0;
                }
            }
            longest
        })
        .max()
        .unwrap_or_default();
    "`".repeat(3.max(longest_backticks + 1))
}
pub fn approve(preview: &str, always: Option<&str>) -> Result<Approval> {
    approve_preview(ApprovalPreview::plain(safe(preview)), always)
}
pub fn approve_preview(preview: ApprovalPreview, always: Option<&str>) -> Result<Approval> {
    if let Some(screen) = crate::screen::current() {
        return screen.approve_preview(&preview, always);
    }
    eprintln!("\n{}", safe(&preview.display()));
    let hint = match always {
        Some(token) => format!(
            "Разрешить? [y/N/a] (a — разрешить «{}» всегда) ",
            safe(token)
        ),
        None => "Разрешить? [y/N] ".to_owned(),
    };
    let mut editor = rustyline::DefaultEditor::new()?;
    match editor.readline(&hint) {
        Ok(s) => Ok(if matches!(s.trim(), "a" | "A" | "ф" | "Ф" | "always") {
            Approval::Always
        } else if matches!(s.trim(), "y" | "Y" | "yes" | "да" | "д") {
            Approval::Yes
        } else {
            Approval::No
        }),
        Err(rustyline::error::ReadlineError::Interrupted) => Ok(Approval::Cancel),
        Err(rustyline::error::ReadlineError::Eof) => Ok(Approval::No),
        Err(e) => Err(e.into()),
    }
}

pub struct CommandHelper {
    extra: Vec<crate::terminal::MenuCommand>,
}
impl rustyline::Helper for CommandHelper {}
impl rustyline::validate::Validator for CommandHelper {}
impl rustyline::highlight::Highlighter for CommandHelper {}
impl rustyline::hint::Hinter for CommandHelper {
    type Hint = String;
}
impl rustyline::completion::Completer for CommandHelper {
    type Candidate = rustyline::completion::Pair;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, matches) = crate::terminal::complete_menu(line, pos, &self.extra);
        let candidates = matches
            .into_iter()
            .map(|(display, replacement)| rustyline::completion::Pair {
                display,
                replacement,
            })
            .collect();
        Ok((start, candidates))
    }
}
pub fn editor() -> Result<rustyline::Editor<CommandHelper, rustyline::history::DefaultHistory>> {
    editor_with_menu(&[])
}
pub fn editor_with_menu(
    extra: &[crate::terminal::MenuCommand],
) -> Result<rustyline::Editor<CommandHelper, rustyline::history::DefaultHistory>> {
    let config = rustyline::Config::builder()
        .max_history_size(crate::terminal::MAX_HISTORY)?
        .build();
    let mut editor = rustyline::Editor::with_config(config)?;
    editor.set_helper(Some(CommandHelper {
        extra: extra.to_vec(),
    }));
    Ok(editor)
}

// Disable echo before displaying the prompt: rpassword displays its prompt
// first, which can echo an immediately pasted key before it configures the TTY.
pub(crate) fn password(prompt: &str) -> Result<String> {
    let _suspended = crate::screen::suspend()?;
    let _echo = password_echo::Guard::new()?;
    Ok(rpassword::prompt_password(prompt)?)
}

#[cfg(unix)]
mod password_echo {
    use std::{
        fs::{File, OpenOptions},
        io,
        os::fd::AsRawFd,
    };
    pub struct Guard {
        tty: File,
        original: libc::termios,
    }
    impl Guard {
        pub fn new() -> io::Result<Self> {
            let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: tty is an open terminal and original points to writable termios storage.
            if unsafe { libc::tcgetattr(tty.as_raw_fd(), original.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful tcgetattr initialized original.
            let original = unsafe { original.assume_init() };
            let mut hidden = original;
            hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
            // SAFETY: hidden is initialized and tty remains open for the entire guard.
            if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { tty, original })
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: tty is still open; restore exactly the mode saved by tcgetattr.
            unsafe {
                libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSANOW, &self.original);
            }
        }
    }
}
#[cfg(windows)]
mod password_echo {
    use std::{ffi::c_void, io};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(id: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }
    pub struct Guard {
        handle: *mut c_void,
        original: u32,
    }
    impl Guard {
        pub fn new() -> io::Result<Self> {
            // SAFETY: STD_INPUT_HANDLE is a documented constant; GetConsoleMode validates it.
            let handle = unsafe { GetStdHandle(-10_i32 as u32) };
            let mut original = 0;
            // SAFETY: original is writable and handle is only passed to console API functions.
            if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: valid console handle; clear ENABLE_ECHO_INPUT before displaying the prompt.
            if unsafe { SetConsoleMode(handle, original & !0x0004) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle, original })
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: restore the mode of the still-open standard console handle.
            unsafe {
                SetConsoleMode(self.handle, self.original);
            }
        }
    }
}
#[cfg(not(any(unix, windows)))]
mod password_echo {
    pub struct Guard;
    impl Guard {
        pub fn new() -> std::io::Result<Self> {
            Ok(Self)
        }
    }
}

pub fn shell_preview(root: &std::path::Path, args: &serde_json::Value) -> Result<String> {
    Ok(shell_preview_content(root, args)?.display())
}

pub fn shell_preview_content(
    root: &std::path::Path,
    args: &serde_json::Value,
) -> Result<ApprovalPreview> {
    let command = args
        .get("command")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Отсутствует команда"))?;
    let quoted = safe(&serde_json::to_string(command)?);
    if quoted.len() > 512 {
        bail!(
            "Команда слишком длинная для ручного подтверждения (512 байт отображения). Разбей её на короткие шаги; для доверенных задач доступен явный --allow-shell."
        );
    }
    if command.split('\n').count() > 12 {
        bail!(
            "Команда слишком длинная для ручного подтверждения (более 12 строк). Разбейте её на короткие шаги; для доверенных задач доступен явный --allow-shell."
        );
    }
    let mut visible_command = String::new();
    for character in command.chars() {
        if character == '\n' {
            visible_command.push('\n');
        } else if character.is_control() {
            visible_command.extend(character.escape_default());
        } else {
            visible_command.push_str(&safe(&character.to_string()));
        }
    }
    let cwd = safe(&serde_json::to_string(&root.display().to_string())?);
    Ok(ApprovalPreview::shell(
        format!("Shell с правами пользователя.\nКаталог: {cwd}\nКоманда:"),
        visible_command,
        "Изменения shell не управляются /undo.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_catalog_starts_with_the_saved_model() {
        let models = ["alpha", "omega", "beta"].map(|id| ModelInfo {
            id: id.into(),
            ..ModelInfo::default()
        });
        let sorted = connection_models(models.to_vec(), "omega", "private-key");
        assert_eq!(
            sorted.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["omega", "alpha", "beta"]
        );
        let missing = connection_models(models.to_vec(), "missing", "private-key");
        assert_eq!(missing[0].id, "missing");
    }
}
