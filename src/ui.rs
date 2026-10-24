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
    eprintln!("\nПровайдер: 1) Yandex AI Studio  2) GigaChat  3) OpenRouter  4) свой OpenAI API");
    match line("Выбор", "1")?.as_str() {
        "1" | "yandex" => Ok(ProviderKind::Yandex),
        "2" | "gigachat" => Ok(ProviderKind::GigaChat),
        "3" | "openrouter" => Ok(ProviderKind::OpenRouter),
        "4" | "custom" => Ok(ProviderKind::Custom),
        _ => bail!("Выберите номер от 1 до 4"),
    }
}
pub async fn connect(
    store: &ConfigStore,
    settings: &mut Settings,
    kind: Option<ProviderKind>,
    rich: bool,
    ca_override: Option<&std::path::Path>,
) -> Result<ProviderSettings> {
    if !terminal() {
        bail!(
            "Для настройки откройте rcode connect в терминале или задайте ключ через переменную окружения"
        );
    }
    // Only the legacy line/password forms own the suspended terminal. The
    // searchable picker below needs Screen's input and renderer running.
    let (mut p, key, save_key) = {
        let _suspended = crate::screen::suspend()?;
        let kind = match kind {
            Some(k) => k,
            None => select_provider()?,
        };
        let mut p = settings.provider(kind);
        if let Some(ca) = ca_override {
            p.ca_file = Some(ca.to_path_buf());
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
        if kind == ProviderKind::Yandex {
            eprintln!(
                "\nОткройте https://console.yandex.cloud/ и выберите каталог, в котором создан ключ.\n\
             Скопируйте ID под названием каталога или из адреса .../folders/<ID каталога>.\n\
             Инструкция: https://yandex.cloud/ru/docs/resource-manager/operations/folder/get-id"
            );
            let uri = reqwest::Url::parse(&p.model)
                .ok()
                .filter(|u| u.scheme() == "gpt");
            let folder = line(
                "ID каталога (Folder ID) или полный gpt:// URI",
                p.folder_id
                    .as_deref()
                    .or_else(|| uri.as_ref().and_then(|u| u.host_str()))
                    .unwrap_or_default(),
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
            p.base_url = Some(line(
                "Адрес API",
                p.base_url.as_deref().unwrap_or_default(),
            )?);
        }
        if kind == ProviderKind::GigaChat {
            eprintln!(
                "\nИз Sber Studio понадобится Authorization Key; Client ID отдельно не нужен."
            );
            let scope = line("Scope", p.scope.as_deref().unwrap_or("GIGACHAT_API_PERS"))?;
            p.scope = Some(scope);
            eprintln!(
                "Сертификат для GigaChat настраивается автоматически. Собственный CA можно задать через --ca-file."
            );
        }
        p.validate()?;
        let (key, save_key) = if let Some(existing) = store.credential(kind)? {
            eprintln!("Ключ уже доступен: {}", safe(&existing.source));
            if existing.source == "credentials.json"
                && line("Заменить сохранённый ключ? y/N", "n")?.eq_ignore_ascii_case("y")
            {
                (password("Новый ключ: ")?, true)
            } else {
                (existing.value, false)
            }
        } else {
            let key = password(if kind == ProviderKind::Yandex {
                "Секретный ключ AI Studio (ввод скрыт): "
            } else {
                "Ключ (ввод скрыт): "
            })?;
            (key, true)
        };
        crate::config::validate_credential(&key)?;
        (p, key, save_key)
    };

    let mut client = ProviderClient::new(p.clone(), key.clone())?;
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
    let models = connection_models(fetched, &p.model, &key);
    let Some(model) = pick_model(&models, &p, rich)? else {
        return Err(connection_cancelled());
    };
    if model != p.model {
        p.effort = Effort::Auto;
    }
    p.model = model;
    p.validate()?;
    if save_key {
        store.save_credential(p.kind, &key)?;
    }
    let mut updated = settings.clone();
    updated.active = p.kind;
    updated.providers.insert(p.kind.to_string(), p.clone());
    store.save(&updated)?;
    *settings = updated;
    crate::screen::notice("Подключение сохранено. rcode doctor --check проверит доступ к API.");
    Ok(p)
}

fn connection_cancelled() -> anyhow::Error {
    io::Error::new(io::ErrorKind::Interrupted, "Подключение отменено").into()
}

fn connection_models(fetched: Vec<ModelInfo>, current: &str, key: &str) -> Vec<ModelInfo> {
    let mut models = std::collections::BTreeMap::new();
    for mut model in fetched {
        let id = model.id.to_ascii_lowercase();
        let name = reqwest::Url::parse(&id)
            .ok()
            .filter(|uri| uri.scheme() == "gpt")
            .map(|uri| uri.path().trim_start_matches('/').to_owned())
            .unwrap_or_else(|| id.rsplit('/').next().unwrap_or(&id).to_owned());
        if model.id.chars().any(char::is_control)
            || model.id.contains(key)
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
        model.name = safe(&model.name.replace(key, "[скрыто]"));
        models.insert(model.id.clone(), model);
    }
    let mut models = models.into_values().collect::<Vec<_>>();
    if !models.iter().any(|m| m.id == current) {
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

fn pick_model(
    models: &[ModelInfo],
    provider: &ProviderSettings,
    rich: bool,
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
        line("ID модели", &provider.model)?
    } else {
        models[index].id.clone()
    }))
}
pub enum Approval {
    Yes,
    No,
    Cancel,
}
pub fn approve(preview: &str) -> Result<Approval> {
    if let Some(screen) = crate::screen::current() {
        return screen.approve(&safe(preview));
    }
    eprintln!("\n{}", safe(preview));
    let mut editor = rustyline::DefaultEditor::new()?;
    match editor.readline("Разрешить? [y/N] ") {
        Ok(s) => Ok(if matches!(s.trim(), "y" | "Y" | "yes" | "да" | "д") {
            Approval::Yes
        } else {
            Approval::No
        }),
        Err(rustyline::error::ReadlineError::Interrupted) => Ok(Approval::Cancel),
        Err(rustyline::error::ReadlineError::Eof) => Ok(Approval::No),
        Err(e) => Err(e.into()),
    }
}

pub struct CommandHelper;
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
        let prefix = &line[..pos];
        let candidates = crate::terminal::COMMANDS
            .iter()
            .map(|command| command.name)
            .filter(|s| s.starts_with(prefix))
            .map(|s| rustyline::completion::Pair {
                display: s.into(),
                replacement: s.into(),
            })
            .collect();
        Ok((0, candidates))
    }
}
pub fn editor() -> Result<rustyline::Editor<CommandHelper, rustyline::history::DefaultHistory>> {
    let mut editor = rustyline::Editor::new()?;
    editor.set_helper(Some(CommandHelper));
    Ok(editor)
}

// Disable echo before displaying the prompt: rpassword displays its prompt
// first, which can echo an immediately pasted key before it configures the TTY.
fn password(prompt: &str) -> Result<String> {
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
    Ok(format!(
        "Shell с правами пользователя; каталог: {}\nКоманда в JSON-записи (\\n означает перевод строки):\n{}\nИзменения shell не управляются /undo.",
        safe(&serde_json::to_string(&root.display().to_string())?),
        quoted
    ))
}
