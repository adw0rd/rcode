//! Инструмент `web_search`: веб-поиск через API провайдера по выбору
//! пользователя (Yandex Search API, Brave, Tavily). Только чтение: GET/POST
//! к внешнему API, ключ — из `credentials.json`, не в аргументах и не в логах.
//! Ключ уходит только на адрес своего провайдера. Если поиск не настроен,
//! интерактивному пользователю предлагается подключить один из провайдеров.
use crate::{
    config::{ConfigStore, Settings, WebSearchSettings},
    protocol::{ToolDefinition, ToolOutcome},
    ui,
};

macro_rules! notice {
    ($($arg:tt)*) => {
        crate::screen::notice(format!($($arg)*))
    };
}
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::io::IsTerminal;
use std::sync::OnceLock;

pub(crate) const TOOL_NAME: &str = "web_search";
pub(crate) const CREDENTIAL_ID: &str = "websearch";
/// Results admitted to the receipt; each snippet is clipped.
const MAX_RESULTS: usize = 10;
const MAX_URL_CHARS: usize = 300;
const MAX_TITLE_CHARS: usize = 200;
const MAX_SNIPPET_CHARS: usize = 600;
const MIN_KEY_CHARS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Provider {
    Yandex,
    Brave,
    Tavily,
}

impl Provider {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "yandex" => Some(Self::Yandex),
            "brave" => Some(Self::Brave),
            "tavily" => Some(Self::Tavily),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Yandex => "yandex",
            Self::Brave => "brave",
            Self::Tavily => "tavily",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Yandex => "Yandex Search API (Yandex Cloud)",
            Self::Brave => "Brave Search API",
            Self::Tavily => "Tavily",
        }
    }

    fn all() -> [Self; 3] {
        [Self::Yandex, Self::Brave, Self::Tavily]
    }
}

#[derive(Clone)]
pub(crate) struct Config {
    provider: Provider,
    folder_id: Option<String>,
    base_url: Option<String>,
    key: String,
}

pub(crate) fn definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_NAME.into(),
        description: "Поиск в интернете через настроенный поисковый API (Yandex Search API, Brave или Tavily). Только чтение; без запросов разрешений. Если поиск не настроен, попросите пользователя выполнить `rcode websearch provider ИМЯ` и передать ключ через `rcode websearch key --stdin`."
            .into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 400},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 20}
            },
            "required": ["query"],
            "additionalProperties": false
        }),
    }
}

/// Reads the configured provider and its key; `None` without configuration.
pub(crate) fn resolve(store: &ConfigStore) -> Result<Option<Config>> {
    let settings: Settings = store.load()?;
    let configured = &settings.websearch;
    let Some(name) = configured.provider.as_deref() else {
        return Ok(None);
    };
    let Some(provider) = Provider::parse(name) else {
        return Ok(None);
    };
    let Some(key) = store.named_credential(CREDENTIAL_ID)? else {
        return Ok(None);
    };
    Ok(Some(Config {
        provider,
        folder_id: configured.folder_id.clone(),
        base_url: configured.base_url.clone(),
        key,
    }))
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("конфигурация HTTP-клиента web_search")
    })
}

struct Request {
    method: &'static str,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn build_request(config: &Config, query: &str, max: usize) -> Result<Request, String> {
    let base = match &config.base_url {
        Some(base) => base.trim().trim_end_matches('/').to_owned(),
        None => match config.provider {
            Provider::Yandex => "https://yandex.cloud/search/v2/web/search".to_owned(),
            Provider::Brave => "https://api.search.brave.com/res/v1/web/search".to_owned(),
            Provider::Tavily => "https://api.tavily.com/search".to_owned(),
        },
    };
    if !base.starts_with("https://") && !base.starts_with("http://127.0.0.1") {
        return Err("Адрес провайдера должен быть https или http://127.0.0.1".into());
    }
    let auth = config.key.clone();
    Ok(match config.provider {
        Provider::Yandex => {
            let mut query_value = json!({
                "searchType": "SEARCH_TYPE_WEB",
                "queryText": query,
            });
            if let Some(folder) = &config.folder_id {
                query_value["folderId"] = json!(folder);
            }
            Request {
                method: "POST",
                url: base,
                headers: vec![
                    ("Authorization".to_owned(), format!("Api-Key {auth}")),
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                ],
                body: Some(
                    json!({
                        "query": query_value,
                        "maxPassages": max,
                        "group": {
                            "groupMode": "GROUP_MODE_FLAT",
                            "groupsOnPage": max,
                            "passagesInGroup": 1
                        }
                    })
                    .to_string(),
                ),
            }
        }
        Provider::Brave => {
            let url = format!("{base}?q={}&count={max}", urlencoded(query));
            Request {
                method: "GET",
                url,
                headers: vec![
                    ("Accept".to_owned(), "application/json".to_owned()),
                    ("X-Subscription-Token".to_owned(), auth),
                ],
                body: None,
            }
        }
        Provider::Tavily => Request {
            method: "POST",
            url: base,
            headers: vec![
                ("Authorization".to_owned(), format!("Bearer {auth}")),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ],
            body: Some(
                json!({"query": query, "max_results": max, "search_depth": "basic"}).to_string(),
            ),
        },
    })
}

fn urlencoded(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(*byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

struct Hit {
    title: String,
    url: String,
    snippet: String,
}

/// Lenient response parsing: Yandex Cloud shapes vary between deployments,
/// so results are collected from every known field arrangement.
fn parse(provider: Provider, body: &str) -> Result<Vec<Hit>, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "Ответ провайдера не является JSON".to_owned())?;
    let arrays: Vec<&Value> = match provider {
        Provider::Brave => vec![
            value
                .pointer("/web/results")
                .or_else(|| value.pointer("/news/results"))
                .unwrap_or(&Value::Null),
        ],
        Provider::Tavily => vec![value.pointer("/results").unwrap_or(&Value::Null)],
        Provider::Yandex => {
            let mut found = Vec::new();
            for pointer in [
                "/docs",
                "/results",
                "/response/docs",
                "/data/docs",
                "/groups",
            ] {
                if let Some(array) = value.pointer(pointer).filter(|value| value.is_array()) {
                    found.push(array);
                }
            }
            if found.is_empty() {
                found.push(&Value::Null);
            }
            found
        }
    };
    let mut hits = Vec::new();
    for array in arrays {
        let Some(items) = array.as_array() else {
            continue;
        };
        for item in items {
            if let Some(hit) = hit_from(item) {
                hits.push(hit);
            }
        }
        if !hits.is_empty() {
            break;
        }
    }
    Ok(hits)
}

fn hit_from(item: &Value) -> Option<Hit> {
    let url = item
        .get("url")
        .or_else(|| item.get("url_encoded"))
        .and_then(Value::as_str)?;
    let title = text_field(item.get("title")).unwrap_or_default();
    let snippet = text_field(item.get("snippet"))
        .or_else(|| text_field(item.get("description")))
        .or_else(|| text_field(item.get("content")))
        .or_else(|| text_field(item.get("passage")))
        .unwrap_or_default();
    let hits = if item.get("docs").is_some() {
        item.get("docs")
            .and_then(Value::as_array)
            .map(|docs| docs.iter().filter_map(hit_from).collect::<Vec<Hit>>())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let _ = hits;
    Some(Hit {
        title: clip(&title, MAX_TITLE_CHARS),
        url: clip(url, MAX_URL_CHARS),
        snippet: clip(&snippet, MAX_SNIPPET_CHARS),
    })
}

fn text_field(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Object(inner)) => inner
            .get("value")
            .or_else(|| inner.get("text"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                if let Some(text) = item.as_str() {
                    Some(text.to_owned())
                } else {
                    text_field(Some(item))
                }
            })
            .next(),
        _ => None,
    }
}

fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    let mut result: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        result.push('…');
    }
    result
}

pub(crate) async fn execute(
    config: &Config,
    args: &Value,
    cancel: &tokio_util::sync::CancellationToken,
) -> ToolOutcome {
    let Some(query) = args.get("query").and_then(Value::as_str) else {
        return ToolOutcome::error("Некорректный JSON аргументов; нужен query");
    };
    let query = query.trim();
    if query.is_empty() {
        return ToolOutcome::error("Пустой поисковый запрос");
    }
    let max = args
        .get("max_results")
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 20) as usize)
        .unwrap_or(MAX_RESULTS)
        .min(MAX_RESULTS);
    let request = match build_request(config, query, max) {
        Ok(request) => request,
        Err(message) => {
            return ToolOutcome::error(
                json!({"error": "invalid_config", "message": message}).to_string(),
            );
        }
    };
    let search = async {
        let mut builder = match request.method {
            "POST" => client().post(&request.url),
            _ => client().get(&request.url),
        };
        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }
        let response = match builder.send().await {
            Ok(response) => response,
            Err(error) => {
                return ToolOutcome::error(
                    json!({"error": "provider_error", "message": format!("{error}")}).to_string(),
                );
            }
        };
        let status = response.status().as_u16();
        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => {
                return ToolOutcome::error(
                    json!({"error": "provider_error", "message": format!("{error}")}).to_string(),
                );
            }
        };
        if !(200..300).contains(&status) {
            return ToolOutcome::error(
                json!({"error": "provider_error", "status": status, "message": "Поисковый API вернул ошибку; проверьте ключ и лимиты"}).to_string(),
            );
        }
        let hits = match parse(config.provider, &body) {
            Ok(hits) => hits,
            Err(message) => {
                return ToolOutcome::error(
                    json!({"error": "provider_error", "message": message}).to_string(),
                );
            }
        };
        let results: Vec<Value> = hits
            .into_iter()
            .take(max)
            .map(|hit| {
                json!({
                    "title": hit.title,
                    "url": hit.url,
                    "snippet": hit.snippet,
                })
            })
            .collect();
        let count = results.len();
        ToolOutcome::success(
            json!({
                "provider": config.provider.as_str(),
                "query": query,
                "results": results,
                "count": count,
            })
            .to_string(),
        )
    };
    tokio::select! {
        outcome = search => outcome,
        _ = cancel.cancelled() => ToolOutcome::error(
            json!({"error": "interrupted", "message": "Поиск отменён"}).to_string(),
        ),
    }
}

/// Interactive first-run setup: the user picks a provider, enters the key
/// (hidden input), and the choice is stored in the application configuration.
/// Nothing is written when the user cancels.
pub(crate) fn setup(store: &ConfigStore) -> Result<Option<Config>> {
    let options: Vec<String> = Provider::all()
        .iter()
        .map(|provider| (*provider).label().to_owned())
        .chain(["Пропустить — не настраивать поиск".to_owned()])
        .collect();
    println!("\nВеб-поиск для модели не настроен. Подключить провайдера?");
    for (index, option) in options.iter().enumerate() {
        println!("  {}) {}", index + 1, option);
    }
    print!("Введите 1-{}: ", options.len());
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error))?;
    let selected: Option<Provider> = match answer.trim() {
        "1" => Some(Provider::Yandex),
        "2" => Some(Provider::Brave),
        "3" => Some(Provider::Tavily),
        _ => None,
    };
    let Some(provider) = selected else {
        println!("Поиск не настроен.");
        return Ok(None);
    };
    let key = ui::password(&format!("API-ключ {} (ввод скрыт): ", provider.label()))?;
    let key = key.trim().to_owned();
    if key.chars().count() < MIN_KEY_CHARS {
        println!("! Ключ короче {MIN_KEY_CHARS} символов; ничего не сохранено");
        return Ok(None);
    }
    let mut settings = WebSearchSettings {
        provider: Some(provider.as_str().to_owned()),
        ..WebSearchSettings::default()
    };
    if provider == Provider::Yandex {
        println!("Folder ID Yandex Cloud (Enter — пропустить):");
        let mut folder = String::new();
        std::io::stdin()
            .read_line(&mut folder)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error))?;
        let folder = folder.trim();
        if !folder.is_empty() {
            settings.folder_id = Some(folder.to_owned());
        }
    }
    store.save_named_credential(CREDENTIAL_ID, &key)?;
    let mut loaded: Settings = store.load()?;
    loaded.websearch = settings;
    store.save(&loaded)?;
    println!("✓ Поиск настроен: {}", provider.label());
    resolve(store)
}

/// Headless `rcode websearch …`: status, provider choice, key from stdin or
/// hidden input, clear. Keys never appear in argv or logs.
pub async fn run(
    command: &crate::cli::WebsearchCommand,
    store: &ConfigStore,
    events: &mut crate::app::Events,
) -> Result<i32> {
    use crate::cli::WebsearchCommand;
    match command {
        WebsearchCommand::Status => {
            let settings: Settings = store.load()?;
            match resolve(store)? {
                Some(config) => {
                    let folder = config
                        .folder_id
                        .as_ref()
                        .map(|folder| format!("  folder: {folder}"))
                        .unwrap_or_default();
                    if events.json {
                        events.emit(
                            "websearch",
                            json!({"version": 1, "provider": config.provider.as_str(),
                                   "key": true}),
                        );
                    } else {
                        println!("Поиск: {} · ключ задан{folder}", config.provider.label());
                    }
                }
                None => {
                    if events.json {
                        events.emit(
                            "websearch",
                            json!({"version": 1, "provider": null, "key": false}),
                        );
                    } else {
                        println!("Поиск не настроен. rcode websearch provider yandex|brave|tavily");
                    }
                }
            }
            let _ = &settings;
            Ok(0)
        }
        WebsearchCommand::Provider { name } => {
            model_shell_guard()?;
            let Some(provider) = Provider::parse(name) else {
                anyhow::bail!("Провайдер не распознан: yandex, brave или tavily");
            };
            let mut settings: Settings = store.load()?;
            settings.websearch.provider = Some(provider.as_str().to_owned());
            store.save(&settings)?;
            events.emit(
                "websearch",
                json!({"version": 1, "provider": provider.as_str()}),
            );
            if !events.json {
                println!("✓ Провайдер поиска: {}", provider.label());
                if store.named_credential(CREDENTIAL_ID)?.is_none() {
                    println!("Ключ ещё не задан: echo КЛЮЧ | rcode websearch key --stdin");
                }
            }
            Ok(0)
        }
        WebsearchCommand::Key { api_key_stdin } => {
            model_shell_guard()?;
            let settings: Settings = store.load()?;
            if settings.websearch.provider.is_none() {
                anyhow::bail!(
                    "Сначала выберите провайдера: rcode websearch provider yandex|brave|tavily"
                );
            }
            let key = if std::io::stdin().is_terminal() && !*api_key_stdin {
                ui::password("Ключ поискового API (ввод скрыт): ")?
            } else {
                use std::io::Read;
                let mut text = String::new();
                std::io::stdin()
                    .take(16 * 1024)
                    .read_to_string(&mut text)
                    .context("Не удалось прочитать ключ из stdin")?;
                text.trim_end_matches(['\r', '\n']).to_owned()
            };
            let key = key.trim();
            if key.chars().count() < MIN_KEY_CHARS {
                anyhow::bail!("Ключ не короче {MIN_KEY_CHARS} символов не сохраняется");
            }
            store.save_named_credential(CREDENTIAL_ID, key)?;
            events.emit("websearch", json!({"version": 1, "key": true}));
            if !events.json {
                println!("✓ Ключ сохранён в credentials.json");
            }
            Ok(0)
        }
        WebsearchCommand::Clear => {
            model_shell_guard()?;
            store.delete_named_credential(CREDENTIAL_ID)?;
            let mut settings: Settings = store.load()?;
            settings.websearch = WebSearchSettings::default();
            store.save(&settings)?;
            events.emit(
                "websearch",
                json!({"version": 1, "provider": null, "key": false}),
            );
            if !events.json {
                println!("✓ Веб-поиск отключён");
            }
            Ok(0)
        }
    }
}

fn model_shell_guard() -> Result<()> {
    if std::env::var("RCODE_MODEL_SHELL").as_deref() == Ok("1") {
        anyhow::bail!(
            "Настройка поиска недоступна из shell модели; попросите пользователя выполнить это сам"
        );
    }
    Ok(())
}

/// Receipt for an unconfigured search: an interactive user is offered the
/// setup dialog once; everything else gets the headless instructions.
pub(crate) fn unconfigured_receipt(
    store: Option<&ConfigStore>,
    events: &crate::app::Events,
    cli: &crate::cli::Cli,
    plan: bool,
    subagent: bool,
) -> ToolOutcome {
    // Fullscreen: the Screen owns stdin during a turn, so the choice happens
    // in a keyboard panel; the key itself is entered later (via /websearch or
    // `rcode websearch key --stdin`), never from the model's shell.
    if !plan
        && !cli.json
        && ui::terminal()
        && !subagent
        && let (Some(store), Some(screen)) = (store, crate::screen::current())
    {
        let all = Provider::all();
        let options: Vec<String> = all
            .iter()
            .map(|provider| provider.label().to_owned())
            .chain(["Пропустить — настроить позже".to_owned()])
            .collect();
        match screen.choose("Веб-поиск не настроен. Выбрать провайдера?", &options)
        {
            Ok(Some(index)) if index < all.len() => {
                let provider = all[index];
                match store.load().map(|mut settings: Settings| {
                    settings.websearch.provider = Some(provider.as_str().to_owned());
                    settings
                }) {
                    Ok(settings) => match store.save(&settings) {
                        Ok(()) => {
                            crate::screen::notice(format!(
                                "✓ Провайдер поиска: {}. Ключ ещё не задан: наберите /websearch или выполните echo КЛЮЧ | rcode websearch key --stdin",
                                provider.label()
                            ));
                            events_notice(
                                events,
                                &format!("выбран провайдер поиска {}", provider.as_str()),
                            );
                        }
                        Err(error) => {
                            return ToolOutcome::error(
                                json!({"error": "setup_failed", "message": crate::ui::safe(&format!("{error:#}"))}).to_string(),
                            );
                        }
                    },
                    Err(error) => {
                        return ToolOutcome::error(
                            json!({"error": "setup_failed", "message": crate::ui::safe(&format!("{error:#}"))}).to_string(),
                        );
                    }
                }
            }
            Err(error) => {
                return ToolOutcome::error(
                    json!({"error": "setup_failed", "message": crate::ui::safe(&format!("{error:#}"))}).to_string(),
                );
            }
            _ => {}
        }
        return unconfigured_error_receipt();
    }
    // Plain mode without a Screen: a stdin prompt is safe here.
    if !plan
        && !cli.json
        && ui::terminal()
        && !subagent
        && crate::screen::current().is_none()
        && let Some(store) = store
    {
        match setup(store) {
            Ok(Some(config)) => return ToolOutcome::success(
                json!({"configured": config.provider.as_str(), "message": "Поиск настроен; повторите запрос web_search"}).to_string(),
            ),
            Ok(None) => {}
            Err(error) => {
                return ToolOutcome::error(
                    json!({"error": "setup_failed", "message": crate::ui::safe(&format!("{error:#}"))}).to_string(),
                );
            }
        }
    }
    unconfigured_error_receipt()
}

fn unconfigured_error_receipt() -> ToolOutcome {
    ToolOutcome::error(
        json!({
            "error": "not_configured",
            "message": "Веб-поиск не настроен или ключ не задан. Попросите пользователя набрать /websearch (выбор провайдера и ключ) или выполнить:\n  rcode websearch provider yandex|brave|tavily\n  echo КЛЮЧ | rcode websearch key --stdin"
        })
        .to_string(),
    )
}

fn events_notice(events: &crate::app::Events, message: &str) {
    events.emit("websearch", json!({"version": 1, "notice": message}));
}

/// `/websearch`: интерактивная настройка поиска между ходами — провайдер и
/// ключ (скрытый ввод). Здесь stdin безопасен: Screen не читает ввод.
pub(crate) async fn choose(
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    events: &mut crate::app::Events,
) -> Result<()> {
    let current = match (
        &settings.websearch.provider,
        store.named_credential(CREDENTIAL_ID)?,
    ) {
        (Some(provider), Some(_)) => format!("{provider}, ключ задан"),
        (Some(provider), None) => format!("{provider}, ключ не задан"),
        _ => "не настроено".to_owned(),
    };
    notice!("Веб-поиск: {}", crate::ui::safe(&current));
    let all = Provider::all();
    let mut choices: Vec<crate::terminal::Choice> = all
        .iter()
        .map(|provider| crate::terminal::Choice {
            label: provider.as_str().to_owned(),
            detail: provider.label().into(),
            enabled: true,
        })
        .collect();
    choices.push(crate::terminal::Choice {
        label: "Выключить поиск".into(),
        detail: "убрать провайдера и ключ".into(),
        enabled: true,
    });
    let Some(selected) = crate::interactive::choose("Провайдер веб-поиска", &choices, 0, rich)?
    else {
        return Ok(());
    };
    if selected == all.len() {
        store.delete_named_credential(CREDENTIAL_ID)?;
        settings.websearch = WebSearchSettings::default();
        store.save(settings)?;
        events.emit(
            "websearch",
            json!({"version": 1, "provider": null, "key": false}),
        );
        notice!("Веб-поиск выключен.");
        return Ok(());
    }
    let provider = all[selected];
    settings.websearch.provider = Some(provider.as_str().to_owned());
    let key = ui::password(&format!("API-ключ {} (ввод скрыт): ", provider.label()))?;
    let key = key.trim();
    if key.chars().count() < MIN_KEY_CHARS {
        notice!("! Ключ короче {MIN_KEY_CHARS} символов; провайдер сохранён, ключ не задан");
    } else {
        store.save_named_credential(CREDENTIAL_ID, key)?;
        notice!("✓ Ключ сохранён в credentials.json");
    }
    store.save(settings)?;
    events.emit(
        "websearch",
        json!({"version": 1, "provider": provider.as_str(), "key": !key.is_empty()}),
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn config(provider: Provider, base: Option<&str>) -> Config {
        Config {
            provider,
            folder_id: None,
            base_url: base.map(str::to_owned),
            key: "test-key-1234567890".to_owned(),
        }
    }

    #[test]
    fn brave_request_carries_the_subscription_token() {
        let request = build_request(
            &config(Provider::Brave, Some("http://127.0.0.1:1")),
            "qwen3 vision",
            5,
        )
        .unwrap();
        assert_eq!(request.method, "GET");
        assert!(
            request
                .url
                .starts_with("http://127.0.0.1:1?q=qwen3%20vision&count=5")
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(k, v)| k == "X-Subscription-Token" && v.contains("test-key"))
        );
        assert!(request.body.is_none());
    }

    #[test]
    fn tavily_request_uses_bearer_and_json_body() {
        let request = build_request(&config(Provider::Tavily, None), "rcode rust", 3).unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "https://api.tavily.com/search");
        assert!(
            request
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.starts_with("Bearer test-key"))
        );
        let body: Value = serde_json::from_str(&request.body.unwrap()).unwrap();
        assert_eq!(body["query"], "rcode rust");
        assert_eq!(body["max_results"], 3);
    }

    #[test]
    fn yandex_request_binds_folder_id_when_present() {
        let mut config = config(Provider::Yandex, Some("http://127.0.0.1:2"));
        config.folder_id = Some("b1gfolder".to_owned());
        let request = build_request(&config, "тест", 4).unwrap();
        assert_eq!(request.method, "POST");
        assert!(
            request
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.starts_with("Api-Key test-key"))
        );
        let body: Value = serde_json::from_str(&request.body.unwrap()).unwrap();
        assert_eq!(body["query"]["queryText"], "тест");
        assert_eq!(body["query"]["folderId"], "b1gfolder");
        assert_eq!(body["query"]["searchType"], "SEARCH_TYPE_WEB");
    }

    #[test]
    fn base_url_must_be_https_or_loopback() {
        assert!(build_request(&config(Provider::Brave, Some("ftp://x")), "q", 5).is_err());
        assert!(
            build_request(&config(Provider::Brave, Some("http://example.com")), "q", 5).is_err()
        );
        assert!(
            build_request(&config(Provider::Brave, Some("http://127.0.0.1:9")), "q", 5).is_ok()
        );
    }

    #[test]
    fn parses_brave_results() {
        let hits = parse(
            Provider::Brave,
            r#"{"web": {"results": [
                {"title": "Qwen3", "url": "https://qwen.example/a", "description": "Модель"},
                {"title": {"value": "Объектный title"}, "url": "https://qwen.example/b"}
            ]}}"#,
        )
        .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].title, "Qwen3");
        assert_eq!(hits[1].title, "Объектный title");
    }

    #[test]
    fn parses_tavily_results() {
        let hits = parse(
            Provider::Tavily,
            r#"{"results": [{"title": "T", "url": "https://t.example", "content": "Содержание"}]}"#,
        )
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].snippet, "Содержание");
    }

    #[test]
    fn parses_yandex_shapes_liberally() {
        let bodies = [
            r#"{"docs": [{"url": "https://y.example/1", "title": "A", "snippet": "S"}]}"#,
            r#"{"results": [{"url": "https://y.example/1", "title": "A", "snippet": "S"}]}"#,
            r#"{"response": {"docs": [{"url": "https://y.example/1", "title": {"value": "A"}, "snippet": [{"text": "S"}]}]}}"#,
        ];
        for body in bodies {
            let hits =
                parse(Provider::Yandex, body).unwrap_or_else(|error| panic!("{error}: {body}"));
            assert_eq!(hits.len(), 1, "{body}");
            assert_eq!(hits[0].url, "https://y.example/1");
            assert_eq!(hits[0].title, "A");
            assert_eq!(hits[0].snippet, "S");
        }
    }

    #[test]
    fn non_json_response_is_an_honest_error() {
        assert!(parse(Provider::Brave, "<html>gateway</html>").is_err());
    }

    #[test]
    fn urlencoded_escapes_reserved_characters() {
        assert_eq!(urlencoded("a b&c=d/е"), "a%20b%26c%3Dd%2F%D0%B5");
    }

    async fn serve(responses: Vec<Vec<u8>>) -> (u16, std::sync::Arc<std::net::TcpListener>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let listener = std::sync::Arc::new(listener);
        let shared = listener.clone();
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = shared.accept() else {
                    return;
                };
                use std::io::Write;
                let mut buffer = [0u8; 8192];
                let _ = std::io::Read::read(&mut stream, &mut buffer);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        (address.port(), listener)
    }

    #[tokio::test]
    async fn brave_fixture_returns_results_receipt() {
        let body = r#"{"web":{"results":[{"title":"Rcode","url":"https://rcode.example","description":"CLI агент"}]}}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(body.as_bytes());
        let (port, _) = serve(vec![response]).await;
        let outcome = execute(
            &config(Provider::Brave, Some(&format!("http://127.0.0.1:{port}"))),
            &json!({"query": "rcode rust", "max_results": 3}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!outcome.is_error, "{}", outcome.content);
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["provider"], "brave");
        assert_eq!(receipt["count"], 1);
        assert_eq!(receipt["results"][0]["title"], "Rcode");
        assert_eq!(receipt["results"][0]["snippet"], "CLI агент");
    }

    #[tokio::test]
    async fn provider_error_reports_the_status() {
        let (port, _) = serve(vec![b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec()]).await;
        let outcome = execute(
            &config(Provider::Brave, Some(&format!("http://127.0.0.1:{port}"))),
            &json!({"query": "q"}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["error"], "provider_error");
        assert_eq!(receipt["status"], 403);
    }

    #[tokio::test]
    async fn tavily_fixture_post_body_reaches_the_fixture() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = r#"{"results":[{"title":"T","url":"https://t.example","content":"c"}]}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(body.as_bytes());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 8192];
            let read = Read::read(&mut stream, &mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let _ = stream.write_all(&response);
            assert!(request.starts_with("POST /search"));
            assert!(request.contains("Bearer test-key"));
            assert!(request.contains("\"query\":\"rcode\""));
        });
        let outcome = execute(
            &config(Provider::Tavily, Some(&format!("http://127.0.0.1:{port}"))),
            &json!({"query": "rcode"}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!outcome.is_error, "{}", outcome.content);
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["provider"], "tavily");
        assert_eq!(receipt["count"], 1);
    }
}
