//! Provider-specific wire formats stay here; sessions contain only the common protocol.
use crate::{
    balance::{BalanceReport, TokenBalance},
    config::{Effort, ProviderKind, ProviderSettings},
    protocol::{
        Completion, FailureKind, FunctionCall, Message, ModelInfo, ProviderFailure, ProviderMeta,
        ToolCall, ToolDefinition, Usage,
    },
};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::StreamExt;
use reqwest::{
    Client, Method, Request, Response, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_CALLS: usize = 128;
const MAX_RETRIES: usize = 2;

enum RequestPayload<'a> {
    Json(&'a Value),
    Multipart(&'a [u8], &'a str),
}

#[derive(Clone)]
pub struct ProviderClient {
    settings: ProviderSettings,
    client: Client,
    loopback_client: Client,
    gigachat_client: Option<Client>,
    base: Url,
    auth_url: Option<Url>,
    /// `None` only for a local profile without a key: no Authorization header.
    credential: Option<String>,
    token: Option<AccessToken>,
    generation_slots: Arc<Semaphore>,
    image_uploads: Arc<tokio::sync::Mutex<BTreeMap<String, String>>>,
    credits_forbidden: Arc<AtomicBool>,
    /// Local servers only: pinned loopback client and state shared by clones.
    local: Option<LocalConnection>,
}

#[derive(Clone)]
struct LocalConnection {
    client: Client,
    runtime_context: Arc<Mutex<Option<u32>>>,
    calibration: Arc<Mutex<f64>>,
    /// Context probes made by this connection and its clones (bounded).
    probes: Arc<std::sync::atomic::AtomicUsize>,
    /// A smaller server context is reported once per connection.
    context_warned: Arc<AtomicBool>,
}
#[derive(Clone)]
struct AccessToken {
    value: String,
    expires_at_secs: u64,
}

impl ProviderClient {
    pub fn new(settings: ProviderSettings, credential: String) -> Result<Self> {
        Self::connect(settings, Some(credential))
    }

    /// Cloud providers require a key. A local profile may connect without
    /// one; then no Authorization header is ever sent.
    pub fn connect(settings: ProviderSettings, credential: Option<String>) -> Result<Self> {
        settings.validate_effort()?;
        let is_local = settings.kind == ProviderKind::Local;
        let default = match settings.kind {
            ProviderKind::Yandex => "https://ai.api.cloud.yandex.net/v1",
            ProviderKind::GigaChat => "https://api.giga.chat/v1",
            ProviderKind::OpenRouter => "https://openrouter.ai/api/v1",
            ProviderKind::Custom | ProviderKind::Local => "",
        };
        if is_local {
            crate::local::validate_local_endpoint(settings.base_url.as_deref().unwrap_or(default))
                .map_err(|error| protocol(&error.to_string()))?;
        }
        let base = checked_url(settings.base_url.as_deref().unwrap_or(default))?;
        if is_local && settings.local.is_none() {
            return Err(protocol("Профиль local повреждён: нет параметров local"));
        }
        let credential = if is_local {
            credential.filter(|key| !key.trim().is_empty())
        } else {
            credential
        };
        let auth_url = if settings.kind == ProviderKind::GigaChat {
            Some(checked_url(settings.auth_url.as_deref().unwrap_or(
                "https://ngw.devices.sberbank.ru:9443/api/v2/oauth",
            ))?)
        } else {
            None
        };
        if !is_local
            && credential
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
        {
            return Err(fail(FailureKind::Auth, None, "Не задан ключ провайдера"));
        }
        if credential
            .as_deref()
            .is_some_and(|key| key.contains(['\r', '\n']))
        {
            return Err(fail(
                FailureKind::Auth,
                None,
                "Недопустимый формат ключа провайдера",
            ));
        }
        // A new local profile lists its server's models before one is chosen;
        // a generation without a model is refused in `model()`.
        if (settings.model.trim().is_empty() && !is_local)
            || settings.max_output_tokens == 0
            || settings.request_timeout_secs == 0
            || settings.idle_timeout_secs == 0
        {
            return Err(fail(
                FailureKind::Protocol,
                None,
                "Модель, лимит токенов, request timeout и idle timeout должны быть заданы",
            ));
        }
        let mut builder = client_builder();
        let mut loopback_builder = client_builder().no_proxy();
        let mut local_builder = is_local.then(local_client_builder);
        if let Some(path) = &settings.ca_file {
            let pem = std::fs::read(path)
                .map_err(|_| fail(FailureKind::Transport, None, "Не удалось прочитать CA-файл"))?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| {
                fail(
                    FailureKind::Transport,
                    None,
                    "CA-файл не содержит корректные PEM-сертификаты",
                )
            })?;
            if certificates.is_empty() {
                return Err(fail(FailureKind::Transport, None, "CA-файл пуст"));
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate.clone());
                local_builder =
                    local_builder.map(|local| local.add_root_certificate(certificate.clone()));
                loopback_builder = loopback_builder.add_root_certificate(certificate);
            }
        }
        let client = builder.build().map_err(|_| {
            fail(
                FailureKind::Transport,
                None,
                "Не удалось создать HTTPS-клиент",
            )
        })?;
        let loopback_client = loopback_builder
            .build()
            .map_err(|_| transport("Не удалось создать локальный HTTPS-клиент"))?;
        let local = local_builder
            .map(|builder| {
                builder
                    .build()
                    .map(|client| LocalConnection {
                        client,
                        runtime_context: Default::default(),
                        calibration: Arc::new(Mutex::new(1.0)),
                        probes: Default::default(),
                        context_warned: Default::default(),
                    })
                    .map_err(|_| transport("Не удалось создать клиент локального сервера"))
            })
            .transpose()?;
        let generation_slots = if is_local {
            crate::local_runtime::generation_slot(&base)
        } else {
            Arc::new(Semaphore::new(if settings.kind == ProviderKind::Yandex {
                2
            } else {
                4
            }))
        };
        Ok(Self {
            settings,
            client,
            loopback_client,
            gigachat_client: None,
            base,
            auth_url,
            credential,
            token: None,
            generation_slots,
            image_uploads: Default::default(),
            credits_forbidden: Default::default(),
            local,
        })
    }

    pub fn settings(&self) -> &ProviderSettings {
        &self.settings
    }

    pub fn is_local(&self) -> bool {
        self.local.is_some()
    }

    /// Reads the server context before the first request and once more after
    /// the first answer (Ollama reports a model only once it is loaded). Returns
    /// a one-time warning when the server context is smaller than the profile.
    pub async fn refresh_local_context(&self) -> Option<String> {
        const MAX_PROBES: usize = 2;
        let local = self.local.as_ref()?;
        crate::local_runtime::context_probe_path(self.settings.local.as_ref()?.runtime)?;
        if lock(&local.runtime_context).is_some()
            || local.probes.fetch_add(1, Ordering::SeqCst) >= MAX_PROBES
        {
            return None;
        }
        let context = self.probe_local_context().await?;
        let profile = self.settings.local.as_ref()?.context_tokens;
        (context < profile && !local.context_warned.swap(true, Ordering::SeqCst)).then(|| {
            format!(
                "Сервер сообщил контекст {context} токенов — меньше, чем в профиле ({profile}). rcode считает бюджет по {context} и не меняет настройки сервера; при необходимости увеличьте контекст на стороне сервера."
            )
        })
    }

    /// Reads the context loaded by a local server (llama.cpp `/props`, Ollama
    /// `/api/ps`) with a short deadline. `None` when unknown; never retried
    /// and never changes server settings.
    pub async fn probe_local_context(&self) -> Option<u32> {
        let local = self.local.as_ref()?;
        let runtime = self.settings.local.as_ref()?.runtime;
        let url = crate::local_runtime::origin(
            &self.base,
            crate::local_runtime::context_probe_path(runtime)?,
        );
        let mut request = local
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(key) = &self.credential {
            request = request.header(
                AUTHORIZATION,
                sensitive_header(&format!("Bearer {key}")).ok()?,
            );
        }
        let deadline = crate::local_runtime::PROBE_DEADLINE;
        let value = tokio::time::timeout(deadline, async {
            let response = request.send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            read_json(response, deadline).await.ok()
        })
        .await
        .ok()
        .flatten()?;
        let context = crate::local_runtime::parse_context(runtime, &value, &self.settings.model);
        if context.is_some() {
            *lock(&local.runtime_context) = context;
        }
        context
    }

    /// Context budget for this connection; cloud providers keep characters.
    pub fn context_budget(&self, overhead: usize) -> crate::context::ContextBudget {
        let (runtime, calibration) = self.local.as_ref().map_or((None, 1.0), |local| {
            (*lock(&local.runtime_context), *lock(&local.calibration))
        });
        crate::context::ContextBudget::for_provider(&self.settings, runtime, calibration, overhead)
    }

    /// Calibrates later local estimates from the prompt tokens a server reported.
    pub fn observe_prompt_tokens(&self, estimated: usize, observed: u64) {
        if let Some(local) = &self.local {
            let mut calibration = lock(&local.calibration);
            *calibration = crate::context::calibrated(*calibration, estimated, observed);
        }
    }

    pub async fn balance(&mut self) -> Result<BalanceReport> {
        let mut report = BalanceReport::empty(self.settings.kind);
        match self.settings.kind {
            ProviderKind::OpenRouter => {
                #[derive(serde::Deserialize)]
                struct Key { limit: Option<f64>, limit_remaining: Option<f64>, usage: f64 }
                #[derive(serde::Deserialize)]
                struct Credits { total_credits: f64, total_usage: f64 }
                let response = self.authorized_request(Method::GET, "key", None).await?;
                let value = read_json(response, self.idle()).await?;
                let key: Key = serde_json::from_value(value["data"].clone()).map_err(|_|protocol("API ключа не вернул корректные данные о лимите и расходе"))?;
                if value["data"].get("limit").is_none() || value["data"].get("limit_remaining").is_none() {
                    return Err(protocol("API ключа не сообщил, задан ли лимит"));
                }
                report.key_remaining_usd = key.limit_remaining;
                report.key_limit_usd = key.limit;
                report.key_usage_usd = Some(key.usage);
                if !self.credits_forbidden.load(Ordering::Relaxed) {
                    match self.authorized_request(Method::GET, "credits", None).await {
                        Ok(response) => {
                            let value=read_json(response,self.idle()).await?;
                            let credits: Credits=serde_json::from_value(value["data"].clone()).map_err(|_|protocol("API баланса не вернул total_credits и total_usage"))?;
                            let remaining=credits.total_credits-credits.total_usage;
                            if !remaining.is_finite() { return Err(protocol("API вернул некорректный баланс")); }
                            report.remaining_usd=Some(remaining);
                        },
                        Err(error) if error.downcast_ref::<ProviderFailure>().is_some_and(|e|matches!(e.status,Some(401|403))) => {
                            self.credits_forbidden.store(true,Ordering::Relaxed);
                        },
                        Err(error) => return Err(error),
                    }
                }
                if self.credits_forbidden.load(Ordering::Relaxed) {
                    report.note=Some("API не разрешил посмотреть баланс счёта этим ключом; может потребоваться отдельный management key. Лимит ключа не является балансом счёта.".into());
                }
            },
            ProviderKind::GigaChat => {
                match self.authorized_request(Method::GET,"balance",None).await {
                    Ok(response) => {
                        let value=read_json(response,self.idle()).await?;
                        report.token_balances=serde_json::from_value::<Vec<TokenBalance>>(value["balance"].clone()).map_err(|_|protocol("API баланса не вернул корректные остатки токенов"))?;
                        if report.token_balances.len()>128 || report.token_balances.iter().any(|p|p.usage.is_empty() || p.usage.len()>128) { return Err(protocol("API баланса вернул некорректный список пакетов")); }
                        report.note=Some("Остатки оплаченных пакетов в токенах; денежный баланс API не сообщает.".into());
                    },
                    Err(error) if error.downcast_ref::<ProviderFailure>().is_some_and(|e|matches!(e.status,Some(403..=405))) => report.note=Some("Баланс токенов недоступен этому ключу или тарифу. При pay-as-you-go GigaChat не предоставляет этот API.".into()),
                    Err(error) => return Err(error),
                }
            },
            ProviderKind::Yandex => report.note=Some("Ключ AI Studio не даёт доступ к балансу Yandex Cloud Billing. Для Billing API нужна отдельная IAM-авторизация; баланс доступен в кабинете.".into()),
            ProviderKind::Custom => report.note=Some("У OpenAI-совместимого API нет стандартного метода баланса. Проверьте кабинет своего провайдера.".into()),
            ProviderKind::Local => report.note=Some("Локальный сервер: баланс не применяется.".into()),
        }
        report.checked_at = epoch_seconds();
        Ok(report)
    }

    pub async fn complete(
        &mut self,
        messages: &[Message],
        tools: &[ToolDefinition],
        emit: &mut (dyn FnMut(&str) + Send),
    ) -> Result<Completion> {
        // Clones share the allowance. Keep it through the complete SSE/JSON body,
        // including retries; reading only headers does not finish a generation.
        let slot = match self.generation_slots.clone().try_acquire_owned() {
            Ok(slot) => Ok(slot),
            Err(_) => {
                // Status only: this text never reaches emit, the answer or history.
                let screen = crate::screen::current().filter(|_| self.is_local());
                if let Some(screen) = &screen {
                    screen.busy("Жду локальную модель: занята другим запросом");
                }
                let slot = self.generation_slots.clone().acquire_owned().await;
                if let Some(screen) = &screen {
                    screen.busy("Локальная модель отвечает");
                }
                slot
            }
        };
        let _slot = slot.map_err(|_| transport("Очередь модельных запросов закрыта"))?;
        let uploaded = self.prepare_images(messages).await?;
        let body = self.completion_body(messages, tools, &uploaded)?;
        let response = self
            .authorized_request(Method::POST, "chat/completions", Some(&body))
            .await?;
        let local = self.is_local();
        let is_sse = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| {
                h.split(';')
                    .next()
                    .is_some_and(|h| h.trim() == "text/event-stream")
            });
        let giga = self.settings.kind == ProviderKind::GigaChat;
        if is_sse {
            let completion = read_sse(response, self.idle(), &self.settings, emit).await?;
            validate_tool_output(&completion, tools, local)?;
            Ok(completion)
        } else {
            let value = read_json(response, self.idle()).await?;
            let mut accumulator = Accumulator::new(&self.settings);
            accumulator.json_completion(&value, giga)?;
            accumulator.flush_reasoning(false, &mut |_| {})?;
            let completion = accumulator.finish()?;
            validate_tool_output(&completion, tools, local)?;
            if !completion.content.is_empty() {
                emit(&completion.content);
            }
            Ok(completion)
        }
    }

    pub async fn models(&mut self) -> Result<Vec<ModelInfo>> {
        let response = match self.authorized_request(Method::GET, "models", None).await {
            Ok(response) => response,
            Err(error)
                if error
                    .downcast_ref::<ProviderFailure>()
                    .is_some_and(|e| matches!(e.status, Some(404 | 405))) =>
            {
                return Ok(vec![ModelInfo {
                    id: self.model()?,
                    name: format!(
                        "{} (из конфигурации; список API недоступен)",
                        self.settings.model
                    ),
                    supports_tools: None,
                    ..ModelInfo::default()
                }]);
            }
            Err(error) => return Err(error),
        };
        let value = read_json(response, self.idle()).await?;
        let models = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| protocol("API моделей не вернул массив data"))?;
        let local = self.is_local();
        models
            .iter()
            .filter(|model| {
                // Local servers also list embedding models; they cannot run an agent.
                !local
                    || !model
                        .get("id")
                        .and_then(Value::as_str)
                        .is_some_and(crate::local_runtime::is_embedding_model)
            })
            .map(|model| {
                let id = model
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| protocol("Модель без идентификатора в ответе API"))?;
                let supports_tools = model
                    .get("supported_parameters")
                    .and_then(Value::as_array)
                    .map(|parameters| parameters.iter().any(|p| p.as_str() == Some("tools")))
                    .or_else(|| {
                        if self.settings.kind == ProviderKind::GigaChat {
                            Some(true)
                        } else {
                            None
                        }
                    });
                let (supports_reasoning, supported_efforts) =
                    reasoning_metadata(model, self.settings.kind);
                Ok(ModelInfo {
                    id: id.into(),
                    name: model
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(id)
                        .into(),
                    supports_tools,
                    context_length: model.get("context_length").and_then(Value::as_u64).or_else(
                        || {
                            model
                                .get("top_provider")
                                .and_then(|provider| provider.get("context_length"))
                                .and_then(Value::as_u64)
                        },
                    ),
                    supports_reasoning,
                    supported_efforts,
                    supports_images: None,
                })
            })
            .collect()
    }

    fn idle(&self) -> Duration {
        Duration::from_secs(self.settings.idle_timeout_secs)
    }

    fn model(&self) -> Result<String> {
        if self.settings.model.trim().is_empty() {
            return Err(protocol(
                "Модель не выбрана: выберите её через /model или --model",
            ));
        }
        if self.settings.kind != ProviderKind::Yandex || self.settings.model.starts_with("gpt://") {
            return Ok(self.settings.model.clone());
        }
        let folder = self
            .settings
            .folder_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                protocol("Для Yandex требуется folder_id или полный gpt:// URI модели")
            })?;
        Ok(format!("gpt://{folder}/{}", self.settings.model))
    }

    fn completion_body(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        uploaded: &BTreeMap<String, String>,
    ) -> Result<Value> {
        let giga = self.settings.kind == ProviderKind::GigaChat;
        let messages = if giga {
            giga_messages(messages, uploaded)?
        } else {
            compatible_messages(messages)?
        };
        let max_tokens = match &self.local {
            Some(local) => crate::context::effective_output(
                self.settings.max_output_tokens,
                lock(&local.runtime_context).unwrap_or(u32::MAX).min(
                    self.settings
                        .local
                        .as_ref()
                        .map_or(u32::MAX, |l| l.context_tokens),
                ),
            ),
            None => self.settings.max_output_tokens,
        };
        let mut body = json!({"model":self.model()?,"messages":messages,"stream":self.settings.stream,"max_tokens":max_tokens});
        if let Some(local) = self.settings.local.as_ref().filter(|_| self.is_local()) {
            // Effort is never sent to a local server; thinking only by explicit choice.
            if let Some(thinking) = local.thinking {
                body["chat_template_kwargs"] = json!({"enable_thinking":thinking});
            }
            if self.settings.stream && local.runtime.stream_usage() {
                body["stream_options"] = json!({"include_usage":true});
            }
            if !tools.is_empty() {
                body["tools"] = Value::Array(tools.iter().map(|t| json!({"type":"function","function":{"name":t.name,"description":t.description,"parameters":t.parameters}})).collect());
                body["tool_choice"] = json!("auto");
            }
            return Ok(body);
        }
        if !self.settings.effort.is_auto() {
            if self.settings.kind == ProviderKind::OpenRouter {
                body["reasoning"] = json!({"effort":self.settings.effort});
            } else {
                body["reasoning_effort"] = json!(self.settings.effort);
            }
        }
        if giga {
            // Native v1 never uses OpenAI tools or parallel calls.
            body["function_call"] = json!(if tools.is_empty() { "none" } else { "auto" });
            if !tools.is_empty() {
                body["functions"] = Value::Array(tools.iter().map(|t| json!({"name":t.name,"description":t.description,"parameters":t.parameters})).collect());
            }
        } else {
            if self.settings.stream && self.settings.kind != ProviderKind::Yandex {
                body["stream_options"] = json!({"include_usage":true});
            }
            if !tools.is_empty() {
                body["tools"] = Value::Array(tools.iter().map(|t| json!({"type":"function","function":{"name":t.name,"description":t.description,"parameters":t.parameters}})).collect());
                body["tool_choice"] = json!("auto");
            }
        }
        Ok(body)
    }

    async fn authorized_request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response> {
        self.authorized_payload(method, path, body.map(RequestPayload::Json))
            .await
    }

    async fn prepare_images(&mut self, messages: &[Message]) -> Result<BTreeMap<String, String>> {
        let images = messages
            .iter()
            .flat_map(|message| &message.images)
            .collect::<Vec<_>>();
        if images.len() > crate::images::MAX_IMAGES {
            return Err(protocol(
                "В истории больше 10 изображений; выполните /compact или /new перед отправкой",
            ));
        }
        for message in messages {
            if !message.images.is_empty() && message.role != "user" {
                return Err(protocol(
                    "Изображения допустимы только в пользовательских сообщениях",
                ));
            }
            for image in &message.images {
                image.validate()?;
            }
        }
        if !images.is_empty()
            && self.is_local()
            && !self
                .settings
                .local
                .as_ref()
                .is_some_and(|local| local.vision)
        {
            return Err(protocol(LOCAL_NO_VISION));
        }
        if self.settings.kind != ProviderKind::GigaChat || images.is_empty() {
            return Ok(BTreeMap::new());
        }
        let cache = self.image_uploads.clone();
        let mut cache = cache.lock().await;
        for image in images {
            if cache.contains_key(&image.sha256) {
                continue;
            }
            let boundary = format!("rcode-{}", uuid::Uuid::new_v4().simple());
            let extension = if image.mime_type == "image/png" {
                "png"
            } else {
                "jpg"
            };
            // A replayable byte body uses the same bounded retry/auth/TLS path as JSON.
            // Filenames in MIME headers are generated, never taken from user text.
            let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\ngeneral\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"image.{extension}\"\r\nContent-Type: {}\r\n\r\n", image.mime_type).into_bytes();
            body.extend_from_slice(&image.data);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let content_type = format!("multipart/form-data; boundary={boundary}");
            let response = self
                .authorized_payload(
                    Method::POST,
                    "files",
                    Some(RequestPayload::Multipart(&body, &content_type)),
                )
                .await?;
            let result = read_json(response, self.idle()).await?;
            let id = result["id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256)
                .ok_or_else(|| protocol("Files API не вернул идентификатор изображения"))?;
            cache.insert(image.sha256.clone(), id.to_owned());
        }
        Ok(cache.clone())
    }

    async fn authorized_payload(
        &mut self,
        method: Method,
        path: &str,
        body: Option<RequestPayload<'_>>,
    ) -> Result<Response> {
        if self.gigachat_client.is_none()
            && crate::certificates::automatic_gigachat_ca(
                &self.settings,
                &self.base,
                self.auth_url.as_ref(),
            )
        {
            let certificate = crate::certificates::gigachat_root().await.map_err(|error| {
                transport(&format!("{error:#}. Повторите подключение или укажите собственный сертификат через --ca-file"))
            })?;
            self.gigachat_client = Some(
                client_builder()
                    .add_root_certificate(certificate)
                    .build()
                    .map_err(|_| transport("Не удалось настроить сертификат GigaChat"))?,
            );
        }
        let giga = self.settings.kind == ProviderKind::GigaChat;
        if giga
            && self
                .token
                .as_ref()
                .is_none_or(|t| t.expires_at_secs <= epoch_seconds().saturating_add(60))
        {
            self.refresh_token().await?;
        }
        for auth_attempt in 0..=1 {
            let authorization = if self.is_local() {
                self.credential.as_ref().map(|key| format!("Bearer {key}"))
            } else if giga {
                Some(format!(
                    "Bearer {}",
                    self.token
                        .as_ref()
                        .ok_or_else(|| protocol("Отсутствует OAuth-токен"))?
                        .value
                ))
            } else if self.settings.kind == ProviderKind::Yandex {
                let key = self.cloud_key();
                Some(
                    if key.starts_with("Bearer ") || key.starts_with("Api-Key ") {
                        key.to_owned()
                    } else {
                        format!("Api-Key {key}")
                    },
                )
            } else {
                Some(format!("Bearer {}", self.cloud_key()))
            };
            let mut request = self
                .client
                .request(method.clone(), endpoint(&self.base, path))
                .header(reqwest::header::ACCEPT, "application/json");
            if let Some(authorization) = &authorization {
                request = request.header(AUTHORIZATION, sensitive_header(authorization)?);
            }
            if self.settings.kind == ProviderKind::Yandex
                && let Some(folder) = self.settings.folder_id.as_deref().filter(|s| !s.is_empty())
            {
                request = request.header("OpenAI-Project", sensitive_header(folder)?);
            }
            if self.settings.kind == ProviderKind::OpenRouter {
                request = request.header("X-Title", "rcode");
            }
            if let Some(body) = &body {
                request = match body {
                    RequestPayload::Json(value) => request.json(value),
                    RequestPayload::Multipart(bytes, content_type) => request
                        .header(reqwest::header::CONTENT_TYPE, *content_type)
                        .body(bytes.to_vec()),
                };
            }
            let request = request
                .build()
                .map_err(|_| protocol("Не удалось сформировать HTTP-запрос"))?;
            let response = self
                .send_with_retry(
                    request,
                    method == Method::POST && path == "chat/completions",
                )
                .await?;
            if giga && response.status() == reqwest::StatusCode::UNAUTHORIZED && auth_attempt == 0 {
                drop(response);
                self.token = None;
                self.refresh_token().await?;
                continue;
            }
            return self.check_status(response).await;
        }
        unreachable!("bounded authorization loop always returns")
    }

    /// Cloud providers always carry a key (enforced in `connect`).
    fn cloud_key(&self) -> &str {
        self.credential.as_deref().unwrap_or_default()
    }

    async fn refresh_token(&mut self) -> Result<()> {
        let key = self.cloud_key();
        let key = key.strip_prefix("Basic ").unwrap_or(key);
        let request = self
            .client
            .post(
                self.auth_url
                    .clone()
                    .ok_or_else(|| protocol("Не задан OAuth URL"))?,
            )
            .header(AUTHORIZATION, sensitive_header(&format!("Basic {key}"))?)
            .header("RqUID", uuid::Uuid::new_v4().to_string())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[(
                "scope",
                self.settings
                    .scope
                    .as_deref()
                    .unwrap_or("GIGACHAT_API_PERS"),
            )])
            .build()
            .map_err(|_| protocol("Не удалось сформировать OAuth-запрос"))?;
        let response = self.send_with_retry(request, false).await?;
        let response = self.check_status(response).await?;
        let value = read_json(response, self.idle()).await?;
        let token = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| protocol("OAuth-ответ не содержит access_token"))?;
        sensitive_header(&format!("Bearer {token}"))?;
        let expires_at = value
            .get("expires_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| protocol("OAuth-ответ не содержит expires_at"))?;
        // Both epoch seconds and the milliseconds used by deployed OAuth servers occur.
        let expires_at_secs = if expires_at > 100_000_000_000 {
            expires_at / 1000
        } else {
            expires_at
        };
        if expires_at_secs <= epoch_seconds() {
            return Err(fail(
                FailureKind::Auth,
                None,
                "OAuth-сервер вернул истёкший токен",
            ));
        }
        self.token = Some(AccessToken {
            value: token.into(),
            expires_at_secs,
        });
        Ok(())
    }

    async fn send_with_retry(&self, request: Request, generation: bool) -> Result<Response> {
        // This deadline stops at response headers. A total reqwest timeout would
        // also cut off an active SSE stream; body reads have their own idle timer.
        let (seconds, setting) = if generation {
            (self.settings.request_timeout_secs, "request_timeout_secs")
        } else {
            (self.settings.idle_timeout_secs, "idle_timeout_secs")
        };
        for attempt in 0..=MAX_RETRIES {
            let next = request
                .try_clone()
                .ok_or_else(|| protocol("HTTP-запрос нельзя повторить"))?;
            let client = if let Some(local) = &self.local {
                &local.client
            } else if is_loopback(request.url()) {
                &self.loopback_client
            } else if crate::certificates::official_gigachat_url(request.url()) {
                self.gigachat_client.as_ref().unwrap_or(&self.client)
            } else {
                &self.client
            };
            let response = tokio::time::timeout(Duration::from_secs(seconds), client.execute(next))
                .await
                .map_err(|_| {
                    transport(&format!(
                        "Превышено время ожидания ответа API: {seconds} с ({setting}). После таймаута запрос автоматически не повторяется. При необходимости увеличьте {setting} и повторите вручную; ожидание можно прервать Ctrl+C."
                    ))
                })?
                .map_err(|error| {
                    if self.is_local() {
                        return transport(&format!(
                            "Локальный сервер {} {}",
                            self.base,
                            if error.is_connect() {
                                "не отвечает. Запустите его или выберите другой профиль через /provider"
                            } else {
                                "оборвал соединение; проверьте, что сервер работает"
                            }
                        ));
                    }
                    transport(if error.is_connect() {
                        "Не удалось подключиться к API; проверьте сеть и CA-сертификат"
                    } else {
                        "Ошибка HTTP-транспорта API"
                    })
                })?;
            if matches!(response.status().as_u16(), 429 | 502 | 503) && attempt < MAX_RETRIES {
                // Only the status/headers have been inspected; no response body was consumed.
                let wait = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|seconds| Duration::from_secs(seconds.min(3)))
                    .unwrap_or_else(|| Duration::from_millis(250 * (1 << attempt)));
                drop(response);
                tokio::time::sleep(wait).await;
                continue;
            }
            return Ok(response);
        }
        unreachable!("bounded retry loop always returns")
    }

    async fn check_status(&self, response: Response) -> Result<Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let code = status.as_u16();
        if status.is_redirection() {
            return Err(fail(
                FailureKind::Protocol,
                Some(code),
                "API вернул перенаправление; укажите конечный HTTPS endpoint",
            ));
        }
        // Inspect for known context errors, but never include an upstream body (which can echo prompts or secrets).
        let bytes = read_bytes(response, self.idle()).await.unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        if self.is_local()
            && let Some((kind, message)) = self.local_failure(code, &text)
        {
            return Err(fail(kind, Some(code), &format!("{message} (HTTP {code})")));
        }
        let (kind, message) = if matches!(code, 401 | 403) {
            (
                FailureKind::Auth,
                "API отклонил авторизацию; проверьте ключ, scope и права",
            )
        } else if code == 429 {
            (
                FailureKind::RateLimit,
                "Лимит запросов API исчерпан; повторите позже",
            )
        } else if code == 413
            || (matches!(code, 400 | 422)
                && [
                    "context_length",
                    "context length",
                    "context window",
                    "maximum context",
                    "max input tokens",
                    "token limit",
                    "too many tokens",
                ]
                .iter()
                .any(|s| text.contains(s)))
        {
            (
                FailureKind::Context,
                "Контекст превышает лимит модели; используйте /compact",
            )
        } else if matches!(code, 400 | 422)
            && text.contains("field 'properties.")
            && text.contains("expected: stringvalue, actual: arrayvalue")
        {
            (
                FailureKind::Protocol,
                "API отклонил схему параметров инструмента: провайдер ожидает один тип параметра, а не список типов",
            )
        } else if status.is_server_error() {
            (FailureKind::Transport, "Сервер API временно недоступен")
        } else {
            (
                FailureKind::Protocol,
                "API отклонил запрос; проверьте endpoint, модель и параметры",
            )
        };
        Err(fail(kind, Some(code), &format!("{message} (HTTP {code})")))
    }
}

impl ProviderClient {
    /// Runtime-aware explanations for local servers; the body is only inspected.
    fn local_failure(&self, code: u16, text: &str) -> Option<(FailureKind, String)> {
        let profile = self
            .settings
            .local
            .as_ref()
            .map_or(crate::local::DRAFT_PROFILE, |local| local.profile.as_str());
        if matches!(code, 401 | 403) {
            return Some((
                FailureKind::Auth,
                format!(
                    "Локальный сервер требует ключ или отклонил его. Сохраните ключ профиля: rcode local key {profile} --stdin"
                ),
            ));
        }
        let mentions_tools = text.contains("tool")
            && ["support", "jinja", "template", "not enabled"]
                .iter()
                .any(|marker| text.contains(marker));
        if matches!(code, 400 | 422 | 500) && mentions_tools {
            return Some((
                FailureKind::Protocol,
                "Локальная модель или сервер не поддерживает вызов инструментов (tools); запрос не повторялся. Выберите модель с function calling; для llama.cpp запустите сервер с --jinja".into(),
            ));
        }
        if matches!(code, 400 | 413 | 422 | 500)
            && [
                "context size",
                "context length",
                "context window",
                "exceeds the available context",
                "n_ctx",
                "too many tokens",
            ]
            .iter()
            .any(|marker| text.contains(marker))
        {
            return Some((
                FailureKind::Context,
                "Запрос не помещается в контекст локального сервера. Уменьшите context_tokens профиля до фактического контекста сервера или увеличьте контекст на стороне сервера; /compact сократит историю".into(),
            ));
        }
        if code == 404 {
            return Some((
                FailureKind::Protocol,
                format!(
                    "Локальный сервер не нашёл модель {} или endpoint; проверьте /model и адрес профиля {profile}",
                    crate::ui::safe(&self.settings.model)
                ),
            ));
        }
        None
    }
}

const LOCAL_NO_VISION: &str = "Модель профиля local не подтверждает изображения; запрос не отправлен. Если сервер и модель поддерживают vision, включите его явно: rcode local add ИМЯ --vision --force";

/// Local servers: no proxy, no redirects, and `localhost` pinned to
/// 127.0.0.1 inside the client: neither a resolver nor an IPv6 fallback can
/// send a profile key to another address (see `local::endpoint_identity`).
fn local_client_builder() -> reqwest::ClientBuilder {
    use std::net::{Ipv4Addr, SocketAddr};
    client_builder()
        .no_proxy()
        .resolve("localhost", SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

pub(crate) fn local_http_client() -> Result<Client> {
    local_client_builder()
        .connect_timeout(crate::local_runtime::PROBE_DEADLINE)
        .build()
        .map_err(|_| transport("Не удалось создать клиент локального сервера"))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("rcode/", env!("CARGO_PKG_VERSION")))
}

fn validate_tool_output(
    completion: &Completion,
    tools: &[ToolDefinition],
    local: bool,
) -> Result<()> {
    let text = completion.content.trim_start();
    if local
        && completion.tool_calls.is_empty()
        && !tools.is_empty()
        && ["<tool_call>", "<function=", "[TOOL_CALL_START]"]
            .iter()
            .any(|marker| text.starts_with(marker))
    {
        return Err(protocol(
            "Локальный сервер вернул вызов инструмента обычным текстом вместо tool_calls; действие не исполнялось. Для llama.cpp запустите сервер с --jinja и шаблоном модели с tool calling; для MLX и LM Studio проверьте поддержку tool calling у модели и сервера.",
        ));
    }
    if completion.tool_calls.is_empty()
        && let Some(rest) = completion
            .content
            .trim_start()
            .strip_prefix("[TOOL_CALL_START]")
        && let Some(name) = rest.lines().next()
        && tools.iter().any(|tool| tool.name == name.trim())
    {
        return Err(protocol(
            "Модель вывела вызов инструмента обычным текстом вместо tool_calls; действие не исполнялось. Выберите модель с корректным function calling через /model.",
        ));
    }
    Ok(())
}

fn reasoning_metadata(model: &Value, kind: ProviderKind) -> (Option<bool>, Option<Vec<Effort>>) {
    let reasoning = model.get("reasoning");
    let efforts_value = reasoning
        .and_then(|reasoning| reasoning.get("supported_efforts"))
        .or_else(|| model.get("supported_efforts"));
    let mandatory = reasoning
        .and_then(|reasoning| reasoning.get("mandatory"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let supported_efforts = match efforts_value {
        Some(Value::Null) if kind == ProviderKind::OpenRouter => Some(
            Effort::all()
                .into_iter()
                .filter(|effort| !effort.is_auto() && (!mandatory || *effort != Effort::None))
                .collect(),
        ),
        Some(Value::Array(values)) => {
            let mut efforts = vec![];
            for value in values {
                if let Ok(effort) = serde_json::from_value::<Effort>(value.clone())
                    && !effort.is_auto()
                    && (!mandatory || effort != Effort::None)
                    && !efforts.contains(&effort)
                {
                    efforts.push(effort);
                }
            }
            Some(efforts)
        }
        _ => None,
    };
    let supports_reasoning = model
        .get("supports_reasoning")
        .and_then(Value::as_bool)
        .or_else(|| supported_efforts.as_ref().map(|_| true))
        .or_else(|| {
            if kind != ProviderKind::OpenRouter {
                return None;
            }
            model
                .get("supported_parameters")
                .and_then(Value::as_array)
                .map(|parameters| {
                    parameters.iter().any(|parameter| {
                        matches!(
                            parameter.as_str(),
                            Some("reasoning" | "reasoning.effort" | "reasoning_effort")
                        )
                    })
                })
        });
    (supports_reasoning, supported_efforts)
}

fn checked_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| protocol("Некорректный URL API"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(protocol(
            "URL API не должен содержать учётные данные, query или fragment",
        ));
    }
    let loopback = is_loopback(&url);
    if url.host_str().is_none()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        return Err(protocol(
            "API требует HTTPS; HTTP разрешён только для loopback",
        ));
    }
    Ok(url)
}
fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}
fn endpoint(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    url.set_path(&format!("{}/{}", base.path().trim_end_matches('/'), path));
    url
}
fn sensitive_header(value: &str) -> Result<HeaderValue> {
    let mut header = HeaderValue::from_str(value).map_err(|_| {
        fail(
            FailureKind::Auth,
            None,
            "Недопустимый формат заголовка авторизации",
        )
    })?;
    header.set_sensitive(true);
    Ok(header)
}
fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn fail(kind: FailureKind, status: Option<u16>, message: &str) -> anyhow::Error {
    ProviderFailure {
        kind,
        status,
        message: message.into(),
    }
    .into()
}
fn protocol(message: &str) -> anyhow::Error {
    fail(FailureKind::Protocol, None, message)
}
fn transport(message: &str) -> anyhow::Error {
    fail(FailureKind::Transport, None, message)
}
fn idle_timeout(idle: Duration) -> anyhow::Error {
    transport(&format!(
        "API не передаёт данные: idle timeout {} с (idle_timeout_secs). После таймаута запрос автоматически не повторяется; повторите вручную при необходимости. Ожидание можно прервать Ctrl+C.",
        idle.as_secs()
    ))
}

fn compatible_messages(messages: &[Message]) -> Result<Vec<Value>> {
    messages
        .iter()
        .map(|message| {
            let mut value = json!({"role":message.role,"content":message.content});
            if !message.images.is_empty() {
                let mut parts = vec![json!({"type":"text","text":message.content.as_deref().unwrap_or_default()})];
                for image in &message.images {
                    parts.push(json!({"type":"image_url","image_url":{"url":format!("data:{};base64,{}", image.mime_type, BASE64.encode(&*image.data))}}));
                }
                value["content"] = Value::Array(parts);
            }
            if !message.tool_calls.is_empty() {
                value["tool_calls"] = serde_json::to_value(&message.tool_calls)
                    .map_err(|_| protocol("Не удалось сериализовать вызов инструмента"))?;
            }
            if let Some(id) = &message.tool_call_id {
                value["tool_call_id"] = json!(id);
            }
            if let Some(name) = &message.name {
                value["name"] = json!(name);
            }
            Ok(value)
        })
        .collect()
}

fn giga_messages(messages: &[Message], uploaded: &BTreeMap<String, String>) -> Result<Vec<Value>> {
    let mut output = vec![];
    let mut index = 0;
    while index < messages.len() {
        let message = &messages[index];
        if message.role == "assistant" && !message.tool_calls.is_empty() {
            let count = message.tool_calls.len();
            let results = messages
                .get(index + 1..index + 1 + count)
                .ok_or_else(|| protocol("История содержит незавершённые вызовы инструментов"))?;
            if results.iter().any(|r| r.role != "tool") {
                return Err(protocol(
                    "После вызова инструмента отсутствует его результат",
                ));
            }
            let mut used = HashSet::new();
            for (position, call) in message.tool_calls.iter().enumerate() {
                if !used.insert(&call.id) {
                    return Err(protocol("Повторный идентификатор вызова инструмента"));
                }
                let matching: Vec<_> = results
                    .iter()
                    .filter(|r| r.tool_call_id.as_deref() == Some(call.id.as_str()))
                    .collect();
                if matching.len() != 1 {
                    return Err(protocol("Нарушена связь вызова инструмента с результатом"));
                }
                let arguments: Value = serde_json::from_str(&call.function.arguments)
                    .map_err(|_| protocol("Некорректные JSON-аргументы в истории"))?;
                if !arguments.is_object() {
                    return Err(protocol("Аргументы функции должны быть JSON-объектом"));
                }
                let mut assistant = json!({"role":"assistant","content":if position == 0 { message.content.as_deref().unwrap_or("") } else { "" },"function_call":{"name":call.function.name,"arguments":arguments}});
                giga_metadata(message, &mut assistant);
                output.push(assistant);
                let result = matching[0];
                let result_text = result.content.as_deref().unwrap_or("");
                let parsed = serde_json::from_str::<Value>(result_text)
                    .unwrap_or_else(|_| json!(result_text));
                let object = if parsed.is_object() {
                    parsed
                } else {
                    json!({"result":parsed})
                };
                output.push(json!({"role":"function","name":call.function.name,"content":object.to_string()}));
            }
            index += count + 1;
        } else {
            if message.role == "tool" {
                return Err(protocol(
                    "Результат инструмента без соответствующего вызова",
                ));
            }
            let mut value =
                json!({"role":message.role,"content":message.content.as_deref().unwrap_or("")});
            if message.role == "assistant" {
                giga_metadata(message, &mut value);
            }
            if !message.images.is_empty() {
                // GigaChat permits one image per message, ten per request.
                for (position, image) in message.images.iter().enumerate() {
                    let mut part = value.clone();
                    if position > 0 {
                        part["content"] =
                            json!("Ещё одно изображение к тому же запросу пользователя.");
                    }
                    let id = uploaded
                        .get(&image.sha256)
                        .ok_or_else(|| protocol("Изображение не загружено в Files API"))?;
                    part["attachments"] = json!([id]);
                    output.push(part);
                }
            } else {
                output.push(value);
            }
            index += 1;
        }
    }
    Ok(output)
}
fn giga_metadata(message: &Message, value: &mut Value) {
    if let Some(meta) = &message.provider_meta
        && meta.kind == "gigachat"
        && let Some(state) = meta.data.get("functions_state_id").and_then(Value::as_str)
    {
        value["functions_state_id"] = json!(state);
    }
}

async fn read_bytes(response: Response, idle: Duration) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY as u64)
    {
        return Err(protocol("Ответ API превышает лимит 8 MiB"));
    }
    let mut stream = response.bytes_stream();
    let mut output = Vec::new();
    while let Some(chunk) = tokio::time::timeout(idle, stream.next())
        .await
        .map_err(|_| idle_timeout(idle))?
    {
        let chunk =
            chunk.map_err(|_| transport("Соединение API оборвалось во время чтения ответа"))?;
        if output.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(protocol("Ответ API превышает лимит 8 MiB"));
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}
async fn read_json(response: Response, idle: Duration) -> Result<Value> {
    let bytes = read_bytes(response, idle).await?;
    serde_json::from_slice(&bytes).map_err(|_| protocol("API вернул некорректный JSON"))
}

#[derive(Default)]
struct Accumulator {
    completion: Completion,
    calls: BTreeMap<u64, PartialCall>,
    terminal: bool,
    yandex_name_ids: bool,
    /// Local servers only: reasoning fields and a leading `<think>` block are hidden.
    think: Option<crate::think::ThinkFilter>,
}
#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
    kind: String,
}
impl Accumulator {
    fn new(settings: &ProviderSettings) -> Self {
        Self {
            yandex_name_ids: settings.kind == ProviderKind::Yandex,
            think: settings
                .local
                .as_ref()
                .filter(|_| settings.kind == ProviderKind::Local)
                .map(|local| crate::think::ThinkFilter::for_local(local.runtime, local.thinking)),
            ..Self::default()
        }
    }
    /// Emits text held back while deciding about a leading `<think>` block.
    fn flush_reasoning(
        &mut self,
        streaming: bool,
        emit: &mut (dyn FnMut(&str) + Send),
    ) -> Result<()> {
        let Some(filter) = self.think.as_mut() else {
            return Ok(());
        };
        let rest = filter
            .finish(&mut self.completion.reasoning)
            .map_err(|_| {
                protocol("Модель не закрыла блок рассуждений <think>, ответа нет. Увеличьте max_output_tokens профиля или отключите рассуждения на сервере (rcode local add … --thinking off, если сервер это поддерживает)")
            })?;
        self.completion.content.push_str(&rest);
        if streaming && !rest.is_empty() {
            emit(&rest);
        }
        Ok(())
    }
    fn json_completion(&mut self, value: &Value, giga: bool) -> Result<()> {
        self.common(value)?;
        let choice = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .ok_or_else(|| protocol("Ответ API не содержит choices"))?;
        let message = choice
            .get("message")
            .filter(|v| v.is_object())
            .ok_or_else(|| protocol("Ответ API не содержит message"))?;
        self.message_delta(message, giga, false, &mut |_| {})?;
        self.finish_reason(choice)?;
        Ok(())
    }
    fn common(&mut self, value: &Value) -> Result<()> {
        if value.get("error").is_some_and(|error| !error.is_null()) {
            let code = value["error"]["code"]
                .as_u64()
                .and_then(|s| u16::try_from(s).ok());
            let kind = match code {
                Some(401 | 403) => FailureKind::Auth,
                Some(429) => FailureKind::RateLimit,
                _ => FailureKind::Protocol,
            };
            return Err(fail(
                kind,
                code,
                "API сообщил об ошибке генерации; ответ не завершён",
            ));
        }
        if let Some(model) = value.get("model").and_then(Value::as_str) {
            self.completion.model = Some(model.into());
        }
        if let Some(usage) = value.get("usage").filter(|v| !v.is_null()) {
            self.completion.usage = Usage {
                input_tokens: usage
                    .get("prompt_tokens")
                    .or_else(|| usage.get("input_tokens"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                output_tokens: usage
                    .get("completion_tokens")
                    .or_else(|| usage.get("output_tokens"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                cached_input_tokens: usage
                    .pointer("/prompt_tokens_details/cached_tokens")
                    .or_else(|| usage.get("precached_prompt_tokens"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                cost_usd: usage
                    .get("cost")
                    .and_then(Value::as_f64)
                    .filter(|cost| cost.is_finite() && *cost >= 0.0),
            };
        }
        Ok(())
    }
    fn stream_event(
        &mut self,
        value: &Value,
        giga: bool,
        emit: &mut (dyn FnMut(&str) + Send),
    ) -> Result<()> {
        self.common(value)?;
        let choices = value
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| protocol("SSE событие не содержит choices"))?;
        for choice in choices {
            if choice
                .get("index")
                .and_then(Value::as_u64)
                .is_some_and(|i| i != 0)
            {
                continue;
            }
            if let Some(delta) = choice.get("delta") {
                self.message_delta(delta, giga, true, emit)?;
            }
            self.finish_reason(choice)?;
        }
        Ok(())
    }
    fn message_delta(
        &mut self,
        delta: &Value,
        giga: bool,
        streaming: bool,
        emit: &mut (dyn FnMut(&str) + Send),
    ) -> Result<()> {
        if let Some(role) = delta.get("role").and_then(Value::as_str)
            && !matches!(role, "assistant" | "")
        {
            return Err(protocol("Неожиданная роль в ответе модели"));
        }
        if self.terminal
            && (delta
                .get("content")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
                || delta
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty())
                || delta
                    .get("function_call")
                    .is_some_and(|call| !call.is_null()))
        {
            return Err(protocol("SSE содержит новые данные после finish_reason"));
        }
        if self.think.is_some() {
            for field in ["reasoning_content", "reasoning"] {
                if let Some(text) = delta.get(field).and_then(Value::as_str) {
                    self.completion.reasoning.push_str(text);
                }
            }
        }
        if let Some(content) = delta.get("content").filter(|v| !v.is_null()) {
            let text = content
                .as_str()
                .ok_or_else(|| protocol("API вернул нетекстовый content"))?;
            let visible = match self.think.as_mut() {
                Some(filter) => filter.push(text, &mut self.completion.reasoning),
                None => text.to_owned(),
            };
            self.completion.content.push_str(&visible);
            if streaming && !visible.is_empty() {
                emit(&visible);
            }
        }
        if giga {
            if let Some(state) = delta.get("functions_state_id").and_then(Value::as_str) {
                self.completion.provider_meta = Some(ProviderMeta {
                    kind: "gigachat".into(),
                    data: json!({"functions_state_id":state}),
                });
            }
            if let Some(call) = delta.get("function_call").filter(|v| !v.is_null()) {
                self.call_delta(0, call, true, streaming)?;
            }
        } else if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for (position, call) in calls.iter().enumerate() {
                let index = if streaming {
                    call.get("index")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| protocol("SSE tool_call не содержит index"))?
                } else {
                    position as u64
                };
                let partial = self.calls.entry(index).or_default();
                if let Some(id) = call.get("id").and_then(Value::as_str) {
                    partial.id.push_str(id);
                }
                if let Some(kind) = call.get("type").and_then(Value::as_str) {
                    partial.kind = kind.into();
                }
                if let Some(function) = call.get("function") {
                    self.call_delta(index, function, false, streaming)?;
                }
            }
        }
        if self.calls.len() > MAX_CALLS {
            return Err(protocol("Слишком много вызовов инструментов в ответе API"));
        }
        Ok(())
    }
    fn call_delta(
        &mut self,
        index: u64,
        function: &Value,
        giga: bool,
        streaming: bool,
    ) -> Result<()> {
        let partial = self.calls.entry(index).or_default();
        if let Some(name) = function.get("name").and_then(Value::as_str) {
            partial.name.push_str(name);
        }
        if let Some(arguments) = function.get("arguments") {
            if let Some(text) = arguments.as_str() {
                partial.arguments.push_str(text);
            } else if giga && arguments.is_object() && (!streaming || partial.arguments.is_empty())
            {
                partial.arguments = arguments.to_string();
            } else {
                return Err(protocol("Некорректный формат аргументов функции"));
            }
        }
        Ok(())
    }
    fn finish_reason(&mut self, choice: &Value) -> Result<()> {
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            if !matches!(reason, "stop" | "tool_calls" | "function_call") {
                return Err(protocol(if reason == "length" {
                    "Ответ модели обрезан лимитом токенов; увеличьте max_output_tokens"
                } else {
                    "Модель не завершила ответ (фильтрация или ошибка генерации)"
                }));
            }
            if self.terminal && self.completion.finish_reason != reason {
                return Err(protocol("Противоречивый finish_reason в SSE"));
            }
            self.completion.finish_reason = reason.into();
            self.terminal = true;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<Completion> {
        if !self.terminal {
            return Err(protocol(
                "Ответ API оборвался до finish_reason; инструменты не исполнены",
            ));
        }
        let mut ids = HashSet::new();
        for (_, partial) in self.calls {
            if partial.name.is_empty() || (!partial.kind.is_empty() && partial.kind != "function") {
                return Err(protocol("Неполное описание вызова инструмента"));
            }
            let arguments: Value = serde_json::from_str(&partial.arguments).map_err(|_| {
                protocol("Аргументы инструмента содержат неполный или некорректный JSON")
            })?;
            if !arguments.is_object() {
                return Err(protocol("Аргументы инструмента должны быть JSON-объектом"));
            }
            // Some Yandex models use the function name as a non-unique ID.
            // Distinct structured indexes remain distinct calls; only their
            // correlation IDs are replaced, exactly as for a missing ID.
            let id =
                if partial.id.is_empty() || (self.yandex_name_ids && partial.id == partial.name) {
                    format!("call_{}", uuid::Uuid::new_v4().simple())
                } else {
                    partial.id
                };
            if !ids.insert(id.clone()) {
                return Err(protocol("Повторный идентификатор вызова инструмента"));
            }
            self.completion.tool_calls.push(ToolCall {
                id,
                kind: "function".into(),
                function: FunctionCall {
                    name: partial.name,
                    arguments: partial.arguments,
                },
            });
        }
        if matches!(
            self.completion.finish_reason.as_str(),
            "tool_calls" | "function_call"
        ) && self.completion.tool_calls.is_empty()
        {
            return Err(protocol("Модель завершила вызов функции без её аргументов"));
        }
        Ok(self.completion)
    }
}

async fn read_sse(
    response: Response,
    idle: Duration,
    settings: &ProviderSettings,
    emit: &mut (dyn FnMut(&str) + Send),
) -> Result<Completion> {
    let kind = settings.kind;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY as u64)
    {
        return Err(protocol("Ответ API превышает лимит 8 MiB"));
    }
    let mut stream = response.bytes_stream();
    let mut pending = Vec::<u8>::new();
    let mut data = String::new();
    let mut bytes = 0usize;
    let giga = kind == ProviderKind::GigaChat;
    let mut accumulator = Accumulator::new(settings);
    while let Some(chunk) = tokio::time::timeout(idle, stream.next())
        .await
        .map_err(|_| idle_timeout(idle))?
    {
        let chunk = chunk
            .map_err(|_| transport("SSE-соединение оборвалось; частичный ответ не сохранён"))?;
        bytes = bytes.saturating_add(chunk.len());
        if bytes > MAX_BODY {
            return Err(protocol("Ответ API превышает лимит 8 MiB"));
        }
        pending.extend_from_slice(&chunk);
        let mut consumed = 0;
        while let Some(relative) = pending[consumed..].iter().position(|b| *b == b'\n') {
            let end = consumed + relative;
            let mut line = &pending[consumed..end];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            let line = std::str::from_utf8(line)
                .map_err(|_| protocol("SSE содержит некорректный UTF-8"))?;
            if line.is_empty() {
                if !data.is_empty() {
                    if data.trim() == "[DONE]" {
                        accumulator.flush_reasoning(true, emit)?;
                        return accumulator.finish();
                    }
                    let value: Value = serde_json::from_str(&data)
                        .map_err(|_| protocol("SSE содержит некорректный JSON"))?;
                    accumulator.stream_event(&value, giga, emit)?;
                    data.clear();
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value.strip_prefix(' ').unwrap_or(value));
            }
            consumed = end + 1;
        }
        pending.drain(..consumed);
    }
    Err(protocol(
        "SSE оборвался до [DONE]; частичный ответ не сохранён, инструменты не исполнены",
    ))
}
