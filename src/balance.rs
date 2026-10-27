//! Фоновый баланс локален; явный инструмент возвращает модели снимок текущего провайдера.
use crate::{config::ProviderKind, presentation, ui};
use crate::{
    protocol::{ToolDefinition, ToolOutcome},
    provider::ProviderClient,
    screen::Screen,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub(crate) const TOOL_NAME: &str = "get_provider_balance";

pub(crate) struct BalanceTool {
    client: ProviderClient,
    model: String,
}

impl BalanceTool {
    pub(crate) fn new(client: ProviderClient, model: String) -> Self {
        Self { client, model }
    }

    pub(crate) fn definition() -> ToolDefinition {
        ToolDefinition {
            name: TOOL_NAME.into(),
            description: "Узнать свежий баланс текущего провайдера по вопросу пользователя: остаток USD OpenRouter или токенов пакета выбранной модели GigaChat. Только чтение, без shell и доступа к ключам. Недоступные данные не означают нулевой баланс. Аргументов нет; другого провайдера выбрать нельзя.".into(),
            parameters: json!({"type":"object","properties":{},"required":[],"additionalProperties":false}),
        }
    }

    pub(crate) async fn execute(
        &mut self,
        args: &Value,
        cancel: &CancellationToken,
    ) -> ToolOutcome {
        if !args.as_object().is_some_and(|args| args.is_empty()) {
            return ToolOutcome::error(
                "get_provider_balance принимает только {}; провайдер и модель берутся из текущей сессии",
            );
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return ToolOutcome::error("Запрос баланса отменён; свежие данные не получены"),
            result = fetch(&mut self.client) => result,
        };
        match result {
            Ok(report) => ToolOutcome::success(report.model_snapshot(&self.model).to_string()),
            Err(error) => ToolOutcome::error(format!("Не удалось получить свежий баланс: {error}")),
        }
    }
}

pub(crate) async fn fetch(client: &mut ProviderClient) -> anyhow::Result<BalanceReport> {
    tokio::time::timeout(Duration::from_secs(8), client.balance())
        .await
        .map_err(|_| anyhow::anyhow!("Баланс: превышено время ожидания API (8 с)"))?
}

pub(crate) struct BalanceMonitor {
    requests: mpsc::Sender<oneshot::Sender<Result<BalanceReport, String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl BalanceMonitor {
    pub(crate) fn start(mut client: ProviderClient, model: String, screen: Arc<Screen>) -> Self {
        let id = screen.begin_balance();
        let (requests, mut receive) =
            mpsc::channel::<oneshot::Sender<Result<BalanceReport, String>>>(1);
        let task = tokio::spawn(async move {
            let mut pending = None::<oneshot::Sender<Result<BalanceReport, String>>>;
            let mut last = None::<String>;
            loop {
                let result = fetch(&mut client).await.map_err(|e| e.to_string());
                let label = match &result {
                    Ok(report) => {
                        let label = report.footer(&model);
                        last = Some(label.clone());
                        label
                    }
                    Err(_) => last
                        .as_ref()
                        .map(|label| format!("{label} · устар."))
                        .unwrap_or_else(|| "Баланс: недоступен".into()),
                };
                screen.set_balance(id, label);
                if let Some(waiter) = pending.take() {
                    let _ = waiter.send(result);
                }
                tokio::select! {
                    request=receive.recv()=>{
                        match request {Some(request)=>pending=Some(request),None=>break}
                    },
                    _=tokio::time::sleep(Duration::from_secs(60))=>{},
                }
            }
        });
        Self { requests, task }
    }
    pub(crate) async fn refresh(&self) -> anyhow::Result<BalanceReport> {
        let (send, receive) = oneshot::channel();
        self.requests
            .send(send)
            .await
            .map_err(|_| anyhow::anyhow!("Монитор баланса остановлен"))?;
        receive
            .await
            .map_err(|_| anyhow::anyhow!("Обновление баланса отменено"))?
            .map_err(anyhow::Error::msg)
    }
}
impl Drop for BalanceMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBalance {
    pub usage: String,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BalanceReport {
    pub provider: ProviderKind,
    pub remaining_usd: Option<f64>,
    pub key_remaining_usd: Option<f64>,
    pub key_limit_usd: Option<f64>,
    pub key_usage_usd: Option<f64>,
    pub token_balances: Vec<TokenBalance>,
    pub note: Option<String>,
    pub checked_at: u64,
}

impl BalanceReport {
    pub(crate) fn empty(provider: ProviderKind) -> Self {
        Self {
            provider,
            remaining_usd: None,
            key_remaining_usd: None,
            key_limit_usd: None,
            key_usage_usd: None,
            token_balances: Vec::new(),
            note: None,
            checked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn selected_tokens(&self, model: &str) -> Option<&TokenBalance> {
        let model = model.strip_suffix("-preview").unwrap_or(model);
        self.token_balances
            .iter()
            .find(|pool| pool.usage.eq_ignore_ascii_case(model))
            .or_else(|| {
                // GigaChat's balance names identify a family, without its generation:
                // the live API returns GigaChat-Ultra for GigaChat-3-Ultra.
                let rest = model.strip_prefix("GigaChat-")?;
                let (generation, family) = rest.split_once('-')?;
                if !generation.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                let family = format!("GigaChat-{family}");
                self.token_balances
                    .iter()
                    .find(|pool| pool.usage.eq_ignore_ascii_case(&family))
            })
    }

    fn model_snapshot(&self, model: &str) -> Value {
        let tokens = self.selected_tokens(model);
        json!({
            "provider": self.provider,
            "model": model,
            "checked_at": self.checked_at,
            "available": self.remaining_usd.is_some() || self.key_remaining_usd.is_some() || tokens.is_some(),
            "remaining_usd": self.remaining_usd,
            "key_remaining_usd": self.key_remaining_usd,
            "key_limit_usd": self.key_limit_usd,
            "selected_token_balance": tokens,
            "note": self.note,
        })
    }

    pub fn footer(&self, model: &str) -> String {
        if let Some(value) = self.remaining_usd {
            let mut label = format!("Баланс ${value:.2}");
            if let Some(key) = self.key_remaining_usd {
                label.push_str(&format!(" · ключ ${key:.2}"));
            }
            return label;
        }
        if let Some(value) = self.key_remaining_usd {
            return format!("Лимит ключа ${value:.2}");
        }
        if let Some(pool) = self.selected_tokens(model) {
            return format!("Остаток {} ток.", presentation::number(pool.value));
        }
        if !self.token_balances.is_empty() {
            return "Токены: /balance".into();
        }
        "Баланс: нет данных".into()
    }

    pub fn details(&self, model: &str) -> String {
        let mut rows = vec![format!("Баланс · {}", self.provider)];
        if let Some(value) = self.remaining_usd {
            rows.push(format!("Счёт OpenRouter: ${value:.4}"));
        }
        if let Some(value) = self.key_remaining_usd {
            rows.push(format!("Остаток лимита ключа: ${value:.4}"));
        }
        if let Some(value) = self.key_limit_usd {
            rows.push(format!("Лимит ключа: ${value:.4}"));
        } else if self.provider == ProviderKind::OpenRouter && self.key_usage_usd.is_some() {
            rows.push("Лимит ключа не задан; это не означает неограниченный баланс счёта.".into());
        }
        if let Some(value) = self.key_usage_usd {
            rows.push(format!("Расход ключа за всё время: ${value:.4}"));
        }
        let selected_pool = self.selected_tokens(model);
        for pool in &self.token_balances {
            let selected = selected_pool.is_some_and(|current| std::ptr::eq(current, pool));
            rows.push(format!(
                "{}: {} токенов{}",
                ui::safe(&pool.usage),
                pool.value,
                if selected {
                    " · выбранная модель"
                } else {
                    ""
                }
            ));
        }
        if let Some(note) = &self.note {
            rows.push(note.clone());
        }
        let link = match self.provider {
            ProviderKind::OpenRouter => Some("https://openrouter.ai/settings/credits"),
            ProviderKind::GigaChat => Some("https://developers.sber.ru/studio/"),
            ProviderKind::Yandex => Some("https://center.yandex.cloud/billing/accounts"),
            ProviderKind::Custom => None,
        };
        if let Some(link) = link {
            rows.push(format!("Кабинет: {link}"));
        }
        rows.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_and_negative_balances_are_real_values_and_unknown_pools_are_not_summed() {
        let mut report = BalanceReport::empty(ProviderKind::OpenRouter);
        report.remaining_usd = Some(0.0);
        assert_eq!(report.footer("any"), "Баланс $0.00");
        report.remaining_usd = Some(-1.25);
        assert_eq!(report.footer("any"), "Баланс $-1.25");
        report.remaining_usd = None;
        report.token_balances = vec![
            TokenBalance {
                usage: "GigaChat-Ultra".into(),
                value: 40,
            },
            TokenBalance {
                usage: "GigaChat-Max".into(),
                value: 900,
            },
        ];
        assert_eq!(report.footer("GigaChat-3-Ultra"), "Остаток 40 ток.");
        assert_eq!(report.footer("unknown"), "Токены: /balance");
        let snapshot = report.model_snapshot("GigaChat-3-Ultra");
        assert_eq!(snapshot["selected_token_balance"]["value"], 40);
        assert!(
            snapshot.get("token_balances").is_none(),
            "Other model pools must not be included"
        );
        assert_eq!(report.model_snapshot("unknown")["available"], false);
    }

    #[tokio::test]
    async fn cancelled_balance_tool_drops_its_pending_http_request() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut settings = crate::config::ProviderSettings::new(ProviderKind::OpenRouter);
        settings.base_url = Some(format!("http://{}/v1", listener.local_addr().unwrap()));
        let client = ProviderClient::new(settings, "cancel-balance-fixture".into()).unwrap();
        let cancel = CancellationToken::new();
        let signal = cancel.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 4096];
            let n = socket.read(&mut bytes).await.unwrap();
            assert!(String::from_utf8_lossy(&bytes[..n]).starts_with("GET /v1/key "));
            signal.cancel();
            let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 0, "Cancelled metadata future must close the socket");
        });
        let mut tool = BalanceTool::new(client, "test".into());
        let outcome =
            tokio::time::timeout(Duration::from_secs(3), tool.execute(&json!({}), &cancel))
                .await
                .unwrap();
        assert!(outcome.is_error);
        assert!(outcome.content.contains("отменён"));
        assert!(!outcome.content.contains("cancel-balance-fixture"));
        server.await.unwrap();
    }
}
