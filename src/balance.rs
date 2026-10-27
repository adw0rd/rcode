//! Данные баланса остаются в интерфейсе, отдельно от модельной истории.
use crate::{config::ProviderKind, presentation, ui};
use crate::{provider::ProviderClient, screen::Screen};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

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
    }
}
