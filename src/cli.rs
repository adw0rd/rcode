pub use crate::config::ApprovalMode;
use crate::config::{Effort, ProviderKind};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rcode",
    version,
    about = "Агент разработки с Yandex AI Studio, GigaChat и OpenRouter",
    after_help = "Без подкоманды открывает интерактивный терминал.\nПример: rcode --provider openrouter\n        rcode exec --approval-mode auto-edit 'Исправь ошибку и проверь тесты'"
)]
pub struct Cli {
    #[arg(short = 'C', long = "directory", global = true, default_value = ".")]
    pub directory: PathBuf,
    #[arg(
        long,
        global = true,
        value_name = "КАТАЛОГ",
        help = "Разрешить файловым инструментам дополнительный каталог; можно повторять"
    )]
    pub add_dir: Vec<PathBuf>,
    #[arg(long, global = true)]
    pub provider: Option<ProviderKind>,
    #[arg(long, global = true)]
    pub model: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Глубина рассуждений: auto, low, medium, high и уровни модели"
    )]
    pub effort: Option<Effort>,
    #[arg(long, global = true, help = "Простой интерфейс без панелей и анимации")]
    pub plain: bool,
    #[arg(long, global = true)]
    pub base_url: Option<String>,
    #[arg(long, global = true)]
    pub folder_id: Option<String>,
    #[arg(long, global = true)]
    pub ca_file: Option<PathBuf>,
    #[arg(long, global=true, num_args=0..=1, default_missing_value="latest")]
    pub resume: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Явно сократить историю перед новым запросом"
    )]
    pub compact: bool,
    #[arg(
        long,
        global = true,
        value_enum,
        help = "Режим разрешений; по умолчанию — сохранённый для проекта или ask"
    )]
    pub approval_mode: Option<ApprovalMode>,
    #[arg(
        long,
        global = true,
        help = "Разрешить команды shell с правами пользователя"
    )]
    pub allow_shell: bool,
    #[arg(
        long,
        global = true,
        help = "Только исследование и план, без изменений и shell"
    )]
    pub plan: bool,
    #[arg(long, global = true, help = "Версионированные события JSONL в stdout")]
    pub json: bool,
    #[arg(long, global=true, default_value_t=32, value_parser=clap::value_parser!(u32).range(1..=256), help="Предел запросов к модели за один ход (1–256); новый запрос начинает новый ход")]
    pub max_steps: u32,
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(help = "Начальный запрос для интерактивной сессии")]
    pub prompt: Option<String>,
}
impl Cli {
    pub fn permissions(&self) -> ApprovalMode {
        self.approval_mode.unwrap_or_default()
    }

    pub fn file_edits_allowed(&self) -> bool {
        matches!(
            self.permissions(),
            ApprovalMode::AutoEdit | ApprovalMode::FullAccess
        )
    }

    pub fn shell_allowed(&self) -> bool {
        self.allow_shell || self.permissions() == ApprovalMode::FullAccess
    }

    pub fn for_project(&self, saved: ApprovalMode) -> Self {
        let mut resolved = self.clone();
        resolved.approval_mode = Some(self.approval_mode.unwrap_or(saved));
        resolved
    }
}
#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    #[command(about = "Выполнить задачу и завершиться")]
    Exec {
        #[arg(required=true, num_args=1..)]
        prompt: Vec<String>,
    },
    #[command(about = "Настроить провайдера и ключ доступа")]
    Connect { provider: Option<ProviderKind> },
    #[command(about = "Список моделей выбранного провайдера")]
    Models,
    #[command(about = "Баланс провайдера и доступные лимиты API")]
    Balance,
    #[command(about = "Сохранённые локальные сессии")]
    Sessions,
    #[command(about = "Проверить настройки; --check проверяет доступ к API")]
    Doctor {
        #[arg(long)]
        check: bool,
    },
}
