use crate::config::{Effort, ProviderKind};
use clap::{Parser, Subcommand, ValueEnum};
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
    #[arg(long, global = true, value_enum, default_value = "ask")]
    pub approval_mode: ApprovalMode,
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
    #[arg(long, global=true, default_value_t=32, value_parser=clap::value_parser!(u32).range(1..=256))]
    pub max_steps: u32,
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(help = "Начальный запрос для интерактивной сессии")]
    pub prompt: Option<String>,
}
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum ApprovalMode {
    Ask,
    AutoEdit,
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
    #[command(about = "Сохранённые локальные сессии")]
    Sessions,
    #[command(about = "Проверить настройки; --check проверяет доступ к API")]
    Doctor {
        #[arg(long)]
        check: bool,
    },
}
