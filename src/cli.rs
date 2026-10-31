pub use crate::config::ApprovalMode;
use crate::config::{Effort, ProviderKind};
use crate::local::LocalRuntime;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rcode",
    version,
    about = "Агент разработки с Yandex AI Studio, GigaChat, OpenRouter и локальными моделями",
    after_help = "Без подкоманды открывает интерактивный терминал.\nПример: rcode --provider openrouter\n        rcode exec --approval-mode auto-edit 'Исправь ошибку и проверь тесты'\n        rcode local add qwen --base-url http://127.0.0.1:11434/v1 --runtime ollama --activate\n        rcode exec --profile qwen 'Объясни структуру проекта'"
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
    #[arg(
        long,
        global = true,
        value_name = "ИМЯ",
        help = "Профиль локальной модели; подразумевает --provider local"
    )]
    pub profile: Option<String>,
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
    #[command(
        about = "Профили локальных моделей (Ollama, llama.cpp, MLX, LM Studio)",
        after_help = "Ключ никогда не передаётся аргументом: используйте --api-key-stdin или rcode local key ИМЯ --stdin.\nСервер запускаете вы сами на 127.0.0.1; rcode его не запускает и не меняет его контекст."
    )]
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Toggle {
    On,
    Off,
}

#[derive(Debug, Subcommand, Clone)]
pub enum LocalCommand {
    #[command(about = "Найти серверы на 127.0.0.1:11434, :8080 и :1234")]
    Discover,
    #[command(about = "Список профилей")]
    List,
    #[command(
        about = "Добавить профиль: rcode local add ИМЯ --base-url URL [--model ID]",
        after_help = "Без --model берётся первая модель из /models сервера. Если сервер не запущен, укажите --model: профиль сохранится."
    )]
    Add {
        name: String,
        #[arg(
            long,
            value_enum,
            help = "Тип сервера; по умолчанию угадывается по порту"
        )]
        runtime: Option<LocalRuntime>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(2048..=1_048_576), help = "Контекст сервера в токенах (по умолчанию 32768)")]
        context_tokens: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=8192), help = "Предел ответа (по умолчанию 4096, не больше четверти контекста)")]
        max_output_tokens: Option<u32>,
        #[arg(long, help = "Модель и сервер принимают изображения")]
        vision: bool,
        #[arg(
            long,
            value_enum,
            help = "Явно передавать chat_template_kwargs.enable_thinking"
        )]
        thinking: Option<Toggle>,
        #[arg(long, help = "Прочитать ключ сервера из stdin")]
        api_key_stdin: bool,
        #[arg(long, help = "Сделать профиль активным")]
        activate: bool,
        #[arg(long, help = "Заменить существующий профиль")]
        force: bool,
    },
    #[command(about = "Сделать профиль активным; --model меняет его модель")]
    Use { name: String },
    #[command(about = "Сохранить ключ из stdin (--stdin) или удалить его (--delete)")]
    Key {
        name: String,
        #[arg(long, conflicts_with = "delete", required_unless_present = "delete")]
        stdin: bool,
        #[arg(long)]
        delete: bool,
    },
    #[command(about = "Удалить профиль вместе с ключом")]
    Remove { name: String },
}
