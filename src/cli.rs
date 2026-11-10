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
    #[arg(
        long,
        global = true,
        help = "Включить отдельный финальный обзор текущего ответа выбранной моделью"
    )]
    pub final_review: bool,
    #[arg(
        long,
        global = true,
        conflicts_with = "final_review",
        help = "Включить финальное ревью с одним ограниченным проходом исправления и проверки"
    )]
    pub final_review_repair: bool,
    #[arg(long, global=true, default_value_t=32, value_parser=clap::value_parser!(u32).range(1..=256), help="Предел запросов к модели за один ход (1–256); новый запрос начинает новый ход")]
    pub max_steps: u32,
    #[arg(
        long,
        global = true,
        default_value_t = 120,
        value_parser = clap::value_parser!(u64).range(1..=3600),
        help = "Общий срок работы субагента по часам (1–3600 секунд), включая очередь, API и инструменты; отдельный от HTTP timeout и TTL процесса, модель его не задаёт"
    )]
    pub agent_timeout_secs: u64,
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

    pub fn final_review_mode(&self) -> crate::final_review::FinalReviewMode {
        if self.final_review_repair {
            crate::final_review::FinalReviewMode::Repair
        } else if self.final_review {
            crate::final_review::FinalReviewMode::OneShot
        } else {
            crate::final_review::FinalReviewMode::Off
        }
    }

    pub fn set_final_review_mode(&mut self, mode: crate::final_review::FinalReviewMode) {
        self.final_review = mode == crate::final_review::FinalReviewMode::OneShot;
        self.final_review_repair = mode == crate::final_review::FinalReviewMode::Repair;
    }
}
#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    #[command(about = "Изолированная проверка качества агента")]
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
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
    #[command(about = "Настроить модель финального ревью (без сетевого запроса)")]
    ReviewModel {
        #[command(subcommand)]
        command: ReviewModelCommand,
    },
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
    #[command(
        about = "Скиллы: каталог, источники, включённость",
        after_help = "Установка наборов меняет файлы в RCODE_HOME и выполняет git; сеть используется только по подтверждению."
    )]
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    #[command(about = "Пользовательские команды: файлы в RCODE_HOME/commands и .rcode/commands")]
    Commands {
        #[command(subcommand)]
        command: CommandsCommand,
    },
    #[command(about = "Веб-поиск для инструмента web_search: Yandex Search API, Brave или Tavily")]
    Websearch {
        #[command(subcommand)]
        command: WebsearchCommand,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum ReviewModelCommand {
    #[command(about = "Показать выбранный маршрут")]
    Status,
    #[command(about = "Использовать текущий маршрут основной модели")]
    Same,
    #[command(about = "Сохранить модель настроенного провайдера или профиля local")]
    Set {
        #[arg(long)]
        model: String,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum WebsearchCommand {
    #[command(about = "Показать настроенного провайдера поиска")]
    Status,
    #[command(about = "Выбрать провайдера поиска: yandex, brave или tavily")]
    Provider {
        #[arg(value_name = "PROVIDER")]
        name: String,
    },
    #[command(about = "Ключ провайдера: читается из stdin или скрытым вводом")]
    Key {
        #[arg(long, visible_alias = "stdin")]
        api_key_stdin: bool,
    },
    #[command(about = "Отключить веб-поиск и удалить ключ")]
    Clear,
}

#[derive(Debug, Subcommand, Clone)]
pub enum SkillsCommand {
    #[command(about = "Найденные скиллы и их статус")]
    List {
        #[arg(long)]
        verbose: bool,
    },
    #[command(about = "Установить набор скиллов из git-репозитория или каталога")]
    Install {
        source: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "ref")]
        reference: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        yes: bool,
    },
    #[command(about = "Проверить обновления установленных наборов (сеть)")]
    Check {
        labels: Vec<String>,
        #[arg(long)]
        yes: bool,
    },
    #[command(about = "Обновить установленные наборы")]
    Update {
        labels: Vec<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        yes: bool,
    },
    #[command(about = "Удалить установленный набор")]
    Remove {
        label: String,
        #[arg(long)]
        yes: bool,
    },
    #[command(
        about = "Подключить чужой каталог скиллов (например ~/.agents/skills) без копирования"
    )]
    Link {
        path: String,
        #[arg(long)]
        name: String,
    },
    #[command(about = "Отключить подключённый каталог скиллов")]
    Unlink { label: String },
    #[command(about = "Включить скиллы для каталога модели")]
    Enable { ids: Vec<String> },
    #[command(about = "Исключить скиллы из каталога модели")]
    Disable { ids: Vec<String> },
}

#[derive(Debug, Subcommand, Clone)]
pub enum CommandsCommand {
    #[command(about = "Найденные пользовательские команды")]
    List,
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

#[derive(Debug, Subcommand, Clone)]
pub enum EvalCommand {
    #[command(about = "Проверить manifest/fixtures/oracles без исполнения и сети")]
    Validate {
        #[arg(long)]
        suite: PathBuf,
    },
    #[command(
        about = "Изолированный Linux-прогон; требует Docker, Python и явного local или GigaChat profile"
    )]
    Run(Box<EvalRun>),
    #[command(about = "Сравнить отчёты с одинаковыми корпусом и настройками")]
    Compare {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
    },
}

#[derive(Debug, clap::Args, Clone)]
pub struct EvalRun {
    #[arg(long)]
    pub suite: PathBuf,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(
        long,
        help = "Сохранить исходники кейсов в новый каталог для локального review"
    )]
    pub snapshots: Option<PathBuf>,
    #[arg(long)]
    pub agent_binary: PathBuf,
    #[arg(
        long,
        help = "Локальный immutable image ID sha256:…; автоматической загрузки нет"
    )]
    pub image: String,
    #[arg(long)]
    pub docker_socket: PathBuf,
    #[arg(long, default_value = "docker")]
    pub docker: PathBuf,
    #[arg(long, default_value = "python3")]
    pub python: PathBuf,
    #[arg(long)]
    pub series: String,
    #[arg(long)]
    pub source_sha256: Option<String>,
    #[arg(
        long,
        help = "Явно разрешить JSON transport для streaming-профиля в этом прогоне"
    )]
    pub non_streaming: bool,
    #[arg(
        long,
        help = "Разрешить запуск недоверенного проекта в изолированных контейнерах"
    )]
    pub yes: bool,
}

#[cfg(test)]
mod agent_timeout_cli_tests {
    use super::{Cli, Command, EvalCommand};
    use clap::{CommandFactory, Parser};
    use std::path::PathBuf;

    fn parsed_timeout(args: &[&str]) -> Result<Option<u64>, clap::Error> {
        let matches = Cli::command().try_get_matches_from(args)?;
        Ok(matches
            .try_get_one::<u64>("agent_timeout_secs")
            .ok()
            .flatten()
            .copied())
    }

    #[test]
    fn agent_timeout_defaults_to_120_for_interactive_and_exec() {
        assert_eq!(parsed_timeout(&["rcode"]).unwrap(), Some(120));
        assert_eq!(
            parsed_timeout(&["rcode", "exec", "task"]).unwrap(),
            Some(120)
        );
    }

    #[test]
    fn agent_timeout_flag_parses_before_and_after_exec_and_with_prompt() {
        assert_eq!(
            parsed_timeout(&["rcode", "--agent-timeout-secs", "600", "exec", "task"]).unwrap(),
            Some(600)
        );
        Cli::try_parse_from(["rcode", "--agent-timeout-secs", "600", "exec", "task"])
            .expect("global timeout flag before exec should parse");
        assert_eq!(
            parsed_timeout(&["rcode", "exec", "--agent-timeout-secs", "600", "task"]).unwrap(),
            Some(600)
        );
        Cli::try_parse_from(["rcode", "exec", "--agent-timeout-secs", "600", "task"])
            .expect("global timeout flag after exec should parse");
        assert_eq!(
            parsed_timeout(&["rcode", "--agent-timeout-secs", "17", "hello"]).unwrap(),
            Some(17)
        );
        Cli::try_parse_from(["rcode", "--agent-timeout-secs", "17", "hello"])
            .expect("interactive prompt should retain the timeout flag");
    }

    #[test]
    fn agent_timeout_accepts_range_endpoints_and_rejects_out_of_range_values() {
        for value in ["1", "3600"] {
            assert_eq!(
                parsed_timeout(&["rcode", "--agent-timeout-secs", value]).unwrap(),
                Some(value.parse().unwrap())
            );
            Cli::try_parse_from(["rcode", "--agent-timeout-secs", value])
                .unwrap_or_else(|error| panic!("timeout {value} should parse: {error}"));
        }

        for value in ["0", "-1", "3601"] {
            assert!(
                Cli::try_parse_from(["rcode", "--agent-timeout-secs", value]).is_err(),
                "timeout {value} should be rejected"
            );
        }
    }

    #[test]
    fn eval_run_parses_snapshots() {
        let cli = Cli::try_parse_from([
            "rcode",
            "eval",
            "run",
            "--suite",
            "suite",
            "--report",
            "report",
            "--agent-binary",
            "agent",
            "--image",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--docker-socket",
            "socket",
            "--series",
            "series",
            "--snapshots",
            "output",
        ])
        .unwrap();
        let Some(Command::Eval {
            command: EvalCommand::Run(args),
        }) = cli.command
        else {
            panic!("expected eval run")
        };
        assert_eq!(args.snapshots, Some(PathBuf::from("output")));
    }

    #[test]
    fn review_model_provider_flag_does_not_collide_with_global_main_provider() {
        let cli = Cli::try_parse_from([
            "rcode",
            "review-model",
            "set",
            "--provider",
            "openrouter",
            "--model",
            "review/model",
        ])
        .unwrap();
        assert_eq!(cli.provider, Some(super::ProviderKind::OpenRouter));
        assert!(matches!(
            cli.command,
            Some(super::Command::ReviewModel { command: super::ReviewModelCommand::Set { model } })
                if model == "review/model"
        ));
    }
}
