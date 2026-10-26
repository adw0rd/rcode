use crate::{
    app::{Events, configured_tools, prepare_context, turn, user_shell},
    cli::{ApprovalMode, Cli},
    config::{ConfigStore, Effort, ProviderKind, ProviderSettings, Settings},
    presentation,
    protocol::{Message, ModelInfo, ProviderMeta},
    provider::ProviderClient,
    state::{AUTO_COMPACT_THRESHOLD, CONTEXT_LIMIT, Session},
    terminal::{self, Choice, Footer, Input},
    tools::Tools,
    ui,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

macro_rules! notice {($($arg:tt)*)=>{crate::screen::notice(format!($($arg)*))};}

fn model_target(current: ProviderKind, args: &[&str]) -> (ProviderKind, Option<String>) {
    match args.first().and_then(|s| s.parse::<ProviderKind>().ok()) {
        Some(kind) => (kind, args.get(1).map(|s| (*s).to_owned())),
        None => (current, args.first().map(|s| (*s).to_owned())),
    }
}
fn efforts(p: &ProviderSettings, model: Option<&ModelInfo>) -> Vec<Effort> {
    if model.is_some_and(|m| m.supports_reasoning == Some(false)) {
        return vec![Effort::Auto];
    }
    let mut options = vec![Effort::Auto];
    for effort in Effort::all().into_iter().filter(|e| *e != Effort::Auto) {
        let mut candidate = p.clone();
        candidate.effort = effort;
        if candidate.validate_effort().is_err() {
            continue;
        }
        if let Some(allowed) = model.and_then(|m| m.supported_efforts.as_ref()) {
            if !allowed.contains(&effort) {
                continue;
            }
        } else if !matches!(effort, Effort::Low | Effort::Medium | Effort::High) {
            continue;
        }
        options.push(effort);
    }
    options
}
fn choose(title: &str, choices: &[Choice], current: usize, rich: bool) -> Result<Option<usize>> {
    if rich {
        return terminal::select(title, choices, current);
    }
    notice!("\n{title}");
    for (i, c) in choices.iter().enumerate() {
        notice!(
            "{}. {} — {}{}",
            i + 1,
            ui::safe(&c.label),
            ui::safe(&c.detail),
            if c.enabled {
                ""
            } else {
                " (недоступно)"
            }
        );
    }
    let answer = ui::line("Номер (0 — отмена)", &(current + 1).to_string())?;
    let index = answer.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
    Ok(index.filter(|i| choices.get(*i).is_some_and(|c| c.enabled)))
}
fn provider_choice(
    store: &ConfigStore,
    current: ProviderKind,
    rich: bool,
) -> Result<Option<ProviderKind>> {
    let kinds = ProviderKind::all();
    let choices = kinds
        .iter()
        .map(|k| Choice {
            label: k.to_string(),
            detail: match store.credential(*k) {
                Ok(Some(_)) => "ключ подключён".into(),
                _ => "настроить ключ доступа".into(),
            },
            enabled: true,
        })
        .collect::<Vec<_>>();
    let current = kinds.iter().position(|k| *k == current).unwrap_or_default();
    Ok(choose("Провайдер", &choices, current, rich)?.map(|i| kinds[i]))
}
async fn catalog(client: &mut ProviderClient, events: &Events) -> Result<Option<Vec<ModelInfo>>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(screen) = crate::screen::current() {
        screen.bind_cancel(cancel.clone());
    }
    events.busy("Получаю список моделей");
    let result = tokio::select! {value=client.models()=>value.map(Some),_=tokio::signal::ctrl_c()=>Ok(None),_=cancel.cancelled()=>Ok(None)};
    events.pause();
    result
}

fn commit_provider(
    store: &ConfigStore,
    settings: &mut Settings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
    p: ProviderSettings,
) -> Result<()> {
    p.validate()?;
    let key = store
        .credential(p.kind)?
        .context("Нет ключа — сначала /connect")?;
    let next = ProviderClient::new(p.clone(), key.value.clone())?;
    settings.active = p.kind;
    settings.providers.insert(p.kind.to_string(), p.clone());
    store.save(settings)?;
    session.provider = p;
    session.save(store)?;
    *client = next;
    events.remember(key.value);
    notice!(
        "✓ {} / {} · effort {}",
        session.provider.kind,
        ui::safe(&session.provider.model),
        session.provider.effort
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn select_model(
    args: &[&str],
    force_provider: bool,
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
    models: &mut Vec<ModelInfo>,
) -> Result<()> {
    let (kind, model) = if force_provider {
        let selected = match args.first() {
            Some(s) => Some(s.parse::<ProviderKind>()?),
            None => provider_choice(store, session.provider.kind, rich)?,
        };
        let Some(kind) = selected else {
            return Ok(());
        };
        (kind, None)
    } else {
        model_target(session.provider.kind, args)
    };
    let mut next = if kind == session.provider.kind {
        session.provider.clone()
    } else {
        settings.provider(kind)
    };
    if store.credential(kind)?.is_none() {
        next = ui::connect(store, settings, Some(kind), rich, None).await?;
    }
    if let Some(id) = model {
        if id != next.model {
            next.effort = Effort::Auto;
        }
        next.model = id;
        // A direct model ID works even when /models is unavailable.
        next.validate()?;
        commit_provider(store, settings, session, client, events, next)?;
        models.clear();
        return Ok(());
    }
    let key = store
        .credential(kind)?
        .context("Нет ключа выбранного провайдера")?;
    let mut candidate_client = ProviderClient::new(next.clone(), key.value)?;
    let Some(mut fetched) = catalog(&mut candidate_client, events).await? else {
        return Ok(());
    };
    fetched.sort_by(|a, b| a.id.cmp(&b.id));
    if !fetched.iter().any(|m| m.id == next.model) {
        fetched.insert(
            0,
            ModelInfo {
                id: next.model.clone(),
                name: "текущая модель из настроек".into(),
                ..ModelInfo::default()
            },
        );
    }
    let mut choices = fetched
        .iter()
        .map(|m| {
            let mut parts = vec![m.id.clone()];
            if let Some(n) = m.context_length {
                parts.push(format!("контекст {}", presentation::number(n)));
            }
            if m.supports_reasoning == Some(true) {
                parts.push("reasoning".into());
            }
            if m.supports_tools == Some(false) {
                parts.push("нет вызова инструментов".into());
            }
            Choice {
                label: m.name.clone(),
                detail: parts.join(" · "),
                enabled: m.supports_tools != Some(false),
            }
        })
        .collect::<Vec<_>>();
    choices.push(Choice {
        label: "Ввести ID модели вручную".into(),
        detail: "для новых или отсутствующих в списке моделей".into(),
        enabled: true,
    });
    let current = fetched
        .iter()
        .position(|m| m.id == next.model)
        .unwrap_or_default();
    let Some(selected) = choose(&format!("Модель · {kind}"), &choices, current, rich)?
    else {
        return Ok(());
    };
    let id = if selected == fetched.len() {
        ui::line("ID модели", &next.model)?
    } else {
        fetched[selected].id.clone()
    };
    if id != next.model {
        next.effort = Effort::Auto;
    }
    next.model = id;
    commit_provider(store, settings, session, client, events, next)?;
    *models = fetched;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn select_effort(
    args: &[&str],
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
    models: &mut Vec<ModelInfo>,
) -> Result<()> {
    if models.is_empty() {
        let Some(fetched) = catalog(client, events).await? else {
            return Ok(());
        };
        *models = fetched;
    }
    let meta = models.iter().find(|m| {
        m.id == session.provider.model || session.provider.model.ends_with(&format!("/{}", m.id))
    });
    let options = efforts(&session.provider, meta);
    if options.len() == 1 {
        notice!(
            "Модель не сообщает о поддержке effort. Доступен auto — настройки модели по умолчанию."
        );
    } else if meta.is_none_or(|m| m.supports_reasoning.is_none()) {
        notice!(
            "API не сообщил возможности reasoning этой модели. Уровень будет отправлен явно; модель может его отклонить."
        );
    }
    let effort = if let Some(value) = args.first() {
        value.parse::<Effort>()?
    } else {
        let choices = options
            .iter()
            .map(|e| Choice {
                label: e.to_string(),
                detail: match e {
                    Effort::Auto => "настройки модели по умолчанию; параметр не отправляется",
                    Effort::None => "отключить рассуждения, если модель разрешает",
                    Effort::Minimal | Effort::Low => "быстрее, меньше токенов рассуждений",
                    Effort::Medium => "баланс скорости и глубины",
                    _ => "больше рассуждений; выше задержка и расход токенов",
                }
                .into(),
                enabled: true,
            })
            .collect::<Vec<_>>();
        let current = options
            .iter()
            .position(|e| *e == session.provider.effort)
            .unwrap_or_default();
        let Some(index) = choose("Глубина рассуждений · effort", &choices, current, rich)?
        else {
            return Ok(());
        };
        options[index]
    };
    if !options.contains(&effort) {
        bail!(
            "Effort {effort} недоступен для выбранной модели. Допустимы: {}",
            options
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let mut p = session.provider.clone();
    p.effort = effort;
    commit_provider(store, settings, session, client, events, p)
}
fn footer(session: &Session, runtime: &Cli, plan: bool) -> Footer {
    Footer {
        model: session.provider.model.clone(),
        provider: session.provider.kind.to_string(),
        effort: session.provider.effort.to_string(),
        permissions: if runtime.permissions() == ApprovalMode::FullAccess {
            "full-access".into()
        } else if runtime.allow_shell {
            if runtime.permissions() == ApprovalMode::AutoEdit {
                "auto-edit + shell".into()
            } else {
                "ask + shell".into()
            }
        } else if runtime.permissions() == ApprovalMode::AutoEdit {
            "auto-edit".into()
        } else {
            "ask".into()
        },
        plan,
        context_chars: session.context_chars(),
        input_tokens: session.usage.input_tokens,
        output_tokens: session.usage.output_tokens,
        workspace: session
            .root
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
    }
}
fn status(session: &Session, runtime: &Cli, plan: bool, models: &[ModelInfo]) {
    notice!(
        "\nМодель       {} / {}\nEffort       {}\nРежим        {} · shell {}\nПапка        {}\nСессия       {}",
        session.provider.kind,
        ui::safe(&session.provider.model),
        session.provider.effort,
        if plan {
            "план (только чтение)"
        } else if runtime.permissions() == ApprovalMode::FullAccess {
            "full-access (без подтверждений)"
        } else if runtime.permissions() == ApprovalMode::AutoEdit {
            "auto-edit"
        } else {
            "подтверждения"
        },
        if plan {
            "запрещён в плане"
        } else if runtime.shell_allowed() {
            "разрешён явно"
        } else {
            "по подтверждению"
        },
        session.root.display(),
        session.id
    );
    context(session, models);
}
fn context(session: &Session, models: &[ModelInfo]) {
    notice!(
        "Контекст     {} / {} символов — локальный бюджет CLI",
        session.context_chars(),
        CONTEXT_LIMIT
    );
    if let Some(m) = models.iter().find(|m| m.id == session.provider.model)
        && let Some(window) = m.context_length
    {
        notice!(
            "Окно API     {} токенов; последний запрос — {} входных токенов",
            presentation::number(window),
            session.last_usage.input_tokens
        );
    }
    notice!(
        "При {AUTO_COMPACT_THRESHOLD} символах история сокращается автоматически перед запросом к API. /compact сокращает её вручную, /clear создаёт новую сессию."
    );
}
fn cost(session: &Session) {
    notice!(
        "\nТокены API за сессию: ↑{} входных · ↓{} выходных · {} кэшированных",
        session.usage.input_tokens,
        session.usage.output_tokens,
        session.usage.cached_input_tokens
    );
    match session.last_usage.cost_usd {
        Some(value) => notice!("Стоимость последнего вызова API: ${value:.6}"),
        None => {
            notice!("Стоимость: API не сообщил цену последнего вызова; оценку не подставляем.")
        }
    }
}
fn agents_view(records: &[Value], selector: Option<&str>) -> Result<String> {
    if let Some(selector) = selector {
        if selector.is_empty() {
            bail!("Укажите ID субагента или однозначный префикс: /agents ID");
        }
        let selected = records.iter().find(|record| record["id"] == selector);
        let selected = match selected {
            Some(record) => record,
            None => {
                let mut matches = records.iter().filter(|record| {
                    record["id"]
                        .as_str()
                        .is_some_and(|id| id.starts_with(selector))
                });
                let record = matches
                    .next()
                    .context("Субагент не найден. /agents покажет доступные ID.")?;
                if matches.next().is_some() {
                    bail!(
                        "Префикс ID неоднозначен. Укажите больше символов; /agents покажет задачи."
                    );
                }
                record
            }
        };
        let task = bounded_agent_text(selected["task"].as_str().unwrap_or_default(), 4_000);
        let result = bounded_agent_text(selected["result"].as_str().unwrap_or_default(), 8_000);
        return Ok(format!(
            "{}\nID: {}\nЗадача:\n{}\nРезультат:\n{}",
            presentation::agent_heading(selected),
            presentation::inline(selected["id"].as_str().unwrap_or_default(), 80),
            task,
            if result.is_empty() {
                "Результат пока не получен."
            } else {
                &result
            },
        ));
    }
    if records.is_empty() {
        return Ok(
            "В этой сессии субагенты ещё не запускались. Попросите делегировать часть задачи."
                .into(),
        );
    }
    let mut output = format!(
        "Субагенты · {} задач · /agents ID — подробности",
        records.len().min(24)
    );
    for record in records.iter().rev().take(24) {
        output.push_str(&format!("\n  {}", presentation::agent_heading(record)));
        if let Some(result) = record["result"]
            .as_str()
            .and_then(|text| text.lines().find(|line| !line.trim().is_empty()))
        {
            output.push_str(&format!("\n    ↳ {}", presentation::inline(result, 160)));
        }
    }
    Ok(output)
}
fn bounded_agent_text(text: &str, limit: usize) -> String {
    let text = ui::safe(text);
    let mut characters = text.chars();
    let mut result: String = characters.by_ref().take(limit).collect();
    if characters.next().is_some() {
        result.push_str("\n… сокращено");
    }
    result
}
fn help() {
    notice!("\nКоманды rcode");
    for c in terminal::COMMANDS {
        notice!("  {:15} {}", c.name, c.description);
    }
    notice!(
        "  !команда       Выполнить локальную shell-команду без запроса к модели; Ctrl+C/Esc — прервать"
    );
    notice!(
        "\n/model [ID] | /model [провайдер] [ID] · /effort [уровень]\n/resume [ID|latest] · /permissions [ask|auto-edit|full-access]\n/export [\"путь.md\"] — сохранённый диалог в Markdown; без пути — новый файл в проекте\n/attach \"путь.png\" [запрос] — изображение; также можно вставить путь к PNG/JPEG/TIFF\n/agents [ID] — задачи и результаты субагентов; ID можно сократить\nВвод: / меню · Tab дополнение · ↑↓ выбор/история · Alt+Enter новая строка\nМышь: колесо — история; выделение — копирование; Ctrl+C копирует выделение; Esc снимает.\nCtrl+C отменить без выделения · Ctrl+D выход · Esc закрыть меню\nИзменения файлов — через diff/подтверждение; full-access выполняет файлы и shell без запросов."
    );
}

fn permissions_choice(
    args: &[&str],
    rich: bool,
    current: ApprovalMode,
) -> Result<Option<ApprovalMode>> {
    if args.len() > 1 {
        bail!("/permissions [ask|auto-edit|full-access]");
    }
    if let Some(mode) = args.first() {
        return Ok(Some(match *mode {
            "ask" => ApprovalMode::Ask,
            "auto-edit" => ApprovalMode::AutoEdit,
            "full-access" => ApprovalMode::FullAccess,
            _ => bail!("Доступны ask, auto-edit и full-access"),
        }));
    }
    let modes = [
        ApprovalMode::Ask,
        ApprovalMode::AutoEdit,
        ApprovalMode::FullAccess,
    ];
    let choices = [
        Choice {
            label: "ask".into(),
            detail: "подтверждать изменения файлов, внешние каталоги и shell".into(),
            enabled: true,
        },
        Choice {
            label: "auto-edit".into(),
            detail: "файловые правки автоматически; внешние каталоги и shell по подтверждению"
                .into(),
            enabled: true,
        },
        Choice {
            label: "full-access · Полный доступ".into(),
            detail: "без подтверждений: файлы, внешние каталоги и shell с вашими правами".into(),
            enabled: true,
        },
    ];
    let selected = choose(
        "Разрешения · выбор сохраняется для этого проекта",
        &choices,
        modes.iter().position(|m| *m == current).unwrap_or_default(),
        rich,
    )?;
    Ok(selected.map(|i| modes[i]))
}

fn apply_permissions(
    mode: ApprovalMode,
    store: &ConfigStore,
    session: &Session,
    runtime: &mut Cli,
    tools: &mut Tools,
) -> Result<()> {
    let mut next = runtime.clone();
    next.approval_mode = Some(mode);
    next.allow_shell = false;
    // Drop directory grants from the prior mode, retaining checkpoints and
    // directories explicitly supplied by the operator with --add-dir.
    let next_tools = configured_tools(
        &session.root,
        &session.dir(store).join("checkpoints"),
        &next,
    )?;
    store.save_permissions(&session.root, mode)?;
    *runtime = next;
    *tools = next_tools;
    notice!(
        "✓ Разрешения: {} · {} · сохранено для этого проекта",
        mode.as_str(),
        if mode == ApprovalMode::FullAccess {
            "без подтверждений"
        } else {
            "shell по подтверждению"
        }
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub async fn run(
    cli: &Cli,
    store: &ConfigStore,
    settings: &mut Settings,
    session: &mut Session,
    tools: &mut Tools,
    client: &mut ProviderClient,
    events: &mut Events,
) -> Result<i32> {
    let rich = events.display.is_rich();
    let _screen = if rich {
        Some(crate::screen::start(footer(session, cli, cli.plan))?)
    } else {
        None
    };
    let mut runtime = cli.clone();
    let mut plan = cli.plan;
    let mut composer = terminal::Editor::new();
    let mut plain = ui::editor()?;
    let mut input_history =
        match crate::input_history::InputHistory::load(store, &session.root, |text| {
            events.redact(text)
        }) {
            Ok((history, entries)) => {
                for entry in entries {
                    composer.add_history(&entry);
                    let _ = plain.add_history_entry(entry.as_str());
                }
                Some(history)
            }
            Err(error) => {
                notice!(
                    "Не удалось загрузить историю ввода: {}",
                    events.redact(&format!("{error:#}"))
                );
                None
            }
        };
    let mut models = Vec::<ModelInfo>::new();
    let mut first = cli.prompt.clone();
    let mut interrupted: Option<Instant> = None;
    presentation::welcome(
        &session.root,
        &session.provider.kind.to_string(),
        &session.provider.model,
        rich,
    );
    let restored_context = if cli.resume.is_some() {
        // Compact before hydration, then announce below the restored conversation.
        // An oversized protected task remains available for /compact or /new.
        Some(prepare_context(session, store, 0)?)
    } else {
        None
    };
    hydrate(session, events);
    if let Some(context) = restored_context {
        context.report(events);
    }
    loop {
        if let Some(screen) = crate::screen::current() {
            screen.set_footer(footer(session, &runtime, plan));
        }
        let input = if let Some(p) = first.take() {
            Input::Submit(p)
        } else if rich {
            composer.read(&footer(session, &runtime, plan))?
        } else {
            match plain.readline(if plan {
                "rcode [план] › "
            } else if runtime.permissions() == ApprovalMode::FullAccess {
                "rcode [полный доступ] › "
            } else {
                "rcode › "
            }) {
                Ok(s) => Input::Submit(s),
                Err(rustyline::error::ReadlineError::Interrupted) => Input::Interrupt,
                Err(rustyline::error::ReadlineError::Eof) => Input::Eof,
                Err(e) => return Err(e.into()),
            }
        };
        let input = match input {
            Input::Submit(s) => {
                interrupted = None;
                s
            }
            Input::Eof => break,
            Input::Interrupt => {
                if interrupted.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
                    break;
                }
                interrupted = Some(Instant::now());
                notice!("Ещё раз Ctrl+C для выхода, либо /exit.");
                continue;
            }
        };
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        if let Some(screen) = crate::screen::current() {
            screen.follow_tail();
        }
        let redacted = events.redact(input);
        composer.add_history(&redacted);
        let _ = plain.add_history_entry(redacted.as_str());
        if let Some(history) = &input_history
            && let Err(error) = history.record(&redacted, |text| events.redact(text))
        {
            notice!(
                "Не удалось сохранить историю ввода: {}. В этом запуске история останется в памяти.",
                events.redact(&format!("{error:#}"))
            );
            input_history = None;
        }
        if let Some(command) = input.strip_prefix('!') {
            if let Err(error) = user_shell(session, store, tools, events, command).await {
                events.emit(
                    "error",
                    json!({"message":events.redact(&format!("{error:#}"))}),
                );
            }
            events.pause();
            continue;
        }
        let first_word = input.split_whitespace().next().unwrap_or_default();
        // /var/folders/.../screen.png is a user path, not a slash command.
        // /attach is parsed with the user prompt so its images reach the same turn.
        if input.starts_with('/')
            && first_word != "/attach"
            && !first_word[1..].contains(['/', '\\', '.'])
        {
            let mut words = input.split_whitespace();
            let command = words.next().unwrap_or_default();
            let args = words.collect::<Vec<_>>();
            if matches!(command, "/exit" | "/quit") {
                break;
            }
            let result:Result<()>=async{match command{
                "/help"=>{help();Ok(())},
                "/model"|"/models"=>select_model(&args,false,rich,store,settings,session,client,events,&mut models).await,
                "/provider"=>select_model(&args,true,rich,store,settings,session,client,events,&mut models).await,
                "/effort"=>select_effort(&args,rich,store,settings,session,client,events,&mut models).await,
                "/connect"|"/login"=>{let kind=args.first().map(|s|s.parse::<ProviderKind>()).transpose()?;let next=ui::connect(store,settings,kind,rich,None).await?;commit_provider(store,settings,session,client,events,next)?;models.clear();Ok(())},
                "/permissions"=>{
                    if let Some(mode)=permissions_choice(&args,rich,runtime.permissions())? {
                        apply_permissions(mode,store,session,&mut runtime,tools)?;
                    }Ok(())
                },
                "/plan"=>{plan=match args.first().copied(){Some("on")=>true,Some("off")=>false,None=>!plan,_=>bail!("/plan [on|off]")};notice!("✓ Режим плана: {}",if plan{"включён"}else{"выключен"});Ok(())},
                "/status"=>{status(session,&runtime,plan,&models);Ok(())},
                "/agents"=>{
                    if args.len()>1{bail!("/agents [ID или однозначный префикс]");}
                    let records=serde_json::to_value(&session.agents)?;
                    let records=records.as_array().context("Не удалось прочитать список субагентов")?;
                    notice!("{}",events.redact(&agents_view(records,args.first().copied())?));
                    Ok(())
                },
                "/context"=>{context(session,&models);Ok(())},
                "/export"=>{
                    let path=crate::export::write(session,input.strip_prefix(command).unwrap_or_default(),|text|events.redact(text))?;
                    notice!("✓ Диалог сохранён: {}",ui::safe(&events.redact(&path.to_string_lossy())));
                    Ok(())
                },
                "/cost"=>{cost(session);Ok(())},
                "/diff"=>{notice!("{}",ui::safe(&tools.diff()?));Ok(())},
                "/undo"=>{let text=tools.undo()?;notice!("{}",ui::safe(&text));let mut message=Message::user(format!("Пользователь выполнил /undo: {text}. Перечитай файлы перед изменениями."));message.provider_meta=Some(ProviderMeta{kind:"rcode_runtime".into(),data:json!({"undo":true})});session.messages.push(message);session.save(store)},
                "/compact"=>{let saved=session.compact()?;session.save(store)?;notice!("✓ История сокращена на {saved} символов");Ok(())},
                "/clear"|"/new"=>{*session=Session::new(&session.root,session.provider.clone())?;session.save(store)?;*tools=configured_tools(&session.root,&session.dir(store).join("checkpoints"),&runtime)?;notice!("✓ Новая сессия: {}",session.id);Ok(())},
                "/resume"=>{
                    let id=if let Some(id)=args.first(){Some((*id).to_owned())}else{
                        let saved=Session::list(store)?.into_iter().filter(|s|s.root==session.root).collect::<Vec<_>>();
                        if saved.is_empty(){notice!("В этой папке пока нет сохранённых сессий.");None}else{
                            let choices=saved.iter().map(|s|Choice{label:if s.title.is_empty(){"Новая сессия".into()}else{s.title.clone()},detail:format!("{} · {}",s.provider,s.id),enabled:true}).collect::<Vec<_>>();choose("Восстановить сессию",&choices,0,rich)?.map(|i|saved[i].id.clone())
                        }
                    };
                    if let Some(id)=id{
                        let mut restored=Session::load(store,&id,&session.root)?;let key=store.credential(restored.provider.kind)?.context("Нет ключа провайдера сохранённой сессии")?;
                        let next=ProviderClient::new(restored.provider.clone(),key.value.clone())?;
                        let next_tools=configured_tools(&restored.root,&restored.dir(store).join("checkpoints"),&runtime)?;restored.save(store)?;
                        *session=restored;*client=next;*tools=next_tools;events.remember(key.value);models.clear();if let Some(screen)=crate::screen::current(){screen.clear_history();}let context=prepare_context(session,store,0)?;hydrate(session,events);context.report(events);notice!("✓ Сессия восстановлена: {}",session.id);
                    }Ok(())
                },
                _=>bail!("Неизвестная команда. / открывает меню, /help — справку"),
            }}.await;
            events.pause();
            if let Err(e) = result {
                events.emit("error", json!({"message":format!("{e:#}")}));
            }
            continue;
        }
        if rich {
            notice!(
                "\n{} {}",
                presentation::tone("❯", "1;38;5;110", true),
                ui::safe(&redacted)
            );
        }
        if let Err(e) = turn(session, store, tools, client, events, &runtime, input, plan).await {
            events.emit("error", json!({"message":format!("{e:#}")}));
        }
        events.pause();
    }
    events.pause();
    Ok(0)
}

fn hydrate(session: &Session, events: &Events) {
    let Some(screen) = crate::screen::current() else {
        return;
    };
    for message in session
        .messages
        .iter()
        .skip(session.messages.len().saturating_sub(100))
    {
        if message
            .provider_meta
            .as_ref()
            .is_some_and(|meta| meta.kind == "rcode_user_shell")
        {
            for call in &message.tool_calls {
                if let Ok(args) = serde_json::from_str::<Value>(&call.function.arguments) {
                    events.emit(
                        "shell_start",
                        json!({"command":args["command"].as_str().unwrap_or_default()}),
                    );
                }
                if let Some(result) = session.messages.iter().find(|m| {
                    m.role == "tool" && m.tool_call_id.as_deref() == Some(call.id.as_str())
                }) {
                    events.emit("shell_result",json!({"content":result.content.as_deref().unwrap_or_default(),"restored":true}));
                }
            }
            continue;
        }
        if message
            .provider_meta
            .as_ref()
            .is_some_and(|meta| meta.kind == "rcode_compaction")
        {
            screen.line("Часть предыдущей истории сокращена; показаны сохранённые сообщения.");
            continue;
        }
        if message
            .provider_meta
            .as_ref()
            .is_none_or(|meta| meta.kind != "rcode_runtime")
            && matches!(message.role.as_str(), "user" | "assistant")
            && let Some(text) = message.content.as_deref().filter(|t| !t.is_empty())
        {
            if message.role == "assistant" {
                screen.line("\n✦ rcode");
                screen.append_markdown(&events.redact(text));
                screen.finish_markdown();
            } else {
                screen.line(&format!("\n❯ {}", events.redact(text)));
                for image in &message.images {
                    screen.line(&format!("  {}", ui::safe(&events.redact(&image.label()))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_selection_requires_unique_prefix_and_prefers_exact_id() {
        let records = [
            json!({"id":"abc", "name":"Точный", "role":"explorer", "status":"completed", "result":"Проверка A"}),
            json!({"id":"abcdef", "name":"Длинный", "role":"worker", "status":"failed", "result":"Проверка B"}),
            json!({"id":"other-id", "name":"Третий", "role":"reviewer", "status":"cancelled", "result":"Проверка C"}),
        ];
        assert!(agents_view(&records, Some("ab")).is_err());
        assert!(agents_view(&records, Some("missing")).is_err());
        assert!(agents_view(&records, Some("")).is_err());
        let selected = agents_view(&records, Some("abc")).unwrap();
        assert!(selected.contains("Проверка A"));
        assert!(!selected.contains("Проверка B"));
        let selected = agents_view(&records, Some("oth")).unwrap();
        assert!(selected.contains("Проверка C"));
    }

    #[test]
    fn agent_list_and_details_sanitize_outputs_and_preserve_usage() {
        let records = [json!({
            "id":"12345678-rest", "name":"Исполнитель\n\x1b[2J\u{202e}",
            "task":"Проверить\x1b[2J проект", "role":"worker", "status":"interrupted",
            "result":"Строка 1\nСтрока 2\x1b[2J\u{202e}",
            "usage":{"input_tokens":1234,"output_tokens":56}
        })];
        let list = agents_view(&records, None).unwrap();
        assert!(list.contains("↑1.2k ↓56"));
        assert!(list.contains("прерван"));
        assert!(list.contains("Исполнитель\\n"));
        let details = agents_view(&records, Some("1234")).unwrap();
        assert!(details.contains("Строка 1\nСтрока 2"));
        assert!(details.contains("12345678-rest"));
        assert!(!list.contains('\x1b') && !details.contains('\x1b'));
        assert!(!list.contains('\u{202e}') && !details.contains('\u{202e}'));
        assert!(agents_view(&[], None).unwrap().contains("не запускались"));
    }
    #[test]
    fn model_argument_supports_both_current_and_explicit_provider() {
        assert_eq!(
            model_target(ProviderKind::Yandex, &["qwen/coder"]),
            (ProviderKind::Yandex, Some("qwen/coder".into()))
        );
        assert_eq!(
            model_target(ProviderKind::Yandex, &["openrouter", "qwen/coder"]),
            (ProviderKind::OpenRouter, Some("qwen/coder".into()))
        );
    }
    #[test]
    fn unsupported_effort_is_not_offered() {
        let p = ProviderSettings::new(ProviderKind::OpenRouter);
        let m = ModelInfo {
            supports_reasoning: Some(false),
            ..ModelInfo::default()
        };
        assert_eq!(efforts(&p, Some(&m)), vec![Effort::Auto]);
        let m = ModelInfo {
            supports_reasoning: Some(true),
            supported_efforts: Some(vec![Effort::Low, Effort::High]),
            ..ModelInfo::default()
        };
        assert_eq!(
            efforts(&p, Some(&m)),
            vec![Effort::Auto, Effort::Low, Effort::High]
        );
    }
}
