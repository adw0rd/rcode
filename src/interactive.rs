use crate::{
    app::{
        Events, catalog_unit, configured_tools, context_budget, discover_skills, prepare_context,
        skill_catalog, turn, user_shell,
    },
    balance::BalanceMonitor,
    cli::{ApprovalMode, Cli},
    config::{ConfigStore, Effort, ProviderKind, ProviderSettings, Settings},
    context::ContextBudget,
    local_app, presentation,
    protocol::{Message, ModelInfo, ProviderMeta},
    provider::ProviderClient,
    skills::{CatalogEntry, CatalogUnit, LookupError, RenderedCatalog, SkillCatalog, SkillProblem},
    state::Session,
    terminal::{self, Choice, Footer, Input},
    tools::Tools,
    ui,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
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
async fn provider_choice(
    store: &ConfigStore,
    settings: &Settings,
    active: &ProviderSettings,
    rich: bool,
) -> Result<Option<ProviderKind>> {
    let kinds = ProviderKind::all();
    let (send, updates) = std::sync::mpsc::channel();
    // The menu owns all requests: leaving it aborts the JoinSet's tasks.
    let mut pending = tokio::task::JoinSet::new();
    let mut choices = Vec::new();
    for (index, kind) in kinds.iter().copied().enumerate() {
        if kind == ProviderKind::Local {
            // Local servers have no balance API and no request is made here.
            choices.push(Choice {
                label: kind.to_string(),
                detail: crate::local_ui::summary(settings, store),
                enabled: true,
            });
            continue;
        }
        let credential = store.credential(kind).ok().flatten();
        let detail = match credential {
            None => "настроить ключ доступа".into(),
            Some(_) if kind == ProviderKind::Yandex => "ключ подключён (баланс в кабинете)".into(),
            Some(_) if kind == ProviderKind::Custom => {
                "ключ подключён (баланс API недоступен)".into()
            }
            Some(key) => {
                let provider = if kind == active.kind {
                    active.clone()
                } else {
                    settings.provider(kind)
                };
                let send = send.clone();
                pending.spawn(async move {
                    // Never forward a key through a copied or inconsistent provider entry.
                    let label = if provider.kind != kind {
                        "Баланс: недоступен".into()
                    } else {
                        match ProviderClient::new(provider.clone(), key.value) {
                            Ok(mut client) => match crate::balance::fetch(&mut client).await {
                                Ok(report) => report.footer(&provider.model),
                                Err(_) => "Баланс: недоступен".into(),
                            },
                            Err(_) => "Баланс: недоступен".into(),
                        }
                    };
                    let _ = send.send((index, format!("ключ подключён ({label})")));
                });
                "ключ подключён (баланс: …)".into()
            }
        };
        choices.push(Choice {
            label: kind.to_string(),
            detail,
            enabled: true,
        });
    }
    drop(send);
    let current = kinds
        .iter()
        .position(|k| *k == active.kind)
        .unwrap_or_default();
    let selected = if rich {
        terminal::select_with_updates("Провайдер", &choices, current, Some(&updates))?
    } else {
        tokio::select! {
            _ = async { while pending.join_next().await.is_some() {} } => {},
            _ = tokio::signal::ctrl_c() => return Ok(None),
        }
        for (index, detail) in updates.try_iter() {
            choices[index].detail = detail;
        }
        choose("Провайдер", &choices, current, false)?
    };
    Ok(selected.map(|i| kinds[i]))
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
    if p.kind == ProviderKind::Local {
        // The in-memory profiles may predate another process's changes.
        settings.local = local_app::check_current(store, &p)?.local;
    }
    let next = local_app::client(store, &p, events, "Нет ключа — сначала /connect")?;
    settings.remember_provider(&p);
    store.save(settings)?;
    session.provider = p;
    session.save(store)?;
    *client = next;
    if session.provider.kind == ProviderKind::Local {
        notice!(
            "✓ local · профиль {} / {}",
            ui::safe(local_app::profile_name(&session.provider)),
            ui::safe(&session.provider.model)
        );
    } else {
        notice!(
            "✓ {} / {} · effort {}",
            session.provider.kind,
            ui::safe(&session.provider.model),
            session.provider.effort
        );
    }
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
            None => provider_choice(store, settings, &session.provider, rich).await?,
        };
        let Some(kind) = selected else {
            return Ok(());
        };
        (kind, None)
    } else {
        model_target(session.provider.kind, args)
    };
    let mut next = if kind == ProviderKind::Local
        && (force_provider || session.provider.kind != ProviderKind::Local)
    {
        // /provider local: saved profiles, discovery or a manual address.
        let Some(profile) = crate::local_ui::choose_profile(store, settings, rich).await? else {
            return Ok(());
        };
        profile
    } else if kind == session.provider.kind {
        session.provider.clone()
    } else {
        settings.provider(kind)
    };
    if kind != ProviderKind::Local && store.credential(kind)?.is_none() {
        next = ui::connect(store, settings, Some(kind), rich, None).await?;
    }
    if kind == ProviderKind::Local {
        // A session snapshot whose profile moved or was removed neither lists
        // models nor asks for a key: that key would be saved under the name.
        local_app::check_current(store, &next)?;
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
    let Some(mut fetched) = (if kind == ProviderKind::Local {
        local_catalog(store, &mut next, events).await?
    } else {
        let mut candidate_client =
            local_app::client(store, &next, events, "Нет ключа выбранного провайдера")?;
        catalog(&mut candidate_client, events).await?
    }) else {
        return Ok(());
    };
    fetched.sort_by(|a, b| {
        (a.id != next.model)
            .cmp(&(b.id != next.model))
            .then_with(|| a.id.cmp(&b.id))
    });
    if !next.model.is_empty() && !fetched.iter().any(|m| m.id == next.model) {
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
            } else if kind == ProviderKind::Local && m.supports_tools.is_none() {
                parts.push("инструменты не подтверждены".into());
            }
            if m.supports_images == Some(true) {
                parts.push("изображения".into());
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
/// Models of a local profile endpoint; a 401/403 asks once for the profile key.
/// Unreachable servers still allow a manual model ID.
async fn local_catalog(
    store: &ConfigStore,
    profile: &mut ProviderSettings,
    events: &Events,
) -> Result<Option<Vec<ModelInfo>>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(screen) = crate::screen::current() {
        screen.bind_cancel(cancel.clone());
    }
    events.busy("Получаю список моделей локального сервера");
    let result = tokio::select! {
        value = crate::local_ui::catalog(store, profile) => Some(value),
        _ = tokio::signal::ctrl_c() => None,
        _ = cancel.cancelled() => None,
    };
    events.pause();
    let fetched = match result {
        None => return Ok(None),
        Some(Ok((models, _))) => models,
        Some(Err(error)) => {
            // A profile moved meanwhile is an error, not a missing catalog.
            local_app::check_current(store, profile)?;
            notice!(
                "Список моделей недоступен: {}. Можно ввести ID модели вручную.",
                ui::safe(&events.redact(&format!("{error:#}")))
            );
            Vec::new()
        }
    };
    Ok(Some(crate::local_ui::local_models(fetched, &profile.model)))
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
fn footer(session: &Session, runtime: &Cli, plan: bool, budget: &ContextBudget) -> Footer {
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
        context_chars: budget.request_used(&session.messages),
        context_limit: budget.limit,
        context_tokens: budget.is_tokens(),
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
fn status(
    session: &Session,
    runtime: &Cli,
    plan: bool,
    models: &[ModelInfo],
    budget: &ContextBudget,
    skills: &str,
) {
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
    if session.provider.kind == ProviderKind::Local {
        notice!(
            "Профиль      local · {} @{}",
            ui::safe(local_app::profile_name(&session.provider)),
            ui::safe(session.provider.base_url.as_deref().unwrap_or_default())
        );
    }
    context(session, models, budget, skills);
}
/// `skills`: the catalog line of `catalog_summary`.
fn context(session: &Session, models: &[ModelInfo], budget: &ContextBudget, skills: &str) {
    if budget.is_tokens() {
        // Local: estimated tokens against the server context; nothing is invented.
        notice!(
            "Контекст     ~{} / {} оценочных токенов (вместе с системным промптом и инструментами)",
            budget.request_used(&session.messages),
            budget.limit
        );
        notice!("{}", budget.limit_sentence());
        if session.last_usage.input_tokens > 0 {
            notice!(
                "Последний запрос — {} входных токенов по данным сервера",
                session.last_usage.input_tokens
            );
        }
        notice!("{skills}");
        notice!(
            "История сокращается автоматически перед запросом, когда приближается к лимиту. /compact сокращает её вручную, /clear создаёт новую сессию."
        );
        return;
    }
    // Cloud: history plus the fixed overhead (skill catalog and load_skill
    // schema) against the request limit, as in the footer.
    notice!(
        "Контекст     {} / {} символов — локальный бюджет CLI",
        budget.request_used(&session.messages),
        budget.limit
    );
    if budget.overhead > 0 {
        notice!(
            "             из них ~{} — каталог скиллов и схема load_skill в каждом запросе",
            budget.overhead
        );
    }
    if let Some(m) = models.iter().find(|m| m.id == session.provider.model)
        && let Some(window) = m.context_length
    {
        notice!(
            "Окно API     {} токенов; последний запрос — {} входных токенов",
            presentation::number(window),
            session.last_usage.input_tokens
        );
    }
    notice!("{skills}");
    notice!(
        "При {} символах история сокращается автоматически перед запросом к API. /compact сокращает её вручную, /clear создаёт новую сессию.",
        budget.threshold()
    );
}
fn unit_label(unit: CatalogUnit) -> &'static str {
    match unit {
        CatalogUnit::Chars => "символов",
        CatalogUnit::EstimatedTokens { .. } => "оценочных токенов",
    }
}
/// The skills line of `/context` and `/status` (DESIGN §9.1).
fn catalog_summary(
    catalog: &SkillCatalog,
    rendered: Option<&RenderedCatalog>,
    unit: CatalogUnit,
) -> String {
    let listed = catalog
        .skills
        .iter()
        .filter(|skill| skill.in_catalog)
        .count();
    let mut line = match rendered {
        Some(rendered) => {
            let mut line = format!(
                "Скиллы       {} в каталоге, ~{} {}",
                rendered.entries + rendered.omitted_ids.len(),
                rendered.cost,
                unit_label(unit)
            );
            if !rendered.omitted_ids.is_empty() {
                line.push_str(&format!(" · без описаний {}", rendered.omitted_ids.len()));
            }
            if rendered.omitted_count > 0 {
                line.push_str(&format!(" · не вошли {}", rendered.omitted_count));
            }
            line
        }
        None if listed > 0 => format!(
            "Скиллы       каталог из {listed} не помещается в бюджет и модели не отправляется"
        ),
        None if catalog.skills.is_empty() => "Скиллы       не найдены".into(),
        None => format!(
            "Скиллы       в каталоге нет; найдено {}",
            catalog.skills.len()
        ),
    };
    line.push_str(" · /skills — подробности");
    line
}
fn size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} Б")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} КиБ", bytes as f64 / 1024.)
    } else {
        format!("{:.1} МиБ", bytes as f64 / (1024. * 1024.))
    }
}
/// Pads `text` to `width` characters; longer text is clipped with `…`.
fn cell(text: &str, width: usize) -> String {
    let mut clipped: String = text.chars().take(width).collect();
    if text.chars().count() > width {
        clipped.pop();
        clipped.push('…');
    }
    format!("{clipped:<width$}")
}
/// `/skills`: id, scope, status, size and catalog cost of every skill of the
/// snapshot, then discovery errors (DESIGN §6.5). Terminal-safe; the caller
/// redacts known secrets.
fn skills_view(
    catalog: &SkillCatalog,
    unit: CatalogUnit,
    rendered: Option<&RenderedCatalog>,
) -> String {
    const SHOWN_PROBLEMS: usize = 10;
    // Shadowed skills are rows of the table with their winner.
    let problems: Vec<&SkillProblem> = catalog
        .problems
        .iter()
        .filter(|problem| problem.code != "shadowed")
        .collect();
    if catalog.skills.is_empty() && problems.is_empty() {
        return "Скиллы не найдены. rcode читает каталоги <имя>/SKILL.md из RCODE_HOME/skills и .rcode/skills проекта.".into();
    }
    let label = unit_label(unit);
    let mut output = match rendered {
        Some(rendered) => format!(
            "Скиллы · {} · в каталоге {} · блок ~{} из {} {label}",
            catalog.skills.len(),
            rendered.entries + rendered.omitted_ids.len(),
            rendered.cost,
            catalog.limits.max_cost(unit)
        ),
        None if catalog.skills.iter().any(|skill| skill.in_catalog) => format!(
            "Скиллы · {} · каталог не помещается в бюджет ({} {label}) и модели не отправляется",
            catalog.skills.len(),
            catalog.limits.max_cost(unit)
        ),
        None => format!(
            "Скиллы · {} · каталог пуст: модель видит скиллы только по /skill",
            catalog.skills.len()
        ),
    };
    if !catalog.skills.is_empty() {
        let entries = catalog.entries(&catalog.limits, unit, rendered);
        let rows: Vec<[String; 5]> = catalog
            .skills
            .iter()
            .zip(entries)
            .map(|(skill, entry)| {
                let status = match (&skill.shadowed_by, entry) {
                    (Some(winner), _) => format!("перекрыт: {winner}"),
                    _ if skill.disabled => "отключён".into(),
                    _ if skill.disable_model_invocation => "только /skill".into(),
                    (_, CatalogEntry::Described(_)) => "в каталоге".into(),
                    (_, CatalogEntry::IdOnly(_)) => "только id".into(),
                    (_, CatalogEntry::Counted | CatalogEntry::Absent) => "не вошёл".into(),
                };
                let cost = match entry {
                    CatalogEntry::Described(cost) | CatalogEntry::IdOnly(cost) => {
                        format!("~{cost}")
                    }
                    CatalogEntry::Counted | CatalogEntry::Absent => "—".into(),
                };
                [
                    ui::safe(&skill.id),
                    skill.scope.as_str().into(),
                    ui::safe(&status),
                    size(skill.bytes),
                    cost,
                ]
            })
            .collect();
        let width = |column: usize, minimum: usize, maximum: usize| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or_default()
                .clamp(minimum, maximum)
        };
        let (id, scope, status) = (width(0, 2, 48), width(1, 7, 7), width(2, 6, 32));
        output.push_str(&format!(
            "\n  {} {} {} {:>9} {:>7}",
            cell("ID", id),
            cell("Область", scope),
            cell("Статус", status),
            "Размер",
            "Каталог"
        ));
        for row in &rows {
            output.push_str(&format!(
                "\n  {} {} {} {:>9} {:>7}",
                cell(&row[0], id),
                cell(&row[1], scope),
                cell(&row[2], status),
                row[3],
                row[4]
            ));
        }
    }
    if !problems.is_empty() {
        output.push_str(&format!(
            "\nОшибки ({}) — эти скиллы не загружаются:",
            problems.len()
        ));
        for problem in problems.iter().take(SHOWN_PROBLEMS) {
            output.push_str(&format!("\n  ! {}", ui::safe(&problem.warning())));
        }
        if problems.len() > SHOWN_PROBLEMS {
            output.push_str(&format!("\n  … ещё {}", problems.len() - SHOWN_PROBLEMS));
        }
    }
    output.push_str(&format!(
        "\n«Каталог» — сколько {label} скилл занимает в блоке каталога. /skill ID [запрос] — явно выбрать скилл, в том числе отключённый или «только /skill»."
    ));
    output
}
/// `/skill ID [запрос]` (DESIGN §6.5): the user request for a skill the
/// snapshot can load. The skill text is not inlined: the model loads it with
/// load_skill. Unknown and ambiguous ids fail here, without a model request.
fn skill_request(catalog: &SkillCatalog, rest: &str) -> Result<String> {
    let rest = rest.trim();
    let (id, request) = rest
        .split_once(char::is_whitespace)
        .map_or((rest, ""), |(id, request)| (id, request.trim()));
    let shown = || ui::safe(&presentation::inline(id, 80));
    let skill = match catalog.find(id) {
        Ok(skill) => skill,
        Err(LookupError::Unknown { suggestions }) if suggestions.is_empty() => {
            bail!(
                "Скилл {} не найден: скиллов нет. /skills покажет, откуда они читаются",
                shown()
            )
        }
        Err(LookupError::Unknown { suggestions }) => bail!(
            "Скилл {} не найден. Похожие: {}. /skills — список",
            shown(),
            suggestions.join(", ")
        ),
        Err(LookupError::Ambiguous { candidates }) => bail!(
            "Имя {} есть у нескольких скиллов: {}. Укажите полный id",
            shown(),
            candidates.join(", ")
        ),
    };
    let mut text = format!(
        "Пользователь явно выбрал скилл {}. Загрузи его через load_skill и действуй по нему",
        skill.id
    );
    if request.is_empty() {
        text.push('.');
    } else {
        text.push_str(": ");
        text.push_str(request);
    }
    Ok(text)
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
fn help(registry: &crate::commands::CommandRegistry) {
    notice!("\nКоманды rcode");
    for c in terminal::COMMANDS {
        notice!("  {:15} {}", c.name, c.description);
    }
    notice!(
        "  !команда       Выполнить локальную shell-команду без запроса к модели; Ctrl+C/Esc — прервать"
    );
    let custom: Vec<_> = registry.loadable().collect();
    if !custom.is_empty() {
        notice!("\nПользовательские команды");
        for c in custom {
            let hint = c
                .hint
                .as_deref()
                .map(|hint| format!(" [{hint}]"))
                .unwrap_or_default();
            notice!(
                "  {:15} {} · {}",
                format!("/{}", c.name),
                format!("{}{hint}", c.description),
                c.scope.as_str()
            );
        }
        let unsupported: Vec<_> = registry
            .loadable()
            .filter(|c| !c.unsupported.is_empty())
            .map(|c| format!("/{}", c.name))
            .collect();
        if !unsupported.is_empty() {
            notice!(
                "  {} — синтаксис !-shell и @файл не исполняется, текст уходит модели как есть",
                unsupported.join(", ")
            );
        }
    }
    if registry
        .commands
        .iter()
        .any(|c| c.shadowed_by == Some(crate::commands::Shadow::Builtin))
    {
        notice!("  Файлы с именами встроенных команд не используются (например, permissions.md).");
    }
    notice!(
        "\n/model [ID] | /model [провайдер] [ID] · /effort [уровень]\n/resume [ID|latest] · /permissions [ask|auto-edit|full-access]\n/export [\"путь.md\"] — сохранённый диалог в Markdown; без пути — новый файл в проекте\n/attach \"путь.png\" [запрос] — изображение; также можно вставить путь к PNG/JPEG/TIFF\n/agents [ID] — задачи и результаты субагентов; ID можно сократить\n/skills — найденные скиллы и стоимость каталога · /skill ID [запрос] — явно выбрать скилл\nВвод: / меню · Tab дополнение · ↑↓ выбор/история · Shift+Enter / Alt+Enter / Ctrl+J новая строка\nМышь: колесо — история; выделение — копирование; Ctrl+C копирует выделение; Esc снимает.\nCtrl+C отменить без выделения · Ctrl+D выход · Esc закрыть меню\nИзменения файлов — через diff/подтверждение; full-access выполняет файлы и shell без запросов."
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
/// Discovery warnings, at most ten lines; shown again only when the set changes.
fn skill_problems(problems: &[SkillProblem], events: &Events) {
    const SHOWN: usize = 10;
    for problem in problems.iter().take(SHOWN) {
        notice!("! {}", ui::safe(&events.redact(&problem.warning())));
    }
    if problems.len() > SHOWN {
        notice!("! Скиллы: ещё предупреждений — {}", problems.len() - SHOWN);
    }
}

/// Command-file warnings, at most ten lines; shown again only when the set changes.
fn command_problems(problems: &[crate::commands::CommandProblem], events: &Events) {
    const SHOWN: usize = 10;
    for problem in problems.iter().take(SHOWN) {
        notice!(
            "! {}: {} ({})",
            ui::safe(&events.redact(&problem.path.display().to_string())),
            problem.message,
            problem.code
        );
    }
    if problems.len() > SHOWN {
        notice!("! Команды: ещё предупреждений — {}", problems.len() - SHOWN);
    }
}
/// `skills`: the snapshot `dispatch` discovered; later inputs rediscover.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    cli: &Cli,
    store: &ConfigStore,
    settings: &mut Settings,
    session: &mut Session,
    tools: &mut Tools,
    client: &mut ProviderClient,
    events: &mut Events,
    skills: SkillCatalog,
) -> Result<i32> {
    let rich = events.display.is_rich();
    let _screen = if rich {
        Some(crate::screen::start(footer(
            session,
            cli,
            cli.plan,
            &context_budget(client, session, cli, cli.plan, &skills),
        ))?)
    } else {
        None
    };
    let mut runtime = cli.clone();
    let mut balance_monitor = start_balance_monitor(client, session);
    let mut plan = cli.plan;
    let mut composer = terminal::Editor::new();
    let mut input_history =
        match crate::input_history::InputHistory::load(store, &session.root, |text| {
            events.redact(text)
        }) {
            Ok((history, entries)) => {
                for entry in entries {
                    composer.add_history(&entry);
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
        Some(prepare_context(
            session,
            store,
            0,
            &context_budget(client, session, cli, plan, &skills),
        )?)
    } else {
        None
    };
    hydrate(session, events);
    if let Some(context) = restored_context {
        context.report(events);
    }
    let mut shown_problems = Vec::new();
    let mut shown_command_problems: Vec<String> = Vec::new();
    let mut unsupported_shown: HashSet<String> = HashSet::new();
    let mut snapshot = Some(skills);
    loop {
        // New and changed skills are picked up without a restart; one turn
        // keeps one snapshot (DESIGN §6.1).
        let skills = snapshot
            .take()
            .unwrap_or_else(|| discover_skills(store, &session.root));
        if skills.problems != shown_problems {
            skill_problems(&skills.problems, events);
            shown_problems = skills.problems.clone();
        }
        let registry = crate::commands::CommandRegistry::discover(store.root(), &session.root);
        let command_fingerprints: Vec<String> = registry
            .problems
            .iter()
            .map(|problem| {
                format!(
                    "{}|{}|{}",
                    problem.path.display(),
                    problem.code,
                    problem.message
                )
            })
            .collect();
        if command_fingerprints != shown_command_problems {
            command_problems(&registry.problems, events);
            shown_command_problems = command_fingerprints;
        }
        composer.set_commands(registry.menu());
        let budget = context_budget(client, session, &runtime, plan, &skills);
        if let Some(screen) = crate::screen::current() {
            screen.set_footer(footer(session, &runtime, plan, &budget));
        }
        let input = if let Some(p) = first.take() {
            Input::Submit(p)
        } else if rich {
            composer.read(&footer(session, &runtime, plan, &budget))?
        } else {
            composer.read_plain(if plan {
                "rcode [план] › "
            } else if runtime.permissions() == ApprovalMode::FullAccess {
                "rcode [полный доступ] › "
            } else {
                "rcode › "
            })?
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
            if let Err(error) = user_shell(session, store, tools, events, command, &budget).await {
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
            let custom = command
                .strip_prefix('/')
                .and_then(|name| registry.find(name))
                .map(|entry| (entry.name.clone(), entry.unsupported.to_vec()));
            let result:Result<()>=async{match command{
                "/help"=>{help(&registry);Ok(())},
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
                "/status"=>{let rendered=skill_catalog(session,&skills);status(session,&runtime,plan,&models,&budget,&catalog_summary(&skills,rendered.as_ref(),catalog_unit(session)));Ok(())},
                "/balance"=>{
                    if !args.is_empty(){bail!("/balance — баланс текущего провайдера; сменить провайдера: /provider");}
                    let cancel=tokio_util::sync::CancellationToken::new();
                    if let Some(screen)=crate::screen::current(){screen.bind_cancel(cancel.clone());}
                    events.busy("Обновляю баланс…");
                    let fetch=async {
                        if let Some(monitor)=&balance_monitor{monitor.refresh().await}
                        else{crate::balance::fetch(client).await}
                    };
                    let report=tokio::select!{result=fetch=>result?,_=cancel.cancelled()=>bail!("Обновление баланса отменено"),_=tokio::signal::ctrl_c()=>bail!("Обновление баланса отменено")};
                    notice!("{}",events.redact(&report.details(&session.provider.model)));Ok(())
                },
                "/agents"=>{
                    if args.len()>1{bail!("/agents [ID или однозначный префикс]");}
                    let records=serde_json::to_value(&session.agents)?;
                    let records=records.as_array().context("Не удалось прочитать список субагентов")?;
                    notice!("{}",events.redact(&agents_view(records,args.first().copied())?));
                    Ok(())
                },
                "/context"=>{let rendered=skill_catalog(session,&skills);context(session,&models,&budget,&catalog_summary(&skills,rendered.as_ref(),catalog_unit(session)));Ok(())},
                "/skills"=>{
                    if !args.is_empty(){bail!("/skills — список скиллов; выбрать скилл: /skill ID [запрос]");}
                    let rendered=skill_catalog(session,&skills);
                    notice!("{}",events.redact(&skills_view(&skills,catalog_unit(session),rendered.as_ref())));
                    Ok(())
                },
                "/skill"=>{
                    let rest=input.strip_prefix(command).unwrap_or_default();
                    if rest.trim().is_empty(){
                        let rendered=skill_catalog(session,&skills);
                        notice!("{}",events.redact(&skills_view(&skills,catalog_unit(session),rendered.as_ref())));
                        notice!("Укажите скилл: /skill ID [запрос]");
                        return Ok(());
                    }
                    // Checked locally first: an unknown id never reaches the model.
                    let prompt=skill_request(&skills,rest)?;
                    if rich{notice!("\n{} {}",presentation::tone("❯","1;38;5;110",true),ui::safe(&redacted));}
                    turn(session,store,tools,client,events,&runtime,&prompt,plan,&skills).await.map(drop)
                },
                "/export"=>{
                    let path=crate::export::write(session,input.strip_prefix(command).unwrap_or_default(),|text|events.redact(text))?;
                    notice!("✓ Диалог сохранён: {}",ui::safe(&events.redact(&path.to_string_lossy())));
                    Ok(())
                },
                "/cost"=>{cost(session);Ok(())},
                "/diff"=>{notice!("{}",ui::safe(&tools.diff()?));Ok(())},
                "/undo"=>{let text=tools.undo()?;notice!("{}",ui::safe(&text));let mut message=Message::user(format!("Пользователь выполнил /undo: {text}. Перечитай файлы перед изменениями."));message.provider_meta=Some(ProviderMeta{kind:"rcode_runtime".into(),data:json!({"undo":true})});session.messages.push(message);session.save(store)},
                "/compact"=>{let saved=session.compact_within(&budget)?;session.save(store)?;notice!("✓ История сокращена на {saved} {}",budget.unit_label());Ok(())},
                "/clear"|"/new"=>{*session=Session::new(&session.root,session.provider.clone())?;session.save(store)?;*tools=configured_tools(&session.root,&session.dir(store).join("checkpoints"),&runtime)?;notice!("✓ Новая сессия: {}",session.id);Ok(())},
                "/resume"=>{
                    let id=if let Some(id)=args.first(){Some((*id).to_owned())}else{
                        let saved=Session::list(store)?.into_iter().filter(|s|s.root==session.root).collect::<Vec<_>>();
                        if saved.is_empty(){notice!("В этой папке пока нет сохранённых сессий.");None}else{
                            let choices=saved.iter().map(|s|Choice{label:if s.title.is_empty(){"Новая сессия".into()}else{s.title.clone()},detail:format!("{} · {}",s.provider,s.id),enabled:true}).collect::<Vec<_>>();choose("Восстановить сессию",&choices,0,rich)?.map(|i|saved[i].id.clone())
                        }
                    };
                    if let Some(id)=id{
                        // The snapshot's provider and endpoint are kept; the key is resolved for that endpoint.
                        let mut restored=Session::load(store,&id,&session.root)?;
                        let next=local_app::client(store,&restored.provider,events,"Нет ключа провайдера сохранённой сессии")?;
                        let next_tools=configured_tools(&restored.root,&restored.dir(store).join("checkpoints"),&runtime)?;restored.save(store)?;
                        *session=restored;*client=next;*tools=next_tools;models.clear();if let Some(screen)=crate::screen::current(){screen.clear_history();}let context=prepare_context(session,store,0,&context_budget(client,session,&runtime,plan,&skills))?;hydrate(session,events);context.report(events);notice!("✓ Сессия восстановлена: {}",session.id);
                    }Ok(())
                },
                _ if custom.is_some() => {
                    let (name, unsupported) = custom.unwrap();
                    if !unsupported.is_empty() && unsupported_shown.insert(name.clone()) {
                        notice!(
                            "Команда «/{name}» содержит !-shell или @файл — это не исполняется: rcode передаёт текст модели, а команды выполняются только инструментами с подтверждением"
                        );
                    }
                    let arguments = input.strip_prefix(command).unwrap_or_default().trim_start();
                    let prompt = registry
                        .find(&name)
                        .context("Команда исчезла при перечитывании")?
                        .expand(arguments)?;
                    if rich {
                        notice!(
                            "\n{} {}",
                            presentation::tone("❯", "1;38;5;110", true),
                            ui::safe(&redacted)
                        );
                    }
                    turn(session, store, tools, client, events, &runtime, &prompt, plan, &skills)
                        .await
                        .map(drop)
                }
                _=>bail!("Неизвестная команда. / открывает меню, /help — справку"),
            }}.await;
            if matches!(
                command,
                "/model" | "/models" | "/provider" | "/connect" | "/login" | "/effort" | "/resume"
            ) {
                drop(balance_monitor.take());
                balance_monitor = start_balance_monitor(client, session);
            }
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
        if let Err(e) = turn(
            session, store, tools, client, events, &runtime, input, plan, &skills,
        )
        .await
        {
            events.emit("error", json!({"message":format!("{e:#}")}));
        }
        events.pause();
    }
    events.pause();
    Ok(0)
}

/// Background balance for cloud providers; a local server has no balance API.
fn start_balance_monitor(client: &ProviderClient, session: &Session) -> Option<BalanceMonitor> {
    if session.provider.kind == ProviderKind::Local {
        return None;
    }
    crate::screen::current()
        .map(|screen| BalanceMonitor::start(client.clone(), session.provider.model.clone(), screen))
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
    use crate::skills::{CatalogLimits, Skill, SkillScope};
    use std::path::PathBuf;

    fn skill(id: &str, scope: SkillScope) -> Skill {
        let name = id.rsplit(':').next().unwrap().to_owned();
        Skill {
            id: id.into(),
            source: id.split_once(':').map(|(label, _)| label.into()),
            scope,
            dir: PathBuf::from("/skills").join(&name),
            file: PathBuf::from("/skills").join(&name).join("SKILL.md"),
            description: format!("Use {name} for its workflow. {}", "w".repeat(200)),
            name,
            bytes: 2560,
            in_catalog: true,
            disabled: false,
            disable_model_invocation: false,
            shadowed_by: None,
            fields: Default::default(),
            ignored_fields: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn catalog(skills: Vec<Skill>) -> SkillCatalog {
        SkillCatalog {
            skills,
            ..SkillCatalog::default()
        }
    }

    #[test]
    fn skills_view_shows_status_size_and_catalog_cost_safely() {
        let mut disabled = skill("superpowers:debugging", SkillScope::Source);
        disabled.disabled = true;
        disabled.in_catalog = false;
        let mut hidden = skill("careful", SkillScope::Project);
        hidden.disable_model_invocation = true;
        hidden.in_catalog = false;
        // A same-root loser names the winner's directory, which is any text.
        let mut shadowed = skill("review", SkillScope::Project);
        shadowed.shadowed_by = Some("evil\x1b[2J\u{202e}dir".into());
        shadowed.in_catalog = false;
        let mut skills = vec![skill("brainstorming", SkillScope::User)];
        skills.extend((0..30).map(|index| skill(&format!("guide-{index:02}"), SkillScope::User)));
        skills.extend([disabled, hidden, shadowed]);
        let mut catalog = catalog(skills);
        catalog.limits = CatalogLimits {
            cloud_chars: 4000,
            ..CatalogLimits::default()
        };
        catalog.problems = vec![
            SkillProblem {
                path: PathBuf::from("/skills/bad\x1b]52;c;AAAA\x07\u{202e}/SKILL.md"),
                code: "duplicate_key",
                message: "Ошибка frontmatter: повтор ключа name в строке 3".into(),
            },
            SkillProblem {
                path: PathBuf::from("/skills/review/SKILL.md"),
                code: "shadowed",
                message: "Скилл review перекрыт файлом /home/skills/review/SKILL.md".into(),
            },
        ];
        let unit = CatalogUnit::Chars;
        let rendered = catalog.render(&catalog.limits, unit).unwrap();
        assert!(rendered.entries > 0 && !rendered.omitted_ids.is_empty());
        let view = skills_view(&catalog, unit, Some(&rendered));
        assert!(!view.contains('\x1b') && !view.contains('\u{202e}') && !view.contains('\x07'));
        assert!(
            view.contains("\\u{202e}"),
            "bidi controls are shown escaped:\n{view}"
        );
        let named = rendered.entries + rendered.omitted_ids.len();
        assert!(view.starts_with(&format!(
            "Скиллы · 34 · в каталоге {named} · блок ~{} из 4000 символов",
            rendered.cost
        )));
        let row = |id: &str| {
            view.lines()
                .find(|line| line.trim_start().starts_with(&format!("{id} ")))
                .unwrap_or_else(|| panic!("no row {id}:\n{view}"))
                .to_owned()
        };
        let entries = catalog.entries(&catalog.limits, unit, Some(&rendered));
        let CatalogEntry::Described(cost) = entries[0] else {
            panic!("{entries:?}");
        };
        let first = row("brainstorming");
        assert!(
            first.contains("user") && first.contains("в каталоге"),
            "{first}"
        );
        assert!(
            first.contains("2.5 КиБ") && first.ends_with(&format!("~{cost}")),
            "{first}"
        );
        let last = rendered.omitted_ids.last().unwrap();
        assert!(row(last).contains("только id"), "{}", row(last));
        let disabled = row("superpowers:debugging");
        assert!(
            disabled.contains("source") && disabled.contains("отключён") && disabled.ends_with('—')
        );
        assert!(row("careful").contains("только /skill"));
        assert!(row("review").contains("перекрыт: evil"));
        // Discovery errors are listed; shadowing is already a table row.
        assert!(view.contains("Ошибки (1)") && view.contains("(duplicate_key)"));
        assert!(!view.contains("перекрыт файлом"));
        assert!(view.contains("/skill ID [запрос]"));
        // Without a block every catalog skill is reported as not sent.
        let none = skills_view(&catalog, unit, None);
        assert!(none.contains("не помещается в бюджет"));
        assert!(row_in(&none, "brainstorming").contains("не вошёл"));
        // Local units are named as such.
        let local = CatalogUnit::EstimatedTokens {
            history_limit: 25_396,
        };
        let rendered = catalog.render(&catalog.limits, local).unwrap();
        assert!(
            skills_view(&catalog, local, Some(&rendered)).contains("из 2539 оценочных токенов")
        );
        assert!(skills_view(&SkillCatalog::empty(), unit, None).starts_with("Скиллы не найдены"));
    }

    fn row_in(view: &str, id: &str) -> String {
        view.lines()
            .find(|line| line.trim_start().starts_with(&format!("{id} ")))
            .unwrap_or_else(|| panic!("no row {id}:\n{view}"))
            .to_owned()
    }

    #[test]
    fn skill_request_names_the_resolved_id_and_keeps_the_request() {
        let mut disabled = skill("off", SkillScope::User);
        disabled.disabled = true;
        disabled.in_catalog = false;
        let mut shadowed = skill("brainstorming", SkillScope::Project);
        shadowed.shadowed_by = Some("user".into());
        shadowed.in_catalog = false;
        let catalog = catalog(vec![
            skill("brainstorming", SkillScope::User),
            disabled,
            shadowed,
            skill("superpowers:debugging", SkillScope::Source),
            skill("gstack:review", SkillScope::Source),
            skill("team:review", SkillScope::Source),
        ]);
        assert_eq!(
            skill_request(&catalog, " brainstorming  новая\nкоманда /export ").unwrap(),
            "Пользователь явно выбрал скилл brainstorming. Загрузи его через load_skill и действуй по нему: новая\nкоманда /export"
        );
        // A unique bare name resolves to the full id; no request — no colon.
        assert_eq!(
            skill_request(&catalog, "debugging").unwrap(),
            "Пользователь явно выбрал скилл superpowers:debugging. Загрузи его через load_skill и действуй по нему."
        );
        // Explicit choice also works for skills outside the catalog.
        assert!(
            skill_request(&catalog, "off проверь")
                .unwrap()
                .contains("скилл off.")
        );
        let ambiguous = skill_request(&catalog, "review").unwrap_err().to_string();
        assert!(
            ambiguous.contains("gstack:review, team:review"),
            "{ambiguous}"
        );
        let unknown = skill_request(&catalog, "brainstormin\x1b[2J идея")
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("Похожие: brainstorming"), "{unknown}");
        assert!(!unknown.contains('\x1b'), "{unknown}");
        let none = skill_request(&SkillCatalog::empty(), "x")
            .unwrap_err()
            .to_string();
        assert!(none.contains("скиллов нет"), "{none}");
    }

    #[test]
    fn catalog_summary_reports_the_block_in_its_unit() {
        let mut catalog = catalog(
            (0..30)
                .map(|index| skill(&format!("guide-{index:02}"), SkillScope::User))
                .collect(),
        );
        let limits = CatalogLimits {
            cloud_chars: 3000,
            ..CatalogLimits::default()
        };
        let rendered = catalog.render(&limits, CatalogUnit::Chars).unwrap();
        let line = catalog_summary(&catalog, Some(&rendered), CatalogUnit::Chars);
        assert!(
            line.starts_with(&format!(
                "Скиллы       30 в каталоге, ~{} символов · без описаний {}",
                rendered.cost,
                rendered.omitted_ids.len()
            )),
            "{line}"
        );
        let local = CatalogUnit::EstimatedTokens {
            history_limit: 25_396,
        };
        let rendered = catalog.render(&limits, local).unwrap();
        assert!(catalog_summary(&catalog, Some(&rendered), local).contains("оценочных токенов"));
        assert!(catalog_summary(&catalog, None, local).contains("не помещается"));
        for skill in &mut catalog.skills {
            skill.in_catalog = false;
        }
        assert!(catalog_summary(&catalog, None, local).contains("в каталоге нет; найдено 30"));
        assert!(
            catalog_summary(&SkillCatalog::empty(), None, local)
                .starts_with("Скиллы       не найдены")
        );
    }
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
    fn efforts_for_local_is_only_auto() {
        let local = crate::local::profile_settings(
            "box",
            "http://127.0.0.1:8080/v1",
            crate::local::LocalRuntime::LlamaCpp,
            "m",
        );
        let reasoning = ModelInfo {
            supports_reasoning: Some(true),
            supported_efforts: Some(vec![Effort::Low, Effort::High]),
            ..ModelInfo::default()
        };
        assert_eq!(efforts(&local, None), vec![Effort::Auto]);
        assert_eq!(efforts(&local, Some(&reasoning)), vec![Effort::Auto]);
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
