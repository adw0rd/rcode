//! CLI-управление межсессионной памятью (`rcode memory …`) и общие текстовые
//! представления для интерактивных слэш-команд `/memory`.

use crate::{
    app::Events,
    cli::{Cli, MemoryClearScope, MemoryCommand, MemoryListScope, Toggle},
    config::{ConfigStore, ProviderKind},
    context::{estimate_text_tokens, estimate_tools},
    memory::{
        DeleteCas, MAX_NOTE_FILE_BYTES, ManifestUpdateOutcome, MemoryCatalogDisposition, MemoryId,
        MemoryManifest, MemoryPolicy, MemoryScope, MemoryStore, canonical_project_key,
        check_any_text_or_parsed_note_secrets, check_parsed_note_secrets,
        ensure_storage_outside_project, now_utc_rfc3339, open_verified_private_dir,
        parse_memory_note, serialize_memory_note,
    },
    memory_tool,
    skills::CatalogUnit,
    ui,
};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{IsTerminal, Read, Write},
    path::Path,
    time::Duration,
};

pub async fn run(
    command: &MemoryCommand,
    cli: &Cli,
    store: &ConfigStore,
    events: &mut Events,
) -> Result<i32> {
    if crate::memory::is_eval_environment(cli, store.root()) {
        bail!("Межсессионная память отключена в изолированном режиме rcode eval");
    }
    events.refresh_keys(store)?;
    let root = cli
        .directory
        .canonicalize()
        .context("Рабочая папка не найдена")?;
    if !root.is_dir() {
        bail!("Рабочая папка должна быть каталогом");
    }
    ensure_storage_outside_project(store.root(), &root)?;
    let mem_store = MemoryStore::new(store.root());

    match command {
        MemoryCommand::Status => status(&root, cli, store, &mem_store, events),
        MemoryCommand::List { scope, query } => {
            list(&root, cli, &mem_store, *scope, query.as_deref(), events)
        }
        MemoryCommand::Show { id } => show(&root, cli, &mem_store, id, events),
        MemoryCommand::Log { id } => log(&root, cli, &mem_store, id, events),
        MemoryCommand::Diff { id, revision } => diff(&root, cli, &mem_store, id, revision, events),
        MemoryCommand::Edit { id } => {
            model_shell_guard()?;
            edit(&root, cli, &mem_store, id, events)
        }
        MemoryCommand::Rm { purge, id } => {
            model_shell_guard()?;
            remove(&root, cli, &mem_store, id, *purge, events)
        }
        MemoryCommand::Undo {
            id,
            revision,
            force,
        } => {
            model_shell_guard()?;
            undo(
                &root,
                cli,
                &mem_store,
                id,
                revision.as_deref(),
                *force,
                events,
            )
        }
        MemoryCommand::Clear {
            scope,
            all_projects,
            purge,
            yes,
        } => {
            model_shell_guard()?;
            clear(
                &root,
                cli,
                &mem_store,
                *scope,
                *all_projects,
                *purge,
                *yes,
                events,
            )
        }
        MemoryCommand::Enable { project } => {
            model_shell_guard()?;
            toggle_enabled(&root, cli, &mem_store, true, *project, events)
        }
        MemoryCommand::Disable { project } => {
            model_shell_guard()?;
            toggle_enabled(&root, cli, &mem_store, false, *project, events)
        }
        MemoryCommand::AutoWrite { project, global } => {
            model_shell_guard()?;
            configure_auto_write(cli, &mem_store, *project, *global, events)
        }
    }
}

fn model_shell_guard() -> Result<()> {
    if std::env::var("RCODE_MODEL_SHELL").as_deref() == Ok("1") {
        bail!(
            "Изменение настроек и заметок памяти через CLI недоступно из shell модели; используйте штатный инструмент write_memory с подтверждением оператора или попросите пользователя выполнить команду сам"
        );
    }
    Ok(())
}

fn short_hash(s: &str) -> &str {
    s.char_indices().nth(12).map_or(s, |(idx, _)| &s[..idx])
}

pub(crate) fn build_status_report(
    project_root: &Path,
    store: &ConfigStore,
    mem_store: &MemoryStore,
    unit: CatalogUnit,
    secrets: &[String],
    live_session: Option<(&crate::state::Session, &Cli, bool)>,
    cli_plan: bool,
) -> Result<(Value, String)> {
    // Explicit CLI status surfaces manifest corruption/version errors rather than hiding them.
    let manifest = MemoryManifest::read(store.root())?;
    let (canonical_root, project_id) = canonical_project_key(project_root);
    let snap = mem_store.discover(&canonical_root, &project_id, secrets);
    let (stored_project, stored_global) = mem_store.count_stored_notes(&project_id);
    let stored_total = stored_project + stored_global;

    let total_notes = snap.notes.len();
    let project_notes = snap
        .notes
        .iter()
        .filter(|n| n.scope == MemoryScope::Project)
        .count();
    let global_notes = snap
        .notes
        .iter()
        .filter(|n| n.scope == MemoryScope::Global)
        .count();

    let read_def = memory_tool::read_definition();
    let write_def = memory_tool::write_definition();
    let mut active_defs = Vec::new();
    let allow_write = if let Some((session, runtime_cli, plan)) = live_session {
        if crate::app::declares_read_memory_for_main(session, &snap) {
            active_defs.push(read_def);
        }
        if crate::app::declares_write_memory_for_main(session, runtime_cli, plan, &snap) {
            active_defs.push(write_def);
        }
        !plan && runtime_cli.interactive && !runtime_cli.json && snap.policy.is_enabled()
    } else {
        if snap.policy.is_enabled() {
            if total_notes > 0 {
                active_defs.push(read_def);
            }
            if !cli_plan {
                active_defs.push(write_def);
            }
        }
        !cli_plan && snap.policy.is_enabled()
    };
    let rendered = snap.render_index_for(unit, secrets, allow_write);

    let (
        described_count,
        id_only_count,
        omitted_count,
        index_chars,
        index_tokens,
        budget_exhausted,
    ) = match &rendered {
        Some(r) if !r.budget_exhausted => (
            r.described_count,
            r.omitted_ids.len(),
            r.omitted_count,
            r.text.chars().count(),
            estimate_text_tokens(&r.text),
            false,
        ),
        Some(r) => (0, 0, r.omitted_count, 0, 0, true),
        None => (0, 0, 0, 0, 0, false),
    };

    let schema_chars: usize = active_defs
        .iter()
        .filter_map(|d| serde_json::to_string(d).ok())
        .map(|s| s.chars().count())
        .sum();
    let schema_tokens = if active_defs.is_empty() {
        0
    } else {
        estimate_tools(&active_defs)
    };
    let index_limit = crate::memory::MemorySnapshot::index_budget_limit(unit);
    let unit_label = match unit {
        CatalogUnit::Chars => "chars",
        CatalogUnit::EstimatedTokens { .. } => "estimated_tokens",
    };

    let problems_json: Vec<Value> = snap
        .problems
        .iter()
        .map(|p| {
            json!({
                "path": p.path.display().to_string(),
                "code": p.code,
                "message": p.message,
            })
        })
        .collect();

    let report = json!({
        "version": 1,
        "status": snap.policy.status_str(),
        "enabled": manifest.enabled,
        "project_enabled": !manifest.is_project_disabled(&project_id, &canonical_root),
        "project_id": project_id,
        "project_root": canonical_root.display().to_string(),
        "storage_dir": mem_store.memory_dir_path().display().to_string(),
        "auto_write_project": manifest.auto_write_project,
        "auto_write_global": manifest.auto_write_global,
        "counts": {
            "total": total_notes,
            "project": project_notes,
            "global": global_notes,
            "stored_total": stored_total,
            "stored_project": stored_project,
            "stored_global": stored_global,
            "sent_with_description": described_count,
            "sent_id_only": id_only_count,
            "omitted": omitted_count,
        },
        "budget": {
            "unit": unit_label,
            "index_limit": index_limit,
            "index_chars": index_chars,
            "index_estimated_tokens": index_tokens,
            "schema_chars": schema_chars,
            "schema_estimated_tokens": schema_tokens,
            "budget_exhausted": budget_exhausted,
        },
        "problems": problems_json,
    });

    let mut text = format!(
        "Межсессионная память: {}\nХранилище: {}\nТекущий проект: {} ({})\nПодтверждение записи: project={} · global={}\nЗаметки: в контексте {} (project: {}, global: {}) · сохранено на диске: {} (project: {}, global: {}) · с описанием: {} · только ID: {} · опущено по бюджету: {}\nБюджет индекса: {} симв. (~{} ток., лимит {} {}) · схемы инструментов: {} симв. (~{} ток.)",
        match snap.policy {
            MemoryPolicy::Enabled => "включена",
            MemoryPolicy::DisabledByConfig => "выключена глобально",
            MemoryPolicy::DisabledForProject => "выключена для текущего проекта",
            MemoryPolicy::DisabledForEval => "отключена (eval)",
            MemoryPolicy::ManifestError(_) => "ошибка манифеста",
        },
        ui::safe(&mem_store.memory_dir_path().display().to_string()),
        ui::safe(&project_id),
        if manifest.is_project_disabled(&project_id, &canonical_root) {
            "отключён"
        } else {
            "активен"
        },
        if manifest.auto_write_project {
            "auto"
        } else {
            "diff-панель"
        },
        if manifest.auto_write_global {
            "auto"
        } else {
            "diff-панель"
        },
        total_notes,
        project_notes,
        global_notes,
        stored_total,
        stored_project,
        stored_global,
        described_count,
        id_only_count,
        omitted_count,
        index_chars,
        index_tokens,
        index_limit,
        unit_label,
        schema_chars,
        schema_tokens,
    );
    if budget_exhausted {
        text.push_str(
            "\n⚠ Окно контекста слишком мало для 4%-ного лимита <rcode_memory_index>; индекс не отправляется.",
        );
    }
    if !snap.notes.is_empty() {
        let dispositions = snap.dispositions(rendered.as_ref());
        text.push_str("\nСписок активных заметок:");
        for (note, disp) in snap.notes.iter().zip(dispositions) {
            let tag = match disp {
                MemoryCatalogDisposition::Described => "в индексе",
                MemoryCatalogDisposition::IdOnly => "только ID",
                MemoryCatalogDisposition::OmittedCount => "опущена (бюджет)",
                MemoryCatalogDisposition::Absent => "не отправляется",
            };
            text.push_str(&format!(
                "\n  {} · {} · {} — {}",
                note.id(),
                note.updated_at,
                tag,
                ui::safe(&note.description)
            ));
        }
    }
    for problem in &snap.problems {
        text.push_str(&format!("\n⚠ {}", ui::safe(&problem.warning())));
    }
    Ok((report, text))
}

fn default_unit_for_cli(store: &ConfigStore, cli: &Cli) -> CatalogUnit {
    let settings = store.load().unwrap_or_default();
    let provider_kind = cli.provider.unwrap_or(settings.active);
    if provider_kind == ProviderKind::Local || cli.profile.is_some() {
        let provider = crate::local_app::requested_provider(&settings, cli)
            .ok()
            .flatten()
            .unwrap_or_else(|| settings.provider(ProviderKind::Local));
        let budget = crate::context::ContextBudget::for_provider(&provider, None, 1.0, 0);
        if budget.is_tokens() {
            return CatalogUnit::EstimatedTokens {
                history_limit: budget.history_limit(),
            };
        }
    }
    CatalogUnit::Chars
}

fn status(
    project_root: &Path,
    cli: &Cli,
    store: &ConfigStore,
    mem_store: &MemoryStore,
    events: &mut Events,
) -> Result<i32> {
    let secrets = events.secret_snapshot();
    let unit = default_unit_for_cli(store, cli);
    let (mut report, text) = build_status_report(
        project_root,
        store,
        mem_store,
        unit,
        &secrets,
        None,
        cli.plan,
    )?;
    events.redact_value_checked(&mut report)?;
    let safe_text = events.redact_checked(&text)?;
    if cli.json {
        events.emit("memory_status", report);
    } else {
        println!("{safe_text}");
    }
    Ok(0)
}

fn list(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    scope: MemoryListScope,
    query: Option<&str>,
    events: &mut Events,
) -> Result<i32> {
    let _ = MemoryManifest::read(mem_store.rcode_home())?;
    let secrets = events.secret_snapshot();
    let (canonical_root, current_pid) = canonical_project_key(project_root);
    let query_lower = query.map(|q| q.to_lowercase());

    let mut items = Vec::new();
    let matches_query = |slug: &str, aliases: &[String], desc: &str| -> bool {
        let Some(q) = &query_lower else {
            return true;
        };
        slug.to_lowercase().contains(q)
            || desc.to_lowercase().contains(q)
            || aliases.iter().any(|a| a.to_lowercase().contains(q))
    };

    if matches!(scope, MemoryListScope::AllProjects) {
        for pid in mem_store.list_all_project_ids()? {
            if let Some(dir) = open_verified_private_dir(
                mem_store.rcode_home(),
                &["memory", "projects", &pid],
                false,
            )? {
                for entry in dir.entries()? {
                    let entry = entry?;
                    let fname = entry.file_name().to_string_lossy().into_owned();
                    let Some(slug) = fname.strip_suffix(".md") else {
                        continue;
                    };
                    let Some((bytes, _)) = crate::memory::read_verified_optional_file(
                        &dir,
                        &fname,
                        MAX_NOTE_FILE_BYTES,
                    )?
                    else {
                        continue;
                    };
                    if let Ok(note) =
                        parse_memory_note(&bytes, Some(slug), Some(MemoryScope::Project))
                        && check_parsed_note_secrets(
                            std::str::from_utf8(&bytes).unwrap_or_default(),
                            &note,
                            &secrets,
                        )
                        .is_ok()
                        && matches_query(&note.name, &note.aliases, &note.description)
                    {
                        items.push(json!({
                            "id": format!("project/{}", note.name),
                            "project_id": pid,
                            "scope": "project",
                            "name": note.name,
                            "aliases": note.aliases,
                            "updated_at": note.updated_at,
                            "description": note.description,
                            "sha256": note.sha256,
                            "bytes": note.bytes,
                        }));
                    }
                }
            }
        }
        if let Some(dir) =
            open_verified_private_dir(mem_store.rcode_home(), &["memory", "global"], false)?
        {
            for entry in dir.entries()? {
                let entry = entry?;
                let fname = entry.file_name().to_string_lossy().into_owned();
                let Some(slug) = fname.strip_suffix(".md") else {
                    continue;
                };
                let Some((bytes, _)) =
                    crate::memory::read_verified_optional_file(&dir, &fname, MAX_NOTE_FILE_BYTES)?
                else {
                    continue;
                };
                if let Ok(note) = parse_memory_note(&bytes, Some(slug), Some(MemoryScope::Global))
                    && check_parsed_note_secrets(
                        std::str::from_utf8(&bytes).unwrap_or_default(),
                        &note,
                        &secrets,
                    )
                    .is_ok()
                    && matches_query(&note.name, &note.aliases, &note.description)
                {
                    items.push(json!({
                        "id": format!("global/{}", note.name),
                        "project_id": Value::Null,
                        "scope": "global",
                        "name": note.name,
                        "aliases": note.aliases,
                        "updated_at": note.updated_at,
                        "description": note.description,
                        "sha256": note.sha256,
                        "bytes": note.bytes,
                    }));
                }
            }
        }
    } else {
        // Discover notes even if disabled in manifest when operator explicitly runs `rcode memory list`.
        let mut temp_store_notes = Vec::new();
        for target_scope in match scope {
            MemoryListScope::Current => vec![MemoryScope::Project, MemoryScope::Global],
            MemoryListScope::Project => vec![MemoryScope::Project],
            MemoryListScope::Global => vec![MemoryScope::Global],
            MemoryListScope::AllProjects => unreachable!(),
        } {
            let comps: Vec<&str> = match target_scope {
                MemoryScope::Project => vec!["memory", "projects", current_pid.as_str()],
                MemoryScope::Global => vec!["memory", "global"],
            };
            if let Some(dir) = open_verified_private_dir(mem_store.rcode_home(), &comps, false)? {
                for entry in dir.entries()? {
                    let entry = entry?;
                    let fname = entry.file_name().to_string_lossy().into_owned();
                    let Some(slug) = fname.strip_suffix(".md") else {
                        continue;
                    };
                    let Some((bytes, _)) = crate::memory::read_verified_optional_file(
                        &dir,
                        &fname,
                        MAX_NOTE_FILE_BYTES,
                    )?
                    else {
                        continue;
                    };
                    if let Ok(note) = parse_memory_note(&bytes, Some(slug), Some(target_scope))
                        && check_parsed_note_secrets(
                            std::str::from_utf8(&bytes).unwrap_or_default(),
                            &note,
                            &secrets,
                        )
                        .is_ok()
                        && matches_query(&note.name, &note.aliases, &note.description)
                    {
                        temp_store_notes.push(note);
                    }
                }
            }
        }
        let _ = canonical_root;
        temp_store_notes.sort_by(|a, b| {
            a.scope
                .cmp(&b.scope)
                .then_with(|| b.updated_at.cmp(&a.updated_at))
                .then_with(|| a.name.cmp(&b.name))
        });
        for note in temp_store_notes {
            items.push(json!({
                "id": note.id().to_string(),
                "project_id": (note.scope == MemoryScope::Project).then_some(current_pid.clone()),
                "scope": note.scope.as_str(),
                "name": note.name,
                "aliases": note.aliases,
                "updated_at": note.updated_at,
                "description": note.description,
                "sha256": note.sha256,
                "bytes": note.bytes,
            }));
        }
    }

    if cli.json {
        for mut item in items {
            events.redact_value_checked(&mut item)?;
            events.emit("memory_note", item);
        }
    } else if items.is_empty() {
        println!("Заметок памяти не найдено.");
    } else {
        for item in items {
            let line = format!(
                "{}  {}  {} — {}",
                item["id"].as_str().unwrap_or_default(),
                item["updated_at"].as_str().unwrap_or_default(),
                item["project_id"]
                    .as_str()
                    .map(|p| format!("[{p}] "))
                    .unwrap_or_default(),
                ui::safe(item["description"].as_str().unwrap_or_default())
            );
            println!("{}", events.redact_checked(&line)?);
        }
    }
    Ok(0)
}

pub fn format_note_show(
    project_root: &Path,
    mem_store: &MemoryStore,
    id_str: &str,
    secrets: &[String],
) -> Result<(Value, String)> {
    let id = MemoryId::parse(id_str)?;
    let (note, path) = mem_store
        .read_single_note(project_root, &id, secrets)?
        .ok_or_else(|| anyhow!("Заметка {id} не найдена"))?;
    let val = json!({
        "id": id.to_string(),
        "scope": note.scope.as_str(),
        "name": note.name,
        "description": note.description,
        "aliases": note.aliases,
        "updated_at": note.updated_at,
        "sha256": note.sha256,
        "bytes": note.bytes,
        "total_lines": note.body_lines,
        "path": path.display().to_string(),
        "body": note.body,
    });
    let text = format!(
        "Заметка: {}\nОписание: {}\nМетки: {}\nОбновлена: {}\nSHA-256: {}\nФайл: {}\n\n{}",
        id,
        ui::safe(&note.description),
        if note.aliases.is_empty() {
            "—".to_owned()
        } else {
            ui::safe(&note.aliases.join(", "))
        },
        note.updated_at,
        note.sha256,
        ui::safe(&path.display().to_string()),
        ui::safe(note.body.trim_end_matches('\n')),
    );
    Ok((val, text))
}

fn show(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    id_str: &str,
    events: &mut Events,
) -> Result<i32> {
    let secrets = events.secret_snapshot();
    let (mut val, text) = format_note_show(project_root, mem_store, id_str, &secrets)?;
    events.redact_value_checked(&mut val)?;
    let safe_text = events.redact_checked(&text)?;
    if cli.json {
        events.emit("memory_show", val);
    } else {
        println!("{safe_text}");
    }
    Ok(0)
}

pub fn format_note_log(
    project_root: &Path,
    mem_store: &MemoryStore,
    id_str: &str,
    secrets: &[String],
) -> Result<(Vec<Value>, String)> {
    let id = MemoryId::parse(id_str)?;
    let revisions = mem_store.list_revisions(project_root, &id, secrets)?;
    let items: Vec<Value> = revisions
        .iter()
        .map(|r| {
            json!({
                "revision_id": r.revision_id,
                "op": r.op,
                "created_at": r.created_at,
                "prev_sha256": r.prev_sha256,
                "post_sha256": r.post_sha256,
            })
        })
        .collect();
    if revisions.is_empty() {
        return Ok((items, format!("Ревизий для {id} не найдено.")));
    }
    let mut text = format!("История ревизий {id} (последние {}):", revisions.len());
    for r in &revisions {
        text.push_str(&format!(
            "\n  {} · {} · op={} · prev={} -> post={}",
            r.revision_id,
            r.created_at,
            r.op,
            r.prev_sha256.as_deref().map(short_hash).unwrap_or("∅"),
            r.post_sha256.as_deref().map(short_hash).unwrap_or("∅"),
        ));
    }
    Ok((items, text))
}

fn log(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    id_str: &str,
    events: &mut Events,
) -> Result<i32> {
    let secrets = events.secret_snapshot();
    let (items, text) = format_note_log(project_root, mem_store, id_str, &secrets)?;
    let safe_text = events.redact_checked(&text)?;
    if cli.json {
        for mut item in items {
            events.redact_value_checked(&mut item)?;
            events.emit("memory_revision", item);
        }
    } else {
        println!("{safe_text}");
    }
    Ok(0)
}

fn diff(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    id_str: &str,
    revision_id: &str,
    events: &mut Events,
) -> Result<i32> {
    let id = MemoryId::parse(id_str)?;
    let secrets = events.secret_snapshot();
    let revisions = mem_store.list_revisions(project_root, &id, &secrets)?;
    let rev = revisions
        .into_iter()
        .find(|r| r.revision_id == revision_id)
        .ok_or_else(|| anyhow!("Ревизия {revision_id:?} для {id} не найдена"))?;
    let current_text = match mem_store.read_validated_raw_note(project_root, &id, &secrets)? {
        Some((raw_text, _note, _path)) => raw_text,
        None => String::new(),
    };
    let prev_text = rev.prev_content.unwrap_or_default();
    let diff = similar::TextDiff::configure()
        .timeout(Duration::from_millis(200))
        .diff_lines(&prev_text, &current_text)
        .unified_diff()
        .header(
            &format!("revision/{}", rev.revision_id),
            &format!("current/{id}"),
        )
        .to_string();
    let safe_diff = events.redact_checked(&diff)?;
    if cli.json {
        events.emit(
            "memory_diff",
            json!({
                "id": id.to_string(),
                "revision_id": rev.revision_id,
                "diff": safe_diff,
            }),
        );
    } else if safe_diff.trim().is_empty() {
        println!(
            "Нет различий между ревизией {} и текущим файлом.",
            rev.revision_id
        );
    } else {
        print!("{safe_diff}");
    }
    Ok(0)
}

fn redact_warnings(warnings: &[String], events: &Events) -> Result<Vec<String>> {
    warnings
        .iter()
        .map(|w| events.redact_checked(w))
        .collect::<Result<Vec<_>>>()
}

fn print_warnings(warnings: &[String], cli: &Cli, events: &Events) -> Result<()> {
    if cli.json {
        return Ok(());
    }
    for w in warnings {
        eprintln!("⚠ {}", ui::safe(&events.redact_checked(w)?));
    }
    Ok(())
}

fn edit(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    id_str: &str,
    events: &Events,
) -> Result<i32> {
    if cli.json {
        bail!(
            "Интерактивное редактирование rcode memory edit недоступно в режиме --json; используйте обычный терминальный режим без --json"
        );
    }
    let id = MemoryId::parse(id_str)?;
    let _ = MemoryManifest::read(mem_store.rcode_home())?;
    let secrets = events.secret_snapshot();

    let editor_raw = std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| {
            anyhow!("Не задан $VISUAL или $EDITOR; укажите редактор для rcode memory edit")
        })?;
    let mut parts = editor_raw.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| anyhow!("Пустая команда редактора"))?;
    let editor_args: Vec<&str> = parts.collect();

    let existing = mem_store.read_raw_existing(project_root, &id)?;
    let (orig_sha, initial_doc) = match existing {
        Some((bytes, sha, _)) => {
            let text = std::str::from_utf8(&bytes)
                .context("Существующая заметка повреждена (не UTF-8)")?;
            if let Err((_, msg)) = check_any_text_or_parsed_note_secrets(text, &secrets) {
                bail!(
                    "Существующая заметка содержит секрет ({msg}); удалите её через rcode memory rm --purge {id}"
                );
            }
            (Some(sha), text.to_owned())
        }
        None => {
            let starter = format!(
                "---\nname: {}\ndescription: \"Краткое описание заметки\"\nscope: {}\nupdated_at: {}\n---\n- [stated] Запишите правило или предпочтение\n",
                id.slug,
                id.scope.as_str(),
                now_utc_rfc3339()
            );
            (None, starter)
        }
    };

    // Private 0600 temporary copy; memory.lock is NOT held while the editor runs!
    let mut temp = tempfile::Builder::new()
        .prefix("rcode-memory-edit-")
        .suffix(".md")
        .tempfile()
        .context("Не удалось создать временный файл редактирования")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(initial_doc.as_bytes())?;
    temp.as_file().sync_all()?;
    let temp_path = temp.path().to_path_buf();

    let status = std::process::Command::new(program)
        .args(&editor_args)
        .arg(&temp_path)
        .status()
        .with_context(|| format!("Не удалось запустить редактор {program:?}"))?;
    if !status.success() {
        let _ = temp.close();
        bail!(
            "Редактор завершился с кодом {:?}; изменения не сохранены",
            status.code()
        );
    }

    let mut edited_bytes = Vec::new();
    std::fs::File::open(&temp_path)?
        .take((MAX_NOTE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut edited_bytes)?;
    let _ = temp.close();

    if edited_bytes.len() > MAX_NOTE_FILE_BYTES {
        bail!(
            "Отредактированная заметка превышает лимит {} байт",
            MAX_NOTE_FILE_BYTES
        );
    }
    let edited_text = std::str::from_utf8(&edited_bytes)
        .context("Отредактированный файл не является валидным UTF-8")?;
    if orig_sha.is_some() && edited_text == initial_doc {
        println!("Изменений нет; заметка {id} оставлена без правок.");
        return Ok(0);
    }

    if let Err((_, msg)) = check_any_text_or_parsed_note_secrets(edited_text, &secrets) {
        bail!("{msg}");
    }
    let parsed_draft = parse_memory_note(&edited_bytes, Some(&id.slug), Some(id.scope))?;
    if let Err((_, msg)) = check_parsed_note_secrets(edited_text, &parsed_draft, &secrets) {
        bail!("{msg}");
    }
    let normalized_doc = serialize_memory_note(
        &parsed_draft.name,
        &parsed_draft.description,
        parsed_draft.scope,
        &parsed_draft.aliases,
        &now_utc_rfc3339(),
        &parsed_draft.body,
    )?;
    if let Err((_, msg)) = check_parsed_note_secrets(&normalized_doc, &parsed_draft, &secrets) {
        bail!("{msg}");
    }

    let op = if orig_sha.is_some() { "edit" } else { "create" };
    let saved = mem_store.commit_write(
        project_root,
        &id,
        op,
        orig_sha.as_deref(),
        &normalized_doc,
        &secrets,
        None,
    )?;
    print_warnings(&saved.warnings, cli, events)?;
    println!(
        "✓ Заметка {id} сохранена (sha256: {})",
        short_hash(&saved.note.sha256)
    );
    Ok(0)
}

fn remove(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    id_str: &str,
    purge: bool,
    events: &mut Events,
) -> Result<i32> {
    let id = MemoryId::parse(id_str)?;
    let secrets = events.secret_snapshot();
    let deleted =
        mem_store.commit_delete(project_root, &id, DeleteCas::Any, purge, &secrets, None)?;
    let safe_warnings = redact_warnings(&deleted.warnings, events)?;
    if cli.json {
        events.emit(
            "memory_deleted",
            json!({
                "id": id.to_string(),
                "deleted_sha256": deleted.deleted_sha256,
                "purged_revisions": purge,
                "purged_revisions_count": deleted.purged_revisions,
                "warnings": safe_warnings,
            }),
        );
    } else {
        print_warnings(&deleted.warnings, cli, events)?;
        if purge {
            if deleted.deleted_sha256.is_some() {
                println!(
                    "✓ Заметка {id} и её ревизии в .revisions/ ({}) удалены безвозвратно (архивные логи прошлых сессий sessions/<id> не перезаписываются).",
                    deleted.purged_revisions
                );
            } else {
                println!(
                    "✓ Оставшиеся ревизии уже удалённой заметки {id} в .revisions/ ({}) очищены безвозвратно (архивные логи прошлых сессий sessions/<id> не перезаписываются).",
                    deleted.purged_revisions
                );
            }
        } else {
            println!("✓ Заметка {id} удалена (доступен откат: rcode memory undo {id}).");
        }
    }
    Ok(0)
}

fn undo(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    id_str: &str,
    revision: Option<&str>,
    force: bool,
    events: &mut Events,
) -> Result<i32> {
    let id = MemoryId::parse(id_str)?;
    let secrets = events.secret_snapshot();
    let outcome = mem_store.undo(project_root, &id, revision, force, &secrets, None)?;
    let safe_warnings = redact_warnings(&outcome.warnings, events)?;
    if cli.json {
        events.emit(
            "memory_undone",
            json!({
                "id": id.to_string(),
                "revision_id": outcome.revision_id,
                "restored": outcome.restored.is_some(),
                "sha256": outcome.restored.as_ref().map(|n| &n.sha256),
                "warnings": safe_warnings,
            }),
        );
    } else {
        print_warnings(&outcome.warnings, cli, events)?;
        match outcome.restored {
            Some(note) => println!(
                "✓ Откат {id} к ревизии {} выполнен (sha256: {}).",
                outcome.revision_id,
                short_hash(&note.sha256)
            ),
            None => println!(
                "✓ Откат создания {id} по ревизии {} выполнен (файл удалён).",
                outcome.revision_id
            ),
        }
    }
    Ok(0)
}

struct ClearTarget {
    project_id: String,
    label: String,
    id: MemoryId,
    pre_sha256: Option<String>,
    revisions_only: bool,
}

#[allow(clippy::too_many_arguments)]
fn clear(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    scope: MemoryClearScope,
    all_projects: bool,
    purge: bool,
    yes: bool,
    events: &mut Events,
) -> Result<i32> {
    let _ = MemoryManifest::read(mem_store.rcode_home())?;
    let secrets = events.secret_snapshot();
    let (_, current_pid) = canonical_project_key(project_root);

    let mut targets: Vec<ClearTarget> = Vec::new();
    let mut seen: BTreeSet<(String, MemoryScope, String)> = BTreeSet::new();

    if all_projects {
        for pid in mem_store.list_all_project_ids()? {
            if let Some(dir) = open_verified_private_dir(
                mem_store.rcode_home(),
                &["memory", "projects", &pid],
                false,
            )? {
                for entry in dir.entries()? {
                    let entry = entry?;
                    let fname = entry.file_name().to_string_lossy().into_owned();
                    if let Some(slug) = fname.strip_suffix(".md")
                        && let Ok(id) = MemoryId::new(MemoryScope::Project, slug)
                        && let Some(sha) = mem_store.read_note_sha256_by_project_id(&pid, &id)?
                        && seen.insert((pid.clone(), id.scope, id.slug.clone()))
                    {
                        targets.push(ClearTarget {
                            project_id: pid.clone(),
                            label: format!("projects/{pid}/{slug}"),
                            id,
                            pre_sha256: Some(sha),
                            revisions_only: false,
                        });
                    }
                }
            }
        }
    } else if matches!(scope, MemoryClearScope::Project | MemoryClearScope::Current)
        && let Some(dir) = open_verified_private_dir(
            mem_store.rcode_home(),
            &["memory", "projects", &current_pid],
            false,
        )?
    {
        for entry in dir.entries()? {
            let entry = entry?;
            let fname = entry.file_name().to_string_lossy().into_owned();
            if let Some(slug) = fname.strip_suffix(".md")
                && let Ok(id) = MemoryId::new(MemoryScope::Project, slug)
                && let Some(sha) = mem_store.read_note_sha256_by_project_id(&current_pid, &id)?
                && seen.insert((current_pid.clone(), id.scope, id.slug.clone()))
            {
                targets.push(ClearTarget {
                    project_id: current_pid.clone(),
                    label: format!("project/{slug}"),
                    id,
                    pre_sha256: Some(sha),
                    revisions_only: false,
                });
            }
        }
    }

    if matches!(scope, MemoryClearScope::Global | MemoryClearScope::Current)
        && let Some(dir) =
            open_verified_private_dir(mem_store.rcode_home(), &["memory", "global"], false)?
    {
        for entry in dir.entries()? {
            let entry = entry?;
            let fname = entry.file_name().to_string_lossy().into_owned();
            if let Some(slug) = fname.strip_suffix(".md")
                && let Ok(id) = MemoryId::new(MemoryScope::Global, slug)
                && let Some(sha) = mem_store.read_note_sha256_by_project_id(&current_pid, &id)?
                && seen.insert((String::new(), id.scope, id.slug.clone()))
            {
                targets.push(ClearTarget {
                    project_id: current_pid.clone(),
                    label: format!("global/{slug}"),
                    id,
                    pre_sha256: Some(sha),
                    revisions_only: false,
                });
            }
        }
    }

    // With --purge, also include orphan revision histories for already-deleted notes (`P2-4`).
    if purge {
        for (proj_opt, id) in mem_store.list_revision_targets()? {
            let (pid, dedup_pid, label) = match (id.scope, proj_opt) {
                (MemoryScope::Project, Some(pid)) if all_projects => {
                    let lbl = format!("projects/{pid}/{}", id.slug);
                    (pid.clone(), pid, lbl)
                }
                (MemoryScope::Project, Some(pid))
                    if matches!(scope, MemoryClearScope::Project | MemoryClearScope::Current)
                        && pid == current_pid =>
                {
                    let lbl = format!("project/{}", id.slug);
                    (pid.clone(), pid, lbl)
                }
                (MemoryScope::Global, None)
                    if matches!(scope, MemoryClearScope::Global | MemoryClearScope::Current) =>
                {
                    let lbl = format!("global/{}", id.slug);
                    (current_pid.clone(), String::new(), lbl)
                }
                _ => continue,
            };
            if !seen.insert((dedup_pid, id.scope, id.slug.clone())) {
                continue;
            }
            let pre_sha = mem_store.read_note_sha256_by_project_id(&pid, &id)?;
            let revisions_only = pre_sha.is_none();
            targets.push(ClearTarget {
                project_id: pid,
                label,
                id,
                pre_sha256: pre_sha,
                revisions_only,
            });
        }
    }

    targets.sort_by(|a, b| a.label.cmp(&b.label));
    if targets.is_empty() {
        if cli.json {
            events.emit(
                "memory_cleared",
                json!({"deleted": [], "purged_revisions": purge, "warnings": []}),
            );
        } else {
            println!("Нет заметок памяти в выбранной области.");
        }
        return Ok(0);
    }

    if !yes {
        if cli.json || !std::io::stdin().is_terminal() {
            bail!(
                "Для неинтерактивной очистки {} целей памяти укажите флаг --yes",
                targets.len()
            );
        }
        println!("Будут удалены следующие записи памяти ({}):", targets.len());
        for t in &targets {
            if t.revisions_only {
                println!("  - {} (только история в .revisions/)", ui::safe(&t.label));
            } else {
                println!("  - {}", ui::safe(&t.label));
            }
        }
        let answer = ui::line("Подтвердить удаление? y/N", "n")?;
        if !matches!(answer.to_lowercase().as_str(), "y" | "yes" | "да" | "д") {
            println!("Очистка отменена.");
            return Ok(0);
        }
    }

    let mut deleted_labels = Vec::new();
    let mut warnings_all = Vec::new();
    let mut conflicts = Vec::new();
    for t in &targets {
        let cas = match &t.pre_sha256 {
            Some(sha) => DeleteCas::MatchSha(sha),
            None => DeleteCas::RequireAbsent,
        };
        match mem_store.commit_delete_by_project_id(
            &t.project_id,
            &t.id,
            cas,
            purge,
            &secrets,
            None,
        ) {
            Ok(out) => {
                deleted_labels.push(t.label.clone());
                warnings_all.extend(out.warnings);
            }
            Err(err) => {
                let msg = format!("{err:#}");
                if msg.contains("sha256_mismatch") {
                    conflicts.push(format!("{}: {}", t.label, events.redact_checked(&msg)?));
                } else if t.revisions_only && msg.contains("not_found") {
                    // Concurrent purge already removed the orphan revisions; harmless no-op.
                } else {
                    print_warnings(&warnings_all, cli, events)?;
                    return Err(err);
                }
            }
        }
    }

    print_warnings(&warnings_all, cli, events)?;
    if !conflicts.is_empty() {
        bail!(
            "Конфликт при очистке памяти (удалено до конфликта: {}): {}",
            deleted_labels.len(),
            conflicts.join("; ")
        );
    }

    let safe_warnings = redact_warnings(&warnings_all, events)?;
    if cli.json {
        events.emit(
            "memory_cleared",
            json!({
                "deleted": deleted_labels,
                "purged_revisions": purge,
                "warnings": safe_warnings,
            }),
        );
    } else {
        println!("✓ Удалено записей памяти: {}.", deleted_labels.len());
        if purge {
            println!(
                "Примечание: очищены RCODE_HOME/memory и .revisions/; архивные истории прошлых сессий в sessions/<id> не перезаписываются."
            );
        }
    }
    Ok(0)
}

pub fn apply_enable_toggle(
    project_root: &Path,
    mem_store: &MemoryStore,
    enable: bool,
    project_only: bool,
) -> Result<(ManifestUpdateOutcome, String)> {
    let (canonical_root, project_id) = canonical_project_key(project_root);
    let outcome = mem_store.update_manifest(|m| {
        if project_only {
            let root_str = canonical_root.to_string_lossy().into_owned();
            if enable {
                m.disabled_projects.remove(&project_id);
                m.disabled_projects.remove(&root_str);
            } else {
                m.disabled_projects.insert(project_id.clone());
            }
        } else {
            m.enabled = enable;
        }
        Ok(())
    })?;
    Ok((outcome, project_id))
}

fn toggle_enabled(
    project_root: &Path,
    cli: &Cli,
    mem_store: &MemoryStore,
    enable: bool,
    project_only: bool,
    events: &mut Events,
) -> Result<i32> {
    let (outcome, project_id) = apply_enable_toggle(project_root, mem_store, enable, project_only)?;
    let safe_warnings = redact_warnings(&outcome.warnings, events)?;
    let manifest = outcome.manifest;
    if cli.json {
        events.emit(
            "memory_config",
            json!({
                "enabled": manifest.enabled,
                "project_id": project_id,
                "disabled_projects": manifest.disabled_projects,
                "warnings": safe_warnings,
            }),
        );
    } else {
        print_warnings(&outcome.warnings, cli, events)?;
        if project_only {
            println!(
                "✓ Память для проекта {project_id}: {}.",
                if enable {
                    "включена"
                } else {
                    "отключена"
                }
            );
        } else {
            println!(
                "✓ Межсессионная память глобально: {}.",
                if enable {
                    "включена"
                } else {
                    "отключена"
                }
            );
        }
    }
    Ok(0)
}

fn configure_auto_write(
    cli: &Cli,
    mem_store: &MemoryStore,
    project: Option<Toggle>,
    global: Option<Toggle>,
    events: &mut Events,
) -> Result<i32> {
    if project.is_none() && global.is_none() {
        bail!("Укажите хотя бы один флаг: --project on|off и/или --global on|off");
    }
    let outcome = mem_store.update_manifest(|m| {
        if let Some(p) = project {
            m.auto_write_project = p == Toggle::On;
        }
        if let Some(g) = global {
            m.auto_write_global = g == Toggle::On;
        }
        Ok(())
    })?;
    let safe_warnings = redact_warnings(&outcome.warnings, events)?;
    let manifest = outcome.manifest;
    if cli.json {
        events.emit(
            "memory_config",
            json!({
                "auto_write_project": manifest.auto_write_project,
                "auto_write_global": manifest.auto_write_global,
                "warnings": safe_warnings,
            }),
        );
    } else {
        print_warnings(&outcome.warnings, cli, events)?;
        println!(
            "✓ Автозапись памяти: project={} · global={}",
            if manifest.auto_write_project {
                "on"
            } else {
                "off (diff-панель)"
            },
            if manifest.auto_write_global {
                "on"
            } else {
                "off (diff-панель)"
            },
        );
    }
    Ok(0)
}
