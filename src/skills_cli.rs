//! Headless `rcode skills …` and `rcode commands …`. No network here:
//! installing and updating sources live elsewhere; this module only reports
//! what is on disk and toggles the disabled set in `skills.json`.
use crate::{
    app::Events,
    cli::{Cli, CommandsCommand, SkillsCommand},
    commands::Shadow,
    config::ConfigStore,
    skills::SkillCatalog,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

pub async fn run(
    command: &SkillsCommand,
    cli: &Cli,
    store: &ConfigStore,
    events: &mut Events,
) -> Result<i32> {
    let root = cli
        .directory
        .canonicalize()
        .context("Рабочая папка не найдена")?;
    let (config, warnings) = crate::skills::SkillsConfig::load(store.root());
    if let Some(warning) = warnings.first() {
        bail!("{warning}");
    }
    match command {
        SkillsCommand::List { verbose } => list(&root, store, &config, cli, *verbose, events),
        SkillsCommand::Enable { ids } => toggle(&root, store, ids, true, cli, events).await,
        SkillsCommand::Disable { ids } => toggle(&root, store, ids, false, cli, events).await,
        SkillsCommand::Install {
            source,
            name,
            reference,
            path,
            only,
            dry_run,
            yes,
        } => {
            install(
                &root,
                store,
                cli,
                &InstallOptions {
                    source: source.clone(),
                    name: name.clone(),
                    reference: reference.clone(),
                    path: path.clone(),
                    only: only.clone(),
                    dry_run: *dry_run,
                    yes: *yes,
                },
                events,
            )
            .await
        }
        SkillsCommand::Check { labels, yes } => {
            check(&root, store, labels, *yes, cli, events).await
        }
        SkillsCommand::Update {
            labels,
            all,
            force,
            yes,
        } => {
            update(
                &root,
                store,
                &UpdateOptions {
                    labels: labels.clone(),
                    all: *all,
                    force: *force,
                    yes: *yes,
                },
                cli,
                events,
            )
            .await
        }
        SkillsCommand::Remove { label, yes } => {
            remove(&root, store, label, *yes, cli, events).await
        }
    }
}

struct InstallOptions {
    source: String,
    name: Option<String>,
    reference: Option<String>,
    path: Option<String>,
    only: Vec<String>,
    dry_run: bool,
    yes: bool,
}

pub async fn run_commands(
    command: &CommandsCommand,
    cli: &Cli,
    store: &ConfigStore,
    events: &mut Events,
) -> Result<i32> {
    let root = cli
        .directory
        .canonicalize()
        .context("Рабочая папка не найдена")?;
    match command {
        CommandsCommand::List => {
            let registry = crate::commands::CommandRegistry::discover(store.root(), &root);
            for problem in &registry.problems {
                events.emit(
                    "warning",
                    json!({"version": 1, "path": problem.path.display().to_string(),
                           "code": problem.code, "message": problem.message}),
                );
            }
            for command in &registry.commands {
                let event = json!({
                    "version": 1,
                    "name": command.name,
                    "scope": scope_json(command.scope),
                    "description": command.description,
                    "argument_hint": command.hint,
                    "unsupported": command.unsupported,
                    "ignored_fields": command.ignored_fields,
                    "shadowed_by": command.shadowed_by.map(|shadow| match shadow {
                        Shadow::Builtin => "builtin",
                        Shadow::User => "user",
                    }),
                });
                if cli.json {
                    events.emit("command", event);
                } else {
                    println!("{}", plain(&event));
                }
            }
            if registry.commands.is_empty() && !cli.json {
                println!(
                    "Пользовательских команд нет. Положите Markdown-файл в {} или {}",
                    store.root().join("commands").display(),
                    root.join(".rcode/commands").display()
                );
            }
            Ok(0)
        }
    }
}

fn list(
    root: &std::path::Path,
    store: &ConfigStore,
    config: &crate::skills::SkillsConfig,
    cli: &Cli,
    verbose: bool,
    events: &mut Events,
) -> Result<i32> {
    let catalog = SkillCatalog::discover(store.root(), root, config);
    for problem in &catalog.problems {
        events.emit(
            "warning",
            json!({"version": 1, "path": problem.path.display().to_string(),
                   "code": problem.code, "message": problem.message}),
        );
    }
    for skill in &catalog.skills {
        let status = if skill.shadowed_by.is_some() {
            "shadowed"
        } else if skill.disabled {
            "disabled"
        } else if !skill.in_catalog {
            "hidden"
        } else {
            "active"
        };
        let mut event = json!({
            "version": 1,
            "id": skill.id,
            "name": skill.name,
            "scope": skill.scope.as_str(),
            "source": skill.source,
            "bytes": skill.bytes,
            "status": status,
            "shadowed_by": skill.shadowed_by,
        });
        if verbose {
            event["description"] = json!(skill.description);
            event["notes"] = json!(skill.notes);
        }
        if cli.json {
            events.emit("skill", event);
        } else {
            println!("{}", plain(&event));
        }
    }
    for source in config.sources.iter() {
        let event = json!({
            "version": 1,
            "label": source.label,
            "root": source.skills_root.display().to_string(),
        });
        if cli.json {
            events.emit("skill_source", event);
        } else {
            println!("{}", plain(&event));
        }
    }
    if catalog.skills.is_empty() && !cli.json {
        println!(
            "Скиллов нет. Положите SKILL.md в {} или {}",
            store.root().join("skills").display(),
            root.join(".rcode/skills").display()
        );
    }
    Ok(0)
}

async fn toggle(
    root: &std::path::Path,
    store: &ConfigStore,
    ids: &[String],
    enable: bool,
    cli: &Cli,
    events: &mut Events,
) -> Result<i32> {
    if ids.is_empty() {
        bail!(
            "Укажите идентификаторы скиллов: rcode skills {} ID…",
            if enable { "enable" } else { "disable" }
        );
    }
    let (config, _) = crate::skills::SkillsConfig::load(store.root());
    let catalog = SkillCatalog::discover(store.root(), root, &config);
    let known: Vec<String> = catalog
        .skills
        .iter()
        .map(|skill| skill.id.clone())
        .collect();
    let mut unknown = Vec::new();
    for id in ids {
        if !known
            .iter()
            .any(|known| known == id || known.ends_with(&format!(":{id}")))
        {
            unknown.push(id.clone());
        }
    }
    if !unknown.is_empty() {
        bail!(
            "Неизвестные скиллы: {}. Смотрите rcode skills list",
            unknown.join(", ")
        );
    }
    let mut manifest = crate::skill_sources::Manifest::read(store.root())?;
    let mut disabled = manifest.disabled().clone();
    let mut changed = 0;
    for id in ids {
        let full = known
            .iter()
            .find(|known| *known == id || known.ends_with(&format!(":{id}")))
            .unwrap();
        if enable {
            changed += disabled.remove(full) as usize;
        } else {
            changed += disabled.insert(full.clone()) as usize;
        }
    }
    manifest.set_disabled(disabled);
    manifest.save(store.root())?;
    events.emit(
        "skills_toggled",
        json!({"version": 1, "enabled": enable, "ids": ids, "changed": changed}),
    );
    if !cli.json {
        println!(
            "{} скиллов {}",
            ids.len(),
            if enable {
                "включено"
            } else {
                "исключено из каталога"
            }
        );
    }
    Ok(0)
}

fn scope_json(scope: crate::commands::CommandScope) -> &'static str {
    match scope {
        crate::commands::CommandScope::User => "user",
        crate::commands::CommandScope::Project => "project",
    }
}

fn plain(event: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(object) = event.as_object() {
        for (key, value) in object {
            if key == "version" {
                continue;
            }
            let text = match value {
                Value::Null => "-".to_owned(),
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            parts.push(format!("{key}={}", crate::ui::safe(&text)));
        }
    }
    parts.join("  ")
}

fn model_shell_guard() -> Result<()> {
    if std::env::var("RCODE_MODEL_SHELL").as_deref() == Ok("1") {
        bail!(
            "Установка и обновление наборов недоступны из shell модели; попросите пользователя выполнить это сам"
        );
    }
    Ok(())
}

fn confirm(json_mode: bool, details: &str) -> Result<()> {
    if json_mode || !std::io::stdin().is_terminal() {
        bail!("Подтвердите действие флагом --yes");
    }
    println!("{details}");
    println!("Продолжить? [y/N]");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error))?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("Отменено; ничего не изменено")
    }
}

fn needs_confirmation(kind: crate::skill_sources::SourceKind) -> bool {
    matches!(
        kind,
        crate::skill_sources::SourceKind::GitHttps | crate::skill_sources::SourceKind::GitSsh
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or_default()
}

async fn fetch_tree(
    root: &Path,
    store: &ConfigStore,
    source: &crate::skill_sources::Source,
    label: &str,
    reference: Option<&str>,
    path_override: Option<&str>,
    events: &Events,
) -> Result<FetchedTree> {
    let sources_dir = store.root().join("skill-sources");
    crate::config::ensure_private_directory(&sources_dir)?;
    let staging_root = sources_dir.join(format!(".staging-{}", uuid::Uuid::new_v4()));
    crate::config::ensure_private_directory(&staging_root)?;
    let fake_home = staging_root.join("home");
    crate::config::ensure_private_directory(&fake_home)?;
    let clone_root = fake_home.join("skill-sources").join(label);
    crate::config::ensure_private_directory(&clone_root)?;
    let result = fetch_into(source, &staging_root, &fake_home, label, reference, events).await;
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging_root);
        return Err(error);
    }
    let skills_root = match path_override {
        Some(path) => PathBuf::from(path),
        None => match detect_skills_root(&clone_root) {
            Some(root) => root,
            None => {
                let _ = std::fs::remove_dir_all(&staging_root);
                bail!("В источнике не найдено SKILL.md; укажите --path с каталогом скиллов");
            }
        },
    };
    let tree_root = if skills_root.as_os_str().is_empty() {
        clone_root.clone()
    } else {
        clone_root.join(&skills_root)
    };
    if !tree_root.is_dir() {
        let _ = std::fs::remove_dir_all(&staging_root);
        bail!(
            "Каталог скиллов {} не найден в источнике; укажите --path",
            tree_root.display()
        );
    }
    let (config, _) = crate::skills::SkillsConfig::load(store.root());
    let _ = config;
    let source_config = crate::skills::SkillsConfig {
        sources: [crate::skills::SourceRoot {
            label: label.to_owned(),
            skills_root: skills_root.clone(),
        }]
        .into(),
        ..crate::skills::SkillsConfig::default()
    };
    let catalog = SkillCatalog::discover(&fake_home, root, &source_config);
    if catalog
        .skills
        .iter()
        .filter(|skill| skill.in_catalog && !skill.disabled && skill.shadowed_by.is_none())
        .count()
        == 0
    {
        let problems: Vec<String> = catalog
            .problems
            .iter()
            .map(|problem| problem.warning())
            .collect();
        let _ = std::fs::remove_dir_all(&staging_root);
        bail!(
            "В источнике нет валидных скиллов. {}",
            problems
                .first()
                .map(String::as_str)
                .unwrap_or("Проверьте структуру набора")
        );
    }
    let commit = if source.kind == crate::skill_sources::SourceKind::Dir {
        String::new()
    } else {
        let git = crate::skill_sources::GitCommand::find(&staging_root, source.kind)?;
        let run = crate::skill_sources::GitRun {
            git: &git,
            redact: &|text: &str| events.redact(text),
        };
        run.run(&git.rev_parse_argv(&clone_root))
            .await?
            .trim()
            .to_owned()
    };
    let tree_sha = crate::skill_sources::tree_sha256(&clone_root)?;
    let warning = crate::skill_sources::compatibility_warning(&clone_root);
    Ok(FetchedTree {
        staging_root,
        clone_root,
        skills_root,
        catalog,
        commit,
        tree_sha,
        warning,
    })
}

struct FetchedTree {
    staging_root: PathBuf,
    clone_root: PathBuf,
    skills_root: PathBuf,
    catalog: SkillCatalog,
    commit: String,
    tree_sha: String,
    warning: Option<&'static str>,
}

fn detect_skills_root(clone_root: &Path) -> Option<PathBuf> {
    if has_skill_dirs(clone_root, Path::new("skills")) {
        return Some(PathBuf::from("skills"));
    }
    if clone_root.join("SKILL.md").is_file() || any_subdir_has_skill(clone_root, Path::new("")) {
        Some(PathBuf::new())
    } else {
        None
    }
}

fn has_skill_dirs(root: &Path, relative: &Path) -> bool {
    let dir = root.join(relative);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().join("SKILL.md").is_file())
}

fn any_subdir_has_skill(root: &Path, relative: &Path) -> bool {
    let dir = root.join(relative);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().join("SKILL.md").is_file())
}

async fn fetch_into(
    source: &crate::skill_sources::Source,
    staging_root: &Path,
    fake_home: &Path,
    label: &str,
    reference: Option<&str>,
    events: &Events,
) -> Result<()> {
    match source.kind {
        crate::skill_sources::SourceKind::Dir => {
            let source_path = Path::new(&source.url);
            crate::skill_sources::copy_dir(
                source_path,
                &fake_home.join("skill-sources").join(label),
            )
        }
        kind => {
            let git = crate::skill_sources::GitCommand::find(staging_root, kind)?;
            let run = crate::skill_sources::GitRun {
                git: &git,
                redact: &|text: &str| events.redact(text),
            };
            let clone_root = fake_home.join("skill-sources").join(label);
            if let Some(commit) = reference.filter(|commit| is_commit_sha(commit)) {
                for step in git.pinned_fetch_argv(&source.url, &clone_root, commit) {
                    run.run(&step).await?;
                }
                return Ok(());
            }
            run.run(&git.clone_argv(&source.url, &clone_root, reference))
                .await?;
            Ok(())
        }
    }
}

fn is_commit_sha(value: &str) -> bool {
    value.len() >= 7 && value.len() <= 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn skills_summary(catalog: &SkillCatalog) -> Vec<String> {
    catalog
        .skills
        .iter()
        .filter(|skill| skill.in_catalog && !skill.disabled && skill.shadowed_by.is_none())
        .map(|skill| skill.id.clone())
        .collect()
}

async fn install(
    root: &Path,
    store: &ConfigStore,
    cli: &Cli,
    options: &InstallOptions,
    events: &mut Events,
) -> Result<i32> {
    model_shell_guard()?;
    let source = crate::skill_sources::parse_source(&options.source, store.root(), root)?;
    let label = options
        .name
        .clone()
        .unwrap_or_else(|| crate::skill_sources::default_label(&source));
    if !crate::skill_sources::valid_label(&label) {
        bail!(
            "Недопустимая метка {label:?}; используйте --name со строчными латинскими буквами, цифрами, _ и -"
        );
    }
    let mut manifest = crate::skill_sources::Manifest::read(store.root())?;
    if manifest.sources().contains_key(&label) {
        bail!("Набор «{label}» уже установлен; используйте rcode skills update {label}");
    }
    if needs_confirmation(source.kind) && !options.dry_run {
        confirm(
            options.yes,
            &format!(
                "Установка набора скиллов\nИсточник: {} ({})\nРевизия: {}\nКаталог: {}\nДействие: git clone --depth 1 без субмодулей; скрипты установки и hooks набора не запускаются\nСкиллы появятся в списке для модели как {label}:<имя>. Их текст передаётся выбранному API и не меняет разрешений rcode.",
                source.input,
                source.kind.describe(),
                options
                    .reference
                    .as_deref()
                    .unwrap_or("ветка по умолчанию удалённого репозитория"),
                store.root().join("skill-sources").join(&label).display()
            ),
        )?;
    }
    let _lock = crate::config::lock_state_file(&store.root().join("skills.lock"))?;
    crate::config::ensure_private_directory(&store.root().join("skill-sources"))?;
    clean_stale_dirs(&store.root().join("skill-sources"))?;
    let fetched = fetch_tree(
        root,
        store,
        &source,
        &label,
        options.reference.as_deref(),
        options.path.as_deref(),
        events,
    )
    .await?;
    let ids = skills_summary(&fetched.catalog);
    let (kept, mut disabled): (Vec<String>, Vec<String>) = if options.only.is_empty() {
        (ids.clone(), Vec::new())
    } else {
        let selected: Vec<String> =
            ids.iter()
                .filter(|id| {
                    options.only.iter().any(|want| {
                        id.as_str() == want.as_str() || id.ends_with(&format!(":{want}"))
                    })
                })
                .cloned()
                .collect();
        let missing: Vec<&String> = options
            .only
            .iter()
            .filter(|want| {
                !selected
                    .iter()
                    .any(|id| id == *want || id.ends_with(&format!(":{want}")))
            })
            .collect();
        if !missing.is_empty() {
            let _ = std::fs::remove_dir_all(&fetched.staging_root);
            bail!(
                "В наборе нет скиллов: {}",
                missing
                    .iter()
                    .map(|want| want.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let rest: Vec<String> = ids
            .iter()
            .filter(|id| !selected.contains(id))
            .cloned()
            .collect();
        (selected, rest)
    };
    if options.dry_run {
        let _ = std::fs::remove_dir_all(&fetched.staging_root);
        report_install(events, true, &label, "dry_run", &fetched, &ids, None);
        println!(
            "Набор «{label}» без установки: {} скиллов ({})",
            ids.len(),
            ids.join(", ")
        );
        return Ok(0);
    }
    let destination = store.root().join("skill-sources").join(&label);
    std::fs::rename(&fetched.clone_root, &destination)
        .with_context(|| format!("Не удалось установить набор в {}", destination.display()))?;
    let record = crate::skill_sources::SourceRecord {
        kind: source_kind_name(source.kind).to_owned(),
        url: source.input.clone(),
        reference: options.reference.clone(),
        commit: fetched.commit.clone(),
        skills_root: fetched.skills_root.display().to_string(),
        tree_sha256: fetched.tree_sha.clone(),
        package_version: crate::skill_sources::package_version(&destination),
        installed_at: now_ms(),
        updated_at: now_ms(),
        only: options.only.clone(),
    };
    manifest.sources_mut().insert(label.clone(), record);
    let mut all_disabled = manifest.disabled().clone();
    for id in &disabled {
        all_disabled.insert(id.clone());
    }
    disabled = Vec::new();
    let _ = &disabled;
    manifest.set_disabled(all_disabled);
    if let Err(error) = manifest.write(store.root()) {
        let _ = std::fs::remove_dir_all(&destination);
        let _ = std::fs::remove_dir_all(&fetched.staging_root);
        return Err(error);
    }
    let _ = std::fs::remove_dir_all(&fetched.staging_root);
    report_install(
        events,
        cli.json,
        &label,
        "installed",
        &fetched,
        &kept,
        Some(&fetched.commit),
    );
    report_install_human(&label, &fetched, &kept, cli.json);
    if let Some(warning) = fetched.warning {
        events.emit(
            "warning",
            json!({"version": 1, "label": label, "message": warning}),
        );
        if !cli.json {
            println!("! {warning}");
        }
    }
    Ok(0)
}

fn source_kind_name(kind: crate::skill_sources::SourceKind) -> &'static str {
    match kind {
        crate::skill_sources::SourceKind::GitHttps => "git",
        crate::skill_sources::SourceKind::GitSsh => "git",
        crate::skill_sources::SourceKind::GitLocal => "git",
        crate::skill_sources::SourceKind::Dir => "dir",
    }
}

fn clean_stale_dirs(sources_dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(sources_dir)
        .with_context(|| format!("Не удалось прочитать {}", sources_dir.display()))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".staging-") || name.starts_with(".old-") || name.contains(".backup-") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    Ok(())
}

fn report_install(
    events: &mut Events,
    _json: bool,
    label: &str,
    status: &str,
    fetched: &FetchedTree,
    ids: &[String],
    commit: Option<&str>,
) {
    events.emit(
        "skill_source",
        json!({
            "version": 1,
            "label": label,
            "status": status,
            "skills": ids.len(),
            "ids": ids,
            "commit": commit.unwrap_or(&fetched.commit),
            "tree_sha256": fetched.tree_sha,
        }),
    );
}

fn report_install_human(label: &str, fetched: &FetchedTree, ids: &[String], json_mode: bool) {
    if json_mode {
        return;
    }
    println!(
        "✓ Набор «{label}»: {} скиллов включено{}",
        ids.len(),
        if ids.is_empty() {
            String::new()
        } else {
            format!(" ({})", ids.join(", "))
        }
    );
    if !fetched.commit.is_empty() {
        println!(
            "  Коммит: {}",
            &fetched.commit[..fetched.commit.len().min(12)]
        );
    }
}

async fn check(
    root: &Path,
    store: &ConfigStore,
    labels: &[String],
    yes: bool,
    cli: &Cli,
    events: &mut Events,
) -> Result<i32> {
    model_shell_guard()?;
    let manifest = crate::skill_sources::Manifest::read(store.root())?;
    let selected = select_labels(&manifest, labels)?;
    if !selected.is_empty()
        && selected
            .iter()
            .any(|(_, record)| needs_confirmation(record_kind(record)))
        && !yes
    {
        confirm(
            yes,
            &format!(
                "Проверить обновления {} источников по сети? ({})",
                selected.len(),
                selected
                    .iter()
                    .map(|(label, _)| label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )?;
    }
    let _ = root;
    let mut failures = 0;
    for (label, record) in &selected {
        let installed = store.root().join("skill-sources").join(label);
        let local_changes = crate::skill_sources::tree_sha256(&installed)
            .map(|sha| sha != record.tree_sha256)
            .unwrap_or(true);
        if record_kind(record) == crate::skill_sources::SourceKind::Dir {
            let source_path = Path::new(&record.url);
            let status = match crate::skill_sources::tree_sha256(source_path) {
                Ok(sha) if sha == record.tree_sha256 => "up_to_date",
                Ok(_) => "update_available",
                Err(_) => "unknown",
            };
            let event = json!({"version": 1, "label": label, "status": status, "local_changes": local_changes});
            events.emit("skill_source", event.clone());
            if !cli.json {
                println!("{}", plain(&event));
            }
            continue;
        }
        if record.reference.as_deref().is_some_and(is_commit_sha) {
            let event = json!({"version": 1, "label": label, "status": "pinned", "local_changes": local_changes});
            events.emit("skill_source", event.clone());
            if !cli.json {
                println!("{}", plain(&event));
            }
            continue;
        }
        let git = match crate::skill_sources::GitCommand::find(
            &store.root().join("skill-sources"),
            record_kind(record),
        ) {
            Ok(git) => git,
            Err(error) => return Err(error),
        };
        let run = crate::skill_sources::GitRun {
            git: &git,
            redact: &|text: &str| events.redact(text),
        };
        let latest = match run
            .run(&git.ls_remote_argv(&record.url, record.reference.as_deref()))
            .await
        {
            Ok(output) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "DEBUG ls-remote argv={:?} raw={:?}",
                    git.ls_remote_argv(&record.url, record.reference.as_deref()),
                    output
                );
                output
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().next())
                    .map(str::to_owned)
            }
            Err(error) => {
                let event = json!({"version": 1, "label": label, "status": "unknown",
                                   "message": events.redact(&format!("{error:#}"))});
                events.emit("skill_source", event.clone());
                if !cli.json {
                    println!("{}", plain(&event));
                }
                failures += 1;
                continue;
            }
        };
        let status = match latest {
            Some(_) if record.reference.as_deref().is_some_and(is_commit_sha) => "pinned",
            Some(latest) if latest == record.commit => "up_to_date",
            Some(latest) => {
                let mut event = json!({"version": 1, "label": label, "status": "update_available", "latest_commit": latest});
                event["local_changes"] = json!(local_changes);
                events.emit("skill_source", event.clone());
                if !cli.json {
                    println!("{}", plain(&event));
                }
                continue;
            }
            None => {
                failures += 1;
                let event = json!({"version": 1, "label": label, "status": "unknown"});
                events.emit("skill_source", event.clone());
                if !cli.json {
                    println!("{}", plain(&event));
                }
                continue;
            }
        };
        let event =
            json!({"version": 1, "label": label, "status": status, "local_changes": local_changes});
        events.emit("skill_source", event.clone());
        if !cli.json {
            println!("{}", plain(&event));
        }
    }
    Ok(if failures > 0 { 4 } else { 0 })
}

fn record_kind(record: &crate::skill_sources::SourceRecord) -> crate::skill_sources::SourceKind {
    if record.kind == "dir" {
        crate::skill_sources::SourceKind::Dir
    } else if record.url.starts_with('/') {
        crate::skill_sources::SourceKind::GitLocal
    } else {
        crate::skill_sources::SourceKind::GitHttps
    }
}

fn select_labels(
    manifest: &crate::skill_sources::Manifest,
    labels: &[String],
) -> Result<Vec<(String, crate::skill_sources::SourceRecord)>> {
    let sources = manifest.sources();
    if labels.is_empty() {
        return Ok(sources
            .iter()
            .map(|(label, record)| (label.clone(), record.clone()))
            .collect());
    }
    let mut selected = Vec::new();
    for label in labels {
        match sources.get(label) {
            Some(record) => selected.push((label.clone(), record.clone())),
            None => bail!("Набор «{label}» не установлен; смотрите rcode skills list"),
        }
    }
    Ok(selected)
}

struct UpdateOptions {
    labels: Vec<String>,
    all: bool,
    force: bool,
    yes: bool,
}

async fn update(
    root: &Path,
    store: &ConfigStore,
    options: &UpdateOptions,
    cli: &Cli,
    events: &mut Events,
) -> Result<i32> {
    model_shell_guard()?;
    let mut manifest = crate::skill_sources::Manifest::read(store.root())?;
    let wanted: Vec<String> = if options.all || options.labels.is_empty() {
        manifest.sources().keys().cloned().collect()
    } else {
        options.labels.clone()
    };
    let selected = select_labels(&manifest, &wanted)?;
    if selected
        .iter()
        .any(|(_, record)| needs_confirmation(record_kind(record)))
        && !options.yes
    {
        confirm(
            options.yes,
            &format!(
                "Обновить {} источников по сети? ({})",
                selected.len(),
                selected
                    .iter()
                    .map(|(label, _)| label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )?;
    }
    let _lock = crate::config::lock_state_file(&store.root().join("skills.lock"))?;
    let sources_dir = store.root().join("skill-sources");
    crate::config::ensure_private_directory(&sources_dir)?;
    clean_stale_dirs(&sources_dir)?;
    let mut failures = 0;
    let mut transport_failures = 0;
    for (label, record) in &selected {
        let installed = sources_dir.join(label);
        let local_sha = crate::skill_sources::tree_sha256(&installed).ok();
        if local_sha.as_deref() != Some(record.tree_sha256.as_str()) {
            if !options.force {
                failures += 1;
                let message =
                    "В источнике есть локальные изменения; сохраните их или повторите с --force";
                events.emit(
                    "skill_source",
                    json!({"version": 1, "label": label, "status": "local_changes"}),
                );
                if !cli.json {
                    println!("! {label}: {message}");
                }
                continue;
            }
            let backup = sources_dir.join(format!("{}.backup-{}", label, chrono_slug()));
            std::fs::rename(&installed, &backup).with_context(|| {
                format!(
                    "Не удалось сохранить резервную копию {}",
                    installed.display()
                )
            })?;
            if !cli.json {
                println!("  Локальные правки сохранены в {}", backup.display());
            }
        }
        let source = crate::skill_sources::Source {
            kind: record_kind(record),
            input: record.url.clone(),
            url: record.url.clone(),
        };
        let fetched = match fetch_tree(
            root,
            store,
            &source,
            label,
            record.reference.as_deref(),
            Some(&record.skills_root),
            events,
        )
        .await
        {
            Ok(fetched) => fetched,
            Err(error) => {
                let transport = error
                    .downcast_ref::<crate::skill_sources::SourceFailure>()
                    .is_some();
                if transport {
                    transport_failures += 1;
                } else {
                    failures += 1;
                }
                let event = json!({"version": 1, "label": label, "status": "unknown",
                                   "message": events.redact(&format!("{error:#}"))});
                events.emit("skill_source", event.clone());
                if !cli.json {
                    println!("{}", plain(&event));
                }
                continue;
            }
        };
        let old_ids: Vec<String> = {
            let (config, _) = crate::skills::SkillsConfig::load(store.root());
            let _ = config;
            let source_config = crate::skills::SkillsConfig {
                sources: [crate::skills::SourceRoot {
                    label: label.clone(),
                    skills_root: PathBuf::from(&record.skills_root),
                }]
                .into(),
                ..crate::skills::SkillsConfig::default()
            };
            let old_catalog = SkillCatalog::discover(store.root(), root, &source_config);
            skills_summary(&old_catalog)
        };
        let new_ids = skills_summary(&fetched.catalog);
        let mut disabled = manifest.disabled().clone();
        let added: Vec<String> = new_ids
            .iter()
            .filter(|id| !old_ids.contains(id))
            .cloned()
            .collect();
        let removed: Vec<String> = old_ids
            .iter()
            .filter(|id| !new_ids.contains(id))
            .cloned()
            .collect();
        for id in &removed {
            let full = format!("{label}:{id}");
            disabled.remove(&full);
        }

        if !record.only.is_empty() {
            for id in &added {
                disabled.insert(id.clone());
            }
        }
        manifest.set_disabled(disabled);
        let updated_record = crate::skill_sources::SourceRecord {
            kind: record.kind.clone(),
            url: record.url.clone(),
            reference: record.reference.clone(),
            commit: fetched.commit.clone(),
            skills_root: record.skills_root.clone(),
            tree_sha256: crate::skill_sources::tree_sha256(&fetched.clone_root)?,
            package_version: crate::skill_sources::package_version(&fetched.clone_root),
            installed_at: record.installed_at,
            updated_at: now_ms(),
            only: record.only.clone(),
        };
        let old_commit = record.commit.clone();
        let destination = sources_dir.join(label);
        let already_backed_up = local_sha
            .as_deref()
            .is_none_or(|sha| sha != record.tree_sha256.as_str() && options.force);
        let old_dir = sources_dir.join(format!(".old-{}", uuid::Uuid::new_v4()));
        if !already_backed_up {
            std::fs::rename(&destination, &old_dir)
                .with_context(|| format!("Не удалось переместить {}", destination.display()))?;
        }
        if let Err(error) = std::fs::rename(&fetched.clone_root, &destination) {
            if !already_backed_up {
                let _ = std::fs::rename(&old_dir, &destination);
            }
            let _ = std::fs::remove_dir_all(&fetched.staging_root);
            return Err(error).context("Не удалось установить обновленный набор");
        }
        manifest.sources_mut().insert(label.clone(), updated_record);
        if let Err(error) = manifest.write(store.root()) {
            let _ = std::fs::rename(&old_dir, &destination);
            let _ = std::fs::remove_dir_all(&fetched.staging_root);
            return Err(error);
        }
        let _ = std::fs::remove_dir_all(&old_dir);
        let _ = std::fs::remove_dir_all(&fetched.staging_root);
        let event = json!({
            "version": 1,
            "label": label,
            "status": "updated",
            "old_commit": old_commit,
            "commit": fetched.commit,
            "added": added,
            "removed": removed,
        });
        events.emit("skill_source", event.clone());
        if !cli.json {
            println!("{}", plain(&event));
        }
    }
    Ok(if transport_failures > 0 {
        4
    } else if failures > 0 {
        1
    } else {
        0
    })
}

fn chrono_slug() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

async fn remove(
    root: &Path,
    store: &ConfigStore,
    label: &str,
    yes: bool,
    cli: &Cli,
    events: &mut Events,
) -> Result<i32> {
    model_shell_guard()?;
    let mut manifest = crate::skill_sources::Manifest::read(store.root())?;
    if !manifest.sources().contains_key(label) {
        bail!("Набор «{label}» не установлен; смотрите rcode skills list");
    }
    if !yes {
        confirm(
            yes,
            &format!(
                "Удалить набор «{label}» и его файлы в {}?",
                store.root().join("skill-sources").join(label).display()
            ),
        )?;
    }
    let _lock = crate::config::lock_state_file(&store.root().join("skills.lock"))?;
    let sources_dir = store.root().join("skill-sources");
    let old_dir = sources_dir.join(format!(".old-{}", uuid::Uuid::new_v4()));
    std::fs::rename(sources_dir.join(label), &old_dir).with_context(|| {
        format!(
            "Не удалось переместить {}",
            sources_dir.join(label).display()
        )
    })?;
    manifest.sources_mut().remove(label);
    let mut disabled = manifest.disabled().clone();
    for id in disabled
        .clone()
        .iter()
        .filter(|id| id.starts_with(&format!("{label}:")))
        .cloned()
        .collect::<Vec<_>>()
    {
        disabled.remove(&id);
    }
    manifest.set_disabled(disabled);
    if let Err(error) = manifest.write(store.root()) {
        let _ = std::fs::rename(&old_dir, sources_dir.join(label));
        return Err(error);
    }
    let _ = std::fs::remove_dir_all(&old_dir);
    events.emit(
        "skill_source",
        json!({"version": 1, "label": label, "status": "removed"}),
    );
    if !cli.json {
        println!("✓ Набор «{label}» удалён");
    }
    let _ = root;
    Ok(0)
}
