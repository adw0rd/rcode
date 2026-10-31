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
    }
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
