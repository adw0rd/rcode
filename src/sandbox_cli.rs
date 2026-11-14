//! CLI-управление OS-песочницей для команд shell модели (`rcode sandbox …`)
//! и общее форматирование статуса для интерактивной команды `/sandbox`.

use crate::{
    app::Events,
    cli::{Cli, SandboxCommand, Toggle},
    config::ConfigStore,
    sandbox::{
        BackendSupport, EffectiveSandboxPolicy, ProjectSandbox, SandboxMode, ensure_mode_supported,
        probe_support,
    },
};
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::path::Path;

pub fn run(
    command: Option<&SandboxCommand>,
    cli: &Cli,
    store: &ConfigStore,
    events: &mut Events,
) -> Result<i32> {
    if crate::memory::is_eval_environment(cli, store.root()) {
        bail!("Управление проектной песочницей отключено в изолированном режиме rcode eval");
    }
    events.refresh_keys(store)?;
    let root = cli
        .directory
        .canonicalize()
        .context("Рабочая папка не найдена")?;
    if !root.is_dir() {
        bail!("Рабочая папка должна быть каталогом");
    }
    if store.root().canonicalize()?.starts_with(&root) {
        bail!("RCODE_HOME должен находиться вне рабочей папки, чтобы секреты не попали в контекст");
    }

    match command {
        None | Some(SandboxCommand::Status) => status(&root, cli, store, events),
        Some(SandboxCommand::Mode { mode }) => {
            model_shell_guard()?;
            set_mode(&root, cli, store, *mode, events)
        }
        Some(SandboxCommand::Network { state }) => {
            model_shell_guard()?;
            set_network(&root, cli, store, *state == Toggle::On, events)
        }
    }
}

fn model_shell_guard() -> Result<()> {
    if std::env::var("RCODE_MODEL_SHELL").as_deref() == Ok("1") {
        bail!(
            "Изменение настроек OS-песочницы через CLI недоступно из shell модели; попросите оператора выполнить rcode sandbox или /sandbox"
        );
    }
    Ok(())
}

fn status(root: &Path, cli: &Cli, store: &ConfigStore, events: &mut Events) -> Result<i32> {
    let support = probe_support();
    let saved = store.project_sandbox(root)?;
    let effective = EffectiveSandboxPolicy::resolve(saved, cli.sandbox, cli.sandbox_network)?;
    if effective.is_active() {
        ensure_mode_supported(effective.mode)?;
    }
    if cli.json {
        events.emit(
            "sandbox",
            json!({
                "action": "status",
                "workspace": root,
                "support": support,
                "saved": saved,
                "effective": effective,
            }),
        );
    } else {
        println!(
            "{}",
            events.redact(&render_status_text(root, &support, saved, effective))
        );
    }
    Ok(0)
}

fn set_mode(
    root: &Path,
    cli: &Cli,
    store: &ConfigStore,
    mode: SandboxMode,
    events: &mut Events,
) -> Result<i32> {
    ensure_mode_supported(mode)?;
    let mut saved = store.project_sandbox(root)?;
    saved.mode = mode;
    let effective = EffectiveSandboxPolicy::resolve(saved, cli.sandbox, cli.sandbox_network)?;
    if effective.is_active() {
        ensure_mode_supported(effective.mode)?;
    }
    store.save_project_sandbox(root, saved)?;
    if cli.json {
        events.emit(
            "sandbox",
            json!({
                "action": "mode",
                "workspace": root,
                "saved": saved,
                "effective": effective,
            }),
        );
    } else {
        println!(
            "✓ OS-песочница проекта ({}) сохранена: {}",
            root.display(),
            mode.label_ru()
        );
        if mode != SandboxMode::Off {
            println!(
                "  Доступ к IP-сети внутри песочницы: {}",
                if saved.network {
                    "разрешён (IPv4/IPv6)"
                } else {
                    "заблокирован (включить: rcode sandbox network on)"
                }
            );
        }
    }
    Ok(0)
}

fn set_network(
    root: &Path,
    cli: &Cli,
    store: &ConfigStore,
    network: bool,
    events: &mut Events,
) -> Result<i32> {
    let mut saved = store.project_sandbox(root)?;
    saved.network = network;
    let effective = EffectiveSandboxPolicy::resolve(saved, cli.sandbox, cli.sandbox_network)?;
    if effective.is_active() {
        ensure_mode_supported(effective.mode)?;
    }
    store.save_project_sandbox(root, saved)?;
    if cli.json {
        events.emit(
            "sandbox",
            json!({
                "action": "network",
                "workspace": root,
                "saved": saved,
                "effective": effective,
            }),
        );
    } else {
        println!(
            "✓ Доступ к IP-сети для песочницы проекта ({}): {}",
            root.display(),
            if network {
                "разрешён (IPv4/IPv6; пользовательские AF_UNIX сокеты заблокированы)"
            } else {
                "заблокирован"
            }
        );
        if saved.mode == SandboxMode::Off {
            println!(
                "  Примечание: сейчас режим песочницы проекта = off; настройка сети вступит в силу при включении workspace-write или read-only."
            );
        }
    }
    Ok(0)
}

pub fn render_status_text(
    root: &Path,
    support: &BackendSupport,
    saved: ProjectSandbox,
    effective: EffectiveSandboxPolicy,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Проект       {}", root.display()));
    let backend_line = match (support.available, support.landlock_abi) {
        (true, Some(abi)) => format!("{} (доступен, Landlock ABI v{abi})", support.backend),
        (true, None) => format!("{} (доступен)", support.backend),
        (false, _) => format!(
            "{} (недоступен: {})",
            support.backend,
            support.reason.as_deref().unwrap_or("нет данных")
        ),
    };
    lines.push(format!("Бэкенд ОС    {backend_line}"));
    let saved_line = match (saved.mode, saved.network) {
        (SandboxMode::Off, false) => "off (без ограничений песочницы)".to_owned(),
        (SandboxMode::Off, true) => {
            "off (без ограничений песочницы; для активных режимов сохранено network=on)".to_owned()
        }
        (mode, true) => format!("{} · сеть on", mode.as_str()),
        (mode, false) => format!("{} · сеть off", mode.as_str()),
    };
    lines.push(format!("Сохранено    {saved_line}"));
    let effective_line = match (effective.mode, effective.network) {
        (SandboxMode::Off, _) => "off (песочница выключена, права пользователя)".to_owned(),
        (mode, true) => format!("{} · IP-сеть разрешена", mode.as_str()),
        (mode, false) => format!("{} · сеть заблокирована", mode.as_str()),
    };
    lines.push(format!("Эффективно   {effective_line}"));
    if !support.limitations.is_empty() {
        lines.push("Границы платформы:".into());
        for note in &support.limitations {
            lines.push(format!("  - {note}"));
        }
    }
    lines.join("\n")
}
