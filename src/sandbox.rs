//! Host-enforced OS sandbox for model shell commands (`macOS Seatbelt` and
//! `Linux Landlock ABI >= 3 + CLOSE_RANGE_CLOEXEC + seccomp-bpf`).
//! Environment scrubbing, command approvals, and process-group supervision stay
//! in their respective host layers.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

const MAX_ARGS: usize = 256;
const MAX_ARG_BYTES: usize = 128 * 1024;
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const MAX_GIT_POINTER_BYTES: u64 = 8 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    #[default]
    Off,
    WorkspaceWrite,
    ReadOnly,
}

impl SandboxMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::WorkspaceWrite => "workspace-write",
            Self::ReadOnly => "read-only",
        }
    }

    pub fn label_ru(self) -> &'static str {
        match self {
            Self::Off => "выключена (права пользователя)",
            Self::WorkspaceWrite => "workspace-write (запись только в проект и TMPDIR задания)",
            Self::ReadOnly => "read-only (проект только на чтение, запись только в TMPDIR задания)",
        }
    }
}

impl std::fmt::Display for SandboxMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SandboxMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "off" => Ok(Self::Off),
            "workspace-write" => Ok(Self::WorkspaceWrite),
            "read-only" => Ok(Self::ReadOnly),
            other => bail!(
                "Неизвестный режим песочницы «{other}» (допустимы: off, workspace-write, read-only)"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectSandbox {
    pub mode: SandboxMode,
    pub network: bool,
}

impl ProjectSandbox {
    pub fn is_default(self) -> bool {
        self.mode == SandboxMode::Off && !self.network
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveSandboxPolicy {
    pub mode: SandboxMode,
    pub network: bool,
}

impl EffectiveSandboxPolicy {
    pub const fn off() -> Self {
        Self {
            mode: SandboxMode::Off,
            network: false,
        }
    }

    pub fn is_active(self) -> bool {
        self.mode != SandboxMode::Off
    }

    pub fn resolve(
        saved: ProjectSandbox,
        cli_mode: Option<SandboxMode>,
        cli_network: Option<crate::cli::Toggle>,
    ) -> Result<Self> {
        let mode = cli_mode.unwrap_or(saved.mode);
        if mode == SandboxMode::Off && cli_network == Some(crate::cli::Toggle::On) {
            bail!(
                "--sandbox-network on требует активного режима песочницы (--sandbox workspace-write или read-only)"
            );
        }
        let network = if mode == SandboxMode::Off {
            false
        } else {
            match cli_network {
                Some(crate::cli::Toggle::On) => true,
                Some(crate::cli::Toggle::Off) => false,
                None => saved.network,
            }
        };
        Ok(Self { mode, network })
    }

    pub fn short_badge(self) -> &'static str {
        match (self.mode, self.network) {
            (SandboxMode::Off, _) => "sandbox: off",
            (SandboxMode::WorkspaceWrite, false) => "sandbox: workspace-write",
            (SandboxMode::WorkspaceWrite, true) => "sandbox: workspace-write+net",
            (SandboxMode::ReadOnly, false) => "sandbox: read-only",
            (SandboxMode::ReadOnly, true) => "sandbox: read-only+net",
        }
    }

    pub fn status_label_ru(self) -> String {
        if self.mode == SandboxMode::Off {
            "выключена (shell запускается с правами пользователя) · /sandbox — настроить".into()
        } else {
            format!(
                "{} · сеть {} · /sandbox — настроить",
                self.mode.as_str(),
                if self.network {
                    "разрешена (только IP)"
                } else {
                    "заблокирована"
                }
            )
        }
    }

    pub fn runtime_context_value(self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode.as_str(),
            "network": self.network,
        })
    }
}

/// Host-only origin authority distinguishing model tool execution from operator `!` shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionAuthority {
    ModelTool(EffectiveSandboxPolicy),
    OperatorBang,
}

impl ExecutionAuthority {
    pub fn policy(self) -> EffectiveSandboxPolicy {
        match self {
            Self::ModelTool(policy) => policy,
            Self::OperatorBang => EffectiveSandboxPolicy::off(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BackendSupport {
    pub available: bool,
    pub backend: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub landlock_abi: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub limitations: Vec<&'static str>,
}

pub fn probe_support() -> BackendSupport {
    #[cfg(target_os = "macos")]
    {
        match available_macos_backend() {
            Ok(()) => BackendSupport {
                available: true,
                backend: "macos_seatbelt",
                landlock_abi: None,
                reason: None,
                limitations: vec![
                    "Намеренный выход потомка из process group (setsid/setpgid) сохраняет ограничения Seatbelt: удержание унаследованных пайпов переводит завершение в cleanup_complete=false, но потомок, закрывший все пайпы после смены группы, не обнаруживается супервизором.",
                ],
            },
            Err(error) => BackendSupport {
                available: false,
                backend: "macos_seatbelt",
                landlock_abi: None,
                reason: Some(format!("{error:#}")),
                limitations: vec![],
            },
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux::probe_linux_support()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        BackendSupport {
            available: false,
            backend: "unsupported",
            landlock_abi: None,
            reason: Some(
                "OS-песочница поддерживается только на macOS (Seatbelt) и Linux x86_64/aarch64 (Landlock ABI >= 3 + seccomp-bpf)".into(),
            ),
            limitations: vec![],
        }
    }
}

pub fn ensure_mode_supported(mode: SandboxMode) -> Result<()> {
    if mode == SandboxMode::Off {
        return Ok(());
    }
    let support = probe_support();
    if !support.available {
        let reason = support
            .reason
            .unwrap_or_else(|| "механизм изоляции ОС недоступен".into());
        bail!(
            "Режим песочницы {} недоступен на этой системе (fail-closed): {reason}",
            mode.as_str()
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    #[default]
    Off,
    Macos,
    Linux,
}

impl SandboxBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Macos => "macos",
            Self::Linux => "linux",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEnforcement {
    #[default]
    None,
    WrapperExec,
    PreExec,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SandboxReceiptMeta {
    pub version: u32,
    pub requested_mode: SandboxMode,
    pub backend: SandboxBackend,
    pub network: bool,
    pub enforcement: SandboxEnforcement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_sha256: Option<String>,
}

impl SandboxReceiptMeta {
    pub fn off() -> Self {
        Self {
            version: 1,
            requested_mode: SandboxMode::Off,
            backend: SandboxBackend::Off,
            network: false,
            enforcement: SandboxEnforcement::None,
            policy_sha256: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub version: u32,
    pub backend: SandboxBackend,
    pub write_roots: Vec<PathBuf>,
    pub read_roots: Vec<PathBuf>,
    pub protected_paths: Vec<PathBuf>,
    pub network: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            version: 1,
            backend: SandboxBackend::Off,
            write_roots: vec![],
            read_roots: vec![],
            protected_paths: vec![],
            network: false,
        }
    }
}

impl SandboxConfig {
    pub fn validate(&self, workspace: &Path) -> Result<()> {
        self.checked_roots(workspace).map(|_| ())
    }

    pub fn wrap(&self, workspace: &Path, argv: &[String]) -> Result<Vec<String>> {
        check_argv(argv)?;
        let roots = self.checked_roots(workspace)?;
        match self.backend {
            SandboxBackend::Off => Ok(argv.to_vec()),
            SandboxBackend::Macos => {
                let read_roots = self
                    .read_roots
                    .iter()
                    .map(|p| canonical_writable_dir(p))
                    .collect::<Result<Vec<_>>>()?;
                let protected = self
                    .protected_paths
                    .iter()
                    .map(|p| protected_path(p))
                    .collect::<Result<Vec<_>>>()?;
                let mut wrapped = vec![
                    SANDBOX_EXEC.into(),
                    "-p".into(),
                    profile(&roots, &read_roots, &[], &protected, self.network)?,
                    "--".into(),
                ];
                wrapped.extend_from_slice(argv);
                Ok(wrapped)
            }
            SandboxBackend::Linux => {
                bail!("Linux Landlock/seccomp применяется через pre_exec, а не argv-обёртку")
            }
        }
    }

    pub fn description(&self) -> &'static str {
        match self.backend {
            SandboxBackend::Off => "Off: shell с правами пользователя, включая доступ к сети.",
            SandboxBackend::Macos => {
                "macOS Seatbelt: чтение проекта и системных runtime, запись только в проект и явно заданные каталоги; IP-сеть по явному выбору оператора. Очисткой env и разрешениями управляет host."
            }
            SandboxBackend::Linux => {
                "Linux Landlock + seccomp-bpf: ограничение дерева ФС, закрытие лишних FD на exec и фильтрация сокетов/io_uring/xattr/chown в pre_exec."
            }
        }
    }

    fn checked_roots(&self, workspace: &Path) -> Result<Vec<PathBuf>> {
        ensure!(
            self.version == 1,
            "Неподдерживаемая версия sandbox {}",
            self.version
        );
        ensure!(
            self.write_roots.len() <= 8,
            "Допускается не более восьми дополнительных каталогов"
        );
        ensure!(
            self.read_roots.len() <= 8 && self.protected_paths.len() <= 32,
            "Превышено число read/protected каталогов sandbox"
        );
        for path in &self.read_roots {
            canonical_writable_dir(path)?;
        }
        for path in &self.protected_paths {
            protected_path(path)?;
        }
        match self.backend {
            SandboxBackend::Off => {}
            SandboxBackend::Macos => available_macos_backend()?,
            SandboxBackend::Linux => ensure_mode_supported(SandboxMode::WorkspaceWrite)?,
        }
        let mut roots = vec![canonical_writable_dir(workspace)?];
        for root in &self.write_roots {
            let root = canonical_writable_dir(root)?;
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        Ok(roots)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellTmpLifecycle {
    /// Created during preflight before child spawn: Drop cleans up immediately.
    Unspawned,
    /// Child process spawned: cleanup is performed ONLY on confirmed process exit,
    /// never blindly in Drop while an unconfirmed descendant may still be alive.
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    Spawned,
    /// Directory confirmed absent after cleanup.
    Cleaned,
}

/// Private per-job temporary directory (`0700`) bound to `(dev, ino)` on Unix.
#[derive(Debug)]
pub struct ShellTmp {
    path: PathBuf,
    parent: PathBuf,
    name: std::ffi::OsString,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    lifecycle: ShellTmpLifecycle,
}

impl ShellTmp {
    pub fn create(
        rcode_home: Option<&Path>,
        home_dir: Option<&Path>,
        secrets: &[String],
    ) -> Result<Self> {
        Self::create_in(&std::env::temp_dir(), rcode_home, home_dir, secrets)
    }

    pub(crate) fn create_in(
        base_raw: &Path,
        rcode_home: Option<&Path>,
        home_dir: Option<&Path>,
        secrets: &[String],
    ) -> Result<Self> {
        let parent = std::fs::canonicalize(base_raw)
            .context("Системный временный каталог недоступен для песочницы")?;
        ensure!(
            parent.is_dir(),
            "Системный временный каталог не является папкой"
        );
        ensure!(
            parent.to_str().is_some(),
            "Путь временного каталога должен быть в UTF-8"
        );
        if let Some(rc) = rcode_home {
            ensure!(
                !parent.starts_with(rc),
                "Системный временный каталог находится внутри RCODE_HOME"
            );
        }
        if let Some(home) = home_dir {
            ensure!(
                parent != home,
                "Системный временный каталог не может совпадать с домашним каталогом $HOME"
            );
        }

        let patterns: Vec<&[u8]> = secrets
            .iter()
            .filter(|s| !s.is_empty())
            .map(String::as_bytes)
            .collect();

        struct RemoveCreatedDirGuard(Option<PathBuf>);
        impl Drop for RemoveCreatedDirGuard {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    let _ = std::fs::remove_dir(path);
                }
            }
        }

        for _ in 0..8 {
            let dir_name = format!("rcode-job-{}", uuid::Uuid::new_v4());
            let candidate = parent.join(&dir_name);
            let candidate_str = candidate
                .to_str()
                .context("Путь временного каталога задания должен быть в UTF-8")?;
            if patterns.iter().any(|pat| {
                candidate_str
                    .as_bytes()
                    .windows(pat.len())
                    .any(|w| w == *pat)
            }) {
                continue;
            }
            validate_grant_against_sensitive_roots(&candidate, rcode_home, home_dir)?;
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut b = std::fs::DirBuilder::new();
                b.mode(0o700);
                b
            };
            #[cfg(not(unix))]
            let builder = std::fs::DirBuilder::new();
            match builder.create(&candidate) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(e).context("Не удалось создать приватный TMPDIR задания");
                }
            }
            let mut created_guard = RemoveCreatedDirGuard(Some(candidate));
            let candidate_ref = created_guard.0.as_deref().expect("armed");
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                std::fs::set_permissions(candidate_ref, std::fs::Permissions::from_mode(0o700))
                    .context("Не удалось установить права 0700 для TMPDIR задания")?;
                let meta = std::fs::symlink_metadata(candidate_ref)
                    .context("Не удалось проверить метаданные TMPDIR задания")?;
                let euid = unsafe { libc::geteuid() };
                ensure!(
                    !meta.file_type().is_symlink()
                        && meta.is_dir()
                        && meta.uid() == euid
                        && (meta.mode() & 0o777) == 0o700,
                    "Проверка безопасности приватного TMPDIR задания не пройдена"
                );
                let dev = meta.dev();
                let ino = meta.ino();
                let path = created_guard.0.take().expect("armed");
                return Ok(Self {
                    path,
                    parent,
                    name: dir_name.into(),
                    dev,
                    ino,
                    lifecycle: ShellTmpLifecycle::Unspawned,
                });
            }
            #[cfg(not(unix))]
            {
                let _ = candidate_ref;
                let path = created_guard.0.take().expect("armed");
                return Ok(Self {
                    path,
                    parent,
                    name: dir_name.into(),
                    lifecycle: ShellTmpLifecycle::Unspawned,
                });
            }
        }
        bail!("Не удалось выделить уникальный безопасный TMPDIR задания")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(any(target_os = "macos", target_os = "linux", all(test, unix)))]
    pub(crate) fn mark_spawned(&mut self) {
        if self.lifecycle == ShellTmpLifecycle::Unspawned {
            self.lifecycle = ShellTmpLifecycle::Spawned;
        }
    }

    pub fn cleanup_confirmed(&mut self) -> Result<()> {
        if self.lifecycle == ShellTmpLifecycle::Cleaned {
            return Ok(());
        }
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.lifecycle = ShellTmpLifecycle::Cleaned;
                return Ok(());
            }
            Err(e) => {
                return Err(e).context("Не удалось проверить метаданные TMPDIR перед очисткой");
            }
        };
        ensure!(
            !meta.file_type().is_symlink() && meta.is_dir(),
            "TMPDIR задания заменён на симлинк или не-каталог"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let euid = unsafe { libc::geteuid() };
            ensure!(
                meta.dev() == self.dev && meta.ino() == self.ino && meta.uid() == euid,
                "Идентичность TMPDIR задания изменилась перед очисткой"
            );
        }
        let parent_dir =
            cap_std::fs::Dir::open_ambient_dir(&self.parent, cap_std::ambient_authority())
                .context("Не удалось открыть родительский каталог TMPDIR для очистки")?;
        let name_str = self
            .name
            .to_str()
            .context("Имя TMPDIR задания не является UTF-8")?;
        if parent_dir.remove_dir_all(name_str).is_err() {
            #[cfg(unix)]
            let expected_id = Some((self.dev, self.ino));
            #[cfg(not(unix))]
            let expected_id = None;
            force_remove_tree_nofollow(&parent_dir, name_str, expected_id, 0)?;
        }
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.lifecycle = ShellTmpLifecycle::Cleaned;
                Ok(())
            }
            Ok(_) => bail!("TMPDIR задания остался на диске после попытки очистки"),
            Err(e) => Err(e).context("Ошибка повторной проверки отсутствия TMPDIR задания"),
        }
    }
}

impl Drop for ShellTmp {
    fn drop(&mut self) {
        if self.lifecycle == ShellTmpLifecycle::Unspawned {
            let _ = self.cleanup_confirmed();
        }
    }
}

fn force_remove_tree_nofollow(
    parent_dir: &cap_std::fs::Dir,
    name: &str,
    expected_id: Option<(u64, u64)>,
    depth: usize,
) -> Result<()> {
    use cap_fs_ext::DirExt;
    ensure!(depth <= 64, "Превышена глубина дерева TMPDIR при очистке");
    #[cfg(unix)]
    let verified_id = restore_unix_dir_mode_nofollow(parent_dir, name, expected_id)?;
    #[cfg(not(unix))]
    let _ = expected_id;

    let sub_dir = parent_dir
        .open_dir(name)
        .with_context(|| format!("Не удалось открыть подкаталог TMPDIR {name}"))?;
    #[cfg(unix)]
    {
        use cap_fs_ext::MetadataExt;
        let sub_meta = sub_dir.dir_metadata()?;
        ensure!(
            (sub_meta.dev(), sub_meta.ino()) == verified_id,
            "Идентичность подкаталога TMPDIR {name} изменилась при очистке"
        );
    }
    for entry in sub_dir
        .entries()
        .context("Не удалось перечислить содержимое TMPDIR")?
    {
        let entry = entry.context("Ошибка чтения записи каталога TMPDIR")?;
        let child_os = entry.file_name();
        let child_name = child_os
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Не-UTF8 имя внутри TMPDIR"))?;
        let ft = entry
            .file_type()
            .context("Не удалось определить тип записи в TMPDIR")?;
        if ft.is_dir() && !ft.is_symlink() {
            force_remove_tree_nofollow(&sub_dir, child_name, None, depth + 1)?;
        } else {
            sub_dir
                .remove_file_or_symlink(child_name)
                .with_context(|| format!("Не удалось удалить запись {child_name} в TMPDIR"))?;
        }
    }
    drop(sub_dir);
    parent_dir
        .remove_dir(name)
        .with_context(|| format!("Не удалось удалить пустой каталог TMPDIR {name}"))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn stat_dev_ino(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

#[cfg(unix)]
fn restore_unix_dir_mode_nofollow(
    parent_dir: &cap_std::fs::Dir,
    name: &str,
    expected_id: Option<(u64, u64)>,
) -> Result<(u64, u64)> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let c_name = CString::new(name).context("Нулевой байт в имени подкаталога TMPDIR")?;
    let euid = unsafe { libc::geteuid() };

    #[cfg(target_os = "macos")]
    {
        let mut st_before: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent_dir.as_raw_fd(),
                c_name.as_ptr(),
                &mut st_before,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("fstatat(AT_SYMLINK_NOFOLLOW) не удался для {name}"));
        }
        ensure!(
            (st_before.st_mode & libc::S_IFMT) == libc::S_IFDIR && st_before.st_uid == euid,
            "Запись {name} в TMPDIR не является обычным каталогом текущего пользователя"
        );
        let actual_id = stat_dev_ino(&st_before);
        if let Some(exp) = expected_id {
            ensure!(
                actual_id == exp,
                "Идентичность корня TMPDIR не совпадает при восстановлении прав"
            );
        }
        if (st_before.st_mode & 0o700) != 0o700
            && unsafe {
                libc::fchmodat(
                    parent_dir.as_raw_fd(),
                    c_name.as_ptr(),
                    0o700,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("fchmodat(AT_SYMLINK_NOFOLLOW, 0700) на каталоге TMPDIR");
        }
        let raw = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("openat(O_NOFOLLOW|O_DIRECTORY) не удался для {name}"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st_after: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st_after) } != 0 {
            return Err(std::io::Error::last_os_error()).context("fstat на подкаталоге TMPDIR");
        }
        ensure!(
            (st_after.st_mode & libc::S_IFMT) == libc::S_IFDIR
                && st_after.st_uid == euid
                && stat_dev_ino(&st_after) == actual_id,
            "Идентичность каталога {name} изменилась после восстановления прав"
        );
        Ok(actual_id)
    }

    #[cfg(target_os = "linux")]
    {
        let raw = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("openat(O_PATH|O_NOFOLLOW) не удался для {name}"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(std::io::Error::last_os_error()).context("fstat на O_PATH каталоге TMPDIR");
        }
        ensure!(
            (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_uid == euid,
            "Запись {name} в TMPDIR не является обычным каталогом текущего пользователя"
        );
        let actual_id = stat_dev_ino(&st);
        if let Some(exp) = expected_id {
            ensure!(
                actual_id == exp,
                "Идентичность корня TMPDIR не совпадает при восстановлении прав"
            );
        }
        if (st.st_mode & 0o700) != 0o700 {
            let proc_fd = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
            if unsafe { libc::chmod(proc_fd.as_ptr(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("chmod 0700 через /proc/self/fd на каталоге TMPDIR");
            }
        }
        Ok(actual_id)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (c_name, euid);
        use cap_fs_ext::MetadataExt;
        let meta = parent_dir.symlink_metadata(name)?;
        ensure!(
            !meta.file_type().is_symlink() && meta.is_dir(),
            "Запись {name} не является каталогом"
        );
        let actual_id = (meta.dev(), meta.ino());
        if let Some(exp) = expected_id {
            ensure!(actual_id == exp, "Идентичность корня TMPDIR не совпадает");
        }
        Ok(actual_id)
    }
}

/// Prepared host-owned sandbox bound to a single `JobSpec`.
#[derive(Debug)]
pub struct PreparedSandbox {
    meta: SandboxReceiptMeta,
    shell_tmp: Option<ShellTmp>,
    #[cfg(unix)]
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    workspace_identity: Option<(u64, u64)>,
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    inner: PreparedInner,
}

#[derive(Debug)]
enum PreparedInner {
    Off,
    #[cfg(target_os = "macos")]
    Macos {
        profile: String,
    },
    #[cfg(target_os = "linux")]
    Linux {
        ruleset: std::os::fd::OwnedFd,
        seccomp_filter: Vec<BpfInsn>,
    },
}

impl Default for PreparedSandbox {
    fn default() -> Self {
        Self::off()
    }
}

impl PreparedSandbox {
    pub fn off() -> Self {
        Self {
            meta: SandboxReceiptMeta::off(),
            shell_tmp: None,
            #[cfg(unix)]
            workspace_identity: None,
            inner: PreparedInner::Off,
        }
    }

    pub fn prepare(
        policy: EffectiveSandboxPolicy,
        workspace: &Path,
        extra_roots: &[PathBuf],
        rcode_home: Option<&Path>,
        secrets: &[String],
    ) -> Result<Self> {
        let env_home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Self::prepare_with_home(
            policy,
            workspace,
            extra_roots,
            rcode_home,
            env_home.as_deref(),
            secrets,
        )
    }

    pub fn prepare_with_home(
        policy: EffectiveSandboxPolicy,
        workspace: &Path,
        extra_roots: &[PathBuf],
        rcode_home: Option<&Path>,
        home_dir: Option<&Path>,
        secrets: &[String],
    ) -> Result<Self> {
        if !policy.is_active() {
            return Ok(Self::off());
        }
        ensure_mode_supported(policy.mode)?;
        ensure!(
            extra_roots.len() <= 16,
            "Превышено допустимое число дополнительных каталогов для песочницы"
        );

        let canonical_rcode_home = match rcode_home {
            Some(path) => Some(resolve_sensitive_path(path)?),
            None => None,
        };
        let canonical_home = match home_dir {
            Some(path) if !path.as_os_str().is_empty() => resolve_sensitive_path(path).ok(),
            _ => None,
        };

        let verified_workspace = canonical_writable_dir_verified(workspace)?;
        #[cfg(unix)]
        let workspace_identity = Some((verified_workspace.dev, verified_workspace.ino));
        validate_grant_against_sensitive_roots(
            &verified_workspace.path,
            canonical_rcode_home.as_deref(),
            canonical_home.as_deref(),
        )?;

        let mut verified_extras: Vec<VerifiedDir> = Vec::new();
        for extra in extra_roots {
            let root = canonical_writable_dir_verified(extra)?;
            validate_grant_against_sensitive_roots(
                &root.path,
                canonical_rcode_home.as_deref(),
                canonical_home.as_deref(),
            )?;
            if root.path != verified_workspace.path
                && !verified_extras.iter().any(|d| d.path == root.path)
            {
                verified_extras.push(root);
            }
        }

        let mut project_roots = Vec::with_capacity(1 + verified_extras.len());
        project_roots.push(verified_workspace);
        project_roots.extend(verified_extras);

        let git_discovery = discover_git_paths(
            &project_roots,
            canonical_rcode_home.as_deref(),
            canonical_home.as_deref(),
        )?;

        let shell_tmp = ShellTmp::create(
            canonical_rcode_home.as_deref(),
            canonical_home.as_deref(),
            secrets,
        )?;
        let shell_tmp_path = shell_tmp.path().to_path_buf();

        let toolchain_reads = discover_user_toolchain_roots(
            canonical_home.as_deref(),
            canonical_rcode_home.as_deref(),
        );

        #[cfg(target_os = "macos")]
        {
            let mut write_roots = vec![shell_tmp_path];
            let mut read_roots = Vec::new();
            match policy.mode {
                SandboxMode::WorkspaceWrite => {
                    for root in &project_roots {
                        if !write_roots.contains(&root.path) {
                            write_roots.push(root.path.clone());
                        }
                    }
                }
                SandboxMode::ReadOnly => {
                    for root in &project_roots {
                        if !read_roots.contains(&root.path) {
                            read_roots.push(root.path.clone());
                        }
                    }
                }
                SandboxMode::Off => unreachable!(),
            }
            for git_read in &git_discovery.external_read_roots {
                if !write_roots.contains(&git_read.path) && !read_roots.contains(&git_read.path) {
                    read_roots.push(git_read.path.clone());
                }
            }
            for tc in toolchain_reads {
                if !write_roots.contains(&tc.path) && !read_roots.contains(&tc.path) {
                    read_roots.push(tc.path);
                }
            }

            let mut protected_write = Vec::new();
            if policy.mode == SandboxMode::WorkspaceWrite {
                for root in &project_roots {
                    protected_write.push(root.path.join(".git"));
                    protected_write.push(root.path.join(".rcode"));
                }
                for path in &git_discovery.protected_write_paths {
                    if !protected_write.contains(path) {
                        protected_write.push(path.clone());
                    }
                }
            }

            let mut protected_all = Vec::new();
            if let Some(rc) = &canonical_rcode_home {
                protected_all.push(rc.clone());
            }

            let rendered = profile(
                &write_roots,
                &read_roots,
                &protected_write,
                &protected_all,
                policy.network,
            )?;
            let digest = hex_sha256(rendered.as_bytes());
            Ok(Self {
                meta: SandboxReceiptMeta {
                    version: 1,
                    requested_mode: policy.mode,
                    backend: SandboxBackend::Macos,
                    network: policy.network,
                    enforcement: SandboxEnforcement::WrapperExec,
                    policy_sha256: Some(digest),
                },
                shell_tmp: Some(shell_tmp),
                workspace_identity,
                inner: PreparedInner::Macos { profile: rendered },
            })
        }

        #[cfg(target_os = "linux")]
        {
            let _ = shell_tmp_path;
            let verified_shell_tmp = linux::verify_shell_tmp_opath(&shell_tmp)?;
            let prepared = linux::prepare_linux_sandbox(
                policy,
                &project_roots,
                &git_discovery.external_read_roots,
                &toolchain_reads,
                &verified_shell_tmp,
                canonical_rcode_home.as_deref(),
                canonical_home.as_deref(),
            )?;
            Ok(Self {
                meta: SandboxReceiptMeta {
                    version: 1,
                    requested_mode: policy.mode,
                    backend: SandboxBackend::Linux,
                    network: policy.network,
                    enforcement: SandboxEnforcement::PreExec,
                    policy_sha256: Some(prepared.policy_sha256),
                },
                shell_tmp: Some(shell_tmp),
                workspace_identity,
                inner: PreparedInner::Linux {
                    ruleset: prepared.ruleset,
                    seccomp_filter: prepared.seccomp_filter,
                },
            })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            #[cfg(unix)]
            let _ = workspace_identity;
            let _ = (shell_tmp_path, toolchain_reads, git_discovery);
            bail!("OS-песочница недоступна на этой платформе")
        }
    }

    pub fn apply_to_env(&self, env: &mut Vec<(String, String)>) {
        let Some(shell_tmp) = &self.shell_tmp else {
            return;
        };
        let value = shell_tmp
            .path()
            .to_str()
            .expect("ShellTmp verified UTF-8")
            .to_owned();
        env.retain(|(k, _)| {
            !matches!(
                k.as_str(),
                "TMPDIR" | "TMP" | "TEMP" | "GIT_CONFIG_NOSYSTEM" | "GIT_CONFIG_GLOBAL"
            )
        });
        env.push(("TMPDIR".into(), value.clone()));
        env.push(("TMP".into(), value.clone()));
        env.push(("TEMP".into(), value));
        env.push(("GIT_CONFIG_NOSYSTEM".into(), "1".into()));
        env.push(("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()));
    }

    pub fn receipt_meta(&self) -> SandboxReceiptMeta {
        self.meta.clone()
    }

    pub fn is_active(&self) -> bool {
        self.meta.requested_mode != SandboxMode::Off
    }

    #[cfg(unix)]
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    pub(crate) fn workspace_identity(&self) -> Option<(u64, u64)> {
        self.workspace_identity
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) fn take_shell_tmp_for_spawned(&mut self) -> Option<ShellTmp> {
        let mut tmp = self.shell_tmp.take()?;
        tmp.mark_spawned();
        Some(tmp)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn macos_profile(&self) -> Option<&str> {
        match &self.inner {
            PreparedInner::Macos { profile } => Some(profile.as_str()),
            PreparedInner::Off => None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn linux_pre_exec_parts(&self) -> Option<(std::os::fd::RawFd, &[BpfInsn])> {
        use std::os::fd::AsRawFd;
        match &self.inner {
            PreparedInner::Linux {
                ruleset,
                seccomp_filter,
            } => Some((ruleset.as_raw_fd(), seccomp_filter.as_slice())),
            PreparedInner::Off => None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn apply_linux_in_child(
        ruleset_fd: std::os::fd::RawFd,
        seccomp_filter: &[BpfInsn],
    ) -> std::io::Result<()> {
        unsafe { linux::apply_in_pre_exec(ruleset_fd, seccomp_filter) }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn resolve_sensitive_path(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "Пустой чувствительный путь");
    let absolute = std::path::absolute(path)?;
    match std::fs::canonicalize(&absolute) {
        Ok(canonical) => Ok(canonical),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name())
                && let Ok(canonical_parent) = std::fs::canonicalize(parent)
            {
                return Ok(canonical_parent.join(name));
            }
            Ok(absolute)
        }
        Err(e) => Err(e).context("Не удалось разрешить чувствительный путь"),
    }
}

fn validate_grant_against_sensitive_roots(
    grant: &Path,
    rcode_home: Option<&Path>,
    home_dir: Option<&Path>,
) -> Result<()> {
    let grant_forms = macos_alias_forms(grant);
    if let Some(rc) = rcode_home {
        for rc_form in macos_alias_forms(rc) {
            for g in &grant_forms {
                ensure!(
                    g != &rc_form && !rc_form.starts_with(g) && !g.starts_with(&rc_form),
                    "Разрешённый каталог песочницы {} пересекается с RCODE_HOME ({})",
                    grant.display(),
                    rc.display()
                );
            }
        }
    }
    if let Some(home) = home_dir {
        for home_form in macos_alias_forms(home) {
            for g in &grant_forms {
                ensure!(
                    g != &home_form && !home_form.starts_with(g),
                    "Разрешённый каталог песочницы {} не может совпадать с $HOME или быть его предком",
                    grant.display()
                );
                if let Ok(rel) = g.strip_prefix(&home_form)
                    && let Some(Component::Normal(first)) = rel.components().next()
                {
                    let name = first.to_string_lossy();
                    ensure!(
                        !matches!(
                            name.as_ref(),
                            ".ssh"
                                | ".aws"
                                | ".gnupg"
                                | ".kube"
                                | ".docker"
                                | ".rcode"
                                | ".netrc"
                                | ".npmrc"
                                | ".pypirc"
                        ),
                        "Каталог {} внутри чувствительного подкаталога $HOME запрещён для песочницы",
                        grant.display()
                    );
                }
            }
        }
    }
    Ok(())
}

struct VerifiedDir {
    path: PathBuf,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(target_os = "linux")]
    opath_fd: std::os::fd::OwnedFd,
}

struct GitDiscovery {
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    external_read_roots: Vec<VerifiedDir>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    protected_write_paths: Vec<PathBuf>,
}

fn discover_git_paths(
    project_roots: &[VerifiedDir],
    rcode_home: Option<&Path>,
    home_dir: Option<&Path>,
) -> Result<GitDiscovery> {
    let mut external_read_roots: Vec<VerifiedDir> = Vec::new();
    let mut protected_write_paths = Vec::new();

    for root_dir in project_roots {
        let root = root_dir.path.as_path();

        let dot_rcode = root.join(".rcode");
        match std::fs::symlink_metadata(&dot_rcode) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let (resolved, symlinks) = resolve_path_collecting_symlinks(&dot_rcode)
                    .with_context(|| {
                        format!(
                            "Симлинк {} указывает на недоступную цель",
                            dot_rcode.display()
                        )
                    })?;
                let resolved_meta = std::fs::symlink_metadata(&resolved).with_context(|| {
                    format!("Не удалось проверить цель симлинка {}", resolved.display())
                })?;
                ensure!(
                    resolved_meta.is_dir() || resolved_meta.is_file(),
                    "Симлинк {} указывает на специальный файл {}",
                    dot_rcode.display(),
                    resolved.display()
                );
                validate_grant_against_sensitive_roots(&resolved, rcode_home, home_dir)?;
                record_in_project_symlinks(&mut protected_write_paths, project_roots, &symlinks)?;
                push_unique_protected(&mut protected_write_paths, resolved)?;
            }
            Ok(meta) if meta.is_dir() || meta.is_file() => {}
            Ok(_) => {
                bail!(
                    "Специальный файл {} не поддерживается песочницей",
                    dot_rcode.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("Не удалось проверить метаданные {}", dot_rcode.display())
                });
            }
        }

        let dot_git = root.join(".git");
        let meta = match std::fs::symlink_metadata(&dot_git) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("Не удалось проверить метаданные {}", dot_git.display())
                });
            }
        };
        if meta.file_type().is_symlink() {
            let (resolved, symlinks) =
                resolve_path_collecting_symlinks(&dot_git).with_context(|| {
                    format!(
                        "Симлинк {} указывает на недоступную цель",
                        dot_git.display()
                    )
                })?;
            validate_grant_against_sensitive_roots(&resolved, rcode_home, home_dir)?;
            record_in_project_symlinks(&mut protected_write_paths, project_roots, &symlinks)?;
            push_unique_protected(&mut protected_write_paths, resolved.clone())?;
            let resolved_meta = std::fs::symlink_metadata(&resolved).with_context(|| {
                format!("Не удалось проверить цель симлинка {}", resolved.display())
            })?;
            if resolved_meta.is_dir() {
                if let Some(common) = parse_commondir_file(&resolved)? {
                    validate_grant_against_sensitive_roots(&common.dir.path, rcode_home, home_dir)?;
                    record_in_project_symlinks(
                        &mut protected_write_paths,
                        project_roots,
                        &common.traversed_symlinks,
                    )?;
                    push_unique_protected(&mut protected_write_paths, common.dir.path)?;
                }
            } else if resolved_meta.is_file() {
                let file_parent = resolved
                    .parent()
                    .context("У целевого gitfile отсутствует родительский каталог")?;
                let file_name = resolved
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("Имя целевого gitfile должно быть в UTF-8")?;
                // Git (`setup.c::read_gitfile_gently`) resolves relative `gitdir:` paths
                // relative to the directory containing `.git` (`root`), NOT the symlink target's parent!
                let gitdir =
                    parse_gitdir_file_at(root, file_parent, file_name)?.with_context(|| {
                        format!(
                            "Целевой gitfile симлинка {} исчез во время подготовки песочницы",
                            dot_git.display()
                        )
                    })?;
                validate_grant_against_sensitive_roots(&gitdir.dir.path, rcode_home, home_dir)?;
                record_in_project_symlinks(
                    &mut protected_write_paths,
                    project_roots,
                    &gitdir.traversed_symlinks,
                )?;
                push_unique_protected(&mut protected_write_paths, gitdir.dir.path.clone())?;
                if let Some(common) = parse_commondir_file(&gitdir.dir.path)? {
                    validate_grant_against_sensitive_roots(&common.dir.path, rcode_home, home_dir)?;
                    record_in_project_symlinks(
                        &mut protected_write_paths,
                        project_roots,
                        &common.traversed_symlinks,
                    )?;
                    push_unique_protected(&mut protected_write_paths, common.dir.path)?;
                }
            } else {
                bail!(
                    "Симлинк {} указывает на специальный файл {}",
                    dot_git.display(),
                    resolved.display()
                );
            }
            continue;
        }
        if meta.is_dir() {
            // Git (`setup.c::get_common_dir_noenv`) also honors `<root>/.git/commondir`
            // inside an ordinary `.git/` directory; protect its target against writes,
            // without promoting unverified external directories into `external_read_roots`.
            if let Some(common) = parse_commondir_file(&dot_git)? {
                validate_grant_against_sensitive_roots(&common.dir.path, rcode_home, home_dir)?;
                record_in_project_symlinks(
                    &mut protected_write_paths,
                    project_roots,
                    &common.traversed_symlinks,
                )?;
                push_unique_protected(&mut protected_write_paths, common.dir.path)?;
            }
            continue;
        }
        ensure!(
            meta.is_file(),
            "Специальный файл {} не поддерживается песочницей",
            dot_git.display()
        );
        let gitdir = parse_gitdir_file(root, &dot_git)?.with_context(|| {
            format!(
                "Файл {} исчез во время подготовки песочницы",
                dot_git.display()
            )
        })?;
        validate_grant_against_sensitive_roots(&gitdir.dir.path, rcode_home, home_dir)?;
        record_in_project_symlinks(
            &mut protected_write_paths,
            project_roots,
            &gitdir.traversed_symlinks,
        )?;
        push_unique_protected(&mut protected_write_paths, gitdir.dir.path.clone())?;

        let commondir = parse_commondir_file(&gitdir.dir.path)?;
        if let Some(common) = &commondir {
            validate_grant_against_sensitive_roots(&common.dir.path, rcode_home, home_dir)?;
            record_in_project_symlinks(
                &mut protected_write_paths,
                project_roots,
                &common.traversed_symlinks,
            )?;
            push_unique_protected(&mut protected_write_paths, common.dir.path.clone())?;
        }

        // Grant external read access ONLY when `<gitdir>/gitdir` mutually links
        // back to `<root>/.git` and the target has verified Git metadata layout.
        // This prevents a crafted or mid-session rewritten `.git` file from
        // promoting arbitrary host directories into `read_roots`.
        let mutually_verified = match &commondir {
            Some(common) => {
                verify_git_worktree_backlink(root, &gitdir.dir.path)
                    && has_regular_git_head(&gitdir.dir.path)
                    && gitdir.dir.path.parent() == Some(common.dir.path.join("worktrees").as_path())
                    && is_verified_git_common_dir(&common.dir.path)
            }
            None => {
                verify_git_worktree_backlink(root, &gitdir.dir.path)
                    && is_verified_git_common_dir(&gitdir.dir.path)
            }
        };
        if !mutually_verified {
            continue;
        }

        if !project_roots
            .iter()
            .any(|r| gitdir.dir.path.starts_with(&r.path))
            && !external_read_roots
                .iter()
                .any(|r| r.path == gitdir.dir.path)
        {
            external_read_roots.push(gitdir.dir);
        }
        if let Some(common) = commondir
            && !project_roots
                .iter()
                .any(|r| common.dir.path.starts_with(&r.path))
            && !external_read_roots
                .iter()
                .any(|r| r.path == common.dir.path)
        {
            external_read_roots.push(common.dir);
        }
    }

    Ok(GitDiscovery {
        external_read_roots,
        protected_write_paths,
    })
}

struct ResolvedGitTarget {
    dir: VerifiedDir,
    traversed_symlinks: Vec<PathBuf>,
}

fn push_unique_protected(protected_write_paths: &mut Vec<PathBuf>, path: PathBuf) -> Result<()> {
    ensure!(
        path.to_str().is_some(),
        "Защищённый путь {} должен быть в UTF-8",
        path.display()
    );
    if !protected_write_paths.contains(&path) {
        protected_write_paths.push(path);
    }
    Ok(())
}

fn record_in_project_symlinks(
    protected_write_paths: &mut Vec<PathBuf>,
    project_roots: &[VerifiedDir],
    symlinks: &[PathBuf],
) -> Result<()> {
    for hop in symlinks {
        if project_roots
            .iter()
            .any(|r| hop != &r.path && hop.starts_with(&r.path))
        {
            push_unique_protected(protected_write_paths, hop.clone())?;
        }
    }
    Ok(())
}

fn resolve_path_collecting_symlinks(path: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    const MAX_SYMLINK_HOPS: usize = 40;
    let abs = std::path::absolute(path)?;
    let mut cur = PathBuf::from("/");
    let mut queue = std::collections::VecDeque::new();
    for comp in abs.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                queue.push_back(std::ffi::OsString::from(".."));
            }
            Component::Normal(c) => {
                queue.push_back(c.to_os_string());
            }
            Component::Prefix(p) => {
                cur = PathBuf::from(p.as_os_str());
            }
        }
    }
    let mut hops = 0usize;
    let mut traversed_symlinks = Vec::new();
    while let Some(part) = queue.pop_front() {
        if part == "." || part.is_empty() {
            continue;
        }
        if part == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(&part);
        let meta = std::fs::symlink_metadata(&next).with_context(|| {
            format!(
                "Путь {} недоступен (компонент {})",
                path.display(),
                next.display()
            )
        })?;
        if meta.file_type().is_symlink() {
            hops += 1;
            ensure!(
                hops <= MAX_SYMLINK_HOPS,
                "Превышен лимит симлинков при разрешении {}",
                path.display()
            );
            if !traversed_symlinks.contains(&next) {
                traversed_symlinks.push(next.clone());
            }
            let target = std::fs::read_link(&next)
                .with_context(|| format!("Не удалось прочитать симлинк {}", next.display()))?;
            let mut replacement = Vec::new();
            for comp in target.components() {
                match comp {
                    Component::RootDir => {
                        cur = PathBuf::from("/");
                        replacement.clear();
                    }
                    Component::CurDir => {}
                    Component::ParentDir => {
                        replacement.push(std::ffi::OsString::from(".."));
                    }
                    Component::Normal(c) => {
                        replacement.push(c.to_os_string());
                    }
                    Component::Prefix(p) => {
                        cur = PathBuf::from(p.as_os_str());
                        replacement.clear();
                    }
                }
            }
            for item in replacement.into_iter().rev() {
                queue.push_front(item);
            }
        } else {
            cur = next;
        }
    }
    let canonical = std::fs::canonicalize(&cur)
        .with_context(|| format!("Канонизация {} не удалась", cur.display()))?;
    Ok((canonical, traversed_symlinks))
}

/// Strips at most one trailing line ending (`\r\n`, `\n`, or `\r`) without trimming spaces,
/// matching Git's `setup.c` (`read_gitfile_gently` and `get_common_dir_noenv`), and rejects
/// empty or multi-line strings.
fn strip_single_git_line(text: &str) -> Option<&str> {
    let stripped = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .or_else(|| text.strip_suffix('\r'))
        .unwrap_or(text);
    if stripped.is_empty() || stripped.contains('\n') || stripped.contains('\r') {
        return None;
    }
    Some(stripped)
}

fn verify_git_worktree_backlink(root: &Path, gitdir: &Path) -> bool {
    let Ok(Some(text)) = read_small_regular_file_nofollow(gitdir, "gitdir") else {
        return false;
    };
    let Some(raw) = strip_single_git_line(&text) else {
        return false;
    };
    let candidate = gitdir.join(raw);
    if candidate.file_name() != Some(std::ffi::OsStr::new(".git")) {
        return false;
    }
    let Some(parent) = candidate.parent() else {
        return false;
    };
    let Ok(canonical_parent) = std::fs::canonicalize(parent) else {
        return false;
    };
    let dot_git = canonical_parent.join(".git");
    let Ok(meta) = std::fs::symlink_metadata(&dot_git) else {
        return false;
    };
    !meta.file_type().is_symlink() && meta.is_file() && canonical_parent == root
}

fn has_regular_git_head(dir_path: &Path) -> bool {
    let Ok(Some(head)) = read_small_regular_file_nofollow(dir_path, "HEAD") else {
        return false;
    };
    let trimmed = head.trim();
    trimmed.starts_with("ref: ")
        || ((trimmed.len() == 40 || trimmed.len() == 64)
            && trimmed.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_verified_git_common_dir(dir_path: &Path) -> bool {
    if !has_regular_git_head(dir_path) {
        return false;
    }
    let Ok(dir) = cap_std::fs::Dir::open_ambient_dir(dir_path, cap_std::ambient_authority()) else {
        return false;
    };
    for sub in ["objects", "refs"] {
        let Ok(meta) = dir.symlink_metadata(sub) else {
            return false;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return false;
        }
    }
    true
}

fn read_small_regular_file_nofollow(parent: &Path, file_name: &str) -> Result<Option<String>> {
    let dir = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    let meta = match dir.symlink_metadata(file_name) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_GIT_POINTER_BYTES {
        return Ok(None);
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = dir.open_with(file_name, &options)?;
    let mut text = String::new();
    use std::io::Read as _;
    file.take(MAX_GIT_POINTER_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_GIT_POINTER_BYTES {
        return Ok(None);
    }
    Ok(Some(text))
}

fn read_git_pointer_file_strict(parent: &Path, file_name: &str) -> Result<Option<String>> {
    let full = parent.join(file_name);
    let dir = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .with_context(|| format!("Не удалось открыть каталог {}", parent.display()))?;
    let meta = match dir.symlink_metadata(file_name) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("Не удалось проверить метаданные {}", full.display()));
        }
    };
    ensure!(
        !meta.file_type().is_symlink(),
        "Git-указатель {} не может быть симлинком",
        full.display()
    );
    ensure!(
        meta.is_file(),
        "Git-указатель {} должен быть обычным файлом",
        full.display()
    );
    ensure!(
        meta.len() <= MAX_GIT_POINTER_BYTES,
        "Git-указатель {} превышает допустимый размер ({} > {})",
        full.display(),
        meta.len(),
        MAX_GIT_POINTER_BYTES
    );
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = dir
        .open_with(file_name, &options)
        .with_context(|| format!("Не удалось открыть Git-указатель {}", full.display()))?;
    let mut text = String::new();
    use std::io::Read as _;
    file.take(MAX_GIT_POINTER_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("Некорректное UTF-8 содержимое в {}", full.display()))?;
    ensure!(
        text.len() as u64 <= MAX_GIT_POINTER_BYTES,
        "Git-указатель {} превышает допустимый размер",
        full.display()
    );
    Ok(Some(text))
}

fn parse_gitdir_file(root: &Path, dot_git: &Path) -> Result<Option<ResolvedGitTarget>> {
    let name = dot_git
        .file_name()
        .and_then(|n| n.to_str())
        .context("Имя gitfile должно быть в UTF-8")?;
    parse_gitdir_file_at(root, root, name)
}

fn parse_gitdir_file_at(
    resolve_base: &Path,
    file_dir: &Path,
    file_name: &str,
) -> Result<Option<ResolvedGitTarget>> {
    let full = file_dir.join(file_name);
    let Some(text) = read_git_pointer_file_strict(file_dir, file_name)? else {
        return Ok(None);
    };
    let line = strip_single_git_line(&text)
        .with_context(|| format!("Некорректный формат gitfile {}", full.display()))?;
    let raw = line
        .strip_prefix("gitdir: ")
        .with_context(|| format!("Отсутствует префикс 'gitdir: ' в {}", full.display()))?;
    ensure!(!raw.is_empty(), "Пустой путь gitdir в {}", full.display());
    let resolved = resolve_base.join(raw);
    let (canonical, traversed_symlinks) = resolve_path_collecting_symlinks(&resolved)
        .with_context(|| format!("Целевой gitdir worktree недоступен: {}", resolved.display()))?;
    let verified = canonical_writable_dir_verified(&canonical)?;
    Ok(Some(ResolvedGitTarget {
        dir: verified,
        traversed_symlinks,
    }))
}

fn parse_commondir_file(gitdir: &Path) -> Result<Option<ResolvedGitTarget>> {
    let Some(text) = read_git_pointer_file_strict(gitdir, "commondir")? else {
        return Ok(None);
    };
    let raw = strip_single_git_line(&text).with_context(|| {
        format!(
            "Некорректное или пустое содержимое commondir в {}",
            gitdir.display()
        )
    })?;
    let resolved = gitdir.join(raw);
    let (canonical, traversed_symlinks) = resolve_path_collecting_symlinks(&resolved)
        .with_context(|| {
            format!(
                "Целевой commondir worktree недоступен: {}",
                resolved.display()
            )
        })?;
    let verified = canonical_writable_dir_verified(&canonical)?;
    Ok(Some(ResolvedGitTarget {
        dir: verified,
        traversed_symlinks,
    }))
}

fn discover_user_toolchain_roots(
    home_dir: Option<&Path>,
    rcode_home: Option<&Path>,
) -> Vec<VerifiedDir> {
    let Some(home) = home_dir else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rel in [".rustup/toolchains", ".cargo/bin"] {
        let candidate = home.join(rel);
        let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if canonical != candidate {
            continue;
        }
        if validate_grant_against_sensitive_roots(&canonical, rcode_home, Some(home)).is_ok()
            && let Ok(verified) = canonical_writable_dir_verified(&canonical)
        {
            out.push(verified);
        }
    }
    out
}

fn check_argv(argv: &[String]) -> Result<()> {
    ensure!(
        !argv.is_empty() && !argv[0].is_empty(),
        "Не указана программа"
    );
    ensure!(argv.len() <= MAX_ARGS, "Слишком много аргументов");
    let mut bytes = 0usize;
    for arg in argv {
        ensure!(!arg.contains('\0'), "Нулевой байт в аргументе");
        bytes = bytes
            .checked_add(arg.len())
            .and_then(|n| n.checked_add(1))
            .context("Переполнение размера аргументов")?;
        ensure!(bytes <= MAX_ARG_BYTES, "Превышен размер аргументов");
    }
    Ok(())
}

fn canonical_writable_dir(path: &Path) -> Result<PathBuf> {
    Ok(canonical_writable_dir_verified(path)?.path)
}

fn canonical_writable_dir_verified(path: &Path) -> Result<VerifiedDir> {
    canonical_writable_dir_verified_with(path, || {})
}

#[cfg(all(test, unix))]
fn canonical_writable_dir_with(path: &Path, after_open: impl FnOnce()) -> Result<PathBuf> {
    Ok(canonical_writable_dir_verified_with(path, after_open)?.path)
}

fn canonical_writable_dir_verified_with(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<VerifiedDir> {
    ensure!(!path.as_os_str().is_empty(), "Пустой каталог записи");
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "Родительский компонент в каталоге записи"
    );
    let absolute = std::path::absolute(path)?;
    ensure!(
        absolute.to_str().is_some(),
        "Путь каталога должен быть в UTF-8"
    );
    let opened = crate::instructions::root_dir(&absolute)?;
    #[cfg(unix)]
    let (before_dev, before_ino) = {
        use std::os::fd::AsRawFd;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(opened.as_raw_fd(), &mut st) } != 0 {
            return Err(std::io::Error::last_os_error()).context("fstat открытого каталога");
        }
        stat_dev_ino(&st)
    };
    #[cfg(not(unix))]
    let before = opened.dir_metadata()?;

    after_open();

    // Never promote a new symlink target to an allowed root. The profile uses
    // the frozen literal, and on Linux the exact verified O_PATH descriptor
    // opened component-by-component without following symlinks.
    ensure!(
        std::fs::canonicalize(&absolute)? == absolute,
        "Каталог изменился или содержит ссылку"
    );

    #[cfg(target_os = "linux")]
    {
        drop(opened);
        let (opath_fd, st) = linux::open_canonical_opath_nofollow(&absolute, true)?;
        ensure!(
            stat_dev_ino(&st) == (before_dev, before_ino),
            "Каталог исполнения изменился"
        );
        Ok(VerifiedDir {
            path: absolute,
            dev: before_dev,
            ino: before_ino,
            opath_fd,
        })
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        drop(opened);
        let current = crate::instructions::root_dir(&absolute)?;
        use std::os::fd::AsRawFd;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(current.as_raw_fd(), &mut st) } != 0 {
            return Err(std::io::Error::last_os_error()).context("fstat проверенного каталога");
        }
        ensure!(
            stat_dev_ino(&st) == (before_dev, before_ino),
            "Каталог исполнения изменился"
        );
        Ok(VerifiedDir {
            path: absolute,
            dev: before_dev,
            ino: before_ino,
        })
    }

    #[cfg(not(unix))]
    {
        drop(opened);
        let current = crate::instructions::root_dir(&absolute)?.dir_metadata()?;
        use cap_fs_ext::MetadataExt;
        ensure!(
            before.dev() == current.dev() && before.ino() == current.ino(),
            "Каталог исполнения изменился"
        );
        Ok(VerifiedDir { path: absolute })
    }
}

fn protected_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.as_os_str().is_empty()
            && !path.components().any(|c| matches!(c, Component::ParentDir)),
        "Некорректный защищённый путь"
    );
    let absolute = std::path::absolute(path)?;
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) {
        let dir = crate::instructions::root_dir(parent)?;
        match dir.symlink_metadata(name) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink() && (meta.is_file() || meta.is_dir()),
                "Защищённый путь содержит ссылку или специальный файл"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    } else {
        crate::instructions::root_dir(&absolute)?;
    }
    ensure!(
        absolute.to_str().is_some(),
        "Защищённый путь должен быть UTF-8"
    );
    Ok(absolute)
}

#[cfg(target_os = "macos")]
fn available_macos_backend() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(SANDBOX_EXEC).context("sandbox-exec недоступен")?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "sandbox-exec не является исполняемым файлом"
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn available_macos_backend() -> Result<()> {
    bail!("Backend macOS sandbox-exec недоступен в этой ОС")
}

/// Expands macOS root symlink aliases (`/tmp` <-> `/private/tmp`, `/var` <-> `/private/var`,
/// `/etc` <-> `/private/etc`) so Seatbelt subpath/literal rules cover both spellings.
pub(crate) fn macos_alias_forms(path: &Path) -> Vec<PathBuf> {
    const PAIRS: &[(&str, &str)] = &[
        ("/tmp", "/private/tmp"),
        ("/var", "/private/var"),
        ("/etc", "/private/etc"),
    ];
    let mut out = vec![path.to_path_buf()];
    for &(short, private) in PAIRS {
        let short_p = Path::new(short);
        let private_p = Path::new(private);
        if let Ok(rest) = path.strip_prefix(private_p) {
            let alt = if rest.as_os_str().is_empty() {
                short_p.to_path_buf()
            } else {
                short_p.join(rest)
            };
            if !out.contains(&alt) {
                out.push(alt);
            }
        } else if let Ok(rest) = path.strip_prefix(short_p) {
            let alt = if rest.as_os_str().is_empty() {
                private_p.to_path_buf()
            } else {
                private_p.join(rest)
            };
            if !out.contains(&alt) {
                out.push(alt);
            }
        }
    }
    out
}

/// Write roots themselves plus intermediate ancestors strictly inside `write_roots`
/// whose `file-write-unlink` must be denied so a sandboxed child cannot rename or remove
/// a write root (`mv "$PWD" "$TMPDIR/moved"`) or an ancestor of a protected path.
fn protected_unlink_ancestors(write_roots: &[PathBuf], protected: &[PathBuf]) -> Vec<PathBuf> {
    let mut ancestors = BTreeSet::new();
    for root in write_roots {
        for root_form in macos_alias_forms(root) {
            if root_form != Path::new("/") {
                ancestors.insert(root_form.clone());
            }
            for prot in protected {
                for prot_form in macos_alias_forms(prot) {
                    if !prot_form.starts_with(&root_form) || prot_form == root_form {
                        continue;
                    }
                    let mut cur = prot_form.parent();
                    while let Some(parent) = cur {
                        if parent == root_form || !parent.starts_with(&root_form) {
                            break;
                        }
                        ancestors.insert(parent.to_path_buf());
                        cur = parent.parent();
                    }
                }
            }
        }
    }
    ancestors.into_iter().collect()
}

fn sbpl_quote(path: &Path) -> Result<String> {
    let s = path.to_str().context("Путь каталога должен быть в UTF-8")?;
    Ok(serde_json::to_string(s)?)
}

fn profile(
    roots: &[PathBuf],
    read_roots: &[PathBuf],
    protected_write: &[PathBuf],
    protected_all: &[PathBuf],
    network: bool,
) -> Result<String> {
    // Own-sandbox info/signals only; no ptrace, host-process signals, arbitrary Mach or Unix IPC.
    // No global temporary directory is added: callers supply a private job ShellTmp in roots.
    let mut text = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec)\n\
         (allow process-fork)\n\
         (allow sysctl-read)\n\
         (allow process-info* (target self))\n\
         (allow process-info* (target same-sandbox))\n\
         (allow signal (target self))\n\
         (allow signal (target same-sandbox))\n\
         (allow file-read-data file-write-data (subpath \"/dev/fd\") (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\"))\n\
         (allow file-read-metadata)\n\
         (allow file-read* (literal \"/\"))\n\
         (allow file-read* file-map-executable \
           (subpath \"/System\") \
           (subpath \"/usr/bin\") \
           (subpath \"/usr/lib\") \
           (subpath \"/usr/libexec\") \
           (subpath \"/usr/share\") \
           (subpath \"/bin\") \
           (subpath \"/sbin\") \
           (subpath \"/Library/Apple\") \
           (subpath \"/Library/Developer\") \
           (subpath \"/Applications/Xcode.app/Contents/Developer\") \
           (subpath \"/opt/homebrew/bin\") \
           (subpath \"/opt/homebrew/Cellar\") \
           (subpath \"/opt/homebrew/lib\") \
           (subpath \"/opt/homebrew/share\") \
           (subpath \"/usr/local/bin\") \
           (subpath \"/usr/local/Cellar\") \
           (subpath \"/usr/local/lib\") \
           (subpath \"/usr/local/share\") \
           (literal \"/private/etc/passwd\") \
           (literal \"/private/etc/group\") \
           (literal \"/private/etc/localtime\") \
           (literal \"/private/etc/hosts\") \
           (literal \"/private/etc/protocols\") \
           (literal \"/private/etc/services\") \
           (literal \"/private/etc/ssl/openssl.cnf\") \
           (literal \"/private/etc/ssl/cert.pem\") \
           (literal \"/private/var/run/resolv.conf\") \
           (literal \"/dev/null\") \
           (literal \"/dev/zero\") \
           (literal \"/dev/random\") \
           (literal \"/dev/urandom\"))\n",
    );
    for root in roots {
        let literal = sbpl_quote(root)?;
        text.push_str(&format!(
            "(allow file-read* file-map-executable file-write* (subpath {literal}))\n"
        ));
    }
    for root in read_roots {
        let literal = sbpl_quote(root)?;
        text.push_str(&format!(
            "(allow file-read* file-map-executable (subpath {literal}))\n"
        ));
    }
    let mut all_protected_for_ancestors =
        Vec::with_capacity(protected_write.len() + protected_all.len());
    for path in protected_write {
        all_protected_for_ancestors.push(path.clone());
        for alias in macos_alias_forms(path) {
            let literal = sbpl_quote(&alias)?;
            text.push_str(&format!(
                "(deny file-write* (subpath {literal}) (literal {literal}))\n"
            ));
        }
    }
    for path in protected_all {
        all_protected_for_ancestors.push(path.clone());
        for alias in macos_alias_forms(path) {
            let literal = sbpl_quote(&alias)?;
            text.push_str(&format!(
                "(deny file-read* file-map-executable file-write* (subpath {literal}) (literal {literal}))\n"
            ));
        }
    }
    for ancestor in protected_unlink_ancestors(roots, &all_protected_for_ancestors) {
        let literal = sbpl_quote(&ancestor)?;
        text.push_str(&format!("(deny file-write-unlink (literal {literal}))\n"));
    }
    if network {
        // Explicit IP-only network grant: keeps external AF_UNIX sockets (Docker, SSH agent, etc.) denied.
        text.push_str(
            "(allow file-read* (subpath \"/Library/Keychains\") (subpath \"/private/var/db/mds\"))\n\
             (allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))\n\
             (allow network-outbound (remote ip))\n\
             (allow network-inbound (local ip))\n\
             (allow network-bind (local ip))\n\
             (allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n\
             (allow mach-lookup \
               (global-name \"com.apple.dnssd.service\") \
               (global-name \"com.apple.TrustEvaluationAgent\") \
               (global-name \"com.apple.securityd.xpc\"))\n",
        );
    }
    ensure!(text.len() <= 64 * 1024, "Профиль sandbox превышает 64 КиБ");
    Ok(text)
}

/// Classic BPF instruction (`struct sock_filter` in Linux `<linux/filter.h>`).
#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeccompArch {
    X86_64,
    Aarch64,
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod seccomp_program {
    use super::{BpfInsn, SeccompArch};

    pub const BPF_LD_W_ABS: u16 = 0x20;
    pub const BPF_ALU_AND_K: u16 = 0x54;
    pub const BPF_JMP_JEQ_K: u16 = 0x15;
    pub const BPF_JMP_JGE_K: u16 = 0x35;
    pub const BPF_RET_K: u16 = 0x06;

    pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    // Offsets into `struct seccomp_data` (little-endian 64-bit x86_64 and aarch64).
    pub const OFF_NR: u32 = 0;
    pub const OFF_ARCH: u32 = 4;
    pub const OFF_ARG0_LO: u32 = 16;
    pub const OFF_ARG1_LO: u32 = 24;

    // Linux errno / socket ABI constants identical across x86_64 and aarch64.
    pub const LINUX_EPERM: u32 = 1;
    pub const LINUX_ENOSYS: u32 = 38;
    pub const LINUX_AF_UNIX: u32 = 1;
    pub const LINUX_AF_INET: u32 = 2;
    pub const LINUX_AF_INET6: u32 = 10;
    pub const LINUX_SOCK_STREAM: u32 = 1;
    pub const LINUX_SOCK_NONBLOCK: u32 = 0o4000;
    pub const LINUX_SOCK_CLOEXEC: u32 = 0o2000000;

    // Unified syscall numbers (>= 400, identical on x86_64 and aarch64).
    pub const SYS_IO_URING_SETUP: u32 = 425;
    pub const SYS_IO_URING_ENTER: u32 = 426;
    pub const SYS_IO_URING_REGISTER: u32 = 427;
    pub const SYS_SETXATTRAT: u32 = 463;
    pub const SYS_REMOVEXATTRAT: u32 = 466;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Label {
        Kill,
        ErrnoEnosys,
        ErrnoEperm,
        Allow,
        CheckSocketpair,
        CheckSocket,
    }

    enum Ir {
        Label(Label),
        Stmt(u16, u32),
        JumpEq {
            k: u32,
            jt: Option<Label>,
            jf: Option<Label>,
        },
        JumpGe {
            k: u32,
            jt: Option<Label>,
            jf: Option<Label>,
        },
    }

    pub fn build(arch: SeccompArch, network: bool) -> Vec<BpfInsn> {
        let (audit_arch, sys_socket, sys_socketpair, meta_eperm): (u32, u32, u32, &[u32]) =
            match arch {
                SeccompArch::X86_64 => (
                    AUDIT_ARCH_X86_64,
                    41, // SYS_socket
                    53, // SYS_socketpair
                    &[
                        92,  // chown
                        93,  // fchown
                        94,  // lchown
                        260, // fchownat
                        188, // setxattr
                        189, // lsetxattr
                        190, // fsetxattr
                        SYS_SETXATTRAT,
                        197, // removexattr
                        198, // lremovexattr
                        199, // fremovexattr
                        SYS_REMOVEXATTRAT,
                    ],
                ),
                SeccompArch::Aarch64 => (
                    AUDIT_ARCH_AARCH64,
                    198, // SYS_socket
                    199, // SYS_socketpair
                    &[
                        54, // fchownat
                        55, // fchown
                        5,  // setxattr
                        6,  // lsetxattr
                        7,  // fsetxattr
                        SYS_SETXATTRAT,
                        14, // removexattr
                        15, // lremovexattr
                        16, // fremovexattr
                        SYS_REMOVEXATTRAT,
                    ],
                ),
            };

        let mut ir = Vec::with_capacity(48);
        // 1. Validate architecture.
        ir.push(Ir::Stmt(BPF_LD_W_ABS, OFF_ARCH));
        ir.push(Ir::JumpEq {
            k: audit_arch,
            jt: None,
            jf: Some(Label::Kill),
        });

        // 2. Load syscall number and block x32 ABI on x86_64.
        ir.push(Ir::Stmt(BPF_LD_W_ABS, OFF_NR));
        if arch == SeccompArch::X86_64 {
            ir.push(Ir::JumpGe {
                k: X32_SYSCALL_BIT,
                jt: Some(Label::Kill),
                jf: None,
            });
        }

        // 3. Block io_uring_* -> ENOSYS so runtimes cleanly fall back to epoll.
        for &nr in &[
            SYS_IO_URING_SETUP,
            SYS_IO_URING_ENTER,
            SYS_IO_URING_REGISTER,
        ] {
            ir.push(Ir::JumpEq {
                k: nr,
                jt: Some(Label::ErrnoEnosys),
                jf: None,
            });
        }

        // 4. Block ownership and extended-attribute mutations -> EPERM.
        for &nr in meta_eperm {
            ir.push(Ir::JumpEq {
                k: nr,
                jt: Some(Label::ErrnoEperm),
                jf: None,
            });
        }

        // 5. Dispatch socketpair and socket; allow everything else (filtered by Landlock).
        ir.push(Ir::JumpEq {
            k: sys_socketpair,
            jt: Some(Label::CheckSocketpair),
            jf: None,
        });
        ir.push(Ir::JumpEq {
            k: sys_socket,
            jt: Some(Label::CheckSocket),
            jf: Some(Label::Allow),
        });

        // CheckSocketpair: allow ONLY AF_UNIX + SOCK_STREAM (+ optional SOCK_NONBLOCK|SOCK_CLOEXEC).
        ir.push(Ir::Label(Label::CheckSocketpair));
        ir.push(Ir::Stmt(BPF_LD_W_ABS, OFF_ARG0_LO));
        ir.push(Ir::JumpEq {
            k: LINUX_AF_UNIX,
            jt: None,
            jf: Some(Label::ErrnoEperm),
        });
        ir.push(Ir::Stmt(BPF_LD_W_ABS, OFF_ARG1_LO));
        ir.push(Ir::Stmt(
            BPF_ALU_AND_K,
            !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC),
        ));
        ir.push(Ir::JumpEq {
            k: LINUX_SOCK_STREAM,
            jt: Some(Label::Allow),
            jf: Some(Label::ErrnoEperm),
        });

        // CheckSocket: deny all when network == false; allow only AF_INET / AF_INET6 when network == true.
        ir.push(Ir::Label(Label::CheckSocket));
        if network {
            ir.push(Ir::Stmt(BPF_LD_W_ABS, OFF_ARG0_LO));
            ir.push(Ir::JumpEq {
                k: LINUX_AF_INET,
                jt: Some(Label::Allow),
                jf: None,
            });
            ir.push(Ir::JumpEq {
                k: LINUX_AF_INET6,
                jt: Some(Label::Allow),
                jf: Some(Label::ErrnoEperm),
            });
        } else {
            ir.push(Ir::Stmt(BPF_RET_K, SECCOMP_RET_ERRNO | LINUX_EPERM));
        }

        ir.push(Ir::Label(Label::Allow));
        ir.push(Ir::Stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

        ir.push(Ir::Label(Label::ErrnoEnosys));
        ir.push(Ir::Stmt(BPF_RET_K, SECCOMP_RET_ERRNO | LINUX_ENOSYS));

        ir.push(Ir::Label(Label::ErrnoEperm));
        ir.push(Ir::Stmt(BPF_RET_K, SECCOMP_RET_ERRNO | LINUX_EPERM));

        ir.push(Ir::Label(Label::Kill));
        ir.push(Ir::Stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));

        assemble(&ir)
    }

    fn assemble(ir: &[Ir]) -> Vec<BpfInsn> {
        let mut label_pos = std::collections::HashMap::new();
        let mut idx = 0usize;
        for item in ir {
            match item {
                Ir::Label(lbl) => {
                    label_pos.insert(*lbl, idx);
                }
                _ => idx += 1,
            }
        }
        let mut out = Vec::with_capacity(idx);
        for item in ir {
            let cur = out.len();
            let rel = |target: Option<Label>| -> u8 {
                match target {
                    None => 0,
                    Some(lbl) => {
                        let pos = label_pos[&lbl];
                        assert!(pos > cur, "BPF jump must be forward");
                        u8::try_from(pos - (cur + 1)).expect("BPF jump offset fits in u8")
                    }
                }
            };
            match *item {
                Ir::Label(_) => {}
                Ir::Stmt(code, k) => out.push(BpfInsn {
                    code,
                    jt: 0,
                    jf: 0,
                    k,
                }),
                Ir::JumpEq { k, jt, jf } => out.push(BpfInsn {
                    code: BPF_JMP_JEQ_K,
                    jt: rel(jt),
                    jf: rel(jf),
                    k,
                }),
                Ir::JumpGe { k, jt, jf } => out.push(BpfInsn {
                    code: BPF_JMP_JGE_K,
                    jt: rel(jt),
                    jf: rel(jf),
                    k,
                }),
            }
        }
        out
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    const SYS_CLOSE_RANGE: libc::c_long = 436;
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

    const ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const ACCESS_FS_REFER: u64 = 1 << 13;
    const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

    const ACCESS_FS_FILE_MASK: u64 = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_TRUNCATE
        | ACCESS_FS_IOCTL_DEV;

    const ACCESS_READ_EXEC_DIR: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
    const ACCESS_READ_EXEC_FILE: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE;
    const ACCESS_READ_ONLY_DIR: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
    const ACCESS_READ_ONLY_FILE: u64 = ACCESS_FS_READ_FILE;
    const ACCESS_WRITE_DIR: u64 = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_SYM
        | ACCESS_FS_REFER
        | ACCESS_FS_TRUNCATE;
    const ACCESS_DEV_RW_FILE: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE | ACCESS_FS_TRUNCATE;

    const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    const SCOPE_SIGNAL: u64 = 1 << 1;

    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_GET_ACTION_AVAIL: libc::c_uint = 2;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C, packed)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    #[repr(C)]
    struct SockFprog {
        len: libc::c_ushort,
        filter: *const BpfInsn,
    }

    const _: () = {
        assert!(std::mem::size_of::<BpfInsn>() == std::mem::size_of::<libc::sock_filter>());
        assert!(std::mem::align_of::<BpfInsn>() == std::mem::align_of::<libc::sock_filter>());
        assert!(std::mem::size_of::<LandlockPathBeneathAttr>() == 12);
    };

    pub(super) struct PreparedLinux {
        pub ruleset: OwnedFd,
        pub seccomp_filter: Vec<BpfInsn>,
        pub policy_sha256: String,
    }

    fn current_seccomp_arch() -> Result<SeccompArch> {
        #[cfg(target_arch = "x86_64")]
        {
            Ok(SeccompArch::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Ok(SeccompArch::Aarch64)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            bail!("Linux-песочница поддерживает только архитектуры x86_64 и aarch64")
        }
    }

    pub(crate) fn validate_landlock_abi(abi: i32) -> Result<i32> {
        ensure!(
            abi >= 3,
            "Ядро Linux сообщает Landlock ABI {abi}, требуется ABI >= 3 (Linux >= 6.2 с поддержкой TRUNCATE)"
        );
        Ok(abi)
    }

    fn query_landlock_abi() -> Result<i32> {
        let rc = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            bail!("Landlock LSM недоступен в ядре Linux: {err}");
        }
        validate_landlock_abi(rc as i32)
    }

    fn check_seccomp_available() -> Result<()> {
        for action in [
            seccomp_program::SECCOMP_RET_ERRNO,
            seccomp_program::SECCOMP_RET_KILL_PROCESS,
        ] {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_GET_ACTION_AVAIL,
                    0 as libc::c_uint,
                    &action as *const u32,
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                bail!("seccomp-bpf недоступен в ядре Linux: {err}");
            }
        }
        Ok(())
    }

    pub(super) fn probe_linux_support() -> BackendSupport {
        let arch_check = current_seccomp_arch();
        if let Err(err) = arch_check {
            return BackendSupport {
                available: false,
                backend: "linux_landlock_seccomp",
                landlock_abi: None,
                reason: Some(format!("{err:#}")),
                limitations: vec![],
            };
        }
        let abi = match query_landlock_abi() {
            Ok(abi) => abi,
            Err(err) => {
                return BackendSupport {
                    available: false,
                    backend: "linux_landlock_seccomp",
                    landlock_abi: None,
                    reason: Some(format!("{err:#}")),
                    limitations: vec![],
                };
            }
        };
        if let Err(err) = check_seccomp_available() {
            return BackendSupport {
                available: false,
                backend: "linux_landlock_seccomp",
                landlock_abi: Some(abi),
                reason: Some(format!("{err:#}")),
                limitations: vec![],
            };
        }
        if let Err(err) = check_sh_and_elf_interp() {
            return BackendSupport {
                available: false,
                backend: "linux_landlock_seccomp",
                landlock_abi: Some(abi),
                reason: Some(format!("{err:#}")),
                limitations: vec![],
            };
        }
        BackendSupport {
            available: true,
            backend: "linux_landlock_seccomp",
            landlock_abi: Some(abi),
            reason: None,
            limitations: vec![
                "В режиме workspace-write непривилегированный Landlock без mount namespaces не вычитает подкаталоги .git и .rcode внутри самого открытого на запись workspace (в read-only запись в них заблокирована ядром; внешние gitdir/commondir открываются только на чтение).",
                "Landlock не фильтрует по путям chmod/utimensat на файлах текущего UID (chown и xattr заблокированы seccomp-bpf).",
            ],
        }
    }

    fn check_sh_and_elf_interp() -> Result<Option<PathBuf>> {
        let sh_meta = std::fs::metadata("/bin/sh").context("/bin/sh недоступен для песочницы")?;
        ensure!(
            sh_meta.is_file() && (sh_meta.permissions().mode() & 0o111 != 0),
            "/bin/sh не является исполняемым файлом"
        );
        let bytes = read_prefix(Path::new("/bin/sh"), 64 * 1024)?;
        if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
            return Ok(None);
        }
        // ELF64 little-endian (both x86_64 and aarch64).
        if bytes[4] != 2 || bytes[5] != 1 {
            return Ok(None);
        }
        let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
        if e_phentsize < 56 || e_phnum > 128 {
            return Ok(None);
        }
        for i in 0..e_phnum {
            let Some(off) = e_phoff.checked_add(i.saturating_mul(e_phentsize)) else {
                break;
            };
            let Some(hdr) = bytes.get(off..off + 56) else {
                break;
            };
            let p_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            if p_type != 3 {
                // PT_INTERP == 3
                continue;
            }
            let p_offset = u64::from_le_bytes(hdr[8..16].try_into().unwrap()) as usize;
            let p_filesz = u64::from_le_bytes(hdr[32..40].try_into().unwrap()) as usize;
            ensure!(
                p_filesz > 1 && p_filesz <= 4096,
                "Некорректный размер ELF PT_INTERP у /bin/sh"
            );
            let interp_bytes = bytes
                .get(p_offset..p_offset + p_filesz)
                .context("ELF PT_INTERP выходит за прочитанный заголовок /bin/sh")?;
            let trimmed = interp_bytes
                .split(|&b| b == 0)
                .next()
                .unwrap_or(interp_bytes);
            let interp_str = std::str::from_utf8(trimmed)
                .context("Путь ELF-интерпретатора /bin/sh не в UTF-8")?;
            let interp_path = PathBuf::from(interp_str);
            let interp_meta = std::fs::metadata(&interp_path).with_context(|| {
                format!(
                    "Обязательный ELF-интерпретатор {} для /bin/sh недоступен",
                    interp_path.display()
                )
            })?;
            ensure!(
                interp_meta.is_file(),
                "ELF-интерпретатор {} не является обычным файлом",
                interp_path.display()
            );
            return Ok(Some(interp_path));
        }
        Ok(None)
    }

    fn read_prefix(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        use std::io::Read as _;
        let file = std::fs::File::open(path)?;
        let mut buf = Vec::new();
        file.take(max_bytes as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn create_ruleset(abi: i32) -> Result<OwnedFd> {
        let mut handled_fs = ACCESS_FS_EXECUTE
            | ACCESS_FS_WRITE_FILE
            | ACCESS_FS_READ_FILE
            | ACCESS_FS_READ_DIR
            | ACCESS_FS_REMOVE_DIR
            | ACCESS_FS_REMOVE_FILE
            | ACCESS_FS_MAKE_CHAR
            | ACCESS_FS_MAKE_DIR
            | ACCESS_FS_MAKE_REG
            | ACCESS_FS_MAKE_SOCK
            | ACCESS_FS_MAKE_FIFO
            | ACCESS_FS_MAKE_BLOCK
            | ACCESS_FS_MAKE_SYM
            | ACCESS_FS_REFER
            | ACCESS_FS_TRUNCATE;
        if abi >= 5 {
            handled_fs |= ACCESS_FS_IOCTL_DEV;
        }
        let scoped = if abi >= 6 {
            SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
        } else {
            0
        };
        let attr = LandlockRulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: 0,
            scoped,
        };
        let attr_size = if abi >= 6 {
            std::mem::size_of::<LandlockRulesetAttr>()
        } else if abi >= 4 {
            2 * std::mem::size_of::<u64>()
        } else {
            std::mem::size_of::<u64>()
        };
        let fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const LandlockRulesetAttr,
                attr_size,
                0u32,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            bail!("Не удалось создать ruleset Landlock (ABI {abi}): {err}");
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    fn add_rule_fd(
        ruleset: &OwnedFd,
        target_fd: RawFd,
        is_dir: bool,
        dir_access: u64,
        file_access: u64,
    ) -> Result<()> {
        let allowed_access = if is_dir {
            dir_access
        } else {
            file_access & ACCESS_FS_FILE_MASK
        };
        if allowed_access == 0 {
            return Ok(());
        }
        let attr = LandlockPathBeneathAttr {
            allowed_access,
            parent_fd: target_fd,
        };
        let rc = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            bail!("Не удалось добавить правило Landlock: {err}");
        }
        Ok(())
    }

    pub(super) fn open_canonical_opath_nofollow(
        canonical: &Path,
        require_dir: bool,
    ) -> std::io::Result<(OwnedFd, libc::stat)> {
        if !canonical.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "canonical path must be absolute",
            ));
        }
        let mut comps = Vec::new();
        for comp in canonical.components() {
            match comp {
                Component::RootDir => {}
                Component::Normal(name) => comps.push(name),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "non-canonical path component",
                    ));
                }
            }
        }
        let root_raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut cur_fd = unsafe { OwnedFd::from_raw_fd(root_raw) };
        if comps.is_empty() {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(cur_fd.as_raw_fd(), &mut st) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            return Ok((cur_fd, st));
        }
        for (idx, comp) in comps.iter().enumerate() {
            let is_last = idx + 1 == comps.len();
            let mut flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            if !is_last || require_dir {
                flags |= libc::O_DIRECTORY;
            }
            let c_comp = CString::new(comp.as_bytes()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component")
            })?;
            let next_raw = unsafe { libc::openat(cur_fd.as_raw_fd(), c_comp.as_ptr(), flags) };
            if next_raw < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let next_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(next_fd.as_raw_fd(), &mut st) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mode_type = st.st_mode & libc::S_IFMT;
            if mode_type == libc::S_IFLNK
                || ((!is_last || require_dir) && mode_type != libc::S_IFDIR)
            {
                return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
            }
            if is_last {
                return Ok((next_fd, st));
            }
            cur_fd = next_fd;
        }
        unreachable!()
    }

    pub(super) fn verify_shell_tmp_opath(shell_tmp: &ShellTmp) -> Result<VerifiedDir> {
        let (opath_fd, st) =
            open_canonical_opath_nofollow(shell_tmp.path(), true).with_context(|| {
                format!(
                    "Не удалось открыть O_PATH для {}",
                    shell_tmp.path().display()
                )
            })?;
        let euid = unsafe { libc::geteuid() };
        ensure!(
            super::stat_dev_ino(&st) == (shell_tmp.dev, shell_tmp.ino) && st.st_uid == euid,
            "Идентичность TMPDIR {} изменилась во время подготовки Landlock",
            shell_tmp.path().display()
        );
        Ok(VerifiedDir {
            path: shell_tmp.path().to_path_buf(),
            dev: shell_tmp.dev,
            ino: shell_tmp.ino,
            opath_fd,
        })
    }

    fn add_system_path_optional(
        ruleset: &OwnedFd,
        path: &Path,
        dir_access: u64,
        file_access: u64,
        rcode_home: Option<&Path>,
        home_dir: Option<&Path>,
        recorded: &mut Vec<String>,
    ) -> Result<()> {
        add_system_path_split(
            ruleset,
            path,
            dir_access,
            file_access,
            rcode_home,
            home_dir,
            0,
            recorded,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_system_path_split(
        ruleset: &OwnedFd,
        path: &Path,
        dir_access: u64,
        file_access: u64,
        rcode_home: Option<&Path>,
        home_dir: Option<&Path>,
        depth: usize,
        recorded: &mut Vec<String>,
    ) -> Result<()> {
        let canonical = match std::fs::canonicalize(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "Не удалось проверить системный путь {} для Landlock",
                        path.display()
                    )
                });
            }
        };

        let contains_rc = rcode_home.is_some_and(|rc| rc.starts_with(&canonical));
        let contains_home = home_dir.is_some_and(|h| h.starts_with(&canonical));
        let inside_rc = rcode_home.is_some_and(|rc| canonical.starts_with(rc));
        if inside_rc
            || rcode_home == Some(canonical.as_path())
            || home_dir == Some(canonical.as_path())
        {
            bail!(
                "Системный путь {} совпадает с RCODE_HOME/$HOME или лежит внутри RCODE_HOME",
                canonical.display()
            );
        }

        if contains_rc || contains_home {
            ensure!(
                depth < 4,
                "Не удалось безопасно отделить системный каталог {} от RCODE_HOME/$HOME",
                canonical.display()
            );
            let entries = std::fs::read_dir(&canonical).with_context(|| {
                format!(
                    "Не удалось перечислить {} для изоляции RCODE_HOME/$HOME",
                    canonical.display()
                )
            })?;
            for entry in entries {
                let entry = entry?;
                let child = entry.path();
                let child_canon = match std::fs::canonicalize(&child) {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                if rcode_home.is_some_and(|rc| child_canon == rc || child_canon.starts_with(rc))
                    || home_dir.is_some_and(|h| child_canon == h)
                {
                    continue;
                }
                add_system_path_split(
                    ruleset,
                    &child_canon,
                    dir_access,
                    file_access,
                    rcode_home,
                    home_dir,
                    depth + 1,
                    recorded,
                )?;
            }
            return Ok(());
        }

        let (fd, st) = match open_canonical_opath_nofollow(&canonical, false) {
            Ok(pair) => pair,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "Не удалось покомпонентно открыть O_PATH|O_NOFOLLOW для {}",
                        canonical.display()
                    )
                });
            }
        };
        let mode_type = st.st_mode & libc::S_IFMT;
        let is_dir = mode_type == libc::S_IFDIR;
        let is_regular_or_char = mode_type == libc::S_IFREG || mode_type == libc::S_IFCHR;
        ensure!(
            is_dir || is_regular_or_char,
            "Неожиданный тип системного файла {} для Landlock",
            canonical.display()
        );
        add_rule_fd(ruleset, fd.as_raw_fd(), is_dir, dir_access, file_access)?;
        recorded.push(format!(
            "{}:{:x}",
            canonical.to_string_lossy(),
            if is_dir { dir_access } else { file_access }
        ));
        Ok(())
    }

    pub(super) fn prepare_linux_sandbox(
        policy: EffectiveSandboxPolicy,
        project_roots: &[VerifiedDir],
        git_read_roots: &[VerifiedDir],
        toolchain_reads: &[VerifiedDir],
        shell_tmp: &VerifiedDir,
        rcode_home: Option<&Path>,
        home_dir: Option<&Path>,
    ) -> Result<PreparedLinux> {
        let arch = current_seccomp_arch()?;
        let abi = query_landlock_abi()?;
        check_seccomp_available()?;
        let sh_interp = check_sh_and_elf_interp()?;

        let ruleset = create_ruleset(abi)?;
        let mut recorded = Vec::new();
        recorded.push(format!(
            "abi={abi};mode={};net={}",
            policy.mode.as_str(),
            policy.network
        ));

        // Mandatory /bin/sh and optional PT_INTERP.
        let sh_canon = std::fs::canonicalize("/bin/sh").context("/bin/sh недоступен")?;
        add_system_path_optional(
            &ruleset,
            &sh_canon,
            ACCESS_READ_EXEC_DIR,
            ACCESS_READ_EXEC_FILE,
            rcode_home,
            home_dir,
            &mut recorded,
        )?;
        if let Some(interp) = sh_interp {
            add_system_path_optional(
                &ruleset,
                &interp,
                ACCESS_READ_EXEC_DIR,
                ACCESS_READ_EXEC_FILE,
                rcode_home,
                home_dir,
                &mut recorded,
            )?;
        }

        // System executable/library hierarchies (missing paths such as /lib64 on Debian arm64 are skipped).
        for sys_dir in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/opt"] {
            add_system_path_optional(
                &ruleset,
                Path::new(sys_dir),
                ACCESS_READ_EXEC_DIR,
                ACCESS_READ_EXEC_FILE,
                rcode_home,
                home_dir,
                &mut recorded,
            )?;
        }

        // Narrow /etc configuration files & TLS trust stores.
        for etc_entry in [
            "/etc/passwd",
            "/etc/group",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/localtime",
            "/etc/ssl",
            "/etc/ca-certificates",
            "/etc/ca-certificates.conf",
            "/etc/pki",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/alternatives",
        ] {
            add_system_path_optional(
                &ruleset,
                Path::new(etc_entry),
                ACCESS_READ_EXEC_DIR,
                ACCESS_READ_ONLY_FILE,
                rcode_home,
                home_dir,
                &mut recorded,
            )?;
        }

        // Read-only /proc and /sys for standard runtime introspection (Python, Node, Rust).
        for ro_fs in ["/proc", "/sys"] {
            add_system_path_optional(
                &ruleset,
                Path::new(ro_fs),
                ACCESS_READ_ONLY_DIR,
                ACCESS_READ_ONLY_FILE,
                rcode_home,
                home_dir,
                &mut recorded,
            )?;
        }

        // Safe character devices only (never /dev, /dev/tty, or /dev/pts).
        for dev_node in [
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/urandom",
            "/dev/random",
        ] {
            add_system_path_optional(
                &ruleset,
                Path::new(dev_node),
                0,
                ACCESS_DEV_RW_FILE,
                rcode_home,
                home_dir,
                &mut recorded,
            )?;
        }

        // User toolchain read-only directories (verified O_PATH descriptors retained since inspection).
        for tc in toolchain_reads {
            add_rule_fd(
                &ruleset,
                tc.opath_fd.as_raw_fd(),
                true,
                ACCESS_READ_EXEC_DIR,
                0,
            )?;
            recorded.push(format!("tc:{}", tc.path.to_string_lossy()));
        }

        // External gitdir / commondir read-only roots (verified O_PATH descriptors).
        for git_root in git_read_roots {
            add_rule_fd(
                &ruleset,
                git_root.opath_fd.as_raw_fd(),
                true,
                ACCESS_READ_ONLY_DIR,
                0,
            )?;
            recorded.push(format!("git_ro:{}", git_root.path.to_string_lossy()));
        }

        // Private per-job ShellTmp (writable in both WorkspaceWrite and ReadOnly).
        add_rule_fd(
            &ruleset,
            shell_tmp.opath_fd.as_raw_fd(),
            true,
            ACCESS_WRITE_DIR,
            0,
        )?;
        recorded.push(format!("tmp:{}", shell_tmp.path.to_string_lossy()));

        // Project roots (writable in WorkspaceWrite, read+exec in ReadOnly).
        let root_access = match policy.mode {
            SandboxMode::WorkspaceWrite => ACCESS_WRITE_DIR,
            SandboxMode::ReadOnly => ACCESS_READ_EXEC_DIR,
            SandboxMode::Off => unreachable!(),
        };
        for root in project_roots {
            add_rule_fd(&ruleset, root.opath_fd.as_raw_fd(), true, root_access, 0)?;
            recorded.push(format!(
                "root:{}:{root_access:x}",
                root.path.to_string_lossy()
            ));
        }

        let seccomp_filter = seccomp_program::build(arch, policy.network);
        let mut policy_bytes = Vec::new();
        for item in &recorded {
            policy_bytes.extend_from_slice(item.as_bytes());
            policy_bytes.push(b'\n');
        }
        for insn in &seccomp_filter {
            policy_bytes.extend_from_slice(&insn.code.to_le_bytes());
            policy_bytes.extend_from_slice(&[insn.jt, insn.jf]);
            policy_bytes.extend_from_slice(&insn.k.to_le_bytes());
        }
        let policy_sha256 = super::hex_sha256(&policy_bytes);

        Ok(PreparedLinux {
            ruleset,
            seccomp_filter,
            policy_sha256,
        })
    }

    /// Async-signal-safe `pre_exec` step: zero heap allocations, locks, or formatting.
    pub(super) unsafe fn apply_in_pre_exec(
        ruleset_fd: RawFd,
        seccomp_filter: &[BpfInsn],
    ) -> std::io::Result<()> {
        if unsafe {
            libc::syscall(
                SYS_CLOSE_RANGE,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let prog = SockFprog {
            len: seccomp_filter.len() as libc::c_ushort,
            filter: seccomp_filter.as_ptr(),
        };
        if unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0 as libc::c_uint,
                &prog as *const SockFprog,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        (temp, path)
    }

    fn eval_bpf(prog: &[BpfInsn], nr: u32, arch: u32, arg0: u32, arg1: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        while pc < prog.len() {
            let insn = prog[pc];
            match insn.code {
                seccomp_program::BPF_LD_W_ABS => {
                    acc = match insn.k {
                        seccomp_program::OFF_NR => nr,
                        seccomp_program::OFF_ARCH => arch,
                        seccomp_program::OFF_ARG0_LO => arg0,
                        seccomp_program::OFF_ARG1_LO => arg1,
                        other => panic!("unexpected BPF offset {other}"),
                    };
                    pc += 1;
                }
                seccomp_program::BPF_ALU_AND_K => {
                    acc &= insn.k;
                    pc += 1;
                }
                seccomp_program::BPF_JMP_JEQ_K => {
                    let jump = if acc == insn.k { insn.jt } else { insn.jf };
                    pc = pc + 1 + (jump as usize);
                }
                seccomp_program::BPF_JMP_JGE_K => {
                    let jump = if acc >= insn.k { insn.jt } else { insn.jf };
                    pc = pc + 1 + (jump as usize);
                }
                seccomp_program::BPF_RET_K => return insn.k,
                other => panic!("unexpected BPF opcode {other:#x}"),
            }
        }
        panic!("BPF fell off end without RET")
    }

    #[test]
    fn defaults_and_off_argv_unchanged() {
        let (_temp, root) = workspace();
        let config: SandboxConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.backend, SandboxBackend::Off);
        assert!(!config.network);
        assert!(config.write_roots.is_empty());
        let argv = vec![
            "sh".into(),
            "-c".into(),
            "echo '); (allow network*)'".into(),
            "".into(),
        ];
        assert_eq!(config.wrap(&root, &argv).unwrap(), argv);
        assert!(config.wrap(&root, &[]).is_err());
        assert!(config.wrap(&root, &["x\0y".into()]).is_err());
        assert!(config.wrap(&root, &["x".repeat(MAX_ARG_BYTES)]).is_err());
        assert!(config.wrap(&root, &vec!["x".into(); MAX_ARGS + 1]).is_err());
    }

    #[test]
    fn invalid_roots_and_versions() {
        let (temp, root) = workspace();
        let mut config = SandboxConfig {
            version: 2,
            ..Default::default()
        };
        assert!(config.validate(&root).is_err());
        config.version = 1;
        config.write_roots = vec![root.clone(); 9];
        assert!(config.validate(&root).is_err());
        config.write_roots = vec![root.join("missing")];
        assert!(config.validate(&root).is_err());
        let file = root.join("file");
        std::fs::write(&file, b"test").unwrap();
        config.write_roots = vec![file];
        assert!(config.validate(&root).is_err());
        config.write_roots.clear();
        assert!(config.validate(&temp.path().join("..")).is_err());
        assert!(config.validate(Path::new("")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_ancestors_rejected() {
        let (_temp, root) = workspace();
        let target = root.join("target");
        std::fs::create_dir_all(target.join("child")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            SandboxConfig::default()
                .validate(&link.join("child"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_paths_are_json_quoted_and_network_is_narrowed_to_ip() {
        let (_temp, root) = workspace();
        let unusual = root.join("quote\" slash\\ newline\n); (allow network*)");
        std::fs::create_dir(&unusual).unwrap();
        let canonical = canonical_writable_dir(&unusual).unwrap();
        let literal = serde_json::to_string(canonical.to_str().unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<String>(&literal).unwrap(),
            canonical.to_str().unwrap()
        );
        let text = profile(&[canonical], &[], &[], &[], false).unwrap();
        assert!(text.contains(&format!("(subpath {literal})")));
        assert!(!text.contains("\n); (allow network*)"));
        assert!(!text.contains("(allow network-outbound (remote ip))"));
        assert!(text.starts_with("(version 1)\n(deny default)\n"));

        let with_net = profile(&[], &[], &[], &[], true).unwrap();
        assert!(!with_net.contains("(allow network*)"));
        assert!(with_net.contains("(allow network-outbound (remote ip))"));
        assert!(with_net.contains(
            "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn changed_directory_is_not_promoted_to_an_external_root() {
        let (_temp, root) = workspace();
        let allowed = root.join("build");
        let old = root.join("old-build");
        let private = root.join("private");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&private).unwrap();
        let result = canonical_writable_dir_with(&allowed, || {
            std::fs::rename(&allowed, &old).unwrap();
            std::os::unix::fs::symlink(&private, &allowed).unwrap();
        });
        assert!(result.is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unavailable_backend_fails_closed() {
        let (_temp, root) = workspace();
        let config = SandboxConfig {
            backend: SandboxBackend::Macos,
            ..Default::default()
        };
        assert!(config.validate(&root).is_err());
        assert!(
            config
                .wrap(&root, &["definitely-not-a-command".into()])
                .is_err()
        );
    }

    #[test]
    fn effective_policy_resolution_and_authority_rules() {
        use crate::cli::Toggle;
        let saved = ProjectSandbox {
            mode: SandboxMode::WorkspaceWrite,
            network: true,
        };
        assert_eq!(
            EffectiveSandboxPolicy::resolve(saved, None, None).unwrap(),
            EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: true
            }
        );
        assert_eq!(
            EffectiveSandboxPolicy::resolve(saved, None, Some(Toggle::Off)).unwrap(),
            EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: false
            }
        );
        assert_eq!(
            EffectiveSandboxPolicy::resolve(saved, Some(SandboxMode::Off), None).unwrap(),
            EffectiveSandboxPolicy::off()
        );
        assert!(
            EffectiveSandboxPolicy::resolve(ProjectSandbox::default(), None, Some(Toggle::On))
                .is_err()
        );
        assert_eq!(
            ExecutionAuthority::OperatorBang.policy(),
            EffectiveSandboxPolicy::off()
        );
        assert_eq!(
            ExecutionAuthority::ModelTool(EffectiveSandboxPolicy {
                mode: SandboxMode::ReadOnly,
                network: false,
            })
            .policy()
            .mode,
            SandboxMode::ReadOnly
        );
    }

    #[test]
    fn macos_aliases_and_ancestor_unlink_protection() {
        let forms = macos_alias_forms(Path::new("/private/tmp/work/sub/.git"));
        assert!(forms.contains(&PathBuf::from("/private/tmp/work/sub/.git")));
        assert!(forms.contains(&PathBuf::from("/tmp/work/sub/.git")));

        let ancestors = protected_unlink_ancestors(
            &[PathBuf::from("/private/tmp/work")],
            &[PathBuf::from("/private/tmp/work/nested/deep/.git")],
        );
        assert!(ancestors.contains(&PathBuf::from("/private/tmp/work/nested")));
        assert!(ancestors.contains(&PathBuf::from("/private/tmp/work/nested/deep")));
        assert!(ancestors.contains(&PathBuf::from("/tmp/work/nested")));
        // Write roots themselves (in all macOS alias forms) are unlink-protected so
        // `mv "$PWD" "$TMPDIR/moved"` cannot relocate `.git`/`.rcode` out of Seatbelt deny literals.
        assert!(ancestors.contains(&PathBuf::from("/private/tmp/work")));
        assert!(ancestors.contains(&PathBuf::from("/tmp/work")));
    }

    #[cfg(unix)]
    #[test]
    fn shell_tmp_lifecycle_preserves_spawned_unknown_and_cleans_chmod_zero_trees() {
        use std::os::unix::fs::PermissionsExt;

        // 1. Unspawned `ShellTmp` cleans up automatically on Drop.
        let unspawned_path = {
            let tmp = ShellTmp::create(None, None, &[]).unwrap();
            let p = tmp.path().to_path_buf();
            std::fs::write(p.join("scratch.txt"), "data").unwrap();
            p
        };
        assert!(!unspawned_path.exists());

        // 2. Spawned `ShellTmp` MUST NOT delete directory on Drop when `cleanup_confirmed`
        //    was not called (e.g. `JobStatus::Unknown` / unconfirmed descendant).
        let mut spawned = ShellTmp::create(None, None, &[]).unwrap();
        let spawned_path = spawned.path().to_path_buf();
        std::fs::write(spawned_path.join("live.txt"), "still_running").unwrap();
        spawned.mark_spawned();
        drop(spawned);
        assert!(spawned_path.exists());
        std::fs::remove_dir_all(&spawned_path).unwrap();

        // 3. `cleanup_confirmed()` restores permissions (`0000` root + `0000` nested subdir + `0400` file)
        //    without following symlinks and confirms absence.
        let mut locked = ShellTmp::create(None, None, &[]).unwrap();
        let locked_path = locked.path().to_path_buf();
        locked.mark_spawned();
        let nested = locked_path.join("sub/deep");
        std::fs::create_dir_all(&nested).unwrap();
        let ro_file = nested.join("readonly.txt");
        std::fs::write(&ro_file, "ro").unwrap();
        std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(
            locked_path.join("sub"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::fs::set_permissions(&locked_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        locked.cleanup_confirmed().unwrap();
        assert!(!locked_path.exists());

        // 4. Sensitive TMPDIR (`$HOME/.ssh`) is rejected BEFORE creating any `rcode-job-*` directory.
        let (_home_guard, fake_home) = workspace();
        let ssh_dir = fake_home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        assert!(ShellTmp::create_in(&ssh_dir, None, Some(&fake_home), &[]).is_err());
        assert_eq!(std::fs::read_dir(&ssh_dir).unwrap().count(), 0);
    }

    #[test]
    fn sensitive_root_overlap_checks_reject_rcode_home_and_home_root() {
        let rc = Path::new("/private/tmp/rcode-state");
        let home = Path::new("/Users/alice");
        assert!(validate_grant_against_sensitive_roots(rc, Some(rc), Some(home)).is_err());
        assert!(
            validate_grant_against_sensitive_roots(
                Path::new("/tmp/rcode-state/sub"),
                Some(rc),
                Some(home)
            )
            .is_err()
        );
        assert!(
            validate_grant_against_sensitive_roots(Path::new("/private/tmp"), Some(rc), Some(home))
                .is_err()
        );
        assert!(validate_grant_against_sensitive_roots(home, Some(rc), Some(home)).is_err());
        assert!(
            validate_grant_against_sensitive_roots(Path::new("/Users"), Some(rc), Some(home))
                .is_err()
        );
        assert!(
            validate_grant_against_sensitive_roots(
                Path::new("/Users/alice/.ssh"),
                Some(rc),
                Some(home)
            )
            .is_err()
        );
        assert!(
            validate_grant_against_sensitive_roots(
                Path::new("/Users/alice/work/project"),
                Some(rc),
                Some(home)
            )
            .is_ok()
        );
    }

    #[test]
    fn seccomp_bpf_enforces_arch_x32_io_uring_xattr_chown_socketpair_and_socket() {
        use seccomp_program::*;

        for (arch, audit, other_audit, sys_sock, sys_pair, eperm_nrs) in [
            (
                SeccompArch::X86_64,
                AUDIT_ARCH_X86_64,
                AUDIT_ARCH_AARCH64,
                41u32,
                53u32,
                &[92u32, 93, 94, 260, 188, 189, 190, 463, 197, 198, 199, 466][..],
            ),
            (
                SeccompArch::Aarch64,
                AUDIT_ARCH_AARCH64,
                AUDIT_ARCH_X86_64,
                198u32,
                199u32,
                &[54u32, 55, 5, 6, 7, 463, 14, 15, 16, 466][..],
            ),
        ] {
            let no_net = build(arch, false);
            let with_net = build(arch, true);

            // Wrong arch -> KILL.
            assert_eq!(
                eval_bpf(&no_net, 0, other_audit, 0, 0),
                SECCOMP_RET_KILL_PROCESS
            );
            if arch == SeccompArch::X86_64 {
                assert_eq!(
                    eval_bpf(&no_net, X32_SYSCALL_BIT | 41, audit, 2, 1),
                    SECCOMP_RET_KILL_PROCESS
                );
            }

            // io_uring -> ENOSYS.
            for nr in [
                SYS_IO_URING_SETUP,
                SYS_IO_URING_ENTER,
                SYS_IO_URING_REGISTER,
            ] {
                assert_eq!(
                    eval_bpf(&no_net, nr, audit, 0, 0),
                    SECCOMP_RET_ERRNO | LINUX_ENOSYS
                );
                assert_eq!(
                    eval_bpf(&with_net, nr, audit, 0, 0),
                    SECCOMP_RET_ERRNO | LINUX_ENOSYS
                );
            }

            // chown / setxattr / setxattrat / removexattr / removexattrat -> EPERM.
            for &nr in eperm_nrs {
                assert_eq!(
                    eval_bpf(&no_net, nr, audit, 0, 0),
                    SECCOMP_RET_ERRNO | LINUX_EPERM,
                    "arch={arch:?} nr={nr}"
                );
            }

            // socketpair: ONLY AF_UNIX + SOCK_STREAM (+ optional NONBLOCK/CLOEXEC).
            assert_eq!(
                eval_bpf(&no_net, sys_pair, audit, LINUX_AF_UNIX, LINUX_SOCK_STREAM),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                eval_bpf(
                    &no_net,
                    sys_pair,
                    audit,
                    LINUX_AF_UNIX,
                    LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK
                ),
                SECCOMP_RET_ALLOW
            );
            // SOCK_DGRAM == 2, SOCK_SEQPACKET == 5 -> EPERM!
            for bad_type in [2u32, 5u32, LINUX_SOCK_STREAM | 0x4000_0000] {
                assert_eq!(
                    eval_bpf(&no_net, sys_pair, audit, LINUX_AF_UNIX, bad_type),
                    SECCOMP_RET_ERRNO | LINUX_EPERM
                );
                assert_eq!(
                    eval_bpf(&with_net, sys_pair, audit, LINUX_AF_UNIX, bad_type),
                    SECCOMP_RET_ERRNO | LINUX_EPERM
                );
            }
            assert_eq!(
                eval_bpf(&with_net, sys_pair, audit, LINUX_AF_INET, LINUX_SOCK_STREAM),
                SECCOMP_RET_ERRNO | LINUX_EPERM
            );

            // socket: all denied when network=false; ONLY AF_INET/AF_INET6 when network=true (AF_UNIX still denied!).
            for dom in [LINUX_AF_UNIX, LINUX_AF_INET, LINUX_AF_INET6, 16] {
                assert_eq!(
                    eval_bpf(&no_net, sys_sock, audit, dom, LINUX_SOCK_STREAM),
                    SECCOMP_RET_ERRNO | LINUX_EPERM
                );
            }
            assert_eq!(
                eval_bpf(&with_net, sys_sock, audit, LINUX_AF_INET, LINUX_SOCK_STREAM),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                eval_bpf(
                    &with_net,
                    sys_sock,
                    audit,
                    LINUX_AF_INET6,
                    LINUX_SOCK_STREAM
                ),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                eval_bpf(&with_net, sys_sock, audit, LINUX_AF_UNIX, LINUX_SOCK_STREAM),
                SECCOMP_RET_ERRNO | LINUX_EPERM
            );

            // Ordinary syscalls (read/write/openat/execve) -> ALLOW.
            assert_eq!(eval_bpf(&no_net, 63, audit, 0, 0), SECCOMP_RET_ALLOW);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_abi_below_three_is_rejected() {
        assert!(linux::validate_landlock_abi(1).is_err());
        assert!(linux::validate_landlock_abi(2).is_err());
        assert_eq!(linux::validate_landlock_abi(3).unwrap(), 3);
        assert_eq!(linux::validate_landlock_abi(6).unwrap(), 6);
    }
}
