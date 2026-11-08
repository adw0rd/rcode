//! Optional command wrapping only: environment scrubbing and broker policy belong
//! to the caller. macOS permits reads only in execution roots and system runtime paths.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

const MAX_ARGS: usize = 256;
const MAX_ARG_BYTES: usize = 128 * 1024;
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    #[default]
    Off,
    Macos,
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
        if self.backend == SandboxBackend::Off {
            return Ok(argv.to_vec());
        }
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
            profile(&roots, &read_roots, &protected, self.network)?,
            "--".into(),
        ];
        wrapped.extend_from_slice(argv);
        Ok(wrapped)
    }

    pub fn description(&self) -> &'static str {
        match self.backend {
            SandboxBackend::Off => "Off: shell с правами пользователя, включая доступ к сети.",
            SandboxBackend::Macos => {
                "macOS Seatbelt: чтение проекта и системных runtime, запись только в проект и явно заданные каталоги; сеть по явному выбору оператора. Очисткой env и разрешениями управляет host."
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
        if self.backend == SandboxBackend::Macos {
            available_backend()?;
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
    canonical_writable_dir_with(path, || {})
}

fn canonical_writable_dir_with(path: &Path, after_open: impl FnOnce()) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "Пустой каталог записи");
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "Родительский компонент в каталоге записи"
    );
    let absolute = std::path::absolute(path)?;
    let opened = crate::instructions::root_dir(&absolute)?;
    let before = opened.dir_metadata()?;
    after_open();
    // Never promote a new symlink target to an allowed root. The profile uses
    // the frozen literal, not the result of following a changed pathname.
    ensure!(
        std::fs::canonicalize(&absolute)? == absolute,
        "Каталог изменился или содержит ссылку"
    );
    let current = crate::instructions::root_dir(&absolute)?.dir_metadata()?;
    use cap_fs_ext::MetadataExt;
    ensure!(
        before.dev() == current.dev() && before.ino() == current.ino(),
        "Каталог исполнения изменился"
    );
    ensure!(
        absolute.to_str().is_some(),
        "Путь каталога должен быть в UTF-8"
    );
    Ok(absolute)
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
fn available_backend() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(SANDBOX_EXEC).context("sandbox-exec недоступен")?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "sandbox-exec не является исполняемым файлом"
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn available_backend() -> Result<()> {
    anyhow::bail!("Backend macOS sandbox-exec недоступен в этой ОС")
}

fn profile(
    roots: &[PathBuf],
    read_roots: &[PathBuf],
    protected: &[PathBuf],
    network: bool,
) -> Result<String> {
    // Own-process info/signals only; no ptrace, other-process signals, Mach or Unix IPC.
    // No global temporary directory is added: callers must explicitly supply a
    // private temporary directory in write_roots and configure the child's env.
    let mut text = String::from(
        "(version 1)\n(deny default)\n(allow process-exec)\n(allow process-fork)\n(allow sysctl-read)\n(allow process-info* (target self))\n(allow signal (target self))\n(allow file-read-data file-write-data (subpath \"/dev/fd\") (literal \"/dev/null\"))\n(allow file-read-metadata)\n(allow file-read* (literal \"/\"))\n(allow file-read* file-map-executable (subpath \"/System\") (subpath \"/usr/bin\") (subpath \"/usr/lib\") (subpath \"/usr/libexec\") (subpath \"/usr/share\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Library/Apple\") (subpath \"/opt/homebrew/bin\") (subpath \"/opt/homebrew/Cellar\") (subpath \"/opt/homebrew/lib\") (subpath \"/opt/homebrew/share\") (subpath \"/usr/local/bin\") (subpath \"/usr/local/Cellar\") (subpath \"/usr/local/lib\") (subpath \"/usr/local/share\") (literal \"/private/etc/passwd\") (literal \"/private/etc/hosts\") (literal \"/private/etc/protocols\") (literal \"/private/etc/services\") (literal \"/private/etc/ssl/openssl.cnf\") (literal \"/private/etc/ssl/cert.pem\") (literal \"/private/var/run/resolv.conf\") (literal \"/dev/null\") (literal \"/dev/random\") (literal \"/dev/urandom\"))\n",
    );
    for root in roots {
        let literal =
            serde_json::to_string(root.to_str().context("Путь каталога должен быть в UTF-8")?)?;
        text.push_str(&format!(
            "(allow file-read* file-map-executable file-write* (subpath {literal}))\n"
        ));
    }
    for root in read_roots {
        let literal =
            serde_json::to_string(root.to_str().context("Путь чтения должен быть UTF-8")?)?;
        text.push_str(&format!(
            "(allow file-read* file-map-executable (subpath {literal}))\n"
        ));
    }
    for path in protected {
        let literal =
            serde_json::to_string(path.to_str().context("Защищённый путь должен быть UTF-8")?)?;
        text.push_str(&format!(
            "(deny file-read* file-map-executable file-write* (subpath {literal}))\n"
        ));
    }
    ensure!(text.len() <= 64 * 1024, "Профиль sandbox превышает 64 КиБ");
    if network {
        // This broad grant is an explicit operator choice, never a fallback.
        text.push_str("(allow network*)\n");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        (temp, path)
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
    fn canonical_paths_are_json_quoted() {
        let (_temp, root) = workspace();
        let unusual = root.join("quote\" slash\\ newline\n); (allow network*)");
        std::fs::create_dir(&unusual).unwrap();
        let canonical = canonical_writable_dir(&unusual).unwrap();
        let literal = serde_json::to_string(canonical.to_str().unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<String>(&literal).unwrap(),
            canonical.to_str().unwrap()
        );
        let text = profile(&[canonical], &[], &[], false).unwrap();
        assert!(text.contains(&format!("(subpath {literal})")));
        assert!(!text.lines().any(|line| line == "(allow network*)"));
        assert!(text.starts_with("(version 1)\n(deny default)\n"));
        assert!(
            profile(&[], &[], &[], true)
                .unwrap()
                .ends_with("(allow network*)\n")
        );
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
}
