use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const MANIFEST_VERSION: u32 = 1;

/// `RCODE_HOME/skills.json`: installed skill sources and catalog settings.
/// Kept out of `config.json` so older rcode versions never overwrite it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Manifest {
    version: u32,
    #[serde(default)]
    sources: BTreeMap<String, SourceRecord>,
    #[serde(default)]
    disabled: BTreeSet<String>,
    #[serde(default)]
    project_roots: Vec<PathBuf>,
    #[serde(default)]
    linked: BTreeMap<String, LinkedRoot>,
    #[serde(default)]
    catalog: CatalogOverrides,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceRecord {
    pub(crate) kind: String,
    pub(crate) url: String,
    #[serde(rename = "ref")]
    pub(crate) reference: Option<String>,
    pub(crate) commit: String,
    pub(crate) skills_root: String,
    pub(crate) tree_sha256: String,
    pub(crate) package_version: Option<String>,
    pub(crate) installed_at: u64,
    pub(crate) updated_at: u64,
    #[serde(default)]
    pub(crate) only: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LinkedRoot {
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct CatalogOverrides {
    pub(crate) description_chars: Option<usize>,
    pub(crate) cloud_chars: Option<usize>,
    pub(crate) local_share_percent: Option<usize>,
}

impl Manifest {
    pub(crate) fn path(rcode_home: &Path) -> PathBuf {
        rcode_home.join("skills.json")
    }

    /// Defaults when the file is missing; a damaged or unknown-version file is
    /// an error and is never rewritten.
    pub(crate) fn read(rcode_home: &Path) -> Result<Self> {
        let path = Self::path(rcode_home);
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(Self {
                version: MANIFEST_VERSION,
                ..Self::default()
            });
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Не удалось прочитать {}", path.display()))?;
        let manifest: Self =
            serde_json::from_str(&text).with_context(|| format!("Повреждён {}", path.display()))?;
        if manifest.version != MANIFEST_VERSION {
            bail!(
                "{} имеет версию {}, эта версия rcode понимает только {}",
                path.display(),
                manifest.version,
                MANIFEST_VERSION
            );
        }
        Ok(manifest)
    }

    /// Saves under the skills.lock; use only when the caller holds no lock.
    pub(crate) fn save(&self, rcode_home: &Path) -> Result<()> {
        let _lock = crate::config::lock_state_file(&rcode_home.join("skills.lock"))?;
        self.write(rcode_home)
    }

    /// Saves without locking; the caller must already hold skills.lock.
    pub(crate) fn write(&self, rcode_home: &Path) -> Result<()> {
        crate::config::write_private_json(&Self::path(rcode_home), self)
    }

    pub(crate) fn sources(&self) -> &BTreeMap<String, SourceRecord> {
        &self.sources
    }

    pub(crate) fn sources_mut(&mut self) -> &mut BTreeMap<String, SourceRecord> {
        &mut self.sources
    }

    pub(crate) fn disabled(&self) -> &BTreeSet<String> {
        &self.disabled
    }

    pub(crate) fn set_disabled(&mut self, disabled: BTreeSet<String>) {
        self.disabled = disabled;
    }

    pub(crate) fn project_roots(&self) -> &[PathBuf] {
        &self.project_roots
    }

    pub(crate) fn linked(&self) -> &BTreeMap<String, LinkedRoot> {
        &self.linked
    }

    pub(crate) fn linked_mut(&mut self) -> &mut BTreeMap<String, LinkedRoot> {
        &mut self.linked
    }

    pub(crate) fn catalog_overrides(&self) -> &CatalogOverrides {
        &self.catalog
    }

    #[expect(dead_code, reason = "каталог переопределяет установщик T11")]
    pub(crate) fn set_catalog(&mut self, catalog: CatalogOverrides) {
        self.catalog = catalog;
    }
}

/// Transport failure of `git` itself; `app::exit_code` maps it to 4 like a
/// provider failure, so argument and configuration problems stay code 2.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct SourceFailure(pub(crate) String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceKind {
    GitHttps,
    GitSsh,
    GitLocal,
    Dir,
}

impl SourceKind {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::GitHttps => "git по HTTPS — сетевая операция",
            Self::GitSsh => "git по SSH — сетевая операция",
            Self::GitLocal => "локальный git-репозиторий, без сети",
            Self::Dir => "локальный каталог, копирование без сети",
        }
    }

    fn protocol(self) -> &'static str {
        match self {
            Self::GitHttps => "https",
            Self::GitSsh => "ssh",
            Self::GitLocal | Self::Dir => "file",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Source {
    pub(crate) kind: SourceKind,
    pub(crate) input: String,
    pub(crate) url: String,
}

pub(crate) fn parse_source(input: &str, rcode_home: &Path, project_root: &Path) -> Result<Source> {
    if input.trim() != input || input.is_empty() || input.chars().any(char::is_control) {
        bail!("Источник содержит пробельные или управляющие символы");
    }
    let forbidden = [
        (
            "http://",
            "Небезопасный протокол http://; используйте https://",
        ),
        (
            "git://",
            "Небезопасный протокол git://; используйте https:// или ssh",
        ),
        ("ext::", "Протокол ext:: не принимается"),
        (
            "file://",
            "Адрес file:// не принимается; укажите локальный путь как путь",
        ),
    ];
    for (prefix, message) in forbidden {
        if input.starts_with(prefix) {
            bail!("{message}");
        }
    }
    if config_userinfo(input) {
        bail!(
            "URL с логином и паролем (userinfo) не принимается; используйте ssh-агент или credential helper"
        );
    }
    let source = if let Some(url) = input.strip_prefix("https://") {
        Source {
            kind: SourceKind::GitHttps,
            input: input.to_owned(),
            url: format!("https://{url}"),
        }
    } else if let Some(url) = input.strip_prefix("ssh://") {
        Source {
            kind: SourceKind::GitSsh,
            input: input.to_owned(),
            url: format!("ssh://{url}"),
        }
    } else if input.starts_with('/') || input.starts_with("./") || input.starts_with("../") {
        let path = Path::new(input);
        let inside_home = rcode_home.starts_with(path) || path.starts_with(rcode_home);
        let inside_project = project_root.starts_with(path) || path.starts_with(project_root);
        if inside_home || inside_project {
            bail!("Источник не может находиться внутри RCODE_HOME или рабочей папки");
        }
        let is_git = path.join(".git").exists() || path.join("HEAD").exists();
        Source {
            kind: if is_git {
                SourceKind::GitLocal
            } else {
                SourceKind::Dir
            },
            input: input.to_owned(),
            url: input.to_owned(),
        }
    } else if let Some((user, rest)) = input.split_once('@')
        && !user.is_empty()
        && let Some((host, path)) = rest.split_once(':')
        && !host.is_empty()
        && !host.contains('/')
        && !path.is_empty()
        && !path.contains("://")
    {
        Source {
            kind: SourceKind::GitSsh,
            input: input.to_owned(),
            url: input.to_owned(),
        }
    } else {
        bail!(
            "Источник не распознан: поддерживаются https://, ssh://, scp-подобный git@host:path и локальный путь"
        )
    };
    Ok(source)
}

fn config_userinfo(value: &str) -> bool {
    value.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}

/// Removes `user:password@` from any URL echoed into git output.
pub(crate) fn scrub_userinfo(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("://") {
        let (before, after) = rest.split_at(position + 3);
        result.push_str(before);
        let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let authority = &after[..authority_end];
        if let Some(host) = authority.rsplit('@').next() {
            let userinfo = &authority[..authority.len() - host.len()];
            if userinfo.contains('@') {
                result.push_str(host);
                rest = &after[authority_end..];
                continue;
            }
        }
        result.push_str(authority);
        rest = &after[authority_end..];
    }
    result.push_str(rest);
    result
}

pub(crate) struct GitCommand {
    program: PathBuf,
    config_args: Vec<String>,
    envs: Vec<(String, String)>,
}

impl GitCommand {
    pub(crate) fn find(staging_dir: &Path, kind: SourceKind) -> Result<Self> {
        let program = search_path("git").ok_or_else(|| {
            anyhow::anyhow!("Не найден git в PATH; установите Git для установки наборов")
        })?;
        let mut config_args = Vec::new();
        for (key, value) in [
            ("http.sslVerify", "true"),
            ("core.hooksPath", &staging_dir.display().to_string()),
            ("core.fsmonitor", "false"),
        ] {
            config_args.push("-c".to_owned());
            config_args.push(format!("{key}={value}"));
        }
        let mut envs = Vec::new();
        let allowed = [
            "PATH",
            "HOME",
            "USERPROFILE",
            "LANG",
            "TMPDIR",
            "TEMP",
            "TMP",
            "SYSTEMROOT",
            "SSH_AUTH_SOCK",
        ];
        for key in allowed {
            if let Ok(value) = std::env::var(key) {
                envs.push((key.to_owned(), value));
            }
        }
        for key in std::env::vars() {
            if key.0.starts_with("LC_") {
                envs.push(key);
            }
        }
        envs.push(("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()));
        envs.push(("GIT_LFS_SKIP_SMUDGE".to_owned(), "1".to_owned()));
        envs.push((
            "GIT_ALLOW_PROTOCOL".to_owned(),
            format!("{}:ssh", kind.protocol()),
        ));
        Ok(Self {
            program,
            config_args,
            envs,
        })
    }

    pub(crate) fn envs(&self) -> &[(String, String)] {
        &self.envs
    }

    pub(crate) fn clone_argv(&self, url: &str, dir: &Path, reference: Option<&str>) -> Vec<String> {
        let mut argv = self.config_args.clone();
        argv.push("clone".to_owned());
        argv.push("--depth".to_owned());
        argv.push("1".to_owned());
        argv.push("--no-recurse-submodules".to_owned());
        argv.push("--single-branch".to_owned());
        if let Some(reference) = reference {
            argv.push("--branch".to_owned());
            argv.push(reference.to_owned());
        }
        argv.push("--".to_owned());
        argv.push(url.to_owned());
        argv.push(dir.display().to_string());
        argv
    }

    pub(crate) fn pinned_fetch_argv(
        &self,
        url: &str,
        dir: &Path,
        commit: &str,
    ) -> Vec<Vec<String>> {
        [
            vec!["init".to_owned(), dir.display().to_string()],
            vec![
                "-C".to_owned(),
                dir.display().to_string(),
                "fetch".to_owned(),
                "--depth".to_owned(),
                "1".to_owned(),
                url.to_owned(),
                commit.to_owned(),
            ],
            vec![
                "-C".to_owned(),
                dir.display().to_string(),
                "checkout".to_owned(),
                "--detach".to_owned(),
                "FETCH_HEAD".to_owned(),
            ],
        ]
        .into_iter()
        .map(|step| [self.config_args.clone(), step].concat())
        .collect()
    }

    pub(crate) fn rev_parse_argv(&self, dir: &Path) -> Vec<String> {
        let mut argv = self.config_args.clone();
        argv.extend([
            "-C".to_owned(),
            dir.display().to_string(),
            "rev-parse".to_owned(),
            "HEAD".to_owned(),
        ]);
        argv
    }

    pub(crate) fn ls_remote_argv(&self, url: &str, reference: Option<&str>) -> Vec<String> {
        let mut argv = self.config_args.clone();
        argv.push("ls-remote".to_owned());
        argv.push("--quiet".to_owned());
        argv.push(url.to_owned());
        if let Some(reference) = reference {
            argv.push(reference.to_owned());
        } else {
            argv.push("HEAD".to_owned());
        }
        argv
    }
}

fn search_path(program: &str) -> Option<PathBuf> {
    search_path_in(program, &std::env::var_os("PATH")?)
}

fn search_path_in(program: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(program);
        #[cfg(windows)]
        let candidate = candidate.with_extension("exe");
        #[cfg(unix)]
        let executable = std::fs::metadata(&candidate)
            .map(|metadata| metadata.is_file() && is_executable(&metadata))
            .unwrap_or(false);
        #[cfg(not(unix))]
        let executable = std::fs::metadata(&candidate)
            .map(|m| m.is_file())
            .unwrap_or(false);
        if executable {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

const GIT_TIMEOUT: Duration = std::time::Duration::from_secs(300);
const MAX_STDERR: usize = 8 * 1024;
const MAX_STDOUT: usize = 64 * 1024;

pub(crate) struct GitRun<'a> {
    pub(crate) git: &'a GitCommand,
    pub(crate) redact: &'a (dyn Fn(&str) -> String + Send + Sync),
}

impl GitRun<'_> {
    /// Runs one git invocation with a closed stdin, a 300 second timeout and
    /// Ctrl+C cancellation; stderr is truncated, redacted and userinfo-free.
    pub(crate) async fn run(&self, argv: &[String]) -> Result<String> {
        use tokio::io::AsyncReadExt;
        let mut command = tokio::process::Command::new(&self.git.program);
        command
            .args(argv)
            .env_clear()
            .envs(
                self.git
                    .envs()
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| SourceFailure(format!("git не запустился: {error}")))?;
        let cancel = tokio::signal::ctrl_c();
        let mut stderr = child.stderr.take().expect("stderr запрошен");
        let mut stdout = child.stdout.take().expect("stdout запрошен");
        let mut buffer = Vec::new();
        let mut out_buffer = Vec::new();
        let read = async {
            let mut chunk = [0u8; 4096];
            loop {
                let read = stderr.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                if buffer.len() < MAX_STDERR {
                    buffer.extend_from_slice(&chunk[..read]);
                }
            }
            anyhow::Ok(())
        };
        let read_stdout = async {
            let mut chunk = [0u8; 4096];
            loop {
                let read = stdout.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                if out_buffer.len() < MAX_STDOUT {
                    out_buffer.extend_from_slice(&chunk[..read]);
                }
            }
            anyhow::Ok(())
        };
        let race = async {
            tokio::select! {
                status = child.wait() => {
                    let status = status.map_err(|error| SourceFailure(format!("git: {error}")))?;
                    let (read, read_stdout) = tokio::join!(read, read_stdout);
                    let _ = (read, read_stdout);
                    Ok::<_, anyhow::Error>(Some(status))
                }
                _ = cancel => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    Ok(None)
                }
            }
        };
        let status = tokio::time::timeout(GIT_TIMEOUT, race)
            .await
            .map_err(|_| SourceFailure("git operation timed out after 300 seconds".to_owned()))??;
        let interrupted = status.is_none();
        if interrupted {
            bail!(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Установка набора прервана"
            ));
        }
        let status = status.expect("статус получен");
        let text = String::from_utf8_lossy(&buffer[..buffer.len().min(MAX_STDERR)]);
        let text = scrub_userinfo(&(self.redact)(&text));
        if !status.success() {
            return Err(
                SourceFailure(format!("git завершился с ошибкой: {}; {text}", status)).into(),
            );
        }
        let stdout = String::from_utf8_lossy(&out_buffer[..out_buffer.len().min(MAX_STDOUT)]);
        Ok(scrub_userinfo(&(self.redact)(&stdout)))
    }
}

pub(crate) fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.len() <= 32
        && bytes
            .first()
            .is_some_and(|first| matches!(first, b'a'..=b'z' | b'0'..=b'9'))
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

pub(crate) fn default_label(source: &Source) -> String {
    let tail = source
        .url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("skills")
        .trim_end_matches(".git");
    let candidate: String = tail
        .chars()
        .map(|ch| {
            if ch.is_ascii_uppercase() {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        })
        .map(|ch| if ch == '.' { '-' } else { ch })
        .collect();
    if valid_label(&candidate) {
        candidate
    } else {
        "skills".to_owned()
    }
}

fn file_digest(path: &Path) -> Result<String> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Не удалось прочитать {}", path.display()))?;
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// SHA-256 over sorted (relative path, is_executable, content digest) of every
/// file in the tree without `.git`; detects manual user edits.
pub(crate) fn tree_sha256(root: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<(String, bool, String)> = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(relative) = stack.pop() {
        let absolute = root.join(&relative);
        let metadata = std::fs::symlink_metadata(&absolute)
            .with_context(|| format!("Не удалось прочитать {}", absolute.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let mut children: Vec<_> = std::fs::read_dir(&absolute)
                .with_context(|| format!("Не удалось прочитать {}", absolute.display()))?
                .flatten()
                .map(|entry| relative.join(entry.file_name()))
                .filter(|relative| {
                    let name = relative.file_name().and_then(|name| name.to_str());
                    name.is_none_or(|name| name != ".git" && name != "node_modules")
                })
                .collect();
            children.sort();
            children.reverse();
            stack.extend(children);
            continue;
        }
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        entries.push((
            relative.display().to_string(),
            executable,
            file_digest(&absolute)?,
        ));
    }
    entries.sort();
    let mut hasher = Sha256::new();
    for (path, executable, digest) in entries {
        hasher.update(path.as_bytes());
        hasher.update([b' ', if executable { 1 } else { 0 }, b' ']);
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Version metadata of the installed set, read-only: `.codex-plugin/plugin.json`,
/// `.claude-plugin/plugin.json`, `package.json` or a `VERSION` file.
pub(crate) fn package_version(root: &Path) -> Option<String> {
    for path in [
        root.join(".codex-plugin/plugin.json"),
        root.join(".claude-plugin/plugin.json"),
        root.join("package.json"),
    ] {
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(version) = value["version"].as_str()
        {
            return Some(version.to_owned());
        }
    }
    let version = root.join("VERSION");
    if let Ok(text) = std::fs::read_to_string(&version) {
        let trimmed = text.trim();
        if !trimmed.is_empty() && trimmed.len() < 40 {
            return Some(trimmed.to_owned());
        }
    }
    None
}

pub(crate) fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    crate::config::ensure_private_directory(destination)?;
    for entry in std::fs::read_dir(source)
        .with_context(|| format!("Не удалось прочитать {}", source.display()))?
    {
        let entry = entry.with_context(|| format!("Не удалось прочитать {}", source.display()))?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .with_context(|| format!("Не удалось прочитать {}", entry.path().display()))?;
        let target = destination.join(entry.file_name());
        if metadata.file_type().is_symlink() {
            continue;
        } else if metadata.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)
                .with_context(|| format!("Не удалось скопировать {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// The set reads like it was written for another agent's installer: it points
/// at `~/.claude/` paths or ships its own setup script. rcode installs only
/// the text and never runs the set's own installer.
pub(crate) fn compatibility_warning(clone: &Path) -> Option<&'static str> {
    let mentions_claude = walk_files(clone, 3).take(400).any(|file| {
        std::fs::read_to_string(&file)
            .map(|text| {
                text.contains("~/.claude")
                    || text.contains("$HOME/.claude")
                    || text.contains("CLAUDE_PLUGIN_ROOT")
            })
            .unwrap_or(false)
    });
    if mentions_claude {
        return Some(
            "набор ссылается на пути другого агента (~/.claude); rcode не запускает его установщик, некоторые шаги могут не работать",
        );
    }
    if clone.join("setup").exists()
        && std::fs::read_to_string(clone.join("package.json"))
            .map(|text| text.contains("\"install\""))
            .unwrap_or(false)
    {
        return Some("набор содержит собственный установщик; rcode его не запускает");
    }
    None
}

fn walk_files(root: &Path, depth: usize) -> impl Iterator<Item = PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![(PathBuf::new(), 0usize)];
    while let Some((relative, level)) = stack.pop() {
        if level > depth {
            continue;
        }
        let absolute = root.join(&relative);
        let Ok(metadata) = std::fs::symlink_metadata(&absolute) else {
            continue;
        };
        if metadata.is_dir() && relative.as_os_str().is_empty()
            || metadata.is_dir() && relative.file_name().is_none_or(|name| name != ".git")
        {
            if let Ok(entries) = std::fs::read_dir(&absolute) {
                for entry in entries.flatten() {
                    stack.push((relative.join(entry.file_name()), level + 1));
                }
            }
        } else if metadata.is_file() {
            files.push(absolute);
        }
    }
    files.into_iter()
}

#[cfg(test)]
mod run_tests {
    use super::*;

    fn staging() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rcode-gitrun-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(windows)]
    #[test]
    fn git_exe_is_discovered_without_changing_process_path() {
        let dir = staging();
        let executable = dir.join("git.exe");
        std::fs::write(&executable, b"fixture; discovery only").unwrap();
        assert_eq!(search_path_in("git", dir.as_os_str()), Some(executable));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn captures_rev_parse_stdout() {
        let repo = staging();
        let run_git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .env_clear()
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run_git(&["init", "-q", "."]);
        std::fs::write(repo.join("file.txt"), "x").unwrap();
        run_git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@e.invalid",
            "add",
            ".",
        ]);
        run_git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@e.invalid",
            "commit",
            "-qm",
            "init",
        ]);
        let git = GitCommand::find(&repo, SourceKind::GitLocal).unwrap();
        let run = GitRun {
            git: &git,
            redact: &|text: &str| text.to_owned(),
        };
        let output = run.run(&git.rev_parse_argv(&repo)).await.unwrap();
        assert_eq!(output.trim().len(), 40, "stdout потерян: {output:?}");
        let _ = std::fs::remove_dir_all(repo);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_captures_plain_stdout() {
        let dir = staging();
        let git = GitCommand {
            program: PathBuf::from("/bin/echo"),
            config_args: Vec::new(),
            envs: Vec::new(),
        };
        let run = GitRun {
            git: &git,
            redact: &|text: &str| text.to_owned(),
        };
        let output = run.run(&["привет".to_owned()]).await.unwrap();
        assert_eq!(output.trim(), "привет", "stdout потерян: {output:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failing_git_maps_to_source_failure() {
        let dir = staging();
        let git = GitCommand::find(&dir, SourceKind::GitHttps).unwrap();
        let run = GitRun {
            git: &git,
            redact: &|text: &str| text.to_owned(),
        };
        let error = run
            .run(&git.ls_remote_argv("https://example.invalid/no-such-repo.git", None))
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<SourceFailure>().is_some(), "{error:#}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_source_accepts_and_rejects() {
        let home = Path::new("/tmp/rcode-home");
        let project = Path::new("/tmp/rcode-project");
        for good in [
            "https://github.com/obra/superpowers.git",
            "git@github.com:owner/repo.git",
            "ssh://github.com/owner/repo.git",
        ] {
            assert!(parse_source(good, home, project).is_ok(), "{good}");
        }
        for bad in [
            "http://github.com/obra/superpowers.git",
            "git://host/repo.git",
            "ext::sh -c touch",
            "file:///tmp/repo",
            "https://user:token@github.com/obra/superpowers.git",
            "https://user@github.com/obra/superpowers.git",
            " не с пробелов",
            "git host path",
        ] {
            assert!(parse_source(bad, home, project).is_err(), "{bad}");
        }
        let inside = parse_source("/tmp/rcode-home/skills", home, project);
        assert!(inside.is_err());
    }

    #[test]
    fn scrub_userinfo_removes_credentials_from_urls() {
        assert_eq!(
            scrub_userinfo("fatal: https://user:token@example.invalid/repo.git not found"),
            "fatal: https://example.invalid/repo.git not found"
        );
        assert_eq!(
            scrub_userinfo("https://token@example.invalid/x.git"),
            "https://example.invalid/x.git"
        );
        assert_eq!(
            scrub_userinfo("plain https://github.com/obra/superpowers.git"),
            "plain https://github.com/obra/superpowers.git"
        );
    }

    #[test]
    fn git_command_env_has_no_secret_variables() {
        // SAFETY: однопоточный тест изменяет окружение процесса до запуска git.
        unsafe {
            std::env::set_var("RCODE_OPENAI_API_KEY", "test-secret-value");
            std::env::set_var("OPENAI_API_KEY", "test-secret-value-2");
        }
        let dir = staging();
        let git = GitCommand::find(&dir, SourceKind::GitHttps).unwrap();
        assert!(
            git.envs().iter().all(|(key, _)| {
                !key.contains("KEY") && !key.contains("TOKEN") || key == "PATH"
            })
        );
        assert!(
            !git.envs()
                .iter()
                .any(|(_, value)| value.contains("test-secret"))
        );
        assert!(
            git.envs()
                .iter()
                .any(|(key, value)| key == "GIT_TERMINAL_PROMPT" && value == "0")
        );
        assert!(
            git.envs()
                .iter()
                .any(|(key, value)| key == "GIT_LFS_SKIP_SMUDGE" && value == "1")
        );
        assert!(
            git.envs()
                .iter()
                .any(|(key, value)| key == "GIT_ALLOW_PROTOCOL" && value.starts_with("https"))
        );
        let _ = std::fs::remove_dir_all(dir);
        // SAFETY: восстановление окружения того же однопоточного теста.
        unsafe {
            std::env::remove_var("RCODE_OPENAI_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");
        }
    }

    #[test]
    fn clone_argv_is_constrained() {
        let dir = staging();
        let git = GitCommand::find(&dir, SourceKind::GitHttps).unwrap();
        let argv = git.clone_argv(
            "https://github.com/obra/superpowers.git",
            Path::new("/tmp/x"),
            Some("main"),
        );
        assert!(argv.windows(2).any(|pair| pair == ["--depth", "1"]));
        assert!(argv.contains(&"--no-recurse-submodules".to_owned()));
        assert!(argv.contains(&"--single-branch".to_owned()));
        assert!(argv.windows(2).any(|pair| pair == ["--branch", "main"]));
        assert!(
            argv.windows(2)
                .any(|pair| pair == ["-c", "http.sslVerify=true"])
        );
        assert!(argv.iter().any(|arg| arg.starts_with("core.hooksPath=")));
        assert!(argv.iter().any(|arg| arg.starts_with("core.fsmonitor=")));
        let pinned = git.pinned_fetch_argv(
            "https://github.com/x/y.git",
            Path::new("/tmp/x"),
            "abcdef1234",
        );
        assert_eq!(pinned.len(), 3);
        assert!(pinned[0].contains(&"init".to_owned()));
        assert!(
            pinned[1].contains(&"fetch".to_owned()) && pinned[1].contains(&"abcdef1234".to_owned())
        );
        assert!(
            pinned[2].contains(&"checkout".to_owned())
                && pinned[2].contains(&"--detach".to_owned())
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
