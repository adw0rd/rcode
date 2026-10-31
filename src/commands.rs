use crate::frontmatter;
use crate::terminal::COMMANDS;
use crate::tools::secret_component;
use anyhow::{Result, bail};
use cap_std::ambient_authority;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const COMMANDS_DIR: &str = "commands";
const MAX_COMMAND_BYTES: u64 = 64 * 1024;
const MAX_RESULT_BYTES: usize = 256 * 1024;
const MAX_COMMANDS: usize = 200;
const MAX_DESCRIPTION_CHARS: usize = 80;
const BUILTIN_ALIASES: &[&str] = &["quit", "models", "login", "new", "attach"];
const UNSUPPORTED_MARKS: &[&str] = &["inline_shell", "file_reference"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandScope {
    User,
    Project,
}

impl CommandScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::User => "пользователь",
            Self::Project => "проект",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shadow {
    Builtin,
    User,
}

pub(crate) struct UserCommand {
    pub(crate) name: String,
    pub(crate) scope: CommandScope,
    #[expect(dead_code, reason = "путь нужен в `rcode commands list` (T9)")]
    pub(crate) path: PathBuf,
    pub(crate) description: String,
    pub(crate) hint: Option<String>,
    pub(crate) template: String,
    pub(crate) unsupported: Vec<&'static str>,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "список нужен в `rcode commands list` (T9)")
    )]
    pub(crate) ignored_fields: Vec<String>,
    pub(crate) shadowed_by: Option<Shadow>,
}

pub(crate) struct CommandProblem {
    pub(crate) path: PathBuf,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

pub(crate) struct CommandRegistry {
    pub(crate) commands: Vec<UserCommand>,
    pub(crate) problems: Vec<CommandProblem>,
}

pub(crate) fn builtin_names() -> Vec<String> {
    let mut names: Vec<String> = COMMANDS.iter().map(|c| c.name.to_owned()).collect();
    names.extend(BUILTIN_ALIASES.iter().map(|alias| format!("/{alias}")));
    names
}

fn is_builtin(name: &str) -> bool {
    builtin_names().contains(&format!("/{name}"))
}

fn valid_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_digit() || first.is_ascii_lowercase())
        && segment.len() <= 48
        && chars.all(|ch| ch.is_ascii_digit() || ch.is_ascii_lowercase() || ch == '_' || ch == '-')
}

impl CommandRegistry {
    pub(crate) fn discover(rcode_home: &Path, project_root: &Path) -> Self {
        let mut discovery = Discovery::default();
        let roots = [
            (
                CommandScope::User,
                rcode_home.to_path_buf(),
                PathBuf::from(COMMANDS_DIR),
            ),
            (
                CommandScope::Project,
                project_root.to_path_buf(),
                PathBuf::from(".rcode").join(COMMANDS_DIR),
            ),
        ];
        for (scope, base, relative) in roots {
            discovery.scan(scope, &base, &relative);
        }
        let mut commands = discovery.found;
        commands.sort_by_key(|found| {
            (
                found.command.scope != CommandScope::User,
                found.command.shadowed_by.is_some(),
                found.command.name.clone(),
            )
        });
        Self {
            commands: commands.into_iter().map(|found| found.command).collect(),
            problems: discovery.problems,
        }
    }

    pub(crate) fn find(&self, name: &str) -> Option<&UserCommand> {
        self.commands
            .iter()
            .find(|command| command.name == name && command.shadowed_by.is_none())
    }

    pub(crate) fn menu(&self) -> Vec<crate::terminal::MenuCommand> {
        self.commands
            .iter()
            .filter(|command| command.shadowed_by.is_none())
            .map(|command| crate::terminal::MenuCommand {
                name: format!("/{}", command.name),
                description: format!("{} · {}", command.description, command.scope.as_str()),
                custom: true,
            })
            .collect()
    }

    pub(crate) fn loadable(&self) -> impl Iterator<Item = &UserCommand> {
        self.commands.iter().filter(|c| c.shadowed_by.is_none())
    }
}

impl UserCommand {
    /// Single-pass substitution: argument values are never re-expanded.
    pub(crate) fn expand(&self, arguments: &str) -> Result<String> {
        let positional: Vec<String> = crate::images::tokens(arguments)
            .into_iter()
            .map(|(_, value)| value)
            .collect();
        let mut expanded = String::new();
        let mut substituted = false;
        let mut rest = self.template.as_str();
        while let Some(index) = rest.find('$') {
            expanded.push_str(&rest[..index]);
            let tail = &rest[index..];
            if let Some(value) = tail.strip_prefix("$$") {
                expanded.push('$');
                rest = value;
            } else if let Some(value) = tail.strip_prefix("$ARGUMENTS") {
                expanded.push_str(arguments);
                substituted = true;
                rest = value;
            } else if tail.len() >= 2
                && let Some(digit) = tail[1..2].chars().next().filter(char::is_ascii_digit)
                && let Some(index) = digit.to_digit(10)
                && index >= 1
                && !tail[2..]
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_digit())
            {
                expanded.push_str(
                    positional
                        .get(index as usize - 1)
                        .map(String::as_str)
                        .unwrap_or(""),
                );
                substituted = true;
                rest = &tail[2..];
            } else {
                expanded.push('$');
                rest = &tail[1..];
            }
        }
        expanded.push_str(rest);
        if !substituted && !arguments.is_empty() {
            expanded.push_str("\n\nАргументы: ");
            expanded.push_str(arguments);
        }
        if expanded.len() > MAX_RESULT_BYTES {
            bail!(
                "Раскрытая команда «{}» больше {} КиБ; сократите шаблон или аргументы",
                self.name,
                MAX_RESULT_BYTES / 1024
            );
        }
        Ok(expanded)
    }
}

#[derive(Default)]
struct Discovery {
    found: Vec<Found>,
    problems: Vec<CommandProblem>,
    total: usize,
}

struct Found {
    command: UserCommand,
}

impl Discovery {
    fn problem(&mut self, path: PathBuf, code: &'static str, message: impl Into<String>) {
        self.problems.push(CommandProblem {
            path,
            code,
            message: message.into(),
        });
    }

    fn open_root(&mut self, base: &Path, relative: &Path) -> Option<(PathBuf, cap_std::fs::Dir)> {
        let path = base.join(relative);
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            self.problem(path, "invalid_root", "Недопустимый путь корня команд");
            return None;
        }
        if relative
            .components()
            .any(|component| secret_component(component.as_os_str()))
        {
            self.problem(
                path,
                "secret_path",
                "Путь корня команд содержит секретный компонент",
            );
            return None;
        }
        let mut current = base.to_path_buf();
        for component in relative.components() {
            current.push(component);
            match std::fs::symlink_metadata(&current) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
                Err(error) => {
                    self.problem(current, "io", format!("Ошибка чтения: {error}"));
                    return None;
                }
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    self.problem(current, "symlink", "Символическая ссылка пропущена");
                    return None;
                }
                Ok(metadata) if !metadata.is_dir() => {
                    self.problem(
                        current,
                        "not_directory",
                        "Корень команд не является каталогом",
                    );
                    return None;
                }
                Ok(_) => {}
            }
        }
        match cap_std::fs::Dir::open_ambient_dir(&path, ambient_authority()) {
            Ok(dir) => Some((path, dir)),
            Err(error) => {
                self.problem(path, "io", format!("Ошибка чтения: {error}"));
                None
            }
        }
    }

    fn scan(&mut self, scope: CommandScope, base: &Path, relative: &Path) {
        let Some((path, dir)) = self.open_root(base, relative) else {
            return;
        };
        let mut names = Vec::new();
        match dir.entries() {
            Err(error) => self.problem(path.to_path_buf(), "io", format!("Ошибка чтения: {error}")),
            Ok(entries) => {
                for entry in entries.flatten() {
                    match entry.file_type() {
                        Ok(kind) => names.push((entry.file_name(), kind)),
                        Err(error) => self.problem(
                            path.to_path_buf(),
                            "io",
                            format!("Ошибка чтения: {error}"),
                        ),
                    }
                }
            }
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, kind) in names {
            let text = name.to_string_lossy();
            if text.starts_with('.') || text == "node_modules" {
                continue;
            }
            if kind.is_symlink() {
                self.problem(
                    path.join(&name),
                    "symlink",
                    "Символическая ссылка пропущена",
                );
            } else if kind.is_dir() {
                let sub = PathBuf::from(text.into_owned());
                self.scan_subdirectory(scope, &dir, &path, sub);
            } else if text.ends_with(".md") {
                self.collect(scope, &dir, &path, text.into_owned());
            }
        }
    }

    fn scan_subdirectory(
        &mut self,
        scope: CommandScope,
        dir: &cap_std::fs::Dir,
        root: &Path,
        relative: PathBuf,
    ) {
        if !valid_segment(relative.to_string_lossy().as_ref()) {
            self.problem(
                root.join(&relative),
                "invalid_name",
                "Недопустимое имя подкаталога команды: строчные латинские буквы, цифры, _ и -",
            );
            return;
        }
        let absolute = root.join(&relative);
        let metadata = match dir.symlink_metadata(&relative) {
            Err(_) => return,
            Ok(metadata) => metadata,
        };
        if metadata.file_type().is_symlink() {
            self.problem(absolute, "symlink", "Символическая ссылка пропущена");
            return;
        }
        let mut names = Vec::new();
        match dir.read_dir(&relative) {
            Err(error) => self.problem(absolute.clone(), "io", format!("Ошибка чтения: {error}")),
            Ok(entries) => {
                for entry in entries.flatten() {
                    match entry.file_type() {
                        Ok(kind) => names.push((entry.file_name(), kind)),
                        Err(error) => {
                            self.problem(absolute.clone(), "io", format!("Ошибка чтения: {error}"))
                        }
                    }
                }
            }
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, kind) in names {
            let text = name.to_string_lossy().into_owned();
            if text.starts_with('.') || text == "node_modules" {
                continue;
            }
            if kind.is_symlink() {
                self.problem(
                    absolute.join(&text),
                    "symlink",
                    "Символическая ссылка пропущена",
                );
            } else if kind.is_dir() {
                let deeper = relative.join(&text);
                self.problem(
                    root.join(&deeper),
                    "too_deep",
                    "Команды вложены не глубже двух уровней имён",
                );
            } else if text.ends_with(".md") {
                self.collect_nested(scope, dir, root, &relative, text);
            }
        }
    }

    fn collect_nested(
        &mut self,
        scope: CommandScope,
        dir: &cap_std::fs::Dir,
        root: &Path,
        parent: &Path,
        file: String,
    ) {
        let stem = match file.strip_suffix(".md") {
            Some(stem) => stem.to_owned(),
            None => return,
        };
        let parent_segment = parent
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = format!("{parent_segment}:{stem}");
        self.collect_named(scope, dir, root, &parent.join(&file), name, stem);
    }

    fn collect(&mut self, scope: CommandScope, dir: &cap_std::fs::Dir, root: &Path, file: String) {
        let Some(stem) = file.strip_suffix(".md").map(str::to_owned) else {
            return;
        };
        self.collect_named(scope, dir, root, Path::new(&file), stem.clone(), stem);
    }

    fn collect_named(
        &mut self,
        scope: CommandScope,
        dir: &cap_std::fs::Dir,
        root: &Path,
        relative: &Path,
        name: String,
        stem: String,
    ) {
        if !valid_segment(&stem) {
            self.problem(
                root.join(relative),
                "invalid_name",
                "Недопустимое имя команды: строчные латинские буквы, цифры, _ и -",
            );
            return;
        }
        let absolute = root.join(relative);
        if self.total == MAX_COMMANDS {
            self.problem(
                root.to_path_buf(),
                "too_many_commands",
                format!("Больше {MAX_COMMANDS} команд; остальные пропущены"),
            );
            return;
        }
        let metadata = match dir.symlink_metadata(relative) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                self.problem(absolute, "io", format!("Ошибка чтения: {error}"));
                return;
            }
            Ok(metadata) => metadata,
        };
        if metadata.file_type().is_symlink() {
            self.problem(absolute, "symlink", "Символическая ссылка пропущена");
            return;
        }
        if metadata.len() > MAX_COMMAND_BYTES {
            self.problem(
                absolute,
                "too_large",
                format!("Файл команды больше {} КиБ", MAX_COMMAND_BYTES / 1024),
            );
            return;
        }
        let mut file = match dir.open(relative) {
            Ok(file) => file,
            Err(error) => {
                self.problem(absolute, "io", format!("Ошибка чтения: {error}"));
                return;
            }
        };
        let mut bytes = Vec::new();
        if let Err(error) = file.read_to_end(&mut bytes) {
            self.problem(absolute, "io", format!("Ошибка чтения: {error}"));
            return;
        }
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                self.problem(absolute, "not_utf8", "Файл команды не в UTF-8");
                return;
            }
        };
        let (fields, nested, body) = match frontmatter::parse(&text) {
            Ok(parsed) => {
                let body = text[parsed.body_offset..].trim().to_owned();
                (parsed.fields, parsed.nested_keys, body)
            }
            Err(error) if error.code() == "missing" => {
                (BTreeMap::new(), Vec::new(), text.trim().to_owned())
            }
            Err(error) => {
                self.problem(
                    absolute,
                    "invalid_frontmatter",
                    format!("Frontmatter команды: {error}"),
                );
                return;
            }
        };
        if body.is_empty() {
            self.problem(absolute, "empty_body", "Файл команды без текста запроса");
            return;
        }
        let mut ignored_fields: Vec<String> = fields
            .keys()
            .filter(|key| *key != "description" && *key != "argument-hint")
            .cloned()
            .collect();
        ignored_fields.extend(nested);
        ignored_fields.sort();
        ignored_fields.dedup();
        let description = fields
            .get("description")
            .cloned()
            .unwrap_or_else(|| first_line(&body));
        let hint = fields.get("argument-hint").cloned();
        let mut unsupported = Vec::new();
        if body.contains("```!") || body.contains("!`") {
            unsupported.push(UNSUPPORTED_MARKS[0]);
        }
        if has_file_reference(&body) {
            unsupported.push(UNSUPPORTED_MARKS[1]);
        }
        if is_builtin(&name) {
            self.found.push(Found {
                command: UserCommand {
                    name: name.clone(),
                    scope,
                    path: absolute.clone(),
                    description,
                    hint,
                    template: body,
                    unsupported,
                    ignored_fields,
                    shadowed_by: Some(Shadow::Builtin),
                },
            });
            self.total += 1;
            return;
        }
        if let Some(existing) = self
            .found
            .iter()
            .find(|found| found.command.name == name)
            .map(|found| (found.command.scope, found.command.shadowed_by.is_none()))
        {
            match existing {
                (CommandScope::User, true) => {
                    self.found.push(Found {
                        command: UserCommand {
                            name: name.clone(),
                            scope,
                            path: absolute.clone(),
                            description,
                            hint,
                            template: body,
                            unsupported,
                            ignored_fields,
                            shadowed_by: Some(Shadow::User),
                        },
                    });
                    self.problem(
                        absolute,
                        "duplicate",
                        format!("Команда «{name}» уже есть у пользователя; используется она"),
                    );
                }
                _ => {
                    self.problem(
                        absolute,
                        "duplicate",
                        format!("Команда «{name}» уже определена; копия пропущена"),
                    );
                }
            }
            self.total += 1;
            return;
        }
        self.found.push(Found {
            command: UserCommand {
                name,
                scope,
                path: absolute,
                description,
                hint,
                template: body,
                unsupported,
                ignored_fields,
                shadowed_by: None,
            },
        });
        self.total += 1;
    }
}

fn first_line(body: &str) -> String {
    let line = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let mut clipped: String = line.trim().chars().take(MAX_DESCRIPTION_CHARS).collect();
    if line.trim().chars().count() > MAX_DESCRIPTION_CHARS {
        clipped.push('…');
    }
    clipped
}

fn has_file_reference(body: &str) -> bool {
    let mut previous = ' ';
    for (index, ch) in body.char_indices() {
        if ch == '@' && previous.is_whitespace() {
            let next = body[index + ch.len_utf8()..].chars().next().unwrap_or(' ');
            if !next.is_whitespace() {
                return true;
            }
        }
        previous = ch;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        home: PathBuf,
        project: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("rcode-home");
            let project = temp.path().join("project");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&project).unwrap();
            Self {
                _temp: temp,
                home,
                project,
            }
        }

        fn user(&self) -> PathBuf {
            self.home.join("commands")
        }

        fn project(&self) -> PathBuf {
            self.project.join(".rcode/commands")
        }

        fn discover(&self) -> CommandRegistry {
            CommandRegistry::discover(&self.home, &self.project)
        }
    }

    fn put(path: &Path, content: impl AsRef<[u8]>) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn command_file(root: &Path, name: &str, template: &str) -> PathBuf {
        let file = root.join(format!("{name}.md"));
        put(&file, template);
        file
    }

    #[test]
    fn builtin_names_cover_the_terminal_menu_and_aliases() {
        let names = builtin_names();
        for command in COMMANDS {
            assert!(
                names.contains(&command.name.to_owned()),
                "{} пропущен",
                command.name
            );
        }
        for alias in BUILTIN_ALIASES {
            assert!(names.contains(&format!("/{alias}")), "{} пропущен", alias);
        }
    }

    #[test]
    fn arguments_and_positional_slots_are_substituted_once() {
        let command = UserCommand {
            name: "pr".into(),
            scope: CommandScope::User,
            path: PathBuf::new(),
            description: String::new(),
            hint: None,
            template: "Задача $1 из $ARGUMENTS; дословно $$ и $10 и $HOME и ${X}".into(),
            unsupported: Vec::new(),
            ignored_fields: Vec::new(),
            shadowed_by: None,
        };
        let expanded = command.expand("42 \"две части\" '$1'").unwrap();
        assert_eq!(
            expanded,
            "Задача 42 из 42 \"две части\" '$1'; дословно $ и $10 и $HOME и ${X}"
        );
    }

    #[test]
    fn missing_slots_are_empty_and_extra_arguments_are_appended() {
        let plain = UserCommand {
            name: "review".into(),
            scope: CommandScope::Project,
            path: PathBuf::new(),
            description: String::new(),
            hint: None,
            template: "Проверь.".into(),
            unsupported: Vec::new(),
            ignored_fields: Vec::new(),
            shadowed_by: None,
        };
        assert_eq!(plain.expand("a b").unwrap(), "Проверь.\n\nАргументы: a b");
        assert_eq!(plain.expand("").unwrap(), "Проверь.");
        let multiline = plain.expand("a\nb").unwrap();
        assert!(multiline.ends_with("Аргументы: a\nb"));
        let slotted = UserCommand {
            template: "Проверь $3.".into(),
            ..plain
        };
        assert_eq!(slotted.expand("a b").unwrap(), "Проверь .");
    }

    #[test]
    fn oversized_expansion_is_a_local_error() {
        let command = UserCommand {
            name: "big".into(),
            scope: CommandScope::User,
            path: PathBuf::new(),
            description: String::new(),
            hint: None,
            template: "$ARGUMENTS".into(),
            unsupported: Vec::new(),
            ignored_fields: Vec::new(),
            shadowed_by: None,
        };
        let arguments = "x".repeat(MAX_RESULT_BYTES + 1);
        assert!(command.expand(&arguments).is_err());
    }

    #[test]
    fn names_from_subdirectories_use_colon_separator() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "pr", "Тело pr");
        put(&fixture.user().join("git").join("log.md"), "Тело git:log");
        let registry = fixture.discover();
        let names: Vec<_> = registry.loadable().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["git:log", "pr"]);
    }

    #[test]
    fn invalid_and_builtin_names_are_shadowed_or_reported() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "Bad Name", "x");
        command_file(&fixture.user(), "UPPER", "x");
        command_file(&fixture.user(), "permissions", "подмена разрешений");
        let registry = fixture.discover();
        assert!(registry.loadable().next().is_none());
        assert!(
            registry
                .commands
                .iter()
                .any(|c| c.name == "permissions" && c.shadowed_by == Some(Shadow::Builtin))
        );
        assert!(
            registry
                .problems
                .iter()
                .any(|p| p.code == "invalid_name" && p.path.ends_with("Bad Name.md"))
        );
        assert!(
            registry
                .problems
                .iter()
                .any(|p| p.code == "invalid_name" && p.path.ends_with("UPPER.md"))
        );
    }

    #[test]
    fn user_commands_win_over_project_copies() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "deploy", "пользовательский шаблон");
        command_file(&fixture.project(), "deploy", "проектный шаблон");
        let registry = fixture.discover();
        assert!(registry.find("deploy").is_some());
        let shadowed = registry
            .commands
            .iter()
            .find(|c| c.shadowed_by.is_some())
            .unwrap();
        assert_eq!(shadowed.scope, CommandScope::Project);
        assert_eq!(shadowed.shadowed_by, Some(Shadow::User));
        assert_eq!(
            registry.find("deploy").unwrap().template,
            "пользовательский шаблон"
        );
    }

    #[test]
    fn duplicate_in_one_root_is_reported_and_skipped() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "deploy", "первый");
        command_file(&fixture.user().join("ops"), "deploy", "второй");
        let registry = fixture.discover();
        let names: Vec<_> = registry.loadable().map(|c| c.name.to_owned()).collect();
        assert_eq!(names, ["deploy", "ops:deploy"]);
        assert!(registry.problems.iter().all(|p| p.code != "duplicate"));
    }

    #[test]
    fn inline_shell_and_file_references_are_marked_unsupported() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "shell", "Выведи `!`touch x`` и @@file");
        command_file(&fixture.user(), "plain", "Просто текст");
        let registry = fixture.discover();
        let shell = registry.find("shell").unwrap();
        assert_eq!(shell.unsupported, ["inline_shell", "file_reference"]);
        assert!(registry.find("plain").unwrap().unsupported.is_empty());
    }

    #[test]
    fn description_defaults_to_the_first_body_line() {
        let fixture = Fixture::new();
        command_file(
            &fixture.user(),
            "no_meta",
            "\n\nПервая строка описания\nВторая",
        );
        put(
            &fixture.user().join("meta.md"),
            "---\ndescription: Из frontmatter\nargument-hint: \"[id]\"\n---\nТело",
        );
        put(
            &fixture.user().join("allowed.md"),
            "---\nallowed-tools: Bash(x *)\n---\nТело",
        );
        let registry = fixture.discover();
        assert_eq!(
            registry.find("no_meta").unwrap().description,
            "Первая строка описания"
        );
        let meta = registry.find("meta").unwrap();
        assert_eq!(meta.description, "Из frontmatter");
        assert_eq!(meta.hint.as_deref(), Some("[id]"));
        let allowed = registry.find("allowed").unwrap();
        assert_eq!(allowed.ignored_fields, ["allowed-tools"]);
    }

    #[test]
    fn deep_files_and_symlinks_and_oversize_are_reported() {
        let fixture = Fixture::new();
        put(&fixture.user().join("a/b/c.md"), "глубоко");
        put(&fixture.user().join("big.md"), "x".repeat(64 * 1024 + 1));
        #[cfg(unix)]
        {
            let target = command_file(&fixture.user(), "real", "тело");
            let link = fixture.user().join("link.md");
            std::os::unix::fs::symlink(target, link).unwrap();
        }
        let registry = fixture.discover();
        let names: Vec<_> = registry.loadable().map(|c| c.name.to_owned()).collect();
        assert_eq!(names, ["real"]);
        assert!(
            registry
                .problems
                .iter()
                .any(|p| p.code == "too_deep" && p.path.ends_with("b"))
        );
        assert!(registry.problems.iter().any(|p| p.code == "too_large"));
        #[cfg(unix)]
        assert!(registry.problems.iter().any(|p| p.code == "symlink"));
    }

    #[test]
    fn command_count_is_bounded() {
        let fixture = Fixture::new();
        for index in 0..MAX_COMMANDS + 5 {
            command_file(&fixture.user(), &format!("cmd{index:03}"), "тело");
        }
        let registry = fixture.discover();
        assert_eq!(registry.commands.len(), MAX_COMMANDS);
        assert!(
            registry
                .problems
                .iter()
                .any(|p| p.code == "too_many_commands")
        );
    }

    #[test]
    fn broken_frontmatter_is_reported_and_the_file_is_skipped() {
        let fixture = Fixture::new();
        put(
            &fixture.user().join("broken.md"),
            "---\nname: x\nдвоеточие нет\n",
        );
        command_file(&fixture.user(), "fine", "тело");
        let registry = fixture.discover();
        assert!(registry.find("broken").is_none());
        assert!(registry.find("fine").is_some());
        assert!(
            registry
                .problems
                .iter()
                .any(|p| p.code == "invalid_frontmatter" && p.path.ends_with("broken.md"))
        );
    }

    #[test]
    fn non_utf8_files_are_reported() {
        let fixture = Fixture::new();
        let file = fixture.user().join("bin.md");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, [0xff, 0xfe, 0x00]).unwrap();
        let registry = fixture.discover();
        assert!(registry.problems.iter().any(|p| p.code == "not_utf8"));
    }

    #[test]
    fn empty_bodies_are_reported() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "empty", "   \n\n");
        let registry = fixture.discover();
        assert!(registry.problems.iter().any(|p| p.code == "empty_body"));
    }

    #[test]
    fn menu_lists_loadable_commands_with_scope_suffix() {
        let fixture = Fixture::new();
        command_file(&fixture.user(), "deploy", "пользовательский");
        command_file(&fixture.project(), "audit", "проектный");
        let registry = fixture.discover();
        let menu = registry.menu();
        assert_eq!(
            menu.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            ["/deploy", "/audit"]
        );
        assert!(menu[0].description.ends_with("· пользователь"));
        assert!(menu[1].description.ends_with("· проект"));
        assert!(menu.iter().all(|c| c.custom));
    }
}
