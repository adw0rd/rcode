//! Pure, conservative literal-argv grants. This module performs no execution or I/O.
//!
//! Grammar: ASCII spaces separate arguments. An argument is either an unquoted
//! literal or a whole double-quoted literal. Double quotes may not be embedded,
//! concatenated with other text, or escaped. Empty quoted arguments are allowed
//! except at argv[0]. Canonical display uses double quotes only for empty tokens
//! and tokens containing spaces; otherwise it uses unquoted tokens.
//!
//! Shell operators, expansions, glob syntax, comments, backslashes, single quotes,
//! CMD expansion/escape characters, control/format characters, and non-ASCII
//! whitespace are rejected even inside quotes. Thus POSIX single quoting,
//! backslash escapes, Windows backslash paths, and CMD-specific quoting are not
//! supported. Ordinary Unicode path characters are supported without normalization.
//! This grammar is intentionally narrower than either POSIX shell or Windows CMD.
//!
//! Consumers must execute parsed argv directly, never submit `display()` or the
//! original command to a shell. A match is not execution authorization: mandatory
//! upstream dangerous/deletion checks and the host permission decision remain
//! independent. Model, file, or skill text cannot establish a grant.
//!
//! Deserialization denies unknown fields but deliberately remains separate from
//! semantic validation. Call `validate()` after deserialization. `permits()` also
//! validates on every call, including for directly constructed public values.
//! There is no legacy-string conversion or migration.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub const MAX_COMMAND_BYTES: usize = 16 * 1024;
pub const MAX_TOKENS: usize = 128;
pub const MAX_TOKEN_CHARS: usize = 4096;

/// A prefix of complete argv tokens, not a prefix of command text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellGrant {
    pub argv_prefix: Vec<String>,
}

/// Parse the documented literal-only grammar. Limits include the original input
/// bytes (including spaces/quotes), token count, and Unicode scalar values/token.
/// Any `=` in the executable is conservatively rejected, including assignments.
pub fn literal_argv(command: &str) -> Option<Vec<String>> {
    if command.is_empty() || command.len() > MAX_COMMAND_BYTES || command.chars().any(forbidden) {
        return None;
    }

    let mut chars = command.chars().peekable();
    let mut argv = Vec::new();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            break;
        };
        if argv.len() == MAX_TOKENS {
            return None;
        }
        let mut token = String::new();
        if first == '"' {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some(c) => token.push(c),
                    None => return None,
                }
            }
            if chars.peek().is_some_and(|c| *c != ' ') {
                return None;
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                if c == '"' {
                    return None;
                }
                token.push(c);
                chars.next();
            }
        }
        if token.chars().count() > MAX_TOKEN_CHARS {
            return None;
        }
        argv.push(token);
    }

    let executable = argv.first()?;
    if executable.is_empty() || executable.contains('=') {
        return None;
    }
    Some(argv)
}

impl ShellGrant {
    /// Preserve *all* parsed arguments as the grant prefix. In particular, a
    /// command with arguments never silently becomes an executable-only grant.
    /// Git requires an explicit subcommand immediately after the executable;
    /// option-leading forms such as `git -C repo status` are not grant sources.
    pub fn from_command(command: &str) -> Option<Self> {
        let grant = Self {
            argv_prefix: literal_argv(command)?,
        };
        grant.validate().ok()?;
        Some(grant)
    }

    pub fn permits(&self, command: &str) -> bool {
        if self.validate().is_err() {
            return false;
        }
        literal_argv(command).is_some_and(|argv| argv.starts_with(&self.argv_prefix))
    }

    /// Strict semantic validation for public construction or deserialized data.
    /// The canonical representation must itself fit the command byte limit.
    /// Git is recognized case-insensitively by its final slash-separated filename,
    /// including `git.exe`. Its subcommand must be an ASCII command name rather
    /// than an option. Executable-only grants for other programs remain possible
    /// only when explicitly supplied as such; callers decide whether to allow them.
    pub fn validate(&self) -> Result<()> {
        if self.argv_prefix.is_empty() || self.argv_prefix.len() > MAX_TOKENS {
            bail!("Правило должно содержать от 1 до {MAX_TOKENS} аргументов");
        }
        for token in &self.argv_prefix {
            if token.chars().count() > MAX_TOKEN_CHARS
                || token.chars().any(|c| c == '"' || forbidden(c))
            {
                bail!("Правило содержит неподдерживаемый или слишком длинный аргумент");
            }
        }
        let executable = &self.argv_prefix[0];
        if executable.is_empty() || executable.contains('=') {
            bail!("Имя программы в правиле должно быть непустым и не содержать '='");
        }
        let filename = executable.rsplit('/').next().unwrap_or(executable);
        if filename.eq_ignore_ascii_case("git") || filename.eq_ignore_ascii_case("git.exe") {
            let Some(subcommand) = self.argv_prefix.get(1) else {
                bail!("Правило Git должно включать явную подкоманду");
            };
            if !subcommand
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                || !subcommand
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            {
                bail!("Правило Git должно начинаться с буквальной подкоманды до опций");
            }
        }
        let canonical = self.display();
        if canonical.len() > MAX_COMMAND_BYTES {
            bail!("Запись правила превышает {MAX_COMMAND_BYTES} байт");
        }
        if literal_argv(&canonical).as_ref() != Some(&self.argv_prefix) {
            bail!("Правило не соответствует грамматике буквальных аргументов");
        }
        Ok(())
    }

    /// Canonical literal-argv notation for valid grants, not a shell invocation.
    /// Invalid public values are rendered defensively (controls are escaped),
    /// but rendering neither validates nor repairs them.
    pub fn display(&self) -> String {
        self.argv_prefix
            .iter()
            .map(|token| {
                let quote =
                    token.is_empty() || token.chars().any(|c| c == ' ' || c == '"' || forbidden(c));
                if !quote {
                    return token.clone();
                }
                let mut rendered = String::from("\"");
                for c in token.chars() {
                    if c == '"' || c == '\\' {
                        rendered.push('\\');
                        rendered.push(c);
                    } else if unicode_control(c) {
                        rendered.extend(c.escape_unicode());
                    } else {
                        rendered.push(c);
                    }
                }
                rendered.push('"');
                rendered
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn forbidden(c: char) -> bool {
    unicode_control(c)
        || (c.is_whitespace() && c != ' ')
        || matches!(
            c,
            ';' | '&'
                | '|'
                | '<'
                | '>'
                | '`'
                | '$'
                | '('
                | ')'
                | '{'
                | '}'
                | '\\'
                | '\''
                | '#'
                | '%'
                | '!'
                | '^'
                | '~'
                | '*'
                | '?'
                | '['
                | ']'
        )
}

// Reject C0/C1 controls plus Unicode format/control ranges, including bidi
// controls, zero-width formatting, tag characters and annotation controls.
fn unicode_control(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F |
            0x0890..=0x0891 | 0x08E2 | 0x180E | 0x200B..=0x200F |
            0x202A..=0x202E | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB |
            0x110BD | 0x110CD | 0x13430..=0x13455 | 0x1BCA0..=0x1BCA3 |
            0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_and_cargo_prefixes_are_complete_tokens() {
        let git = ShellGrant::from_command("git status").unwrap();
        assert!(git.permits("git status"));
        assert!(git.permits("git status --short"));
        assert!(!git.permits("git push"));
        assert!(!git.permits("git statusx"));
        assert!(!git.permits("git"));
        let cargo = ShellGrant::from_command("cargo test").unwrap();
        assert!(cargo.permits("cargo test --lib"));
        assert!(!cargo.permits("cargo clean"));
        assert_eq!(cargo.argv_prefix, vec!["cargo", "test"]);
        let specific = ShellGrant::from_command("cargo test --lib").unwrap();
        assert!(!specific.permits("cargo test"));
        assert!(ShellGrant::from_command("git").is_none());
        assert!(ShellGrant::from_command("/usr/bin/git").is_none());
        assert!(ShellGrant::from_command("GIT.EXE").is_none());
        assert!(ShellGrant::from_command("git -C repo status").is_none());
        assert!(ShellGrant::from_command("git \"\"").is_none());
        assert!(
            ShellGrant::from_command("cargo")
                .unwrap()
                .permits("cargo test")
        );
    }

    #[test]
    fn quotes_spaces_and_canonical_round_trip() {
        let command = "  tool   \"a b\" \"\" plain  ";
        assert_eq!(
            literal_argv(command).unwrap(),
            vec!["tool", "a b", "", "plain"]
        );
        let grant = ShellGrant::from_command(command).unwrap();
        assert_eq!(grant.display(), "tool \"a b\" \"\" plain");
        assert_eq!(literal_argv(&grant.display()).unwrap(), grant.argv_prefix);
        assert!(grant.permits("\"tool\" \"a b\" \"\" plain extra"));
        for bad in [
            "tool \"unfinished",
            "tool a\"b\"",
            "tool \"a\"b",
            "tool \"a\"\"b\"",
            "tool 'a b'",
            "\"\" arg",
        ] {
            assert!(literal_argv(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn shell_syntax_is_rejected_even_inside_quotes() {
        let grant = ShellGrant::from_command("git status").unwrap();
        for bad in [
            "git status; git push",
            "git status && git push",
            "git status | cat",
            "git status > out",
            "git status < in",
            "git $(whoami)",
            "git `id`",
            "X=1 git status",
            "\"X=1\" git status",
            "git status # comment",
            "git status\n",
            "git\tstatus",
            "git status\0",
            "git {status}",
            "git (status)",
            "git status *",
            "git status ?",
            "git status [a]",
            "git status ~",
            "git status %PATH%",
            "git status !PATH!",
            "git status ^x",
            "git \"$HOME\"",
            "git \"a;b\"",
        ] {
            assert!(literal_argv(bad).is_none(), "accepted {bad:?}");
            assert!(!grant.permits(bad));
        }
        // An assignment-shaped *argument* is literal, not an executable prefix.
        assert!(literal_argv("tool KEY=value").is_some());
    }

    #[test]
    fn unicode_paths_but_not_hidden_controls() {
        let grant = ShellGrant::from_command("\"/工具/é tool\" \"文档/文件 名\"").unwrap();
        assert!(grant.validate().is_ok());
        assert!(grant.permits("\"/工具/é tool\" \"文档/文件 名\" extra"));
        for c in [
            '\u{202e}', '\u{2066}', '\u{061c}', '\u{200b}', '\u{feff}', '\u{00ad}', '\u{85}',
            '\u{a0}', '\u{2028}',
        ] {
            assert!(literal_argv(&format!("tool \"a{c}b\"")).is_none());
        }
        let composed = ShellGrant::from_command("tool é").unwrap();
        assert!(!composed.permits("tool e\u{301}"));
    }

    #[test]
    fn windows_backslashes_and_escape_forms_are_refused() {
        for bad in [
            r"C:\Windows\tool.exe arg",
            r#""C:\Program Files\tool.exe" arg"#,
            r"tool a\ b",
            r#"tool "a\"b""#,
        ] {
            assert!(literal_argv(bad).is_none(), "accepted {bad:?}");
        }
        assert!(literal_argv("\"C:/Program Files/tool.exe\" arg").is_some());
    }

    #[test]
    fn empty_and_size_boundaries() {
        for empty in ["", " ", "    "] {
            assert!(literal_argv(empty).is_none());
        }
        let token = "x".repeat(MAX_TOKEN_CHARS);
        assert!(literal_argv(&format!("tool {token}")).is_some());
        assert!(literal_argv(&format!("tool {token}x")).is_none());
        let unicode_token = "界".repeat(MAX_TOKEN_CHARS);
        assert!(literal_argv(&format!("tool {unicode_token}")).is_some());
        assert!(literal_argv(&format!("tool {unicode_token}界")).is_none());
        let tokens = vec!["x"; MAX_TOKENS].join(" ");
        assert!(literal_argv(&tokens).is_some());
        assert!(literal_argv(&format!("{tokens} x")).is_none());
        let exact = format!("tool{}", " ".repeat(MAX_COMMAND_BYTES - 4));
        assert!(literal_argv(&exact).is_some());
        assert!(literal_argv(&(exact + " ")).is_none());
        let oversized = ShellGrant {
            argv_prefix: vec![token; 4],
        };
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn malformed_public_and_deserialized_grants_fail_closed() {
        for argv_prefix in [
            vec![],
            vec![String::new()],
            vec!["X=1".into()],
            vec!["git".into()],
            vec!["tool;other".into()],
            vec!["tool".into(), "a\"b".into()],
            vec!["tool".into(), "a\nb".into()],
            vec!["x".into(); MAX_TOKENS + 1],
        ] {
            let grant = ShellGrant { argv_prefix };
            assert!(grant.validate().is_err());
            assert!(!grant.permits("tool anything"));
            assert!(!grant.display().contains('\n'));
        }
        let invalid: ShellGrant = serde_json::from_str(r#"{"argv_prefix":[]}"#).unwrap();
        assert!(invalid.validate().is_err());
        assert!(!invalid.permits("anything"));
        assert!(
            serde_json::from_str::<ShellGrant>(r#"{"argv_prefix":["tool"],"extra":true}"#).is_err()
        );
        assert!(serde_json::from_str::<ShellGrant>(r#""git""#).is_err());
        assert!(serde_json::from_str::<ShellGrant>(r#"{"argv_prefix":"git status"}"#).is_err());
        let valid = ShellGrant::from_command("git status").unwrap();
        let decoded: ShellGrant =
            serde_json::from_str(&serde_json::to_string(&valid).unwrap()).unwrap();
        assert!(decoded.validate().is_ok());
        assert_eq!(decoded, valid);
    }

    #[test]
    fn parsing_is_not_execution_or_danger_classification() {
        // These are just strings. No subprocess or filesystem fixture is needed.
        assert!(literal_argv("nonexistent-program literal-argument").is_some());
        assert!(literal_argv("tool $(touch marker)").is_none());
        // Deletion classification is explicitly upstream, not silently added here.
        let grant = ShellGrant::from_command("rm").unwrap();
        assert!(grant.permits("rm file"));
    }
}
