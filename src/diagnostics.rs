//! Pure, bounded diagnostic parsing and command discovery. Nothing is executed.
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, io::Read, path::Path};

const TEXT_LIMIT: usize = 4 * 1024 * 1024;
const MESSAGE_LIMIT: usize = 4096;
const DIAGNOSTIC_LIMIT: usize = 1000;
const MANIFEST_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parser {
    Rust,
    Pytest,
    TypeScript,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub parser: Parser,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub unparsed: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCommand {
    pub id: String,
    pub label: String,
    pub argv: Vec<String>,
    pub parser: Parser,
}

fn prefix(s: &str, limit: usize) -> &str {
    let mut n = s.len().min(limit);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

fn push(report: &mut DiagnosticReport, mut diagnostic: Diagnostic) {
    if diagnostic.message.len() > MESSAGE_LIMIT {
        diagnostic.message = prefix(&diagnostic.message, MESSAGE_LIMIT).to_owned();
        report.truncated = true;
    }
    if report.diagnostics.len() == DIAGNOSTIC_LIMIT {
        report.truncated = true;
    } else {
        report.diagnostics.push(diagnostic);
    }
}

fn diagnostic(
    file: Option<String>,
    line: Option<u64>,
    column: Option<u64>,
    severity: &str,
    message: &str,
) -> Diagnostic {
    Diagnostic {
        file,
        line,
        column,
        severity: severity.into(),
        message: message.into(),
    }
}

/// Success is deliberately conservative; plain text and missing status cannot prove it.
pub fn parse(
    parser: Parser,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> Result<DiagnosticReport> {
    let out = prefix(stdout, TEXT_LIMIT);
    let err = prefix(stderr, TEXT_LIMIT - out.len());
    let mut report = DiagnosticReport {
        parser,
        exit_code,
        success: false,
        diagnostics: vec![],
        unparsed: false,
        truncated: out.len() != stdout.len() || err.len() != stderr.len(),
    };
    if parser == Parser::Raw {
        report.unparsed = true;
        return Ok(report);
    }
    let ts = Regex::new(r"^(?:(.+)\((\d+),(\d+)\): |)(error) (TS\d+): (.+)$")?;
    let py_location = Regex::new(r"^(.+\.py):(\d+):(?:\s*(.*))?$")?;
    let py_failed = Regex::new(r"^(?:FAILED|ERROR) (.+?\.py)(?:::[^ ]+)?(?: - (.*))?$")?;
    let summary = Regex::new(
        r"^(?:=+\s*)?((?:\d+ (?:passed|failed|error|errors|skipped|deselected|xfailed|xpassed)(?:, )?)+) in [0-9.]+(?:s| seconds?)(?:\s*=+)?$",
    )?;
    let bad_summary = Regex::new(r"\d+ (?:failed|errors?|xpassed)\b")?;
    let mut terminal =
        parser == Parser::TypeScript && out.trim().is_empty() && err.trim().is_empty();
    let mut failure = false;
    let mut recognized = terminal;
    for text in [out, err] {
        for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
            match parser {
                Parser::Rust => {
                    let Ok(value) = serde_json::from_str::<Value>(line) else {
                        report.unparsed = true;
                        continue;
                    };
                    match value.get("reason").and_then(Value::as_str) {
                        Some("build-finished") => {
                            if let Some(ok) = value.get("success").and_then(Value::as_bool) {
                                recognized = true;
                                terminal |= ok;
                                failure |= !ok;
                            } else {
                                report.unparsed = true;
                            }
                        }
                        Some("compiler-message") => {
                            let msg = &value["message"];
                            let (Some(level), Some(message)) =
                                (msg["level"].as_str(), msg["message"].as_str())
                            else {
                                report.unparsed = true;
                                continue;
                            };
                            recognized = true;
                            failure |= matches!(level, "error" | "failure-note" | "ice");
                            let span = msg["spans"].as_array().and_then(|spans| {
                                spans
                                    .iter()
                                    .find(|s| s["is_primary"].as_bool() == Some(true))
                            });
                            push(
                                &mut report,
                                diagnostic(
                                    span.and_then(|s| s["file_name"].as_str())
                                        .map(str::to_owned),
                                    span.and_then(|s| s["line_start"].as_u64()),
                                    span.and_then(|s| s["column_start"].as_u64()),
                                    level,
                                    message,
                                ),
                            );
                        }
                        Some("compiler-artifact" | "build-script-executed") => {
                            recognized = true;
                        }
                        _ => {
                            report.unparsed = true;
                        }
                    }
                }
                Parser::Pytest => {
                    if let Some(c) = summary.captures(line) {
                        recognized = true;
                        terminal = true;
                        failure |= bad_summary.is_match(&c[1]);
                    } else if let Some(c) = py_failed.captures(line) {
                        recognized = true;
                        failure = true;
                        push(
                            &mut report,
                            diagnostic(
                                Some(c[1].into()),
                                None,
                                None,
                                "error",
                                c.get(2).map_or(line, |m| m.as_str()),
                            ),
                        );
                    } else if let Some(c) = py_location.captures(line) {
                        recognized = true;
                        failure = true;
                        push(
                            &mut report,
                            diagnostic(
                                Some(c[1].into()),
                                c[2].parse().ok(),
                                None,
                                "error",
                                c.get(3)
                                    .filter(|m| !m.as_str().is_empty())
                                    .map_or(line, |m| m.as_str()),
                            ),
                        );
                    } else if line.starts_with("E ")
                        || line.contains("ERROR collecting ")
                        || line.contains("Interrupted:")
                        || line.contains("INTERNALERROR>")
                    {
                        recognized = true;
                        failure = true;
                        push(&mut report, diagnostic(None, None, None, "error", line));
                    } else {
                        report.unparsed = true;
                    }
                }
                Parser::TypeScript => {
                    if let Some(c) = ts.captures(line) {
                        recognized = true;
                        failure = true;
                        push(
                            &mut report,
                            diagnostic(
                                c.get(1).map(|m| m.as_str().into()),
                                c.get(2).and_then(|m| m.as_str().parse().ok()),
                                c.get(3).and_then(|m| m.as_str().parse().ok()),
                                "error",
                                &format!("{}: {}", &c[5], &c[6]),
                            ),
                        );
                    } else {
                        report.unparsed = true;
                    }
                    // Unknown nonempty text remains unparsed, even with exit zero.
                }
                Parser::Raw => unreachable!(),
            }
        }
    }
    report.unparsed |= !recognized;
    report.success = exit_code == Some(0) && terminal && !failure && !report.truncated;
    Ok(report)
}

fn marker(root: &Path, name: &str) -> Result<Option<String>> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
    let dir = crate::instructions::root_dir(root)?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match dir.open_with(name, &options) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("Не удалось открыть маркер проекта"),
    };
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file() && meta.len() <= MANIFEST_LIMIT as u64,
        "Недопустимый тип или размер манифеста"
    );
    let mut bytes = Vec::new();
    file.take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= MANIFEST_LIMIT, "Превышен размер манифеста");
    Ok(Some(
        String::from_utf8(bytes).context("Манифест должен содержать UTF-8")?,
    ))
}

fn sections(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter_map(|line| {
            let line = line.split(" #").next().unwrap_or(line).trim();
            line.strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .map(|s| s.trim_matches(['[', ']']))
        })
        .collect()
}

/// Reads only bounded local markers. Returned argv is descriptive, never executed.
/// Marker discovery neither parses a partial TOML dialect nor claims the project is valid.
pub fn discover(root: &Path) -> Result<Vec<DiagnosticCommand>> {
    crate::instructions::root_dir(root)?;
    if !fs::metadata(root)
        .context("Не удалось прочитать каталог")?
        .is_dir()
    {
        bail!("Ожидался каталог проекта");
    }
    let mut commands = Vec::new();
    let mut add = |id: &str, label: &str, argv: Vec<String>, parser| {
        if commands.len() < 8 {
            commands.push(DiagnosticCommand {
                id: id.into(),
                label: label.into(),
                argv,
                parser,
            });
        }
    };
    if let Some(text) = marker(root, "Cargo.toml")? {
        let sections = sections(&text);
        if !sections
            .iter()
            .any(|s| *s == "package" || *s == "workspace")
        {
            bail!("В Cargo.toml отсутствует package или workspace");
        }
        add(
            "cargo-check",
            "Cargo check",
            vec![
                "cargo".into(),
                "check".into(),
                "--message-format=json".into(),
            ],
            Parser::Rust,
        );
    }
    let mut python = false;
    if let Some(text) = marker(root, "pyproject.toml")? {
        python = sections(&text).contains(&"tool.pytest.ini_options");
    }
    if let Some(text) = marker(root, "pytest.ini")? {
        if !sections(&text).contains(&"pytest") {
            bail!("В pytest.ini отсутствует секция pytest");
        }
        python = true;
    }
    if python {
        add(
            "pytest",
            "Pytest",
            vec!["python3".into(), "-m".into(), "pytest".into()],
            Parser::Pytest,
        );
    }
    if let Some(text) = marker(root, "package.json")? {
        let json: Value = serde_json::from_str(&text).context("Некорректный package.json")?;
        if !json.is_object() {
            bail!("package.json должен быть объектом");
        }
        if let Some(scripts) = json.get("scripts") {
            let scripts = scripts
                .as_object()
                .context("scripts должен быть объектом")?;
            if scripts.values().any(|v| !v.is_string()) {
                bail!("Скрипт должен быть строкой");
            }
            for name in ["check", "typecheck", "test"] {
                if scripts.contains_key(name) {
                    add(
                        &format!("npm-{name}"),
                        &format!("npm run {name}"),
                        vec!["npm".into(), "run".into(), name.into()],
                        Parser::Raw,
                    );
                }
            }
        }
    }
    if let Some(text) = marker(root, "tsconfig.json")? {
        if text.trim().is_empty() {
            bail!("Пустой tsconfig.json");
        }
        let argv = vec!["tsc".into(), "--pretty".into(), "false".into()];
        add("tsc", "TypeScript check", argv, Parser::TypeScript);
    }
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rust_nested_and_failed_finish() {
        let text = concat!(
            r#"{"reason":"compiler-message","message":{"level":"warning","message":"осторожно","spans":[{"is_primary":true,"file_name":"src/я.rs","line_start":2,"column_start":3}]}}"#,
            "\n",
            r#"{"reason":"build-finished","success":false}"#
        );
        let r = parse(Parser::Rust, text, "", Some(0)).unwrap();
        assert!(!r.success);
        assert_eq!(r.diagnostics[0].file.as_deref(), Some("src/я.rs"));
        assert_eq!(r.diagnostics[0].column, Some(3));
        assert!(
            parse(
                Parser::Rust,
                r#"{"reason":"build-finished","success":true}"#,
                "",
                Some(0)
            )
            .unwrap()
            .success
        );
    }
    #[test]
    fn status_and_malformed_never_forge_success() {
        for parser in [
            Parser::Rust,
            Parser::Pytest,
            Parser::TypeScript,
            Parser::Raw,
        ] {
            for status in [None, Some(1), Some(0)] {
                assert_eq!(
                    parse(parser, "", "", status).unwrap().success,
                    parser == Parser::TypeScript && status == Some(0)
                );
                assert!(!parse(parser, "PASS\n{broken}", "", status).unwrap().success);
            }
        }
        for status in [None, Some(2)] {
            assert!(
                !parse(Parser::Pytest, "1 passed in 0.01s", "", status)
                    .unwrap()
                    .success
            );
        }
        assert!(
            parse(Parser::Raw, "error TS1234: bad", "", Some(0))
                .unwrap()
                .diagnostics
                .is_empty()
        );
    }
    #[test]
    fn pytest_unicode_and_collection() {
        let r = parse(
            Parser::Pytest,
            "FAILED tests/я.py::test_я - ошибка\n1 failed in 0.12s",
            "",
            Some(1),
        )
        .unwrap();
        assert_eq!(r.diagnostics[0].message, "ошибка");
        assert!(!r.success);
        let r = parse(
            Parser::Pytest,
            "tests/a.py:12: ImportError: нет\nERROR collecting tests/a.py\n1 passed in 0.1s",
            "",
            Some(0),
        )
        .unwrap();
        assert!(!r.success);
        assert_eq!(r.diagnostics[0].line, Some(12));
        assert!(
            parse(
                Parser::Pytest,
                "=== 2 passed, 1 skipped in 0.20s ===",
                "",
                Some(0)
            )
            .unwrap()
            .success
        );
    }
    #[test]
    fn typescript_locations_and_global() {
        let r = parse(
            Parser::TypeScript,
            "C:/я.ts(12,3): error TS1234: ошибка\nerror TS18003: No inputs",
            "",
            Some(2),
        )
        .unwrap();
        assert_eq!(r.diagnostics.len(), 2);
        assert_eq!(r.diagnostics[0].line, Some(12));
        assert_eq!(r.diagnostics[1].file, None);
        assert!(!r.unparsed);
        assert!(
            parse(Parser::TypeScript, "unsupported", "", Some(0))
                .unwrap()
                .unparsed
        );
    }
    #[test]
    fn limits_are_utf8_safe_and_explicit() {
        let line = format!("error TS1234: {}\n", "я".repeat(3000));
        let r = parse(Parser::TypeScript, &line.repeat(1001), "", Some(1)).unwrap();
        assert!(r.truncated);
        assert!(r.diagnostics.len() <= DIAGNOSTIC_LIMIT);
        assert!(
            r.diagnostics
                .iter()
                .all(|d| d.message.len() <= MESSAGE_LIMIT)
        );
        let r = parse(
            Parser::TypeScript,
            &"error TS1: x\n".repeat(1001),
            "",
            Some(1),
        )
        .unwrap();
        assert_eq!(r.diagnostics.len(), 1000);
        assert!(r.truncated);
        assert!(
            parse(Parser::Raw, &"я".repeat(TEXT_LIMIT), "", None)
                .unwrap()
                .truncated
        );
    }
    #[test]
    fn discovery_is_bounded_and_never_executes_scripts() {
        let temp = tempfile::tempdir().unwrap();
        // Canonicalization keeps this test usable where the OS temp directory is a symlink.
        let root = temp.path().canonicalize().unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"scripts":{"check":"touch OWNED; curl invalid","test":"exit 99"}}"#,
        )
        .unwrap();
        fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
        fs::write(root.join("tsconfig.json"), "{}").unwrap();
        let commands = discover(&root).unwrap();
        assert_eq!(
            commands.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["npm-check", "npm-test", "tsc"]
        );
        assert_eq!(commands[2].argv, ["tsc", "--pretty", "false"]);
        assert!(!root.join("OWNED").exists());
        assert_eq!(discover(&root).unwrap(), commands);
        fs::write(root.join("pytest.ini"), "[pytest]\naddopts = -q\n").unwrap();
        assert!(
            discover(&root)
                .unwrap()
                .iter()
                .any(|c| c.parser == Parser::Pytest)
        );
        fs::write(root.join("package.json"), "{").unwrap();
        assert!(discover(&root).is_err());
        fs::write(root.join("package.json"), " ".repeat(MANIFEST_LIMIT + 1)).unwrap();
        assert!(discover(&root).is_err());
        fs::write(root.join("Cargo.toml"), "not a manifest").unwrap();
        assert!(discover(&root).is_err());
    }
}
