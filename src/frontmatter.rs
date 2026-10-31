#![allow(dead_code)]

use std::collections::BTreeMap;

pub(crate) const MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frontmatter {
    pub(crate) fields: BTreeMap<String, String>,
    pub(crate) nested_keys: Vec<String>,
    pub(crate) body_offset: usize,
    pub(crate) body_start_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrontmatterError {
    #[error("файл не начинается с frontmatter (---)")]
    Missing,
    #[error("frontmatter не закрыт строкой ---")]
    Unterminated,
    #[error("frontmatter больше 16 КиБ")]
    TooLarge,
    #[error("повтор ключа {key} в строке {line}")]
    DuplicateKey { key: String, line: usize },
    #[error("неверная строка {line}")]
    InvalidLine { line: usize },
    #[error("неверное экранирование в поле {key} в строке {line}")]
    InvalidEscape { key: String, line: usize },
}

impl FrontmatterError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unterminated => "unterminated",
            Self::TooLarge => "too_large",
            Self::DuplicateKey { .. } => "duplicate_key",
            Self::InvalidLine { .. } => "invalid_line",
            Self::InvalidEscape { .. } => "invalid_escape",
        }
    }
}

struct Line<'a> {
    number: usize,
    text: &'a str,
}

pub(crate) fn parse(text: &str) -> Result<Frontmatter, FrontmatterError> {
    let start = if text.starts_with('\u{feff}') { 3 } else { 0 };
    let mut offset = start;
    let mut number = 0;
    let mut lines = Vec::new();
    let mut opened = false;
    while offset <= text.len() {
        let rest = &text[offset..];
        let (raw, next) = match rest.find('\n') {
            Some(index) => (&rest[..index], offset + index + 1),
            None => (rest, text.len() + 1),
        };
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        number += 1;
        if !opened {
            if line.trim_end() != "---" {
                return Err(FrontmatterError::Missing);
            }
            opened = true;
        } else {
            if offset - start > MAX_BYTES {
                return Err(FrontmatterError::TooLarge);
            }
            if line.trim_end() == "---" {
                let mut frontmatter = parse_lines(&lines)?;
                frontmatter.body_offset = next.min(text.len());
                frontmatter.body_start_line = number + 1;
                return Ok(frontmatter);
            }
            lines.push(Line { number, text: line });
        }
        offset = next;
    }
    if opened {
        Err(FrontmatterError::Unterminated)
    } else {
        Err(FrontmatterError::Missing)
    }
}

fn blank(line: &str) -> bool {
    line.trim().is_empty()
}

fn indented(line: &str) -> bool {
    line.starts_with([' ', '\t'])
}

fn split_key(line: &str) -> Option<(&str, &str)> {
    let end = line
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(line.len());
    let key = &line[..end];
    if key.is_empty() || key.starts_with('-') {
        return None;
    }
    let value = line[end..].strip_prefix(':')?;
    if !value.is_empty() && !value.starts_with([' ', '\t']) {
        return None;
    }
    Some((key, value.trim()))
}

fn parse_lines(lines: &[Line]) -> Result<Frontmatter, FrontmatterError> {
    let mut fields = BTreeMap::new();
    let mut nested_keys: Vec<String> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = &lines[index];
        index += 1;
        if blank(line.text) || line.text.trim_start().starts_with('#') {
            continue;
        }
        let invalid = FrontmatterError::InvalidLine { line: line.number };
        if line.text.starts_with([' ', '\t', '-']) {
            return Err(invalid);
        }
        let (key, value) = split_key(line.text).ok_or(invalid.clone())?;
        if fields.contains_key(key) || nested_keys.iter().any(|known| known == key) {
            return Err(FrontmatterError::DuplicateKey {
                key: key.to_owned(),
                line: line.number,
            });
        }
        let value = if value.starts_with('#') { "" } else { value };
        if value.starts_with(['|', '>']) {
            let (folded, chomp) = block_header(value).ok_or(invalid)?;
            let end = scan(lines, index, |text| blank(text) || indented(text));
            fields.insert(key.to_owned(), block(&lines[index..end], folded, chomp));
            index = end;
        } else if value.is_empty() {
            let end = scan(lines, index, |text| {
                blank(text) || text.starts_with([' ', '\t', '-'])
            });
            if lines[index..end].iter().any(|line| !blank(line.text)) {
                nested_keys.push(key.to_owned());
            } else {
                fields.insert(key.to_owned(), String::new());
            }
            index = end;
        } else if value.starts_with(['[', '{']) {
            index = scan(lines, index, |text| blank(text) || indented(text));
            nested_keys.push(key.to_owned());
        } else if let Some(quoted) = value.strip_prefix('"') {
            let strict = matches!(key, "name" | "description");
            let parsed = double_quoted(quoted, strict).map_err(|error| match error {
                QuoteError::Line => invalid.clone(),
                QuoteError::Escape => FrontmatterError::InvalidEscape {
                    key: key.to_owned(),
                    line: line.number,
                },
            })?;
            fields.insert(key.to_owned(), parsed);
        } else if let Some(quoted) = value.strip_prefix('\'') {
            fields.insert(key.to_owned(), single_quoted(quoted).ok_or(invalid)?);
        } else {
            let mut parsed = strip_comment(value).to_owned();
            let end = scan(lines, index, |text| blank(text) || indented(text));
            let mut pending_breaks = 0;
            for continuation in &lines[index..end] {
                let text = continuation.text.trim();
                if text.is_empty() {
                    pending_breaks += 1;
                    continue;
                }
                if text.starts_with('#') {
                    continue;
                }
                let text = strip_comment(text);
                if text.contains(": ") || text.ends_with(':') {
                    return Err(FrontmatterError::InvalidLine {
                        line: continuation.number,
                    });
                }
                if pending_breaks == 0 {
                    parsed.push(' ');
                } else {
                    parsed.push_str(&"\n".repeat(pending_breaks));
                }
                pending_breaks = 0;
                parsed.push_str(text);
            }
            fields.insert(key.to_owned(), parsed);
            index = end;
        }
    }
    Ok(Frontmatter {
        fields,
        nested_keys,
        body_offset: 0,
        body_start_line: 0,
    })
}

fn scan(lines: &[Line], start: usize, belongs: impl Fn(&str) -> bool) -> usize {
    lines[start..]
        .iter()
        .position(|line| !belongs(line.text))
        .map_or(lines.len(), |offset| start + offset)
}

fn strip_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let end = (1..bytes.len())
        .find(|&index| bytes[index] == b'#' && matches!(bytes[index - 1], b' ' | b'\t'))
        .unwrap_or(bytes.len());
    value[..end].trim_end()
}

fn only_comment(rest: &str) -> bool {
    let trimmed = rest.trim_start();
    trimmed.is_empty() || (trimmed.starts_with('#') && trimmed.len() < rest.len())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Chomp {
    Clip,
    Strip,
    Keep,
}

fn block_header(value: &str) -> Option<(bool, Chomp)> {
    let folded = value.starts_with('>');
    let rest = &value[1..];
    let (chomp, rest) = match rest.chars().next() {
        Some('-') => (Chomp::Strip, &rest[1..]),
        Some('+') => (Chomp::Keep, &rest[1..]),
        _ => (Chomp::Clip, rest),
    };
    only_comment(rest).then_some((folded, chomp))
}

fn block(lines: &[Line], folded: bool, chomp: Chomp) -> String {
    let indent = lines
        .iter()
        .filter(|line| !blank(line.text))
        .map(|line| line.text.len() - line.text.trim_start_matches([' ', '\t']).len())
        .min()
        .unwrap_or(0);
    let content: Vec<&str> = lines
        .iter()
        .map(|line| {
            if blank(line.text) {
                ""
            } else {
                &line.text[indent..]
            }
        })
        .collect();
    let used = content
        .iter()
        .rposition(|line| !line.is_empty())
        .map_or(0, |index| index + 1);
    let trailing = content.len() - used;
    let content = &content[..used];
    let mut out = String::new();
    if folded {
        let mut previous: Option<&str> = None;
        let mut breaks = 0;
        for line in content {
            if line.is_empty() {
                breaks += 1;
                continue;
            }
            if let Some(previous) = previous {
                if breaks > 0 {
                    out.push_str(&"\n".repeat(breaks));
                } else if indented(previous) || indented(line) {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
            }
            breaks = 0;
            out.push_str(line);
            previous = Some(line);
        }
    } else {
        out = content.join("\n");
    }
    if used > 0 {
        match chomp {
            Chomp::Strip => {}
            Chomp::Clip => out.push('\n'),
            Chomp::Keep => out.push_str(&"\n".repeat(trailing + 1)),
        }
    } else if chomp == Chomp::Keep {
        out.push_str(&"\n".repeat(trailing));
    }
    out
}

enum QuoteError {
    Line,
    Escape,
}

fn single_quoted(rest: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = rest.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        if c == '\'' {
            if chars.peek().is_some_and(|&(_, next)| next == '\'') {
                chars.next();
                out.push('\'');
                continue;
            }
            return only_comment(&rest[index + 1..]).then_some(out);
        }
        out.push(c);
    }
    None
}

fn hex4(text: &str) -> Option<u32> {
    let digits = text.get(..4)?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

fn unicode_escape(text: &str) -> Option<(char, usize)> {
    let first = hex4(text)?;
    if (0xD800..0xDC00).contains(&first) {
        let low = hex4(text.get(4..)?.strip_prefix("\\u")?)?;
        if !(0xDC00..0xE000).contains(&low) {
            return None;
        }
        let code = 0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00);
        return char::from_u32(code).map(|c| (c, 10));
    }
    char::from_u32(first).map(|c| (c, 4))
}

fn double_quoted(rest: &str, strict: bool) -> Result<String, QuoteError> {
    let mut out = String::new();
    let mut index = 0;
    while let Some(c) = rest[index..].chars().next() {
        index += c.len_utf8();
        match c {
            '"' => {
                return if only_comment(&rest[index..]) {
                    Ok(out)
                } else {
                    Err(QuoteError::Line)
                };
            }
            '\\' => {
                let Some(escape) = rest[index..].chars().next() else {
                    return Err(QuoteError::Line);
                };
                let simple = match escape {
                    '\\' => Some('\\'),
                    '"' => Some('"'),
                    '/' => Some('/'),
                    'n' => Some('\n'),
                    't' => Some('\t'),
                    'r' => Some('\r'),
                    _ => None,
                };
                if let Some(value) = simple {
                    out.push(value);
                    index += 1;
                } else if let Some((value, used)) = (escape == 'u')
                    .then(|| unicode_escape(&rest[index + 1..]))
                    .flatten()
                {
                    out.push(value);
                    index += 1 + used;
                } else if strict {
                    return Err(QuoteError::Escape);
                } else {
                    out.push('\\');
                }
            }
            _ => out.push(c),
        }
    }
    Err(QuoteError::Line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(frontmatter: &'a Frontmatter, key: &str) -> &'a str {
        frontmatter
            .fields
            .get(key)
            .unwrap_or_else(|| panic!("нет поля {key}"))
    }

    #[test]
    fn superpowers_like_quoted_fields() {
        let text = "---\nname: brainstorming\ndescription: \"You MUST use this before any creative work - creating features, building components. Explores intent: \\\"why\\\" first.\"\n---\n\n# Brainstorming\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "name"), "brainstorming");
        assert_eq!(
            field(&parsed, "description"),
            "You MUST use this before any creative work - creating features, building components. Explores intent: \"why\" first."
        );
        assert!(parsed.nested_keys.is_empty());
        assert_eq!(&text[parsed.body_offset..], "\n# Brainstorming\n");
        assert_eq!(parsed.body_start_line, 5);
    }

    #[test]
    fn gstack_like_nested_structures_are_only_named() {
        let text = "---\nname: review\npreamble-tier: 4\nversion: 1.0.0\ndescription: |\n  Pre-landing PR review. Analyzes diff against the base branch.\n  Use when asked to \"review this PR\".\nallowed-tools:\n  - Bash\n  - Read\n  - Edit\ntriggers:\n- review pr\n- check my diff\nhooks:\n  PreToolUse:\n    - matcher: \"Bash\"\n      hooks:\n        - type: command\n          command: \"bash ${CLAUDE_SKILL_DIR}/bin/check-careful.sh\"\n          statusMessage: \"Checking for destructive commands...\"\ngbrain:\n  context_queries:\n    - id: prior\n      kind: vector\n      query: \"{repo_slug} review\"\n  schema: 1\nmetadata: {short-description: Review, tags: [a, b]}\n---\n# Review\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "name"), "review");
        assert_eq!(field(&parsed, "preamble-tier"), "4");
        assert_eq!(field(&parsed, "version"), "1.0.0");
        assert_eq!(
            field(&parsed, "description"),
            "Pre-landing PR review. Analyzes diff against the base branch.\nUse when asked to \"review this PR\".\n"
        );
        assert_eq!(
            parsed.nested_keys,
            ["allowed-tools", "triggers", "hooks", "gbrain", "metadata"]
        );
        for key in &parsed.nested_keys {
            assert!(!parsed.fields.contains_key(key));
        }
        assert_eq!(&text[parsed.body_offset..], "# Review\n");
    }

    #[test]
    fn literal_block_keeps_lines() {
        let text = "---\nname: a\ndescription: |\n  First line.\n    Indented line.\n\n  After blank.\n---\nbody";
        let parsed = parse(text).unwrap();
        assert_eq!(
            field(&parsed, "description"),
            "First line.\n  Indented line.\n\nAfter blank.\n"
        );
    }

    #[test]
    fn folded_block_joins_single_breaks() {
        let text = "---\nname: a\ndescription: >\n  Use when the user\n  asks for a review.\n\n  Second paragraph.\nwhen_to_use: >\n  When code\n  changes.\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(
            field(&parsed, "description"),
            "Use when the user asks for a review.\nSecond paragraph.\n"
        );
        assert_eq!(field(&parsed, "when_to_use"), "When code changes.\n");
    }

    #[test]
    fn block_chomping_indicators() {
        let text = "---\nstrip: |-\n  a\n  b\n\nkeep: >+\n  c\n  d\n\n\nclip: |\n  e\n\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "strip"), "a\nb");
        assert_eq!(field(&parsed, "keep"), "c d\n\n\n");
        assert_eq!(field(&parsed, "clip"), "e\n");
    }

    #[test]
    fn tabs_inside_block() {
        let text = "---\nname: a\ndescription: |\n\tStep one\n\t\tnested\tvalue\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "description"), "Step one\n\tnested\tvalue\n");
    }

    #[test]
    fn plain_value_with_parentheses_and_colon() {
        let text = "---\nallowed-tools: Bash(agtermctl *)\nother: Bash(git log:*), Read\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "allowed-tools"), "Bash(agtermctl *)");
        assert_eq!(field(&parsed, "other"), "Bash(git log:*), Read");
    }

    #[test]
    fn blank_line_before_closing_delimiter() {
        let text = "---\nname: _gstack-command\ndescription: Internal command.\n\n---\nBody\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "name"), "_gstack-command");
        assert_eq!(&text[parsed.body_offset..], "Body\n");
        assert_eq!(parsed.body_start_line, 6);
    }

    #[test]
    fn crlf_line_endings() {
        let text = "---\r\nname: a\r\ndescription: |\r\n  one\r\n  two\r\n---\r\nBody\r\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "name"), "a");
        assert_eq!(field(&parsed, "description"), "one\ntwo\n");
        assert_eq!(&text[parsed.body_offset..], "Body\r\n");
        assert_eq!(parsed.body_start_line, 7);
    }

    #[test]
    fn byte_order_mark_is_skipped_and_offset_counts_it() {
        let text = "\u{feff}---\nname: a\n---\nBody";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "name"), "a");
        assert_eq!(parsed.body_offset, "\u{feff}---\nname: a\n---\n".len());
        assert_eq!(&text[parsed.body_offset..], "Body");
        assert_eq!(parsed.body_start_line, 4);
    }

    #[test]
    fn closing_delimiter_at_end_of_text() {
        let text = "---\nname: a\n---";
        let parsed = parse(text).unwrap();
        assert_eq!(parsed.body_offset, text.len());
        assert_eq!(parsed.body_start_line, 4);
    }

    #[test]
    fn plain_scalar_continuation_is_folded() {
        let text = "---\ndescription: Use this skill\n  when the task\n  is large.\nname: a\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(
            field(&parsed, "description"),
            "Use this skill when the task is large."
        );
        assert_eq!(field(&parsed, "name"), "a");
    }

    #[test]
    fn flow_collections_are_nested_even_across_lines() {
        let text = "---\nallowed-tools: [Bash, Read,\n  Edit]\nmetadata: {a: 1}\nname: a\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(parsed.nested_keys, ["allowed-tools", "metadata"]);
        assert_eq!(field(&parsed, "name"), "a");
    }

    #[test]
    fn comments_and_empty_values() {
        let text = "---\n# leading comment\nname: a # trailing\ndescription: Use C# and issue #1\n  # indented comment line\nlicense:\nversion: # only comment\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "name"), "a");
        assert_eq!(field(&parsed, "description"), "Use C# and issue");
        assert_eq!(field(&parsed, "license"), "");
        assert_eq!(field(&parsed, "version"), "");
        assert!(parsed.nested_keys.is_empty());
    }

    #[test]
    fn single_and_double_quotes() {
        let text = "---\nsingle: 'It''s # not a comment' # comment\ndouble: \"a\\\\b \\/ \\n\\t\\r \\u00e9 \\ud83d\\ude00\" # comment\nother: \"keep \\x41 raw\"\n---\n";
        let parsed = parse(text).unwrap();
        assert_eq!(field(&parsed, "single"), "It's # not a comment");
        assert_eq!(field(&parsed, "double"), "a\\b / \n\t\r é 😀");
        assert_eq!(field(&parsed, "other"), "keep \\x41 raw");
    }

    #[test]
    fn missing_frontmatter() {
        assert_eq!(parse(""), Err(FrontmatterError::Missing));
        assert_eq!(parse("# Title\n---\n"), Err(FrontmatterError::Missing));
        assert_eq!(
            parse(" ---\nname: a\n---\n"),
            Err(FrontmatterError::Missing)
        );
    }

    #[test]
    fn unterminated_frontmatter() {
        assert_eq!(
            parse("---\nname: a\ndescription: b\n"),
            Err(FrontmatterError::Unterminated)
        );
        assert_eq!(parse("---"), Err(FrontmatterError::Unterminated));
    }

    #[test]
    fn duplicate_keys() {
        assert_eq!(
            parse("---\nname: a\nname: b\n---\n"),
            Err(FrontmatterError::DuplicateKey {
                key: "name".into(),
                line: 3
            })
        );
        assert_eq!(
            parse("---\nhooks:\n  a: b\nhooks: c\n---\n"),
            Err(FrontmatterError::DuplicateKey {
                key: "hooks".into(),
                line: 4
            })
        );
    }

    #[test]
    fn invalid_lines() {
        for (text, line) in [
            ("---\nname a\n---\n", 2),
            ("---\nname:a\n---\n", 2),
            ("---\nname: a\n  stray: b\n---\n", 3),
            ("---\n- item\n---\n", 2),
            ("---\n\"name\": a\n---\n", 2),
            ("---\nname: \"open\n---\n", 2),
            ("---\nname: \"a\" b\n---\n", 2),
            ("---\nname: 'a\n---\n", 2),
            ("---\ndescription: |2\n  a\n---\n", 2),
            ("---\ndescription: > text\n---\n", 2),
        ] {
            assert_eq!(
                parse(text),
                Err(FrontmatterError::InvalidLine { line }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn invalid_escape_in_name_or_description() {
        assert_eq!(
            parse("---\nname: \"a\\x41\"\n---\n"),
            Err(FrontmatterError::InvalidEscape {
                key: "name".into(),
                line: 2
            })
        );
        assert_eq!(
            parse("---\nname: a\ndescription: \"bad \\ud800 surrogate\"\n---\n"),
            Err(FrontmatterError::InvalidEscape {
                key: "description".into(),
                line: 3
            })
        );
        assert_eq!(
            parse("---\ndescription: \"bad \\u12\"\n---\n"),
            Err(FrontmatterError::InvalidEscape {
                key: "description".into(),
                line: 2
            })
        );
    }

    #[test]
    fn frontmatter_larger_than_limit() {
        let filler = format!("description: {}\n", "x".repeat(MAX_BYTES));
        let text = format!("---\nname: a\n{filler}---\nBody");
        assert_eq!(parse(&text), Err(FrontmatterError::TooLarge));
        let lines: String = (0..(MAX_BYTES - 16) / 10)
            .map(|index| format!("k{index:05}: v\n"))
            .collect();
        let fits = format!("---\n{lines}---\n");
        assert!(fits.len() > MAX_BYTES - 32);
        assert_eq!(parse(&fits).unwrap().fields.len(), (MAX_BYTES - 16) / 10);
    }

    #[test]
    fn error_codes() {
        assert_eq!(FrontmatterError::Missing.code(), "missing");
        assert_eq!(FrontmatterError::Unterminated.code(), "unterminated");
        assert_eq!(FrontmatterError::TooLarge.code(), "too_large");
        assert_eq!(
            FrontmatterError::DuplicateKey {
                key: "a".into(),
                line: 1
            }
            .code(),
            "duplicate_key"
        );
        assert_eq!(
            FrontmatterError::InvalidLine { line: 1 }.code(),
            "invalid_line"
        );
        assert_eq!(
            FrontmatterError::InvalidEscape {
                key: "a".into(),
                line: 1
            }
            .code(),
            "invalid_escape"
        );
    }

    fn collect_skill_files(dir: &std::path::Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if depth < 6 && !name.starts_with('.') && name != "node_modules" {
                    collect_skill_files(&path, depth + 1, out);
                }
            } else if name == "SKILL.md" {
                out.push(path);
            }
        }
    }

    #[test]
    #[ignore = "нужен RCODE_SKILLS_CORPUS с изолированной копией наборов скиллов"]
    fn real_corpus_parses_without_errors() {
        let Some(root) = std::env::var_os("RCODE_SKILLS_CORPUS") else {
            eprintln!("SKIP corpus: переменная RCODE_SKILLS_CORPUS не задана");
            return;
        };
        let root = std::path::PathBuf::from(root);
        let mut files = Vec::new();
        collect_skill_files(&root, 0, &mut files);
        assert!(!files.is_empty(), "в {} нет SKILL.md", root.display());
        let errors: Vec<String> = files
            .iter()
            .filter_map(|path| {
                let result = std::fs::read_to_string(path)
                    .map_err(|error| error.to_string())
                    .and_then(|text| parse(&text).map_err(|error| error.to_string()));
                result
                    .err()
                    .map(|error| format!("{}: {error}", path.display()))
            })
            .collect();
        eprintln!("corpus: {} SKILL.md, ошибок {}", files.len(), errors.len());
        assert!(errors.is_empty(), "{errors:#?}");
    }
}
