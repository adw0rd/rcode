//! Pure, bounded Codex-style patch parsing and context application.
//!
//! Parsing produces intent only. Paths are lexical names, not filesystem safety
//! checks or permission grants. The caller must independently enforce policy,
//! ignored-path rules, symlink safety, and all actual filesystem operations.
//!
//! Matching is exact, without whitespace folding or fuzzy fallback. A heading
//! selects the region after its unique matching line. EOF markers constrain a
//! hunk to end at EOF. Application preserves the original trailing-newline state
//! and untouched line endings; inserted lines use the first original line ending
//! (LF for an empty or single unterminated-line file).

use anyhow::{Result, bail};

pub const MAX_PATCH_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_OPERATIONS: usize = 100;
pub const MAX_LINES: usize = 100_000;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Deterministic cap on byte-comparison work across all hunk searches.
pub const MAX_SEARCH_WORK: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add {
        path: String,
        content: String,
    },
    Delete {
        path: String,
    },
    Update {
        path: String,
        move_to: Option<String>,
        hunks: Vec<Hunk>,
    },
}

/// Publicly constructible; `apply_hunks` also validates these values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    /// Exact optional search anchor; matching starts after this line.
    pub heading: Option<String>,
    pub lines: Vec<HunkLine>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HunkLine {
    Context(String),
    Remove(String),
    Add(String),
}

impl Patch {
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_PATCH_BYTES {
            bail!("Превышен предел размера патча: 2 МиБ");
        }
        let mut lines = Vec::new();
        for raw in input.split_terminator('\n') {
            if lines.len() == MAX_LINES {
                bail!("Превышен предел числа строк патча");
            }
            // CRLF is accepted as patch transport framing, not as payload.
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            validate_text_line(line)?;
            lines.push(line);
        }
        if lines.first().copied() != Some("*** Begin Patch") {
            bail!("Ожидался заголовок *** Begin Patch");
        }

        let mut i = 1;
        let mut operations = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        loop {
            let Some(&line) = lines.get(i) else {
                bail!("Отсутствует завершающий маркер *** End Patch");
            };
            if line == "*** End Patch" {
                if i + 1 != lines.len() {
                    bail!("После *** End Patch обнаружены лишние строки");
                }
                if operations.is_empty() {
                    bail!("Патч не содержит операций");
                }
                return Ok(Self { operations });
            }
            if operations.len() == MAX_OPERATIONS {
                bail!("Превышен предел числа операций: 100");
            }

            let operation = if let Some(path) = line.strip_prefix("*** Add File: ") {
                validate_path(path)?;
                i += 1;
                let mut content = String::new();
                while let Some(&body) = lines.get(i) {
                    if body.starts_with("***") {
                        break;
                    }
                    let Some(text) = body.strip_prefix('+') else {
                        bail!("Строка добавляемого файла должна начинаться с +");
                    };
                    content.push_str(text);
                    content.push('\n');
                    i += 1;
                }
                Operation::Add {
                    path: path.to_owned(),
                    content,
                }
            } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
                validate_path(path)?;
                i += 1;
                Operation::Delete {
                    path: path.to_owned(),
                }
            } else if let Some(path) = line.strip_prefix("*** Update File: ") {
                validate_path(path)?;
                i += 1;
                let move_to = if let Some(destination) = lines
                    .get(i)
                    .and_then(|line| line.strip_prefix("*** Move to: "))
                {
                    validate_path(destination)?;
                    i += 1;
                    Some(destination.to_owned())
                } else {
                    None
                };
                let mut hunks: Vec<Hunk> = Vec::new();
                while lines.get(i).is_some_and(|line| line.starts_with("@@")) {
                    if hunks.last().is_some_and(|hunk| hunk.eof) {
                        bail!(
                            "После фрагмента с привязкой к концу файла нельзя задавать новый фрагмент"
                        );
                    }
                    hunks.push(parse_hunk(&lines, &mut i)?);
                }
                if hunks.is_empty() && move_to.is_none() {
                    bail!("Обновление без переименования должно содержать фрагменты");
                }
                Operation::Update {
                    path: path.to_owned(),
                    move_to,
                    hunks,
                }
            } else {
                bail!("Неизвестный или некорректный заголовок операции");
            };

            match &operation {
                Operation::Add { path, .. } | Operation::Delete { path } => {
                    register_path(&mut touched, path)?;
                }
                Operation::Update { path, move_to, .. } => {
                    register_path(&mut touched, path)?;
                    if let Some(destination) = move_to {
                        register_path(&mut touched, destination)?;
                    }
                }
            }
            operations.push(operation);
        }
    }

    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
}

fn validate_text_line(line: &str) -> Result<()> {
    if line.len() > MAX_LINE_BYTES {
        bail!("Превышен предел длины строки");
    }
    if line.chars().any(|ch| ch.is_control() && ch != '\t') {
        bail!("Управляющие символы и двоичные данные не поддерживаются");
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path.contains(['\\', ':']) || path.chars().any(char::is_control) {
        bail!("Недопустимое написание относительного пути");
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.trim() != component
            || component.ends_with('.')
        {
            bail!("Путь должен состоять из обычных непустых относительных компонентов");
        }
        if [".git", ".env", "credentials.json"]
            .iter()
            .any(|name| component.eq_ignore_ascii_case(name))
        {
            bail!("Запрещён служебный или секретный компонент пути");
        }
    }
    Ok(())
}

fn register_path(touched: &mut Vec<String>, path: &str) -> Result<()> {
    // Ancestor/descendant names also conflict: one patch cannot make a name
    // simultaneously act as a file and as a parent directory.
    for other in touched.iter() {
        let descendant = path
            .strip_prefix(other.as_str())
            .is_some_and(|tail| tail.starts_with('/'));
        let ancestor = other
            .strip_prefix(path)
            .is_some_and(|tail| tail.starts_with('/'));
        if path == other || descendant || ancestor {
            bail!("Конфликт исходных или целевых путей операций");
        }
    }
    touched.push(path.to_owned());
    Ok(())
}

fn parse_hunk(lines: &[&str], i: &mut usize) -> Result<Hunk> {
    let header = lines[*i];
    let heading = if header == "@@" {
        None
    } else if let Some(text) = header.strip_prefix("@@ ") {
        if text.trim().is_empty() {
            bail!("Пустой поисковый заголовок фрагмента");
        }
        Some(text.to_owned())
    } else {
        bail!("Некорректный заголовок фрагмента");
    };
    *i += 1;
    let mut hunk = Hunk {
        heading,
        lines: Vec::new(),
        eof: false,
    };
    while let Some(&line) = lines.get(*i) {
        if line == "*** End of File" {
            hunk.eof = true;
            *i += 1;
            break;
        }
        if line.starts_with("***") || line.starts_with("@@") {
            break;
        }
        let item = if let Some(text) = line.strip_prefix(' ') {
            HunkLine::Context(text.to_owned())
        } else if let Some(text) = line.strip_prefix('-') {
            HunkLine::Remove(text.to_owned())
        } else if let Some(text) = line.strip_prefix('+') {
            HunkLine::Add(text.to_owned())
        } else {
            bail!("Строка фрагмента должна начинаться с пробела, - или +");
        };
        hunk.lines.push(item);
        *i += 1;
    }
    validate_hunk(&hunk)?;
    Ok(hunk)
}

fn validate_hunk(hunk: &Hunk) -> Result<()> {
    if let Some(heading) = &hunk.heading {
        validate_text_line(heading)?;
        if heading.trim().is_empty() {
            bail!("Пустой поисковый заголовок фрагмента");
        }
    }
    if hunk.lines.is_empty() || hunk.lines.len() > MAX_LINES {
        bail!("Недопустимое число строк фрагмента");
    }
    let mut changed = false;
    for line in &hunk.lines {
        let text = match line {
            HunkLine::Context(text) => text,
            HunkLine::Remove(text) | HunkLine::Add(text) => {
                changed = true;
                text
            }
        };
        validate_text_line(text)?;
    }
    if !changed {
        bail!("Фрагмент не содержит изменений");
    }
    Ok(())
}

#[derive(Clone)]
struct TextLine {
    text: String,
    ending: &'static str,
}

fn original_lines(original: &str) -> Result<Vec<TextLine>> {
    if original.len() > MAX_PATCH_BYTES {
        bail!("Превышен предел размера исходного текста: 2 МиБ");
    }
    let mut result = Vec::new();
    for raw in original.split_inclusive('\n') {
        if result.len() == MAX_LINES {
            bail!("Превышен предел числа строк исходного текста");
        }
        let (text, ending) = if let Some(text) = raw.strip_suffix("\r\n") {
            (text, "\r\n")
        } else if let Some(text) = raw.strip_suffix('\n') {
            (text, "\n")
        } else {
            (raw, "")
        };
        validate_text_line(text)?;
        result.push(TextLine {
            text: text.to_owned(),
            ending,
        });
    }
    Ok(result)
}

/// Apply ordered, nonoverlapping hunks to one text snapshot.
///
/// Every old/context sequence must have exactly one match in the unconsumed
/// original region. An insertion without old/context lines is accepted only
/// when there is exactly one candidate boundary (empty remaining region or
/// explicit EOF). No hunk can match text created by an earlier hunk.
/// An empty hunk slice is an identity operation, useful for rename-only intent.
pub fn apply_hunks(original: &str, hunks: &[Hunk]) -> Result<String> {
    if hunks.len() > MAX_LINES {
        bail!("Превышен предел числа фрагментов");
    }
    let source = original_lines(original)?;
    let mut line_count = 0usize;
    let mut text_bytes = 0usize;
    for (index, hunk) in hunks.iter().enumerate() {
        validate_hunk(hunk)?;
        if hunk.eof && index + 1 != hunks.len() {
            bail!("Привязка к концу файла допустима только в последнем фрагменте");
        }
        line_count += hunk.lines.len();
        text_bytes += hunk.heading.as_ref().map_or(0, String::len);
        for line in &hunk.lines {
            let text = match line {
                HunkLine::Context(text) | HunkLine::Remove(text) | HunkLine::Add(text) => text,
            };
            text_bytes += text.len() + 1;
        }
        if line_count > MAX_LINES || text_bytes > MAX_PATCH_BYTES {
            bail!("Превышены пределы объёма фрагментов");
        }
    }

    let preferred_ending = source
        .iter()
        .find(|line| !line.ending.is_empty())
        .map_or("\n", |line| line.ending);
    let ends_with_newline = source.last().is_some_and(|line| !line.ending.is_empty());
    let mut output: Vec<TextLine> = Vec::new();
    let mut cursor = 0;
    let mut previous_start = None;
    let mut search_budget = MAX_SEARCH_WORK;
    for hunk in hunks {
        let mut lower = cursor;
        if let Some(heading) = &hunk.heading {
            let mut anchor = None;
            for (index, line) in source.iter().enumerate().skip(cursor) {
                if same_line(&line.text, heading, &mut search_budget)? {
                    if anchor.is_some() {
                        bail!("Поисковый заголовок неоднозначен в оставшейся области файла");
                    }
                    anchor = Some(index);
                }
            }
            let Some(anchor) = anchor else {
                bail!("Поисковый заголовок не найден в оставшейся области файла");
            };
            lower = anchor + 1;
        }
        let old: Vec<&str> = hunk
            .lines
            .iter()
            .filter_map(|line| match line {
                HunkLine::Context(text) | HunkLine::Remove(text) => Some(text.as_str()),
                HunkLine::Add(_) => None,
            })
            .collect();
        let start = unique_match(&source, &old, lower, hunk.eof, &mut search_budget)?;
        if previous_start == Some(start) {
            bail!("Фрагменты пересекаются в одной позиции вставки");
        }
        output.extend_from_slice(&source[cursor..start]);
        let mut consumed = start;
        for line in &hunk.lines {
            match line {
                HunkLine::Context(_) => {
                    output.push(source[consumed].clone());
                    consumed += 1;
                }
                HunkLine::Remove(_) => consumed += 1,
                HunkLine::Add(text) => output.push(TextLine {
                    text: text.clone(),
                    ending: preferred_ending,
                }),
            }
        }
        cursor = consumed;
        previous_start = Some(start);
    }
    output.extend_from_slice(&source[cursor..]);
    if output.len() > MAX_LINES {
        bail!("Превышен предел числа строк результата");
    }
    let last_index = output.len().checked_sub(1);
    let mut result = String::new();
    for (index, line) in output.iter().enumerate() {
        let ending = if Some(index) == last_index && !ends_with_newline {
            ""
        } else if line.ending.is_empty() {
            preferred_ending
        } else {
            line.ending
        };
        if result.len() + line.text.len() + ending.len() > MAX_PATCH_BYTES {
            bail!("Превышен предел размера результата: 2 МиБ");
        }
        result.push_str(&line.text);
        result.push_str(ending);
    }
    Ok(result)
}

fn same_line(left: &str, right: &str, budget: &mut usize) -> Result<bool> {
    let work = if left.len() == right.len() {
        left.len() + 1
    } else {
        1
    };
    *budget = budget.checked_sub(work).ok_or_else(|| {
        anyhow::anyhow!("Исчерпан общий бюджет поиска контекста патча; уменьшите число фрагментов")
    })?;
    Ok(left == right)
}

// KMP over logical lines avoids quadratic scans on repetitive input. Only two
// matches need to be discovered to reject ambiguity.
fn unique_match(
    source: &[TextLine],
    needle: &[&str],
    lower: usize,
    eof: bool,
    budget: &mut usize,
) -> Result<usize> {
    if needle.is_empty() {
        if eof || lower == source.len() {
            return Ok(source.len());
        }
        bail!("Вставка без контекста неоднозначна; требуется привязка к концу файла");
    }
    let mut prefix = vec![0usize; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        while matched > 0 && !same_line(needle[index], needle[matched], budget)? {
            matched = prefix[matched - 1];
        }
        if same_line(needle[index], needle[matched], budget)? {
            matched += 1;
        }
        prefix[index] = matched;
    }
    matched = 0;
    let mut found = None;
    for (index, line) in source.iter().enumerate().skip(lower) {
        while matched > 0 && !same_line(line.text.as_str(), needle[matched], budget)? {
            matched = prefix[matched - 1];
        }
        if same_line(line.text.as_str(), needle[matched], budget)? {
            matched += 1;
        }
        if matched == needle.len() {
            if !eof || index + 1 == source.len() {
                if found.is_some() {
                    bail!("Контекст фрагмента неоднозначен в оставшейся области файла");
                }
                found = Some(index + 1 - needle.len());
            }
            matched = prefix[matched - 1];
        }
    }
    found.ok_or_else(|| anyhow::anyhow!("Контекст фрагмента не найден в оставшейся области файла"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(body: &str) -> Vec<Hunk> {
        let input = format!("*** Begin Patch\n*** Update File: src/a.rs\n{body}\n*** End Patch\n");
        let patch = Patch::parse(&input).unwrap();
        match &patch.operations()[0] {
            Operation::Update { hunks, .. } => hunks.clone(),
            _ => panic!("ожидалось обновление"),
        }
    }

    fn wrap(body: &str) -> String {
        format!("*** Begin Patch\n{body}\n*** End Patch\n")
    }

    #[test]
    fn parses_realistic_multiple_operations() {
        let patch = Patch::parse(&wrap(concat!(
            "*** Add File: docs/пример.txt\n+Привет\n+\n",
            "*** Delete File: obsolete.txt\n",
            "*** Update File: src/old.rs\n*** Move to: src/new.rs\n",
            "@@ fn answer() {\n-    41\n+    42\n }\n*** End of File"
        )))
        .unwrap();
        assert_eq!(patch.operations().len(), 3);
        assert_eq!(
            patch.operations()[0],
            Operation::Add {
                path: "docs/пример.txt".into(),
                content: "Привет\n\n".into(),
            }
        );
        assert_eq!(
            patch.operations()[1],
            Operation::Delete {
                path: "obsolete.txt".into()
            }
        );
        match &patch.operations()[2] {
            Operation::Update {
                path,
                move_to,
                hunks,
            } => {
                assert_eq!(path, "src/old.rs");
                assert_eq!(move_to.as_deref(), Some("src/new.rs"));
                assert_eq!(hunks[0].heading.as_deref(), Some("fn answer() {"));
                assert!(hunks[0].eof);
            }
            _ => panic!("ожидалось обновление"),
        }
    }

    #[test]
    fn exact_replacement_preserves_unmatched_text() {
        let hunks = update("@@\n before\n-old\n+new\n after");
        assert_eq!(
            apply_hunks("prefix\nbefore\nold\nafter\nsuffix\n", &hunks).unwrap(),
            "prefix\nbefore\nnew\nafter\nsuffix\n"
        );
        assert!(apply_hunks("before\n old\nafter\n", &hunks).is_err());
    }

    #[test]
    fn ambiguity_and_missing_context_are_rejected() {
        let hunks = update("@@\n-x\n+y");
        assert!(apply_hunks("x\nx\n", &hunks).is_err());
        assert!(apply_hunks("z\n", &hunks).is_err());
        let overlapping = update("@@\n-a\n-a\n+b");
        assert!(apply_hunks("a\na\na\n", &overlapping).is_err());
    }

    #[test]
    fn eof_disambiguates_and_requires_actual_eof() {
        let hunks = update("@@\n-x\n+y\n*** End of File");
        assert_eq!(apply_hunks("x\nx\n", &hunks).unwrap(), "x\ny\n");
        assert!(apply_hunks("x\nz\n", &hunks).is_err());
        assert!(
            Patch::parse(&wrap(
                "*** Update File: a\n@@\n-x\n+y\n*** End of File\n@@\n-z\n+w"
            ))
            .is_err()
        );
    }

    #[test]
    fn unicode_and_trailing_newline_state_are_preserved() {
        let hunks = update("@@\n-старое 🦀\n+новое 世界");
        for (original, expected) in [
            ("старое 🦀", "новое 世界"),
            ("старое 🦀\n", "новое 世界\n"),
            ("старое 🦀\n\n", "новое 世界\n\n"),
            ("старое 🦀\r\n", "новое 世界\r\n"),
        ] {
            assert_eq!(apply_hunks(original, &hunks).unwrap(), expected);
        }
    }

    #[test]
    fn mixed_line_endings_remain_intact_outside_changes() {
        let hunks = update("@@\n-b\n+B");
        assert_eq!(
            apply_hunks("a\r\nb\nc\r\nd", &hunks).unwrap(),
            "a\r\nB\r\nc\r\nd"
        );
        assert_eq!(apply_hunks("a\r\nb\nc", &[]).unwrap(), "a\r\nb\nc");
    }

    #[test]
    fn insertion_requires_a_unique_boundary() {
        let insertion = update("@@\n+new");
        assert!(apply_hunks("old\n", &insertion).is_err());
        assert_eq!(apply_hunks("", &insertion).unwrap(), "new");
        let eof = update("@@\n+new\n*** End of File");
        assert_eq!(apply_hunks("old\n", &eof).unwrap(), "old\nnew\n");
        assert_eq!(apply_hunks("old", &eof).unwrap(), "old\nnew");
        let anchored = update("@@ last\n+new");
        assert_eq!(apply_hunks("last\n", &anchored).unwrap(), "last\nnew\n");
        assert!(apply_hunks("last\nother\n", &anchored).is_err());
    }

    #[test]
    fn headings_only_narrow_the_remaining_search_region() {
        let hunks = update("@@ second\n-x\n+y");
        assert_eq!(
            apply_hunks("first\nx\nsecond\nx\n", &hunks).unwrap(),
            "first\nx\nsecond\ny\n"
        );
        assert!(apply_hunks("first\nx\n", &hunks).is_err());
        assert!(apply_hunks("second\nx\nsecond\nx\n", &hunks).is_err());
        assert!(apply_hunks("second\nx\nx\n", &hunks).is_err());
    }

    #[test]
    fn ordered_hunks_match_only_original_unconsumed_lines() {
        let valid = update("@@\n-a\n+A\n@@\n-c\n+C");
        assert_eq!(apply_hunks("a\nb\nc", &valid).unwrap(), "A\nb\nC");
        let reverse = update("@@\n-c\n+C\n@@\n-a\n+A");
        assert!(apply_hunks("a\nb\nc", &reverse).is_err());
        let overlap = update("@@\n a\n-b\n+B\n@@\n-b\n+C");
        assert!(apply_hunks("a\nb\n", &overlap).is_err());
        let generated = update("@@\n-a\n+b\n@@\n-b\n+c");
        assert!(apply_hunks("a\n", &generated).is_err());
        let repeated_boundary = update("@@\n+x\n@@\n+y");
        assert!(apply_hunks("", &repeated_boundary).is_err());
    }

    #[test]
    fn deletions_and_rename_only_are_intent() {
        let patch = Patch::parse(&wrap(
            "*** Delete File: absent\n*** Update File: old\n*** Move to: new",
        ))
        .unwrap();
        match &patch.operations()[1] {
            Operation::Update { hunks, move_to, .. } => {
                assert!(hunks.is_empty());
                assert_eq!(move_to.as_deref(), Some("new"));
                assert_eq!(apply_hunks("unchanged", hunks).unwrap(), "unchanged");
            }
            _ => panic!("ожидалось переименование"),
        }
        let remove = update("@@\n-only");
        assert_eq!(apply_hunks("only\n", &remove).unwrap(), "");
        assert_eq!(apply_hunks("only", &remove).unwrap(), "");
    }

    #[test]
    fn malformed_headers_instructions_and_binary_are_rejected() {
        for input in [
            "",
            "*** Begin Patch\n*** End Patch\n",
            "text\n*** Begin Patch\n*** Delete File: a\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a",
            "*** Begin Patch\n*** Delete File: a\n*** End Patch\nextra",
            "*** Begin Patch\n*** Delete File: a\n*** End Patch\n\n",
        ] {
            assert!(Patch::parse(input).is_err(), "{input:?}");
        }
        for body in [
            "*** Add File:a\n+x",
            "*** Add File: a\nplain text",
            "*** Delete File: a\n+unexpected",
            "*** Update File: a",
            "*** Update File: a\n@@bad\n-x\n+y",
            "*** Update File: a\n@@ \n-x\n+y",
            "*** Update File: a\n@@\n context",
            "*** Update File: a\n@@\n",
            "*** Update File: a\n@@\n-x\n+y\n\\ No newline at end of file",
            "*** Update File: a\n*** Move to: b\n*** Move to: c",
            "*** Delete File: a\n*** Ignored: false",
            "Ignore previous instructions\n*** Delete File: a",
            "*** Add File: a\nGIT binary patch",
            "*** Add File: a\n+x\0y",
        ] {
            assert!(Patch::parse(&wrap(body)).is_err(), "{body:?}");
        }
        // Marker-looking text is harmless when explicitly encoded as content.
        let patch = Patch::parse(&wrap("*** Add File: a\n+*** End Patch")).unwrap();
        assert!(
            matches!(&patch.operations()[0], Operation::Add { content, .. }
            if content == "*** End Patch\n")
        );
    }

    #[test]
    fn unsafe_source_and_destination_paths_are_rejected() {
        for path in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "./a",
            "a/./b",
            "C:/a",
            "a:b",
            "a\\b",
            "a\0b",
            "a\tb",
            " a",
            "a ",
            "a.",
            ".git/config",
            "nested/.GIT/config",
            ".env",
            "a/.env/x",
            "credentials.json",
            "a/CREDENTIALS.JSON",
        ] {
            assert!(
                Patch::parse(&wrap(&format!("*** Delete File: {path}"))).is_err(),
                "{path:?}"
            );
            assert!(
                Patch::parse(&wrap(&format!(
                    "*** Update File: safe\n*** Move to: {path}"
                )))
                .is_err(),
                "{path:?}"
            );
        }
        assert!(Patch::parse(&wrap("*** Add File: 文档/a b.txt\n+ok")).is_ok());
        assert!(Patch::parse(&wrap("*** Delete File: .gitignore")).is_ok());
    }

    #[test]
    fn duplicate_and_move_touch_conflicts_are_rejected() {
        for body in [
            "*** Delete File: a\n*** Add File: a\n+x",
            "*** Update File: a\n*** Move to: a",
            "*** Update File: a\n*** Move to: b\n*** Delete File: b",
            "*** Delete File: b\n*** Update File: a\n*** Move to: b",
            "*** Update File: a\n*** Move to: b\n*** Update File: b\n*** Move to: a",
            "*** Update File: a\n*** Move to: a/b",
            "*** Add File: a/b\n+x\n*** Delete File: a",
        ] {
            assert!(Patch::parse(&wrap(body)).is_err(), "{body:?}");
        }
    }

    #[test]
    fn crlf_transport_and_missing_final_patch_newline_are_supported() {
        let input = "*** Begin Patch\r\n*** Add File: a\r\n+x\r\n*** End Patch";
        let patch = Patch::parse(input).unwrap();
        assert!(
            matches!(&patch.operations()[0], Operation::Add { content, .. }
            if content == "x\n")
        );
    }

    #[test]
    fn input_operation_and_line_limits() {
        assert!(Patch::parse(&"x".repeat(MAX_PATCH_BYTES + 1)).is_err());
        let operations = (0..MAX_OPERATIONS)
            .map(|n| format!("*** Delete File: f{n}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            Patch::parse(&wrap(&operations)).unwrap().operations().len(),
            MAX_OPERATIONS
        );
        assert!(Patch::parse(&wrap(&format!("{operations}\n*** Delete File: extra"))).is_err());
        assert!(Patch::parse(&"\n".repeat(MAX_LINES + 1)).is_err());
        assert!(
            Patch::parse(&wrap(&format!(
                "*** Add File: a\n+{}",
                "x".repeat(MAX_LINE_BYTES)
            )))
            .is_err()
        );
    }

    #[test]
    fn application_validates_public_hunks_and_output_limits() {
        let malformed = Hunk {
            heading: None,
            lines: vec![HunkLine::Add("embedded\nline".into())],
            eof: true,
        };
        assert!(apply_hunks("", &[malformed]).is_err());
        assert!(apply_hunks("a\0b", &[]).is_err());
        assert!(apply_hunks(&"x".repeat(MAX_PATCH_BYTES + 1), &[]).is_err());
        let line = "x".repeat(MAX_LINE_BYTES - 1);
        let original = format!("{line}\n").repeat(MAX_PATCH_BYTES / MAX_LINE_BYTES);
        assert_eq!(apply_hunks(&original, &[]).unwrap(), original);
        let insertion = Hunk {
            heading: None,
            lines: vec![HunkLine::Add("extra".into())],
            eof: true,
        };
        assert!(apply_hunks(&original, &[insertion]).is_err());
        let too_many = Hunk {
            heading: None,
            lines: vec![HunkLine::Add(String::new()); MAX_LINES + 1],
            eof: true,
        };
        assert!(apply_hunks("", &[too_many]).is_err());
        let mut early_eof = update("@@\n-a\n+A\n*** End of File");
        early_eof.extend(update("@@\n-b\n+B"));
        assert!(apply_hunks("a\nb\n", &early_eof).is_err());
    }
}
