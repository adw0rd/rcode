//! Безопасное представление Markdown: данные и стили, без терминальных команд.
use crate::ui;
use pulldown_cmark::{Alignment, CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use std::sync::{Arc, Mutex};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

const MAX_SOURCE: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Tone {
    #[default]
    Normal,
    Muted,
    Accent,
    InlineCode,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Style {
    pub tone: Tone,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub text: String,
    pub style: Style,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Row {
    pub spans: Vec<Span>,
    pub code: bool,
}
impl Row {
    pub fn text(&self) -> String {
        self.spans.iter().map(|s| s.text.as_str()).collect()
    }
}

struct Cache {
    width: usize,
    revision: usize,
    rows: Arc<Vec<Row>>,
}
pub(crate) struct Markdown {
    source: String,
    truncated: bool,
    cache: Mutex<Option<Cache>>,
}
impl Markdown {
    pub fn new() -> Self {
        Self {
            source: String::new(),
            truncated: false,
            cache: Mutex::new(None),
        }
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn append(&mut self, text: &str) {
        if self.truncated {
            return;
        }
        let text = ui::safe(text);
        let mut end = text.len().min(MAX_SOURCE.saturating_sub(self.source.len()));
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.source.push_str(&text[..end]);
        self.truncated = end < text.len();
        *self.cache.get_mut().unwrap_or_else(|e| e.into_inner()) = None;
    }
    pub fn rows(&self, width: usize) -> Arc<Vec<Row>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cache.as_ref()
            && c.width == width
            && c.revision == self.source.len()
        {
            return c.rows.clone();
        }
        let mut rows = render(&self.source, width);
        if self.truncated {
            rows.extend(wrap(
                &[span(
                    "[…ответ сокращён на экране; полный текст сохранён в сессии…]",
                    Style::default(),
                )],
                &[],
                width,
            ));
        }
        let rows = Arc::new(rows);
        *cache = Some(Cache {
            width,
            revision: self.source.len(),
            rows: rows.clone(),
        });
        rows
    }
}
fn span(text: &str, style: Style) -> Span {
    // Entities decoded by the Markdown parser also pass through the sanitizer.
    Span {
        text: ui::safe(text).replace('\t', "    ").replace('\n', "\\n"),
        style,
    }
}
fn add(spans: &mut Vec<Span>, value: Span) {
    if value.text.is_empty() {
        return;
    }
    if let Some(last) = spans.last_mut().filter(|s| s.style == value.style) {
        last.text.push_str(&value.text);
    } else {
        spans.push(value);
    }
}
fn cells(spans: &[Span]) -> usize {
    spans
        .iter()
        .map(|s| UnicodeWidthStr::width(s.text.as_str()))
        .sum()
}
fn wrap(spans: &[Span], continuation: &[Span], width: usize) -> Vec<Row> {
    if width == 0 {
        return vec![Row::default()];
    }
    let mut rows = Vec::new();
    let mut current = Row::default();
    let mut size = 0;
    for s in spans {
        for g in s.text.graphemes(true) {
            let n = UnicodeWidthStr::width(g);
            if size + n > width && size > 0 {
                rows.push(std::mem::take(&mut current));
                // At tiny widths indentation must not consume the entire row.
                if cells(continuation) + n <= width {
                    current.spans = continuation.to_vec();
                }
                size = cells(&current.spans);
            }
            if n <= width {
                add(
                    &mut current.spans,
                    Span {
                        text: g.to_owned(),
                        style: s.style,
                    },
                );
                size += n;
            }
        }
    }
    rows.push(current);
    rows
}

#[derive(Default)]
struct Table {
    alignment: Vec<Alignment>,
    rows: Vec<Vec<Vec<Span>>>,
    head: bool,
}
struct Item {
    marker: String,
    first: bool,
}
#[derive(Default)]
struct Builder {
    rows: Vec<Row>,
    current: Vec<Span>,
    continuation: Vec<Span>,
    lists: Vec<Option<u64>>,
    items: Vec<Item>,
    quotes: usize,
    heading: bool,
    strong: usize,
    emphasis: usize,
    strike: usize,
    links: Vec<(String, String)>,
    table: Option<Table>,
    code: Option<(String, String)>,
    width: usize,
}
impl Builder {
    fn style(&self) -> Style {
        Style {
            tone: if self.heading || !self.links.is_empty() {
                Tone::Accent
            } else {
                Tone::Normal
            },
            bold: self.heading || self.strong > 0 || self.table.as_ref().is_some_and(|t| t.head),
            italic: self.emphasis > 0,
            underline: !self.links.is_empty(),
            strike: self.strike > 0,
        }
    }
    fn prefix(&mut self) {
        if !self.current.is_empty() {
            return;
        }
        let quote = "│ ".repeat(self.quotes);
        let indent = "  ".repeat(self.items.len().saturating_sub(1));
        let marker = self
            .items
            .last_mut()
            .map(|item| {
                if std::mem::take(&mut item.first) {
                    item.marker.clone()
                } else {
                    " ".repeat(UnicodeWidthStr::width(item.marker.as_str()))
                }
            })
            .unwrap_or_default();
        let prefix = format!("{quote}{indent}{marker}");
        let continuation = format!(
            "{quote}{indent}{}",
            " ".repeat(UnicodeWidthStr::width(marker.as_str()))
        );
        let muted = Style {
            tone: Tone::Muted,
            ..Style::default()
        };
        self.continuation = vec![span(&continuation, muted)];
        add(&mut self.current, span(&prefix, muted));
    }
    fn text(&mut self, text: &str, style: Style) {
        for (_, label) in &mut self.links {
            label.push_str(text);
        }
        let value = span(text, style);
        if let Some(table) = &mut self.table {
            if let Some(cell) = table.rows.last_mut().and_then(|r| r.last_mut()) {
                add(cell, value);
            }
        } else {
            self.prefix();
            add(&mut self.current, value);
        }
    }
    fn flush(&mut self) {
        if !self.current.is_empty() {
            self.rows.extend(wrap(
                &std::mem::take(&mut self.current),
                &self.continuation,
                self.width,
            ));
        }
    }
    fn blank(&mut self) {
        self.flush();
        if self.rows.last().is_some_and(|r| !r.spans.is_empty()) {
            self.rows.push(Row::default());
        }
    }
    fn code_block(&mut self, language: &str, code: &str) {
        self.flush();
        let width = self.width.min(96);
        let widest = code
            .graphemes(true)
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0);
        if width < 5 || widest > width.saturating_sub(4) {
            for line in code.lines() {
                self.rows
                    .extend(wrap(&[span(line, Style::default())], &[], width));
            }
            return;
        }
        let label = crate::presentation::clip(
            language.split_whitespace().next().unwrap_or("код"),
            width.saturating_sub(6),
        );
        let title = format!("╭─ {label} ");
        let border = Style {
            tone: Tone::Muted,
            ..Style::default()
        };
        self.rows.push(Row {
            spans: vec![span(
                &format!(
                    "{title}{}╮",
                    "─".repeat(width.saturating_sub(1 + UnicodeWidthStr::width(title.as_str())))
                ),
                border,
            )],
            code: true,
        });
        let lines: Vec<_> = code.split_terminator('\n').collect();
        for line in if lines.is_empty() { vec![""] } else { lines } {
            let mut expanded = String::new();
            let mut column = 0;
            for g in line.graphemes(true) {
                if g == "\t" {
                    let spaces = 4 - column % 4;
                    expanded.push_str(&" ".repeat(spaces));
                    column += spaces;
                } else {
                    expanded.push_str(g);
                    column += UnicodeWidthStr::width(g);
                }
            }
            for row in wrap(&[span(&expanded, Style::default())], &[], width - 4) {
                let padding = width - 4 - cells(&row.spans);
                let mut spans = vec![span("│ ", border)];
                spans.extend(row.spans);
                spans.push(span(&format!("{} │", " ".repeat(padding)), border));
                self.rows.push(Row { spans, code: true });
            }
        }
        self.rows.push(Row {
            spans: vec![span(&format!("╰{}╯", "─".repeat(width - 2)), border)],
            code: true,
        });
    }
    fn table(&mut self, table: Table) {
        self.flush();
        let columns = table.rows.iter().map(Vec::len).max().unwrap_or_default();
        if columns == 0 {
            return;
        }
        let mut minimums = vec![1; columns];
        for row in &table.rows {
            for (i, cell) in row.iter().enumerate() {
                for s in cell {
                    for g in s.text.graphemes(true) {
                        minimums[i] = minimums[i].max(UnicodeWidthStr::width(g));
                    }
                }
            }
        }
        if minimums.iter().sum::<usize>() + columns.saturating_mul(3) + 1 > self.width {
            // Narrow terminal: keep every cell readable rather than clipping columns.
            for row in table.rows {
                for (i, cell) in row.into_iter().enumerate() {
                    let mut values = vec![span(
                        &format!("{}: ", i + 1),
                        Style {
                            tone: Tone::Muted,
                            ..Style::default()
                        },
                    )];
                    values.extend(cell);
                    self.rows.extend(wrap(&values, &[], self.width));
                }
                self.blank();
            }
            return;
        }
        let mut widths = minimums.clone();
        for row in &table.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cells(cell));
            }
        }
        let budget = self.width.saturating_sub(columns * 3 + 1);
        while widths.iter().sum::<usize>() > budget {
            let Some((i, _)) = widths
                .iter()
                .enumerate()
                .filter(|(i, w)| **w > minimums[*i])
                .max_by_key(|(_, w)| **w)
            else {
                break;
            };
            widths[i] -= 1;
        }
        let border = Style {
            tone: Tone::Muted,
            ..Style::default()
        };
        for (index, row) in table.rows.into_iter().enumerate() {
            let wrapped: Vec<_> = widths
                .iter()
                .enumerate()
                .map(|(i, w)| wrap(row.get(i).map(Vec::as_slice).unwrap_or_default(), &[], *w))
                .collect();
            for line in 0..wrapped.iter().map(Vec::len).max().unwrap_or(1) {
                let mut spans = vec![span("│", border)];
                for (i, parts) in wrapped.iter().enumerate() {
                    let contents = parts
                        .get(line)
                        .map(|r| r.spans.as_slice())
                        .unwrap_or_default();
                    let pad = widths[i].saturating_sub(cells(contents));
                    let left = match table.alignment.get(i) {
                        Some(Alignment::Right) => pad,
                        Some(Alignment::Center) => pad / 2,
                        _ => 0,
                    };
                    spans.push(span(&" ".repeat(left + 1), border));
                    spans.extend_from_slice(contents);
                    spans.push(span(&format!("{}│", " ".repeat(pad - left + 1)), border));
                }
                self.rows.push(Row { spans, code: false });
            }
            if index == 0 {
                let rule = widths
                    .iter()
                    .map(|w| "─".repeat(w + 2))
                    .collect::<Vec<_>>()
                    .join("┼");
                self.rows.push(Row {
                    spans: vec![span(&format!("├{rule}┤"), border)],
                    code: false,
                });
            }
        }
    }
}
fn render(source: &str, width: usize) -> Vec<Row> {
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let mut b = Builder {
        width,
        ..Builder::default()
    };
    for event in Parser::new_ext(source, options) {
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => {
                    b.flush();
                }
                Tag::Heading { .. } => {
                    b.blank();
                    b.heading = true;
                }
                Tag::CodeBlock(kind) => {
                    b.blank();
                    let language = match kind {
                        CodeBlockKind::Fenced(info) => info.into_string(),
                        CodeBlockKind::Indented => String::new(),
                    };
                    b.code = Some((language, String::new()));
                }
                Tag::List(first) => {
                    b.flush();
                    b.lists.push(first);
                }
                Tag::Item => {
                    b.flush();
                    let marker = match b.lists.last_mut() {
                        Some(Some(n)) => {
                            let marker = format!("{n}. ");
                            *n = n.saturating_add(1);
                            marker
                        }
                        _ => "• ".into(),
                    };
                    b.items.push(Item {
                        marker,
                        first: true,
                    });
                }
                Tag::BlockQuote(_) => {
                    b.flush();
                    b.quotes += 1;
                }
                Tag::Strong => b.strong += 1,
                Tag::Emphasis => b.emphasis += 1,
                Tag::Strikethrough => b.strike += 1,
                Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                    b.links.push((ui::safe(&dest_url), String::new()))
                }
                Tag::Table(alignment) => {
                    b.blank();
                    b.table = Some(Table {
                        alignment,
                        ..Table::default()
                    });
                }
                Tag::TableHead => {
                    if let Some(t) = &mut b.table {
                        t.head = true;
                        t.rows.push(vec![]);
                    }
                }
                Tag::TableRow => {
                    if let Some(t) = &mut b.table {
                        t.rows.push(vec![]);
                    }
                }
                Tag::TableCell => {
                    if let Some(t) = &mut b.table
                        && let Some(row) = t.rows.last_mut()
                    {
                        row.push(vec![]);
                    }
                }
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph => {
                    b.flush();
                    if b.items.is_empty() {
                        b.blank();
                    }
                }
                TagEnd::Heading(_) => {
                    b.flush();
                    b.heading = false;
                    b.blank();
                }
                TagEnd::CodeBlock => {
                    if let Some((language, code)) = b.code.take() {
                        b.code_block(&language, &code);
                        b.blank();
                    }
                }
                TagEnd::List(_) => {
                    b.flush();
                    b.lists.pop();
                    if b.lists.is_empty() {
                        b.blank();
                    }
                }
                TagEnd::Item => {
                    b.flush();
                    b.items.pop();
                }
                TagEnd::BlockQuote(_) => {
                    b.flush();
                    b.quotes = b.quotes.saturating_sub(1);
                    b.blank();
                }
                TagEnd::Strong => b.strong = b.strong.saturating_sub(1),
                TagEnd::Emphasis => b.emphasis = b.emphasis.saturating_sub(1),
                TagEnd::Strikethrough => b.strike = b.strike.saturating_sub(1),
                TagEnd::Link | TagEnd::Image => {
                    if let Some((url, label)) = b.links.pop()
                        && url != label
                        && !url.is_empty()
                    {
                        b.text(
                            &format!(" ({url})"),
                            Style {
                                tone: Tone::Muted,
                                ..Style::default()
                            },
                        );
                    }
                }
                TagEnd::TableHead => {
                    if let Some(t) = &mut b.table {
                        t.head = false;
                    }
                }
                TagEnd::Table => {
                    if let Some(table) = b.table.take() {
                        b.table(table);
                        b.blank();
                    }
                }
                _ => {}
            },
            Event::Text(text) => {
                if let Some((_, code)) = &mut b.code {
                    code.push_str(&text);
                } else {
                    b.text(&text, b.style());
                }
            }
            Event::Code(text) => b.text(
                &text,
                Style {
                    tone: Tone::InlineCode,
                    ..b.style()
                },
            ),
            Event::SoftBreak => b.text(" ", b.style()),
            Event::HardBreak => {
                b.flush();
            }
            Event::Rule => {
                b.blank();
                b.rows.push(Row {
                    spans: vec![span(
                        &"─".repeat(width.min(96)),
                        Style {
                            tone: Tone::Muted,
                            ..Style::default()
                        },
                    )],
                    code: false,
                });
                b.blank();
            }
            Event::TaskListMarker(done) => b.text(if done { "[✓] " } else { "[ ] " }, b.style()),
            Event::Html(text) | Event::InlineHtml(text) => {
                for (i, line) in text.lines().enumerate() {
                    if i > 0 {
                        b.flush();
                    }
                    b.text(line, b.style());
                }
            }
            Event::FootnoteReference(text) => b.text(&format!("[{text}]"), b.style()),
            _ => {}
        }
    }
    b.flush();
    while b.rows.last().is_some_and(|r| r.spans.is_empty()) {
        b.rows.pop();
    }
    b.rows
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(rows: &[Row]) -> String {
        rows.iter().map(Row::text).collect::<Vec<_>>().join("\n")
    }
    #[test]
    fn commonmark_content_and_inline_styles_are_preserved_without_markup() {
        let rows = render(
            "## Заголовок\n\n**жирный** и *курсив*, ~~старое~~, `код`\n\n- первый\n  - второй\n\n3. третий\n4. четвёртый\n\n> цитата\n\n[Ссылка](https://example.com)\n\n- [x] готово",
            100,
        );
        let all = text(&rows);
        for expected in [
            "Заголовок",
            "жирный и курсив, старое, код",
            "• первый",
            "  • второй",
            "3. третий",
            "4. четвёртый",
            "│ цитата",
            "Ссылка (https://example.com)",
            "[✓] готово",
        ] {
            assert!(all.contains(expected), "missing {expected:?}: {all}");
        }
        assert!(!all.contains("**") && !all.contains("##") && !all.contains('`'));
        let spans: Vec<_> = rows.iter().flat_map(|r| &r.spans).collect();
        assert!(spans.iter().any(|s| s.text == "жирный" && s.style.bold));
        assert!(spans.iter().any(|s| s.text == "курсив" && s.style.italic));
        assert!(spans.iter().any(|s| s.text == "старое" && s.style.strike));
        assert!(
            spans
                .iter()
                .any(|s| s.text == "код" && s.style.tone == Tone::InlineCode)
        );
    }
    #[test]
    fn code_fences_keep_literal_code_indentation_blank_lines_and_tabs() {
        let code = "````python\nif True:\n\tprint('**literal**')\n\n```\n````\nAfter";
        let rows = render(code, 48);
        let all = text(&rows);
        assert!(all.contains("╭─ python"), "{all}");
        assert!(all.contains("│     print('**literal**')"), "{all}");
        assert!(rows.iter().any(|r| r.code && r.text().contains("│ ```")));
        assert!(
            rows.iter()
                .any(|r| r.code && r.text().trim_matches(['│', ' ']).is_empty())
        );
        assert_eq!(rows.last().unwrap().text(), "After");
    }
    #[test]
    fn streamed_source_and_unfinished_fences_reflow_without_losing_text() {
        let mut doc = Markdown::new();
        for chunk in [
            "# Title\n\n`",
            "``ba",
            "sh\npython3 /tmp/saper/saper.py\n",
            "`",
            "``\n\n**Done**",
        ] {
            doc.append(chunk);
        }
        assert_eq!(
            doc.source(),
            "# Title\n\n```bash\npython3 /tmp/saper/saper.py\n```\n\n**Done**"
        );
        let wide = doc.rows(80);
        assert!(text(&wide).contains("│ python3 /tmp/saper/saper.py"));
        assert!(
            Arc::ptr_eq(&wide, &doc.rows(80)),
            "unchanged output must use cache"
        );
        for width in 0..80 {
            for row in doc.rows(width).iter() {
                assert!(
                    UnicodeWidthStr::width(row.text().as_str()) <= width,
                    "width {width}: {:?}",
                    row.text()
                );
            }
        }
        let open = render("~~~rust\nlet value = 1;", 40);
        assert!(text(&open).contains("╭─ rust") && text(&open).contains("let value = 1;"));
    }
    #[test]
    fn tables_wrap_cells_and_fit_unicode_at_all_terminal_widths() {
        let source = "| Модель | Результат |\n| :--- | ---: |\n| Ultra 世界 | **Готово** |\n| Long | a_very_long_value_to_wrap |";
        for width in 0..100 {
            let rows = render(source, width);
            for row in &rows {
                assert!(
                    UnicodeWidthStr::width(row.text().as_str()) <= width,
                    "width {width}: {:?}",
                    row.text()
                );
            }
            if width > 60 {
                let all = text(&rows);
                assert!(
                    all.contains("Ultra 世界") && all.contains("Готово") && all.contains('┼'),
                    "{all}"
                );
            }
        }
    }
    #[test]
    fn narrow_tables_and_code_do_not_drop_wide_characters_to_fit_borders() {
        let table = format!(
            "{}\n{}\n{}",
            "| A ".repeat(10) + "|",
            "| --- ".repeat(10) + "|",
            "| 界 ".repeat(10) + "|"
        );
        for width in [41, 42, 51, 60] {
            let rows = render(&table, width);
            let all = text(&rows);
            assert_eq!(all.matches('界').count(), 10, "width {width}: {all}");
            assert!(
                rows.iter()
                    .all(|r| UnicodeWidthStr::width(r.text().as_str()) <= width)
            );
        }
        assert!(text(&render("```text\n世界\n```", 5)).contains("世界"));
    }
    #[test]
    fn parsed_entities_and_urls_cannot_inject_terminal_commands() {
        let rows = render(
            "**&#27;[2J** [link](https://x/&#27;)\n\n```sh\n\u{1b}]52;c;secret\u{7}\u{202e}\n```",
            80,
        );
        let all = text(&rows);
        assert!(
            !all.contains('\x1b') && !all.contains('\x07') && !all.contains('\u{202e}'),
            "{all:?}"
        );
    }
    #[test]
    fn entities_cannot_put_physical_linebreaks_inside_a_rendered_row() {
        for source in [
            "A&#10;B",
            "[label](https://example.com/&#10;bad)",
            "**&#9;&#10;value**",
        ] {
            let rows = render(source, 80);
            assert!(
                rows.iter()
                    .flat_map(|r| &r.spans)
                    .all(|s| !s.text.contains(['\n', '\r', '\t'])),
                "{rows:?}"
            );
            assert!(text(&rows).contains("\\n"));
        }
    }
    #[test]
    fn displayed_source_has_a_bounded_size() {
        let mut doc = Markdown::new();
        doc.append(&"я".repeat(MAX_SOURCE));
        doc.append("ignored");
        assert!(doc.source().len() <= MAX_SOURCE);
        assert!(text(&doc.rows(100)).contains("сокращён на экране"));
    }
}
