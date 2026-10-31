//! Hides a leading `<think>…</think>` block that some local servers leave in
//! `content`. Only a block at the very start of the answer is treated as
//! reasoning; the same text later in an answer (code, docs) is content.
//!
//! Some chat templates open `<think>` inside the prompt, so the answer starts
//! with reasoning and an orphan `</think>`. That case is recognized only within
//! an explicit window at the start of the answer (see `for_local`): it is a
//! bounded heuristic, not detection of every form of reasoning. Text without a
//! closing tag is never lost: it is released as content.
use crate::local::LocalRuntime;

const OPEN: &str = "<think>";
const CLOSE: &str = "</think>";
/// Bytes held back for an orphan `</think>` when thinking is not configured on
/// a server that does not separate reasoning itself (MLX, generic servers).
pub(crate) const ORPHAN_WINDOW: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Not enough text yet to tell whether the answer opens with `<think>`.
    Start,
    Inside,
    /// Skip whitespace that separates the closed block from the answer.
    AfterThink,
    Pass,
}

/// The stream ended inside an unclosed reasoning block.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unclosed;

pub(crate) struct ThinkFilter {
    state: State,
    buffer: String,
    /// 0: only a leading `<think>` block; otherwise how many bytes may be held
    /// back while looking for an orphan `</think>`.
    orphan_window: usize,
}

impl Default for ThinkFilter {
    fn default() -> Self {
        Self::with_orphan_window(0)
    }
}

impl ThinkFilter {
    pub(crate) fn with_orphan_window(orphan_window: usize) -> Self {
        Self {
            state: State::Start,
            buffer: String::new(),
            orphan_window,
        }
    }

    /// `thinking`: the profile's explicit choice. Explicitly thinking models
    /// are held until `</think>` (within the SSE size limit); with thinking off
    /// nothing is held back. Without a choice only MLX and generic servers,
    /// which leave reasoning in `content`, get a small window.
    pub(crate) fn for_local(runtime: LocalRuntime, thinking: Option<bool>) -> Self {
        Self::with_orphan_window(match thinking {
            Some(true) => usize::MAX,
            Some(false) => 0,
            None if matches!(runtime, LocalRuntime::Mlx | LocalRuntime::OpenAi) => ORPHAN_WINDOW,
            None => 0,
        })
    }

    /// Start state without a leading `<think>`: look for `</think>` that ends
    /// reasoning opened by the template. `None` means: wait for more text.
    fn orphan(&mut self, reasoning: &mut String) -> Option<bool> {
        let Some(end) = self.buffer.find(CLOSE) else {
            // Wait within the window; beyond it the text is ordinary content.
            return (self.buffer.len() >= self.orphan_window).then_some(false);
        };
        if end >= self.orphan_window {
            return Some(false);
        }
        let after = &self.buffer[end + CLOSE.len()..];
        // A real close is followed by a line break or space; a tag quoted in an
        // answer (`</think>`, "</think>.") is content.
        let Some(next) = after.chars().next() else {
            return (self.buffer.len() >= self.orphan_window).then_some(false);
        };
        if !next.is_whitespace()
            || self.buffer[..end].contains(OPEN)
            || self.buffer[..end].ends_with(['`', '"', '\'', '<'])
        {
            return Some(false);
        }
        reasoning.push_str(&self.buffer[..end]);
        self.buffer = after.to_owned();
        Some(true)
    }

    /// Returns the text that may be shown; reasoning goes to `reasoning`.
    pub(crate) fn push(&mut self, text: &str, reasoning: &mut String) -> String {
        if self.state == State::Pass {
            return text.to_owned();
        }
        self.buffer.push_str(text);
        loop {
            match self.state {
                State::Start => {
                    let trimmed = self.buffer.trim_start();
                    if let Some(rest) = trimmed.strip_prefix(OPEN) {
                        self.buffer = rest.to_owned();
                        self.state = State::Inside;
                    } else if OPEN.starts_with(trimmed) {
                        return String::new();
                    } else if self.orphan_window == 0 {
                        self.state = State::Pass;
                        return std::mem::take(&mut self.buffer);
                    } else {
                        match self.orphan(reasoning) {
                            None => return String::new(),
                            Some(true) => self.state = State::AfterThink,
                            Some(false) => {
                                self.state = State::Pass;
                                return std::mem::take(&mut self.buffer);
                            }
                        }
                    }
                }
                State::Inside => {
                    if let Some(end) = self.buffer.find(CLOSE) {
                        reasoning.push_str(&self.buffer[..end]);
                        self.buffer = self.buffer[end + CLOSE.len()..].to_owned();
                        self.state = State::AfterThink;
                    } else {
                        // Keep a suffix that may be the beginning of a split `</think>`.
                        let keep = (1..CLOSE.len())
                            .rev()
                            .find(|length| self.buffer.ends_with(&CLOSE[..*length]))
                            .unwrap_or(0);
                        let split = self.buffer.len() - keep;
                        reasoning.push_str(&self.buffer[..split]);
                        self.buffer.drain(..split);
                        return String::new();
                    }
                }
                State::AfterThink => {
                    let trimmed = self.buffer.trim_start();
                    if trimmed.is_empty() {
                        self.buffer.clear();
                        return String::new();
                    }
                    let visible = trimmed.to_owned();
                    self.buffer.clear();
                    self.state = State::Pass;
                    return visible;
                }
                State::Pass => return std::mem::take(&mut self.buffer),
            }
        }
    }

    /// Flushes undecided text at the end of the answer.
    pub(crate) fn finish(&mut self, reasoning: &mut String) -> Result<String, Unclosed> {
        // Reasoning that ends exactly at the end of the answer.
        if self.state == State::Start
            && self.orphan_window > 0
            && let Some(prefix) = self.buffer.trim_end().strip_suffix(CLOSE)
            && prefix.len() < self.orphan_window
            && !prefix.contains(OPEN)
            && !prefix.ends_with(['`', '"', '\'', '<'])
        {
            reasoning.push_str(prefix);
            self.buffer.clear();
            return Ok(String::new());
        }
        match self.state {
            State::Start | State::Pass => Ok(std::mem::take(&mut self.buffer)),
            State::AfterThink => {
                self.buffer.clear();
                Ok(String::new())
            }
            State::Inside => {
                reasoning.push_str(&std::mem::take(&mut self.buffer));
                Err(Unclosed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&str]) -> (String, String, Result<(), Unclosed>) {
        let mut filter = ThinkFilter::default();
        let mut reasoning = String::new();
        let mut visible = String::new();
        for chunk in chunks {
            visible.push_str(&filter.push(chunk, &mut reasoning));
        }
        let end = filter
            .finish(&mut reasoning)
            .map(|rest| visible.push_str(&rest));
        (visible, reasoning, end)
    }

    #[test]
    fn leading_block_is_hidden_even_when_tags_are_split_across_chunks() {
        let text = "\n<think>план: прочитать файл</think>\n\nГотово: `<think>` в коде остаётся.";
        for size in 1..=9 {
            let chunks: Vec<String> = text
                .chars()
                .collect::<Vec<_>>()
                .chunks(size)
                .map(|chunk| chunk.iter().collect())
                .collect();
            let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
            let (visible, reasoning, end) = run(&chunks);
            assert_eq!(visible, "Готово: `<think>` в коде остаётся.", "size {size}");
            assert_eq!(reasoning, "план: прочитать файл");
            assert_eq!(end, Ok(()));
        }
    }

    #[test]
    fn similar_prefixes_and_late_tags_are_content() {
        for text in [
            "<thinking>x</thinking>",
            "<th>table</th>",
            "<",
            "Ответ <think>a</think>",
            "  ",
        ] {
            let (visible, reasoning, end) = run(&[text]);
            assert_eq!(visible, text);
            assert!(reasoning.is_empty());
            assert_eq!(end, Ok(()));
        }
        let (visible, _, _) = run(&["<th", "e>x"]);
        assert_eq!(visible, "<the>x");
    }

    #[test]
    fn unclosed_block_is_reported_not_shown() {
        let (visible, reasoning, end) = run(&["<think>", "долгие рассуждения </thi"]);
        assert!(visible.is_empty());
        assert_eq!(reasoning, "долгие рассуждения </thi");
        assert_eq!(end, Err(Unclosed));
    }

    #[test]
    fn empty_reasoning_block_and_only_reasoning() {
        let (visible, reasoning, end) = run(&["<think></think>", "ok"]);
        assert_eq!(
            (visible.as_str(), reasoning.as_str(), end),
            ("ok", "", Ok(()))
        );
        let (visible, _, end) = run(&["<think>x</think>\n\n"]);
        assert_eq!((visible.as_str(), end), ("", Ok(())));
    }

    fn orphan(window: usize, chunks: &[&str]) -> (String, String, Vec<String>) {
        let mut filter = ThinkFilter::with_orphan_window(window);
        let mut reasoning = String::new();
        let mut pieces = Vec::new();
        for chunk in chunks {
            pieces.push(filter.push(chunk, &mut reasoning));
        }
        let rest = filter.finish(&mut reasoning).unwrap();
        pieces.push(rest);
        (pieces.concat(), reasoning, pieces)
    }

    fn split(text: &str, size: usize) -> Vec<String> {
        text.chars()
            .collect::<Vec<_>>()
            .chunks(size)
            .map(|chunk| chunk.iter().collect())
            .collect()
    }

    #[test]
    fn orphan_close_from_template_is_hidden_in_any_split() {
        let text = "план: прочитать файл</think>\n\nответ";
        for window in [ORPHAN_WINDOW, usize::MAX] {
            for size in 1..=9 {
                let chunks = split(text, size);
                let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
                let (visible, reasoning, _) = orphan(window, &chunks);
                assert_eq!(visible, "ответ", "window {window} size {size}");
                assert_eq!(reasoning, "план: прочитать файл");
            }
        }
        // Reasoning only: the answer is empty, nothing leaks.
        let (visible, reasoning, _) = orphan(ORPHAN_WINDOW, &["думаю</think>", "\n"]);
        assert_eq!((visible.as_str(), reasoning.as_str()), ("", "думаю"));
    }

    #[test]
    fn plain_answers_lose_nothing_and_stream_after_the_window() {
        let short = "Короткий ответ без тегов.";
        assert_eq!(orphan(ORPHAN_WINDOW, &[short]).0, short);
        assert_eq!(
            orphan(usize::MAX, &[short]).0,
            short,
            "EOF releases held text"
        );
        let long = "строка ответа\n".repeat(200);
        let chunks = split(&long, 7);
        let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
        let (visible, reasoning, pieces) = orphan(ORPHAN_WINDOW, &chunks);
        assert_eq!(visible, long);
        assert!(reasoning.is_empty());
        let first = pieces.iter().position(|piece| !piece.is_empty()).unwrap();
        assert!(
            first < chunks.len() / 2,
            "streaming resumes after the window"
        );
        // Disabled thinking holds nothing back.
        assert_eq!(orphan(0, &["первый"]).2[0], "первый");
    }

    #[test]
    fn quoted_or_late_close_tags_stay_content() {
        for text in [
            "Тег `</think>` закрывает рассуждение.",
            "Пишите \"</think>\" без пробела",
            "Ответ <think>a</think> b",
            "Закрытие </think>.",
        ] {
            let (visible, reasoning, _) = orphan(ORPHAN_WINDOW, &[text]);
            assert_eq!(visible, text);
            assert!(reasoning.is_empty(), "{text}");
        }
        let late = format!("{}</think>\nхвост", "x".repeat(ORPHAN_WINDOW + 10));
        assert_eq!(
            orphan(ORPHAN_WINDOW, &[&late]).0,
            late,
            "beyond the window it is content"
        );
        assert_eq!(orphan(0, &["план</think>\nответ"]).0, "план</think>\nответ");
    }

    #[test]
    fn window_follows_runtime_and_explicit_thinking() {
        let window = |runtime, thinking| ThinkFilter::for_local(runtime, thinking).orphan_window;
        assert_eq!(window(LocalRuntime::Mlx, None), ORPHAN_WINDOW);
        assert_eq!(window(LocalRuntime::OpenAi, None), ORPHAN_WINDOW);
        assert_eq!(window(LocalRuntime::Ollama, None), 0);
        assert_eq!(window(LocalRuntime::LlamaCpp, None), 0);
        assert_eq!(window(LocalRuntime::Mlx, Some(false)), 0);
        assert_eq!(window(LocalRuntime::LlamaCpp, Some(true)), usize::MAX);
    }
}
