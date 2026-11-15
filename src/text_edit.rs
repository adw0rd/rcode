use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::ops::Range;

const AMBIGUOUS_MSG: &str =
    "old_text неоднозначен; уточните контекст или явно укажите replace_all=true";
const NOT_FOUND_MSG: &str = "old_text не найден; перечитайте файл";

#[derive(Clone, Copy, Debug)]
struct FileLine<'a> {
    start: usize,
    content_end: usize,
    full_end: usize,
    trimmed: &'a str,
}

/// Applies `edit_file` replacement in two stages:
/// - Stage 1: Exact byte match (preserving legacy `str::replace` behavior verbatim).
/// - Stage 2a: When exact match finds 0 occurrences, CRLF <-> LF normalized pass
///   preserving horizontal whitespace.
/// - Stage 2b: Full-line pass ignoring per-line trailing `' '` / `'\t'` and CRLF <-> LF
///   in `O(|text| + |old|)` time via KMP over interned line IDs.
pub(crate) fn apply_edit_text(
    text: &str,
    old: &str,
    new: &str,
    replace_all: bool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    ensure!(!old.is_empty(), "old_text не должен быть пустым");
    ensure!(
        old.len() <= max_bytes && new.len() <= max_bytes,
        "Слишком большой текст замены"
    );

    // Stage 1: exact byte match.
    let exact_count = text
        .match_indices(old)
        .take(if replace_all { usize::MAX } else { 2 })
        .count();
    if exact_count > 0 {
        let overlapping = if !replace_all {
            let first = text.find(old).expect("exact_count > 0");
            let next = first
                + text[first..]
                    .chars()
                    .next()
                    .expect("non-empty old")
                    .len_utf8();
            text[next..].contains(old)
        } else {
            false
        };
        ensure!(
            !overlapping && (exact_count == 1 || replace_all),
            "{AMBIGUOUS_MSG}"
        );
        let length = text
            .len()
            .checked_sub(exact_count * old.len())
            .and_then(|rem| {
                exact_count
                    .checked_mul(new.len())
                    .and_then(|added| rem.checked_add(added))
            })
            .context("Слишком большая замена")?;
        ensure!(length <= max_bytes, "Результат превышает лимит файла 1 MiB");
        return Ok(text.replace(old, new).into_bytes());
    }

    // Stage 2a: CRLF <-> LF normalization only (exact horizontal whitespace).
    let (norm, norm_to_orig) = normalize_crlf_with_map(text);
    let old_lf = old.replace("\r\n", "\n");
    debug_assert!(!old_lf.is_empty());

    let stage2a_count = norm
        .match_indices(&old_lf)
        .take(if replace_all { usize::MAX } else { 2 })
        .count();
    if stage2a_count > 0 {
        if !replace_all {
            let first = norm.find(&old_lf).expect("stage2a_count > 0");
            let next = first
                + norm[first..]
                    .chars()
                    .next()
                    .expect("non-empty old_lf")
                    .len_utf8();
            let overlapping = norm[next..].contains(&old_lf);
            ensure!(!overlapping && stage2a_count == 1, "{AMBIGUOUS_MSG}");
            let orig_range = norm_to_orig[first]..norm_to_orig[first + old_lf.len()];
            return replace_ranges_preserving_eol(
                text,
                std::slice::from_ref(&orig_range),
                new,
                max_bytes,
            );
        }
        let ranges: Vec<Range<usize>> = norm
            .match_indices(&old_lf)
            .map(|(start, _)| norm_to_orig[start]..norm_to_orig[start + old_lf.len()])
            .collect();
        return replace_ranges_preserving_eol(text, &ranges, new, max_bytes);
    }

    // Stage 2b: full-line match ignoring per-line trailing ' ' / '\t' and CRLF <-> LF.
    if text.is_empty() || !old_lf.bytes().any(|b| b != b' ' && b != b'\t') {
        bail!("{NOT_FOUND_MSG}");
    }

    let file_lines = split_file_lines(text);
    let (trailing_newline, body) = match old_lf.strip_suffix('\n') {
        Some(stripped) => (true, stripped),
        None => (false, old_lf.as_str()),
    };
    let old_lines: Vec<&str> = body
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']))
        .collect();
    let pat_len = old_lines.len();
    if pat_len == 0 || file_lines.len() < pat_len {
        bail!("{NOT_FOUND_MSG}");
    }

    let mut intern: HashMap<&str, u32> = HashMap::with_capacity(pat_len);
    let mut next_id = 0u32;
    let mut pat_ids = Vec::with_capacity(pat_len);
    for &line in &old_lines {
        let id = *intern.entry(line).or_insert_with(|| {
            let assigned = next_id;
            next_id = next_id.checked_add(1).expect("pattern lines <= 1 MiB");
            assigned
        });
        pat_ids.push(id);
    }

    let text_ids: Vec<u32> = file_lines
        .iter()
        .map(|line| intern.get(line.trimmed).copied().unwrap_or(u32::MAX))
        .collect();

    let pi = kmp_prefix(&pat_ids);
    let mut candidates: Vec<Range<usize>> = Vec::new();
    let mut matched = 0usize;
    for (idx, &tid) in text_ids.iter().enumerate() {
        while matched > 0 && pat_ids[matched] != tid {
            matched = pi[matched - 1];
        }
        if pat_ids[matched] == tid {
            matched += 1;
            if matched == pat_len {
                let start_line = idx + 1 - pat_len;
                let end_line = idx;
                matched = pi[matched - 1];

                if trailing_newline
                    && file_lines[end_line].full_end == file_lines[end_line].content_end
                {
                    continue;
                }
                let orig_start = file_lines[start_line].start;
                let orig_end = if trailing_newline {
                    file_lines[end_line].full_end
                } else {
                    file_lines[end_line].content_end
                };
                if orig_end > orig_start {
                    candidates.push(orig_start..orig_end);
                    if !replace_all && candidates.len() > 1 {
                        bail!("{AMBIGUOUS_MSG}");
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        bail!("{NOT_FOUND_MSG}");
    }
    if !replace_all {
        ensure!(candidates.len() == 1, "{AMBIGUOUS_MSG}");
        return replace_ranges_preserving_eol(text, &candidates, new, max_bytes);
    }

    let mut selected: Vec<Range<usize>> = Vec::with_capacity(candidates.len());
    let mut last_end = 0usize;
    for range in candidates {
        if range.start >= last_end {
            last_end = range.end;
            selected.push(range);
        }
    }
    replace_ranges_preserving_eol(text, &selected, new, max_bytes)
}

fn normalize_crlf_with_map(text: &str) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let mut norm = Vec::with_capacity(bytes.len());
    let mut norm_to_orig = Vec::with_capacity(bytes.len() + 1);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            norm.push(b'\n');
            norm_to_orig.push(i);
            i += 2;
        } else {
            norm.push(bytes[i]);
            norm_to_orig.push(i);
            i += 1;
        }
    }
    norm_to_orig.push(bytes.len());
    let norm_str = String::from_utf8(norm).expect("CRLF->LF preserves valid UTF-8");
    (norm_str, norm_to_orig)
}

fn split_file_lines(text: &str) -> Vec<FileLine<'_>> {
    if text.is_empty() {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut line_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            let content_end = if i > line_start && bytes[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            let full_end = i + 1;
            let trimmed = text[line_start..content_end].trim_end_matches([' ', '\t']);
            lines.push(FileLine {
                start: line_start,
                content_end,
                full_end,
                trimmed,
            });
            line_start = full_end;
        }
        i += 1;
    }
    if line_start < bytes.len() {
        let content_end = bytes.len();
        let trimmed = text[line_start..content_end].trim_end_matches([' ', '\t']);
        lines.push(FileLine {
            start: line_start,
            content_end,
            full_end: content_end,
            trimmed,
        });
    } else if bytes.ends_with(b"\n") {
        let end = bytes.len();
        lines.push(FileLine {
            start: end,
            content_end: end,
            full_end: end,
            trimmed: "",
        });
    }
    lines
}

fn kmp_prefix(pattern: &[u32]) -> Vec<usize> {
    let mut pi = vec![0usize; pattern.len()];
    let mut k = 0usize;
    for i in 1..pattern.len() {
        while k > 0 && pattern[k] != pattern[i] {
            k = pi[k - 1];
        }
        if pattern[k] == pattern[i] {
            k += 1;
        }
        pi[i] = k;
    }
    pi
}

fn count_line_endings(slice: &str) -> (usize, usize) {
    let bytes = slice.as_bytes();
    let mut crlf = 0usize;
    let mut lf_only = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            if i > 0 && bytes[i - 1] == b'\r' {
                crlf += 1;
            } else {
                lf_only += 1;
            }
        }
    }
    (crlf, lf_only)
}

fn replace_ranges_preserving_eol(
    text: &str,
    ranges: &[Range<usize>],
    new: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut file_eol: Option<bool> = None;
    let span_uses_crlf = |range: &Range<usize>, file_eol: &mut Option<bool>| -> bool {
        let (c, l) = count_line_endings(&text[range.clone()]);
        if c + l > 0 {
            c > l
        } else {
            *file_eol.get_or_insert_with(|| {
                let (fc, fl) = count_line_endings(text);
                fc > fl
            })
        }
    };
    let new_lf = new.replace("\r\n", "\n");
    let mut new_crlf: Option<String> = None;
    let mut range_crlf = Vec::with_capacity(ranges.len());
    let mut removed_bytes = 0usize;
    let mut added_bytes = 0usize;
    for range in ranges {
        let use_crlf = span_uses_crlf(range, &mut file_eol);
        range_crlf.push(use_crlf);
        let rep_len = if use_crlf {
            new_crlf
                .get_or_insert_with(|| new_lf.replace('\n', "\r\n"))
                .len()
        } else {
            new_lf.len()
        };
        removed_bytes = removed_bytes
            .checked_add(range.end - range.start)
            .context("Слишком большая замена")?;
        added_bytes = added_bytes
            .checked_add(rep_len)
            .context("Слишком большая замена")?;
    }

    let final_len = text
        .len()
        .checked_sub(removed_bytes)
        .and_then(|rem| rem.checked_add(added_bytes))
        .context("Слишком большая замена")?;
    ensure!(
        final_len <= max_bytes,
        "Результат превышает лимит файла 1 MiB"
    );

    let src = text.as_bytes();
    let mut out = Vec::with_capacity(final_len);
    let mut cursor = 0usize;
    for (range, &use_crlf) in ranges.iter().zip(&range_crlf) {
        out.extend_from_slice(&src[cursor..range.start]);
        let rep = if use_crlf {
            new_crlf.as_deref().unwrap_or(&new_lf)
        } else {
            &new_lf
        };
        out.extend_from_slice(rep.as_bytes());
        cursor = range.end;
    }
    out.extend_from_slice(&src[cursor..]);
    debug_assert_eq!(out.len(), final_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const MAX: usize = 1024 * 1024;

    #[test]
    fn exact_stage_preserves_legacy_behavior_and_ambiguity_checks() {
        let out = apply_edit_text("hello world\n", "world", "rust", false, MAX).unwrap();
        assert_eq!(out, b"hello rust\n");

        // Exact stage does not rewrite new_text line endings.
        let out = apply_edit_text("a\r\nb\r\n", "a", "x\ny", false, MAX).unwrap();
        assert_eq!(out, b"x\ny\r\nb\r\n");

        // Overlapping ambiguity in exact stage.
        let err = apply_edit_text("aaa", "aa", "b", false, MAX).unwrap_err();
        assert!(err.to_string().contains("неоднозначен"));

        // Duplicate ambiguity unless replace_all=true.
        let err = apply_edit_text("foo bar foo", "foo", "baz", false, MAX).unwrap_err();
        assert!(err.to_string().contains("неоднозначен"));
        let out = apply_edit_text("foo bar foo", "foo", "baz", true, MAX).unwrap();
        assert_eq!(out, b"baz bar baz");
    }

    #[test]
    fn stage2a_matches_crlf_files_with_lf_old_text_and_preserves_crlf() {
        let file = "fn main() {\r\n    let a = 1;\r\n    let b = 2;\r\n}\r\n";
        let old = "    let a = 1;\n    let b = 2;";
        let new = "    let a = 10;\n    let b = 20;";
        let out = apply_edit_text(file, old, new, false, MAX).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "fn main() {\r\n    let a = 10;\r\n    let b = 20;\r\n}\r\n"
        );

        // Reverse: CRLF old_text against LF file emits LF.
        let lf_file = "alpha\nbeta\ngamma\n";
        let out = apply_edit_text(lf_file, "alpha\r\nbeta", "one\r\ntwo", false, MAX).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "one\ntwo\ngamma\n");
    }

    #[test]
    fn stage2a_precedes_stage2b_when_only_line_endings_differ() {
        // Two lines differ only by trailing spaces; Stage 2a resolves uniquely by exact spaces!
        let file = "item = 1\r\nitem = 1   \r\n";
        let out = apply_edit_text(file, "item = 1\n", "item = 2\n", false, MAX).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "item = 2\r\nitem = 1   \r\n"
        );
    }

    #[test]
    fn stage2b_matches_full_lines_ignoring_trailing_spaces_and_tabs_only() {
        let file = "fn demo() {   \r\n    let x = 1;\t\t\r\n}\r\n";
        let old = "fn demo() {\n    let x = 1;\n}";
        let new = "fn demo() {\n    let x = 42;\n}";
        let out = apply_edit_text(file, old, new, false, MAX).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "fn demo() {\r\n    let x = 42;\r\n}\r\n"
        );

        // Single full line without newline in old_text (where trailing whitespace differs) preserves the file's line ending.
        let single = "let value = 1;   \r\nlet next = 2;\r\n";
        let out =
            apply_edit_text(single, "let value = 1;\t", "let value = 9;", false, MAX).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "let value = 9;\r\nlet next = 2;\r\n"
        );

        // Substring inside a line must NOT match via trailing-whitespace stripping.
        let in_literal = "let msg = \"hello   \";\n";
        let err = apply_edit_text(in_literal, "\"hello\"", "\"world\"", false, MAX).unwrap_err();
        assert!(err.to_string().contains("не найден"));

        // Curly / guillemet quotes are NEVER normalized.
        let quotes = "let title = «Поребрик»;\n";
        let err =
            apply_edit_text(quotes, "let title = \"Поребрик\";", "x", false, MAX).unwrap_err();
        assert!(err.to_string().contains("не найден"));
    }

    #[test]
    fn stage2b_handles_trailing_empty_segment_and_adjacent_byte_ranges() {
        // Distinguishing trailing empty segment case: file ends with '\n', old ends with trailing space on empty line.
        let out = apply_edit_text("a \n", "a\t\n ", "b\n", false, MAX).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "b\n");

        // Adjacent non-overlapping byte ranges [0..4) and [4..8) both apply under replace_all=true.
        let out = apply_edit_text("\na \n\na \n\n", "\na\t\n ", "\nb\n", true, MAX).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\nb\n\nb\n\n");

        // Without replace_all, the same two windows are rejected as ambiguous.
        let err = apply_edit_text("\na \n\na \n\n", "\na\t\n ", "\nb\n", false, MAX).unwrap_err();
        assert!(err.to_string().contains("неоднозначен"));

        // Whitespace-only single line without '\n' is rejected, whereas multi-line "\t\n\t" works.
        let err = apply_edit_text("   \n", "\t", "x", false, MAX).unwrap_err();
        assert!(err.to_string().contains("не найден"));
        let out = apply_edit_text(" \n ", "\t\n\t", "x\ny", false, MAX).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "x\ny");
    }

    #[test]
    fn stage2b_kmp_runs_in_linear_time_on_adversarial_1mib_input() {
        let text = "a \n".repeat(262_144);
        assert!(text.len() <= MAX);
        let mut old = "a\n".repeat(131_071);
        old.push_str("b\n");
        assert!(old.len() <= MAX);

        let started = Instant::now();
        let err = apply_edit_text(&text, &old, "c\n", false, MAX).unwrap_err();
        assert!(err.to_string().contains("не найден"));
        assert!(
            started.elapsed().as_millis() < 1_000,
            "KMP Stage 2b took too long: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn enforces_max_bytes_limit_on_fallback_expansion() {
        let file = "line   \r\n".repeat(100);
        let huge_new = "x".repeat(15_000);
        let err = apply_edit_text(&file, "line", &huge_new, true, MAX).unwrap_err();
        assert!(err.to_string().contains("1 MiB"));
    }

    #[test]
    fn mixed_eol_uses_matched_span_style_first_and_falls_back_to_file_for_single_line() {
        // File overall has more LF lines (4 LF vs 2 CRLF), but the matched span is CRLF:
        // multi-line replacement preserves the matched span's CRLF style.
        let mixed = "lf1\nlf2\ncrlf_a\r\ncrlf_b\r\nlf3\nlf4\n";
        let out_span =
            apply_edit_text(mixed, "crlf_a\ncrlf_b", "new_a\nnew_b\nnew_c", false, MAX).unwrap();
        assert_eq!(
            String::from_utf8(out_span).unwrap(),
            "lf1\nlf2\nnew_a\r\nnew_b\r\nnew_c\r\nlf3\nlf4\n"
        );

        // Single-line Stage 2b match has 0 line breaks inside the matched content range,
        // so it falls back to the whole file's dominant line-ending style (CRLF here).
        let crlf_dominant = "h1\r\nh2\r\nsingle_target   \nlf_tail\n";
        // 2 CRLF vs 2 LF -> tie prefers LF; 3 CRLF vs 1 LF -> prefers CRLF.
        let crlf_dominant_three = "h1\r\nh2\r\nh3\r\nsingle_target   \n";
        let out_single = apply_edit_text(
            crlf_dominant_three,
            "single_target\t",
            "line_one\nline_two",
            false,
            MAX,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out_single).unwrap(),
            "h1\r\nh2\r\nh3\r\nline_one\r\nline_two\n"
        );
        let _ = crlf_dominant;

        // Under replace_all=true in a mixed-EOL file, each matched span preserves its own EOL style!
        let mixed_multi = "a \r\nb \r\n--\na \nb \n";
        let out_multi = apply_edit_text(mixed_multi, "a\t\nb\t\n", "x\ny\n", true, MAX).unwrap();
        assert_eq!(
            String::from_utf8(out_multi).unwrap(),
            "x\r\ny\r\n--\nx\ny\n"
        );
    }
}
