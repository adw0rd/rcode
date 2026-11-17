use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::ops::Range;

#[derive(Clone, Copy, Debug)]
struct FileLine<'a> {
    start: usize,
    content_end: usize,
    full_end: usize,
    trimmed: &'a str,
}

#[derive(Clone, Copy, Debug)]
enum MissLocation {
    None,
    MissingFinalNewline {
        start_line: usize,
        matched_lines: usize,
    },
    Prefix {
        start_line: usize,
        matched_lines: usize,
        pat_len: usize,
        mismatch_line: Option<usize>,
    },
    Anchor {
        old_line_1based: usize,
        file_line_1based: usize,
    },
}

/// Applies `edit_file` replacement in two stages:
/// - Stage 1: Exact byte match (preserving legacy `str::replace` behavior verbatim).
/// - Stage 2a: When exact match finds 0 occurrences, CRLF <-> LF normalized pass
///   preserving horizontal whitespace.
/// - Stage 2b: Full-line pass ignoring per-line trailing `' '` / `'\t'` and CRLF <-> LF
///   in `O(|text| + |old|)` time via KMP over interned line IDs.
#[cfg(test)]
pub(crate) fn apply_edit_text(
    text: &str,
    old: &str,
    new: &str,
    replace_all: bool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    apply_edit_text_with_context(text, old, new, replace_all, max_bytes, || false)
}

pub(crate) fn apply_edit_text_with_context<F>(
    text: &str,
    old: &str,
    new: &str,
    replace_all: bool,
    max_bytes: usize,
    snapshot_is_fresh: F,
) -> Result<Vec<u8>>
where
    F: FnOnce() -> bool,
{
    ensure!(!old.is_empty(), "old_text не должен быть пустым");
    ensure!(
        old.len() <= max_bytes && new.len() <= max_bytes,
        "Слишком большой текст замены"
    );

    // Stage 1: exact byte match.
    let exact_count = if replace_all {
        text.match_indices(old).count()
    } else {
        let sample: Vec<usize> = text.match_indices(old).take(4).map(|(i, _)| i).collect();
        if !sample.is_empty() {
            let first = sample[0];
            let next = first
                + text[first..]
                    .chars()
                    .next()
                    .expect("non-empty old")
                    .len_utf8();
            let overlapping = sample.len() == 1 && text[next..].contains(old);
            if overlapping || sample.len() > 1 {
                bail!(
                    "{}",
                    format_ambiguous_message(
                        text,
                        &sample[..sample.len().min(3)],
                        sample.len() > 3,
                        overlapping,
                    )
                );
            }
        }
        sample.len()
    };
    if exact_count > 0 {
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

    if !replace_all {
        let sample: Vec<usize> = norm
            .match_indices(&old_lf)
            .take(4)
            .map(|(i, _)| i)
            .collect();
        if !sample.is_empty() {
            let first = sample[0];
            let next = first
                + norm[first..]
                    .chars()
                    .next()
                    .expect("non-empty old_lf")
                    .len_utf8();
            let overlapping = sample.len() == 1 && norm[next..].contains(&old_lf);
            if overlapping || sample.len() > 1 {
                let orig_offsets: Vec<usize> =
                    sample.iter().take(3).map(|&i| norm_to_orig[i]).collect();
                bail!(
                    "{}",
                    format_ambiguous_message(text, &orig_offsets, sample.len() > 3, overlapping)
                );
            }
            let orig_range = norm_to_orig[first]..norm_to_orig[first + old_lf.len()];
            return replace_ranges_preserving_eol(
                text,
                std::slice::from_ref(&orig_range),
                new,
                max_bytes,
            );
        }
    } else {
        let ranges: Vec<Range<usize>> = norm
            .match_indices(&old_lf)
            .map(|(start, _)| norm_to_orig[start]..norm_to_orig[start + old_lf.len()])
            .collect();
        if !ranges.is_empty() {
            return replace_ranges_preserving_eol(text, &ranges, new, max_bytes);
        }
    }

    // Stage 2b: full-line match ignoring per-line trailing ' ' / '\t' and CRLF <-> LF.
    if text.is_empty() || !old_lf.bytes().any(|b| b != b' ' && b != b'\t') {
        bail!(
            "{}",
            format_not_found_message(text, old, &old_lf, MissLocation::None, snapshot_is_fresh())
        );
    }

    let file_line_count = text.lines().count();
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
    if pat_len == 0 {
        bail!(
            "{}",
            format_not_found_message(text, old, &old_lf, MissLocation::None, snapshot_is_fresh())
        );
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
    let min_meaningful_len = min_meaningful_prefix_len(&old_lines);
    let mut candidates: Vec<Range<usize>> = Vec::new();
    let mut best_prefix: Option<(usize, usize)> = None;
    let mut missing_eof_newline_start: Option<usize> = None;
    let mut matched = 0usize;
    for (idx, &tid) in text_ids.iter().enumerate() {
        while matched > 0 && pat_ids[matched] != tid {
            matched = pi[matched - 1];
        }
        if pat_ids[matched] == tid {
            matched += 1;
            if idx < file_line_count
                && matched < pat_len
                && best_prefix.is_none_or(|(best_len, _)| matched > best_len)
                && min_meaningful_len.is_some_and(|min_len| matched >= min_len)
            {
                let start_idx = idx + 1 - matched;
                if start_idx < file_line_count {
                    best_prefix = Some((matched, start_idx));
                }
            }
            if matched == pat_len {
                let start_line = idx + 1 - pat_len;
                let end_line = idx;
                matched = pi[matched - 1];

                if trailing_newline
                    && file_lines[end_line].full_end == file_lines[end_line].content_end
                {
                    if end_line < file_line_count && missing_eof_newline_start.is_none() {
                        missing_eof_newline_start = Some(start_line + 1);
                    }
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
                    if !replace_all && candidates.len() >= 4 {
                        break;
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        let location = if let Some(start_line) = missing_eof_newline_start {
            MissLocation::MissingFinalNewline {
                start_line,
                matched_lines: pat_len,
            }
        } else if let Some((matched_lines, start_idx)) = best_prefix {
            let mismatch = start_idx + matched_lines + 1;
            MissLocation::Prefix {
                start_line: start_idx + 1,
                matched_lines,
                pat_len,
                mismatch_line: (mismatch <= file_line_count).then_some(mismatch),
            }
        } else {
            find_anchor_line(&old_lines, &pat_ids, &text_ids[..file_line_count])
        };
        bail!(
            "{}",
            format_not_found_message(text, old, &old_lf, location, snapshot_is_fresh())
        );
    }
    if !replace_all {
        if candidates.len() > 1 {
            let orig_offsets: Vec<usize> = candidates.iter().take(3).map(|r| r.start).collect();
            bail!(
                "{}",
                format_ambiguous_message(text, &orig_offsets, candidates.len() > 3, false)
            );
        }
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

fn min_meaningful_prefix_len(old_lines: &[&str]) -> Option<usize> {
    let first_alnum4 = old_lines
        .iter()
        .position(|line| {
            let trimmed = line.trim();
            trimmed.chars().count() >= 4 && trimmed.chars().any(char::is_alphanumeric)
        })
        .map(|idx| idx + 1);
    let first_two_nonempty = (old_lines.len() >= 2)
        .then(|| {
            old_lines
                .iter()
                .position(|line| !line.trim().is_empty())
                .map(|idx| (idx + 1).max(2))
        })
        .flatten();
    match (first_alnum4, first_two_nonempty) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn find_anchor_line(old_lines: &[&str], pat_ids: &[u32], text_ids: &[u32]) -> MissLocation {
    let mut id_hits = [(0u32, 0usize); 16];
    for (idx, &tid) in text_ids.iter().enumerate() {
        let slot = tid as usize;
        if slot < id_hits.len() {
            if id_hits[slot].0 == 0 {
                id_hits[slot].1 = idx;
            }
            id_hits[slot].0 = id_hits[slot].0.saturating_add(1);
        }
    }
    for (k, (&line, &pid)) in old_lines.iter().zip(pat_ids.iter()).enumerate() {
        let slot = pid as usize;
        if slot >= id_hits.len() {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.chars().count() >= 8
            && trimmed.chars().any(char::is_alphanumeric)
            && (1..=3).contains(&id_hits[slot].0)
        {
            return MissLocation::Anchor {
                old_line_1based: k + 1,
                file_line_1based: id_hits[slot].1 + 1,
            };
        }
    }
    MissLocation::None
}

fn looks_like_numbered_read_output(old_lf: &str) -> bool {
    let mut iter = old_lf.lines().peekable();
    let Some(first_line) = iter.next() else {
        return false;
    };
    let has_multiple = iter.peek().is_some();
    let mut prev_num: Option<u32> = None;
    let mut saw_tab = false;
    let mut parsed_any = false;
    for line in std::iter::once(first_line).chain(iter) {
        if !has_multiple && line.trim().is_empty() {
            return false;
        }
        let trimmed_spaces = line.trim_start_matches(' ');
        if !matches!(trimmed_spaces.as_bytes().first(), Some(b'1'..=b'9')) {
            return false;
        }
        let digit_len = trimmed_spaces
            .bytes()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if !(1..=7).contains(&digit_len) {
            return false;
        }
        let Ok(num) = trimmed_spaces[..digit_len].parse::<u32>() else {
            return false;
        };
        let rest = &trimmed_spaces[digit_len..];
        if rest.starts_with('\t') {
            saw_tab = true;
        } else if !(rest.is_empty() && has_multiple) {
            return false;
        }
        if let Some(prev) = prev_num
            && num != prev.saturating_add(1)
        {
            return false;
        }
        prev_num = Some(num);
        parsed_any = true;
    }
    parsed_any && saw_tab
}

fn offsets_to_1based_lines(text: &str, sorted_offsets: &[usize]) -> Vec<usize> {
    if sorted_offsets.is_empty() {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(sorted_offsets.len());
    let mut cursor = 0usize;
    let mut line = 1usize;
    for &target in sorted_offsets {
        let clamped = target.min(bytes.len());
        while cursor < clamped {
            if bytes[cursor] == b'\n' {
                line += 1;
            }
            cursor += 1;
        }
        if out.last().copied() != Some(line) {
            out.push(line);
        }
    }
    out
}

fn format_ambiguous_message(
    text: &str,
    byte_offsets: &[usize],
    has_more: bool,
    overlapping: bool,
) -> String {
    let lines = offsets_to_1based_lines(text, byte_offsets);
    if overlapping {
        let line = lines.first().copied().unwrap_or(1);
        return format!(
            "old_text неоднозначен (перекрывающиеся вхождения на {line}-й строке); расширьте old_text соседним контекстом или явно укажите replace_all=true"
        );
    }
    if lines.len() <= 1 && !has_more {
        let line = lines.first().copied().unwrap_or(1);
        return format!(
            "old_text неоднозначен (несколько совпадений на {line}-й строке); уточните контекст или явно укажите replace_all=true"
        );
    }
    let joined = lines
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if has_more { " и др." } else { "" };
    format!(
        "old_text неоднозначен (совпадения на строках {joined}{suffix}); включите соседние строки для уникальности или явно укажите replace_all=true"
    )
}

fn format_not_found_message(
    text: &str,
    old: &str,
    old_lf: &str,
    location: MissLocation,
    snapshot_fresh: bool,
) -> String {
    let file_line_count = text.lines().count();
    let old_line_count = old_lf.lines().count().max(1);
    if text.is_empty() {
        return if snapshot_fresh {
            format!(
                "old_text не найден (файл пуст: 0 стр., old_text: {old_line_count} стр.); снимок файла уже актуален — запишите содержимое через write_file без expected_sha256"
            )
        } else {
            format!(
                "old_text не найден (файл пуст: 0 стр., old_text: {old_line_count} стр.); прочитайте файл через read_file и запишите содержимое через write_file без expected_sha256"
            )
        };
    }

    let numbered = looks_like_numbered_read_output(old_lf);
    let mut details = vec![format!(
        "файл: {file_line_count} стр., old_text: {old_line_count} стр."
    )];
    if numbered {
        details.push("в old_text обнаружены префиксы номеров строк N\\t из read_file".to_owned());
    }
    match location {
        MissLocation::None => {}
        MissLocation::MissingFinalNewline {
            start_line,
            matched_lines,
        } => {
            details.push(format!(
                "совпали все {matched_lines} стр. с {start_line}-й строки, но в конце файла нет завершающего перевода строки"
            ));
        }
        MissLocation::Prefix {
            start_line,
            matched_lines,
            pat_len,
            mismatch_line: Some(mismatch),
        } => {
            details.push(format!(
                "совпали первые {matched_lines} из {pat_len} стр. с {start_line}-й строки, расхождение на {mismatch}-й строке"
            ));
        }
        MissLocation::Prefix {
            start_line,
            matched_lines,
            pat_len,
            mismatch_line: None,
        } => {
            details.push(format!(
                "совпали первые {matched_lines} из {pat_len} стр. с {start_line}-й строки до конца файла"
            ));
        }
        MissLocation::Anchor {
            old_line_1based,
            file_line_1based,
        } => {
            details.push(format!(
                "ориентир: строка {old_line_1based} old_text найдена на {file_line_1based}-й строке файла"
            ));
        }
    }

    let is_broad = old_line_count >= 12
        || old.len() >= 600
        || (old_line_count >= 6 && old_line_count * 2 >= file_line_count);
    let guidance = if numbered {
        if is_broad && snapshot_fresh {
            "уберите префиксы N\\t из old_text (передайте 3–8 строк контекста) или для крупной замены сразу вызовите write_file без expected_sha256"
        } else if is_broad {
            "уберите префиксы N\\t из old_text и передайте короткий контекст (3–8 строк), либо для крупной замены прочитайте файл через read_file и перезапишите через write_file без expected_sha256"
        } else {
            "уберите префиксы N\\t из old_text и передайте чистый уникальный фрагмент файла"
        }
    } else if is_broad && snapshot_fresh {
        "снимок файла в текущем ходе уже актуален: для крупной замены сразу вызовите write_file без expected_sha256, либо прочитайте нужный диапазон через read_file(start_line, max_lines) и передайте короткий уникальный old_text (3–8 строк)"
    } else if is_broad {
        "для точечной правки прочитайте нужный диапазон через read_file(start_line, max_lines) и передайте короткий уникальный old_text (3–8 строк), либо для крупной замены прочитайте файл через read_file и перезапишите через write_file без expected_sha256"
    } else {
        "перечитайте нужный диапазон через read_file(start_line, max_lines) и передайте точный уникальный фрагмент без префиксов N\\t"
    };

    format!("old_text не найден ({}); {guidance}", details.join(", "))
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

    #[test]
    fn diagnostics_report_line_counts_partial_prefix_anchor_and_numbered_prefixes_without_echoing_file_text()
     {
        let secret_marker = "SUPER_SECRET_SENTINEL_DO_NOT_ECHO_991";

        // 1) Empty file with stale/missing snapshot vs fresh snapshot.
        let empty_stale = apply_edit_text_with_context("", "x = 1", "x = 2", false, MAX, || false)
            .unwrap_err()
            .to_string();
        assert!(empty_stale.starts_with("old_text не найден"));
        assert!(empty_stale.contains("файл пуст: 0 стр."));
        assert!(empty_stale.contains("прочитайте файл через read_file"));

        let empty_fresh = apply_edit_text_with_context("", "x = 1", "x = 2", false, MAX, || true)
            .unwrap_err()
            .to_string();
        assert!(empty_fresh.contains("снимок файла уже актуален"));
        assert!(empty_fresh.contains("write_file без expected_sha256"));

        // 2) Partial KMP prefix match reports exact 1-based start and divergence lines without leaking text.
        let mut lines = Vec::new();
        for idx in 1..=20 {
            lines.push(format!("def func_{idx}(): return {idx} # {secret_marker}"));
        }
        let file = format!("{}\n", lines.join("\n"));
        let partial_old = format!(
            "{}\n{}\n{}\ndef wrong_line(): return 999\n{}",
            lines[9], lines[10], lines[11], lines[13]
        );
        let err_partial = apply_edit_text(&file, &partial_old, "pass", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(err_partial.starts_with("old_text не найден"));
        assert!(
            err_partial.contains("файл: 20 стр., old_text: 5 стр."),
            "{err_partial}"
        );
        assert!(
            err_partial
                .contains("совпали первые 3 из 5 стр. с 10-й строки, расхождение на 13-й строке"),
            "{err_partial}"
        );
        assert!(!err_partial.contains(secret_marker));
        assert!(!err_partial.contains("wrong_line"));

        // 3) Prefix matching to EOF when old_text overruns the end of file.
        let overrun_old = format!("{}\n{}\nextra_after_eof = 1", lines[18], lines[19]);
        let err_eof = apply_edit_text(&file, &overrun_old, "pass", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            err_eof.contains("совпали первые 2 из 3 стр. с 19-й строки до конца файла"),
            "{err_eof}"
        );

        // 4) Missing final newline at EOF vs synthetic EOF sentinel when file already ends with '\n'.
        let no_eof_nl = "alpha_line\nbeta_line";
        let err_nl = apply_edit_text(no_eof_nl, "alpha_line\nbeta_line\n", "x\n", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            err_nl.contains(
                "совпали все 2 стр. с 1-й строки, но в конце файла нет завершающего перевода строки"
            ),
            "{err_nl}"
        );
        let err_synth = apply_edit_text("alpha\n", "alpha\n\n", "x\n", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            !err_synth.contains("нет завершающего перевода строки"),
            "{err_synth}"
        );
        assert!(
            err_synth.contains("совпали первые 1 из 2 стр. с 1-й строки до конца файла"),
            "{err_synth}"
        );
        let err_two_punct = apply_edit_text("{} \n)\nactual\n", "{}\n)\nmissing", "x", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            err_two_punct
                .contains("совпали первые 2 из 3 стр. с 1-й строки, расхождение на 3-й строке"),
            "{err_two_punct}"
        );

        // 5) Anchor fallback when line 1 of old_text diverges.
        let anchor_old = format!("def outdated_header():\n{}\n{}", lines[14], lines[15]);
        let err_anchor = apply_edit_text(&file, &anchor_old, "pass", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            err_anchor.contains("ориентир: строка 2 old_text найдена на 15-й строке файла"),
            "{err_anchor}"
        );
        assert!(!err_anchor.contains(secret_marker));

        // 6) Broad old_text (>= 12 lines) distinguishes fresh vs stale read_snapshots.
        let broad_old = (0..14)
            .map(|i| format!("missing_line_{i} = {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let broad_stale =
            apply_edit_text_with_context(&file, &broad_old, "x", false, MAX, || false)
                .unwrap_err()
                .to_string();
        assert!(broad_stale.contains("3–8 строк"));
        assert!(
            broad_stale.contains("прочитайте файл через read_file и перезапишите через write_file")
        );

        let broad_fresh = apply_edit_text_with_context(&file, &broad_old, "x", false, MAX, || true)
            .unwrap_err()
            .to_string();
        assert!(broad_fresh.contains("снимок файла в текущем ходе уже актуален"));
        assert!(broad_fresh.contains("сразу вызовите write_file без expected_sha256"));

        // 7) Accidental `N\t` prefixes from `read_file` vs non-sequential TSV data.
        let numbered_old = "10\tdef func_10():\n11\n12\tdef func_12():";
        let err_num = apply_edit_text(&file, numbered_old, "pass", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            err_num.contains("префиксы номеров строк N\\t из read_file"),
            "{err_num}"
        );

        let tsv_old = "1\tapple\n1\tbanana";
        let err_tsv = apply_edit_text(&file, tsv_old, "pass", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            !err_tsv.contains("префиксы номеров строк N\\t из read_file"),
            "{err_tsv}"
        );
        let leading_zero_old = "01\talpha\n02\tbeta";
        let err_zero = apply_edit_text(&file, leading_zero_old, "pass", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            !err_zero.contains("префиксы номеров строк N\\t из read_file"),
            "{err_zero}"
        );
        let broad_numbered = (1..=12)
            .map(|i| format!("{i}\tmissing_{i} = {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let err_broad_num =
            apply_edit_text_with_context(&file, &broad_numbered, "pass", false, MAX, || false)
                .unwrap_err()
                .to_string();
        assert!(err_broad_num.contains("3–8 строк"), "{err_broad_num}");
        assert!(
            err_broad_num
                .contains("прочитайте файл через read_file и перезапишите через write_file"),
            "{err_broad_num}"
        );

        // 8) Ambiguous match reports exact 1-based line numbers and `и др.` when > 3 matches.
        let dup_file = "header\nreturn 404\nmid\nreturn 404\nfooter\n";
        let err_dup = apply_edit_text(dup_file, "return 404", "return 400", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(err_dup.starts_with("old_text неоднозначен"));
        assert!(err_dup.contains("совпадения на строках 2, 4"), "{err_dup}");
        assert!(err_dup.contains("replace_all=true"));

        let many_dup = "x = 1\ny\nx = 1\ny\nx = 1\ny\nx = 1\n";
        let err_many = apply_edit_text(many_dup, "x = 1", "x = 2", false, MAX)
            .unwrap_err()
            .to_string();
        assert!(
            err_many.contains("совпадения на строках 1, 3, 5 и др."),
            "{err_many}"
        );
    }
}
