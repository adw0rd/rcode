//! Redaction of known host secrets before bytes reach an output sink.
//!
//! Each stdout/stderr connection owns its own instance. Returned byte chunks
//! need an incremental UTF-8 decoder if they are displayed as text. Normal EOF
//! flushes only after matching known secrets; abort never releases the pending
//! raw lookbehind. This is not a detector for unknown project credentials.
use aho_corasick::automaton::{Automaton, StateID};
use aho_corasick::nfa::contiguous::NFA;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, Anchored, MatchKind};
use anyhow::{Context, Result, ensure};
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, VecDeque};
use std::fmt;

const MAX_SECRETS: usize = 128;
const MAX_SECRET_BYTES: usize = 8192;
const MAX_PATTERN_BYTES: usize = 4 * 1024 * 1024;
// Bound the simultaneous dictionary metadata allocations independently of
// encoded input bytes. A dictionary may meet the input cap and still require
// far too many trie records to compile safely for each output connection.
const MAX_PREFIX_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MASK: &[u8] = b"[REDACTED]";
const PENDING_MASK: &[u8] = b"[REDACTED_PENDING]";

// A Standard NFA state represents the longest trie-prefix suffix of the input.
// State IDs are opaque, sparse offsets, not array indices. Every reachable
// non-start state is visited while walking the dictionary's full prefixes.
struct PrefixNode {
    id: StateID,
    depth: usize,
    failure: usize,
    proper: bool,
    terminal: bool,
    proper_suffix: usize,
    terminal_suffix: Option<usize>,
}

struct PrefixTracker {
    nfa: NFA,
    // Sorted by opaque state ID; only actual trie states occupy this table.
    nodes: Vec<PrefixNode>,
    state: usize,
    #[cfg(test)]
    work: usize,
}

type PrefixRecord = (StateID, usize, StateID, bool, bool);

impl PrefixTracker {
    fn new(patterns: &BTreeSet<Vec<u8>>) -> Result<Self> {
        let capacity = patterns.iter().try_fold(1usize, |count, pattern| {
            count
                .checked_add(pattern.len())
                .context("Переполнение redaction prefix tables")
        })?;
        let entry_bytes = size_of::<PrefixRecord>() + size_of::<PrefixNode>() + size_of::<usize>();
        ensure!(
            capacity
                .checked_mul(entry_bytes)
                .is_some_and(|bytes| bytes <= MAX_PREFIX_TABLE_BYTES),
            "Превышен бюджет памяти таблиц redaction"
        );
        // NFA::new uses Standard semantics. Unlike a leftmost automaton, it
        // preserves suffix transitions after terminal states.
        let nfa = NFA::new(patterns).context("Не удалось построить redaction prefix matcher")?;
        let start = nfa
            .start_state(Anchored::No)
            .context("Не удалось начать redaction prefix matcher")?;
        let mut records = Vec::<PrefixRecord>::with_capacity(capacity);
        records.push((start, 0usize, start, true, false));
        for pattern in patterns {
            let mut state = start;
            let mut suffix = start;
            for (index, &byte) in pattern.iter().enumerate() {
                state = nfa.next_state(Anchored::No, state, byte);
                // Walking p[1..] alongside p gives p's failure state, without
                // inspecting private NFA storage or enumerating all suffixes.
                if index != 0 {
                    suffix = nfa.next_state(Anchored::No, suffix, byte);
                }
                records.push((
                    state,
                    index + 1,
                    suffix,
                    index + 1 < pattern.len(),
                    index + 1 == pattern.len(),
                ));
            }
        }
        records.sort_unstable_by_key(|record| record.0);
        records.dedup_by(|later, earlier| {
            if later.0 != earlier.0 {
                return false;
            }
            debug_assert_eq!(later.1, earlier.1);
            debug_assert_eq!(later.2, earlier.2);
            earlier.3 |= later.3;
            earlier.4 |= later.4;
            true
        });
        let root = records
            .binary_search_by_key(&start, |record| record.0)
            .unwrap();
        let mut nodes = Vec::with_capacity(records.len());
        for &(id, depth, failure_id, proper, terminal) in &records {
            let failure = records
                .binary_search_by_key(&failure_id, |record| record.0)
                .expect("a failure state is a dictionary prefix");
            nodes.push(PrefixNode {
                id,
                depth,
                failure,
                proper,
                terminal,
                proper_suffix: root,
                terminal_suffix: None,
            });
        }
        drop(records);
        let mut order: Vec<usize> = (0..nodes.len()).collect();
        order.sort_unstable_by_key(|&index| nodes[index].depth);
        for index in order {
            let failure = nodes[index].failure;
            nodes[index].proper_suffix = if nodes[index].proper {
                index
            } else {
                nodes[failure].proper_suffix
            };
            nodes[index].terminal_suffix = if nodes[index].terminal {
                Some(index)
            } else if index == root {
                None
            } else {
                nodes[failure].terminal_suffix
            };
        }
        Ok(Self {
            nfa,
            nodes,
            state: root,
            #[cfg(test)]
            work: 0,
        })
    }

    fn advance(&mut self, byte: u8) -> Option<usize> {
        let id = self
            .nfa
            .next_state(Anchored::No, self.nodes[self.state].id, byte);
        let index = self
            .nodes
            .binary_search_by_key(&id, |node| node.id)
            .expect("a reachable NFA state is a dictionary prefix");
        self.state = self.nodes[index].proper_suffix;
        #[cfg(test)]
        {
            self.work += 1;
        }
        self.nodes[index].terminal_suffix
    }

    fn depth(&self) -> usize {
        self.nodes[self.state].depth
    }

    fn clip(&mut self, available: usize) {
        // A mask can consume part of a raw-stream suffix. Follow failure
        // links, rather than replaying the remaining buffer. This prevents
        // matches from crossing an already masked range.
        while self.nodes[self.state].depth > available {
            self.state = self.nodes[self.state].failure;
            #[cfg(test)]
            {
                self.work += 1;
            }
        }
        self.state = self.nodes[self.state].proper_suffix;
    }

    fn terminal_within(&mut self, mut terminal: usize, available: usize) -> Option<usize> {
        // Only terminal links are visited here: at most the number of encoded
        // dictionary forms, regardless of the byte length of a shared prefix.
        loop {
            if self.nodes[terminal].depth <= available {
                return Some(terminal);
            }
            #[cfg(test)]
            {
                self.work += 1;
            }
            terminal = self.nodes[self.nodes[terminal].failure].terminal_suffix?;
        }
    }
}

// One event per matching input position, not one per matching dictionary key.
// Earliest start wins; at equal starts the greatest end wins. The terminal
// index allows a lazily invalidated overlapping event to expose its shorter,
// still-valid terminal suffix after an earlier match is consumed.
type MatchEvent = Reverse<(usize, Reverse<usize>, usize)>;

pub struct StreamingRedactor {
    matcher: Option<AhoCorasick>,
    prefixes: Option<PrefixTracker>,
    longest: usize,
    pending: VecDeque<u8>,
    matches: BinaryHeap<MatchEvent>,
    consumed: usize,
    end: usize,
    closed: bool,
    incomplete: bool,
}

impl fmt::Debug for StreamingRedactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingRedactor")
            .field("longest_pattern", &self.longest)
            .field("pending_bytes", &self.pending.len())
            .field("closed", &self.closed)
            .field("incomplete", &self.incomplete)
            .finish_non_exhaustive()
    }
}

fn percent_encoded(secret: &str, all: bool, lower: bool) -> String {
    let mut encoded = String::new();
    let hex = if lower {
        b"0123456789abcdef"
    } else {
        b"0123456789ABCDEF"
    };
    for byte in secret.bytes() {
        if !all && (byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(hex[(byte >> 4) as usize]));
            encoded.push(char::from(hex[(byte & 15) as usize]));
        }
    }
    encoded
}

impl StreamingRedactor {
    /// Recognized forms: exact UTF-8, serde JSON string escaping, JSON slash
    /// escaping, and canonical/fully percent-encoded forms in upper/lower hex.
    /// Arbitrary encodings and unknown secrets are outside this contract.
    pub fn new(secrets: &[String]) -> Result<Self> {
        ensure!(
            secrets.len() <= MAX_SECRETS,
            "Слишком много секретов для redaction"
        );
        let mut patterns = BTreeSet::<Vec<u8>>::new();
        let mut bytes = 0usize;
        for secret in secrets {
            ensure!(!secret.is_empty(), "Пустой секрет для redaction недопустим");
            ensure!(
                secret.len() <= MAX_SECRET_BYTES,
                "Секрет превышает предел redaction"
            );
            let json = serde_json::to_string(secret).context("Не удалось подготовить redaction")?;
            let escaped = &json[1..json.len() - 1];
            let forms = [
                secret.clone(),
                escaped.to_owned(),
                escaped.replace('/', "\\/"),
                percent_encoded(secret, false, false),
                percent_encoded(secret, false, true),
                percent_encoded(secret, true, false),
                percent_encoded(secret, true, true),
            ];
            for form in forms {
                if patterns.insert(form.as_bytes().to_vec()) {
                    bytes = bytes
                        .checked_add(form.len())
                        .context("Переполнение redaction")?;
                    ensure!(
                        bytes <= MAX_PATTERN_BYTES,
                        "Превышен бюджет redaction patterns"
                    );
                }
            }
        }
        let longest = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let (matcher, prefixes) = if patterns.is_empty() {
            (None, None)
        } else {
            // Preflight the metadata budget before building either automaton.
            let prefixes = PrefixTracker::new(&patterns)?;
            let matcher = AhoCorasickBuilder::new()
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .context("Не удалось построить redaction matcher")?;
            (Some(matcher), Some(prefixes))
        };
        Ok(Self {
            matcher,
            prefixes,
            longest,
            pending: VecDeque::new(),
            matches: BinaryHeap::new(),
            consumed: 0,
            end: 0,
            closed: false,
            incomplete: false,
        })
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        ensure!(!self.closed, "Поток redaction уже закрыт");
        if self.matcher.is_none() {
            return Ok(bytes.to_vec());
        }
        self.end
            .checked_add(bytes.len())
            .context("Переполнение redaction stream")?;
        let mut output = Vec::new();
        for &byte in bytes {
            self.pending.push_back(byte);
            self.end += 1;
            let prefixes = self.prefixes.as_mut().unwrap();
            if let Some(terminal) = prefixes.advance(byte) {
                let start = self.end - prefixes.nodes[terminal].depth;
                self.matches
                    .push(Reverse((start, Reverse(self.end), terminal)));
            }
            self.release(&mut output);
        }
        Ok(output)
    }

    fn discard_to(&mut self, end: usize) {
        let count = end - self.consumed;
        self.pending.drain(..count);
        self.consumed = end;
    }

    fn emit_to(&mut self, end: usize, output: &mut Vec<u8>) {
        let count = end - self.consumed;
        output.extend(self.pending.drain(..count));
        self.consumed = end;
    }

    fn normalize_matches(&mut self) {
        while let Some(&Reverse((start, Reverse(end), terminal))) = self.matches.peek() {
            if start >= self.consumed {
                break;
            }
            self.matches.pop();
            if end <= self.consumed {
                continue;
            }
            let prefixes = self.prefixes.as_mut().unwrap();
            if let Some(terminal) = prefixes.terminal_within(terminal, end - self.consumed) {
                let start = end - prefixes.nodes[terminal].depth;
                self.matches.push(Reverse((start, Reverse(end), terminal)));
            }
        }
    }

    fn release(&mut self, output: &mut Vec<u8>) {
        loop {
            self.normalize_matches();
            let safe = self.end - self.prefixes.as_ref().unwrap().depth();
            let Some(&Reverse((start, Reverse(end), _))) = self.matches.peek() else {
                self.emit_to(safe, output);
                break;
            };
            if start >= safe {
                self.emit_to(safe, output);
                break;
            }
            // No incomplete prefix begins at or before this match. Thus no
            // future input can replace it with an earlier or longer match.
            self.matches.pop();
            self.emit_to(start, output);
            output.extend_from_slice(MASK);
            self.discard_to(end);
            self.prefixes.as_mut().unwrap().clip(self.pending.len());
        }
    }

    /// Flush at confirmed EOF; idempotent. No raw buffer is returned on error.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.closed {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        // At known EOF no proper prefix needs protection. Keep the original
        // LeftmostLongest matcher as the authority for the remaining tail.
        let pending = self.pending.make_contiguous();
        let mut consumed = 0;
        if let Some(matcher) = &self.matcher {
            for matched in matcher.find_iter(&pending[..]) {
                output.extend_from_slice(&pending[consumed..matched.start()]);
                output.extend_from_slice(MASK);
                consumed = matched.end();
            }
        }
        output.extend_from_slice(&pending[consumed..]);
        self.pending.clear();
        self.matches.clear();
        self.consumed = self.end;
        self.closed = true;
        Ok(output)
    }

    /// Cancel/error/quota path: discard every unprocessed byte, even a partial
    /// match. The caller must retain the real operation status separately.
    pub fn abort(&mut self) -> Vec<u8> {
        if self.closed {
            return Vec::new();
        }
        self.closed = true;
        self.incomplete = true;
        self.matches.clear();
        if self.pending.is_empty() {
            return Vec::new();
        }
        self.pending.clear();
        self.consumed = self.end;
        PENDING_MASK.to_vec()
    }

    pub fn redaction_incomplete(&self) -> bool {
        self.incomplete
    }
}

/// Complete text at confirmed EOF. Streaming producers use their own instance.
pub fn redact_text(text: &str, secrets: &[String]) -> Result<String> {
    let mut redactor = StreamingRedactor::new(secrets)?;
    let mut bytes = redactor.push(text.as_bytes())?;
    bytes.extend(redactor.finish()?);
    String::from_utf8(bytes).context("Некорректный UTF-8 после redaction")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(input: &[u8], keys: &[String]) -> Vec<u8> {
        let redactor = StreamingRedactor::new(keys).unwrap();
        let mut output = Vec::new();
        let mut consumed = 0;
        if let Some(matcher) = &redactor.matcher {
            for matched in matcher.find_iter(input) {
                output.extend_from_slice(&input[consumed..matched.start()]);
                output.extend_from_slice(MASK);
                consumed = matched.end();
            }
        }
        output.extend_from_slice(&input[consumed..]);
        output
    }

    #[test]
    fn safe_twenty_bytes_do_not_wait_for_an_8192_byte_key() {
        let mut stream = StreamingRedactor::new(&["z".repeat(8192)]).unwrap();
        let sentence = b"Plain text is ready.";
        assert_eq!(sentence.len(), 20);
        assert_eq!(stream.push(sentence).unwrap(), sentence);
        for &byte in sentence {
            assert_eq!(stream.push(&[byte]).unwrap(), [byte]);
        }
        assert!(stream.finish().unwrap().is_empty());
    }

    #[test]
    fn markdown_codeblock_is_visible_before_eof() {
        let mut stream = StreamingRedactor::new(&["md-fixture-secret-key-42".into()]).unwrap();
        let text = b"```rust\nprintln!(\"userfixture\");\n```\n[documentation](https://example.org/documentation)";
        let cut = text.len() - 20;
        let output = stream.push(&text[..cut]).unwrap();
        assert!(
            output
                .windows(b"println!(\"userfixture\");".len())
                .any(|part| part == b"println!(\"userfixture\");")
        );
        let mut all = output;
        all.extend(stream.push(&text[cut..]).unwrap());
        all.extend(stream.finish().unwrap());
        assert_eq!(all, text);
    }

    #[test]
    fn arbitrary_chunks_preserve_long_shared_prefixes() {
        let prefix = "q".repeat(4096);
        let keys = vec![format!("{prefix}first"), format!("{prefix}second")];
        let input = format!("safe {} then {} done", keys[1], keys[0]);
        let expected = reference(input.as_bytes(), &keys);
        for size in [1, 2, 7, 31, 511, 4096, 8192] {
            let mut stream = StreamingRedactor::new(&keys).unwrap();
            let mut output = Vec::new();
            for chunk in input.as_bytes().chunks(size) {
                output.extend(stream.push(chunk).unwrap());
            }
            output.extend(stream.finish().unwrap());
            assert_eq!(output, expected, "chunk size {size}");
        }
    }

    #[test]
    fn mismatch_releases_a_long_proper_prefix_immediately() {
        let key = format!("{}b", "a".repeat(8191));
        let mut stream = StreamingRedactor::new(&[key]).unwrap();
        assert!(stream.push(&vec![b'a'; 8191]).unwrap().is_empty());
        let mut expected = vec![b'a'; 8191];
        expected.push(b'!');
        assert_eq!(stream.push(b"!").unwrap(), expected);
        assert!(stream.finish().unwrap().is_empty());
    }

    #[test]
    fn one_byte_long_key_work_does_not_rescan_the_pending_tail() {
        let key = format!("{}b", "a".repeat(8191));
        let mut stream = StreamingRedactor::new(&[key]).unwrap();
        let count = 100_000;
        let mut output = Vec::new();
        for _ in 0..count {
            output.extend(stream.push(b"a").unwrap());
            assert!(stream.pending.len() <= 8191);
        }
        assert!(output.len() > 90_000);
        assert_eq!(stream.prefixes.as_ref().unwrap().work, count);
        output.extend(stream.finish().unwrap());
        assert_eq!(output, vec![b'a'; count]);
    }

    #[test]
    fn overlapping_short_matches_do_not_replay_long_pending_prefixes() {
        let keys = vec!["aa".into(), format!("{}b", "a".repeat(8191))];
        let mut stream = StreamingRedactor::new(&keys).unwrap();
        let count = 40_000;
        let mut output = Vec::new();
        for _ in 0..count {
            output.extend(stream.push(b"a").unwrap());
        }
        // Includes explicit failure-link and terminal-link work, but no
        // rescans of thousands of pending bytes for every two-byte mask.
        assert!(stream.prefixes.as_ref().unwrap().work <= count * 4);
        output.extend(stream.finish().unwrap());
        assert_eq!(output, MASK.repeat(count / 2));
    }

    #[test]
    fn prefix_keys_and_overlapping_ranges_agree_with_leftmost_longest() {
        let keys = vec![
            "a".into(),
            "aa".into(),
            "aaaaab".into(),
            "aab".into(),
            "ab".into(),
            "bc".into(),
            "bcd".into(),
            "prefix".into(),
            "prefix-long".into(),
        ];
        for input in [
            b"aaaaaaaabcaab!".as_slice(),
            b"prefix-long prefix! prefix-lon!",
            b"aaaaabaaaaabaaaaaaaab!",
            b"abcdbcdab!",
        ] {
            let expected = reference(input, &keys);
            for cut in 0..=input.len() {
                let mut stream = StreamingRedactor::new(&keys).unwrap();
                let mut output = stream.push(&input[..cut]).unwrap();
                output.extend(stream.push(&input[cut..]).unwrap());
                output.extend(stream.finish().unwrap());
                assert_eq!(output, expected, "input={input:?}, cut={cut}");
            }
        }
    }

    #[test]
    fn exhaustive_small_overlaps_match_the_eof_matcher() {
        for keys in [
            vec!["ab".into(), "bc".into(), "abcab".into()],
            vec!["a".into(), "aaaab".into(), "ba".into()],
            vec!["aba".into(), "ababa".into(), "bab".into()],
        ] {
            for bits in 0..256usize {
                let input: Vec<u8> = (0..8)
                    .map(|index| if bits & (1 << index) == 0 { b'a' } else { b'b' })
                    .collect();
                let expected = reference(&input, &keys);
                let mut stream = StreamingRedactor::new(&keys).unwrap();
                let mut output = Vec::new();
                for byte in &input {
                    output.extend(stream.push(std::slice::from_ref(byte)).unwrap());
                }
                output.extend(stream.finish().unwrap());
                assert_eq!(output, expected, "input={input:?}, keys={keys:?}");
            }
        }
    }

    #[test]
    fn encoded_forms_and_abort_tails_remain_protected() {
        let secret = "fixture/quote\"back\\line\n-key".to_owned();
        let json = serde_json::to_string(&secret).unwrap();
        let escaped = &json[1..json.len() - 1];
        for form in [
            secret.clone(),
            escaped.to_owned(),
            escaped.replace('/', "\\/"),
            percent_encoded(&secret, false, false),
            percent_encoded(&secret, false, true),
            percent_encoded(&secret, true, false),
            percent_encoded(&secret, true, true),
        ] {
            for count in 1..form.len() {
                let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
                assert!(stream.push(&form.as_bytes()[..count]).unwrap().is_empty());
                assert_eq!(stream.abort(), PENDING_MASK);
                assert!(stream.redaction_incomplete());
                assert!(stream.push(b"later").is_err());
                assert!(stream.finish().unwrap().is_empty());
            }
            let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
            let mut output = Vec::new();
            for byte in form.bytes() {
                output.extend(stream.push(&[byte]).unwrap());
            }
            output.extend(stream.push(b"!").unwrap());
            assert_eq!(output, b"[REDACTED]!");
            assert!(stream.finish().unwrap().is_empty());
        }
    }

    #[test]
    fn eof_releases_partial_but_abort_does_not() {
        let keys = vec!["fixture-long-secret".into()];
        let mut complete = StreamingRedactor::new(&keys).unwrap();
        assert!(complete.push(b"fixture-long-").unwrap().is_empty());
        assert_eq!(complete.finish().unwrap(), b"fixture-long-");
        assert!(complete.finish().unwrap().is_empty());
        assert!(complete.abort().is_empty());
        assert!(!complete.redaction_incomplete());
        let mut aborted = StreamingRedactor::new(&keys).unwrap();
        assert!(aborted.push(b"fixture-long-").unwrap().is_empty());
        assert_eq!(aborted.abort(), PENDING_MASK);
        assert!(aborted.redaction_incomplete());
    }

    #[test]
    fn limits_empty_dictionary_debug_and_binary_output() {
        assert!(StreamingRedactor::new(&[String::new()]).is_err());
        assert!(StreamingRedactor::new(&["s".repeat(8193)]).is_err());
        assert!(StreamingRedactor::new(&vec!["key".into(); 129]).is_err());
        let oversized: Vec<String> = (0..128)
            .map(|index| format!("{}{index:03}", "z".repeat(8189)))
            .collect();
        assert!(StreamingRedactor::new(&oversized).is_err());
        let mut empty = StreamingRedactor::new(&[]).unwrap();
        assert_eq!(empty.push(b"normal").unwrap(), b"normal");
        assert!(empty.abort().is_empty());
        assert!(empty.redaction_incomplete());
        let secret = "fixture-debug-secret".to_owned();
        let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
        assert!(!format!("{stream:?}").contains(&secret));
        let mut input = vec![0xff];
        input.extend_from_slice(secret.as_bytes());
        input.push(0xfe);
        let mut output = stream.push(&input).unwrap();
        output.extend(stream.finish().unwrap());
        assert_eq!(output, b"\xff[REDACTED]\xfe");
    }
}
