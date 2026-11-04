//! Incremental, in-place remasking of retained, originally valid UTF-8 text.
//!
//! This is a host-side primitive, not an output gate or a refresh coordinator.
//! The caller MUST withhold the entire retained payload until `step` returns
//! `Ok(true)`. Cancellation, dropping the cursor, or any error leaves the payload
//! quarantined; partially remasked text must not become observable.
//!
//! Between steps the caller may release its registry mutex. It must keep the
//! same payload, dictionary epoch, provenance, original length and original
//! contents immutable except for this cursor's masks. Length changes are checked;
//! same-length edits, payload substitution and epoch changes cannot be detected
//! by this interface. Restarting against partially masked text is not a substitute
//! for completing the original pass.
//!
//! The matcher keeps only a trie state and a bounded ring of original bytes and
//! coverage endpoints. At each ending position only the longest terminal suffix
//! is needed: every shorter suffix match is contained in that match. Delayed
//! scalar-sized writes therefore compute the union of *all* overlapping matches
//! without enumerating matches or rescanning already modified text.

use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;

pub const MAX_ENCODED_PATTERN_BYTES: usize = 49_152;
pub const MAX_DICTIONARY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PATTERNS: usize = 128 * 7;
const MAX_COMPILE_BYTES: usize = 8 * 1024 * 1024;
const NONE: usize = usize::MAX;
/// An additional hard cap even if a caller supplies an enormous budget.
pub const MAX_STEP_WORK: usize = 4096;

/// Static diagnostics deliberately contain no input bytes or host error strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemaskError {
    InvalidDictionary,
    InvalidProvenance,
    LengthChanged,
    MissingByte,
    InvalidUtf8,
    InvalidMaskBounds,
    MaskFailed,
    CursorFailed,
}

impl fmt::Display for RemaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDictionary => "invalid retained-redaction dictionary",
            Self::InvalidProvenance => "invalid retained-redaction provenance",
            Self::LengthChanged => "retained text length changed",
            Self::MissingByte => "retained text byte unavailable",
            Self::InvalidUtf8 => "retained text is not valid UTF-8",
            Self::InvalidMaskBounds => "invalid retained mask bounds",
            Self::MaskFailed => "retained mask failed",
            Self::CursorFailed => "retained remask cursor previously failed",
        })
    }
}

impl std::error::Error for RemaskError {}

pub type Result<T> = std::result::Result<T, RemaskError>;

/// Host adapter over disjoint retained blocks. No contiguous payload is needed.
///
/// `byte` must address the concatenation of the blocks, including across block
/// boundaries. `mask` must replace EVERY byte in the range with ASCII `*`, with
/// no insertion, deletion or edits outside the range. It must reject invalid
/// bounds; it must not stringify host errors containing payload data.
///
/// The cursor calls `mask` only with nonempty, scalar-aligned ranges of at most
/// four original bytes. Hosts must provide bounded indexed access (for example
/// an indexed block/page table), not a linear walk of all blocks per access.
/// Host methods must not perform unbounded blocking work under the registry lock.
pub trait RetainedText {
    fn len(&self) -> usize;
    fn byte(&self, index: usize) -> Option<u8>;
    fn mask(&mut self, range: Range<usize>) -> Result<()>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct Node {
    edge: usize,
    failure: usize,
    // Longest terminal at this node or anywhere on its failure chain.
    terminal: usize,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            edge: NONE,
            failure: 0,
            terminal: 0,
        }
    }
}
struct Edge {
    byte: u8,
    target: usize,
    next: usize,
}

struct Dictionary {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    longest: usize,
}
impl Dictionary {
    // Each sibling list has at most the 256-byte alphabet. No allocator nodes,
    // per-state maps or transition table proportional to the entire alphabet.
    fn transition(&self, state: usize, byte: u8) -> Option<usize> {
        let mut at = self.nodes[state].edge;
        while at != NONE {
            let edge = &self.edges[at];
            if edge.byte == byte {
                return Some(edge.target);
            }
            at = edge.next;
        }
        None
    }
    fn new(patterns: Vec<Vec<u8>>) -> Result<Self> {
        if patterns.len() > MAX_PATTERNS {
            return Err(RemaskError::InvalidDictionary);
        }
        let mut total = 0usize;
        let mut longest = 0usize;
        for pattern in &patterns {
            if pattern.is_empty()
                || pattern.len() > MAX_ENCODED_PATTERN_BYTES
                || std::str::from_utf8(pattern).is_err()
            {
                return Err(RemaskError::InvalidDictionary);
            }
            total = total
                .checked_add(pattern.len())
                .filter(|&n| n <= MAX_DICTIONARY_BYTES)
                .ok_or(RemaskError::InvalidDictionary)?;
            longest = longest.max(pattern.len());
        }
        // Preflight the peak requested capacities, including the compilation
        // queue, incoming pattern descriptors/data and the cursor ring. Keep
        // allocator bookkeeping outside this byte accounting; allocation count
        // is bounded by MAX_PATTERNS plus these four contiguous tables.
        let capacity = total + 1;
        let peak = capacity * (std::mem::size_of::<Node>() + std::mem::size_of::<usize>())
            + total * std::mem::size_of::<Edge>()
            + total
            + patterns.len() * std::mem::size_of::<Vec<u8>>()
            + (longest.max(1) + 8) * std::mem::size_of::<Slot>();
        if peak > MAX_COMPILE_BYTES {
            return Err(RemaskError::InvalidDictionary);
        }
        let mut dictionary = Self {
            nodes: Vec::with_capacity(capacity),
            edges: Vec::with_capacity(total),
            longest,
        };
        dictionary.nodes.push(Node::default());
        for pattern in patterns {
            let mut state = 0;
            for byte in &pattern {
                state = if let Some(next) = dictionary.transition(state, *byte) {
                    next
                } else {
                    let next = dictionary.nodes.len();
                    dictionary.nodes.push(Node::default());
                    let edge = dictionary.edges.len();
                    dictionary.edges.push(Edge {
                        byte: *byte,
                        target: next,
                        next: dictionary.nodes[state].edge,
                    });
                    dictionary.nodes[state].edge = edge;
                    next
                };
            }
            dictionary.nodes[state].terminal = pattern.len();
        }
        let mut queue = VecDeque::with_capacity(capacity);
        let mut edge = dictionary.nodes[0].edge;
        while edge != NONE {
            queue.push_back(dictionary.edges[edge].target);
            edge = dictionary.edges[edge].next;
        }
        while let Some(parent) = queue.pop_front() {
            let mut edge = dictionary.nodes[parent].edge;
            while edge != NONE {
                let byte = dictionary.edges[edge].byte;
                let child = dictionary.edges[edge].target;
                let mut failure = dictionary.nodes[parent].failure;
                let target = loop {
                    if let Some(next) = dictionary.transition(failure, byte) {
                        break next;
                    }
                    if failure == 0 {
                        break 0;
                    }
                    failure = dictionary.nodes[failure].failure;
                };
                dictionary.nodes[child].failure = target;
                dictionary.nodes[child].terminal = dictionary.nodes[child]
                    .terminal
                    .max(dictionary.nodes[target].terminal);
                queue.push_back(child);
                edge = dictionary.edges[edge].next;
            }
        }
        Ok(dictionary)
    }
}

#[derive(Clone, Copy, Default)]
struct Slot {
    original: u8,
    // Maximum end of any coverage interval starting at this absolute position.
    end: usize,
}

/// Compiled once per host credential candidate and shared across retained streams.
/// Creating cursors does not copy or recompile the pattern trie.
#[derive(Clone)]
pub struct RetainedDictionary {
    dictionary: Arc<Dictionary>,
}
impl RetainedDictionary {
    pub fn new(credentials: &crate::redaction::SecretDictionary) -> Result<Self> {
        Ok(Self {
            dictionary: Arc::new(Dictionary::new(credentials.patterns().to_vec())?),
        })
    }
    pub fn cursor<'a>(
        &self,
        length: usize,
        provenance: &'a [Range<usize>],
    ) -> Result<RemaskCursor<'a>> {
        RemaskCursor::from_dictionary(length, Arc::clone(&self.dictionary), provenance)
    }
}

/// A single immutable-epoch retained-text pass.
///
/// Construction validates provenance and allocates scratch; do that outside
/// the registry critical section. Construction is not covered by `step`'s budget.
/// Provenance is borrowed, never copied into per-text metadata. Spans must be
/// nonempty, sorted, nonoverlapping and within `original_len`; their endpoints
/// may be inside scalars. Both replacement and lossy-decoding spans belong here.
///
/// Resident memory is O(dictionary bytes + maximum pattern length), plus a
/// bounded breadth-first queue during compilation. There is no per-text-size
/// graph, output buffer, or match list. Trie nodes/edges use flat, preallocated
/// arrays. The compilation preflight budgets 8 MiB for the shared tables, input
/// descriptors and one cursor ring. Every additional live cursor owns another
/// ring reported by `scratch_bytes`; the coordinator bounds their concurrency.
pub struct RemaskCursor<'a> {
    dictionary: Arc<Dictionary>,
    provenance: &'a [Range<usize>],
    provenance_index: usize,
    length: usize,
    ring: Vec<Slot>,
    loaded: usize,
    scanned: usize,
    released: usize,
    state: usize,
    covered_until: usize,
    failed: bool,
    #[cfg(test)]
    last_work: usize,
    #[cfg(test)]
    peak_live: usize,
}

impl fmt::Debug for RemaskCursor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemaskCursor")
            .field("original_length", &self.length)
            .field("scanned_bytes", &self.scanned)
            .field("released_bytes", &self.released)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<'a> RemaskCursor<'a> {
    #[cfg(test)]
    fn new(
        original_len: usize,
        patterns: Vec<Vec<u8>>,
        provenance: &'a [Range<usize>],
    ) -> Result<Self> {
        Self::from_dictionary(
            original_len,
            Arc::new(Dictionary::new(patterns)?),
            provenance,
        )
    }
    fn from_dictionary(
        original_len: usize,
        dictionary: Arc<Dictionary>,
        provenance: &'a [Range<usize>],
    ) -> Result<Self> {
        let mut previous_end = 0;
        for span in provenance {
            if span.start >= span.end || span.end > original_len || span.start < previous_end {
                return Err(RemaskError::InvalidProvenance);
            }
            previous_end = span.end;
        }
        let capacity = dictionary.longest.max(1) + 8;
        Ok(Self {
            dictionary,
            provenance,
            provenance_index: 0,
            length: original_len,
            ring: vec![Slot::default(); capacity],
            loaded: 0,
            scanned: 0,
            released: 0,
            state: 0,
            covered_until: 0,
            failed: false,
            #[cfg(test)]
            last_work: 0,
            #[cfg(test)]
            peak_live: 0,
        })
    }

    /// Bytes occupied by the original-byte/coverage ring, excluding dictionary
    /// allocations, the cursor itself and caller-owned borrowed provenance.
    pub fn scratch_bytes(&self) -> usize {
        self.ring.len() * std::mem::size_of::<Slot>()
    }

    fn padded_span(&self) -> Option<Range<usize>> {
        let span = self.provenance.get(self.provenance_index)?;
        let radius = self.dictionary.longest.saturating_sub(1);
        Some(span.start.saturating_sub(radius)..span.end.saturating_add(radius).min(self.length))
    }

    /// Advance by bounded WORK, not merely bounded input reads.
    ///
    /// Each budget unit performs one of: one failure-link hop; one byte
    /// transition and constant-size coverage update; one original scalar read
    /// (at most four byte calls); one scalar release/mask (at most four bytes);
    /// or one provenance-span advancement. Sparse edge lookups are bounded by the
    /// 256-byte alphabet. In particular, output/failure chains and dense overlap
    /// sets cannot hide unbounded work in one unit. Work is capped at
    /// `min(byte_budget, MAX_STEP_WORK)` units per invocation.
    ///
    /// `Ok(true)` means the entire pass completed, not that a prefix may be
    /// published. Zero budget makes no progress. Errors poison the cursor;
    /// callers must keep the payload gated on errors and cancellation.
    pub fn step(&mut self, text: &mut impl RetainedText, byte_budget: usize) -> Result<bool> {
        if self.failed {
            return Err(RemaskError::CursorFailed);
        }
        #[cfg(test)]
        {
            self.last_work = 0;
        }
        if text.len() != self.length {
            self.failed = true;
            return Err(RemaskError::LengthChanged);
        }
        for _ in 0..byte_budget.min(MAX_STEP_WORK) {
            if self.released == self.length {
                return Ok(true);
            }
            #[cfg(test)]
            {
                self.last_work += 1;
            }
            if let Err(error) = self.work(text) {
                self.failed = true;
                return Err(error);
            }
        }
        Ok(self.released == self.length)
    }

    fn work(&mut self, text: &mut impl RetainedText) -> Result<()> {
        // The extra four bytes make the entire oldest scalar safe. All matches
        // touching it have been scanned before any of its original bytes change.
        let delay = self.dictionary.longest + 4;
        if self.scanned == self.length || self.scanned - self.released >= delay {
            return self.release_scalar(text);
        }
        if self.scanned < self.loaded {
            let byte = self.ring[self.scanned % self.ring.len()].original;
            if let Some(next) = self.dictionary.transition(self.state, byte) {
                self.state = next;
            } else if self.state != 0 {
                // A failure hop consumes its own work unit, without rereading
                // the host or consuming the byte. No unbounded inner loop.
                self.state = self.dictionary.nodes[self.state].failure;
                return Ok(());
            }
            self.scanned += 1;
            let matched = self.dictionary.nodes[self.state].terminal;
            if matched != 0 {
                let start = self.scanned - matched;
                debug_assert!(start >= self.released);
                self.cover(start, self.scanned);
            }
            return Ok(());
        }
        let padded = self.padded_span();
        if padded.as_ref().is_some_and(|span| span.end <= self.loaded) {
            self.provenance_index += 1;
            return Ok(());
        }
        let start = self.loaded;
        let mut scalar = [0u8; 4];
        scalar[0] = text.byte(start).ok_or(RemaskError::MissingByte)?;
        let width = scalar_width(scalar[0]).ok_or(RemaskError::InvalidUtf8)?;
        if width > self.length - start {
            return Err(RemaskError::InvalidUtf8);
        }
        for (offset, byte) in scalar.iter_mut().enumerate().take(width).skip(1) {
            *byte = text.byte(start + offset).ok_or(RemaskError::MissingByte)?;
        }
        std::str::from_utf8(&scalar[..width]).map_err(|_| RemaskError::InvalidUtf8)?;
        let end = start + width;
        debug_assert!(end - self.released <= self.ring.len());
        for (offset, &byte) in scalar.iter().take(width).enumerate() {
            let slot = (start + offset) % self.ring.len();
            self.ring[slot] = Slot {
                original: byte,
                end: 0,
            };
        }
        self.loaded = end;
        // Intersecting whole original scalars expands padded provenance bounds
        // outward exactly to UTF-8 boundaries, including bounds inside scalars.
        if padded.is_some_and(|span| span.start < end && span.end > start) {
            self.cover(start, end);
        }
        #[cfg(test)]
        {
            self.peak_live = self.peak_live.max(self.loaded - self.released);
        }
        Ok(())
    }

    fn cover(&mut self, start: usize, end: usize) {
        let index = start % self.ring.len();
        self.ring[index].end = self.ring[index].end.max(end);
    }

    fn release_scalar(&mut self, text: &mut impl RetainedText) -> Result<()> {
        let start = self.released;
        let width = scalar_width(self.ring[start % self.ring.len()].original)
            .ok_or(RemaskError::InvalidUtf8)?;
        let end = start + width;
        debug_assert!(end <= self.scanned);
        for position in start..end {
            self.covered_until = self
                .covered_until
                .max(self.ring[position % self.ring.len()].end);
        }
        if self.covered_until > start {
            text.mask(start..end)?;
            if text.len() != self.length {
                return Err(RemaskError::LengthChanged);
            }
        }
        self.released = end;
        Ok(())
    }
}

fn scalar_width(lead: u8) -> Option<usize> {
    match lead {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Individual blocks may split a UTF-8 scalar. Empty blocks are permitted.
    struct Blocks {
        blocks: Vec<Vec<u8>>,
        offsets: Vec<usize>,
        length: usize,
        missing: Option<usize>,
        reject_masks: bool,
    }

    impl Blocks {
        fn split(bytes: &[u8], cut: usize) -> Self {
            Self {
                blocks: vec![bytes[..cut].to_vec(), Vec::new(), bytes[cut..].to_vec()],
                offsets: vec![0, cut, cut],
                length: bytes.len(),
                missing: None,
                reject_masks: false,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.blocks.concat()
        }

        fn location(&self, index: usize) -> Option<(usize, usize)> {
            if index >= self.length {
                return None;
            }
            let block = self.offsets.partition_point(|&offset| offset <= index) - 1;
            Some((block, index - self.offsets[block]))
        }
    }

    impl RetainedText for Blocks {
        fn len(&self) -> usize {
            self.length
        }

        fn byte(&self, index: usize) -> Option<u8> {
            if self.missing == Some(index) {
                return None;
            }
            let (block, offset) = self.location(index)?;
            self.blocks[block].get(offset).copied()
        }

        fn mask(&mut self, range: Range<usize>) -> Result<()> {
            if range.start >= range.end || range.end > self.length {
                return Err(RemaskError::InvalidMaskBounds);
            }
            if self.reject_masks {
                return Err(RemaskError::MaskFailed);
            }
            assert!(range.len() <= 4);
            // Cursor calls must start/end at boundaries in the current text too.
            let before = self.bytes();
            let valid = std::str::from_utf8(&before).unwrap();
            assert!(valid.is_char_boundary(range.start));
            assert!(valid.is_char_boundary(range.end));
            for index in range {
                let (block, offset) = self.location(index).unwrap();
                self.blocks[block][offset] = b'*';
            }
            Ok(())
        }
    }

    fn patterns(values: &[&str]) -> Vec<Vec<u8>> {
        values.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    fn finish(cursor: &mut RemaskCursor<'_>, text: &mut Blocks, budget: usize) {
        // A finite test guard catches stalled failure/provenance state machines.
        for _ in 0..1_000_000 {
            let done = cursor.step(text, budget).unwrap();
            assert!(cursor.last_work <= budget.min(MAX_STEP_WORK));
            assert!(cursor.peak_live <= cursor.ring.len());
            assert_eq!(text.len(), cursor.length);
            if done {
                return;
            }
        }
        panic!("cursor did not finish");
    }

    #[test]
    fn all_block_splits_and_tiny_budgets_preserve_overlap_union() {
        for input in ["abcd", "!abcd!abcdbcd", "aaaaaaaab!"] {
            let keys = ["abc", "bcd", "aa", "aaaab"];
            let mut expected = input.as_bytes().to_vec();
            for key in keys {
                for start in 0..input.len() {
                    if input.as_bytes()[start..].starts_with(key.as_bytes()) {
                        expected[start..start + key.len()].fill(b'*');
                    }
                }
            }
            for cut in 0..=input.len() {
                for budget in 1..=5 {
                    let mut text = Blocks::split(input.as_bytes(), cut);
                    let mut cursor = RemaskCursor::new(text.len(), patterns(&keys), &[]).unwrap();
                    assert!(!cursor.step(&mut text, 0).unwrap());
                    finish(&mut cursor, &mut text, budget);
                    assert_eq!(text.bytes(), expected);
                    assert!(cursor.step(&mut text, 1).unwrap());
                }
            }
        }
    }

    #[test]
    fn multibyte_matches_and_final_tiny_chunk_keep_offsets() {
        let input = "aé猫🦀猫z";
        let expected = format!("a{}z", "*".repeat(input.len() - 2));
        for cut in 0..=input.len() {
            let mut text = Blocks::split(input.as_bytes(), cut);
            let mut cursor =
                RemaskCursor::new(text.len(), patterns(&["é猫", "猫🦀", "🦀猫"]), &[]).unwrap();
            finish(&mut cursor, &mut text, 1);
            assert_eq!(text.bytes(), expected.as_bytes());
            assert_eq!(text.len(), input.len());
            assert!(std::str::from_utf8(&text.bytes()).is_ok());
        }
    }

    #[test]
    fn provenance_neighborhoods_cross_old_replacements_and_lossy_scalars() {
        let input = "okab[REDACTED]cdé�猫!";
        let replacement_start = input.find('[').unwrap();
        let replacement_end = input.find(']').unwrap() + 1;
        let lossy = input.find('�').unwrap();
        let spans = [replacement_start..replacement_end, lossy..lossy + 3];
        for cut in 0..=input.len() {
            let mut text = Blocks::split(input.as_bytes(), cut);
            // Radius two; the lossy neighborhood starts inside é and ends inside 猫.
            let mut cursor = RemaskCursor::new(text.len(), patterns(&["xyz"]), &spans).unwrap();
            finish(&mut cursor, &mut text, 1);
            let expected = format!("ok{}!", "*".repeat(input.len() - 3));
            assert_eq!(text.bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn empty_dictionary_still_masks_scalar_expanded_provenance() {
        let spans = [Range { start: 2, end: 3 }]; // Interior of the three-byte scalar.
        let mut text = Blocks::split("a猫z".as_bytes(), 2);
        let mut cursor = RemaskCursor::new(text.len(), vec![], &spans).unwrap();
        finish(&mut cursor, &mut text, 1);
        assert_eq!(text.bytes(), b"a***z");
        let mut empty = Blocks::split(b"", 0);
        let mut cursor = RemaskCursor::new(0, vec![], &[]).unwrap();
        assert!(cursor.step(&mut empty, 0).unwrap());
    }

    #[test]
    fn validation_missing_bytes_and_failures_are_sticky() {
        for keys in [
            vec![vec![]],
            vec![vec![0xff]],
            vec![vec![b'a'; MAX_ENCODED_PATTERN_BYTES + 1]],
        ] {
            assert!(matches!(
                RemaskCursor::new(5, keys, &[]),
                Err(RemaskError::InvalidDictionary)
            ));
        }
        let oversized = vec![
            vec![b'a'; MAX_ENCODED_PATTERN_BYTES];
            MAX_DICTIONARY_BYTES / MAX_ENCODED_PATTERN_BYTES + 1
        ];
        assert!(RemaskCursor::new(5, oversized, &[]).is_err());
        for spans in [
            vec![Range { start: 3, end: 2 }],
            vec![Range { start: 0, end: 6 }],
            vec![0..3, 2..4],
            vec![Range { start: 2, end: 2 }],
        ] {
            assert!(matches!(
                RemaskCursor::new(5, vec![], &spans),
                Err(RemaskError::InvalidProvenance)
            ));
        }
        let mut text = Blocks::split(b"abcd", 2);
        assert_eq!(text.mask(3..5), Err(RemaskError::InvalidMaskBounds));
        text.missing = Some(2);
        let mut cursor = RemaskCursor::new(4, patterns(&["abc"]), &[]).unwrap();
        assert_eq!(cursor.step(&mut text, 100), Err(RemaskError::MissingByte));
        assert_eq!(cursor.step(&mut text, 100), Err(RemaskError::CursorFailed));

        let mut text = Blocks::split(b"abc", 1);
        let mut cursor = RemaskCursor::new(4, vec![], &[]).unwrap();
        assert_eq!(cursor.step(&mut text, 1), Err(RemaskError::LengthChanged));
        let mut text = Blocks::split(b"\xc0\x80", 1);
        let mut cursor = RemaskCursor::new(2, vec![], &[]).unwrap();
        assert_eq!(cursor.step(&mut text, 10), Err(RemaskError::InvalidUtf8));
        let mut text = Blocks::split(b"abc", 1);
        text.reject_masks = true;
        let mut cursor = RemaskCursor::new(3, patterns(&["abc"]), &[]).unwrap();
        assert_eq!(cursor.step(&mut text, 100), Err(RemaskError::MaskFailed));
    }

    #[test]
    fn maximum_scratch_is_independent_of_text_length_and_work_is_capped() {
        let key = vec![b'q'; MAX_ENCODED_PATTERN_BYTES];
        let input = vec![b'q'; MAX_ENCODED_PATTERN_BYTES * 2 + 1];
        let mut text = Blocks::split(&input, MAX_ENCODED_PATTERN_BYTES - 1);
        let mut cursor = RemaskCursor::new(input.len(), vec![key], &[]).unwrap();
        let bound = (MAX_ENCODED_PATTERN_BYTES + 8) * std::mem::size_of::<Slot>();
        assert_eq!(cursor.scratch_bytes(), bound);
        assert!(!cursor.step(&mut text, usize::MAX).unwrap());
        assert_eq!(cursor.last_work, MAX_STEP_WORK);
        finish(&mut cursor, &mut text, MAX_STEP_WORK);
        assert_eq!(cursor.scratch_bytes(), bound);
        assert!(text.bytes().iter().all(|&byte| byte == b'*'));
    }

    #[test]
    fn dense_suffixes_and_many_provenance_spans_have_explicit_progress() {
        let keys: Vec<Vec<u8>> = (1..=100).map(|n| vec![b'a'; n]).collect();
        let input = vec![b'a'; 500];
        let spans: Vec<Range<usize>> = (0..500).map(|n| n..n + 1).collect();
        let mut text = Blocks::split(&input, 251);
        let mut cursor = RemaskCursor::new(input.len(), keys, &spans).unwrap();
        finish(&mut cursor, &mut text, 1);
        assert!(text.bytes().iter().all(|&b| b == b'*'));
    }

    #[test]
    fn debug_and_errors_do_not_include_pattern_values() {
        let marker = "private-fixture-value";
        let cursor = RemaskCursor::new(100, patterns(&[marker]), &[]).unwrap();
        assert!(!format!("{cursor:?}").contains(marker));
        assert!(!RemaskError::InvalidDictionary.to_string().contains(marker));
    }

    #[test]
    fn memory_preflight_rejects_large_tries_before_compilation() {
        // Under the encoded-byte cap, but far beyond the concrete table budget.
        let patterns = vec![vec![b'x'; 49_000]; 4];
        assert!(matches!(
            Dictionary::new(patterns),
            Err(RemaskError::InvalidDictionary)
        ));
        assert!(matches!(
            Dictionary::new(vec![vec![b'x']; MAX_PATTERNS + 1]),
            Err(RemaskError::InvalidDictionary)
        ));
    }

    #[test]
    fn randomized_utf8_and_provenance_match_independent_union_oracle() {
        let mut seed = 0x752ac41d_u64;
        let mut random = |max: usize| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 32) as usize % max
        };
        let alphabet = ['a', 'b', '猫', 'é', '🦀', '*'];
        for _ in 0..3000 {
            let input: String = (0..1 + random(24))
                .map(|_| alphabet[random(alphabet.len())])
                .collect();
            let boundaries: Vec<_> = input
                .char_indices()
                .map(|(i, _)| i)
                .chain([input.len()])
                .collect();
            let mut keys = Vec::new();
            for _ in 0..1 + random(7) {
                let start = random(boundaries.len() - 1);
                let end = start + 1 + random(boundaries.len() - start - 1);
                keys.push(input.as_bytes()[boundaries[start]..boundaries[end]].to_vec());
            }
            let mut spans: Vec<Range<usize>> = Vec::new();
            let mut at = random(3).min(input.len());
            while at < input.len() {
                let end = (at + 1 + random(3)).min(input.len());
                spans.push(at..end);
                at = end + random(6);
            }
            let mut covered = vec![false; input.len()];
            for key in &keys {
                for start in 0..=input.len() - key.len() {
                    if input.as_bytes()[start..].starts_with(key) {
                        covered[start..start + key.len()].fill(true);
                    }
                }
            }
            let radius = keys.iter().map(Vec::len).max().unwrap() - 1;
            for span in &spans {
                let range = span.start.saturating_sub(radius)..(span.end + radius).min(input.len());
                covered[range].fill(true);
            }
            let mut expected = input.as_bytes().to_vec();
            for pair in boundaries.windows(2) {
                if covered[pair[0]..pair[1]].iter().any(|&v| v) {
                    expected[pair[0]..pair[1]].fill(b'*');
                }
            }
            let mut text = Blocks::split(input.as_bytes(), random(input.len() + 1));
            let mut cursor = RemaskCursor::new(input.len(), keys, &spans).unwrap();
            finish(&mut cursor, &mut text, 1 + random(13));
            assert_eq!(text.bytes(), expected);
        }
    }

    #[test]
    fn repeated_failure_links_consume_separate_work_units() {
        let mut key = vec![b'a'; 2048];
        key.push(b'b');
        let mut input = vec![b'a'; 2048];
        input.push(b'c');
        let mut text = Blocks::split(&input, 1024);
        let mut cursor = RemaskCursor::new(input.len(), vec![key], &[]).unwrap();
        let mut stalled = 0;
        while !cursor.step(&mut text, 1).unwrap() {
            if cursor.loaded == input.len() && cursor.scanned == input.len() - 1 {
                stalled += 1;
            }
            assert!(cursor.last_work <= 1);
        }
        assert!(stalled >= 2048);
        assert_eq!(text.bytes(), input);
    }
}
