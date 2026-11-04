//! Per-reader redaction and incremental UTF-8 decoding. No I/O or locking.
//!
//! The coordinator must pause readers, install a union dictionary, remask ALL
//! retained history (including its final M-1 bytes), and publish the new epoch
//! atomically. `prepared` must be a fresh, unused stream from that dictionary;
//! `max_pattern_len` must cover every encoded pattern in it. Preparation belongs
//! outside the registry lock. This primitive neither implements that barrier nor
//! authorizes publication of its returned chunks.
//!
//! Keep this object after reader EOF. Only confirmed successful process outcome
//! authorizes `finish`; cancellation, failure, or quota exhaustion drops it.
//!
//! Boundary protection masks whole redactor output batches while fewer than
//! M-1 original bytes have been consumed after refresh. Matching always sees the
//! ORIGINAL bytes first. Each batch consumes at most 4096 additional input bytes
//! plus withheld matcher lookbehind, bounding conservative extra masking by one
//! input chunk plus the pattern bound. UTF-8 tail masking is carried per scalar,
//! not as a sticky decoder-wide mode. State is bounded by matcher lookbehind,
//! one input chunk, redaction expansion, and constant-size decoding metadata.

use crate::redaction::StreamingRedactor;
use anyhow::{Result, anyhow, ensure};
use std::ops::Range;

pub const MAX_PUSH_BYTES: usize = 4096;
const MASK: &[u8] = b"[REDACTED]";
const PENDING_MASK: &[u8] = b"[REDACTED_PENDING]";

/// Offsets are local UTF-8 byte offsets into `text`, sorted and disjoint.
/// No Debug implementation: diagnostics must not accidentally expose output.
pub struct OutputChunk {
    pub text: String,
    pub lossy: bool,
    pub sensitive: Vec<Range<usize>>,
}

impl OutputChunk {
    fn empty() -> Self {
        Self {
            text: String::new(),
            lossy: false,
            sensitive: Vec::new(),
        }
    }

    fn scalar(&mut self, scalar: char, mask: bool, sensitive: bool, lossy: bool) {
        let start = self.text.len();
        if mask {
            // Preserve the decoded scalar's UTF-8 byte width, not its character
            // count. No partial scalar ever escapes the decoder.
            for _ in 0..scalar.len_utf8() {
                self.text.push('*');
            }
        } else {
            self.text.push(scalar);
        }
        self.lossy |= lossy;
        if sensitive || mask || scalar == '\u{fffd}' {
            let end = self.text.len();
            if let Some(last) = self.sensitive.last_mut()
                && last.end == start
            {
                last.end = end;
                return;
            }
            self.sensitive.push(start..end);
        }
    }
}

#[derive(Clone, Copy)]
struct Byte {
    value: u8,
    mask: bool,
    sensitive: bool,
}

/// Deliberately not Debug, Clone, or serializable.
pub struct OutputStream {
    redactor: StreamingRedactor,
    // A proper, incomplete UTF-8 scalar: at most three bytes between calls.
    tail: Vec<Byte>,
    // A possible prefix of either literal replacement token, at most 17 bytes.
    marker: Vec<u8>,
    // Original input bytes still requiring conservative boundary protection.
    boundary_left: usize,
}

impl OutputStream {
    pub fn new(redactor: StreamingRedactor) -> Self {
        Self {
            redactor,
            tail: Vec::with_capacity(4),
            marker: Vec::with_capacity(PENDING_MASK.len()),
            boundary_left: 0,
        }
    }

    /// Oversized pushes fail before changing state. Split native reads here.
    /// On any other error the coordinator must discard this stream/job output.
    pub fn push(&mut self, raw: &[u8]) -> Result<OutputChunk> {
        ensure!(raw.len() <= MAX_PUSH_BYTES, "output input chunk too large");
        let mut chunk = OutputChunk::empty();
        self.feed(raw, &mut chunk)?;
        Ok(chunk)
    }

    fn feed(&mut self, raw: &[u8], chunk: &mut OutputChunk) -> Result<()> {
        debug_assert!(raw.len() <= MAX_PUSH_BYTES);
        let before = self.redactor.pending_len();
        let mask = self.boundary_left != 0;
        let output = self
            .redactor
            .push(raw)
            .map_err(|_| anyhow!("output redaction failed"))?;
        let consumed = before
            .checked_add(raw.len())
            .and_then(|n| n.checked_sub(self.redactor.pending_len()))
            .ok_or_else(|| anyhow!("invalid output redactor state"))?;
        self.boundary_left = self.boundary_left.saturating_sub(consumed);
        self.decode(&output, mask, chunk);
        Ok(())
    }

    /// Installs a prepared union matcher without finishing the previous one.
    /// The old decoder tail precedes the old ORIGINAL matcher pending bytes.
    pub fn cutover(
        &mut self,
        prepared: StreamingRedactor,
        max_pattern_len: usize,
    ) -> Result<OutputChunk> {
        ensure!(prepared.pending_len() == 0, "output redactor is not fresh");
        let old = std::mem::replace(&mut self.redactor, prepared);
        let pending = old.into_pending_for_cutover();
        let tail = std::mem::take(&mut self.tail);
        // A second refresh must not forget protection from the first one.
        let inherited = if self.boundary_left != 0 {
            self.boundary_left
                .checked_add(tail.len())
                .ok_or_else(|| anyhow!("output boundary overflow"))?
        } else if tail.iter().any(|b| b.mask) {
            tail.len()
        } else {
            0
        };
        self.boundary_left = max_pattern_len.saturating_sub(1).max(inherited);

        let mut chunk = OutputChunk::empty();
        let original_tail: Vec<u8> = tail.iter().map(|b| b.value).collect();
        self.feed(&original_tail, &mut chunk)?;
        for bytes in pending.chunks(MAX_PUSH_BYTES) {
            self.feed(bytes, &mut chunk)?;
        }
        Ok(chunk)
    }

    /// Consume only after the coordinator confirms successful process outcome.
    pub fn finish(mut self) -> Result<OutputChunk> {
        let bytes = self
            .redactor
            .finish()
            .map_err(|_| anyhow!("output redaction failed"))?;
        let mut chunk = OutputChunk::empty();
        self.decode(&bytes, self.boundary_left != 0, &mut chunk);
        if !self.tail.is_empty() {
            let mask = self.tail.iter().any(|b| b.mask);
            let sensitive = self.tail.iter().any(|b| b.sensitive);
            chunk.scalar('\u{fffd}', mask, sensitive, true);
            self.tail.clear();
        }
        Ok(chunk)
    }

    // Tag possible marker prefixes immediately. This deliberately over-tags
    // incomplete literal prefixes (e.g. "[REDx"), allowing exact mask provenance
    // across output boundaries without withholding text or backpatching history.
    // Actual generated replacement tokens and literal U+FFFD are always tagged.
    fn marker_byte(&mut self, byte: u8) -> bool {
        self.marker.push(byte);
        if MASK == self.marker.as_slice() || PENDING_MASK == self.marker.as_slice() {
            self.marker.clear();
            return true;
        }
        let keep = (1..=self.marker.len())
            .rev()
            .find(|&len| {
                let suffix = &self.marker[self.marker.len() - len..];
                MASK.starts_with(suffix) || PENDING_MASK.starts_with(suffix)
            })
            .unwrap_or(0);
        let discard = self.marker.len() - keep;
        self.marker.drain(..discard);
        keep != 0
    }

    fn decode(&mut self, bytes: &[u8], mask: bool, chunk: &mut OutputChunk) {
        // The common plain-output path needs no per-scalar allocation or tagging.
        // 0xef includes U+FFFD's lead byte; ambiguous bytes use the full decoder.
        if self.tail.is_empty()
            && self.marker.is_empty()
            && !mask
            && !bytes.contains(&b'[')
            && !bytes.contains(&0xef)
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            chunk.text.push_str(text);
            return;
        }
        for &value in bytes {
            let sensitive = self.marker_byte(value);
            self.tail.push(Byte {
                value,
                mask,
                sensitive,
            });
            self.decode_tail(chunk);
        }
    }

    fn decode_tail(&mut self, chunk: &mut OutputChunk) {
        // At most four bytes. Reconsider a non-continuation after replacing the
        // preceding invalid sequence, matching standard incremental lossy UTF-8.
        while !self.tail.is_empty() {
            let mut bytes = [0u8; 4];
            for (dst, src) in bytes.iter_mut().zip(&self.tail) {
                *dst = src.value;
            }
            let bytes = &bytes[..self.tail.len()];
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    let scalar = text.chars().next().expect("nonempty scalar");
                    self.emit_tail(scalar.len_utf8(), scalar, false, chunk);
                }
                Err(error) if error.valid_up_to() != 0 => {
                    let valid = std::str::from_utf8(&bytes[..error.valid_up_to()])
                        .expect("validated UTF-8 prefix");
                    let scalar = valid.chars().next().expect("nonempty prefix");
                    self.emit_tail(scalar.len_utf8(), scalar, false, chunk);
                }
                Err(error) => match error.error_len() {
                    Some(len) => self.emit_tail(len, '\u{fffd}', true, chunk),
                    None => break,
                },
            }
        }
        debug_assert!(self.tail.len() <= 3);
    }

    fn emit_tail(&mut self, len: usize, scalar: char, lossy: bool, chunk: &mut OutputChunk) {
        let mask = self.tail[..len].iter().any(|b| b.mask);
        let sensitive = self.tail[..len].iter().any(|b| b.sensitive);
        chunk.scalar(scalar, mask, sensitive, lossy);
        self.tail.drain(..len);
    }
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)] // These intentionally contain one span.
mod tests {
    use super::*;
    use crate::redaction::SecretDictionary;

    fn dictionary(keys: &[&str]) -> SecretDictionary {
        SecretDictionary::new(&keys.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn stream(keys: &[&str]) -> OutputStream {
        OutputStream::new(dictionary(keys).stream().unwrap())
    }

    fn check(chunk: &OutputChunk) {
        let mut end = 0;
        for range in &chunk.sensitive {
            assert!(range.start >= end && range.start < range.end);
            assert!(range.end <= chunk.text.len());
            assert!(chunk.text.is_char_boundary(range.start));
            assert!(chunk.text.is_char_boundary(range.end));
            end = range.end;
        }
    }

    fn append(text: &mut String, chunk: OutputChunk) {
        check(&chunk);
        text.push_str(&chunk.text);
    }

    #[test]
    fn unaffected_controls_and_every_utf8_split() {
        let input = "hello é水🦀\n";
        for split in 0..=input.len() {
            let mut s = stream(&[]);
            let mut out = String::new();
            let first = s.push(&input.as_bytes()[..split]).unwrap();
            assert!(!first.lossy && first.sensitive.is_empty());
            append(&mut out, first);
            let second = s.push(&input.as_bytes()[split..]).unwrap();
            assert!(!second.lossy && second.sensitive.is_empty());
            append(&mut out, second);
            append(&mut out, s.finish().unwrap());
            assert_eq!(out, input);
        }
    }

    #[test]
    fn raw_json_and_percent_forms_across_every_cutover_split() {
        let key = "a\"/é";
        let forms = [
            "a\"/é",
            "a\\\"/é",
            "a\\\"\\/é",
            "a%22%2F%C3%A9",
            "%61%22%2f%c3%a9",
        ];
        let union = dictionary(&[key]);
        for form in forms {
            for split in 0..=form.len() {
                let mut s = stream(&[]);
                // History before cutover belongs to the coordinator. Verify only
                // the still-private suffix here; local history is not remasked.
                let _history = s.push(&form.as_bytes()[..split]).unwrap();
                let mut after = String::new();
                append(
                    &mut after,
                    s.cutover(union.stream().unwrap(), union.max_pattern_len())
                        .unwrap(),
                );
                for byte in &form.as_bytes()[split..] {
                    append(&mut after, s.push(&[*byte]).unwrap());
                }
                append(&mut after, s.finish().unwrap());
                assert!(after.bytes().all(|b| b == b'*'));
            }
        }
    }

    #[test]
    fn old_original_pending_is_preserved_and_rechecked() {
        let union = dictionary(&["abcdef", "bc"]);
        let mut s = stream(&["abcdef"]);
        assert!(s.push(b"abc").unwrap().text.is_empty());
        assert_eq!(s.redactor.pending_len(), 3);
        let mut out = String::new();
        append(
            &mut out,
            s.cutover(union.stream().unwrap(), union.max_pattern_len())
                .unwrap(),
        );
        append(&mut out, s.push(b"def!").unwrap());
        append(&mut out, s.finish().unwrap());
        // Replaying original abc + def yields one ten-byte replacement, not
        // six masked raw bytes or an old finish's prematurely released prefix.
        assert_eq!(out, "*".repeat(MASK.len() + 1));
    }

    #[test]
    fn decoder_tail_precedes_original_matcher_pending() {
        let mut s = stream(&["secret"]);
        let first = s.push(&[0xe2, 0x82]).unwrap();
        assert!(first.text.is_empty());
        let union = dictionary(&["secret", "€token"]);
        let mut out = String::new();
        append(
            &mut out,
            s.cutover(union.stream().unwrap(), union.max_pattern_len())
                .unwrap(),
        );
        append(&mut out, s.push(b"\xactoken!").unwrap());
        append(&mut out, s.finish().unwrap());
        assert_eq!(out, "*".repeat(MASK.len() + 1));
    }

    #[test]
    fn masked_scalar_finishes_without_sticky_masking() {
        let empty = dictionary(&[]);
        let mut s = stream(&[]);
        // Exercise the conservative-window primitive independently of dictionary
        // construction: an oversized bound is safe and deliberately supported.
        s.cutover(empty.stream().unwrap(), 2).unwrap();
        assert!(s.push(&[0xe2]).unwrap().text.is_empty());
        let c = s.push(&[0x82, 0xac, b'Z']).unwrap();
        assert_eq!(c.text, "***Z");
        assert_eq!(c.sensitive, vec![0..3]);
        assert_eq!(s.push(b"normal").unwrap().text, "normal");
    }

    #[test]
    fn repeated_refresh_preserves_masked_scalar() {
        let empty = dictionary(&[]);
        let mut s = stream(&[]);
        s.cutover(empty.stream().unwrap(), 2).unwrap();
        s.push(&[0xf0, 0x9f]).unwrap();
        assert!(
            s.cutover(empty.stream().unwrap(), 0)
                .unwrap()
                .text
                .is_empty()
        );
        let c = s.push(&[0xa6, 0x80, b'!']).unwrap();
        assert_eq!(c.text, "****!");
        assert_eq!(c.sensitive, vec![0..4]);
    }

    #[test]
    fn real_matcher_sees_secret_extending_beyond_boundary_window() {
        let union = dictionary(&["abcdefgh", "bcdef"]);
        let mut s = stream(&[]);
        s.cutover(union.stream().unwrap(), union.max_pattern_len())
            .unwrap();
        let mut out = String::new();
        // Max encoded length is 24, so the raw secret straddles byte 23.
        for byte in b"xxxxxxxxxxxxxxxxxxxxxabcdefgh!" {
            append(&mut out, s.push(&[*byte]).unwrap());
        }
        append(&mut out, s.push(b" normal text").unwrap());
        append(&mut out, s.finish().unwrap());
        assert!(!out.contains("defgh"));
        assert!(out.ends_with(" normal text"));
    }

    #[test]
    fn overlapping_keys_and_replacement_provenance_without_refresh() {
        let mut s = stream(&["abc", "abcdef", "bcde"]);
        let c = s.push(b"abcdef!").unwrap();
        assert_eq!(c.text, "[REDACTED]!");
        assert_eq!(c.sensitive, vec![0..MASK.len()]);
        assert!(!c.lossy);
        assert!(s.finish().unwrap().text.is_empty());
    }

    #[test]
    fn literal_marker_boundaries_are_tagged_without_buffering_history() {
        let mut s = stream(&[]);
        for part in ["[RED", "ACTED", "]", "[REDACTED_", "PENDING]"] {
            let c = s.push(part.as_bytes()).unwrap();
            assert_eq!(c.text, part);
            assert_eq!(c.sensitive, vec![0..part.len()]);
        }
        assert!(s.push(b"ordinary").unwrap().sensitive.is_empty());
        let c = s.push("�".as_bytes()).unwrap();
        assert_eq!(c.sensitive, vec![0..3]);
        assert!(!c.lossy);
    }

    #[test]
    fn successful_eof_releases_nonmatching_tail_and_decodes_invalid_utf8() {
        let mut s = stream(&["abcdef"]);
        assert!(s.push(b"abc").unwrap().text.is_empty());
        let c = s.finish().unwrap();
        assert_eq!(c.text, "abc");
        assert!(!c.lossy && c.sensitive.is_empty());

        let mut s = stream(&[]);
        let c = s.push(b"A\xffB\xe2\x82").unwrap();
        assert_eq!(c.text, "A�B");
        assert!(c.lossy);
        assert_eq!(c.sensitive, vec![1..4]);
        let c = s.finish().unwrap();
        assert_eq!(c.text, "�");
        assert!(c.lossy);
        assert_eq!(c.sensitive, vec![0..3]);
    }

    #[test]
    fn oversized_push_is_rejected_without_consuming_input() {
        let mut s = stream(&[]);
        assert!(s.push(&vec![b'x'; MAX_PUSH_BYTES + 1]).is_err());
        assert_eq!(s.push(b"ok").unwrap().text, "ok");
        assert!(s.finish().unwrap().text.is_empty());
    }

    #[test]
    fn abort_is_drop_not_finish() {
        let mut s = stream(&["abcdef"]);
        assert!(s.push(b"abc").unwrap().text.is_empty());
        assert_eq!(s.redactor.pending_len(), 3);
        drop(s); // No API path returns the withheld bytes on failure.
    }
}
