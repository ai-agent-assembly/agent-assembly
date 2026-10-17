//! Server-Sent Events framing for the enforcing MitM path (AAASM-6356 PR2).
//!
//! An SSE response is unbounded, so it cannot be buffered and judged whole the
//! way a JSON body is. The proxy instead judges and forwards it one event at a
//! time, and the invariant that makes that safe is: **the bytes the gateway
//! judged are exactly the bytes forwarded.** [`SseParser`] therefore never
//! relays upstream bytes; it parses events and yields a *canonical*
//! re-serialisation, so a framing quirk (`\r`, `\r\n` and `\n` line ends,
//! comment lines, unknown fields, a BOM) cannot make the proxy's reading of an
//! event differ from the client's.
//!
//! Only `data`, `event`, `id` and `retry` survive: they are the fields a client
//! acts on. Comment lines and unknown fields are dropped (a comment-only event
//! becomes a fixed content-free keep-alive), so they cannot carry content past
//! the judgement.

/// Largest single event the parser will hold. An event that has not completed
/// by this size is an error, which the caller treats as fail-closed.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Content-free keep-alive sent in place of a comment-only event.
pub const KEEPALIVE: &[u8] = b":\n\n";

/// Why the stream cannot be judged any further.
#[derive(Debug, PartialEq, Eq)]
pub enum SseError {
    /// An event passed [`MAX_EVENT_BYTES`] without completing.
    EventTooLarge,
    /// An event was not valid UTF-8, so its meaning cannot be judged.
    NotUtf8,
}

/// Incremental event splitter. Feed it decoded body bytes with [`Self::push`].
#[derive(Debug, Default)]
pub struct SseParser {
    /// Line-ending-normalised bytes of the event in progress.
    buf: Vec<u8>,
    /// The previous byte was `\r`, so a following `\n` is the same line end.
    pending_cr: bool,
    seen_event: bool,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// True while bytes of an event that has not completed are held.
    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Consume `bytes`; return the canonical form of every event they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, SseError> {
        for &b in bytes {
            if self.pending_cr {
                self.pending_cr = false;
                if b == b'\n' {
                    continue;
                }
            }
            if b == b'\r' {
                self.buf.push(b'\n');
                self.pending_cr = true;
            } else {
                self.buf.push(b);
            }
        }
        let mut out = Vec::new();
        while let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let raw: Vec<u8> = self.buf.drain(..end + 2).collect();
            if let Some(canonical) = self.canonicalise(&raw[..end])? {
                out.push(canonical);
            }
        }
        // Blank lines between events carry nothing.
        let blank = self.buf.iter().take_while(|&&b| b == b'\n').count();
        self.buf.drain(..blank);
        if self.buf.len() > MAX_EVENT_BYTES {
            return Err(SseError::EventTooLarge);
        }
        Ok(out)
    }

    fn canonicalise(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, SseError> {
        let mut text = std::str::from_utf8(raw).map_err(|_| SseError::NotUtf8)?;
        if !self.seen_event {
            self.seen_event = true;
            text = text.strip_prefix('\u{feff}').unwrap_or(text);
        }
        let mut out = Vec::new();
        let mut saw_comment = false;
        for line in text.split('\n') {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(':') {
                saw_comment = true;
                continue;
            }
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            if !matches!(name, "data" | "event" | "id" | "retry") {
                continue;
            }
            // A NUL in an id makes clients ignore it; do not forward it either.
            if name == "id" && value.contains('\0') {
                continue;
            }
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.push(b'\n');
        }
        if out.is_empty() {
            return Ok(saw_comment.then(|| KEEPALIVE.to_vec()));
        }
        out.push(b'\n');
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(chunks: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut p = SseParser::new();
        chunks.iter().flat_map(|c| p.push(c).unwrap()).collect()
    }

    #[test]
    fn every_line_ending_yields_the_same_canonical_event() {
        let want = vec![b"data: hi\n\n".to_vec()];
        assert_eq!(events(&[b"data: hi\n\n"]), want);
        assert_eq!(events(&[b"data: hi\r\n\r\n"]), want);
        assert_eq!(events(&[b"data: hi\r\r"]), want);
        assert_eq!(events(&[b"data: hi\r\n\n"]), want);
    }

    #[test]
    fn a_crlf_split_across_pushes_is_one_line_end() {
        assert_eq!(events(&[b"data: a\r", b"\n\r", b"\n"]), vec![b"data: a\n\n".to_vec()]);
    }

    #[test]
    fn an_event_split_at_any_byte_boundary_is_the_same_event() {
        let whole = b"event: message\r\ndata: one\r\ndata: two\r\n\r\ndata: three\n\n";
        let want = events(&[whole]);
        assert_eq!(want.len(), 2);
        for cut in 0..whole.len() {
            assert_eq!(events(&[&whole[..cut], &whole[cut..]]), want, "cut at {cut}");
        }
    }

    #[test]
    fn comments_and_unknown_fields_never_reach_the_canonical_form() {
        assert_eq!(
            events(&[b": hidden\ndata: x\nsecret-field: leak\nid: 7\n\n"]),
            vec![b"data: x\nid: 7\n\n".to_vec()]
        );
        assert_eq!(events(&[b": only a comment with text\n\n"]), vec![KEEPALIVE.to_vec()]);
    }

    #[test]
    fn a_field_without_a_colon_is_a_field_with_an_empty_value() {
        assert_eq!(events(&[b"data\n\n"]), vec![b"data: \n\n".to_vec()]);
    }

    #[test]
    fn a_leading_bom_and_blank_lines_are_ignored() {
        assert_eq!(events(&[b"\xEF\xBB\xBF\n\ndata: a\n\n"]), vec![b"data: a\n\n".to_vec()]);
    }

    #[test]
    fn an_incomplete_event_is_held_and_reported_as_partial() {
        let mut p = SseParser::new();
        assert!(p.push(b"data: half").unwrap().is_empty());
        assert!(p.has_partial());
        assert_eq!(p.push(b" done\n\n").unwrap(), vec![b"data: half done\n\n".to_vec()]);
        assert!(!p.has_partial());
    }

    #[test]
    fn an_oversized_or_non_utf8_event_is_an_error() {
        let mut p = SseParser::new();
        let big = vec![b'a'; MAX_EVENT_BYTES + 1];
        assert_eq!(p.push(&big), Err(SseError::EventTooLarge));
        let mut p = SseParser::new();
        assert_eq!(p.push(b"data: \xFF\xFE\n\n"), Err(SseError::NotUtf8));
    }
}
