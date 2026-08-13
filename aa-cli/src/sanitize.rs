//! Terminal output sanitization for server-supplied text.

/// Char cursor type used by the escape-sequence consumers.
type CharCursor<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Consume a CSI sequence: parameters/intermediates up to a final byte (`0x40`–`0x7e`).
/// Called after the `ESC [` introducer has been consumed.
fn consume_csi(chars: &mut CharCursor) {
    for tail in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&tail) {
            break;
        }
    }
}

/// Consume an OSC sequence: data terminated by BEL (`0x07`) or ST (`ESC \`).
/// Called after the `ESC ]` introducer has been consumed.
fn consume_osc(chars: &mut CharCursor) {
    while let Some(&t) = chars.peek() {
        if t == '\u{07}' {
            chars.next();
            break;
        }
        if t == '\u{1b}' {
            chars.next();
            if chars.peek() == Some(&'\\') {
                chars.next();
            }
            break;
        }
        chars.next();
    }
}

/// Whether `c` is a control character that should be stripped: C0 (`0x00`–`0x1f`),
/// DEL (`0x7f`), or C1 (`0x80`–`0x9f`).
fn is_control_char(c: char) -> bool {
    let code = c as u32;
    code < 0x20 || code == 0x7f || (0x80..=0x9f).contains(&code)
}

/// Strip terminal control sequences from server-supplied text before it is
/// printed to the operator's terminal.
///
/// Fields such as an approval's `agent_id`, `action`, or `reason` originate
/// from a (potentially malicious) agent and are echoed verbatim by
/// `aasm approvals watch`, `aasm logs`, and the dashboard feed. Without
/// sanitization, an agent can embed ANSI/OSC escape sequences that repaint the
/// line so a dangerous request looks benign (approve/reject decision spoofing)
/// or drive the terminal directly (e.g. an OSC-52 clipboard write).
///
/// This removes:
/// - the ESC (`0x1b`) introducer together with the rest of the escape
///   sequence it begins — CSI (`ESC [` … final byte `0x40`–`0x7e`),
///   OSC (`ESC ]` … terminated by BEL `0x07` or ST `ESC \`), and the
///   shorter two-byte escapes (`ESC` + one byte); and
/// - every remaining C0 control character (`0x00`–`0x1f`) and DEL (`0x7f`),
///   which includes newlines and carriage returns that could otherwise inject
///   extra lines into a single-line field; and
/// - the C1 control range (`0x80`–`0x9f`), which includes `U+009B` — the 8-bit
///   CSI introducer that some terminals interpret as an escape sequence start
///   even without a leading `ESC`, reopening the spoofing vector above.
///
/// Printable text (including multi-byte Unicode) is preserved unchanged.
pub fn sanitize_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => consume_escape_sequence(&mut chars),
            c if is_control_char(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Consume an escape sequence starting after the ESC (`0x1b`) byte.
fn consume_escape_sequence(chars: &mut CharCursor) {
    match chars.peek() {
        Some('[') => {
            chars.next();
            consume_csi(chars);
        }
        Some(']') => {
            chars.next();
            consume_osc(chars);
        }
        Some(_) => {
            // Other two-byte escape (e.g. `ESC c`, `ESC ( B`).
            chars.next();
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_color_sequences() {
        assert_eq!(sanitize_terminal("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(sanitize_terminal("a\x1b[1;33mb\x1b[0mc"), "abc");
    }

    #[test]
    fn strips_osc_clipboard_write() {
        // OSC-52 clipboard write, BEL-terminated.
        assert_eq!(sanitize_terminal("a\x1b]52;c;ZXZpbA==\x07b"), "ab");
        // OSC title set, ST-terminated (ESC \).
        assert_eq!(sanitize_terminal("a\x1b]0;pwned\x1b\\b"), "ab");
    }

    #[test]
    fn strips_c0_controls_and_del() {
        // Newlines/carriage returns/tab/backspace/DEL are all removed so a
        // single-line field cannot inject extra lines.
        assert_eq!(sanitize_terminal("line1\nline2\r\t\x08\x7fx"), "line1line2x");
    }

    #[test]
    fn strips_c1_controls() {
        // U+009B is the 8-bit CSI introducer; some terminals act on it as if it
        // were `ESC [`, so it must be dropped even though it carries no ESC.
        assert_eq!(sanitize_terminal("a\u{9b}31mred"), "a31mred");
        // Full C1 range boundaries (0x80 and 0x9f) are removed too.
        assert_eq!(sanitize_terminal("x\u{80}y\u{9f}z"), "xyz");
    }

    #[test]
    fn preserves_plain_and_unicode_text() {
        assert_eq!(sanitize_terminal("agent-7 working"), "agent-7 working");
        // Accented Latin, Greek, CJK, and an emoji are all printable and kept —
        // C1 stripping must not touch code points at or above U+00A0.
        assert_eq!(sanitize_terminal("héllo-β-世界-🚀"), "héllo-β-世界-🚀");
    }
}
