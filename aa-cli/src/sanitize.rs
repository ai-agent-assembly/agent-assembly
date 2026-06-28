//! Terminal output sanitization for server-supplied text.

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
///   extra lines into a single-line field.
///
/// Printable text (including multi-byte Unicode) is preserved unchanged.
pub fn sanitize_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // ESC: consume the escape sequence it introduces.
            '\u{1b}' => match chars.peek() {
                Some('[') => {
                    // CSI: parameters/intermediates up to a final byte.
                    chars.next();
                    for tail in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&tail) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: data terminated by BEL or ST (ESC \).
                    chars.next();
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
                Some(_) => {
                    // Other two-byte escape (e.g. `ESC c`, `ESC ( B`).
                    chars.next();
                }
                None => {}
            },
            // Drop all other C0 control characters and DEL.
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {}
            c => out.push(c),
        }
    }
    out
}
