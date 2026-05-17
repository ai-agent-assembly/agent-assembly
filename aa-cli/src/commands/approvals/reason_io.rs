//! Stdin / flag resolution for `--reason` on `aasm approvals approve` and
//! `aasm approvals reject` (AAASM-1477).
//!
//! When `--reason` is omitted but stdin is a pipe (not a TTY), read until
//! EOF and use that as the reason. Symmetric across approve and reject.

use std::io::{self, Read};

/// Resolve the effective `--reason` from a flag value and a possibly-piped
/// stdin.
///
/// Resolution order:
/// 1. If `flag` is `Some` with non-whitespace content, return its trimmed form.
/// 2. Otherwise, if `is_tty` is `false`, read `stdin` to EOF and return its
///    trimmed form (or `None` if empty after trim).
/// 3. Otherwise return `None` — caller decides whether to error
///    (reject does; approve does not).
///
/// Factored out as a pure function over `impl Read` + `is_tty` so the
/// stdin-piped path can be unit-tested without forking a real pipe.
pub fn resolve_reason(flag: Option<String>, stdin: &mut impl Read, is_tty: bool) -> Option<String> {
    if let Some(s) = flag.as_deref() {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if is_tty {
        return None;
    }
    let mut buf = String::new();
    if stdin.read_to_string(&mut buf).is_err() {
        return None;
    }
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Convenience wrapper that reads from the real process stdin. Uses
/// `std::io::IsTerminal` to detect whether stdin is a pipe.
pub fn resolve_reason_from_process_stdin(flag: Option<String>) -> Option<String> {
    use std::io::IsTerminal;
    let is_tty = io::stdin().is_terminal();
    let mut stdin = io::stdin().lock();
    resolve_reason(flag, &mut stdin, is_tty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn flag_value_takes_priority_over_stdin() {
        let mut stdin = Cursor::new(b"piped reason");
        let result = resolve_reason(Some("flag reason".into()), &mut stdin, false);
        assert_eq!(result.as_deref(), Some("flag reason"));
    }

    #[test]
    fn empty_flag_falls_back_to_stdin_when_pipe() {
        let mut stdin = Cursor::new(b"piped reason");
        let result = resolve_reason(Some("   ".into()), &mut stdin, false);
        assert_eq!(result.as_deref(), Some("piped reason"));
    }

    #[test]
    fn missing_flag_falls_back_to_stdin_when_pipe() {
        let mut stdin = Cursor::new(b"piped reason\n");
        let result = resolve_reason(None, &mut stdin, false);
        assert_eq!(result.as_deref(), Some("piped reason"));
    }

    #[test]
    fn missing_flag_returns_none_when_tty_and_no_pipe() {
        let mut stdin = Cursor::new(b"this should be ignored on a tty");
        let result = resolve_reason(None, &mut stdin, true);
        assert!(result.is_none());
    }

    #[test]
    fn empty_stdin_returns_none() {
        let mut stdin = Cursor::new(b"   \n\n");
        let result = resolve_reason(None, &mut stdin, false);
        assert!(result.is_none());
    }
}
