//! `aasm proxy logs` — tail the proxy log file.

use std::io::{BufRead, Seek};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;

/// Arguments for `aasm proxy logs`.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Stream new log entries continuously (like `tail -f`).
    #[arg(short = 'f', long)]
    pub follow: bool,
    /// Number of lines to show from the end of the log (default 50).
    #[arg(long, default_value_t = 50)]
    pub lines: usize,
    /// Filter to lines at or above this level: error, warn, info, debug.
    #[arg(long, value_name = "LEVEL")]
    pub level: Option<String>,
    /// Show only entries since a relative duration (e.g., `5m`, `1h`, `30s`).
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
}

fn default_log_path() -> PathBuf {
    dirs::data_local_dir()
        .expect("cannot determine local data directory")
        .join("aasm")
        .join("logs")
        .join("proxy.log")
}

/// Parse a relative duration string like `5m`, `1h30m`, or `45s` into seconds.
pub fn parse_since(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut total = 0u64;
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else {
            let n: u64 = cur.parse().ok()?;
            cur.clear();
            total += match ch {
                's' => n,
                'm' => n * 60,
                'h' => n * 3600,
                'd' => n * 86400,
                _ => return None,
            };
        }
    }
    if !cur.is_empty() {
        return None; // trailing digits with no unit
    }
    Some(total)
}

/// Return `true` if the log line's level meets the minimum threshold.
pub fn line_matches_level(line: &str, min_level: &str) -> bool {
    let order = ["error", "warn", "info", "debug", "trace"];
    let threshold = order.iter().position(|&l| l.eq_ignore_ascii_case(min_level));
    let Some(threshold_idx) = threshold else {
        return true; // unknown level — don't filter
    };
    // Try to detect the level keyword anywhere in the line.
    for (idx, &level) in order.iter().enumerate() {
        if line.to_lowercase().contains(level) {
            return idx <= threshold_idx;
        }
    }
    true // no recognisable level — pass through
}

/// Read the last `n` lines from a file.
fn last_n_lines(path: &PathBuf, n: usize) -> Vec<String> {
    let Ok(mut file) = std::fs::File::open(path) else {
        return vec![];
    };
    let Ok(meta) = file.metadata() else {
        return vec![];
    };

    let size = meta.len();
    // Read up to 8 KiB per line estimate to find the last N lines efficiently.
    let chunk = (n as u64 * 256).min(size);
    let start = size.saturating_sub(chunk);
    if file.seek(std::io::SeekFrom::Start(start)).is_err() {
        return vec![];
    }

    let reader = std::io::BufReader::new(file);
    let mut lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    // If we didn't start at the beginning we may have a partial first line — drop it.
    if start > 0 && lines.len() > 1 {
        lines.remove(0);
    }

    lines
        .into_iter()
        .rev()
        .take(n)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

pub fn dispatch(args: LogsArgs) -> ExitCode {
    let log_path = default_log_path();

    if !log_path.exists() {
        eprintln!("No proxy log file found at {}.", log_path.display());
        eprintln!("Start the proxy with `aasm proxy start` first.");
        return ExitCode::FAILURE;
    }

    let since_secs = args.since.as_deref().and_then(parse_since);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let should_print = |line: &str| -> bool {
        if let Some(ref lvl) = args.level {
            if !line_matches_level(line, lvl) {
                return false;
            }
        }
        if let Some(cutoff) = since_secs {
            let oldest_ts = now_secs.saturating_sub(cutoff);
            // Heuristic: look for an ISO-8601-style timestamp prefix and compare.
            if let Some(ts) = parse_line_timestamp(line) {
                if ts < oldest_ts {
                    return false;
                }
            }
        }
        true
    };

    // Print the last N lines.
    let tail = last_n_lines(&log_path, args.lines);
    for line in &tail {
        if should_print(line) {
            println!("{line}");
        }
    }

    if !args.follow {
        return ExitCode::SUCCESS;
    }

    // Follow mode: poll for new content appended to the file.
    let Ok(mut file) = std::fs::File::open(&log_path) else {
        eprintln!("error: could not open log file for tailing");
        return ExitCode::FAILURE;
    };
    // Seek to end before polling for new lines.
    let _ = file.seek(std::io::SeekFrom::End(0));

    loop {
        let mut reader = std::io::BufReader::new(&file);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let trimmed = line.trim_end_matches('\n');
            if should_print(trimmed) {
                println!("{trimmed}");
            }
            line.clear();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Attempt to parse a Unix timestamp from a tracing-formatted log line.
/// tracing-subscriber's compact/full format starts with e.g. `2026-05-18T14:23:01`.
fn parse_line_timestamp(line: &str) -> Option<u64> {
    let s = line.get(..19)?;
    // Expect format: YYYY-MM-DDTHH:MM:SS
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    // Simple (non-leap-second) approximation.
    let days_since_epoch = days_from_epoch(year, month, day)?;
    Some(days_since_epoch * 86400 + hour * 3600 + min * 60 + sec)
}

fn days_from_epoch(year: u64, month: u64, day: u64) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    let months_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = |y: u64| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);

    let mut days: u64 = 0;
    for y in 1970..year {
        days += if leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        let extra = if m == 2 && leap(year) { 1 } else { 0 };
        days += months_days[(m - 1) as usize] + extra;
    }
    days += day - 1;
    Some(days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: LogsArgs,
    }

    #[test]
    fn logs_args_defaults() {
        let w = Wrapper::parse_from(["test"]);
        assert!(!w.inner.follow);
        assert_eq!(w.inner.lines, 50);
        assert!(w.inner.level.is_none());
        assert!(w.inner.since.is_none());
    }

    #[test]
    fn logs_args_follow_flag() {
        let w = Wrapper::parse_from(["test", "-f"]);
        assert!(w.inner.follow);
    }

    #[test]
    fn logs_args_lines_override() {
        let w = Wrapper::parse_from(["test", "--lines", "100"]);
        assert_eq!(w.inner.lines, 100);
    }

    #[test]
    fn logs_args_level_filter() {
        let w = Wrapper::parse_from(["test", "--level", "warn"]);
        assert_eq!(w.inner.level.as_deref(), Some("warn"));
    }

    #[test]
    fn logs_args_since_filter() {
        let w = Wrapper::parse_from(["test", "--since", "5m"]);
        assert_eq!(w.inner.since.as_deref(), Some("5m"));
    }

    #[test]
    fn parse_since_seconds() {
        assert_eq!(parse_since("30s"), Some(30));
    }

    #[test]
    fn parse_since_minutes() {
        assert_eq!(parse_since("5m"), Some(300));
    }

    #[test]
    fn parse_since_hours() {
        assert_eq!(parse_since("1h"), Some(3600));
    }

    #[test]
    fn parse_since_composite() {
        assert_eq!(parse_since("1h30m"), Some(5400));
    }

    #[test]
    fn parse_since_invalid_returns_none() {
        assert_eq!(parse_since("5x"), None);
        assert_eq!(parse_since("abc"), None);
        assert_eq!(parse_since(""), None);
    }

    #[test]
    fn line_matches_level_error_only() {
        assert!(line_matches_level("ERROR something bad", "error"));
        assert!(!line_matches_level("INFO everything fine", "error"));
        assert!(!line_matches_level("WARN watch out", "error"));
    }

    #[test]
    fn line_matches_level_warn_includes_error() {
        assert!(line_matches_level("ERROR bad", "warn"));
        assert!(line_matches_level("WARN careful", "warn"));
        assert!(!line_matches_level("INFO ok", "warn"));
    }

    #[test]
    fn line_matches_level_info_includes_error_and_warn() {
        assert!(line_matches_level("ERROR bad", "info"));
        assert!(line_matches_level("WARN careful", "info"));
        assert!(line_matches_level("INFO ok", "info"));
        assert!(!line_matches_level("DEBUG verbose", "info"));
    }

    #[test]
    fn line_without_level_passes_through() {
        assert!(line_matches_level("just some text", "error"));
    }
}
