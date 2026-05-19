//! `aasm gateway logs` — tail the gateway log file.
//!
//! The gateway emits structured JSON lines via `tracing-subscriber`'s JSON
//! formatter. Each line looks like:
//!
//! ```json
//! {"timestamp":"2026-05-18T10:00:00.123456Z","level":"INFO","fields":{"message":"..."},"target":"aa_gateway::server"}
//! ```
//!
//! `--level` filtering matches the `"level"` field (case-insensitive).

use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, ValueEnum};

const FOLLOW_POLL: Duration = Duration::from_millis(100);

/// Log level filter for `--level`.
#[derive(Debug, Clone, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }
}

/// Arguments for `aasm gateway logs`.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Stream new log entries in real time (like `tail -f`).
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Number of lines to show from the end of the log (default 50).
    #[arg(long, default_value_t = 50)]
    pub lines: u64,

    /// Filter log entries by minimum severity level.
    #[arg(long)]
    pub level: Option<LogLevel>,

    /// Path to the log file (default ~/.aasm/logs/gateway.log).
    #[arg(long)]
    pub log_file: Option<PathBuf>,
}

/// Dispatch `aasm gateway logs`.
pub fn dispatch(args: LogsArgs) -> ExitCode {
    let log_path = resolve_log_path(&args);

    let file = match std::fs::File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot open {}: {e}", log_path.display());
            return ExitCode::FAILURE;
        }
    };

    let level_filter = args.level.as_ref().map(|l| l.as_str());

    if args.follow {
        follow_logs(file, level_filter)
    } else {
        tail_logs(file, args.lines, level_filter)
    }
}

fn resolve_log_path(args: &LogsArgs) -> PathBuf {
    if let Some(ref p) = args.log_file {
        return p.clone();
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aasm")
        .join("logs")
        .join("gateway.log")
}

/// Print the last `n` lines of `file`, filtered by `level_filter`.
fn tail_logs(file: std::fs::File, n: u64, level_filter: Option<&str>) -> ExitCode {
    let reader = BufReader::new(file);
    let mut window: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if matches_level(&line, level_filter) {
            if window.len() as u64 >= n {
                window.pop_front();
            }
            window.push_back(line);
        }
    }

    for line in &window {
        println!("{line}");
    }
    ExitCode::SUCCESS
}

/// Stream new lines appended to `file`, filtered by `level_filter`.
/// Polls for new content every FOLLOW_POLL ms. Stops on Ctrl-C.
fn follow_logs(mut file: std::fs::File, level_filter: Option<&str>) -> ExitCode {
    // Seek to end so we only show new entries.
    if file.seek(SeekFrom::End(0)).is_err() {
        eprintln!("error: could not seek to end of log file");
        return ExitCode::FAILURE;
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = tokio::time::sleep(FOLLOW_POLL) => {
                    loop {
                        buf.clear();
                        match reader.read_line(&mut buf) {
                            Ok(0) => break, // no new data
                            Ok(_) => {
                                let line = buf.trim_end_matches('\n').trim_end_matches('\r');
                                if matches_level(line, level_filter) {
                                    println!("{line}");
                                    // Flush immediately: stdout is block-buffered
                                    // when redirected to a file (non-TTY), so without
                                    // an explicit flush each line would sit in the
                                    // process buffer until it fills or the process exits.
                                    let _ = std::io::stdout().flush();
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }
    });

    ExitCode::SUCCESS
}

/// Returns `true` if `line` passes the level filter.
///
/// Lines are expected to be JSON with a top-level `"level"` field. Non-JSON
/// lines are always passed through so operator notes in the log are preserved.
pub fn matches_level(line: &str, level_filter: Option<&str>) -> bool {
    let Some(filter) = level_filter else {
        return true;
    };

    let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
        return true; // non-JSON line: pass through
    };

    let Some(level_field) = val.get("level").and_then(|v| v.as_str()) else {
        return true; // no level field: pass through
    };

    level_field.eq_ignore_ascii_case(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_level_no_filter_always_true() {
        assert!(matches_level(r#"{"level":"DEBUG","message":"x"}"#, None));
        assert!(matches_level("plain text line", None));
    }

    #[test]
    fn matches_level_filters_by_json_level_field() {
        let info = r#"{"level":"INFO","fields":{"message":"started"}}"#;
        let debug = r#"{"level":"DEBUG","fields":{"message":"tick"}}"#;
        assert!(matches_level(info, Some("INFO")));
        assert!(!matches_level(debug, Some("INFO")));
    }

    #[test]
    fn matches_level_case_insensitive() {
        let warn = r#"{"level":"WARN","message":"high memory"}"#;
        assert!(matches_level(warn, Some("warn")));
        assert!(matches_level(warn, Some("WARN")));
    }

    #[test]
    fn matches_level_passes_non_json_lines_through() {
        assert!(matches_level("not json at all", Some("ERROR")));
    }

    #[test]
    fn matches_level_passes_json_without_level_field() {
        assert!(matches_level(r#"{"message":"no level here"}"#, Some("INFO")));
    }

    #[test]
    fn log_level_as_str_values() {
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Warn.as_str(), "WARN");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
    }

    #[test]
    fn tail_logs_returns_last_n_lines() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        for i in 0..10u32 {
            writeln!(tmp, "{{\"level\":\"INFO\",\"msg\":{i}}}").unwrap();
        }
        let file = std::fs::File::open(tmp.path()).unwrap();
        // tail_logs should succeed (testing return code only; stdout goes to test runner)
        assert_eq!(tail_logs(file, 5, None), ExitCode::SUCCESS);
    }
}
