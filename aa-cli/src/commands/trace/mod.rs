//! `aasm trace` — session trace visualization.

use std::process::ExitCode;

use clap::{Args, ValueEnum};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

pub mod client;
pub mod models;
pub mod timeline;
pub mod tree;
pub mod wire;

/// Visualization format for trace output.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum TraceFormat {
    /// Indented tree with box-drawing characters (default).
    #[default]
    Tree,
    /// Horizontal ASCII timeline with duration bars.
    Timeline,
}

/// Arguments for the `aasm trace` subcommand.
#[derive(Debug, Args)]
pub struct TraceArgs {
    /// Session ID to retrieve the trace for.
    pub session_id: String,

    /// Visualization format.
    #[arg(long, value_enum, default_value_t = TraceFormat::Tree)]
    pub format: TraceFormat,
}

/// Execute the `aasm trace` subcommand.
pub fn dispatch(args: TraceArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let trace = match rt.block_on(client::fetch_trace(ctx, &args.session_id)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error fetching trace: {e}");
            return ExitCode::FAILURE;
        }
    };

    match output {
        OutputFormat::Json => match serde_json::to_string_pretty(&trace) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("error serializing trace: {e}");
                return ExitCode::FAILURE;
            }
        },
        OutputFormat::Yaml => match serde_yaml::to_string(&trace) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => {
                eprintln!("error serializing trace: {e}");
                return ExitCode::FAILURE;
            }
        },
        OutputFormat::Table => match args.format {
            TraceFormat::Tree => {
                print!("{}", tree::render_tree(&trace));
            }
            TraceFormat::Timeline => {
                print!("{}", timeline::render_timeline(&trace, 80));
            }
        },
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Minimal CLI struct for testing subcommand parsing.
    #[derive(Parser)]
    #[command(name = "aasm")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Trace(TraceArgs),
    }

    #[test]
    fn parse_trace_with_session_id() {
        let cli = TestCli::try_parse_from(["aasm", "trace", "sess-001"]).unwrap();
        match cli.command {
            TestCommands::Trace(args) => {
                assert_eq!(args.session_id, "sess-001");
                assert!(matches!(args.format, TraceFormat::Tree));
            }
        }
    }

    #[test]
    fn parse_trace_with_timeline_format() {
        let cli = TestCli::try_parse_from(["aasm", "trace", "sess-002", "--format", "timeline"]).unwrap();
        match cli.command {
            TestCommands::Trace(args) => {
                assert_eq!(args.session_id, "sess-002");
                assert!(matches!(args.format, TraceFormat::Timeline));
            }
        }
    }

    #[test]
    fn parse_trace_missing_session_id_fails() {
        let result = TestCli::try_parse_from(["aasm", "trace"]);
        assert!(result.is_err());
    }
}
