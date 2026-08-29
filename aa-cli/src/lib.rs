//! `aa-cli` library — shared types for the `aasm` binary and integration tests.

use clap::Parser;

pub mod auth;
pub mod client;
pub mod commands;
pub mod config;
pub mod env_guard;
pub mod error;
pub mod output;
pub mod sanitize;

#[cfg(test)]
mod test_support;

/// Agent Assembly CLI — governance gateway management tool.
#[derive(Parser)]
#[command(name = "aasm", version, about)]
pub struct Cli {
    /// Named context from ~/.aa/config.yaml to use.
    #[arg(long, global = true)]
    pub context: Option<String>,

    /// Output format for list/get commands.
    #[arg(long, global = true, value_enum, default_value_t = output::OutputFormat::Table)]
    pub output: output::OutputFormat,

    /// Override the API URL (takes precedence over context config).
    #[arg(long, global = true)]
    pub api_url: Option<String>,

    /// Override the API key (takes precedence over context config).
    ///
    /// Reads from the `AASM_API_KEY` environment variable when the flag is
    /// absent. Prefer the env var: passing `--api-key` on the command line
    /// leaks the operator bearer token into argv, which is world-readable via
    /// `ps`, `/proc/<pid>/cmdline`, and shell history. The flag still wins when
    /// both are set, so existing scripts keep working.
    ///
    /// `hide_env_values` is load-bearing, not decorative (AAASM-5935). Without
    /// it clap renders `[env: AASM_API_KEY=<the live value>]` into help output,
    /// and because this arg is `global = true` that fires on `aasm --help` and
    /// on every `aasm <subcommand> --help`. Help output is the single likeliest
    /// CLI output to be pasted into a ticket, a chat channel or a support
    /// bundle, so the advice above — prefer the env var, argv is world-readable
    /// — would otherwise route the token from one disclosure channel into a
    /// worse one.
    #[arg(long, global = true, env = "AASM_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    #[command(subcommand)]
    pub command: commands::Commands,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The global `--api-key` flag must fall back to `AASM_API_KEY` so the
    /// operator bearer token need never appear in argv (ps/proc/shell history).
    #[test]
    fn api_key_resolves_from_env_when_flag_absent() {
        let _guard = test_support::env_guard();
        std::env::set_var("AASM_API_KEY", "env-secret");
        let parsed = Cli::try_parse_from(["aasm", "version"]);
        std::env::remove_var("AASM_API_KEY");
        let cli = parsed.expect("parse must succeed");
        assert_eq!(cli.api_key.as_deref(), Some("env-secret"));
    }

    /// An explicit `--api-key` flag still wins over the env var (back-compat).
    #[test]
    fn api_key_flag_takes_precedence_over_env() {
        let _guard = test_support::env_guard();
        std::env::set_var("AASM_API_KEY", "env-secret");
        let parsed = Cli::try_parse_from(["aasm", "--api-key", "flag-secret", "version"]);
        std::env::remove_var("AASM_API_KEY");
        let cli = parsed.expect("parse must succeed");
        assert_eq!(cli.api_key.as_deref(), Some("flag-secret"));
    }

    /// Every environment variable name any argument in the command tree reads.
    fn env_backed_names(cmd: &clap::Command, out: &mut Vec<String>) {
        for arg in cmd.get_arguments() {
            if let Some(name) = arg.get_env() {
                out.push(name.to_string_lossy().into_owned());
            }
        }
        for sub in cmd.get_subcommands() {
            env_backed_names(sub, out);
        }
    }

    /// Long help for `cmd` and for every subcommand beneath it.
    ///
    /// `cmd` must already be built: clap propagates `global = true` args into
    /// subcommands during `build`, so walking an unbuilt tree renders
    /// subcommand help *without* the global args and silently checks a smaller
    /// surface than the one that matters. Verified rather than assumed — before
    /// the build call in the caller, reverting `hide_env_values` on the global
    /// `--api-key` reddened for `["aasm"]` alone; after it, for every
    /// subcommand as well.
    fn all_long_help(cmd: &clap::Command) -> Vec<(String, String)> {
        let mut out = vec![(cmd.get_name().to_string(), cmd.clone().render_long_help().to_string())];
        for sub in cmd.get_subcommands() {
            out.extend(all_long_help(sub));
        }
        out
    }

    /// No help output anywhere in the command tree may render an environment
    /// variable's **value** (AAASM-5935).
    ///
    /// clap renders `[env: NAME=<live value>]` unless the argument sets
    /// `hide_env_values`, so an operator who followed this CLI's own advice —
    /// export `AASM_API_KEY` rather than pass `--api-key`, because argv is
    /// world-readable — had the token printed by `aasm --help` instead. The arg
    /// is `global = true`, so it appeared under every subcommand's help too.
    ///
    /// This asserts the property over the whole tree rather than over the one
    /// argument that was wrong, because the defect was never specific to
    /// `AASM_API_KEY`: it is what clap does by default, so the next `env = `
    /// argument someone adds inherits it. Deciding per-variable whether a value
    /// is secret-bearing is the same name-based trust that AAASM-5935 exists to
    /// remove — help needs the variable's *name*, never its contents.
    #[test]
    fn no_help_output_in_the_command_tree_renders_an_environment_value() {
        let _guard = test_support::env_guard();

        let mut names = Vec::new();
        env_backed_names(&Cli::command(), &mut names);
        assert!(
            !names.is_empty(),
            "no env-backed args found — the walk is broken, not the CLI"
        );

        // Distinctive, non-functional, and not a credential of any kind. clap
        // resolves an arg's env value while building the command, so these must
        // be set before `Cli::command()` is asked for help.
        let canary = "SYNTHETIC-ENV-CANARY-NOT-A-CREDENTIAL";
        for name in &names {
            std::env::set_var(name, canary);
        }
        let mut built = Cli::command();
        built.build();
        let rendered = all_long_help(&built);
        for name in &names {
            std::env::remove_var(name);
        }

        // Cleanup happens before the assertion so a failure does not leave the
        // canary set for every test that runs after it.
        let leaked: Vec<&str> = rendered
            .iter()
            .filter(|(_, help)| help.contains(canary))
            .map(|(cmd, _)| cmd.as_str())
            .collect();
        assert!(
            leaked.is_empty(),
            "help output renders an env value for: {leaked:?} (add `hide_env_values = true` to the arg)"
        );

        // The names must still be there: withholding the value is the point,
        // withholding the variable would break the help's usefulness.
        let (_, root_help) = rendered.first().expect("root help");
        assert!(
            root_help.contains("AASM_API_KEY"),
            "help must still name the variable it reads"
        );
    }

    /// With neither flag nor env set, `--api-key` resolves to `None` (no panic).
    #[test]
    fn api_key_none_when_neither_flag_nor_env_set() {
        let _guard = test_support::env_guard();
        std::env::remove_var("AASM_API_KEY");
        let cli = Cli::try_parse_from(["aasm", "version"]).expect("parse must succeed");
        assert!(cli.api_key.is_none());
    }
}
