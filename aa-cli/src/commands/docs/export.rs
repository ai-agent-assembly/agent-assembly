//! `aasm docs export` — auto-generate the CLI reference from the live `clap`
//! command tree.
//!
//! The renderer walks the `clap::Command` returned by [`crate::Cli::command()`]
//! — never a hand-maintained list — so the emitted Markdown can never drift
//! from the actual CLI surface. Each command (the root plus every subcommand,
//! recursively) becomes one Markdown file under the output directory:
//!
//! * the root `aasm` command  → `aasm.md`
//! * `aasm agent`             → `aasm-agent.md`
//! * `aasm agent create`      → `aasm-agent-create.md`
//!
//! Every file carries a stable anchor id derived from the command path
//! (`#cmd-aasm-agent-create`) so external docs can deep-link to a command and
//! keep working across regenerations.
//!
//! `--check` re-renders into memory and compares against the on-disk tree,
//! returning a non-zero exit code when they differ. This is what the CI job
//! runs to keep `docs/cli/` honest.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::StyledStr;
use clap::{Args, Command, CommandFactory};

/// Arguments for `aasm docs export`.
#[derive(Args)]
#[command(after_help = "\
Examples:
  aasm docs export
  aasm docs export --format markdown --out docs/cli/
  aasm docs export --check")]
pub struct ExportArgs {
    /// Output format for the generated reference (only `markdown` today).
    #[arg(long, value_enum, default_value_t = DocsFormat::Markdown)]
    pub format: DocsFormat,

    /// Directory to write the generated reference into.
    #[arg(long, default_value = "docs/cli/")]
    pub out: PathBuf,

    /// Verify the on-disk reference is up to date instead of writing it.
    ///
    /// Re-renders the CLI tree in memory and compares it against the files in
    /// `--out`. Exits non-zero (and lists the stale paths) when they differ,
    /// without modifying anything. Used by CI to block PRs that change a
    /// `clap` definition without regenerating `docs/cli/`.
    #[arg(long)]
    pub check: bool,
}

/// Output format for `aasm docs export`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum DocsFormat {
    /// One Markdown file per command.
    Markdown,
}

/// Run `aasm docs export`.
pub fn run(args: ExportArgs) -> ExitCode {
    // `format` is currently single-valued; the flag exists so the acceptance
    // contract (`--format markdown`) is explicit and future formats slot in
    // here without a breaking CLI change.
    let DocsFormat::Markdown = args.format;

    let root = crate::Cli::command();
    let pages = render_all(&root);

    if args.check {
        check(&args.out, &pages)
    } else {
        write(&args.out, &pages)
    }
}

/// A single rendered reference page: its on-disk file name and Markdown body.
struct Page {
    /// File name relative to the output directory (e.g. `aasm-agent-create.md`).
    file_name: String,
    /// Rendered Markdown contents.
    body: String,
}

/// Walk the live command tree and render every command to a [`Page`].
///
/// Results are keyed and sorted by file name so the output (and any `--check`
/// diff) is deterministic regardless of `clap`'s subcommand ordering.
fn render_all(root: &Command) -> Vec<Page> {
    let mut pages: BTreeMap<String, Page> = BTreeMap::new();
    walk(root, &[], &mut pages);
    pages.into_values().collect()
}

/// Recursively visit `cmd` and each of its subcommands.
///
/// `ancestors` is the slice of command names from the root down to (but not
/// including) `cmd`; the full path is `ancestors + [cmd.get_name()]`.
fn walk(cmd: &Command, ancestors: &[String], pages: &mut BTreeMap<String, Page>) {
    let mut path: Vec<String> = ancestors.to_vec();
    path.push(cmd.get_name().to_string());

    let file_name = format!("{}.md", path.join("-"));
    let body = render_command(cmd, &path);
    pages.insert(file_name.clone(), Page { file_name, body });

    for sub in cmd.get_subcommands() {
        // `clap`'s built-in `help` pseudo-subcommand is not a real command and
        // would render an empty, confusing page — skip it.
        if sub.get_name() == "help" {
            continue;
        }
        walk(sub, &path, pages);
    }
}

/// Render one command's Markdown page given its full command path.
fn render_command(cmd: &Command, path: &[String]) -> String {
    let full = path.join(" ");
    let anchor = anchor_id(path);
    let mut out = String::new();

    // Title + stable anchor for durable cross-links.
    out.push_str(&format!("# `{full}`\n\n"));
    out.push_str(&format!("<a id=\"{anchor}\"></a>\n\n"));

    // Synopsis — the command's about/long-about text.
    if let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()).map(styled_to_string) {
        let about = about.trim();
        if !about.is_empty() {
            out.push_str(&format!("{about}\n\n"));
        }
    }

    // Usage — reuse clap's own rendered usage string for accuracy.
    out.push_str("## Synopsis\n\n");
    out.push_str("```text\n");
    out.push_str(render_usage(cmd, path).trim_end());
    out.push('\n');
    out.push_str("```\n\n");

    // Options table — every argument the command accepts.
    let args: Vec<&clap::Arg> = cmd.get_arguments().collect();
    if !args.is_empty() {
        out.push_str("## Options\n\n");
        out.push_str("| Option | Value | Description |\n");
        out.push_str("|--------|-------|-------------|\n");
        for arg in &args {
            out.push_str(&render_arg_row(arg));
        }
        out.push('\n');
    }

    // Subcommands — link to each child page by its stable anchor.
    let subs: Vec<&Command> = cmd.get_subcommands().filter(|s| s.get_name() != "help").collect();
    if !subs.is_empty() {
        out.push_str("## Subcommands\n\n");
        out.push_str("| Command | Description |\n");
        out.push_str("|---------|-------------|\n");
        for sub in &subs {
            let mut sub_path = path.to_vec();
            sub_path.push(sub.get_name().to_string());
            let sub_full = sub_path.join(" ");
            let sub_file = format!("{}.md", sub_path.join("-"));
            let sub_anchor = anchor_id(&sub_path);
            let desc = sub
                .get_about()
                .map(styled_to_string)
                .unwrap_or_default()
                .replace('\n', " ");
            out.push_str(&format!(
                "| [`{sub_full}`]({sub_file}#{sub_anchor}) | {} |\n",
                escape_cell(&desc)
            ));
        }
        out.push('\n');
    }

    // Examples — surfaced from `#[command(after_help = …)]`.
    if let Some(after) = cmd
        .get_after_long_help()
        .or_else(|| cmd.get_after_help())
        .map(styled_to_string)
    {
        let after = after.trim();
        if !after.is_empty() {
            out.push_str("## Examples\n\n");
            // after_help conventionally already reads "Examples:\n  <cmd>".
            // Drop a leading "Examples:" line to avoid a doubled heading, then
            // render the remainder as a fenced block.
            let body = after
                .strip_prefix("Examples:")
                .unwrap_or(after)
                .trim_start_matches('\n');
            out.push_str("```text\n");
            out.push_str(body.trim_end());
            out.push('\n');
            out.push_str("```\n\n");
        }
    }

    out
}

/// Build the stable anchor id for a command path: `cmd-aasm-agent-create`.
fn anchor_id(path: &[String]) -> String {
    format!("cmd-{}", path.join("-"))
}

/// Render one option as a Markdown table row.
fn render_arg_row(arg: &clap::Arg) -> String {
    // Flag column: `--long`, `-s`, or a positional `<NAME>`.
    let flag = if let Some(long) = arg.get_long() {
        match arg.get_short() {
            Some(short) => format!("`-{short}`, `--{long}`"),
            None => format!("`--{long}`"),
        }
    } else if let Some(short) = arg.get_short() {
        format!("`-{short}`")
    } else {
        format!("`<{}>`", arg.get_id().as_str().to_uppercase())
    };

    // Value column: placeholder + enumerated possible values when present.
    let value = if matches!(
        arg.get_action(),
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Help | clap::ArgAction::Version
    ) {
        String::new()
    } else {
        let placeholder = arg
            .get_value_names()
            .map(|names| names.iter().map(|n| format!("`<{n}>`")).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let possible: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|p| format!("`{}`", p.get_name()))
            .collect();
        if possible.is_empty() {
            placeholder
        } else if placeholder.is_empty() {
            possible.join(", ")
        } else {
            format!("{placeholder} ({})", possible.join(", "))
        }
    };

    // Description column: help text + default value + required marker.
    let mut desc = arg
        .get_long_help()
        .or_else(|| arg.get_help())
        .map(styled_to_string)
        .unwrap_or_default()
        .replace('\n', " ");
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    if !defaults.is_empty() {
        desc.push_str(&format!(" [default: {}]", defaults.join(", ")));
    }
    if arg.is_required_set() {
        desc.push_str(" *(required)*");
    }

    format!(
        "| {} | {} | {} |\n",
        escape_cell(&flag),
        escape_cell(&value),
        escape_cell(desc.trim())
    )
}

/// Render clap's own usage string for a command, prefixed with the full path.
fn render_usage(cmd: &Command, path: &[String]) -> String {
    // `render_usage` yields e.g. "Usage: list [OPTIONS]" using the leaf name;
    // rewrite the leaf to the full path so the synopsis is copy-pasteable.
    let usage = styled_to_string(&cmd.clone().render_usage());
    let leaf = cmd.get_name();
    let full = path.join(" ");
    usage.replacen(&format!("Usage: {leaf}"), &format!("Usage: {full}"), 1)
}

/// Flatten a clap [`StyledStr`] to plain text (ANSI styling stripped).
fn styled_to_string(s: &StyledStr) -> String {
    s.to_string()
}

/// Escape Markdown table-cell-breaking characters.
fn escape_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Write every page to `out_dir`, creating it if necessary.
fn write(out_dir: &Path, pages: &[Page]) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        eprintln!("error: failed to create {}: {e}", out_dir.display());
        return ExitCode::FAILURE;
    }
    for page in pages {
        let path = out_dir.join(&page.file_name);
        if let Err(e) = std::fs::write(&path, &page.body) {
            eprintln!("error: failed to write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }
    println!("wrote {} CLI reference file(s) to {}", pages.len(), out_dir.display());
    ExitCode::SUCCESS
}

/// Compare the on-disk reference against the freshly rendered pages.
///
/// Returns [`ExitCode::SUCCESS`] only when every page matches byte-for-byte and
/// no extra/orphaned files exist in `out_dir`.
fn check(out_dir: &Path, pages: &[Page]) -> ExitCode {
    let mut stale: Vec<String> = Vec::new();

    let expected: std::collections::BTreeSet<&str> = pages.iter().map(|p| p.file_name.as_str()).collect();

    for page in pages {
        let path = out_dir.join(&page.file_name);
        match std::fs::read_to_string(&path) {
            Ok(on_disk) if on_disk == page.body => {}
            Ok(_) => stale.push(format!("{} (out of date)", path.display())),
            Err(_) => stale.push(format!("{} (missing)", path.display())),
        }
    }

    // Catch orphaned files — a command was removed but its page lingers.
    if let Ok(entries) = std::fs::read_dir(out_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".md") && !expected.contains(name.as_ref()) {
                stale.push(format!("{} (orphaned)", entry.path().display()));
            }
        }
    }

    if stale.is_empty() {
        println!("CLI reference in {} is up to date", out_dir.display());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "error: CLI reference in {} is stale; run `aasm docs export` to regenerate:",
            out_dir.display()
        );
        for s in &stale {
            eprintln!("  - {s}");
        }
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered() -> Vec<Page> {
        render_all(&crate::Cli::command())
    }

    #[test]
    fn renders_a_page_for_the_root_command() {
        let pages = rendered();
        assert!(pages.iter().any(|p| p.file_name == "aasm.md"));
    }

    #[test]
    fn renders_a_page_per_nested_subcommand() {
        let pages = rendered();
        // `aasm agent list` is a known three-level command.
        assert!(
            pages.iter().any(|p| p.file_name == "aasm-agent-list.md"),
            "expected a page for `aasm agent list`"
        );
    }

    #[test]
    fn does_not_emit_a_page_for_clap_help_pseudo_command() {
        let pages = rendered();
        assert!(
            !pages.iter().any(|p| p.file_name.contains("-help.md")),
            "the built-in `help` subcommand must not get its own page"
        );
    }

    #[test]
    fn anchor_id_is_stable_and_path_derived() {
        assert_eq!(
            anchor_id(&["aasm".to_string(), "agent".to_string(), "create".to_string()]),
            "cmd-aasm-agent-create"
        );
    }

    #[test]
    fn page_contains_its_stable_anchor() {
        let pages = rendered();
        let agent = pages
            .iter()
            .find(|p| p.file_name == "aasm-agent.md")
            .expect("agent page");
        assert!(agent.body.contains("<a id=\"cmd-aasm-agent\"></a>"));
    }

    #[test]
    fn page_has_synopsis_and_options_sections() {
        let pages = rendered();
        let root = pages.iter().find(|p| p.file_name == "aasm.md").expect("root page");
        assert!(root.body.contains("## Synopsis"));
        assert!(root.body.contains("## Options"));
        assert!(root.body.contains("## Subcommands"));
    }

    #[test]
    fn examples_are_surfaced_from_after_help() {
        let pages = rendered();
        // `aasm docs export` itself declares an after_help Examples block.
        let export = pages
            .iter()
            .find(|p| p.file_name == "aasm-docs-export.md")
            .expect("docs export page");
        assert!(export.body.contains("## Examples"));
        assert!(export.body.contains("aasm docs export --check"));
    }

    #[test]
    fn subcommand_links_use_stable_anchors() {
        let pages = rendered();
        let agent = pages
            .iter()
            .find(|p| p.file_name == "aasm-agent.md")
            .expect("agent page");
        assert!(agent.body.contains("aasm-agent-list.md#cmd-aasm-agent-list"));
    }

    #[test]
    fn check_passes_against_freshly_written_pages() {
        let dir = tempfile::tempdir().unwrap();
        let pages = rendered();
        assert_eq!(write(dir.path(), &pages), ExitCode::SUCCESS);
        assert_eq!(check(dir.path(), &pages), ExitCode::SUCCESS);
    }

    #[test]
    fn check_fails_when_a_page_is_modified() {
        let dir = tempfile::tempdir().unwrap();
        let pages = rendered();
        write(dir.path(), &pages);
        // Corrupt one file to simulate a drifted clap definition.
        std::fs::write(dir.path().join("aasm.md"), "stale").unwrap();
        assert_eq!(check(dir.path(), &pages), ExitCode::FAILURE);
    }

    #[test]
    fn check_fails_when_a_page_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let pages = rendered();
        write(dir.path(), &pages);
        std::fs::remove_file(dir.path().join("aasm.md")).unwrap();
        assert_eq!(check(dir.path(), &pages), ExitCode::FAILURE);
    }

    #[test]
    fn check_fails_on_orphaned_page() {
        let dir = tempfile::tempdir().unwrap();
        let pages = rendered();
        write(dir.path(), &pages);
        std::fs::write(dir.path().join("aasm-ghost.md"), "orphan").unwrap();
        assert_eq!(check(dir.path(), &pages), ExitCode::FAILURE);
    }
}
