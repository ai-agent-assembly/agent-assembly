# `aasm docs export`

<a id="cmd-aasm-docs-export"></a>

Export the CLI reference, one Markdown file per command

## Synopsis

```text
Usage: aasm docs export [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--format` | `<FORMAT>` (`markdown`) | Output format for the generated reference (only `markdown` today) [default: markdown] |
| `--out` | `<OUT>` | Directory to write the generated reference into [default: docs/cli/] |
| `--check` |  | Verify the on-disk reference is up to date instead of writing it.  Re-renders the CLI tree in memory and compares it against the files in `--out`. Exits non-zero (and lists the stale paths) when they differ, without modifying anything. Used by CI to block PRs that change a `clap` definition without regenerating `docs/cli/`. |

## Examples

```text
  aasm docs export
  aasm docs export --format markdown --out docs/cli/
  aasm docs export --check
```

