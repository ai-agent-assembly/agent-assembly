# aasm completion

Generate a shell completion script for `aasm` and write it to stdout. Source
or install the output to get tab-completion for commands, subcommands, and
flags.

## Synopsis

```text
aasm completion <SHELL>
```

This command has no subcommands.

## Arguments

| Argument | Type | Description |
|---|---|---|
| `<SHELL>` | shell | Shell to generate completions for. Supported values come from `clap_complete::Shell`: `bash`, `elvish`, `fish`, `powershell`, `zsh`. |

## Examples

Bash (current session):

```bash
source <(aasm completion bash)
```

Zsh (install into a completions directory on `$fpath`):

```bash
aasm completion zsh > ~/.zfunc/_aasm
```

Fish:

```bash
aasm completion fish > ~/.config/fish/completions/aasm.fish
```
