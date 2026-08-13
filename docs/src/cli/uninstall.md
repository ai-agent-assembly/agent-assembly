# aasm uninstall

Uninstall Agent Assembly tools installed via the curl installer.

`aasm uninstall` is a thin wrapper over the installer's uninstall engine. The
curl installer (`scripts/install-cli.sh`) is the single source of truth for the
manifest-driven removal and `--purge` logic; on install it persists a runnable
copy at `${AASM_STATE_DIR:-~/.aasm}/aasm-uninstall`, and this command forwards
to it so the CLI, the curl installer, and the offline fallback all share one
engine. Homebrew-managed installs are detected by the engine and redirected to
`brew uninstall`.

If no local uninstaller is found, the command prints the Homebrew and curl
fallbacks and exits non-zero.

## Synopsis

```text
aasm uninstall [OPTIONS]
```

Safe by default: without `--purge`, only the installed components are removed;
Agent Assembly-owned local data (config + state) is left in place.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--components <LIST>` | string | — | Remove only these components (comma-separated: `cli,runtime,proxy,ebpf`). |
| `--component <NAME>` | string (repeatable) | — | Remove a single component; repeat the flag for several. |
| `--all` | flag | off | Uninstall all components (the default scope; accepted for explicitness). |
| `--purge` | flag | off | Also remove Agent Assembly-owned local data (config + state). |
| `--dry-run` | flag | off | Show what would be removed without changing anything. |
| `-y, --yes` | flag | off | Skip the `--purge` confirmation prompt (non-interactive). |

```bash
aasm uninstall --dry-run
aasm uninstall --purge --yes
```
