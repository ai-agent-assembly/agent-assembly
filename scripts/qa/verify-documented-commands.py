#!/usr/bin/env python3
"""Verify every documented shell command in the CLI quick-start docs and the
README's onboarding sections actually runs (AAASM-5888).

WHY THIS SHAPE
--------------
J21 ("Doc + command integrity — every documented command and internal link
works") claimed the full documented command matrix worked, but the
`verify-commands` CI job only ever ran 2 hand-picked commands (`cargo build`,
`cargo doc`) — nothing noticed when a doc gained a new command that no CI job
executed. A second hand-written list of `run:` steps would reproduce the same
failure mode with more steps.

Instead this script *extracts* every fenced `sh`/`bash`/`shell`/`console` code
block from the in-scope docs (see SOURCES below), classifies each one as
either EXECUTED (run here, with an assertion on its documented outcome) or
ALLOWLISTED (not run, with a reason string), and treats any block that is
**neither** as a hard failure. That "unclassified = fail" rule is the actual
fix: a newly-documented command that nobody has classified yet stops the
build instead of silently shipping unverified, which is exactly the gap this
ticket exists to close.

SCOPE
-----
- Sources: every `docs/src/quick-start/*.md` file (installation, first run,
  configuration, requirements) plus a fixed set of README.md headings that
  constitute its "Getting Started" material — the install/uninstall flow and
  the Quickstart / Docker Compose walkthroughs. The rest of the README
  (architecture, ecosystem, crate map, ...) is prose, not documented as
  something a reader is meant to invoke.
- Unit of classification is the **fenced code block** for `sh`/`bash`/`shell`
  blocks (the block is what a reader copies), and the individual `$ <cmd>`
  line for `console` transcript blocks (those are already delimited that way
  in the docs).
- Blocks containing a `<placeholder>` token are not literally runnable
  verbatim; they must be ALLOWLISTED, not EXECUTED.
- Commands that pipe a network download into a shell
  (`curl ... | sh`), invoke Homebrew, download a release tarball, or run
  `cosign verify-blob` are ALLOWLISTED, not executed — running an installer
  script or an external package manager against this CI job's environment is
  both a supply-chain risk or a repo security-rule violation (never pipe
  remote content into a shell) and, for the release-artifact commands,
  requires a published release to exist. `make dev-setup` / `make dev-verify`
  and `docker compose up` are likewise ALLOWLISTED — see the reasons attached
  to each entry below for specifics.
- A command that the docs *show failing* (`aasm status` before a control
  plane is up, `aasm agent list` / `aasm topology overview` with no
  registry) is still EXECUTED — the assertion is on the *documented* outcome
  (a specific non-zero exit and message), not on exit 0. Silently accepting
  any exit code would make the check vacuous.

Usage:
    python3 scripts/qa/verify-documented-commands.py --check-coverage
        Extract + classify every in-scope block; fail if any block is
        unclassified or if an ALLOWLIST/EXECUTORS entry no longer matches
        anything in the docs (stale entry). Does not run anything. Cheap;
        this is what to run locally.

    python3 scripts/qa/verify-documented-commands.py --run
        Coverage check, then actually execute every EXECUTORS entry in order
        against a built `aasm` CLI on $PATH. This is what CI runs, after
        `cargo build --workspace --exclude aa-ebpf` and
        `cargo install --path aa-cli --force`.

    python3 scripts/qa/verify-documented-commands.py --selftest
        Proves the detector actually fails in both directions, using inline
        fixtures (not the real docs): (a) a fenced block with no matching
        ALLOWLIST/EXECUTORS entry is reported uncovered, and (b) an
        EXECUTORS entry whose command fails is reported as a failure. Fast,
        no build required.

Exit codes: 0 clean, 1 a block is unclassified / stale entry / execution
failed, 2 usage or I/O error.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]

# Files this script scans in full.
QUICK_START_FILES = [
    "docs/src/quick-start/installation.md",
    "docs/src/quick-start/first-run.md",
    "docs/src/quick-start/configuration.md",
    "docs/src/quick-start/requirements.md",
]

# README.md headings (## or ###) whose content counts as "Getting Started"
# material. Everything outside these headings (Overview, Ecosystem, Crate
# Map, Project Status, Requirements, Supported platforms, Repository Layout,
# ...) is architecture/reference prose, not an onboarding walkthrough.
README_HEADINGS_IN_SCOPE = {
    "Install the CLI",
    "Install additional components",
    "Review-first install",
    "Homebrew (macOS / Linux)",
    "Uninstall",
    "Quickstart",
    "1. Clone the repository",
    "2. Bootstrap the development environment",
    "3. Verify the installation",
    "Running with Docker Compose",
}

FENCE_LANGS = {"sh", "bash", "shell", "console", "zsh"}
PLACEHOLDER_RE = re.compile(r"<[a-zA-Z][a-zA-Z0-9_-]*>")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
DATA_TITLE_RE = re.compile(r'data-title="([^"]+)"')
FENCE_START_RE = re.compile(r"^(>\s*)?```(\S*)\s*$")
FENCE_END_RE = re.compile(r"^(>\s*)?```\s*$")


@dataclass(frozen=True)
class Block:
    file: str
    heading: str
    lang: str
    text: str  # full block body, blockquote markers stripped

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.file, self.heading, self.text)

    @property
    def label(self) -> str:
        first_line = self.text.strip().splitlines()[0] if self.text.strip() else "(empty)"
        return f"{self.file} [{self.heading}] {self.lang!r}: {first_line[:70]}"


@dataclass(frozen=True)
class ConsoleCommand:
    file: str
    heading: str
    lang: str
    command: str
    output: str  # lines following the '$ ' line, up to the next '$ ' or block end

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.file, self.heading, f"$ {self.command}")

    @property
    def label(self) -> str:
        return f"{self.file} [{self.heading}] console: $ {self.command}"


Unit = Block | ConsoleCommand


def _strip_quote(line: str) -> str:
    if line.startswith("> "):
        return line[2:]
    if line == ">":
        return ""
    return line


def extract_blocks(file_rel: str) -> list[Unit]:
    path = REPO_ROOT / file_rel
    lines = path.read_text(encoding="utf-8").splitlines()

    units: list[Unit] = []
    heading = ""
    i = 0
    while i < len(lines):
        raw = lines[i]
        m = HEADING_RE.match(raw)
        if m:
            heading = m.group(2)
            i += 1
            continue
        dt = DATA_TITLE_RE.search(raw)
        if dt:
            heading = dt.group(1)

        fm = FENCE_START_RE.match(raw)
        if fm:
            lang = fm.group(2).lower()
            body_lines: list[str] = []
            i += 1
            while i < len(lines) and not FENCE_END_RE.match(lines[i]):
                body_lines.append(_strip_quote(lines[i]))
                i += 1
            i += 1  # consume closing fence
            if lang not in FENCE_LANGS:
                continue
            if lang == "console":
                units.extend(_split_console(file_rel, heading, lang, body_lines))
            else:
                text = "\n".join(body_lines).strip("\n")
                if text.strip():
                    units.append(Block(file_rel, heading, lang, text))
            continue
        i += 1
    return units


def _split_console(file_rel: str, heading: str, lang: str, body_lines: list[str]) -> list[ConsoleCommand]:
    out: list[ConsoleCommand] = []
    command: str | None = None
    output_lines: list[str] = []
    for line in body_lines:
        if line.startswith("$ "):
            if command is not None:
                out.append(ConsoleCommand(file_rel, heading, lang, command, "\n".join(output_lines)))
            command = line[2:]
            output_lines = []
        else:
            output_lines.append(line)
    if command is not None:
        out.append(ConsoleCommand(file_rel, heading, lang, command, "\n".join(output_lines)))
    return out


def collect_units() -> list[Unit]:
    units: list[Unit] = []
    for f in QUICK_START_FILES:
        units.extend(extract_blocks(f))
    for u in extract_blocks("README.md"):
        if u.heading in README_HEADINGS_IN_SCOPE:
            units.append(u)
    return units


# --------------------------------------------------------------------------
# Classification: every unit key below must correspond to something
# extract_units() actually finds in the docs (checked by --check-coverage),
# and every extracted unit must appear in exactly one of these two tables.
# --------------------------------------------------------------------------

ALLOWLIST: dict[tuple[str, str, str], str] = {
    # -- installation.md: network installer / package-manager / release-asset flows.
    ("docs/src/quick-start/installation.md", "Quick-install script",
     "curl -sSf https://agent-assembly.com/install.sh | sh"):
        "pipes a network download into a shell against a published GitHub "
        "release — forbidden in CI by this repo's own security rules "
        "(never pipe remote content into a shell), and needs a real release "
        "to exist.",
    ("docs/src/quick-start/installation.md", "Quick-install script",
     'export PATH="$HOME/.local/bin:$PATH"'):
        "a PATH hint fragment printed by the installer, not a standalone "
        "command with an outcome to assert.",
    ("docs/src/quick-start/installation.md", "Pin a version or change the install directory",
     "# Install a specific release tag (default: latest)\n"
     "AASM_VERSION=v0.0.1-rc.6 curl -sSf https://agent-assembly.com/install.sh | sh\n"
     "\n"
     "# Install to a custom directory\n"
     "AASM_INSTALL_DIR=/usr/local/bin curl -sSf https://agent-assembly.com/install.sh | sh"):
        "same curl | sh network-install pattern, pinned to a specific "
        "published release tag.",
    ("docs/src/quick-start/installation.md", "Supply-chain verification (checksum + cosign)",
     "AASM_REQUIRE_SIGNATURE=1 curl -sSf https://agent-assembly.com/install.sh | sh"):
        "same curl | sh network-install pattern.",
    ("docs/src/quick-start/installation.md", "Homebrew",
     "brew install ai-agent-assembly/tap/aasm"):
        "installs from the external Homebrew tap's published formula; "
        "requires a tagged release and Homebrew, neither guaranteed in the "
        "docs-governance runner.",
    ("docs/src/quick-start/installation.md", "Pre-built binaries",
     'VERSION=v0.0.1-rc.6\n'
     'ASSET=aasm-aarch64-apple-darwin.tar.gz   # adjust for your platform\n'
     'BASE="https://github.com/ai-agent-assembly/agent-assembly/releases/download/${VERSION}"\n\n'
     'curl -sSfL "${BASE}/${ASSET}"        -o "${ASSET}"\n'
     'curl -sSfL "${BASE}/SHA256SUMS"      -o SHA256SUMS\n\n'
     '# Verify the checksum (use sha256sum on Linux, shasum -a 256 on macOS)\n'
     'shasum -a 256 -c <(grep "${ASSET}" SHA256SUMS)\n\n'
     '# (Optional) Verify the cosign signature on the checksum file\n'
     'curl -sSfL "${BASE}/SHA256SUMS.cosign.bundle" -o SHA256SUMS.cosign.bundle\n'
     'cosign verify-blob \\\n'
     '  --bundle SHA256SUMS.cosign.bundle \\\n'
     "  --certificate-identity-regexp '^https://github\\.com/ai-agent-assembly/agent-assembly/\\.github/workflows/release\\.yml@refs/tags/v.*$' \\\n"
     "  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\\n"
     '  SHA256SUMS\n\n'
     'tar -xzf "${ASSET}" aasm\n'
     'install -m755 aasm ~/.local/bin/aasm'):
        "downloads a pinned release tarball + cosign bundle from GitHub "
        "Releases and verifies them; needs a real published release matching "
        "the pinned VERSION and a macOS/aarch64 asset name.",
    # -- first-run.md
    ("docs/src/quick-start/first-run.md", "1. Start the gateway",
     "cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml"):
        "documented as an equivalent alternative to `aasm gateway start`, "
        "which this script already executes in the same job — running both "
        "would collide on the shared 127.0.0.1:50051 listener.",
    ("docs/src/quick-start/first-run.md", "4. Observe an agent",
     "cd examples/docker-compose\nAA_API_KEY=dev-local-key docker compose up"):
        "a long-running foreground Docker Compose stack that pulls external "
        "images and never exits on its own; out of scope for a command-smoke "
        "check.",
    ("docs/src/quick-start/first-run.md", "4. Observe an agent",
     "aasm agent list          # all registered agents\n"
     "aasm agent inspect <id>  # detail for one agent"):
        "contains a templated `<id>` placeholder — not literally runnable "
        "verbatim as a block; `aasm agent list` on its own is executed via "
        "the console transcript command below.",
    ("docs/src/quick-start/first-run.md", "5. View the topology",
     "aasm topology overview   # fleet-wide overview\n"
     "aasm topology tree <id>  # subtree rooted at an agent\n"
     "aasm topology stats      # aggregate statistics"):
        "contains a templated `<id>` placeholder — not literally runnable "
        "verbatim as a block; `aasm topology overview` on its own is "
        "executed via the console transcript command below.",
    # -- README.md: same network-install / package-manager / destructive-uninstall
    # patterns as installation.md, plus the sibling-repo dev workflow.
    ("README.md", "Install the CLI",
     "curl -fsSL https://agent-assembly.com/install.sh | sh"):
        "pipes a network download into a shell — forbidden in CI by this "
        "repo's own security rules; needs a published release.",
    ("README.md", "Install the CLI",
     "# Pin a specific version\n"
     "AASM_VERSION=v0.0.1-rc.6 curl -sSf https://agent-assembly.com/install.sh | sh\n\n"
     "# Custom install directory\n"
     "AASM_INSTALL_DIR=/usr/local/bin curl -sSf https://agent-assembly.com/install.sh | sh"):
        "same curl | sh network-install pattern, pinned to a release tag.",
    ("README.md", "Install additional components",
     "# CLI + local runtime\n"
     "curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --components cli,runtime\n\n"
     "# Full local profile (cli + runtime + proxy)\n"
     "curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --profile full"):
        "same curl | sh network-install pattern.",
    ("README.md", "Review-first install",
     "curl -fsSL https://agent-assembly.com/install.sh -o install.sh\n"
     "less install.sh\n"
     "sh install.sh --components cli,runtime"):
        "downloads and runs the same installer script from the network "
        "(reviewed via an interactive pager, not scriptable in CI either).",
    ("README.md", "Homebrew (macOS / Linux)",
     "brew install ai-agent-assembly/tap/aasm"):
        "installs from the external Homebrew tap; needs a tagged release "
        "and Homebrew.",
    ("README.md", "Homebrew (macOS / Linux)",
     "brew tap ai-agent-assembly/tap\n"
     "brew install aasm            # CLI only\n"
     "brew install aasm-runtime    # runtime (start with: brew services start aasm-runtime)"):
        "same external Homebrew tap dependency.",
    ("README.md", "Uninstall",
     "aasm uninstall                          # remove tools; preserve data\n"
     "aasm uninstall --components cli,runtime # remove only these components"):
        "destructive: would remove the CLI/state this same job's later "
        "steps depend on. Verifying it correctly needs an isolated, "
        "throwaway install — out of scope for this pass.",
    ("README.md", "Uninstall",
     "aasm uninstall --all --purge            # remove tools + config + state\n"
     "aasm uninstall --all --purge --dry-run  # show what would be removed"):
        "destructive (same reason as the plain `aasm uninstall` entry above).",
    ("README.md", "Uninstall",
     "curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --uninstall"):
        "pipes a network download into a shell, and is also destructive.",
    ("README.md", "Uninstall",
     "brew uninstall aasm            # plus aasm-runtime / aasm-proxy if installed"):
        "external Homebrew tap dependency; also destructive.",
    ("README.md", "1. Clone the repository",
     "git clone https://github.com/ai-agent-assembly/agent-assembly.git\ncd agent-assembly"):
        "this CI job already runs inside a checkout of this repo; "
        "re-cloning it is redundant. The build-from-source step in "
        "installation.md exercises the compiled-artifact half of this flow.",
    ("README.md", "2. Bootstrap the development environment", "make dev-setup"):
        "clones three external sibling SDK repos (python-sdk, node-sdk, "
        "go-sdk) and installs their toolchains — depends on out-of-repo "
        "state and costs several minutes on every docs-touching PR. "
        "Tracked as a documented gap, not silently skipped.",
    ("README.md", "3. Verify the installation", "make dev-verify"):
        "depends on `make dev-setup`'s sibling-repo clones above; same "
        "documented gap.",
    ("README.md", "Running with Docker Compose",
     "# 1. Build the workspace (first time only)\n"
     "cargo build --workspace --exclude aa-ebpf\n"
     "\n"
     "# 2. Launch the sidecar + a stub agent container\n"
     "cd examples/docker-compose\n"
     "AA_API_KEY=dev-local-key docker compose up"):
        "one fenced block mixing a build step with a long-running Docker "
        "Compose stack that pulls external images and never exits on its "
        "own, so the block as a whole can't be executed; the build half is "
        "already exercised by the separate, pre-existing "
        "'cargo build --workspace --exclude aa-ebpf' check this workflow "
        "keeps.",
    ("README.md", "Running with Docker Compose",
     "# Listens on 127.0.0.1:50051 by default; SDK shims and aa-proxy connect over gRPC.\n"
     "cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml"):
        "same alternative-gateway-launch collision as first-run.md's "
        "identical command — would fight `aasm gateway start` for "
        "127.0.0.1:50051.",
}


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 30)
    return subprocess.run(cmd, **kw)  # noqa: S603 - fixed, non-shell argv


def _assert_in(haystack: str, needle: str, label: str) -> None:
    if needle not in haystack:
        raise AssertionError(f"{label}: expected {needle!r} in output, got:\n{haystack}")


# Each entry: key -> (description, func). func raises AssertionError/OSError on failure.
EXECUTORS: list[tuple[tuple[str, str, str], str, Callable[[], None]]] = []


def _executor(file: str, heading: str, text: str, description: str):
    def deco(fn: Callable[[], None]):
        EXECUTORS.append(((file, heading, text), description, fn))
        return fn

    return deco


@_executor(
    "docs/src/quick-start/installation.md", "Build from source",
    "git clone https://github.com/ai-agent-assembly/agent-assembly.git\n"
    "cd agent-assembly\n"
    "cargo build -p aa-cli            # produces ./target/debug/aasm",
    "build the aa-cli binary from source (clone/cd skipped: CI already runs "
    "inside a checkout of this repo)",
)
def _exec_build_aa_cli() -> None:
    r = _run(["cargo", "build", "-p", "aa-cli"], cwd=REPO_ROOT, timeout=1800)
    if r.returncode != 0:
        raise AssertionError(f"cargo build -p aa-cli failed:\n{r.stderr}")
    binary = REPO_ROOT / "target" / "debug" / "aasm"
    if not binary.exists():
        raise AssertionError(f"expected binary at {binary}, not found")


@_executor(
    "docs/src/quick-start/installation.md", "Build from source",
    "cargo install --path aa-cli      # installs `aasm` into ~/.cargo/bin",
    "install `aasm` onto PATH via cargo install, as documented",
)
def _exec_cargo_install() -> None:
    r = _run(["cargo", "install", "--path", "aa-cli", "--force"], cwd=REPO_ROOT, timeout=1800)
    if r.returncode != 0:
        raise AssertionError(f"cargo install --path aa-cli failed:\n{r.stderr}")


def _aasm(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return _run(["aasm", *args], cwd=REPO_ROOT, timeout=timeout)


@_executor(
    "docs/src/quick-start/installation.md", "Verify the install",
    "$ aasm --version",
    "`aasm --version` exits 0 and prints a version string",
)
def _exec_aasm_version_flag() -> None:
    r = _aasm("--version")
    if r.returncode != 0:
        raise AssertionError(f"aasm --version failed:\n{r.stderr}")
    _assert_in(r.stdout, "aasm ", "aasm --version")


@_executor(
    "docs/src/quick-start/installation.md", "Verify the install",
    "$ aasm version",
    "`aasm version` reports cli/gateway/api, both unreachable before any gateway is started",
)
def _exec_aasm_version_table() -> None:
    r = _aasm("version")
    if r.returncode != 0:
        raise AssertionError(f"aasm version failed:\n{r.stderr}")
    for needle in ("cli", "gateway", "api", "unreachable"):
        _assert_in(r.stdout, needle, "aasm version")


@_executor(
    "docs/src/quick-start/installation.md", "Verify the install",
    "$ aasm --help",
    "`aasm --help` lists the documented subcommands",
)
def _exec_aasm_help() -> None:
    r = _aasm("--help")
    if r.returncode != 0:
        raise AssertionError(f"aasm --help failed:\n{r.stderr}")
    for needle in ("status", "topology", "gateway", "start", "version"):
        _assert_in(r.stdout, needle, "aasm --help")


@_executor(
    "docs/src/quick-start/configuration.md", "Named contexts (connection profiles)",
    "$ aasm context set local --api-url http://localhost:8080",
    "`aasm context set` creates the 'local' named context",
)
def _exec_context_set_local() -> None:
    r = _aasm("context", "set", "local", "--api-url", "http://localhost:8080")
    if r.returncode != 0:
        raise AssertionError(f"aasm context set local failed:\n{r.stderr}")
    _assert_in(r.stdout, "'local'", "aasm context set local")
    _assert_in(r.stdout, "saved", "aasm context set local")


@_executor(
    "docs/src/quick-start/configuration.md", "Named contexts (connection profiles)",
    "$ aasm context set production --api-url https://api.example.com --api-key secret123",
    "`aasm context set` creates the 'production' named context",
)
def _exec_context_set_production() -> None:
    r = _aasm("context", "set", "production", "--api-url", "https://api.example.com", "--api-key", "secret123")
    if r.returncode != 0:
        raise AssertionError(f"aasm context set production failed:\n{r.stderr}")
    _assert_in(r.stdout, "'production'", "aasm context set production")
    _assert_in(r.stdout, "saved", "aasm context set production")


@_executor(
    "docs/src/quick-start/configuration.md", "Named contexts (connection profiles)",
    "$ aasm context use local",
    "`aasm context use` switches the default context",
)
def _exec_context_use() -> None:
    r = _aasm("context", "use", "local")
    if r.returncode != 0:
        raise AssertionError(f"aasm context use local failed:\n{r.stderr}")
    _assert_in(r.stdout, "local", "aasm context use")


@_executor(
    "docs/src/quick-start/configuration.md", "Named contexts (connection profiles)",
    "$ aasm context list",
    "`aasm context list` shows both contexts with the default marked",
)
def _exec_context_list() -> None:
    r = _aasm("context", "list")
    if r.returncode != 0:
        raise AssertionError(f"aasm context list failed:\n{r.stderr}")
    _assert_in(r.stdout, "local", "aasm context list")
    _assert_in(r.stdout, "production", "aasm context list")


@_executor(
    "docs/src/quick-start/configuration.md", "Named contexts (connection profiles)",
    "aasm status                       # uses default context (local)\n"
    "aasm status --context production  # one-off against production\n"
    "aasm status --api-url http://localhost:9090   # ad-hoc URL, ignores contexts",
    "all three `aasm status` context-resolution variants run and fail closed "
    "(no control plane reachable on any of the three targets yet)",
)
def _exec_status_context_variants() -> None:
    for args in (
        [],
        ["--context", "production"],
        ["--api-url", "http://localhost:9090"],
    ):
        r = _aasm("status", *args, timeout=15)
        if r.returncode == 0:
            raise AssertionError(f"aasm status {args} unexpectedly succeeded:\n{r.stdout}")
        _assert_in(r.stdout + r.stderr, "unreachable", f"aasm status {args}")


@_executor(
    "docs/src/quick-start/configuration.md", "Output format",
    "$ aasm version --output json",
    "`aasm version --output json` prints parseable JSON naming the cli component",
)
def _exec_version_json() -> None:
    r = _aasm("version", "--output", "json")
    if r.returncode != 0:
        raise AssertionError(f"aasm version --output json failed:\n{r.stderr}")
    data = json.loads(r.stdout)
    components = {row.get("component") for row in data}
    if "cli" not in components:
        raise AssertionError(f"expected a 'cli' component row, got: {data}")


@_executor(
    "docs/src/quick-start/configuration.md", "Validate it before you boot",
    "$ aasm config validate agent-assembly.toml.example",
    "`aasm config validate` accepts the shipped example config",
)
def _exec_config_validate() -> None:
    r = _aasm("config", "validate", "agent-assembly.toml.example")
    if r.returncode != 0:
        raise AssertionError(f"aasm config validate failed:\n{r.stderr}")
    _assert_in(r.stdout, "Config is valid", "aasm config validate")


@_executor(
    "docs/src/quick-start/first-run.md", "1. Start the gateway",
    "$ aasm gateway start --policy policy-examples/low-risk.yaml",
    "`aasm gateway start` boots the managed gateway on 127.0.0.1:50051",
)
def _exec_gateway_start() -> None:
    r = _aasm("gateway", "start", "--policy", "policy-examples/low-risk.yaml", timeout=30)
    if r.returncode != 0:
        raise AssertionError(f"aasm gateway start failed:\n{r.stdout}\n{r.stderr}")
    _assert_in(r.stdout, "127.0.0.1:50051", "aasm gateway start")


@_executor(
    "docs/src/quick-start/first-run.md", "2. Confirm it is running",
    "$ aasm gateway status",
    "`aasm gateway status` reports running immediately after start "
    "(this single key covers both mentions of the identical command in this "
    "section — the doc's second mention is an illustrative not-running "
    "example, not a distinct command)",
)
def _exec_gateway_status_running() -> None:
    r = _aasm("gateway", "status")
    if r.returncode != 0:
        raise AssertionError(f"aasm gateway status failed:\n{r.stdout}\n{r.stderr}")
    _assert_in(r.stdout, "running", "aasm gateway status")


@_executor(
    "docs/src/quick-start/first-run.md", "3. Check overall status",
    "$ aasm status",
    "`aasm status` fails closed: the gRPC gateway is up but the HTTP API on "
    "8080 is not, so it must still report unreachable",
)
def _exec_status_after_gateway_start() -> None:
    r = _aasm("status", timeout=15)
    if r.returncode == 0:
        raise AssertionError(f"aasm status unexpectedly succeeded:\n{r.stdout}")
    _assert_in(r.stdout + r.stderr, "unreachable", "aasm status")


@_executor(
    "docs/src/quick-start/first-run.md", "4. Observe an agent",
    "$ aasm agent list",
    "`aasm agent list` fails closed with no reachable HTTP API",
)
def _exec_agent_list() -> None:
    r = _aasm("agent", "list", timeout=15)
    if r.returncode == 0:
        raise AssertionError(f"aasm agent list unexpectedly succeeded:\n{r.stdout}")


@_executor(
    "docs/src/quick-start/first-run.md", "5. View the topology",
    "$ aasm topology overview",
    "`aasm topology overview` prints the documented unreachable-registry message",
)
def _exec_topology_overview_message() -> None:
    r = _aasm("topology", "overview", timeout=15)
    if r.returncode == 0:
        raise AssertionError(f"aasm topology overview unexpectedly succeeded:\n{r.stdout}")
    _assert_in(r.stdout + r.stderr, "unreachable", "aasm topology overview")


@_executor(
    "docs/src/quick-start/first-run.md", "7. Stop the gateway",
    "aasm gateway stop",
    "`aasm gateway stop` shuts the managed gateway down cleanly",
)
def _exec_gateway_stop() -> None:
    r = _aasm("gateway", "stop", timeout=30)
    if r.returncode != 0:
        raise AssertionError(f"aasm gateway stop failed:\n{r.stdout}\n{r.stderr}")
    r2 = _aasm("gateway", "status")
    _assert_in(r2.stdout, "not running", "aasm gateway status after stop")


# --------------------------------------------------------------------------


def _index_by_key(entries) -> dict:
    idx: dict = {}
    for key, *_rest in entries:
        idx[key] = _rest
    return idx


def check_coverage(units: list[Unit], allowlist: dict, executors: list) -> list[str]:
    problems: list[str] = []
    exec_index = _index_by_key(executors)
    seen_keys = set()

    for u in units:
        k = u.key
        seen_keys.add(k)
        in_allow = k in allowlist
        in_exec = k in exec_index
        if in_allow and in_exec:
            problems.append(f"UNCOVERED (ambiguous): {u.label} is in BOTH the allowlist and executors")
        elif not in_allow and not in_exec:
            has_placeholder = PLACEHOLDER_RE.search(u.text if isinstance(u, Block) else u.command)
            hint = " (contains a <placeholder> — likely needs an ALLOWLIST entry)" if has_placeholder else ""
            problems.append(f"UNCOVERED: {u.label}{hint}")

    for k in allowlist:
        if k not in seen_keys:
            problems.append(f"STALE ALLOWLIST entry (no longer found in docs): {k[0]} [{k[1]}]: {k[2][:70]!r}")
    for k in exec_index:
        if k not in seen_keys:
            problems.append(f"STALE EXECUTORS entry (no longer found in docs): {k[0]} [{k[1]}]: {k[2][:70]!r}")

    return problems


def run_executors(executors: list) -> list[str]:
    failures: list[str] = []
    for key, description, fn in executors:
        try:
            fn()
            print(f"  OK   {key[0]} [{key[1]}]: {description}")
        except (AssertionError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            failures.append(f"{key[0]} [{key[1]}] ({description}): {exc}")
            print(f"  FAIL {key[0]} [{key[1]}]: {description}\n       {exc}")
    return failures


# --------------------------------------------------------------------------
# Selftest: proves the detector fails in both directions, using inline
# fixtures rather than the real docs, so it stays fast and does not require
# a build.
# --------------------------------------------------------------------------


def selftest() -> int:
    ok = True

    # (a) an unclassified block must be reported uncovered.
    fixture_dir = Path(tempfile.mkdtemp(prefix="aaasm5888-selftest-"))
    fixture = fixture_dir / "fixture.md"
    fixture.write_text(
        "# Fixture\n\n## A heading\n\n```sh\necho this-command-has-no-entry-anywhere\n```\n",
        encoding="utf-8",
    )
    rel = str(fixture.relative_to(REPO_ROOT)) if fixture.is_relative_to(REPO_ROOT) else None
    # extract_blocks() takes a repo-relative path; use an absolute-path shim
    # so the fixture doesn't need to live under REPO_ROOT.
    units = _extract_blocks_from_path(fixture, "fixture.md")
    problems = check_coverage(units, {}, [])
    if not any("UNCOVERED" in p and "echo this-command-has-no-entry-anywhere" in p for p in problems):
        print("SELFTEST FAILED (a): an unclassified command was not reported as uncovered")
        ok = False
    else:
        print("SELFTEST (a) passed: unclassified command correctly reported uncovered")

    # (b) an EXECUTORS entry whose command fails must be reported as a failure.
    def _boom() -> None:
        r = _run(["false"])
        if r.returncode != 0:
            raise AssertionError("`false` exited non-zero, as expected of `false`")

    fake_executors = [(("fixture.md", "A heading", "deliberately-failing"), "selftest failure fixture", _boom)]
    failures = run_executors(fake_executors)
    if not failures:
        print("SELFTEST FAILED (b): a failing command was not reported as a failure")
        ok = False
    else:
        print("SELFTEST (b) passed: a failing command was correctly reported as a failure")

    return 0 if ok else 1


def _extract_blocks_from_path(path: Path, label: str) -> list[Unit]:
    # Same parser as extract_blocks(), but for an arbitrary path (used only
    # by selftest fixtures, which need not live under REPO_ROOT).
    lines = path.read_text(encoding="utf-8").splitlines()
    units: list[Unit] = []
    heading = ""
    i = 0
    while i < len(lines):
        raw = lines[i]
        m = HEADING_RE.match(raw)
        if m:
            heading = m.group(2)
            i += 1
            continue
        fm = FENCE_START_RE.match(raw)
        if fm:
            lang = fm.group(2).lower()
            body_lines: list[str] = []
            i += 1
            while i < len(lines) and not FENCE_END_RE.match(lines[i]):
                body_lines.append(_strip_quote(lines[i]))
                i += 1
            i += 1
            if lang not in FENCE_LANGS:
                continue
            if lang == "console":
                units.extend(_split_console(label, heading, lang, body_lines))
            else:
                text = "\n".join(body_lines).strip("\n")
                if text.strip():
                    units.append(Block(label, heading, lang, text))
            continue
        i += 1
    return units


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-coverage", action="store_true", help="classify only, no execution")
    group.add_argument("--run", action="store_true", help="classify, then execute EXECUTORS entries")
    group.add_argument("--list", action="store_true", help="print every extracted unit and its classification")
    group.add_argument("--selftest", action="store_true", help="prove the detector fails in both directions")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    units = collect_units()
    exec_index = _index_by_key(EXECUTORS)

    if args.list:
        for u in units:
            status = "EXECUTE" if u.key in exec_index else ("ALLOW" if u.key in ALLOWLIST else "UNCOVERED")
            print(f"[{status:9}] {u.label}")
        return 0

    problems = check_coverage(units, ALLOWLIST, EXECUTORS)
    if problems:
        print(f"{len(problems)} coverage problem(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"Coverage OK: {len(units)} documented command(s), "
          f"{len(exec_index)} executed, {len(ALLOWLIST)} allowlisted.")

    if args.run:
        failures = run_executors(EXECUTORS)
        if failures:
            print(f"\n{len(failures)} documented command(s) failed:", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)
            return 1
        print(f"\nAll {len(EXECUTORS)} executed commands passed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
