#!/bin/sh
# One-line installer for Agent Assembly components (ADR-014).
#
# Default (CLI only):
#   curl -sSf https://agent-assembly.com/install.sh | sh
#
# Select components / profiles — pass options to the SHELL, not to curl:
#   curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --components cli,runtime
#   curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --profile full
#
# Detects the host OS and CPU architecture, downloads the matching per-component
# tarball(s) plus the release SHA256SUMS (and cosign bundle when present) from the
# ai-agent-assembly GitHub Release, verifies each tarball's SHA-256 (and the
# signature on SHA256SUMS), and installs the requested component binaries into the
# install directory. It aborts if the checksum is missing/mismatched, or if any
# requested component is unavailable for the platform/version (no partial install).
#
# Flags (see --help): --component, --components, --profile, --version,
#   --install-dir, -h/--help.
#
# Environment overrides (flags take precedence):
#   AASM_INSTALL_DIR     Installation directory (default: auto / ~/.local/bin)
#   AASM_VERSION         Specific release tag to install (default: latest)
#   AASM_NO_MODIFY_PATH  Set to 1 to skip the PATH modification hint
#   AASM_REQUIRE_SIGNATURE  Set to 1 to make a missing cosign signature fatal
set -eu

REPO="ai-agent-assembly/agent-assembly"
VERSION="${AASM_VERSION:-}"
# INSTALL_DIR is resolved in main() after pick_install_dir is in scope.

# ── helpers ──────────────────────────────────────────────────────────────────

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1 — install it and retry"
}

usage() {
  cat <<'EOF'
Install the Agent Assembly components.

USAGE:
  install.sh [OPTIONS]

By default this installs the CLI only. To pass options through a piped install,
send them to the SHELL, not to curl:

  curl -fsSL https://agent-assembly.com/install.sh | sh                         # CLI only
  curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --components cli,runtime
  curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --profile full

Or review first, then run:

  curl -fsSL https://agent-assembly.com/install.sh -o install.sh
  less install.sh
  sh install.sh --components cli,runtime

OPTIONS:
  --component <name>          Install a single component (repeatable).
  --components <a,b,c>        Install a comma-separated list of components.
  --profile <name>           Install a named profile (cli | local | full).
  --version <tag>            Install a specific release tag (default: latest).
  --install-dir <path>       Install into <path> (default: auto / ~/.local/bin).
  -h, --help                 Show this help and exit.

COMPONENTS:
  cli       the `aasm` command (default)
  runtime   the local runtime daemon (aa-runtime)
  proxy     the proxy enforcement layer
  ebpf      the eBPF component (supported Linux platforms only)

PROFILES:
  cli       cli
  local     cli,runtime
  full      cli,runtime,proxy   (ebpf only where explicitly supported)

Note: installing `runtime` does NOT start it. Start it yourself afterwards.
EOF
}

pick_install_dir() {
  # Choose install dir based on write permission:
  #   1. /usr/local/bin if it (or its parent) is writable to the current user
  #   2. otherwise ~/.local/bin (always user-writable, no sudo needed)
  # AASM_INSTALL_DIR (if set) overrides this entirely; see main().
  if [ -w /usr/local/bin ] 2>/dev/null; then
    echo "/usr/local/bin"
  elif [ ! -e /usr/local/bin ] && [ -w /usr/local ] 2>/dev/null; then
    echo "/usr/local/bin"
  else
    echo "${HOME}/.local/bin"
  fi
}

# ── detect platform ───────────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "apple-darwin" ;;
    Linux)  echo "unknown-linux-gnu" ;;
    *)      err "unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "x86_64" ;;
    arm64|aarch64)  echo "aarch64" ;;
    *)              err "unsupported architecture: $(uname -m)" ;;
  esac
}

# Short OS/arch tokens for component-aware artifact names (ADR-014):
# component artifacts are named aasm-<component>-<version>-<os>-<arch>.tar.gz,
# e.g. aasm-runtime-v1.2.3-darwin-arm64.tar.gz. The CLI keeps its legacy
# target-triple name for backward compatibility (see component_artifact()).
detect_os_short() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux)  echo "linux" ;;
    *)      err "unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch_short() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "amd64" ;;
    arm64|aarch64)  echo "arm64" ;;
    *)              err "unsupported architecture: $(uname -m)" ;;
  esac
}

# ── component model (ADR-014) ─────────────────────────────────────────────────

# Space-separated list of installable components. `cli` is the default and is the
# only component installed when no --component/--components/--profile is given.
VALID_COMPONENTS="cli runtime proxy ebpf"

is_valid_component() {
  case " ${VALID_COMPONENTS} " in
    *" $1 "*) return 0 ;;
    *)        return 1 ;;
  esac
}

resolve_profile() {
  # Expand a profile name to its space-separated component list.
  case "$1" in
    cli)   echo "cli" ;;
    local) echo "cli runtime" ;;
    full)  echo "cli runtime proxy" ;;   # ebpf added only where explicitly supported
    *)     err "unknown profile: $1 (valid: cli, local, full)" ;;
  esac
}

component_binary() {
  # The binary name a component ships inside its tarball.
  case "$1" in
    cli)     echo "aasm" ;;
    runtime) echo "aa-runtime" ;;
    proxy)   echo "aa-proxy" ;;
    ebpf)    echo "aa-ebpf" ;;
    *)       err "unknown component: $1 (valid: ${VALID_COMPONENTS})" ;;
  esac
}

component_artifact() {
  # Resolve the release artifact basename for <component> at <version>.
  # `cli` keeps the legacy target-triple name so existing installs keep working
  # until the component-aware CLI artifact ships (AAASM-3951); every other
  # component uses the ADR-014 aasm-<component>-<version>-<os>-<arch> scheme.
  component="$1" version="$2"
  case "$component" in
    cli)
      echo "aasm-$(detect_arch)-$(detect_os).tar.gz"
      ;;
    runtime|proxy|ebpf)
      echo "aasm-${component}-${version}-$(detect_os_short)-$(detect_arch_short).tar.gz"
      ;;
    *)
      err "unknown component: $component (valid: ${VALID_COMPONENTS})"
      ;;
  esac
}

assert_component_supported() {
  # Fail fast on component/platform combinations we do not ship.
  # eBPF is Linux-only kernel instrumentation (ADR-014, ebpf non-goal on macOS).
  case "$1" in
    ebpf)
      [ "$(detect_os_short)" = "linux" ] || \
        err "component 'ebpf' is Linux-only and is not available on $(uname -s)."
      ;;
  esac
}

# ── sha256 ─────────────────────────────────────────────────────────────────────

sha256_compute() {
  # Print the lowercase hex SHA-256 of a file path.
  # Uses sha256sum (Linux) or shasum -a 256 (macOS).
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    err "no sha256 tool available (need sha256sum or shasum)"
  fi
}

sha256_verify() {
  # Verify <tarball> against an entry in <sums_file>.
  # SHA256SUMS lines are "<hash>  <filename>"; lookup is by basename.
  local tarball="$1" sums_file="$2"
  local fname expected actual
  fname=$(basename "$tarball")
  expected=$(awk -v t="$fname" '$2==t || $2=="*"t {print $1; exit}' "$sums_file")
  [ -n "$expected" ] || err "no SHA256 entry for ${fname} in SHA256SUMS"
  actual=$(sha256_compute "$tarball")
  if [ "$expected" != "$actual" ]; then
    err "SHA256 mismatch for ${fname}
  expected: ${expected}
    actual: ${actual}"
  fi
  say "SHA256 verified."
}

# ── cosign signature verification ─────────────────────────────────────────────

# Expected signer: the agent-assembly release workflow, signed keyless via GitHub
# OIDC (Fulcio cert + Rekor log). `(?i)` keeps the org/repo match case-insensitive.
COSIGN_IDENTITY_RE='(?i)^https://github\.com/ai-agent-assembly/agent-assembly/\.github/workflows/release\.yml@refs/tags/v.*$'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

verify_signature() {
  # Verify <sums_file> against the cosign <bundle>. Honors AASM_REQUIRE_SIGNATURE:
  # when 1, a missing cosign or missing bundle is fatal; otherwise it warns and
  # falls back to checksum-only (the SHA-256 check below is always enforced).
  sums_file="$1" bundle="$2"
  require="${AASM_REQUIRE_SIGNATURE:-0}"

  if [ ! -f "$bundle" ]; then
    [ "$require" = "1" ] && err "AASM_REQUIRE_SIGNATURE=1 but this release has no cosign bundle."
    warn "no cosign bundle for this release — skipping signature check (checksum still enforced)."
    return 0
  fi

  if ! command -v cosign >/dev/null 2>&1; then
    [ "$require" = "1" ] && err "AASM_REQUIRE_SIGNATURE=1 but cosign is not installed.
  Install it: https://docs.sigstore.dev/cosign/system_config/installation/"
    warn "cosign not installed — skipping signature verification (checksum still enforced)."
    warn "For full supply-chain verification install cosign, or set AASM_REQUIRE_SIGNATURE=1."
    return 0
  fi

  if cosign verify-blob \
      --bundle "$bundle" \
      --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$sums_file" >/dev/null 2>&1; then
    say "Cosign signature verified."
  else
    err "cosign signature verification FAILED for SHA256SUMS — refusing to install."
  fi
}

# ── fetch latest release tag ──────────────────────────────────────────────────

latest_release() {
  need curl
  # Prefer the latest stable (non-prerelease) release. Stderr is silenced because a
  # 404 here is expected (and benign) when no stable release exists yet — see fallback.
  tag=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
  # Fall back to the newest release overall when no stable release exists yet:
  # the 0.0.1 series ships entirely as pre-releases, which /releases/latest skips
  # (it 404s when every release is a pre-release), so resolve the newest from the list.
  if [ -z "$tag" ]; then
    tag=$(curl -sSf "https://api.github.com/repos/${REPO}/releases?per_page=1" \
      | grep '"tag_name"' | head -1 | cut -d'"' -f4)
  fi
  [ -n "$tag" ] || err "could not determine latest release — does ${REPO} have a published release?"
  echo "$tag"
}

# ── per-component install ─────────────────────────────────────────────────────

check_artifact_available() {
  # HEAD-check that <url> exists so a multi-component install fails up front
  # rather than half-way through (no partial, silent success — ADR-014).
  curl -fsIL -o /dev/null "$1" 2>/dev/null
}

install_component() {
  # Download, checksum-verify, extract, and install one component's binary.
  # Args: <component> <version> <tmp-dir> <sums-file> <install-dir>
  comp="$1" cver="$2" tmp="$3" sums="$4" dir="$5"
  artifact="$(component_artifact "$comp" "$cver")"
  bin="$(component_binary "$comp")"
  url="https://github.com/${REPO}/releases/download/${cver}/${artifact}"

  curl -sSfL "$url" -o "${tmp}/${artifact}" \
    || err "download failed for component '${comp}': ${url}"
  sha256_verify "${tmp}/${artifact}" "$sums"
  tar -C "$tmp" -xzf "${tmp}/${artifact}" "$bin" \
    || err "failed to extract ${bin} from ${artifact}"
  mkdir -p "$dir"
  install -m755 "${tmp}/${bin}" "${dir}/${bin}"
  say "Installed: ${dir}/${bin}"

  # Component-specific next steps. Runtime is never auto-started (ADR-014).
  case "$comp" in
    runtime) say "  Runtime installed but NOT started. Start it with:  ${bin} --help" ;;
  esac
}

# ── argument parsing ──────────────────────────────────────────────────────────

COMPONENTS=""   # space-separated selection; empty means the default (cli)

add_components() {
  # Append the components in $1 (comma- or space-separated) to COMPONENTS,
  # validating each against VALID_COMPONENTS.
  for _c in $(echo "$1" | tr ',' ' '); do
    is_valid_component "$_c" || err "unknown component: '$_c' (valid: ${VALID_COMPONENTS})"
    COMPONENTS="${COMPONENTS} $_c"
  done
}

dedupe_words() {
  # Echo unique space-separated words, preserving first-seen order.
  _seen=""
  for _w in $1; do
    case " $_seen " in *" $_w "*) ;; *) _seen="${_seen} $_w" ;; esac
  done
  echo "${_seen# }"
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --component)     [ $# -ge 2 ] || err "--component needs a value"; add_components "$2"; shift 2 ;;
      --component=*)   add_components "${1#*=}"; shift ;;
      --components)    [ $# -ge 2 ] || err "--components needs a value"; add_components "$2"; shift 2 ;;
      --components=*)  add_components "${1#*=}"; shift ;;
      --profile)       [ $# -ge 2 ] || err "--profile needs a value"; _p="$(resolve_profile "$2")" || exit $?; add_components "$_p"; shift 2 ;;
      --profile=*)     _p="$(resolve_profile "${1#*=}")" || exit $?; add_components "$_p"; shift ;;
      --version)       [ $# -ge 2 ] || err "--version needs a value"; VERSION="$2"; shift 2 ;;
      --version=*)     VERSION="${1#*=}"; shift ;;
      --install-dir)   [ $# -ge 2 ] || err "--install-dir needs a value"; AASM_INSTALL_DIR="$2"; shift 2 ;;
      --install-dir=*) AASM_INSTALL_DIR="${1#*=}"; shift ;;
      -h|--help)       usage; exit 0 ;;
      *)               err "unknown option: $1 (try --help)" ;;
    esac
  done
  # Default to CLI-only when nothing is selected; then dedupe.
  [ -n "$COMPONENTS" ] || COMPONENTS="cli"
  COMPONENTS="$(dedupe_words "$COMPONENTS")"
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
  parse_args "$@"
  need curl
  need tar

  INSTALL_DIR="${AASM_INSTALL_DIR:-$(pick_install_dir)}"

  if [ -z "$VERSION" ]; then
    say "Fetching latest release ..."
    VERSION="$(latest_release)"
  fi

  # Fail fast on unsupported component/platform combinations before any download.
  for comp in $COMPONENTS; do
    assert_component_supported "$comp"
  done

  TMP="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$TMP'" EXIT

  SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"
  SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS.cosign.bundle"

  curl -sSfL "$SUMS_URL" -o "${TMP}/SHA256SUMS" \
    || err "SHA256SUMS download failed: ${SUMS_URL}\n  Refusing to install without checksum verification."
  # Best-effort fetch of the cosign bundle (releases before AAASM-2700 lack one).
  curl -sSfL "$SIG_URL" -o "${TMP}/SHA256SUMS.cosign.bundle" 2>/dev/null || true
  verify_signature "${TMP}/SHA256SUMS" "${TMP}/SHA256SUMS.cosign.bundle"

  # Preflight: every requested artifact must exist before we install anything.
  for comp in $COMPONENTS; do
    artifact="$(component_artifact "$comp" "$VERSION")"
    check_artifact_available "https://github.com/${REPO}/releases/download/${VERSION}/${artifact}" \
      || err "component '${comp}' is not published for ${VERSION} (${artifact} not found)."
  done

  say "Installing [${COMPONENTS}] ${VERSION} ($(detect_arch)-$(detect_os)) into ${INSTALL_DIR} ..."
  for comp in $COMPONENTS; do
    install_component "$comp" "$VERSION" "$TMP" "${TMP}/SHA256SUMS" "$INSTALL_DIR"
  done

  # PATH hint (shown once).
  case ":${PATH}:" in
    *:"${INSTALL_DIR}":*) ;;
    *)
      if [ "${AASM_NO_MODIFY_PATH:-0}" != "1" ]; then
        warn "${INSTALL_DIR} is not in your PATH."
        warn "Add the following to your shell profile:"
        warn "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      fi
      ;;
  esac

  # Print the CLI version when the CLI was part of the install.
  case " $COMPONENTS " in
    *" cli "*) "${INSTALL_DIR}/aasm" --version ;;
  esac
}

# Run the installer unless sourced for tests (bats sets AASM_LIB=1 to load the
# functions without executing main).
[ "${AASM_LIB:-0}" = "1" ] || main "$@"
