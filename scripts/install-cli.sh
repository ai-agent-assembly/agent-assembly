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

UNINSTALL:
  --uninstall                Remove installed Agent Assembly tools (preserves
                             your config/state/data by default).
  --uninstall --components <a,b>   Uninstall only the listed components.
  --uninstall --all --purge  Remove tools AND Agent Assembly-owned local data
                             (config + state). Prompts for confirmation.
  --uninstall --purge --dry-run    Show what a full cleanup would remove; change
                             nothing.
  -y, --yes                  Skip the purge confirmation prompt (non-interactive).

  Homebrew-managed installs are detected and left untouched — use
  `brew uninstall aasm` instead. Fallback (no `aasm` on PATH):
    curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --uninstall
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

# ── install manifest + uninstall (AAASM-3957) ─────────────────────────────────

# AA-owned local data locations (only touched by an explicit --purge).
aa_config_dir()    { echo "${AASM_CONFIG_DIR:-$HOME/.aa}"; }
aa_state_dir()     { echo "${AASM_STATE_DIR:-$HOME/.aasm}"; }
manifest_path()    { echo "$(aa_state_dir)/install-manifest"; }
uninstaller_path() { echo "$(aa_state_dir)/aasm-uninstall"; }

# Canonical installer URL, used to persist an offline uninstaller when the script
# was piped (curl | sh) and thus has no readable $0 to copy.
INSTALLER_URL="${AASM_INSTALLER_URL:-https://agent-assembly.com/install.sh}"

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown"; }

write_manifest() {
  # Record what was installed so uninstall never guesses. KEY=VALUE lines with
  # repeatable keys (component=/binary=). Merges with any existing manifest so a
  # later component install augments the record rather than replacing it.
  # Args: <install-dir> <version> <space-separated components>
  _dir="$1" _ver="$2" _comps="$3"
  _mf="$(manifest_path)"
  mkdir -p "$(dirname "$_mf")"

  _old_comps="" _created=""
  if [ -f "$_mf" ]; then
    _old_comps="$(grep '^component=' "$_mf" 2>/dev/null | cut -d= -f2- | tr '\n' ' ')"
    _created="$(grep '^created=' "$_mf" 2>/dev/null | head -1 | cut -d= -f2-)"
  fi
  [ -n "$_created" ] || _created="$(now_utc)"
  _all_comps="$(dedupe_words "$_old_comps $_comps")"
  case "$_dir" in "$HOME"/*) _mode="user" ;; *) _mode="system" ;; esac

  {
    echo "# agent-assembly install manifest v1 — managed by install.sh (AAASM-3957); do not hand-edit"
    echo "installer_source=curl"
    echo "version=${_ver}"
    echo "install_mode=${_mode}"
    echo "install_root=${_dir}"
    echo "created=${_created}"
    echo "updated=$(now_utc)"
    for _c in $_all_comps; do
      echo "component=${_c}"
      echo "binary=$(component_binary "$_c")"
    done
    echo "config_location=$(aa_config_dir)"
    echo "state_location=$(aa_state_dir)"
  } > "$_mf"
  chmod 600 "$_mf" 2>/dev/null || true
}

persist_uninstaller() {
  # Persist a runnable copy of this installer so `aasm uninstall` and offline
  # cleanup work without re-fetching. Copies $0 when it is a real file (review-
  # first `sh install.sh`), else downloads the canonical installer (piped run).
  # Best-effort: a failure here must never fail the install.
  _u="$(uninstaller_path)"
  mkdir -p "$(dirname "$_u")"
  if [ -f "$0" ] && [ -r "$0" ]; then
    cp "$0" "$_u" 2>/dev/null || { warn "could not persist uninstaller to $_u"; return 0; }
  else
    curl -fsSL "$INSTALLER_URL" -o "$_u" 2>/dev/null \
      || { warn "could not persist offline uninstaller; use: curl -fsSL $INSTALLER_URL | sh -s -- --uninstall"; return 0; }
  fi
  chmod 755 "$_u" 2>/dev/null || true
}

detect_homebrew_managed() {
  # Return 0 if <path> lives under a Homebrew prefix — then we must NOT rm it;
  # the user should `brew uninstall` instead.
  case "$1" in
    */Cellar/*|*/homebrew/*|*/Homebrew/*) return 0 ;;
  esac
  if command -v brew >/dev/null 2>&1; then
    _bp="$(brew --prefix 2>/dev/null)"
    [ -n "$_bp" ] && case "$1" in "${_bp}"/*) return 0 ;; esac
  fi
  return 1
}

remove_path() {
  # Remove <path> honoring DRY_RUN; warn (never fail) when already gone. Only
  # ever called with a manifest-recorded / AA-owned path — never a computed glob.
  _p="$1"
  if [ ! -e "$_p" ] && [ ! -L "$_p" ]; then warn "already absent: $_p"; return 0; fi
  if [ "${DRY_RUN:-0}" = "1" ]; then say "  would remove: $_p"; return 0; fi
  rm -rf "$_p" && say "  removed: $_p"
}

do_uninstall() {
  # Manifest-driven uninstall. Removes tool binaries by default; with PURGE also
  # removes AA-owned config/state. Homebrew-managed installs are redirected.
  # Globals: COMPONENTS (scope; empty = all recorded), PURGE, DRY_RUN, ASSUME_YES.
  _mf="$(manifest_path)"
  if [ ! -f "$_mf" ]; then
    warn "no install manifest at $_mf — nothing recorded to uninstall."
    warn "If you installed via Homebrew, run: brew uninstall aasm"
    return 0
  fi

  _root="$(grep '^install_root=' "$_mf" | head -1 | cut -d= -f2-)"
  _all_comps="$(grep '^component=' "$_mf" | cut -d= -f2- | tr '\n' ' ')"
  _scope="$(dedupe_words "${COMPONENTS:-$_all_comps}")"

  # Homebrew guard: never delete brew-managed files.
  if detect_homebrew_managed "${_root}/aasm"; then
    warn "aasm appears Homebrew-managed (${_root}). Not removing any files."
    warn "Use: brew uninstall aasm   (plus aasm-runtime / aasm-proxy as needed)"
    return 0
  fi

  say "Uninstalling [${_scope}] from ${_root}$( [ "${DRY_RUN:-0}" = 1 ] && printf ' (dry-run)' )..."
  for _c in $_scope; do
    remove_path "${_root}/$(component_binary "$_c")"
    # aa-gateway ships inside the cli component tarball; remove it with cli.
    [ "$_c" = "cli" ] && remove_path "${_root}/aa-gateway"
  done

  if [ "${PURGE:-0}" = "1" ]; then
    _cfg="$(grep '^config_location=' "$_mf" | head -1 | cut -d= -f2-)"
    _st="$(grep '^state_location=' "$_mf"  | head -1 | cut -d= -f2-)"
    warn "PURGE also removes Agent Assembly local data:"
    say  "  config: ${_cfg}"
    say  "  state:  ${_st}  (includes the manifest + persisted uninstaller)"
    if [ "${DRY_RUN:-0}" != "1" ] && [ "${ASSUME_YES:-0}" != "1" ]; then
      printf 'Proceed with full cleanup? [y/N] '
      read -r _ans </dev/tty 2>/dev/null || _ans=""
      case "$_ans" in y|Y|yes|YES) ;; *) err "aborted; no data removed." ;; esac
    fi
    remove_path "$_cfg"
    remove_path "$_st"
  else
    say "Preserved local data (config/state). Full cleanup: --uninstall --purge"
  fi

  # Scoped, non-purge uninstall: rewrite the manifest with the remaining
  # components, or drop it entirely when nothing is left.
  if [ "${DRY_RUN:-0}" != "1" ] && [ "${PURGE:-0}" != "1" ] && [ -n "$COMPONENTS" ]; then
    _remaining=""
    for _c in $_all_comps; do
      case " $_scope " in *" $_c "*) ;; *) _remaining="$_remaining $_c" ;; esac
    done
    _remaining="$(dedupe_words "$_remaining")"
    if [ -n "$_remaining" ]; then
      # Rewrite fresh (not merge): write_manifest unions with the existing file,
      # which would re-add the just-removed component — so drop it first.
      _ver="$(grep '^version=' "$_mf" | head -1 | cut -d= -f2-)"
      rm -f "$_mf"
      write_manifest "$_root" "$_ver" "$_remaining"
    else
      remove_path "$_mf"; remove_path "$(uninstaller_path)"
    fi
  fi
  say "Uninstall complete."
}

# ── argument parsing ──────────────────────────────────────────────────────────

COMPONENTS=""   # space-separated selection; empty means the default (cli)
UNINSTALL=0 PURGE=0 DRY_RUN=0 ASSUME_YES=0

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
      --uninstall)     UNINSTALL=1; shift ;;
      --purge)         PURGE=1; shift ;;
      --all)           shift ;;   # uninstall all components (the default scope) — accepted for explicitness
      --dry-run)       DRY_RUN=1; shift ;;
      -y|--yes)        ASSUME_YES=1; shift ;;
      -h|--help)       usage; exit 0 ;;
      *)               err "unknown option: $1 (try --help)" ;;
    esac
  done
  # Install: default to CLI-only when nothing is selected. Uninstall: an empty
  # selection means "all recorded components", so don't inject the cli default.
  if [ "$UNINSTALL" != "1" ] && [ -z "$COMPONENTS" ]; then COMPONENTS="cli"; fi
  COMPONENTS="$(dedupe_words "$COMPONENTS")"
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
  parse_args "$@"

  # Uninstall mode (AAASM-3957) needs no downloads — dispatch before requiring
  # curl/tar. The served installer thus doubles as the fallback uninstaller:
  #   curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --uninstall
  if [ "$UNINSTALL" = "1" ]; then
    do_uninstall
    return
  fi

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

  # Record the install so `aasm uninstall` never guesses which files are ours,
  # and persist an offline uninstaller (AAASM-3957). Both are best-effort.
  write_manifest "$INSTALL_DIR" "$VERSION" "$COMPONENTS"
  persist_uninstaller

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
