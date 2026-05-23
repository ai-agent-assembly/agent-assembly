#!/bin/sh
# One-line installer for the aasm CLI.
# Usage: curl -fsSL https://get.agent-assembly.io | sh
#
# Detects the host OS and CPU architecture, downloads the matching
# pre-built tarball plus its SHA256SUMS file from the AI-agent-assembly
# GitHub Release, verifies the tarball's SHA-256 against SHA256SUMS, and
# extracts the binary into ${AASM_INSTALL_DIR}. The install aborts if
# the checksum cannot be downloaded or does not match.
#
# Environment overrides:
#   AASM_INSTALL_DIR   Installation directory (default: ~/.local/bin)
#   AASM_VERSION       Specific release tag to install (default: latest)
#   AASM_NO_MODIFY_PATH  Set to 1 to skip PATH modification hint
set -eu

REPO="AI-agent-assembly/agent-assembly"
BINARY="aasm"
INSTALL_DIR="${AASM_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${AASM_VERSION:-}"

# ── helpers ──────────────────────────────────────────────────────────────────

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1 — install it and retry"
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

# ── fetch latest release tag ──────────────────────────────────────────────────

latest_release() {
  need curl
  tag=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
  [ -n "$tag" ] || err "could not determine latest release — does ${REPO} have a published release?"
  echo "$tag"
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
  need curl
  need tar

  OS="$(detect_os)"
  ARCH="$(detect_arch)"

  if [ -z "$VERSION" ]; then
    say "Fetching latest release ..."
    VERSION="$(latest_release)"
  fi

  TARBALL="${BINARY}-${ARCH}-${OS}.tar.gz"
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
  SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"

  say "Installing ${BINARY} ${VERSION} (${ARCH}-${OS}) ..."

  TMP="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$TMP'" EXIT

  curl -sSfL "$URL" -o "${TMP}/${TARBALL}" \
    || err "download failed: ${URL}\n  Make sure ${VERSION} has a published release for ${ARCH}-${OS}."

  curl -sSfL "$SUMS_URL" -o "${TMP}/SHA256SUMS" \
    || err "SHA256SUMS download failed: ${SUMS_URL}\n  Refusing to install without checksum verification."

  sha256_verify "${TMP}/${TARBALL}" "${TMP}/SHA256SUMS"

  tar -C "$TMP" -xzf "${TMP}/${TARBALL}" "${BINARY}" \
    || err "failed to extract ${BINARY} from ${TARBALL}"

  mkdir -p "$INSTALL_DIR"
  install -m755 "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

  say "Installed: ${INSTALL_DIR}/${BINARY}"

  # PATH hint
  case ":${PATH}:" in
    *:"${INSTALL_DIR}":*) ;;
    *)
      if [ "${AASM_NO_MODIFY_PATH:-0}" != "1" ]; then
        warn "${INSTALL_DIR} is not in your PATH."
        warn "Add the following to your shell profile:"
        warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
      fi
      ;;
  esac

  "${INSTALL_DIR}/${BINARY}" --version
}

main "$@"
