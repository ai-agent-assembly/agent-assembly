#!/bin/sh
# One-line installer for the aasm CLI.
# Usage: curl -sSf https://install.ai-agent-assembly.dev | sh
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

# ── detect platform ───────────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
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

  TARBALL="${BINARY}-${VERSION}-${ARCH}-${OS}.tar.gz"
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

  say "Installing ${BINARY} ${VERSION} (${ARCH}-${OS}) ..."

  TMP="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$TMP'" EXIT

  curl -sSfL "$URL" -o "${TMP}/${TARBALL}" \
    || err "download failed: ${URL}\n  Make sure ${VERSION} has a published release for ${ARCH}-${OS}."

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
