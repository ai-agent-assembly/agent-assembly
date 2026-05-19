#!/usr/bin/env bash
# run.sh — developer helper to run Python agent fixture scripts against aasm.
#
# Sibling of run_agents_ts.sh; thin uv wrapper around python/run_agents.py.
#
# Usage examples:
#   ./run.sh --list                                              # dry-run list
#   ./run.sh --framework langchain                               # filter by framework
#   ./run.sh --scenario single_agent                             # filter by scenario
#   ./run.sh --file "*hierarchy*"                                # glob filter
#   ./run.sh --framework langgraph --scenario root_sub_agents    # intersection
#   ./run.sh --parallel --verbose                                # parallel + verbose
#   ./run.sh --auto-gateway --framework langchain                # auto-start gateway
#   ./run.sh --selftest                                          # hermetic smoke
#   ./run.sh --proxy-addr 127.0.0.1:8081 --scenario single_agent # Layer 2 test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR/python"

if ! command -v uv &>/dev/null; then
  echo "error: uv is required. Install: curl -Ls https://astral.sh/uv/install.sh | sh" >&2
  exit 1
fi

cd "$PYTHON_DIR"
exec uv run --extra runner --extra all run_agents.py "$@"
