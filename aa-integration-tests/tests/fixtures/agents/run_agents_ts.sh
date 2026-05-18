#!/usr/bin/env bash
# run_agents_ts.sh — developer helper to run all TypeScript fixture scripts.
#
# Usage (selftest mode — no gateway required):
#   bash run_agents_ts.sh
#   bash run_agents_ts.sh --selftest
#
# Usage (real mode — gateway must be running):
#   AA_GATEWAY_ADDR=127.0.0.1:50051 bash run_agents_ts.sh
#
# The SELFTEST env-var is automatically set when AA_GATEWAY_ADDR is absent or
# --selftest is passed, so each script emits synthetic events and exits 0
# without contacting anything.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$SCRIPT_DIR/typescript"

SELFTEST_FLAG=0
for arg in "$@"; do
  case "$arg" in
    --selftest) SELFTEST_FLAG=1 ;;
  esac
done

if [[ "$SELFTEST_FLAG" -eq 1 || -z "${AA_GATEWAY_ADDR:-}" ]]; then
  export AA_SELFTEST=1
  export AA_GATEWAY_ADDR=dummy
  echo "[run_agents_ts] Running in selftest mode"
fi

export AA_AGENT_ID="${AA_AGENT_ID:-e2e-dev}"
export AA_TASK="${AA_TASK:-hello}"

SCRIPTS=(
  "single_agent/langchain_agent.ts"
  "single_agent/langgraph_agent.ts"
  "agent_team/langchain_team.ts"
  "agent_team/langgraph_team.ts"
  "root_sub_agents/langgraph_hierarchy.ts"
)

PASS=0
FAIL=0

for script in "${SCRIPTS[@]}"; do
  echo ""
  echo "==> $script"
  if (cd "$TS_DIR" && pnpm exec tsx "$script" 2>&1); then
    echo "    [PASS]"
    PASS=$((PASS + 1))
  else
    echo "    [FAIL]"
    FAIL=$((FAIL + 1))
  fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
