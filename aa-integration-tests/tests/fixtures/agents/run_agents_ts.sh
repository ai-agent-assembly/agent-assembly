#!/usr/bin/env bash
# run_agents_ts.sh — developer helper to run TypeScript fixture scripts.
#
# Usage (selftest mode — no gateway required):
#   bash run_agents_ts.sh
#   bash run_agents_ts.sh --selftest
#
# Usage (filter scripts):
#   bash run_agents_ts.sh --list
#   bash run_agents_ts.sh --framework langchain
#   bash run_agents_ts.sh --scenario single_agent
#   bash run_agents_ts.sh --file "*hierarchy*"
#
# Usage (run options):
#   bash run_agents_ts.sh --parallel --verbose
#
# Usage (real mode — supply a running gateway):
#   AA_GATEWAY_ADDR=127.0.0.1:50051 bash run_agents_ts.sh
#
# Usage (auto-start gateway from workspace build):
#   bash run_agents_ts.sh --auto-gateway [--scenario single_agent]
#
# The AA_SELFTEST env-var is automatically set when AA_GATEWAY_ADDR is absent
# and --auto-gateway is not passed, so each script emits synthetic events and
# exits 0 without contacting anything.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$SCRIPT_DIR/typescript"

# ── Argument parsing ───────────────────────────────────────────────────────
SELFTEST_FLAG=0
LIST_FLAG=0
PARALLEL_FLAG=0
VERBOSE_FLAG=0
AUTO_GATEWAY_FLAG=0
FILTER_FRAMEWORK=""
FILTER_SCENARIO=""
FILTER_FILE_GLOB=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --selftest)      SELFTEST_FLAG=1 ;;
    --list)          LIST_FLAG=1 ;;
    --parallel)      PARALLEL_FLAG=1 ;;
    --verbose)       VERBOSE_FLAG=1 ;;
    --auto-gateway)  AUTO_GATEWAY_FLAG=1 ;;
    --framework)     shift; FILTER_FRAMEWORK="$1" ;;
    --scenario)      shift; FILTER_SCENARIO="$1" ;;
    --file)          shift; FILTER_FILE_GLOB="$1" ;;
    -h|--help)
      sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "error: unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

# ── Script discovery ───────────────────────────────────────────────────────
# Discover *.ts files under typescript/, excluding _shared.ts and node_modules.
DISCOVERED=()
while IFS= read -r -d '' f; do
  rel="${f#$TS_DIR/}"
  DISCOVERED+=("$rel")
done < <(find "$TS_DIR" -name "*.ts" ! -name "_shared.ts" \
           -not -path "*/node_modules/*" -print0 | sort -z)

# ── Filtering ──────────────────────────────────────────────────────────────
SCRIPTS=()
for script in "${DISCOVERED[@]}"; do
  scenario="$(dirname "$script")"
  stem="$(basename "$script" .ts)"
  framework="${stem%%_*}"

  [[ -n "$FILTER_FRAMEWORK" && "$framework" != "$FILTER_FRAMEWORK" ]] && continue
  [[ -n "$FILTER_SCENARIO"  && "$scenario"  != "$FILTER_SCENARIO"  ]] && continue
  if [[ -n "$FILTER_FILE_GLOB" ]]; then
    # shellcheck disable=SC2254
    case "$(basename "$script")" in $FILTER_FILE_GLOB) ;; *) continue ;; esac
  fi

  SCRIPTS+=("$script")
done

if [[ "${#SCRIPTS[@]}" -eq 0 ]]; then
  echo "[run_agents_ts] No matching scripts found." >&2
  exit 1
fi

# ── --list ─────────────────────────────────────────────────────────────────
if [[ "$LIST_FLAG" -eq 1 ]]; then
  printf "  %-14s  %-24s  %s\n" "FRAMEWORK" "SCENARIO" "PATH"
  printf "  %-14s  %-24s  %s\n" "---------" "--------" "----"
  for script in "${SCRIPTS[@]}"; do
    scenario="$(dirname "$script")"
    stem="$(basename "$script" .ts)"
    framework="${stem%%_*}"
    printf "  %-14s  %-24s  %s\n" "$framework" "$scenario" "$script"
  done
  exit 0
fi

# ── --auto-gateway ─────────────────────────────────────────────────────────
GATEWAY_PID=""
if [[ "$AUTO_GATEWAY_FLAG" -eq 1 ]]; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
  GATEWAY_BIN=""
  for candidate in \
      "$REPO_ROOT/target/debug/aa-gateway" \
      "$REPO_ROOT/target/release/aa-gateway"; do
    if [[ -x "$candidate" ]]; then
      GATEWAY_BIN="$candidate"
      break
    fi
  done

  if [[ -z "$GATEWAY_BIN" ]]; then
    echo "[run_agents_ts] Building aa-gateway (cargo build -p aa-gateway)..." >&2
    (cd "$REPO_ROOT" && cargo build -p aa-gateway 2>&1) >&2
    GATEWAY_BIN="$REPO_ROOT/target/debug/aa-gateway"
  fi

  # Write an inline allow-all policy to a temp file.
  POLICY_FILE="$(mktemp /tmp/aa-allow-all-XXXXXX.yaml)"
  cat > "$POLICY_FILE" <<'YAML'
version: "1"
global:
  default_action: allow
YAML

  # Pick a free TCP port.
  FREE_PORT="$(python3 -c \
    "import socket; s=socket.socket(); s.bind(('',0)); \
     p=s.getsockname()[1]; s.close(); print(p)")"

  export AA_GATEWAY_ADDR="127.0.0.1:$FREE_PORT"
  "$GATEWAY_BIN" --policy "$POLICY_FILE" --listen "$AA_GATEWAY_ADDR" \
    >/tmp/aa-gateway.log 2>&1 &
  GATEWAY_PID=$!
  echo "[run_agents_ts] Gateway started on $AA_GATEWAY_ADDR (PID $GATEWAY_PID)"
  sleep 1  # allow gateway to finish binding

  # shellcheck disable=SC2064
  trap "kill '$GATEWAY_PID' 2>/dev/null; rm -f '$POLICY_FILE'" EXIT
fi

# ── Selftest mode ──────────────────────────────────────────────────────────
if [[ "$SELFTEST_FLAG" -eq 1 ]] || \
   [[ -z "${AA_GATEWAY_ADDR:-}" && "$AUTO_GATEWAY_FLAG" -eq 0 ]]; then
  export AA_SELFTEST=1
  export AA_GATEWAY_ADDR="${AA_GATEWAY_ADDR:-dummy}"
  echo "[run_agents_ts] Running in selftest mode"
fi

export AA_AGENT_ID="${AA_AGENT_ID:-e2e-dev}"
export AA_TASK="${AA_TASK:-hello}"

# ── Execution helpers ──────────────────────────────────────────────────────
_run_one() {
  local script="$1"
  local scenario stem framework label
  scenario="$(dirname "$script")"
  stem="$(basename "$script" .ts)"
  framework="${stem%%_*}"
  label="[$framework / $scenario]"

  if [[ "$VERBOSE_FLAG" -eq 1 ]]; then
    echo ""
    echo "==> $label $script"
  else
    echo ""
    echo "==> $script"
  fi

  (cd "$TS_DIR" && pnpm exec tsx "$script" 2>&1)
}

# ── Run scripts ────────────────────────────────────────────────────────────
PASS=0
FAIL=0

if [[ "$PARALLEL_FLAG" -eq 1 ]]; then
  TMPDIR_P="$(mktemp -d)"
  PIDS=()
  IDX=0
  for script in "${SCRIPTS[@]}"; do
    tmpout="$TMPDIR_P/$IDX.out"
    ( _run_one "$script"; echo $? ) > "$tmpout" 2>&1 &
    PIDS+=($!)
    IDX=$((IDX + 1))
  done

  IDX=0
  for script in "${SCRIPTS[@]}"; do
    wait "${PIDS[$IDX]}" 2>/dev/null || true
    tmpout="$TMPDIR_P/$IDX.out"
    line_count="$(wc -l < "$tmpout")"
    head -n $((line_count - 1)) "$tmpout"
    rc="$(tail -n 1 "$tmpout")"
    if [[ "$rc" -eq 0 ]]; then
      echo "    [PASS]"
      PASS=$((PASS + 1))
    else
      echo "    [FAIL]"
      FAIL=$((FAIL + 1))
    fi
    IDX=$((IDX + 1))
  done
  rm -rf "$TMPDIR_P"
else
  for script in "${SCRIPTS[@]}"; do
    if _run_one "$script"; then
      echo "    [PASS]"
      PASS=$((PASS + 1))
    else
      echo "    [FAIL]"
      FAIL=$((FAIL + 1))
    fi
  done
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
