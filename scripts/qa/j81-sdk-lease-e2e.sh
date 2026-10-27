#!/usr/bin/env bash
# J81 / AAASM-6259 (PR6): real Python-SDK end-to-end proof of the capability-lease gate.
#
# Drives the REAL python-sdk (llama-index FunctionTool -> LlamaIndexPatch ->
# RuntimeQueryInterceptor -> native RuntimeClient) against REAL aa-runtime
# processes running in governed mode (AA_LEASE_POLICY), so every TOOL_CALL reaches
# handle_policy_query -> PolicyLeaseGate. The tool body writes a sentinel file in a
# per-run temp dir, so "the forbidden side effect did not occur" is observed on disk,
# independently of the verdict the SDK reports. Nothing here is mocked.
#
# What it is not: the lease gate is admission control for cooperative SDK tool calls,
# not confinement (ADR 0038 sections 33, 36). This is manual local evidence, not a CI
# gate. S5d shows that relabelling a call WITH its tool context is denied; S5e shows
# the same for the omit-context relabel, which governed mode now denies because only
# TOOL_CALL can be admitted (ADR 0038 section 36). The denial reason is deliberately
# generic ("capability lease required"), so it does not identify WHICH check denied;
# the sentinel file and the positive controls are what discriminate.
#
# Usage:
#   scripts/qa/j81-sdk-lease-e2e.sh                  run all scenarios
#   scripts/qa/j81-sdk-lease-e2e.sh --mutation-check run once with the gate ABSENT
#                                                    (AA_LEASE_POLICY unset): S1 must still
#                                                    PASS and the gate scenarios must FAIL
#   scripts/qa/j81-sdk-lease-e2e.sh --ungoverned     (mutation) AA_LEASE_POLICY unset
#
# Env: J81_SDK_DIR (python-sdk checkout, default ../python-sdk), J81_AASM_BIN,
#      J81_RUNTIME_BIN (default $CARGO_TARGET_DIR/debug or ./target/debug),
#      J81_KEEP=1 (keep the temp dir).
#
# Output: a human table plus one machine-readable line per scenario
#   J81_RESULT|<id>|<PASS|FAIL|INFO>|<description>|<observed>
# and J81_SUMMARY|...; exit status is non-zero if any scenario FAILs.
set -uo pipefail

MODE=governed
MUTATION_CHECK=0
for arg in "$@"; do
  case "$arg" in
    --mutation-check) MUTATION_CHECK=1 ;;
    --ungoverned) MODE=ungoverned ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
[ "${J81_MUTATE:-}" = "ungoverned" ] && MODE=ungoverned

REPO="$(cd "$(dirname "$0")/../.." && pwd -P)"

if [ "$MUTATION_CHECK" = "1" ]; then
  # Gate-absent control only: it shows the harness notices a runtime that does not run
  # the gate. It says nothing about subtler gate defects (a wrong verdict, a lease that
  # re-grants); those are what the governed run's scenarios assert.
  out="$(mktemp)"
  trap 'rm -f "$out"' EXIT
  J81_MUTATE=ungoverned "$0" >"$out" 2>&1
  cat "$out"
  bad=0
  for id in S1a S1b S1c S1d; do
    grep -q "^J81_RESULT|$id|PASS|" "$out" || { echo "MUTATION-CHECK: positive control $id did not PASS in the mutant run" >&2; bad=1; }
  done
  for id in S2a S2b S3 S4a S4b S5a S5b1 S5b2 S5d-llm_call S5d-tool_result S5e-llm_call S5e-tool_result S6a S6b S6c2 S7b S7d1 S7e; do
    grep -q "^J81_RESULT|$id|FAIL|" "$out" || { echo "MUTATION-CHECK: scenario $id did NOT fail with the gate absent" >&2; bad=1; }
  done
  if [ "$bad" = "0" ]; then
    echo "MUTATION-CHECK: PASS (S1 passes; gate scenarios S2-S7 fail with AA_LEASE_POLICY unset)"
    exit 0
  fi
  exit 1
fi

SDK_DIR_IN="${J81_SDK_DIR:-$REPO/../python-sdk}"
SDK_DIR="$(cd "$SDK_DIR_IN" 2>/dev/null && pwd -P)" || { echo "python-sdk not found at $SDK_DIR_IN" >&2; exit 2; }
PY="$SDK_DIR/.venv/bin/python"
FIX="$REPO/scripts/qa/j81_sdk_lease_fixture.py"
TARGET_DEBUG="${CARGO_TARGET_DIR:-$REPO/target}/debug"
AASM="${J81_AASM_BIN:-$TARGET_DEBUG/aasm}"
RT="${J81_RUNTIME_BIN:-$TARGET_DEBUG/aa-runtime}"

[ -x "$PY" ] || { echo "missing $PY (run uv sync in python-sdk)" >&2; exit 2; }
[ -x "$AASM" ] || { echo "missing $AASM (cargo build -p aa-cli)" >&2; exit 2; }
[ -x "$RT" ] || { echo "missing $RT (cargo build -p aa-runtime)" >&2; exit 2; }
ls "$SDK_DIR"/agent_assembly/_core*.so >/dev/null 2>&1 \
  || { echo "python-sdk native _core is missing: build it with maturin first" >&2; exit 2; }

WORK_RAW="$(mktemp -d "${TMPDIR:-/tmp}/j81e2e.XXXXXX")" || exit 2
WORK="$(cd "$WORK_RAW" && pwd -P)"
RESULTS="$WORK/results.txt"; : >"$RESULTS"
IDS="$WORK/agent-ids.txt"; : >"$IDS"

# ------------------------------------------------------------------ cleanup --
cleanup() {
  # Only processes this script started (pid files), never a pattern match.
  for f in "$WORK"/rt-*.pid; do
    [ -e "$f" ] || continue
    p="$(cat "$f")"
    # A recycled pid must not be killed: only a live process whose command is our runtime.
    case "$(ps -p "$p" -o command= 2>/dev/null)" in
      "$RT"*) kill "$p" 2>/dev/null; sleep 0.3; kill -9 "$p" 2>/dev/null ;;
    esac
    rm -f "$f"
  done
  while read -r id; do rm -f "/tmp/aa-runtime-$id.sock"; done <"$IDS"
  [ "${J81_KEEP:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# ------------------------------------------------------------------ helpers --
run_fix() {
  # Fixture env is minimal and explicit: no gateway, no runtime-socket override,
  # never the proxy trust installer.
  env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" "$PY" "$FIX" "$@"
}

field() { # field "<RESULT line>" key
  printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1
}

free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

record() { # record ID PASS|FAIL|INFO "description" "observed"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$RESULTS"
  printf '  [%s] %-4s %s -- %s\n' "$2" "$1" "$3" "$4"
}

rt_file() { printf '%s/rt-%s.%s' "$WORK" "$1" "$2"; }
rt_port() { cat "$(rt_file "$1" port)"; }
rt_pid() { cat "$(rt_file "$1" pid)"; }

policy_file() { # policy_file PATH TTL_FS_WRITE TTL_FS_READ(or none)
  local path="$1" ttl_w="$2" ttl_r="$3"
  {
    cat <<'EOF'
tools:
  calc: { allow: true, capabilities: [none] }
  note_writer: { allow: true, capabilities: [filesystem_write] }
  note_reader: { allow: true, capabilities: [filesystem_read] }
  net_fetch: { allow: true, capabilities: [network_egress] }
  rw_net: { allow: true, capabilities: [filesystem_write, network_egress] }
  blocked_tool: { allow: false, capabilities: [none] }
authority:
  leases:
EOF
    if [ "$ttl_w" != "none" ]; then
      printf '    - domain: filesystem_write\n      scope: whole\n      ttl_seconds: %s\n      reason: j81-e2e\n' "$ttl_w"
    fi
    if [ "$ttl_r" != "none" ]; then
      printf '    - domain: filesystem_read\n      scope: whole\n      ttl_seconds: %s\n      reason: j81-e2e\n' "$ttl_r"
    fi
  } >"$path"
}

new_session() { # new_session NAME TTL_W TTL_R -> sets S_ID S_DIR S_STATE S_POLICY
  local name="$1"
  S_ID="j81-$$-$name"
  S_DIR="$WORK/$name"; mkdir -p "$S_DIR"; chmod 700 "$S_DIR"
  S_STATE="$S_DIR/lease.json"; S_POLICY="$S_DIR/policy.yaml"
  echo "$S_ID" >>"$IDS"
  policy_file "$S_POLICY" "$2" "$3"
  "$AASM" lease init --state "$S_STATE" --subject "$S_ID" --policy "$S_POLICY" >"$S_DIR/init.out" 2>&1 \
    || { echo "aasm lease init failed:"; cat "$S_DIR/init.out"; return 1; }
}

runtime_env() { # runtime_env NAME ID STATE POLICY PORT governed? -> prints env assignments
  local name="$1" id="$2" state="$3" policy="$4" port="$5"
  printf '%s\n' "AA_AGENT_ID=$id" "AA_POLICY_PATH=" "AA_METRICS_ADDR=127.0.0.1:$port" \
    "AA_AUDIT_BUFFER_PATH=$WORK/audit-$name.db" "RUST_LOG=info" "AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS=3"
  if [ "$MODE" = "governed" ]; then
    printf '%s\n' "AA_LEASE_POLICY=$policy" "AA_LEASE_STATE=$state"
  fi
}

launch_rt() { # launch_rt NAME ID STATE POLICY [keep_socket]
  local name="$1" id="$2" state="$3" policy="$4" port envs=()
  port="$(free_port)"
  [ "${5:-}" = "keep_socket" ] || rm -f "/tmp/aa-runtime-$id.sock"
  while IFS= read -r line; do envs+=("$line"); done < <(runtime_env "$name" "$id" "$state" "$policy" "$port")
  env -i PATH="$PATH" HOME="$HOME" "${envs[@]}" "$RT" >"$(rt_file "$name" log)" 2>&1 &
  echo $! >"$(rt_file "$name" pid)"
  echo "$port" >"$(rt_file "$name" port)"
}

wait_ready() { # wait_ready NAME ID -> 0 ready, 1 exited, 2 timeout
  local name="$1" id="$2" i=0
  while [ "$i" -lt 2400 ]; do
    kill -0 "$(rt_pid "$name")" 2>/dev/null || return 1
    if [ -S "/tmp/aa-runtime-$id.sock" ] \
       && curl -s --noproxy '*' --max-time 2 -o /dev/null "http://127.0.0.1:$(rt_port "$name")/health"; then
      return 0
    fi
    sleep 0.05; i=$((i + 1))
  done
  return 2
}

start_rt() { # start_rt NAME ID STATE POLICY [keep_socket]
  launch_rt "$@"
  wait_ready "$1" "$2"
  local rc=$?
  if [ "$rc" != "0" ]; then echo "runtime $1 did not become ready (rc=$rc); log:" >&2; tail -20 "$(rt_file "$1" log)" >&2; return 1; fi
}

stop_rt() { # graceful
  local p; p="$(rt_pid "$1")"
  kill "$p" 2>/dev/null
  local i=0; while kill -0 "$p" 2>/dev/null && [ "$i" -lt 300 ]; do sleep 0.05; i=$((i + 1)); done
  kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
}

do_call() { # do_call ID TOOL [ARGS_JSON] -> C_STATUS C_EXEC C_REASON (C_EXEC from files on disk)
  local id="$1" tool="$2" args="${3:-}" sd line
  # mktemp, not a counter: do_call also runs inside $(...) subshells, where a counter
  # would not advance in the parent and a later call would inherit stale sentinels.
  mkdir -p "$WORK/sentinels"; sd="$(mktemp -d "$WORK/sentinels/c.XXXXXX")"
  if [ -n "$args" ]; then
    line="$(run_fix call --agent "$id" --tool "$tool" --sentinel-dir "$sd" --args "$args" 2>"$WORK/fix.err" | grep '^RESULT ' | tail -1)"
  else
    line="$(run_fix call --agent "$id" --tool "$tool" --sentinel-dir "$sd" 2>"$WORK/fix.err" | grep '^RESULT ' | tail -1)"
  fi
  C_STATUS="$(field "$line" status)"
  C_REASON="${line#*reason=}"
  # Ground truth for the side effect is the directory, not the fixture's own report.
  C_EXEC="$(find "$sd" -type f -name '*.sentinel' | wc -l | tr -d ' ')"
  if [ -z "$line" ]; then C_STATUS=error; C_REASON="$(tail -3 "$WORK/fix.err" | tr '\n' ' ')"; fi
  if [ "$(field "$line" executed)" != "$C_EXEC" ] && [ -n "$line" ]; then
    C_REASON="$C_REASON [fixture/disk disagree: fixture=$(field "$line" executed) disk=$C_EXEC]"
    C_STATUS=inconsistent
  fi
}

GATE_REASON="capability lease required"

expect_allow() { # expect_allow ID "desc"
  if [ "$C_STATUS" = "allow" ] && [ "$C_EXEC" = "1" ]; then
    record "$1" PASS "$2" "status=allow sentinel=created"
  else
    record "$1" FAIL "$2" "status=$C_STATUS sentinel_files=$C_EXEC reason=$C_REASON"
  fi
}

expect_gate_deny() { # denied by the lease gate (not by an unreachable runtime), before execution
  case "$C_REASON" in *"$GATE_REASON"*) local from_gate=1 ;; *) local from_gate=0 ;; esac
  if [ "$C_STATUS" = "deny" ] && [ "$C_EXEC" = "0" ] && [ "$from_gate" = "1" ]; then
    record "$1" PASS "$2" "status=deny(lease gate) sentinel=absent"
  else
    record "$1" FAIL "$2" "status=$C_STATUS sentinel_files=$C_EXEC from_lease_gate=$from_gate reason=$C_REASON"
  fi
}

lease_id() { run_fix lease-id --state "$1" --domain "$2"; }
health_field() { run_fix health --url "http://127.0.0.1:$(rt_port "$1")" --field "$2" 2>/dev/null; }

# -------------------------------------------------------------------- run --
echo "J81 SDK lease-gate E2E (AAASM-6259 PR6)  mode=$MODE"
echo "  sdk=$SDK_DIR  runtime=$RT  aasm=$AASM  work=$WORK"

# Sessions: A holds fs_write + fs_read; B holds only fs_read; E is the short-TTL run.
new_session a 3600 3600 || exit 2
A_ID="$S_ID"; A_STATE="$S_STATE"; A_POLICY="$S_POLICY"
new_session b none 3600 || exit 2
B_ID="$S_ID"; B_STATE="$S_STATE"; B_POLICY="$S_POLICY"
start_rt a "$A_ID" "$A_STATE" "$A_POLICY" || exit 2
start_rt b "$B_ID" "$B_STATE" "$B_POLICY" || exit 2

echo "== S1 positive control (declared tool + valid lease) =="
do_call "$A_ID" calc;        expect_allow S1a "A: [none] tool needs no lease"
do_call "$A_ID" note_writer; expect_allow S1b "A: declared filesystem_write tool with valid lease -> ALLOW, side effect occurs"
do_call "$A_ID" note_reader; expect_allow S1c "A: declared filesystem_read tool with valid lease"
do_call "$B_ID" note_reader; expect_allow S1d "B: own session, own lease"
if awk -F'\t' '$2=="FAIL"{f=1} END{exit !f}' "$RESULTS"; then
  if [ "$MODE" = "governed" ]; then
    echo "ABORT: positive control failed; no later scenario can be trusted" >&2
    echo "J81_SUMMARY|mode=$MODE|aborted=positive_control"
    exit 1
  fi
fi

echo "== S2 AC1: undeclared / disallowed tool is denied before execution =="
do_call "$A_ID" ghost_tool;   expect_gate_deny S2a "A: tool absent from policy tools.* -> denied, no side effect"
do_call "$A_ID" blocked_tool; expect_gate_deny S2b "A: tool declared allow:false -> denied, no side effect"

echo "== S3 AC1: no lease for the declared class =="
do_call "$B_ID" note_writer; expect_gate_deny S3 "B: declares filesystem_write, B holds no filesystem_write lease -> denied"

echo "== S4 AC2: lease for X does not authorize a tool that needs Y =="
do_call "$A_ID" net_fetch; expect_gate_deny S4a "A: holds fs leases, tool needs network_egress -> denied"
do_call "$A_ID" rw_net;    expect_gate_deny S4b "A: tool needs {filesystem_write, network_egress}, only one leased -> denied (no partial cover)"

echo "== S5 spoofed capability / identity / action_type =="
SPOOF="{\"capabilities\":[\"none\",\"filesystem_write\",\"network_egress\"],\"capability\":\"none\",\"action_type\":\"llm_call\",\"agent_id\":\"$B_ID\",\"lease\":\"granted\",\"tool_source\":\"builtin\",\"requires\":[]}"
do_call "$A_ID" net_fetch "$SPOOF"; expect_gate_deny S5a "A: agent-supplied capabilities/action_type/agent_id in the call args do not authorize net_fetch"
do_call "$A_ID" Note_writer;        expect_gate_deny S5b1 "A: case-altered tool name 'Note_writer' is undeclared (exact match only)"
do_call "$A_ID" "note_writer "  ;   expect_gate_deny S5b2 "A: trailing-space tool name is undeclared (no trimming)"
do_call "$A_ID" note_writer "$SPOOF"
if [ "$C_STATUS" = "allow" ] && [ "$C_EXEC" = "1" ]; then
  record S5c1 PASS "A: spoofed args on a legitimately leased tool change nothing (verdict keyed on tool name + operator state)" "status=allow"
else
  record S5c1 FAIL "A: spoofed args on a legitimately leased tool change nothing" "status=$C_STATUS reason=$C_REASON"
fi
# Raw query_policy, no SDK wrapper, with the tool context still attached: the relabel is denied
# (ADR 0038 section 36). The omit-context form is S5e.
for at in llm_call tool_result; do
  line="$(run_fix raw --agent "$A_ID" --tool net_fetch --action-type "$at" --args '{}' 2>/dev/null | grep '^RESULT ' | tail -1)"
  st="$(field "$line" status)"
  if [ "$st" = "deny" ]; then
    record "S5d-$at" PASS "raw query_policy relabel net_fetch as $at, tool context still attached (relabel-with-context only)" "status=deny reason=${line#*reason=}"
  else
    record "S5d-$at" FAIL "raw query_policy relabel net_fetch as $at, tool context still attached" "status=$st reason=${line#*reason=}"
  fi
done
# Omit-context relabel: the native shim builds no typed context when tool_name is None, so the SDK
# CAN send this. Governed mode admits only TOOL_CALL (ADR 0038 section 36), so it must be denied.
# With the gate absent (--mutation-check) the runtime answers allow and this FAILs, as it should.
for at in llm_call tool_result; do
  line="$(run_fix raw --agent "$A_ID" --action-type "$at" 2>/dev/null | grep '^RESULT ' | tail -1)"
  st="$(field "$line" status)"
  if [ "$st" = "deny" ]; then
    record "S5e-$at" PASS "raw $at with tool_name=None (no tool context), sent by the SDK shim, is denied" "status=deny reason=${line#*reason=}"
  else
    record "S5e-$at" FAIL "raw $at with tool_name=None (no tool context), sent by the SDK shim, is denied" "status=$st reason=${line#*reason=}"
  fi
done

echo "== S8 cross-session isolation (B revokes its own lease) =="
B_READ_ID="$(lease_id "$B_STATE" filesystem_read)"
"$AASM" lease revoke --state "$B_STATE" --lease-id "$B_READ_ID" --wait-health "http://127.0.0.1:$(rt_port b)" >"$WORK/revoke-b.out" 2>&1
B_REV_RC=$?
do_call "$B_ID" note_reader; expect_gate_deny S8a "B: its revoked filesystem_read lease denies B's next call (revoke rc=$B_REV_RC)"
do_call "$A_ID" note_reader; expect_allow S8b "A: B's revocation does not leak into A (A's own lease intact)"
A_RUN="$(lease_id "$A_STATE" x | cut -d: -f3)"; B_RUN="$(lease_id "$B_STATE" x | cut -d: -f3)"
if [ "$A_ID" != "$B_ID" ] && [ "$A_STATE" != "$B_STATE" ] && [ "$A_RUN" != "$B_RUN" ] \
   && [ "$(health_field a run_id)" = "$A_RUN" ] && [ "$(health_field b run_id)" = "$B_RUN" ] \
   && [ "$(health_field a generation)" = "1" ] && [ "$(health_field b generation)" = "2" ]; then
  record S8c PASS "distinct agent id, state file, run_id; each runtime reports only its own run (A gen=1, B gen=2)" "A=$A_RUN B=$B_RUN"
else
  record S8c FAIL "session isolation of identity/state/run_id/generation" "A_run=$A_RUN/$(health_field a run_id)/g$(health_field a generation) B_run=$B_RUN/$(health_field b run_id)/g$(health_field b generation)"
fi

echo "== S6a AC3: explicit revoke --wait-health, very next call denied =="
A_W_ID="$(lease_id "$A_STATE" filesystem_write)"
"$AASM" lease revoke --state "$A_STATE" --lease-id "$A_W_ID" --wait-health "http://127.0.0.1:$(rt_port a)" >"$WORK/revoke-a.out" 2>&1
A_REV_RC=$?
do_call "$A_ID" note_writer
if [ "$A_REV_RC" = "0" ]; then expect_gate_deny S6a "A: revoke acknowledged via /health (rc=0); the VERY NEXT note_writer call is denied, no grace, no side effect"
else record S6a FAIL "A: revoke --wait-health" "rc=$A_REV_RC out=$(tr '\n' ' ' <"$WORK/revoke-a.out")"; fi
do_call "$A_ID" calc; expect_allow S6a2 "A: lease-free tool unaffected by the revocation (gate is not blanket-denying)"

echo "== S6b AC3: revoke while a client is calling continuously =="
A_R_ID="$(lease_id "$A_STATE" filesystem_read)"
mkdir -p "$WORK/sentinels/watch"
wline="$(run_fix watch --agent "$A_ID" --tool note_reader --sentinel-dir "$WORK/sentinels/watch" \
  --aasm "$AASM" --state "$A_STATE" --lease-id "$A_R_ID" --health-url "http://127.0.0.1:$(rt_port a)" \
  --revoke-after 2.0 --duration 7.0 2>"$WORK/watch.err" | grep '^RESULT ' | tail -1)"
w_rc="$(field "$wline" revoke_rc)"; w_before="$(field "$wline" allows_before_ack)"
w_after="$(field "$wline" allows_after_ack)"; w_n="$(field "$wline" calls_after_ack)"; w_ex="$(field "$wline" executed_after_ack)"
w_gate="$(field "$wline" gate_denies_after_ack)"
# The ack time is taken the instant the revoke process returns. Calls sent between the revoke write
# and that ack may be allowed by design (the reload runs every ~100 ms); only calls sent at or after
# the ack are asserted, and every one must be a gate denial.
if [ "$w_rc" = "0" ] && [ "${w_before:-0}" -gt 0 ] && [ "${w_n:-0}" -gt 0 ] && [ "$w_after" = "0" ] && [ "$w_ex" = "0" ] && [ "$w_gate" = "$w_n" ]; then
  record S6b PASS "every call sent at/after the revoke ack was a lease-gate denial with no side effect (positive control: allows before ack > 0)" "revoke_rc=$w_rc allows_before_ack=$w_before calls_after_ack=$w_n allows_after_ack=$w_after executed_after_ack=$w_ex gate_denies_after_ack=$w_gate"
else
  record S6b FAIL "continuous-call revocation" "line=${wline:-<none>} err=$(tail -2 "$WORK/watch.err" | tr '\n' ' ')"
fi

echo "== S6c AC3: short-TTL expiry denies on the next check =="
EXP_TTL=18
new_session e "$EXP_TTL" none || exit 2
E_ID="$S_ID"; E_STATE="$S_STATE"; E_POLICY="$S_POLICY"
E_ISSUED="$(lease_id "$E_STATE" filesystem_write | cut -d: -f4)"
E_EXPIRY=$((E_ISSUED + EXP_TTL))
start_rt e "$E_ID" "$E_STATE" "$E_POLICY" || exit 2
do_call "$E_ID" note_writer; expect_allow S6c1 "E: ${EXP_TTL}s lease permits before expiry (positive control)"
# Probe as soon as the wall clock reaches issued_at+ttl; the fixture's start-up adds roughly a second
# before the query is sent, so this bounds a grace period to about that, not to zero.
while [ "$(date +%s)" -lt "$E_EXPIRY" ]; do sleep 0.05; done
do_call "$E_ID" note_writer; expect_gate_deny S6c2 "E: call sent about 1s after issued_at+ttl is denied, no side effect (a grace under ~1s is not excluded here; the runtime test pins it tighter)"
sleep 2
do_call "$E_ID" note_writer; expect_gate_deny S6c2b "E: call sent about 3s after issued_at+ttl is denied, no side effect"
do_call "$E_ID" calc;        expect_allow S6c3 "E: lease-free tool still allowed after expiry"

echo "== S7 AC4: kill -9 and restart on the same state =="
declare_matrix() {
  local id="$1" out="" t
  for t in calc note_writer note_reader net_fetch ghost_tool; do
    do_call "$id" "$t"; out="$out$t=$C_STATUS/$C_EXEC;"
  done
  printf '%s' "$out"
}
GEN_BEFORE="$(health_field a generation)"
MATRIX_BEFORE="$(declare_matrix "$A_ID")"
A_PID="$(rt_pid a)"
kill -9 "$A_PID" 2>/dev/null; wait "$A_PID" 2>/dev/null
if kill -0 "$A_PID" 2>/dev/null; then record S7p FAIL "kill -9 of runtime A" "still alive"; fi
# Deliberately keep the stale socket the kill left behind: restart must cope.
start_rt a "$A_ID" "$A_STATE" "$A_POLICY" keep_socket
if [ "$?" = "0" ]; then
  MATRIX_AFTER="$(declare_matrix "$A_ID")"
  if [ "$MODE" = "governed" ] && [ "$MATRIX_BEFORE" = "$MATRIX_AFTER" ] && [ "$MATRIX_BEFORE" != "" ]; then
    record S7a PASS "decisions identical before kill -9 and after restart on the same state file" "$MATRIX_AFTER"
  else
    record S7a FAIL "decisions identical across kill -9 + restart" "before=[$MATRIX_BEFORE] after=[$MATRIX_AFTER]"
  fi
  case "$MATRIX_AFTER" in
    *"note_writer=deny/0"*"note_reader=deny/0"*) record S7b PASS "no implicit re-grant: both revoked leases (filesystem_write, filesystem_read) stay denied after restart" "$MATRIX_AFTER" ;;
    *) record S7b FAIL "no implicit re-grant of revoked leases after restart" "$MATRIX_AFTER" ;;
  esac
  if [ "$(health_field a generation)" = "$GEN_BEFORE" ] && [ "$GEN_BEFORE" = "3" ] && [ "$(health_field a run_id)" = "$A_RUN" ] \
     && [ "$(health_field a state)" = "governed" ]; then
    record S7c PASS "restarted runtime reports the SAME run_id and generation 3 (two revocations survived), state=governed" "run_id=$A_RUN gen=3"
  else
    record S7c FAIL "restart keeps run_id/generation" "gen_before=$GEN_BEFORE gen_after=$(health_field a generation) run=$(health_field a run_id)"
  fi
  do_call "$A_ID" note_writer; expect_gate_deny S7b2 "A after restart: the revoked note_writer denial is the lease gate's, not an outage"
else
  record S7a FAIL "runtime A restart after kill -9 on stale socket" "$(tail -3 "$(rt_file a log)" | tr '\n' ' ')"
fi

# Restart must not change the outcome in the other direction either: a still-valid lease keeps
# permitting, and an expired lease is not refreshed by the restart.
new_session v 3600 3600 || exit 2
V_ID="$S_ID"; V_STATE="$S_STATE"; V_POLICY="$S_POLICY"
V_RUN="$(lease_id "$V_STATE" x | cut -d: -f3)"
start_rt v "$V_ID" "$V_STATE" "$V_POLICY" || exit 2
do_call "$V_ID" note_writer; expect_allow S7h1 "V: still-valid lease permits before kill -9 (positive control)"
V_PID="$(rt_pid v)"; kill -9 "$V_PID" 2>/dev/null; wait "$V_PID" 2>/dev/null
start_rt v "$V_ID" "$V_STATE" "$V_POLICY" keep_socket || exit 2
do_call "$V_ID" note_writer; expect_allow S7h2 "V: the same still-valid lease still permits after kill -9 and restart (same run_id)"
do_call "$V_ID" ghost_tool;  expect_gate_deny S7h3 "V: undeclared tool still denied after restart"
if [ "$MODE" = "governed" ] && [ "$(health_field v run_id)" = "$V_RUN" ]; then record S7h4 PASS "V keeps its run_id across restart" "run_id=$V_RUN"
else record S7h4 FAIL "V keeps its run_id across restart" "run=$(health_field v run_id)"; fi

E_PID="$(rt_pid e)"; kill -9 "$E_PID" 2>/dev/null; wait "$E_PID" 2>/dev/null
start_rt e "$E_ID" "$E_STATE" "$E_POLICY" keep_socket || exit 2
do_call "$E_ID" note_writer; expect_gate_deny S7i1 "E: restart after expiry does not refresh the TTL (lease counts from the record's issued_at)"
do_call "$E_ID" calc;        expect_allow S7i2 "E: lease-free tool allowed after restart (positive control)"

refusal_case() { # refusal_case ID "desc" NAME  (state/policy prepared by caller in $RC_STATE/$RC_POLICY)
  local id="$1" desc="$2" name="$3" i=0 rc=""
  RC_AGENT="j81-$$-$name"; echo "$RC_AGENT" >>"$IDS"
  rm -f "/tmp/aa-runtime-$RC_AGENT.sock"
  launch_rt "$name" "$RC_AGENT" "$RC_STATE" "$RC_POLICY"
  local p; p="$(rt_pid "$name")"
  while kill -0 "$p" 2>/dev/null && [ "$i" -lt 2400 ]; do
    if curl -s --noproxy '*' --max-time 1 -o /dev/null "http://127.0.0.1:$(rt_port "$name")/health"; then break; fi
    sleep 0.05; i=$((i + 1))
  done
  if kill -0 "$p" 2>/dev/null; then
    kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
    record "$id" FAIL "$desc" "runtime STARTED (did not refuse); socket=$([ -S "/tmp/aa-runtime-$RC_AGENT.sock" ] && echo present || echo absent)"
    return
  fi
  wait "$p" 2>/dev/null; rc=$?
  if [ "$rc" = "78" ] && [ ! -S "/tmp/aa-runtime-$RC_AGENT.sock" ]; then
    record "$id" PASS "$desc" "exit=78 socket=absent"
  else
    record "$id" FAIL "$desc" "exit=$rc socket=$([ -S "/tmp/aa-runtime-$RC_AGENT.sock" ] && echo present || echo absent)"
  fi
}

# A fresh record bound to the refusal cases' own agent id (id is fixed per case name).
mk_refusal_state() { # mk_refusal_state NAME -> RC_STATE RC_POLICY with a valid record
  local name="$1"; local d="$WORK/$name"; mkdir -p "$d"; chmod 700 "$d"
  RC_STATE="$d/lease.json"; RC_POLICY="$d/policy.yaml"
  policy_file "$RC_POLICY" 3600 3600
  "$AASM" lease init --state "$RC_STATE" --subject "j81-$$-$name" --policy "$RC_POLICY" >/dev/null 2>&1
}
mk_refusal_state r1; printf 'garbage' >"$RC_STATE"
refusal_case S7d1 "corrupt state record (garbage) -> runtime refuses to start" r1
mk_refusal_state r2; head -c 40 "$RC_STATE" >"$RC_STATE.t" && cat "$RC_STATE.t" >"$RC_STATE"; rm -f "$RC_STATE.t"
refusal_case S7d2 "truncated state record -> runtime refuses to start" r2
mk_refusal_state r3; : >"$RC_STATE"
refusal_case S7d3 "empty state record -> runtime refuses to start" r3
mk_refusal_state r4; rm -f "$RC_STATE"
refusal_case S7e "missing state record -> runtime refuses to start and never creates one" r4
if [ -e "$RC_STATE" ]; then record S7e2 FAIL "missing state record was not implicitly created" "state file now exists"; else record S7e2 PASS "missing state record was not implicitly created" "absent"; fi
mk_refusal_state r5; "$AASM" lease init --state "$RC_STATE" --subject "someone-else" --policy "$RC_POLICY" --force >/dev/null 2>&1
refusal_case S7f "record for a different subject -> runtime refuses to start" r5

echo "== S7g AC4: live corruption fails closed and never heals =="
# E is the restarted, governed runtime above; its lease already expired. Use calc (needs no lease) as the sensor.
do_call "$E_ID" calc; expect_allow S7g0 "E: calc allowed before corruption (positive control)"
cp -p "$E_STATE" "$WORK/e-state.good"
printf 'garbage' >"$E_STATE"
sleep 1.5
do_call "$E_ID" calc
case "$C_REASON" in *"$GATE_REASON"*) g_gate=1 ;; *) g_gate=0 ;; esac
if [ "$C_STATUS" = "deny" ] && [ "$C_EXEC" = "0" ] && [ "$g_gate" = "1" ]; then
  record S7g1 PASS "after the state record is corrupted even a lease-free tool is denied by the gate (deny-all)" "status=deny reason=$C_REASON"
else
  record S7g1 FAIL "live corruption must fail closed with the gate's denial" "status=$C_STATUS sentinel_files=$C_EXEC from_lease_gate=$g_gate"
fi
cat "$WORK/e-state.good" >"$E_STATE"
sleep 1.5
do_call "$E_ID" calc
case "$C_REASON" in *"$GATE_REASON"*) g_gate=1 ;; *) g_gate=0 ;; esac
if [ "$C_STATUS" = "deny" ] && [ "$C_EXEC" = "0" ] && [ "$g_gate" = "1" ] && [ "$(health_field e state)" = "denied_all" ]; then
  record S7g2 PASS "restoring the original record does not heal a tripped gate (state=denied_all until restart)" "status=deny state=denied_all"
else
  record S7g2 FAIL "tripped gate must stay denied after the record is restored" "status=$C_STATUS state=$(health_field e state)"
fi

# ---------------------------------------------------------------- summary --
echo
echo "== J81 results (mode=$MODE) =="
printf '%-6s %-5s %s\n' ID RESULT DESCRIPTION
awk -F'\t' '{printf "%-6s %-5s %s\n", $1, $2, $3}' "$RESULTS"
echo
awk -F'\t' '{printf "J81_RESULT|%s|%s|%s|%s\n", $1, $2, $3, $4}' "$RESULTS"
PASS_N="$(awk -F'\t' '$2=="PASS"' "$RESULTS" | wc -l | tr -d ' ')"
FAIL_N="$(awk -F'\t' '$2=="FAIL"' "$RESULTS" | wc -l | tr -d ' ')"
INFO_N="$(awk -F'\t' '$2=="INFO"' "$RESULTS" | wc -l | tr -d ' ')"
echo "J81_SUMMARY|mode=$MODE|pass=$PASS_N|fail=$FAIL_N|info=$INFO_N"
[ "$FAIL_N" = "0" ]
