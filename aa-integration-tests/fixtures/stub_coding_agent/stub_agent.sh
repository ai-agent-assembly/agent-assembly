#!/bin/sh
# AAASM-6297 (ST-10) -- a deterministic STUB coding agent. It is NOT Claude
# Code, Codex, Copilot or Windsurf and no result of running it is evidence
# about any real agent; it exists only to drive the governed-launch plumbing
# (`aasm run --workspace-tx exec`) with the three things a coding agent does:
# edit a file, run a shell command, and attempt a policy-restricted action.
#
#   $1 session   label written into every artifact (cross-attribution probe)
#   $2 cacert    path to the Agent Assembly proxy CA certificate (public)
#   $3 mode      "deny"       - call allow_test, then deny_test, exit 0
#                "allow"      - call allow_test only, exit 0
#                "deny-fail"  - as "deny" but exit 7 (a failing agent run)
#
# Every observation is recorded under results/ INSIDE the workspace so it
# travels through the transaction like any real agent output would.
set -u
session="$1"
cacert="$2"
mode="$3"

# 1. file edit
echo "stub-edit-by-$session" >> src/lib.txt

# 2. shell command
printf 'built-by-%s\n' "$session" > out.txt

mkdir -p results

# 3. MCP tools/call through the governed HTTPS proxy aasm exported to us.
mcp_call() {
    tool="$1"
    status=$(curl -sS -o "results/$tool.body" -w '%{http_code}' \
        --max-time 20 \
        --proxy "$HTTPS_PROXY" --cacert "$cacert" \
        -H 'content-type: application/json' \
        -H 'accept: application/json, text/event-stream' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}" \
        "https://mcp.example.com/mcp" 2>"results/$tool.curl_err") || status="curl-failed"
    printf '%s\n' "$status" > "results/$tool.status"
}

mcp_call allow_test
case "$mode" in
    deny*) mcp_call deny_test ;;
esac
case "$mode" in
    *-fail) exit 7 ;;
esac
exit 0
