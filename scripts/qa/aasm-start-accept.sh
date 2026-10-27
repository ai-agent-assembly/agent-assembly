#!/usr/bin/env bash
# AAASM-6385: acceptance of the `aasm start` Server line and mismatch warning, driving a real
# aasm against the real aa-api-server and against stub servers that return hostile or broken
# health answers. Manual local evidence, not a CI gate.
#
# Usage: scripts/qa/aasm-start-accept.sh <dir with aasm + aa-api-server> <label for the log>
# Env:   ACCEPT_OUT (default: a fresh temp dir), RC6_SERVER (default /opt/homebrew/bin/aa-api-server;
#        the stale-version case is skipped when it is absent).
set -u
T="$1"; SHA="$2"
Q="$(cd "$(dirname "$0")" && pwd -P)"; OUT="${ACCEPT_OUT:-$(mktemp -d)}"; mkdir -p "$OUT"; echo "evidence dir: $OUT"
KEY=aa_0123456789abcdef0123456789abcdef
RC6="${RC6_SERVER:-/opt/homebrew/bin/aa-api-server}"
pass=0; fail=0
ok(){ echo "PASS $1"; pass=$((pass+1)); }
ko(){ echo "FAIL $1 :: $2"; fail=$((fail+1)); }
port(){ python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
now(){ python3 -c 'import time;print(time.time())'; }
# $1 name  $2 bin dir holding aasm (+ optional server)  $3 extra PATH  [env VAR=val ...]
run_start(){
  name=$1; bindir=$2; extra=$3; shift 3
  H="$OUT/$name.home"; mkdir -p "$H"; P=$(port)
  s=$(now)
  env -i HOME="$H" TMPDIR="$OUT" PATH="$bindir:$extra:/usr/bin:/bin" AASM_API_KEY=$KEY "$@" "$bindir/aasm" start --host 127.0.0.1 --port "$P" >"$OUT/$name.out" 2>"$OUT/$name.err"
  RC=$?; e=$(now); ELAPSED=$(python3 -c "print(round($e-$s,2))"); PORT=$P; HOME_=$H; BIN=$bindir; EXTRA=$extra
}
stop(){ env -i HOME="$1" TMPDIR="$OUT" PATH="$2:/usr/bin:/bin" "$2/aasm" stop >/dev/null 2>&1; }
alive_pid(){ cat "$1/.aasm/gateway.pid" 2>/dev/null; }
echo "pinned main: $SHA"
mkdir -p "$OUT/real/bin" "$OUT/stale/bin"; cp "$T/aasm" "$T/aa-api-server" "$OUT/real/bin/"; cp "$T/aasm" "$OUT/stale/bin/"
CLIV=$("$T/aasm" --version 2>/dev/null | awk '{print $NF}'); echo "aasm version: $CLIV"

# 1 matching sibling
run_start match "$OUT/real/bin" ""
pid=$(alive_pid "$HOME_")
[ $RC -eq 0 ] && /usr/bin/grep -q "Server:  aa-api-server $CLIV from $OUT/real/bin/aa-api-server" "$OUT/match.out" && ! /usr/bin/grep -qi warning "$OUT/match.err" "$OUT/match.out" && ok "matching versions: Server line with version and resolved path, no warning" || ko matching "rc=$RC $(cat $OUT/match.out $OUT/match.err | tr '\n' '|')"
[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && ok "lifecycle: daemon alive after start+probe, aasm exited rc=0 in ${ELAPSED}s" || ko lifecycle-alive "pid=$pid"
# 8 already running (same home/port)
env -i HOME="$HOME_" TMPDIR="$OUT" PATH="$OUT/real/bin:/usr/bin:/bin" AASM_API_KEY=$KEY "$OUT/real/bin/aasm" start --host 127.0.0.1 --port "$PORT" >"$OUT/again.out" 2>"$OUT/again.err"; rc2=$?
[ $rc2 -eq 0 ] && /usr/bin/grep -qi 'already running' "$OUT/again.out" && ! /usr/bin/grep -q 'Server:' "$OUT/again.out" && [ "$(alive_pid "$HOME_")" = "$pid" ] && ok "already-running: reports it, no Server line, same PID, rc=0" || ko already-running "rc=$rc2 $(cat $OUT/again.out | tr '\n' '|')"
stop "$HOME_" "$OUT/real/bin"; sleep 1
kill -0 "$pid" 2>/dev/null && ko lifecycle-stop "pid $pid still alive after aasm stop" || ok "lifecycle: aasm stop ends the daemon"

# 2 mismatch with the installed rc.6 server (only reachable via PATH)
if [ -x "$RC6" ]; then
  run_start stale "$OUT/stale/bin" "$(dirname "$RC6")"
  RC6V=$(curl -s -m2 "http://localhost:$PORT/api/v1/health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["version"])' 2>/dev/null)
  [ $RC -eq 0 ] && /usr/bin/grep -q "Server:  aa-api-server $RC6V from $RC6" "$OUT/stale.out" && /usr/bin/grep -q "warning: aa-api-server is $RC6V but aasm is $CLIV ($RC6)" "$OUT/stale.err" && ok "mismatch: warning names both versions and the shadowing path ($RC6V vs $CLIV)" || ko mismatch "rc=$RC out=$(cat $OUT/stale.out $OUT/stale.err | tr '\n' '|')"
  stop "$HOME_" "$OUT/stale/bin"
else echo "SKIP mismatch: $RC6 not installed"; fi

# stub-server scenarios: a fake aa-api-server on PATH, real aasm
stub(){ mode=$1; d="$OUT/stub-$mode/bin"; mkdir -p "$d"; cp "$T/aasm" "$d/"; cp "$Q/aasm-start-stub-server.py" "$d/aa-api-server"; chmod +x "$d/aa-api-server"; run_start "stub-$mode" "$d" "" STUB_MODE="$mode"; }
for m in ctrl big nojson noversion slow; do
  stub $m
  esc=$(cat "$OUT/stub-$m.out" "$OUT/stub-$m.err" | /usr/bin/tr -cd '\033\007' | /usr/bin/wc -c | tr -d ' ')
  [ $RC -eq 0 ] && /usr/bin/grep -q 'version not reported' "$OUT/stub-$m.out" && ! /usr/bin/grep -qi 'warning:' "$OUT/stub-$m.err" && [ "$esc" = "0" ] && python3 -c "import sys;sys.exit(0 if $ELAPSED < 4 else 1)" && ok "stub $m: 'version not reported', no warning, 0 control bytes, ${ELAPSED}s" || ko "stub-$m" "rc=$RC esc=$esc t=$ELAPSED $(cat $OUT/stub-$m.out $OUT/stub-$m.err | tr '\n' '|' | cut -c1-300)"
  [ "$m" = ctrl ] && { /usr/bin/grep -q 'FAKE-LINE\|RED' "$OUT/stub-$m.out" "$OUT/stub-$m.err" && ko "ctrl-text-leak" "hostile version text reached output" || ok "control-character version text never reached output"; }
  pid=$(alive_pid "$HOME_"); stop "$HOME_" "$BIN"; sleep 1
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && ko "stub-$m-stop" "pid $pid survived stop"
done
# stub ok:<other version> proves a stub can drive a mismatch warning too
stub "ok:0.0.0-stub"; /usr/bin/grep -q 'warning: aa-api-server is 0.0.0-stub' "$OUT/stub-ok:0.0.0-stub.err" && ok "stub ok:0.0.0-stub produces the mismatch warning (positive control for the stub path)" || ko stub-positive "$(cat "$OUT/stub-ok:0.0.0-stub.err")"; stop "$HOME_" "$BIN"

# 9 stranger holds the port, our server exits immediately
d="$OUT/stub-exit/bin"; mkdir -p "$d"; cp "$T/aasm" "$d/"; cp "$Q/aasm-start-stub-server.py" "$d/aa-api-server"; chmod +x "$d/aa-api-server"
P=$(port); python3 - "$P" <<'PY' &
import json,socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(8)
b=json.dumps({"status":"ok","version":"9.9.9","api_version":"v1"}).encode()
while True:
    c,_=s.accept(); c.recv(4096); c.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: %d\r\nconnection: close\r\n\r\n"%len(b)+b); c.close()
PY
STR=$!; sleep 0.5
H="$OUT/stranger.home"; mkdir -p "$H"
env -i HOME="$H" TMPDIR="$OUT" PATH="$d:/usr/bin:/bin" AASM_API_KEY=$KEY STUB_MODE=exit "$d/aasm" start --host 127.0.0.1 --port "$P" >"$OUT/stranger.out" 2>"$OUT/stranger.err"; rcs=$?
kill $STR 2>/dev/null
if [ $rcs -ne 0 ] && /usr/bin/grep -q 'already in use' "$OUT/stranger.err" && ! /usr/bin/grep -q '9.9.9\|started' "$OUT/stranger.out" "$OUT/stranger.err" && [ ! -e "$H/.aasm/gateway.pid" ]; then ok "stranger on the port: refused (rc=$rcs) with an in-use message, nothing launched, no PID recorded, its 9.9.9 never shown"; else ko stranger "rc=$rcs $(cat $OUT/stranger.out $OUT/stranger.err | tr '\n' '|')"; fi

# no leftovers from this run
left=$(ps -axo pid,command | /usr/bin/grep -F "$OUT" | /usr/bin/grep -v grep | /usr/bin/grep -vF accept.sh | wc -l | tr -d ' ')
[ "$left" = "0" ] && ok "no process from this run remains" || ko leftovers "$left process(es) mention $OUT"
echo "SUMMARY pass=$pass fail=$fail sha=$SHA"
[ $fail -eq 0 ]
