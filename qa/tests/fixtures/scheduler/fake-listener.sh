#!/usr/bin/env bash
# Binds a loopback TCP listener and creates a temp directory, self-reports
# both to aa-sched via $AA_SCHED_JOB_META (see aa-sched's cmd_run), then
# either exits (success path) or hangs until killed (failure/kill path).
set -u
mode="${1:-succeed}" # succeed | hang
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/aa-sched-fixture.XXXXXX")

find_free_port() {
    python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
'
}
listen_port=$(find_free_port)
nc -l "$listen_port" >/dev/null 2>&1 &
listener_pid=$!

if [[ -n "${AA_SCHED_JOB_META:-}" ]]; then
    echo "port=$listen_port" >>"$AA_SCHED_JOB_META"
    echo "temp_dir=$temp_dir" >>"$AA_SCHED_JOB_META"
fi

echo "listening on $listen_port, temp dir $temp_dir"

if [[ "$mode" == "hang" ]]; then
    sleep 3600
else
    kill "$listener_pid" >/dev/null 2>&1
    exit 0
fi
