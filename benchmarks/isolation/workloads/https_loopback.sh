#!/usr/bin/env sh
# Sustained HTTPS traffic: 200 sequential requests against the TLS server the
# harness runs on loopback.
#
# One long-lived client process rather than 200 curl invocations, so the family
# measures socket and TLS cost rather than process creation, which process_spawn
# already covers. AABENCH_HTTPS_URL and AABENCH_HTTPS_CA are exported by the
# harness; the server lives outside the sandbox because it stands in for a
# remote API the confined agent reaches out to.
set -eu

: "${AABENCH_HTTPS_URL:?AABENCH_HTTPS_URL not set by harness}"
: "${AABENCH_HTTPS_CA:?AABENCH_HTTPS_CA not set by harness}"

python3 - <<'PYEOF'
import os
import ssl
import urllib.request

url = os.environ["AABENCH_HTTPS_URL"]
context = ssl.create_default_context(cafile=os.environ["AABENCH_HTTPS_CA"])
context.check_hostname = False

total = 0
for _ in range(200):
    with urllib.request.urlopen(url, context=context, timeout=10) as response:
        total += len(response.read())

if total <= 0:
    raise SystemExit("no bytes read from loopback TLS server")
PYEOF
