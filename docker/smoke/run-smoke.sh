#!/usr/bin/env bash
# run-smoke.sh — per-language Docker base-image smoke harness (AAASM-3524).
#
# For ONE base image (or all 9, see --all) this:
#   1. builds the base image from its docker/Dockerfile.<lang>-<ver>;
#   2. builds the aa-runtime sidecar image once (reused across images);
#   3. brings up the governance compose stack (base-image agent + aa-runtime
#      sharing the UDS), waits for the runtime socket, runs the minimal agent;
#   4. asserts: image builds, the agent runs with no manual config and exits
#      clean (Tier A), entrypoint/default-env hygiene;
#   5. AAASM-5886 — drives one real ALLOW (TOOL_CALL) and one real DENY
#      (PROCESS_EXEC) governed call through the containerized aa-runtime sidecar
#      itself, over its UDS, via the standalone `governed_call_probe` (not the
#      base image's own SDK — see docker/smoke/README.md "Governed-call
#      enforcement"), and fails the leg if either lands on the wrong decision;
#   6. records the base image's own governance-transport tier honestly (live vs
#      offline — AAASM-1202, the published images don't yet ship the SDK native
#      client) rather than faking a green for what that image cannot prove;
#   7. tears the stack down.
#
# It is the local fallback for when GHCR pull / CI is unavailable, and the unit
# the CI matrix (.github/workflows/docker-image-smoke.yml) runs one leg of.
#
# Usage:
#   docker/smoke/run-smoke.sh --lang python --version 3.14-slim
#   docker/smoke/run-smoke.sh --all
#   IMAGE_MODE=pull docker/smoke/run-smoke.sh --lang go --version 1.26-alpine
#
# Env:
#   IMAGE_MODE=build|pull   build from docker/ (default) or pull from GHCR (for
#                           post-publish release verification of a real v* tag).
#   GHCR_TAG=<tag>          the tag to pull when IMAGE_MODE=pull (e.g. v0.0.1).
#   KEEP_STACK=1            do not tear the compose stack down (debugging).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGES_JSON="${SCRIPT_DIR}/images.json"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.smoke.yml"

IMAGE_MODE="${IMAGE_MODE:-build}"
GHCR_TAG="${GHCR_TAG:-}"
GHCR_NS="ghcr.io/ai-agent-assembly"
RUNTIME_IMAGE_TAG="aa-runtime:smoke"
# AAASM-5886 — governed_call_probe image tag, built once and reused across legs
# exactly like RUNTIME_IMAGE_TAG.
PROBE_IMAGE_TAG="aa-governed-probe:smoke"

log()  { printf '\033[1;34m[smoke]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

require() {
  command -v "$1" >/dev/null 2>&1 || { fail "missing required tool: $1"; exit 2; }
}

# --- arg parsing -------------------------------------------------------------
LANG_FILTER=""
VERSION_FILTER=""
RUN_ALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --lang)    LANG_FILTER="$2"; shift 2 ;;
    --version) VERSION_FILTER="$2"; shift 2 ;;
    --all)     RUN_ALL=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown arg: $1"; exit 2 ;;
  esac
done

require docker
require jq
docker compose version >/dev/null 2>&1 || { fail "docker compose plugin not available"; exit 2; }

if [ "$RUN_ALL" -eq 0 ] && { [ -z "$LANG_FILTER" ] || [ -z "$VERSION_FILTER" ]; }; then
  fail "specify --lang <l> --version <v>, or --all"
  exit 2
fi

# Select matrix entries from images.json.
if [ "$RUN_ALL" -eq 1 ]; then
  SELECTOR='.images[]'
else
  SELECTOR=".images[] | select(.lang==\"${LANG_FILTER}\" and .version==\"${VERSION_FILTER}\")"
fi
# Portable read into an array (avoid `mapfile`, absent on macOS bash 3.2).
ENTRIES=()
while IFS= read -r line; do
  [ -n "$line" ] && ENTRIES+=("$line")
done < <(jq -c "${SELECTOR}" "${IMAGES_JSON}")
if [ "${#ENTRIES[@]}" -eq 0 ]; then
  fail "no matrix entry matched (lang=${LANG_FILTER} version=${VERSION_FILTER})"
  exit 2
fi

# --- build the aa-runtime sidecar once (build mode) --------------------------
build_runtime() {
  if [ "$IMAGE_MODE" = "pull" ]; then
    local tag="${GHCR_TAG:-latest}"
    RUNTIME_IMAGE_TAG="${GHCR_NS}/aa-runtime:${tag}"
    log "pulling aa-runtime sidecar ${RUNTIME_IMAGE_TAG}"
    docker pull "${RUNTIME_IMAGE_TAG}"
    return
  fi
  # Skip the (multi-minute) Rust build when the sidecar image is already loaded
  # — e.g. CI pre-loads it as an artifact, or a prior --all leg built it.
  if docker image inspect "${RUNTIME_IMAGE_TAG}" >/dev/null 2>&1; then
    ok "aa-runtime sidecar already present (${RUNTIME_IMAGE_TAG}) — skipping build"
    return
  fi
  log "building aa-runtime sidecar (${RUNTIME_IMAGE_TAG}) — one-time, reused across images"
  DOCKER_BUILDKIT=1 docker build \
    -f "${REPO_ROOT}/aa-runtime/Dockerfile" \
    -t "${RUNTIME_IMAGE_TAG}" \
    "${REPO_ROOT}"
  ok "aa-runtime sidecar built"
}

# --- build the governed-call probe once (build mode) -------------------------
# AAASM-5886. Mirrors build_runtime(): built once, reused across all matrix
# legs. IMAGE_MODE=pull has no probe equivalent — the probe is smoke-only
# infrastructure, never published — so it is always built locally regardless
# of IMAGE_MODE.
build_probe() {
  if docker image inspect "${PROBE_IMAGE_TAG}" >/dev/null 2>&1; then
    ok "governed-call probe already present (${PROBE_IMAGE_TAG}) — skipping build"
    return
  fi
  log "building governed-call probe (${PROBE_IMAGE_TAG}) — one-time, reused across images"
  DOCKER_BUILDKIT=1 docker build \
    -f "${SCRIPT_DIR}/probe/Dockerfile.probe" \
    -t "${PROBE_IMAGE_TAG}" \
    "${REPO_ROOT}"
  ok "governed-call probe built"
}

# --- resolve / build one base image ------------------------------------------
# echoes the resolved base image tag on stdout; RETURNS NON-ZERO if the build or
# pull failed, so the caller can record BUILD_FAIL instead of proceeding against
# a non-existent image. (A bare `printf` after a failed build would otherwise
# mask the failure under command substitution.)
resolve_base_image() {
  local lang="$1" version="$2" dockerfile="$3"
  if [ "$IMAGE_MODE" = "pull" ]; then
    local img="${GHCR_NS}/${lang}:${version}"
    log "pulling base image ${img}"
    docker pull "${img}" >&2 || return 1
    printf '%s' "${img}"
    return 0
  fi
  local img="aaasm-smoke/${lang}-${version}:local"
  # Build with the manifest-pinned SDK_VERSION — the governed smoke tests the
  # PUBLISHED image configuration (docker.yml pins from the same manifest), and the
  # known-compatible pin keeps the deep-governance smoke stable. Building with the
  # floating default would pull a newer SDK that attempts live transport and trips
  # the open IPC gap (AAASM-3000 / AAASM-3172). jq is a smoke-runner prerequisite.
  local sdk_version
  sdk_version="$(jq -r --arg l "${lang}" '.sdk[$l]' "${REPO_ROOT}/docker/sdk-versions.json")"
  log "building base image ${lang}:${version} from ${dockerfile} (SDK ${sdk_version})"
  if ! DOCKER_BUILDKIT=1 docker build \
      -f "${REPO_ROOT}/${dockerfile}" \
      --build-arg "SDK_VERSION=${sdk_version}" \
      -t "${img}" \
      "${REPO_ROOT}" >&2; then
    return 1
  fi
  printf '%s' "${img}"
  return 0
}

# --- image hygiene checks (entrypoint / default env / no shell surprises) ----
check_image_hygiene() {
  local lang="$1" base_image="$2"
  # The language base images intentionally inherit the upstream runtime default
  # (python REPL / node REPL / go) — assert the toolchain + SDK are present and
  # `aasm --version` works with no extra config, which is the real hygiene bar.
  log "hygiene: aasm --version on ${base_image}"
  docker run --rm "${base_image}" aasm --version >/dev/null
  ok "hygiene: aasm present and runnable (${lang})"
}

# --- per-image smoke ---------------------------------------------------------
PASS=0
FAILED=0
RESULTS=()

run_one() {
  local entry="$1"
  local lang version dockerfile
  lang="$(jq -r '.lang' <<<"$entry")"
  version="$(jq -r '.version' <<<"$entry")"
  dockerfile="$(jq -r '.dockerfile' <<<"$entry")"

  log "=== ${lang}:${version} ==================================================="

  local base_image
  if ! base_image="$(resolve_base_image "$lang" "$version" "$dockerfile")"; then
    fail "${lang}:${version} — base image build/pull failed"
    RESULTS+=("${lang}:${version}|BUILD_FAIL|-|-|-")
    FAILED=$((FAILED + 1))
    return
  fi
  ok "${lang}:${version} — base image ready (${base_image})"

  if ! check_image_hygiene "$lang" "$base_image"; then
    fail "${lang}:${version} — image hygiene failed"
    RESULTS+=("${lang}:${version}|HYGIENE_FAIL|-|-|-")
    FAILED=$((FAILED + 1))
    return
  fi

  # Bring up the governance stack and run the agent.
  local agent_id project agent_dir agent_df
  agent_id="aaitsmoke-${lang}-${version//./-}-$RANDOM"
  project="aaasm-smoke-${lang}-${version//./-}"
  agent_dir="${SCRIPT_DIR}/agents/${lang}"
  agent_df="${agent_dir}/Dockerfile.agent"

  export AA_RUNTIME_IMAGE="${RUNTIME_IMAGE_TAG}"
  export AA_PROBE_IMAGE="${PROBE_IMAGE_TAG}"
  export SMOKE_BASE_IMAGE="${base_image}"
  export SMOKE_AGENT_DIR="${agent_dir}"
  export SMOKE_AGENT_DOCKERFILE="${agent_df}"
  export AA_AGENT_ID="${agent_id}"

  local teardown=1
  [ "${KEEP_STACK:-0}" = "1" ] && teardown=0

  cleanup() {
    [ "$teardown" -eq 1 ] || return 0
    docker compose -f "${COMPOSE_FILE}" -p "${project}" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  }

  # Start the aa-runtime sidecar. Since AAASM-3527 fixed the image's entrypoint,
  # a healthy leg is expected to reach a bound socket below — see the
  # SIDECAR_UNREACHABLE branch, which now fails the leg rather than tolerating it.
  log "${lang}:${version} — starting aa-runtime sidecar"
  docker compose -f "${COMPOSE_FILE}" -p "${project}" up -d aa-runtime >&2 || true

  # Wait for the runtime to bind its UDS in the shared volume (no shell in the
  # distroless image, so probe via a throwaway alpine mounting the same volume).
  log "${lang}:${version} — waiting for runtime socket /tmp/aa-runtime-${agent_id}.sock"
  local sock_ready=0 i
  for i in $(seq 1 15); do
    if docker run --rm -v "${project}_aa-runtime-socket:/tmp" alpine:latest \
         sh -c "test -S /tmp/aa-runtime-${agent_id}.sock" >/dev/null 2>&1; then
      sock_ready=1
      break
    fi
    sleep 1
  done
  if [ "$sock_ready" -eq 1 ]; then
    ok "${lang}:${version} — runtime socket is bound (live transport reachable)"
  else
    # AAASM-3527 (the aa-runtime image's /aa-runtime entrypoint being a
    # directory) is fixed — an unbound socket here is no longer an expected,
    # tolerated state. Record it and fail this leg's governed-call assertion
    # rather than silently degrading, like the pre-fix harness did.
    log "${lang}:${version} — runtime socket NOT bound; sidecar unreachable"
    docker compose -f "${COMPOSE_FILE}" -p "${project}" logs aa-runtime 2>/dev/null \
      | tail -10 >&2 || true
    fail "${lang}:${version} — aa-runtime sidecar did not bind its UDS in time"
    cleanup
    RESULTS+=("${lang}:${version}|SIDECAR_UNREACHABLE|-|down|-")
    FAILED=$((FAILED + 1))
    return
  fi

  # AAASM-5886 — drive one real ALLOW and one real DENY governed call through
  # the containerized sidecar over the socket just confirmed above, using the
  # standalone probe (not the base image's own SDK — see governed_call_probe.rs
  # for why). This is the actual enforcement assertion J52 was missing; a
  # failure here means the containerized aa-runtime is not enforcing policy for
  # real, independent of whether the language agent itself ran cleanly.
  log "${lang}:${version} — driving governed call (allow + deny) through the sidecar"
  local probe_out probe_rc=0
  probe_out="$(docker compose -f "${COMPOSE_FILE}" -p "${project}" run --rm --no-deps probe 2>/dev/null)" || probe_rc=$?
  local probe_json
  probe_json="$(printf '%s\n' "$probe_out" | grep -E '^\{.*\}$' | tail -n1 || true)"
  local probe_ok="false"
  [ -n "$probe_json" ] && probe_ok="$(jq -r '.ok // false' <<<"$probe_json")"
  if [ "$probe_rc" -ne 0 ] || [ "$probe_ok" != "true" ]; then
    fail "${lang}:${version} — governed call was not enforced as expected (rc=${probe_rc})"
    printf '%s\n' "${probe_json:-$probe_out}" >&2
    cleanup
    RESULTS+=("${lang}:${version}|GOVERNED_CALL_FAIL|-|up|FAIL")
    FAILED=$((FAILED + 1))
    return
  fi
  ok "${lang}:${version} — governed call enforced for real: allow=$(jq -r '.allow_decision' <<<"$probe_json") deny=$(jq -r '.deny_decision' <<<"$probe_json")"

  # Run the agent (build overlay + run, capturing its JSON result line).
  # --no-deps: run ONLY the agent — the sidecar is already confirmed up above,
  # and Tier A (the agent runs with no manual config) does not itself require it.
  log "${lang}:${version} — running minimal agent on the base image"
  local agent_out agent_rc=0
  agent_out="$(docker compose -f "${COMPOSE_FILE}" -p "${project}" run --rm --no-deps --build agent 2>/dev/null)" || agent_rc=$?

  # Parse the last JSON line the agent emitted.
  local json
  json="$(printf '%s\n' "$agent_out" | grep -E '^\{.*\}$' | tail -n1 || true)"

  cleanup

  local sidecar="down"
  [ "$sock_ready" -eq 1 ] && sidecar="up"

  if [ -z "$json" ]; then
    fail "${lang}:${version} — agent produced no JSON result (rc=${agent_rc})"
    printf '%s\n' "$agent_out" >&2
    RESULTS+=("${lang}:${version}|AGENT_NO_RESULT|-|${sidecar}|PASS")
    FAILED=$((FAILED + 1))
    return
  fi

  local tier_a transport
  tier_a="$(jq -r '.tier_a // false' <<<"$json")"
  transport="$(jq -r '.transport // "offline"' <<<"$json")"

  if [ "$agent_rc" -ne 0 ] || [ "$tier_a" != "true" ]; then
    fail "${lang}:${version} — agent did not run cleanly on the base image (rc=${agent_rc})"
    printf '%s\n' "$json" >&2
    RESULTS+=("${lang}:${version}|AGENT_FAIL|${transport}|${sidecar}|PASS")
    FAILED=$((FAILED + 1))
    return
  fi

  ok "${lang}:${version} — agent ran with no manual config (Tier A); transport=${transport} sidecar=${sidecar}"
  RESULTS+=("${lang}:${version}|PASS|${transport}|${sidecar}|PASS")
  PASS=$((PASS + 1))
}

# --- fast pre-flight: the policy fixture text is not self-contradictory -----
# This runs once (policy is language-agnostic), before any image build, purely
# as a cheap fail-fast sanity check on the fixture file itself. The REAL
# deny/allow assertion is `governed_call_probe` (AAASM-5886), run per-leg once
# the sidecar's socket is up — this only guards against a broken fixture
# wasting a multi-minute image build before that.
check_policy_denies() {
  log "policy fixture: asserting PROCESS_EXEC is denied and TOOL_CALL is not"
  # Inspect ONLY the actual `blocked_actions = [...]` assignment lines (strip
  # comments first) so a comment that merely names an action type is not a false
  # match. The allowed action the agents perform is a TOOL_CALL.
  local blocked
  blocked="$(sed 's/#.*//' "${SCRIPT_DIR}/policy.toml" | grep 'blocked_actions' || true)"
  if ! printf '%s' "$blocked" | grep -q 'PROCESS_EXEC'; then
    fail "policy.toml does not block PROCESS_EXEC — deny path fixture is broken"
    return 1
  fi
  if printf '%s' "$blocked" | grep -q 'TOOL_CALL'; then
    fail "policy.toml unexpectedly blocks TOOL_CALL — allowed action would be denied"
    return 1
  fi
  ok "policy fixture denies the restricted action, permits the allowed one"
}

# --- main --------------------------------------------------------------------
build_runtime
build_probe
check_policy_denies || { FAILED=$((FAILED + 1)); }

for entry in "${ENTRIES[@]}"; do
  run_one "$entry"
done

# --- summary -----------------------------------------------------------------
log "================= summary ================="
printf '%-22s %-20s %-10s %-8s %s\n' "IMAGE" "RESULT" "TRANSPORT" "SIDECAR" "GOVERNED" >&2
for r in "${RESULTS[@]}"; do
  IFS='|' read -r img res tr sc gv <<<"$r"
  printf '%-22s %-20s %-10s %-8s %s\n' "$img" "$res" "$tr" "${sc:-?}" "${gv:-?}" >&2
done
log "passed=${PASS} failed=${FAILED}"
log "NOTE: GOVERNED=PASS means governed_call_probe (AAASM-5886) drove a real ALLOW"
log "      and a real DENY CheckAction through the containerized aa-runtime sidecar"
log "      over its UDS and both landed on the expected decision — the assertion"
log "      J52's smoke was previously missing. transport=offline still reflects a"
log "      separate, honestly-reported gap: the published base image ships no SDK"
log "      native client of its own (AAASM-1202), so the language agent's own Tier"
log "      B is unavailable even though the sidecar itself is proven enforcing."

[ "$FAILED" -eq 0 ]
