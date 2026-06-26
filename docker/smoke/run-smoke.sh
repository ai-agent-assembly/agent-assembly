#!/usr/bin/env bash
# run-smoke.sh — per-language Docker base-image smoke harness (AAASM-3524).
#
# For ONE base image (or all 9, see --all) this:
#   1. builds the base image from its docker/Dockerfile.<lang>-<ver>;
#   2. builds the aa-runtime sidecar image once (reused across images);
#   3. brings up the governance compose stack (base-image agent + aa-runtime
#      sharing the UDS), waits for the runtime socket, runs the minimal agent;
#   4. asserts: image builds, the agent runs with no manual config and exits
#      clean (Tier A), entrypoint/default-env hygiene, and the policy fixture
#      genuinely denies the restricted action (offline, real);
#   5. records the governance-transport tier honestly (live vs offline) and the
#      deny-enforcement gap (AAASM-3000 / AAASM-3021, pending AAASM-3172) — never
#      faking a green for what cannot be proven from the base image today;
#   6. tears the stack down.
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
  # SDK_VERSION is required by the language Dockerfiles (ADR 0009): there is no
  # floating fallback, so the smoke build must pass the same pin docker.yml uses.
  # Resolve it from the single source of truth (jq is a smoke-runner prerequisite).
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
    RESULTS+=("${lang}:${version}|BUILD_FAIL|-")
    FAILED=$((FAILED + 1))
    return
  fi
  ok "${lang}:${version} — base image ready (${base_image})"

  if ! check_image_hygiene "$lang" "$base_image"; then
    fail "${lang}:${version} — image hygiene failed"
    RESULTS+=("${lang}:${version}|HYGIENE_FAIL|-")
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

  # Start the aa-runtime sidecar. NOTE: a sidecar that cannot start does NOT fail
  # the base-image smoke — Tier A ("the agent runs with no manual config") is
  # independent of the sidecar. The sidecar's reachability only governs whether
  # the live governance transport (Tier B) can be exercised; we record it.
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
    # The aa-runtime image is currently unrunnable (AAASM-3527: /aa-runtime is a
    # directory). The harness records this and proceeds; the agent runs its
    # offline path. Flip to a live-transport assertion once AAASM-3527 + the SDK
    # native-client gaps land.
    log "${lang}:${version} — runtime socket NOT bound; sidecar unreachable"
    log "${lang}:${version}   (aa-runtime image is unrunnable — see AAASM-3527)"
    docker compose -f "${COMPOSE_FILE}" -p "${project}" logs aa-runtime 2>/dev/null \
      | tail -3 >&2 || true
  fi

  # Run the agent (build overlay + run, capturing its JSON result line).
  # --no-deps: run ONLY the agent — do NOT let compose (re)start the aa-runtime
  # dependency, which currently crashes (AAASM-3527) and would otherwise abort the
  # whole `run`. The sidecar was already started best-effort above; the agent's
  # Tier-A path does not require it.
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
    RESULTS+=("${lang}:${version}|AGENT_NO_RESULT|-|${sidecar}")
    FAILED=$((FAILED + 1))
    return
  fi

  local tier_a transport
  tier_a="$(jq -r '.tier_a // false' <<<"$json")"
  transport="$(jq -r '.transport // "offline"' <<<"$json")"

  if [ "$agent_rc" -ne 0 ] || [ "$tier_a" != "true" ]; then
    fail "${lang}:${version} — agent did not run cleanly on the base image (rc=${agent_rc})"
    printf '%s\n' "$json" >&2
    RESULTS+=("${lang}:${version}|AGENT_FAIL|${transport}|${sidecar}")
    FAILED=$((FAILED + 1))
    return
  fi

  ok "${lang}:${version} — agent ran with no manual config (Tier A); transport=${transport} sidecar=${sidecar}"
  RESULTS+=("${lang}:${version}|PASS|${transport}|${sidecar}")
  PASS=$((PASS + 1))
}

# --- offline, real: assert the policy fixture genuinely denies ---------------
# This runs once (policy is language-agnostic). It proves the deny side of the
# governance path is encoded for real, even though asserting the BLOCK end-to-end
# from inside the base image is gated on AAASM-3000 / AAASM-3021 (see README).
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
check_policy_denies || { FAILED=$((FAILED + 1)); }

for entry in "${ENTRIES[@]}"; do
  run_one "$entry"
done

# --- summary -----------------------------------------------------------------
log "================= summary ================="
printf '%-22s %-14s %-10s %s\n' "IMAGE" "RESULT" "TRANSPORT" "SIDECAR" >&2
for r in "${RESULTS[@]}"; do
  IFS='|' read -r img res tr sc <<<"$r"
  printf '%-22s %-14s %-10s %s\n' "$img" "$res" "$tr" "${sc:-?}" >&2
done
log "passed=${PASS} failed=${FAILED}"
log "NOTE: sidecar=down on every row reflects AAASM-3527 (the aa-runtime image"
log "      entrypoint is a directory — the sidecar cannot start). Tier A (agent"
log "      runs with no manual config) is independent and still asserted."
log "NOTE: deny-enforcement-from-image is a separate known product gap (AAASM-3000"
log "      / AAASM-3021); see docker/smoke/README.md. transport=offline reflects"
log "      that the published base image ships no socket-dialing native client."

[ "$FAILED" -eq 0 ]
