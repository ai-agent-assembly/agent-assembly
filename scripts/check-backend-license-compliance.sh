#!/usr/bin/env bash
# AAASM-5714 — execution-isolation backend license / provenance gate.
#
# WHY: `cargo deny check` (deny.toml, the `Dependency checks` CI job) is the
# workspace's license gate, but it can only evaluate crates in the cargo
# dependency graph. An isolation backend that ships as a PREBUILT BINARY —
# bundled into a release tarball, fetched by the installer, or baked into a
# container image — never enters that graph. cargo-deny never sees it, nothing
# fails, and an incompatible or unreviewed license reaches a distribution
# channel silently. Before this gate, NO mechanism covered that class at all.
#
# This gate closes that hole. It evaluates metadata/isolation-backends.json:
# every backend must declare exact provenance (upstream name, version, source,
# release checksum), an SPDX license cleared against the allowlist for EVERY
# channel that distributes it, whether AASM carries upstream modifications, and
# a named review with capability evidence.
#
# FAIL CLOSED. The license policy is an ALLOWLIST with implicit deny, mirroring
# deny.toml's `[licenses] allow` model: a license that is merely unrecognised is
# an error, not a warning. The `known_incompatible_spdx` map only makes that
# error legible — it is not the enforcement mechanism, and deleting an entry
# from it permits nothing.
#
# The allowlist is split in two, because the obligation that matters differs by
# channel: `oss_allowed_spdx` applies to the Apache-2.0 open-source channels,
# `proprietary_allowed_spdx` (a strict subset) to Enterprise/SaaS. A license
# cleared for OSS distribution is NOT thereby cleared for a proprietary bundle —
# that is the specific accident this gate exists to prevent.
#
# Usage:
#   scripts/check-backend-license-compliance.sh
#   scripts/check-backend-license-compliance.sh --manifest PATH --notices PATH
#   scripts/check-backend-license-compliance.sh --self-test
#
# `--self-test` is the NEGATIVE CONTROL. A gate that has only ever been run
# against a manifest it accepts has not been shown to reject anything — it
# could be passing vacuously. The self-test builds one known-good baseline,
# asserts the gate accepts it, then applies exactly ONE mutation at a time and
# asserts the gate rejects each with the expected message.
#
# Exit codes: 0 = all checks pass, 1 = at least one violation, 2 = bad usage.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF_TEST=0
MANIFEST="$REPO_ROOT/metadata/isolation-backends.json"
NOTICES="$REPO_ROOT/THIRD_PARTY_NOTICES.md"

# Strategies describing what AASM does with the backend on a given channel.
#   bundled         AASM redistributes the backend's bytes in its own artifact.
#   downloaded      AASM (installer/runtime) fetches it from an upstream origin.
#   source          AASM ships a recipe that builds it from upstream source.
#   system          The backend must already be installed by the operator.
#   not-distributed The channel does not carry or acquire the backend at all.
VALID_STRATEGIES="bundled downloaded source system not-distributed"

# Strategies where AASM causes the artifact to be acquired, and therefore where
# its license must be cleared for that channel. `system` and `not-distributed`
# are excluded: the operator supplies the bytes on their own terms.
GATED_STRATEGIES="bundled downloaded source"

fail=0
err() { echo "::error::$*" >&2; fail=1; }

usage() {
  echo "usage: $0 [--manifest PATH] [--notices PATH] [--self-test]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) [ $# -ge 2 ] || usage; MANIFEST="$2"; shift 2 ;;
    --notices)  [ $# -ge 2 ] || usage; NOTICES="$2";  shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    -h|--help) usage ;;
    *) echo "::error::unknown argument '$1'" >&2; usage ;;
  esac
done

# `jq -r '<expr> // empty'` on a compact one-line backend object.
jget() { printf '%s' "$1" | jq -r "${2} // empty"; }

# ---------------------------------------------------------------------------
# 0. The manifest must exist and parse. An unparseable manifest is a FAILURE,
#    never a skip: a gate that silently passes when its input is broken is the
#    same silent hole this ticket exists to close.
# ---------------------------------------------------------------------------
check_manifest() {
  if [ ! -f "$MANIFEST" ]; then
    err "backend manifest not found at '$MANIFEST'. Every isolation backend must be recorded there (AAASM-5714)."
    return
  fi
  if ! jq empty "$MANIFEST" >/dev/null 2>&1; then
    err "backend manifest '$MANIFEST' is not valid JSON."
    return
  fi

  local schema_version
  schema_version="$(jq -r '.schema_version // empty' "$MANIFEST")"
  if [ "$schema_version" != "1" ]; then
    err "backend manifest schema_version is '${schema_version:-<missing>}'; this gate implements version 1. Update the gate and the manifest together."
    return
  fi

  check_policy
  check_channels
  check_backends
}

# ---------------------------------------------------------------------------
# 1. License policy coherence. Both allowlists must exist and be non-empty, the
#    proprietary list must not be wider than the OSS one, and no license may be
#    both allowlisted and flagged incompatible.
# ---------------------------------------------------------------------------
check_policy() {
  local oss_count prop_count
  oss_count="$(jq -r '(.license_policy.oss_allowed_spdx // []) | length' "$MANIFEST")"
  prop_count="$(jq -r '(.license_policy.proprietary_allowed_spdx // []) | length' "$MANIFEST")"

  if [ "$oss_count" -eq 0 ]; then
    err "license_policy.oss_allowed_spdx is missing or empty. An empty allowlist would deny everything, which reads as 'gate broken' rather than 'policy'."
    return
  fi
  if [ "$prop_count" -eq 0 ]; then
    err "license_policy.proprietary_allowed_spdx is missing or empty."
    return
  fi

  # A license cleared for a proprietary bundle but not for the OSS one is
  # almost certainly a mistake in the manifest, not a real policy.
  local widened
  widened="$(jq -r '
    (.license_policy.oss_allowed_spdx // []) as $oss
    | (.license_policy.proprietary_allowed_spdx // [])
    | map(select(. as $l | ($oss | index($l)) | not)) | join(", ")' "$MANIFEST")"
  if [ -n "$widened" ]; then
    err "license_policy.proprietary_allowed_spdx allows licenses the OSS list does not ($widened). The proprietary list must be a subset of the OSS one."
  fi

  # Contradiction guard: a license cannot be both allowed and flagged as
  # needing a decision — that combination makes the diagnostic map lie.
  local contradictory
  contradictory="$(jq -r '
    ((.license_policy.oss_allowed_spdx // []) + (.license_policy.proprietary_allowed_spdx // [])) as $allowed
    | ((.license_policy.known_incompatible_spdx // {}) | keys_unsorted)
    | map(select(. != "_about"))
    | map(select(. as $l | ($allowed | index($l))))
    | unique | join(", ")' "$MANIFEST")"
  if [ -n "$contradictory" ]; then
    err "license(s) appear in BOTH an allowlist and known_incompatible_spdx ($contradictory). Resolve the contradiction; the allowlist is what enforces."
  fi
}

# ---------------------------------------------------------------------------
# 2. Channels. Each needs a unique id and an explicit oss/proprietary
#    classification — the classification is what selects the allowlist, so an
#    unclassified channel cannot be evaluated at all.
# ---------------------------------------------------------------------------
check_channels() {
  local count
  count="$(jq -r '(.channels // []) | length' "$MANIFEST")"
  if [ "$count" -eq 0 ]; then
    err "manifest declares no channels. The distribution matrix must be explicit (AAASM-5714)."
    return
  fi

  local dupes
  dupes="$(jq -r '[.channels[].id] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")' "$MANIFEST")"
  [ -z "$dupes" ] || err "duplicate channel id(s): $dupes"

  local ch id dist
  while IFS= read -r ch; do
    [ -n "$ch" ] || continue
    id="$(jget "$ch" '.id')"
    dist="$(jget "$ch" '.distribution')"
    if [ -z "$id" ]; then
      err "a channel entry has no 'id'."
      continue
    fi
    case "$dist" in
      oss|proprietary) ;;
      *) err "channel '$id' has distribution '${dist:-<missing>}'; must be 'oss' or 'proprietary' — this selects which allowlist applies, so it cannot be omitted." ;;
    esac
  done < <(jq -c '.channels[]' "$MANIFEST")
}

# ---------------------------------------------------------------------------
# 3. Backends.
# ---------------------------------------------------------------------------
check_backends() {
  local dupes
  dupes="$(jq -r '[(.backends // [])[].id] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")' "$MANIFEST")"
  [ -z "$dupes" ] || err "duplicate backend id(s): $dupes"

  local b id status
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    id="$(jget "$b" '.id')"
    status="$(jget "$b" '.status')"
    if [ -z "$id" ]; then
      err "a backend entry has no 'id'."
      continue
    fi
    case "$status" in
      pending) check_pending_backend "$b" "$id" ;;
      active)  check_active_backend  "$b" "$id" ;;
      *) err "backend '$id' has status '${status:-<missing>}'; must be 'pending' or 'active'." ;;
    esac
  done < <(jq -c '(.backends // [])[]' "$MANIFEST")
}

# A `pending` backend is one that does not exist yet. It must name the ticket
# that will deliver it, and — the point of this check — must carry NO
# provenance whatsoever. A placeholder version or checksum would sail through
# every downstream check while attesting to something nobody measured; an
# invented provenance row is strictly worse than an absent one.
check_pending_backend() {
  local b="$1" id="$2" ticket forbidden
  ticket="$(jget "$b" '.tracking_ticket')"
  case "$ticket" in
    AAASM-[0-9]*) ;;
    *) err "backend '$id' is 'pending' but tracking_ticket is '${ticket:-<missing>}'; it must name the AAASM ticket that will deliver it, so the empty row cannot become permanent by accident." ;;
  esac

  forbidden="$(printf '%s' "$b" | jq -r '
    . as $obj
    | [ "upstream_name","version","source_url","release_sha256","spdx_license",
        "license_text_path","modifications","review","channels","sbom" ]
    | map(. as $k | select($obj | has($k)))
    | join(", ")')"
  if [ -n "$forbidden" ]; then
    err "backend '$id' is 'pending' but carries provenance field(s): $forbidden. A pending backend has not been measured — recording a placeholder version/checksum/license would attest to something unverified. Remove the field(s), or set status to 'active' and record real, reviewed values."
  fi
}

check_active_backend() {
  local b="$1" id="$2"
  local upstream version source_url sha license modified notice_path
  local rticket rdate revidence

  upstream="$(jget "$b" '.upstream_name')"
  [ -n "$upstream" ] || err "active backend '$id' has no 'upstream_name'."

  version="$(jget "$b" '.version')"
  [ -n "$version" ] || err "active backend '$id' has no 'version'. The exact released version must be recorded, not a range or a branch."

  source_url="$(jget "$b" '.source_url')"
  case "$source_url" in
    https://*) ;;
    *) err "active backend '$id' has source_url '${source_url:-<missing>}'; an https:// URL identifying the exact upstream artifact or source tree is required." ;;
  esac

  sha="$(jget "$b" '.release_sha256')"
  if ! printf '%s' "$sha" | grep -qE '^[0-9a-f]{64}$'; then
    err "active backend '$id' has release_sha256 '${sha:-<missing>}'; must be 64 lowercase hex characters. This is the digest that makes the recorded provenance checkable (same role as EBPF_SHA256SUMS for the eBPF objects)."
  fi

  license="$(jget "$b" '.spdx_license')"
  [ -n "$license" ] || err "active backend '$id' has no 'spdx_license'."

  # Upstream modification tracking. Several allowlisted licenses (Apache-2.0
  # §4(b) among them) require a statement of changes when a modified work is
  # distributed; if we carry patches, the notice must exist and be findable.
  # NOT read via jget: jq's `//` operator treats `false` as absent, so
  # `"modified": false` — the common, correct case — would read as missing and
  # be reported as an error. Read the type explicitly instead, which also
  # rejects a string "false" masquerading as a boolean.
  modified="$(printf '%s' "$b" | jq -r '
    (.modifications // {}) as $m
    | if ($m | type) != "object" then "<invalid>"
      elif ($m.modified | type) == "boolean" then ($m.modified | tostring)
      else "<invalid>" end')"
  case "$modified" in
    true)
      notice_path="$(jget "$b" '.modifications.notice_path')"
      if [ -z "$notice_path" ]; then
        err "active backend '$id' declares upstream modifications but no 'modifications.notice_path'. A modified work carries a statement-of-changes obligation under several allowlisted licenses; the notice must exist and be locatable."
      elif [ ! -e "$REPO_ROOT/$notice_path" ]; then
        err "active backend '$id' modifications.notice_path '$notice_path' does not exist in the repository."
      fi
      ;;
    false) ;;
    *) err "active backend '$id' has a missing or non-boolean 'modifications.modified'; it must be the boolean true or false. 'We did not check' is not a valid answer here — whether AASM carries upstream patches decides whether a statement-of-changes obligation applies." ;;
  esac

  # AC: a backend upgrade must require capability/evidence and license review,
  # not just a version bump. Encoded as required fields that a bump cannot
  # satisfy by itself.
  rticket="$(jget "$b" '.review.ticket')"
  case "$rticket" in
    AAASM-[0-9]*) ;;
    *) err "active backend '$id' has review.ticket '${rticket:-<missing>}'; a reviewed backend must cite the AAASM ticket the review happened under." ;;
  esac
  rdate="$(jget "$b" '.review.reviewed_at')"
  if ! printf '%s' "$rdate" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    err "active backend '$id' has review.reviewed_at '${rdate:-<missing>}'; must be an ISO date (YYYY-MM-DD)."
  fi
  revidence="$(jget "$b" '.review.capability_evidence')"
  [ -n "$revidence" ] || err "active backend '$id' has no 'review.capability_evidence'. A version bump must not be able to pass review on its own — the evidence that the new version still provides the required isolation capabilities has to be cited."

  check_backend_channels "$b" "$id" "$license"
}

# The distribution matrix, per backend. Every declared channel must get an
# explicit strategy — a missing channel is a silent gap, which is precisely the
# failure mode this ticket names.
check_backend_channels() {
  local b="$1" id="$2" license="$3"
  local missing unknown ch_id strategy dist allowlist_key allowed hint bundled_anywhere=0

  if [ "$(printf '%s' "$b" | jq -r '(.channels // {}) | length')" -eq 0 ]; then
    err "active backend '$id' declares no per-channel distribution strategy. Each channel in the manifest must say whether AASM bundles, downloads, expects a system install, builds from source, or does not distribute it."
    return
  fi

  missing="$(jq -r --argjson b "$b" '
    [ .channels[].id ] - ($b.channels | keys) | join(", ")' "$MANIFEST")"
  [ -z "$missing" ] || err "active backend '$id' does not state a strategy for channel(s): $missing. Every channel must be explicit — an unlisted channel is a silent gap, not a default."

  unknown="$(jq -r --argjson b "$b" '
    ($b.channels | keys) - [ .channels[].id ] | join(", ")' "$MANIFEST")"
  [ -z "$unknown" ] || err "active backend '$id' names channel(s) not declared in the manifest: $unknown."

  while IFS="=" read -r ch_id strategy; do
    [ -n "$ch_id" ] || continue

    case " $VALID_STRATEGIES " in
      *" $strategy "*) ;;
      *) err "active backend '$id' channel '$ch_id' has strategy '$strategy'; must be one of: $VALID_STRATEGIES."
         continue ;;
    esac

    if [ "$strategy" = "bundled" ]; then bundled_anywhere=1; fi

    # Only channels where AASM causes acquisition are license-gated.
    case " $GATED_STRATEGIES " in
      *" $strategy "*) ;;
      *) continue ;;
    esac

    dist="$(jq -r --arg c "$ch_id" '.channels[] | select(.id == $c) | .distribution' "$MANIFEST")"
    [ -n "$dist" ] || continue   # already reported by check_channels

    if [ "$dist" = "proprietary" ]; then
      allowlist_key="proprietary_allowed_spdx"
    else
      allowlist_key="oss_allowed_spdx"
    fi

    allowed="$(jq -r --arg k "$allowlist_key" --arg l "$license" '
      (.license_policy[$k] // []) | index($l) | if . == null then "no" else "yes" end' "$MANIFEST")"

    if [ "$allowed" != "yes" ]; then
      hint="$(jq -r --arg l "$license" '
        .license_policy.known_incompatible_spdx[$l] // empty' "$MANIFEST")"
      if [ -n "$hint" ]; then
        err "backend '$id' is '$strategy' on channel '$ch_id' ($dist) under license '$license', which is NOT in license_policy.$allowlist_key. $hint  Clearing it requires an explicit reviewed decision recorded in the manifest — it cannot enter this channel by default."
      else
        err "backend '$id' is '$strategy' on channel '$ch_id' ($dist) under license '$license', which is NOT in license_policy.$allowlist_key. The policy is an allowlist with implicit deny: an unrecognised license fails closed. Add it deliberately (with security-reviewer sign-off) or do not ship the backend on this channel."
      fi
    fi
  done < <(printf '%s' "$b" | jq -r '(.channels // {}) | to_entries[] | "\(.key)=\(.value)"')

  if [ "$bundled_anywhere" -eq 1 ]; then
    check_bundled_obligations "$b" "$id"
  fi
}

# Obligations that attach specifically to redistributing the backend's bytes.
check_bundled_obligations() {
  local b="$1" id="$2" sbom

  # Third-party notice. Matched against an EXACT `### <id>` heading rather than
  # a substring: this file also carries a "Pending: <id>" heading while a
  # backend is unimplemented, and a substring match would let that pending
  # placeholder satisfy the requirement for a real shipped backend.
  if [ ! -f "$NOTICES" ]; then
    err "backend '$id' is bundled but the notices file '$NOTICES' does not exist."
  elif ! grep -E '^#{2,4}[[:space:]]' "$NOTICES" | grep -qxiF -- "### $id"; then
    err "backend '$id' is bundled into a release artifact but $(basename "$NOTICES") has no '### $id' section. Retaining the upstream copyright and license text is an obligation of every license in the allowlist; the notice must ship with the bytes."
  fi

  # SBOM coverage. Only container images have SBOM generation today
  # (docker.yml `sbom: true`); nothing covers the released binaries. A bundled
  # backend must therefore state HOW it is accounted for, so the gap is
  # recorded rather than assumed away.
  sbom="$(jget "$b" '.sbom.covered_by')"
  [ -n "$sbom" ] || err "backend '$id' is bundled but has no 'sbom.covered_by' stating how the shipped artifact is accounted for in release/SBOM output. Note that SBOM generation today covers container images only — a binary bundled into a release tarball is not covered by it."
}

# ---------------------------------------------------------------------------
# Self-test — the negative control.
#
# Design note: every case below is ONE mutation of a single shared baseline
# that the gate is first proven to accept. That is deliberate. If each case
# built its own manifest from scratch, a case could "fail" for a reason
# unrelated to the property under test and still look like evidence. Mutating
# a known-good baseline means the only thing that changed is the variable
# being tested, so the rejection is attributable to it.
#
# The mpl_* pair is the discriminating control: the SAME license produces
# opposite verdicts, differing only in whether the channel carrying it is
# classified proprietary. A gate that ignored channel classification would
# pass both, so this pair is what distinguishes a working two-tier allowlist
# from one that merely looks like it.
# ---------------------------------------------------------------------------
ST_PASS=0
ST_FAIL=0

# run_case <name> <expect: pass|fail> <expected-substring> <manifest> [notices]
run_case() {
  local name="$1" expect="$2" want="$3" manifest="$4" notices="${5:-}"
  local out rc
  [ -n "$notices" ] || notices="$ST_TMP/NOTICES.md"

  set +e
  out="$(bash "$SELF" --manifest "$manifest" --notices "$notices" 2>&1)"
  rc=$?
  set -e

  if [ "$expect" = "pass" ]; then
    if [ "$rc" -eq 0 ]; then
      echo "  ok   $name (exit 0, as expected)"
      ST_PASS=$((ST_PASS + 1))
    else
      echo "  FAIL $name: expected the gate to ACCEPT this manifest, got exit $rc" >&2
      echo "$out" | sed 's/^/       | /' >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
    return 0
  fi

  if [ "$rc" -eq 0 ]; then
    echo "  FAIL $name: gate ACCEPTED a manifest it must reject (exit 0)." >&2
    ST_FAIL=$((ST_FAIL + 1))
  elif ! printf '%s' "$out" | grep -qF -- "$want"; then
    # Rejected, but not for the reason under test — that is a wrong-reason
    # pass, which is not evidence the property is enforced.
    echo "  FAIL $name: rejected (exit $rc) but not for the expected reason." >&2
    echo "       wanted substring: $want" >&2
    echo "$out" | sed 's/^/       | /' >&2
    ST_FAIL=$((ST_FAIL + 1))
  else
    echo "  ok   $name (exit $rc, expected rejection)"
    ST_PASS=$((ST_PASS + 1))
  fi
  return 0
}

# Write a mutated copy of the baseline. `$1` = case name, `$2` = jq program.
mutate() {
  local name="$1" program="$2" out="$ST_TMP/$1.json"
  jq "$program" "$ST_TMP/baseline.json" > "$out"
  printf '%s' "$out"
}

run_self_test() {
  ST_TMP="$(mktemp -d)"
  trap 'rm -rf "$ST_TMP"' EXIT

  local hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

  cat > "$ST_TMP/NOTICES.md" <<'NOTICES'
# Third-party notices (self-test fixture)

### fixture-backend

Fixture notice section.
NOTICES

  # A notices file whose ONLY mention of the backend is a "Pending" heading.
  # Used to prove a pending placeholder cannot satisfy a shipped backend's
  # notice requirement.
  cat > "$ST_TMP/NOTICES-pending-only.md" <<'NOTICES'
# Third-party notices (self-test fixture)

### Pending: fixture-backend (AAASM-5708)

No notice written yet.
NOTICES

  cat > "$ST_TMP/baseline.json" <<BASELINE
{
  "schema_version": 1,
  "license_policy": {
    "oss_allowed_spdx": ["Apache-2.0", "MIT", "MPL-2.0"],
    "proprietary_allowed_spdx": ["Apache-2.0", "MIT"],
    "known_incompatible_spdx": {
      "AGPL-3.0-only": "Network-use source-disclosure obligation reaches hosted deployment."
    }
  },
  "channels": [
    { "id": "oss-chan",  "distribution": "oss" },
    { "id": "prop-chan", "distribution": "proprietary" }
  ],
  "backends": [
    {
      "id": "fixture-backend",
      "status": "active",
      "upstream_name": "Fixture Backend",
      "version": "1.2.3",
      "source_url": "https://example.invalid/fixture-1.2.3.tar.gz",
      "release_sha256": "$hex",
      "spdx_license": "Apache-2.0",
      "modifications": { "modified": false },
      "review": {
        "ticket": "AAASM-5714",
        "reviewed_at": "2026-08-13",
        "capability_evidence": "docs/release/isolation-backend-licensing.md"
      },
      "sbom": { "covered_by": "self-test fixture" },
      "channels": { "oss-chan": "bundled", "prop-chan": "not-distributed" }
    },
    {
      "id": "fixture-pending",
      "status": "pending",
      "tracking_ticket": "AAASM-5708"
    }
  ]
}
BASELINE

  echo "isolation-backend gate self-test"
  echo

  # --- positive control -----------------------------------------------------
  # Establishes that the baseline is otherwise valid, so every rejection below
  # is attributable to that case's single mutation and nothing else.
  run_case "baseline_is_accepted" pass "" "$ST_TMP/baseline.json"

  echo '{ this is not json' > "$ST_TMP/malformed.json"
  run_case "malformed_json" fail "is not valid JSON" "$ST_TMP/malformed.json"

  run_case "unsupported_schema_version" fail "schema_version" \
    "$(mutate unsupported_schema_version '.schema_version = 2')"

  # --- the fabrication guard ------------------------------------------------
  run_case "pending_without_tracking_ticket" fail "tracking_ticket" \
    "$(mutate pending_without_tracking_ticket 'del(.backends[1].tracking_ticket)')"

  run_case "pending_carries_provenance" fail "carries provenance field" \
    "$(mutate pending_carries_provenance '.backends[1].version = "0.1.0"')"

  run_case "pending_carries_license" fail "carries provenance field" \
    "$(mutate pending_carries_license '.backends[1].spdx_license = "Apache-2.0"')"

  # --- the license allowlist, fail-closed -----------------------------------
  run_case "agpl_on_oss_channel" fail "oss_allowed_spdx" \
    "$(mutate agpl_on_oss_channel '.backends[0].spdx_license = "AGPL-3.0-only"')"

  run_case "unrecognised_license_denied_by_default" fail "allowlist with implicit deny" \
    "$(mutate unrecognised_license_denied_by_default '.backends[0].spdx_license = "Totally-Made-Up-1.0"')"

  # --- discriminating pair: same license, verdict decided by channel tier ----
  run_case "mpl_on_oss_channel_is_allowed" pass "" \
    "$(mutate mpl_on_oss_channel_is_allowed '.backends[0].spdx_license = "MPL-2.0"')"

  run_case "mpl_on_proprietary_channel_is_denied" fail "proprietary_allowed_spdx" \
    "$(mutate mpl_on_proprietary_channel_is_denied \
       '.backends[0].spdx_license = "MPL-2.0"
        | .backends[0].channels["prop-chan"] = "bundled"')"

  # A non-distributing channel must NOT be gated — otherwise the gate would
  # block backends nobody ships, and the "denied" result above would be
  # unfalsifiable rather than meaningful.
  run_case "proprietary_channel_not_distributing_is_ungated" pass "" \
    "$(mutate proprietary_channel_not_distributing_is_ungated \
       '.backends[0].spdx_license = "MPL-2.0"
        | .backends[0].channels["prop-chan"] = "system"')"

  # --- provenance completeness ----------------------------------------------
  run_case "checksum_not_sha256" fail "64 lowercase hex" \
    "$(mutate checksum_not_sha256 '.backends[0].release_sha256 = "deadbeef"')"

  run_case "source_url_not_https" fail "source_url" \
    "$(mutate source_url_not_https '.backends[0].source_url = "git@example.invalid:x.git"')"

  run_case "missing_version" fail "no 'version'" \
    "$(mutate missing_version 'del(.backends[0].version)')"

  # --- modification notice --------------------------------------------------
  run_case "modified_without_notice_path" fail "notice_path" \
    "$(mutate modified_without_notice_path '.backends[0].modifications.modified = true')"

  run_case "modified_notice_path_missing_on_disk" fail "does not exist in the repository" \
    "$(mutate modified_notice_path_missing_on_disk \
       '.backends[0].modifications = {"modified": true, "notice_path": "docs/nope/absent.md"}')"

  run_case "modification_state_not_boolean" fail "must be the boolean" \
    "$(mutate modification_state_not_boolean '.backends[0].modifications.modified = "unknown"')"

  # --- review, not just a version bump --------------------------------------
  run_case "no_capability_evidence" fail "capability_evidence" \
    "$(mutate no_capability_evidence 'del(.backends[0].review.capability_evidence)')"

  run_case "no_review_block" fail "review.ticket" \
    "$(mutate no_review_block 'del(.backends[0].review)')"

  # --- channel matrix completeness ------------------------------------------
  run_case "channel_strategy_missing" fail "does not state a strategy" \
    "$(mutate channel_strategy_missing 'del(.backends[0].channels["prop-chan"])')"

  run_case "channel_strategy_unknown" fail "must be one of" \
    "$(mutate channel_strategy_unknown '.backends[0].channels["oss-chan"] = "vendored"')"

  run_case "channel_not_declared" fail "not declared in the manifest" \
    "$(mutate channel_not_declared '.backends[0].channels["ghost-chan"] = "bundled"')"

  run_case "channel_unclassified" fail "must be 'oss' or 'proprietary'" \
    "$(mutate channel_unclassified 'del(.channels[0].distribution)')"

  # --- notices + SBOM obligations on bundled bytes --------------------------
  run_case "bundled_without_sbom_statement" fail "sbom.covered_by" \
    "$(mutate bundled_without_sbom_statement 'del(.backends[0].sbom)')"

  run_case "bundled_without_notice_section" fail "has no '### fixture-backend' section" \
    "$ST_TMP/baseline.json" "$ST_TMP/NOTICES-pending-only.md"

  # --- policy coherence -----------------------------------------------------
  run_case "proprietary_list_wider_than_oss" fail "must be a subset" \
    "$(mutate proprietary_list_wider_than_oss \
       '.license_policy.proprietary_allowed_spdx += ["GPL-3.0-only"]')"

  run_case "license_both_allowed_and_incompatible" fail "BOTH an allowlist" \
    "$(mutate license_both_allowed_and_incompatible \
       '.license_policy.oss_allowed_spdx += ["AGPL-3.0-only"]')"

  echo
  echo "self-test: $ST_PASS passed, $ST_FAIL failed"
  if [ "$ST_FAIL" -ne 0 ]; then
    echo "::error::isolation-backend gate self-test FAILED — the gate does not enforce what it claims." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
main() {
  if [ "$SELF_TEST" -eq 1 ]; then
    run_self_test
    exit 0
  fi
  check_manifest
  if [ "$fail" -ne 0 ]; then
    echo "isolation-backend license/provenance gate: FAILED" >&2
    exit 1
  fi
  echo "isolation-backend license/provenance gate: OK"
  echo "  manifest : $MANIFEST"
  echo "  notices  : $NOTICES"
  echo "  channels : $(jq -r '[.channels[].id] | join(" ")' "$MANIFEST")"
  echo "  backends : $(jq -r '[(.backends // [])[] | "\(.id)=\(.status)"] | join(" ")' "$MANIFEST")"
}

main
