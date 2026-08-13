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
#
# Exit codes: 0 = all checks pass, 1 = at least one violation, 2 = bad usage.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
  echo "usage: $0 [--manifest PATH] [--notices PATH]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) [ $# -ge 2 ] || usage; MANIFEST="$2"; shift 2 ;;
    --notices)  [ $# -ge 2 ] || usage; NOTICES="$2";  shift 2 ;;
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
main() {
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
