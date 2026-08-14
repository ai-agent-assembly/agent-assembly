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
# Root that each channel's `packaging_paths` globs resolve against. Overridable
# only so the self-test can point at a fixture packaging tree — the negative
# control has to scan real files it controls the contents of, and it must not
# be able to "pass" by reading this repository's actual release pipeline.
PACKAGING_ROOT="$REPO_ROOT"

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
  echo "usage: $0 [--manifest PATH] [--notices PATH] [--packaging-root PATH] [--self-test]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) [ $# -ge 2 ] || usage; MANIFEST="$2"; shift 2 ;;
    --notices)  [ $# -ge 2 ] || usage; NOTICES="$2";  shift 2 ;;
    --packaging-root) [ $# -ge 2 ] || usage; PACKAGING_ROOT="$2"; shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    -h|--help) usage ;;
    *) echo "::error::unknown argument '$1'" >&2; usage ;;
  esac
done

# `jq -r '<expr> // empty'` on a compact one-line backend object.
jget() { printf '%s' "$1" | jq -r "${2} // empty"; }

# --- packaging surface -----------------------------------------------------
#
# A channel's `packaging_paths` names the files in this repository that decide
# what that channel ships. The gate reads them so a backend's declared
# distribution strategy is checked against the packaging code instead of being
# believed. Three properties make that reading worth something:
#
#   * a glob matching NOTHING is an error. A scan over an empty set confirms
#     every claim equally, which is indistinguishable from no scan at all.
#   * this gate's OWN inputs — the manifest, the notices file, this script —
#     are excluded from every surface. All three name backends by id; a surface
#     built out of them would find its own text and report a padded floor.
#   * `packaging_owner: external-repo` is the only way to declare an empty
#     surface, so "we cannot see this channel from here" is a written-down
#     limitation rather than a silent absence.

# Absolute path of $1, without requiring the file itself to exist.
abspath() {
  local dir base
  dir="$(dirname "$1")"
  base="$(basename "$1")"
  if [ -d "$dir" ]; then
    printf '%s/%s\n' "$(cd "$dir" && pwd)" "$base"
  else
    printf '%s\n' "$1"
  fi
}

# Newline-separated absolute paths of the files this gate reads as its own
# input. Set once in main(); membership is what excludes a file from a surface.
GATE_INPUTS=""
is_gate_input() { printf '%s\n' "$GATE_INPUTS" | grep -Fxq -- "$1"; }

# Files a single packaging_paths glob expands to, relative to PACKAGING_ROOT.
# Prints nothing when the glob matches nothing (the caller reports that).
expand_pattern() {
  local pat="$1"
  (
    cd "$PACKAGING_ROOT" 2>/dev/null || exit 0
    shopt -s nullglob
    local f
    # Intentionally unquoted: this is the glob expansion. Entries containing
    # whitespace are rejected before they reach here.
    for f in $pat; do
      [ -f "$f" ] && printf '%s\n' "$f"
    done
  )
}

# The scannable files of channel $1 — every glob expanded, gate inputs removed.
# Prints nothing for an external channel, which is the point: an empty surface
# means "not corroborable here", and callers must treat it as such.
channel_surface_files() {
  local ch_id="$1" pat f
  while IFS= read -r pat; do
    [ -n "$pat" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      is_gate_input "$(abspath "$PACKAGING_ROOT/$f")" && continue
      printf '%s\n' "$f"
    done < <(expand_pattern "$pat")
  done < <(jq -r --arg c "$ch_id" '
    .channels[] | select(.id == $c) | (.packaging_paths // [])[]' "$MANIFEST")
}

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
    check_channel_surface "$ch" "$id"
  done < <(jq -c '.channels[]' "$MANIFEST")
}

# 2b. The channel's packaging surface must be real and non-vacuous, or declared
#     absent on purpose. Everything the backend-level corroboration concludes
#     rests on this, so it is validated up front and independently of any
#     backend.
check_channel_surface() {
  local ch="$1" id="$2"
  local n_paths pat matched kept f

  if [ "$(printf '%s' "$ch" | jq -r 'has("packaging_paths")')" != "true" ]; then
    err "channel '$id' has no 'packaging_paths'. It must name the files in this repository that decide what the channel ships, so a backend's declared strategy for it can be checked against the packaging code rather than believed. Use \"packaging_owner\": \"external-repo\" with an empty list if the deciding files genuinely live in another repository."
    return
  fi
  if [ "$(printf '%s' "$ch" | jq -r '.packaging_paths | type')" != "array" ]; then
    err "channel '$id' packaging_paths must be an array of path globs."
    return
  fi

  n_paths="$(printf '%s' "$ch" | jq -r '.packaging_paths | length')"
  if [ "$n_paths" -eq 0 ]; then
    if [ "$(jget "$ch" '.packaging_owner')" != "external-repo" ]; then
      err "channel '$id' declares an EMPTY packaging_paths without \"packaging_owner\": \"external-repo\". An empty surface means this gate can corroborate nothing about what the channel ships; that is only acceptable when the deciding files live in another repository, and it has to be stated rather than left to look like an oversight."
    fi
    return
  fi

  while IFS= read -r pat; do
    [ -n "$pat" ] || continue
    case "$pat" in
      *[[:space:]]*)
        err "channel '$id' packaging_paths entry '$pat' contains whitespace; the entries are expanded as shell globs, so a path with spaces would silently split into fragments that match nothing."
        continue ;;
    esac

    matched="$(expand_pattern "$pat")"
    if [ -z "$matched" ]; then
      err "channel '$id' packaging_paths entry '$pat' matches no file under '$PACKAGING_ROOT'. A glob that selects nothing is a scan that confirms every claim equally — fix the path or drop the entry."
      continue
    fi

    kept=""
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      is_gate_input "$(abspath "$PACKAGING_ROOT/$f")" && continue
      kept="$kept$f"
    done <<SURFACE
$matched
SURFACE
    if [ -z "$kept" ]; then
      err "channel '$id' packaging_paths entry '$pat' resolves only to this gate's own inputs (the manifest, the notices file, or the gate script). Those files name every backend by id, so a surface made of them would match its own text and report coverage it does not have."
    fi
  done < <(printf '%s' "$ch" | jq -r '.packaging_paths[]')
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
        "license_text_path","modifications","review","channels","sbom",
        "distribution_probe" ]
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
  check_distribution_claim "$b" "$id"
}

# Grep $2.. (executable names) across the newline-separated relative paths in
# $1, printing `file:line: text` for each hit. Case-insensitive fixed strings,
# deliberately over-broad: a false positive is a loud failure someone reads and
# resolves, a false negative is the silent hole this file exists to close.
probe_hits() {
  local files="$1" names="$2"
  [ -n "$files" ] || return 0
  [ -n "$names" ] || return 0
  # A pattern FILE rather than repeated `-e`: bash 3.2 (the macOS default, and
  # what a developer runs this under locally) errors on `${#arr[@]}` for an
  # empty array with `set -u`, so the array form fails on the exact edge case
  # this function has to survive.
  local pf f
  pf="$(mktemp)"
  printf '%s\n' "$names" > "$pf"
  # De-duplicated: several channels legitimately share a packaging file
  # (release.yml owns three), and reporting the same line once per channel
  # makes a single defect look like several.
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    ( cd "$PACKAGING_ROOT" && grep -n -i -F -f "$pf" -- "$f" 2>/dev/null ) \
      | head -2 | sed "s|^|  $f:|" || true
  done <<HITS
$(printf '%s\n' "$files" | sort -u)
HITS
  rm -f "$pf"
}

# ---------------------------------------------------------------------------
# 4. The distribution claim, checked against the packaging code.
#
# AAASM-5714 AC4 asks that SBOM/release checks cover any backend artifact AASM
# distributes. AASM currently distributes none — every channel's strategy is
# `system` or `not-distributed`. That answer is only worth something if it can
# be contradicted, so this check reads the files that decide what each channel
# ships and requires them to AGREE with the manifest, in both directions:
#
#   * a backend claiming non-distribution on every channel must appear NOWHERE
#     in the packaging surface. A row asserting "we ship nothing" while the
#     release pipeline names its binary is exactly the lie the row could
#     otherwise tell forever.
#   * a backend claiming `bundled`/`downloaded`/`source` must appear SOMEWHERE
#     in the surface of a channel it claims. Otherwise the claim is stale, or
#     the surface is declared wrong — either way nothing here is being checked.
#
# The two directions share one scanner, so neither verdict can be produced by a
# scanner that is not actually reading anything.
# ---------------------------------------------------------------------------
check_distribution_claim() {
  local b="$1" id="$2"
  local names name acq_files all_files hits ch_id strategy
  local scannable_acq=0 acquiring=0

  if [ "$(printf '%s' "$b" | jq -r '(.distribution_probe.binary_names // []) | length')" -eq 0 ]; then
    err "active backend '$id' has no 'distribution_probe.binary_names'. Without the executable name(s) AASM would have to write into its packaging code, this backend's per-channel strategy is an assertion nothing can contradict."
    return
  fi
  names="$(printf '%s' "$b" | jq -r '.distribution_probe.binary_names[]')"
  for name in $names; do
    case "$name" in
      *[[:space:]]*|"") err "active backend '$id' has a distribution_probe.binary_names entry containing whitespace; it must be a bare executable name." ; return ;;
    esac
  done

  acq_files=""
  all_files=""
  while IFS="=" read -r ch_id strategy; do
    [ -n "$ch_id" ] || continue
    # Skip ids the manifest does not declare — already reported as unknown.
    [ "$(jq -r --arg c "$ch_id" '[.channels[] | select(.id == $c)] | length' "$MANIFEST")" -eq 1 ] || continue
    local ch_files
    ch_files="$(channel_surface_files "$ch_id")"
    [ -z "$ch_files" ] || all_files="$all_files$ch_files
"
    case " $GATED_STRATEGIES " in
      *" $strategy "*)
        acquiring=$((acquiring + 1))
        if [ -n "$ch_files" ]; then
          scannable_acq=1
          acq_files="$acq_files$ch_files
"
        fi
        ;;
    esac
  done < <(printf '%s' "$b" | jq -r '(.channels // {}) | to_entries[] | "\(.key)=\(.value)"')

  if [ "$acquiring" -gt 0 ]; then
    # Acquisition claimed. Nothing to corroborate if every acquiring channel is
    # owned by another repository — that limit is declared on the channel.
    [ "$scannable_acq" -eq 1 ] || return
    hits="$(probe_hits "$acq_files" "$names")"
    if [ -z "$hits" ]; then
      err "active backend '$id' claims AASM acquires it on at least one channel, but none of those channels' packaging files reference any of its binary names ($(printf '%s' "$names" | tr '\n' ' ')). Either the claim is stale, or the file that actually does the packaging is not in that channel's packaging_paths — an unscannable claim is not a checked one."
    fi
    return
  fi

  # No acquiring channel: this backend claims AASM distributes nothing.
  if [ -z "$all_files" ]; then
    err "active backend '$id' claims non-distribution on every channel, but no channel offers a scannable packaging surface, so the claim rests on nothing. At least one channel must declare packaging_paths that resolve to real files."
    return
  fi
  hits="$(probe_hits "$all_files" "$names")"
  if [ -n "$hits" ]; then
    err "active backend '$id' declares 'system'/'not-distributed' on EVERY channel, but its binary name appears in the packaging surface:
$hits
A channel that names the backend's executable in the code that builds its artifact is distributing it. Correct the channel strategy (and take on the license, notice and SBOM obligations that follow), or correct the packaging."
  fi
}

# The distribution matrix, per backend. Every declared channel must get an
# explicit strategy — a missing channel is a silent gap, which is precisely the
# failure mode this ticket names.
check_backend_channels() {
  local b="$1" id="$2" license="$3"
  local missing unknown ch_id strategy dist allowlist_key allowed hint
  local bundled_anywhere=0 acq_channels=""

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
      *" $strategy "*) acq_channels="$acq_channels $ch_id" ;;
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
    check_notice_obligation "$b" "$id"
  fi
  if [ -n "$acq_channels" ]; then
    check_sbom_obligations "$b" "$id" "$acq_channels"
  fi
}

# The notice obligation attaches to REDISTRIBUTING the bytes, so it is tied to
# `bundled` alone: downloading an upstream artifact at install time does not
# make this project the redistributor.
check_notice_obligation() {
  local b="$1" id="$2"

  # Third-party notice. Matched against an EXACT `### <id>` heading rather than
  # a substring: this file also carries a "Pending: <id>" heading while a
  # backend is unimplemented, and a substring match would let that pending
  # placeholder satisfy the requirement for a real shipped backend.
  if [ ! -f "$NOTICES" ]; then
    err "backend '$id' is bundled but the notices file '$NOTICES' does not exist."
  elif ! grep -E '^#{2,4}[[:space:]]' "$NOTICES" | grep -qxiF -- "### $id"; then
    err "backend '$id' is bundled into a release artifact but $(basename "$NOTICES") has no '### $id' section. Retaining the upstream copyright and license text is an obligation of every license in the allowlist; the notice must ship with the bytes."
  fi

}

# SBOM accounting, per acquiring channel — AAASM-5714 AC4.
#
# Applies to `bundled`, `downloaded` AND `source`, not `bundled` alone: an
# installer that fetches a backend puts those bytes on the user's machine as
# surely as a tarball does, and an SBOM that omits it is wrong in the same way.
#
# Coverage differs sharply by channel — container images get an image-layer
# SBOM from buildx, the released binaries get nothing — so the status is stated
# per channel rather than once for the backend. `partial` and `none` are
# first-class answers: the point is to record the gap accurately, and a schema
# that only allowed `covered` would buy honesty-shaped text and nothing else.
#
# A `covered` claim is checked, not accepted: the channel's packaging surface
# must actually contain an SBOM-producing directive. That is what stops the
# strongest of the three statuses from being the cheapest to write.
check_sbom_obligations() {
  local b="$1" id="$2" acq_channels="$3"
  local sbom ch_id entry status mechanism surface

  sbom="$(jget "$b" '.sbom.covered_by')"
  [ -n "$sbom" ] || err "backend '$id' is bundled but has no 'sbom.covered_by' stating how the shipped artifact is accounted for in release/SBOM output. Note that SBOM generation today covers container images only — a binary bundled into a release tarball is not covered by it."

  for ch_id in $acq_channels; do
    entry="$(printf '%s' "$b" | jq -c --arg c "$ch_id" '.sbom.channel_coverage[$c] // empty')"
    if [ -z "$entry" ]; then
      err "backend '$id' is acquired by AASM on channel '$ch_id' but has no 'sbom.channel_coverage.$ch_id'. Coverage differs per channel — image layers are covered by buildx, released binaries are covered by nothing — so a single overall statement cannot be true of all of them."
      continue
    fi
    status="$(jget "$entry" '.status')"
    case "$status" in
      covered|partial|none) ;;
      *) err "backend '$id' sbom.channel_coverage.$ch_id.status is '${status:-<missing>}'; must be one of: covered, partial, none. 'partial' and 'none' are valid answers — an inaccurate 'covered' is not."
         continue ;;
    esac
    mechanism="$(jget "$entry" '.mechanism')"
    [ -n "$mechanism" ] || err "backend '$id' sbom.channel_coverage.$ch_id has no 'mechanism' naming what does (or does not) produce the SBOM for this channel."

    [ "$status" = "covered" ] || continue
    surface="$(channel_surface_files "$ch_id")"
    # An external channel cannot be checked from here; the channel's own
    # packaging_owner records that limit rather than this claim hiding it.
    [ -n "$surface" ] || continue
    if ! probe_sbom_generator "$surface"; then
      err "backend '$id' claims sbom.channel_coverage.$ch_id.status = 'covered', but no file in that channel's packaging surface contains an SBOM-producing directive. Claiming coverage that nothing produces is worse than declaring 'none': it stops anyone from looking."
    fi
  done
}

# True when some file in the newline-separated surface $1 mentions SBOM
# generation at all. Deliberately coarse — it distinguishes "something here
# produces an SBOM" from "nothing here does", which is the only distinction a
# `covered` claim needs to survive.
probe_sbom_generator() {
  local files="$1" f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if ( cd "$PACKAGING_ROOT" && grep -qiF -- "sbom" "$f" 2>/dev/null ); then
      return 0
    fi
  done <<SURFACE
$files
SURFACE
  return 1
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

  # --packaging-root points at the fixture tree, never at this repository: the
  # packaging-surface cases must be decided by files whose contents this test
  # writes, not by whatever the real release pipeline happens to contain today.
  set +e
  out="$(bash "$SELF" --manifest "$manifest" --notices "$notices" \
           --packaging-root "$ST_TMP" 2>&1)"
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

  # Fixture packaging tree. These two files are the "positive control located
  # elsewhere": they are NOT the manifest, the notices file or this script, so
  # a scan that reports a hit in them is reading real file contents rather than
  # its own definition. Their contents differ in exactly two ways, and both
  # differences decide a verdict below:
  #   * both reference `fixture-backend-bin`; neither references
  #     `absent-backend-bin` — that pair discriminates the distribution probe.
  #   * only `pkg/oss-image.yml` carries an SBOM-producing directive — that
  #     difference discriminates an honest `covered` claim from a bare one.
  mkdir -p "$ST_TMP/pkg"
  cat > "$ST_TMP/pkg/oss-release.yml" <<'PKG'
# self-test fixture — the packaging file for channel `oss-chan`.
# Ships the backend binary. This file deliberately carries no bill-of-materials
# directive of any kind, and must not gain one: its ABSENCE is what the
# "covered" claim on this channel is measured against.
steps:
  - run: tar -czf bundle.tar.gz aasm fixture-backend-bin
PKG
  cat > "$ST_TMP/pkg/oss-image.yml" <<'PKG'
# self-test fixture — the packaging file for channel `img-chan`.
# Bakes in the same binary AND generates an SBOM for the result.
steps:
  - uses: docker/build-push-action
    with:
      sbom: true
  - run: COPY fixture-backend-bin /usr/local/bin/fixture-backend-bin
PKG

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
    {
      "id": "oss-chan",
      "distribution": "oss",
      "packaging_paths": ["pkg/oss-release.yml"]
    },
    {
      "id": "img-chan",
      "distribution": "oss",
      "packaging_paths": ["pkg/oss-image.yml"]
    },
    {
      "id": "prop-chan",
      "distribution": "proprietary",
      "packaging_owner": "external-repo",
      "packaging_paths": []
    }
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
      "distribution_probe": { "binary_names": ["fixture-backend-bin"] },
      "sbom": {
        "covered_by": "self-test fixture",
        "channel_coverage": {
          "oss-chan":  { "status": "none",    "mechanism": "no SBOM is produced for this fixture channel" },
          "img-chan":  { "status": "covered", "mechanism": "buildx sbom: true on the image" },
          "prop-chan": { "status": "none",    "mechanism": "channel does not carry the backend" }
        }
      },
      "channels": {
        "oss-chan": "bundled",
        "img-chan": "bundled",
        "prop-chan": "not-distributed"
      }
    },
    {
      "id": "fixture-absent",
      "status": "active",
      "upstream_name": "Fixture Absent Backend",
      "version": "0.4.0",
      "source_url": "https://example.invalid/absent-0.4.0.tar.gz",
      "release_sha256": "$hex",
      "spdx_license": "MIT",
      "modifications": { "modified": false },
      "review": {
        "ticket": "AAASM-5714",
        "reviewed_at": "2026-08-13",
        "capability_evidence": "docs/release/isolation-backend-licensing.md"
      },
      "distribution_probe": { "binary_names": ["absent-backend-bin"] },
      "channels": {
        "oss-chan": "system",
        "img-chan": "system",
        "prop-chan": "not-distributed"
      }
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
    "$(mutate pending_without_tracking_ticket 'del(.backends[2].tracking_ticket)')"

  run_case "pending_carries_provenance" fail "carries provenance field" \
    "$(mutate pending_carries_provenance '.backends[2].version = "0.1.0"')"

  run_case "pending_carries_license" fail "carries provenance field" \
    "$(mutate pending_carries_license '.backends[2].spdx_license = "Apache-2.0"')"

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

  # --- the packaging surface must be real ------------------------------------
  # Everything the distribution-claim corroboration concludes rests on these
  # three properties. Each is one mutation of the accepted baseline.
  run_case "channel_without_packaging_paths" fail "has no 'packaging_paths'" \
    "$(mutate channel_without_packaging_paths 'del(.channels[0].packaging_paths)')"

  run_case "packaging_glob_matches_nothing" fail "matches no file" \
    "$(mutate packaging_glob_matches_nothing \
       '.channels[0].packaging_paths = ["pkg/does-not-exist-*.yml"]')"

  # A surface pointed at the gate's own inputs. `NOTICES.md` sits in the
  # fixture packaging root and IS one of those inputs, so the glob matches a
  # real file and is still rejected — the rejection is the exclusion working,
  # not the file being absent.
  run_case "packaging_surface_is_only_gate_input" fail "resolves only to this gate's own inputs" \
    "$(mutate packaging_surface_is_only_gate_input \
       '.channels[0].packaging_paths = ["NOTICES.md"]')"

  run_case "empty_surface_without_external_marker" fail "packaging_owner" \
    "$(mutate empty_surface_without_external_marker \
       'del(.channels[2].packaging_owner)')"

  # --- the distribution claim, checked against the packaging code ------------
  run_case "no_binary_names_to_probe_with" fail "distribution_probe.binary_names" \
    "$(mutate no_binary_names_to_probe_with 'del(.backends[0].distribution_probe)')"

  run_case "pending_carries_distribution_probe" fail "carries provenance field" \
    "$(mutate pending_carries_distribution_probe \
       '.backends[2].distribution_probe = {"binary_names": ["guess"]}')"

  # THE DISCRIMINATING PAIR. `fixture-absent` claims non-distribution on every
  # channel and the baseline accepts it, because `absent-backend-bin` appears in
  # neither fixture packaging file. The single mutation below changes only the
  # name being probed for — same row, same strategies, same packaging files —
  # and the verdict flips. A scanner that was not reading the files could not
  # tell these two apart.
  run_case "non_distribution_claim_contradicted_by_packaging" fail \
    "declares 'system'/'not-distributed' on EVERY channel" \
    "$(mutate non_distribution_claim_contradicted_by_packaging \
       '.backends[1].distribution_probe.binary_names = ["fixture-backend-bin"]')"

  # The other direction, also one mutation: `fixture-backend` still claims
  # `bundled`, but under a name nothing packages. A gate that only ever checked
  # for absence would pass this.
  run_case "acquisition_claimed_but_nothing_packages_it" fail \
    "none of those channels' packaging files reference" \
    "$(mutate acquisition_claimed_but_nothing_packages_it \
       '.backends[0].distribution_probe.binary_names = ["never-packaged-bin"]')"

  # A non-distribution claim with nothing to read it against is not a checked
  # claim. Marking every channel external leaves the scanner no files at all.
  run_case "non_distribution_claim_with_no_scannable_surface" fail \
    "rests on nothing" \
    "$(mutate non_distribution_claim_with_no_scannable_surface \
       '.channels |= map(.packaging_owner = "external-repo" | .packaging_paths = [])
        | .backends[0].channels |= map_values("not-distributed")
        | del(.backends[0].sbom)')"

  # --- notices + SBOM obligations on acquired bytes -------------------------
  run_case "bundled_without_sbom_statement" fail "sbom.covered_by" \
    "$(mutate bundled_without_sbom_statement 'del(.backends[0].sbom)')"

  run_case "acquiring_channel_without_coverage_row" fail "sbom.channel_coverage.oss-chan" \
    "$(mutate acquiring_channel_without_coverage_row \
       'del(.backends[0].sbom.channel_coverage["oss-chan"])')"

  run_case "sbom_status_not_a_recognised_answer" fail "must be one of: covered, partial, none" \
    "$(mutate sbom_status_not_a_recognised_answer \
       '.backends[0].sbom.channel_coverage["oss-chan"].status = "yes"')"

  run_case "sbom_coverage_row_without_mechanism" fail "has no 'mechanism'" \
    "$(mutate sbom_coverage_row_without_mechanism \
       'del(.backends[0].sbom.channel_coverage["oss-chan"].mechanism)')"

  # The moving control for the `covered` claim. The baseline already asserts
  # `covered` on `img-chan` and is accepted, because that channel's packaging
  # file carries an SBOM directive. The SAME word on `oss-chan`, whose
  # packaging file does not, must be rejected — so the verdict is decided by
  # the packaging surface and not by the word.
  run_case "sbom_claims_covered_with_no_generator_in_the_surface" fail \
    "no file in that channel's packaging surface contains an SBOM-producing directive" \
    "$(mutate sbom_claims_covered_with_no_generator_in_the_surface \
       '.backends[0].sbom.channel_coverage["oss-chan"].status = "covered"')"

  # A `downloaded` channel is accounted for exactly like a bundled one: the
  # bytes land on the user's machine either way. Before AAASM-5714 AC4 this
  # mutation passed, because only `bundled` carried an SBOM obligation.
  run_case "downloaded_channel_without_coverage_row" fail "sbom.channel_coverage.img-chan" \
    "$(mutate downloaded_channel_without_coverage_row \
       '.backends[0].channels["img-chan"] = "downloaded"
        | del(.backends[0].sbom.channel_coverage["img-chan"])')"

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
  # The files this gate reads as its own input, excluded from every packaging
  # surface below. All three name backends by id, so a surface built out of
  # them would find its own text.
  GATE_INPUTS="$(abspath "$MANIFEST")
$(abspath "$NOTICES")
$(abspath "$SELF")"
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
