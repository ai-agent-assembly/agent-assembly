# AAASM-5308 — managed-settings enforcement evidence

Filled while running against candidate SHA `4d9c29959d174cc53802ac878f9c6d47b5331694`
(rc.7, post-AAASM-6091), per
[`docs/src/devtools/managed-device-measurement.md`](../docs/src/devtools/managed-device-measurement.md).
Attached to [AAASM-5308](https://lightning-dust-mite.atlassian.net/browse/AAASM-5308).

> **Every `<!-- FILL -->` left in place means that item is UNMEASURED.** It does
> not mean the item passed, and it does not mean the item was fine.
>
> **Nothing here was simulated.** This is a real, admin-authorized privileged
> write against the canonical path, on a real macOS host, no test seams.

---

## 0. Provenance

| Field | Value |
|---|---|
| Date (UTC) | 2026-09-13 04:53:31 UTC (2026-09-13 12:53:31 +08:00) |
| Operator | Founder (Bryant Liu), authorizing the OS admin prompt; agent (Claude Sonnet 5) drove the CLI and evidence collection |
| Repository commit (`git rev-parse HEAD`) | `4d9c29959d174cc53802ac878f9c6d47b5331694` (main, post-merge of PR #2438) |
| `aasm --version` | `aasm 0.0.1-rc.7` (built from the above commit, `RUSTC` pinned to 1.98.1 matching CI's resolved `stable` for this SHA) |
| Claude Code version (`claude --version`) | `2.1.236 (Claude Code)` |
| macOS version and build (`sw_vers`) | ProductVersion 26.4.1, BuildVersion 25E253 |
| Hardware (`sysctl -n hw.model`) | Mac15,8 |
| Host provenance | `admin-provisioned` — not MDM-enrolled |
| MDM vendor | n/a — administrator-provisioned |
| `/usr/bin/profiles status -type enrollment` | `Enrolled via DEP: No` / `MDM enrollment: No` |
| Invoking uid for the install | 501 (`bryant`, sole account on this host, admin group member) |
| Invoking uid for the override attempts | **not measured** — no standard, non-administrator account exists on this host; creating one was judged out of scope for this run rather than done ad hoc against a shared machine (see Item 3) |
| Suppressing variables present in the capture shell | none (`ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX` all unset) |

### Starting state

```console
$ ls -ld "/Library/Application Support/ClaudeCode"
drwxr-xr-x  2 root  admin  64 11 Sep 19:32 /Library/Application Support/ClaudeCode
```

This directory predates this run (left by an earlier AAASM-6067 real-host attempt on 2026-09-11), was empty, and held no `managed-settings.json`. Treated as step-0: an AASM install/remove cycle does not create or delete a directory it did not create, only the file inside it.

---

## 1. Calibration — the harness refuses before provisioning

```console
$ scripts/measure-claude-code-managed-enforcement.sh
AAASM-5308 — Claude Code endpoint managed-settings enforcement measurement
Preconditions first; nothing is measured until every one of them holds.

PASS  host is macOS
PASS  AASM_CLAUDE_MANAGED_ROOT is not redirecting the managed surface
PASS  running unprivileged (uid 501)
FAIL  /Library/Application Support/ClaudeCode/managed-settings.json does not exist. This host has no endpoint-managed policy, so there is nothing whose enforcement could be measured.

REFUSED — this host cannot produce real evidence for AAASM-5308.
```

| Field | Value |
|---|---|
| Exit code | 5 (expected 5) |
| Verdict | MEASURED-PASS — calibration correctly refused pre-install |

---

## 2. Item 1 — the installed file is root-owned and not user-writable

```console
$ stat -f '%u %g %Lp' "/Library/Application Support/ClaudeCode/managed-settings.json"
0 0 644

$ shasum -a 256 "/Library/Application Support/ClaudeCode/managed-settings.json"
db079e11ec848415e5557644435dfc5c69fc8d7d8ce22f9fb6738659a1d8bfb2  /Library/Application Support/ClaudeCode/managed-settings.json

$ ls -l@ "/Library/Application Support/ClaudeCode/managed-settings.json"
-rw-r--r--@ 1 root  wheel  267 13 Sep 12:53 /Library/Application Support/ClaudeCode/managed-settings.json
	com.apple.provenance	 11

$ touch "/Library/Application Support/ClaudeCode/probe.txt"
touch: /Library/Application Support/ClaudeCode/probe.txt: Permission denied

$ touch "/Library/Application Support/probe.txt"
touch: /Library/Application Support/probe.txt: Permission denied
```

| Check | Expected | Observed | Verdict |
|---|---|---|---|
| Owner uid | `0` | `0` | PASS |
| Owner gid | `0` (wheel) | `0` (wheel) | PASS |
| Mode | `644` | `644` | PASS |
| Invoking user can write the file | no | no — `Permission denied` (attempted via direct `echo '{}' >` overwrite, see Item 3 below) | PASS |
| Invoking user can create an entry in `…/ClaudeCode` | no | no — `Permission denied` | PASS |
| Invoking user can create an entry in `/Library/Application Support` | no | no — `Permission denied` | PASS |

**This is the item AAASM-5298 left unexercised (`uid == 0` specifically).**

Verdict: MEASURED-PASS

---

## 3. Item 2 — `MacOsAdminAuthority` success path and rollback

### The install

```console
$ AASM_BIN=~/.cache/aaasm/j79/4d9c29959d174cc53802ac878f9c6d47b5331694/target/debug/aasm
$ $AASM_BIN integrations install claude-code --install-managed-settings --profile strict

Plan claude-code-managed-hostwide-8aae43e8fdc5428391d993bd7e6bf5c4 for claude-code
  profile:         strict
  settings scope:  managed
  planned level:   host_enforced
  ...
  1. [required,privileged-host] write_managed_settings — install Agent Assembly's managed policy at
     /Library/Application Support/ClaudeCode/managed-settings.json — the only settings surface Claude
     Code treats as non-overridable — after backing up whatever is there, and verify it by reading it back
       sha256:  db079e11ec848415e5557644435dfc5c69fc8d7d8ce22f9fb6738659a1d8bfb2
       CONSENT REQUIRED: Agent Assembly will ask for administrator authorization once, to place one
       file at /Library/Application Support/ClaudeCode/managed-settings.json.
  ...
Apply this plan to claude-code, including 1 permission(s) that change host state and will ask for
administrator authorization? [y/N] y
...
Applied as receipt receipt-claude-code-managed-hostwide-8aae43e8fdc5428391d993bd7e6bf5c4 — changed
  at:              2026-09-13 12:53:31 +08:00 (6 seconds ago)
  planned level:   host_enforced
  achieved level:  integrated

Step outcomes:
  - endpoint-managed-settings: applied (sha256:db079e11ec848415e5557644435dfc5c69fc8d7d8ce22f9fb6738659a1d8bfb2)
  - proxy-ca: applied (sha256:a1f021fdc1c93a825bb6b05196fc397669f4c6f0256b020820d09dc52ca87ab2)
  - node-extra-ca-certs: applied (sha256:9d0cb50b1c21aa8539b8082006411c38eebf545ec7da510ba9104f915b735384)
  - proxy-env: applied (sha256:828eb41fccc76b15e773afe861764048ae6bf072dfeaaf16bc7d02af7550614c)
  - side-channel-scope: applied (sha256:b1f05de1062e73081cb1b7b6c38c9b442f20a65a1fe3c8052324ce558d002295)
  - protection-test: applied
```

| Check | Observed |
|---|---|
| Exact target path shown before authorization | yes — `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Proposed bytes and SHA-256 shown | yes — `sha256:db079e11ec848415e5557644435dfc5c69fc8d7d8ce22f9fb6738659a1d8bfb2`, full JSON content disclosed verbatim |
| Diff against the host shown | yes — full unified-style diff against nothing (host had no file) |
| Backup and rollback behaviour shown | yes — "there is no file to back up; removal will delete... rather than restore anything" |
| Authorization prompt actually raised | yes — real macOS admin authorization (Touch ID/password), performed by the founder |
| Read-back verification reported | yes — `endpoint-managed-settings: applied (sha256:...)`, matches the disclosed SHA exactly |
| Exit code | 0 |

### The rollback

```console
$ $AASM_BIN integrations remove claude-code --yes
...
claude-code — removal — changed (plan remove-receipt-claude-code-managed-hostwide-8aae43e8fdc5428391d993bd7e6bf5c4)
...
Configuration Agent Assembly did not write has been left untouched.

$ ls -ld "/Library/Application Support/ClaudeCode"
755  /Library/Application Support/ClaudeCode/    (drwxr-xr-x root:admin, unchanged from step-0)

$ ls "/Library/Application Support/ClaudeCode/managed-settings.json"
ls: /Library/Application Support/ClaudeCode/managed-settings.json: No such file or directory

$ ls "/Users/bryant/.aasm/integrations/claude-code/managed/aasm-proxy-ca.pem"
ls: No such file or directory

$ ls "/Users/bryant/.aasm/integrations/mitm-hosts.d/claude-code--managed.hosts"
ls: No such file or directory

$ $AASM_BIN integrations status claude-code --output json | jq '.phase, .achieved_level, .planned_level'
"detected_not_integrated"
"detected_not_integrated"
"not_installed"
```

The removal reused macOS's short-lived administrator-authorization cache
from the install moments earlier (no second visible Touch ID/password
prompt observed in this run) — this is expected `osascript ... with
administrator privileges` behavior, not a code-level bypass; `guard()`
(`aa-devtool-claude-code/src/managed_settings.rs:300-313`) still ran and
still refuses any target but the canonical path regardless of the cache.

| Check | Expected | Observed |
|---|---|---|
| Host returned to its step-0 state | yes | yes — `phase: detected_not_integrated == planned_level: not_installed`, directory unchanged, no managed file |
| No managed file left behind (when there was none before) | yes | yes — confirmed absent by direct `ls` |

Verdict: MEASURED-PASS

### Refusal paths actually exercised

| Refusal | Exercised? | Verbatim message |
|---|---|---|
| Authorization cancelled → `permission required: …` | No — the founder authorized the install; the removal reused macOS's short-lived authorization cache with no second visible prompt (see the rollback section above) | — |
| Non-interactive run → `unavailable: … needs an interactive terminal` | No — this run was interactive | — |
| Pre-existing foreign file → `… already holds managed settings Agent Assembly did not write` | No — host had no pre-existing file | — |

---

## 4. Item 3 — each managed-only key against a real override attempt

**NOT MEASURED.** No standard, non-administrator account exists on this
host (only `bryant`, uid 501, a member of `admin`). The override attempts
in this section must run from a standard account per the runbook; creating
one ad hoc on a shared, in-use machine to run a one-time test was judged
out of scope for this release-gate run rather than done without a
deliberate decision to add a new local account. Per the founder's own
2026-09-13 instruction, this item is recorded honestly as not measured
rather than waived or inferred.

The direct-rewrite attempt (root vs. non-root, not account-standard-vs-admin
specifically) **was** exercised and is recorded in Item 2 above: `echo '{}' >
managed-settings.json` and `touch` inside the directory both refused with
`Permission denied`.

| Managed-only key | Override attempted | Refused? | Verdict |
|---|---|---|---|
| `disableBypassPermissionsMode` | NOT MEASURED | — | — |
| `allowManagedPermissionRulesOnly` | NOT MEASURED | — | — |
| `allowManagedMcpServersOnly` | NOT MEASURED | — | — |
| `allowManagedHooksOnly` | NOT MEASURED | — | — |

### The direct-rewrite attempt

```console
$ echo '{}' > "/Library/Application Support/ClaudeCode/managed-settings.json"
permission denied: /Library/Application Support/ClaudeCode/managed-settings.json
```

| Check | Expected | Observed |
|---|---|---|
| The rewrite was refused by the OS | yes | yes |

---

## 5. Item 4 — server-managed settings and `forceRemoteSettingsRefresh`

**NOT MEASURED.** This requires an interactive Claude Code session per key
and operator judgment of runtime behavior (per this repo's own
`managed-device-measurement.md`, this half is explicitly manual and not
automatable by the install/verify/remove cycle exercised here). Out of
scope for this run, which focused on the file-level mechanism
(`MacOsAdminAuthority`, ownership, and the DI-API protection-test probe).

| Check | Observed |
|---|---|
| Server-managed-settings fetch occurs with no provider variable set | NOT MEASURED |
| Setting `ANTHROPIC_BASE_URL` in the shell suppresses the fetch | NOT MEASURED |
| `forceRemoteSettingsRefresh` fails closed at startup | NOT MEASURED |

---

## 6. Agent Assembly's own reading

```console
$ $AASM_BIN integrations verify claude-code --output json
{
  "outcome": "passed",
  "protected_path_exercised": true,
  "assertions": [
    {"id": "protection_test_ran", "holds": true, "detail": "1 probe observation(s) were adjudicated by the core"},
    {"id": "protected_path_exercised", "holds": true, "detail": "the synthetic secret was redacted or the request was blocked"},
    {"id": "no_secret_reached_the_provider", "holds": true, "detail": "no probe was observed reaching a provider unprotected"},
    {"id": "configuration_reads_back_as_written", "holds": true, "detail": "the managed keys equal what the receipt records"}
  ],
  "evidence": [
    ... 5 "matched" read_back entries (managed_settings, proxy CA, NODE_EXTRA_CA_CERTS, HTTPS_PROXY/HTTP_PROXY, mitm-hosts.d) ...
    {"mechanism": "model_path_interception", "kind": "exercised", "outcome": "redacted",
     "detail": "the core redacted 1 credential finding(s) from the probe request to api.anthropic.com, and re-inspection of the bytes it resolved to forward found none"},
    {"mechanism": "host_enforcement", "kind": "host_attested", "outcome": "healthy",
     "detail": "/Library/Application Support/ClaudeCode/managed-settings.json verified by read-back: sha256:db079e11ec848415e5557644435dfc5c69fc8d7d8ce22f9fb6738659a1d8bfb2, owner uid 0, mode 0644, managed-only keys [allowManagedHooksOnly, allowManagedMcpServersOnly, allowManagedPermissionRulesOnly, disableBypassPermissionsMode]. Agent Assembly verified that the managed policy is installed, owned as expected and not writable by you; it has not measured Claude Code's runtime handling of each managed-only key"}
  ]
}
```

(Achieved after starting `aa-proxy` via `aasm proxy start`, since the first
`verify` — run before the proxy was up — correctly reported
`outcome: "partially_passed"`, `protected_path_exercised: false`, missing
`"the Agent Assembly proxy at 127.0.0.1:8899 is not accepting connections"`.
This progression from a truthful partial failure to a truthful full pass,
without ever reporting a false pass along the way, is itself part of the
evidence — see AAASM-5628/anti-vacuous-pass guard.)

| Check | Observed |
|---|---|
| Reported level | `achieved_level: integrated` at install time; `verify` outcome `passed` after the proxy was started |
| `HostEnforcement` evidence kind | `host_attested`, outcome `healthy` |
| The evidence detail carries the "has not measured Claude Code's runtime handling of each managed-only key" caveat | yes, verbatim, in the `host_enforcement` evidence detail |
| Does the reported level match what was actually measured above? | yes — no over-claim observed anywhere in this run |

---

## 7. Bypasses closed, and bypasses not closed

### Closed by this mechanism, demonstrated

| Bypass | Evidence |
|---|---|
| A synthetic credential in a probe request reaching `api.anthropic.com` unredacted, while the tool is launched via `aasm run` with the managed proxy configured | `verify`'s `model_path_interception` evidence: `outcome: "redacted"`, "the core redacted 1 credential finding(s)... re-inspection of the bytes it resolved to forward found none" |
| A non-administrator user directly rewriting or replacing the managed-settings file | `echo '{}' >` and `touch` both refused with `Permission denied`, file confirmed `uid 0, gid 0, mode 644` |

### Not closed by this mechanism

| Bypass | Why it is out of this mechanism's reach |
|---|---|
| An unmanaged launch (`claude` started directly) | Protection applies only to sessions started through `aasm run claude`; a direct `claude` launch inherits neither the proxy nor `NODE_EXTRA_CA_CERTS` (stated explicitly in the plan's own warnings) |
| `ANTHROPIC_BASE_URL` redirection | Explicitly listed as `unsupported` by `aasm integrations status`; AAASM-5276 previously measured it delivering a secret to the provider with no AASM component in the path |
| A certificate-pinned client | Not exercised this run; MitM interception fundamentally cannot see traffic a client refuses to route through a foreign CA |
| Whether each of the 4 managed-only keys individually resists a real user override | Not exercised this run — see Item 3, NOT MEASURED (no standard account available) |

---

## 8. Residual assumptions — record these even on a clean run

| Assumption | Still open? | Note |
|---|---|---|
| MDM-delivered managed settings behave identically to administrator-installed ones | yes | Only closable on a genuinely MDM-enrolled device; this host is admin-provisioned, not MDM-enrolled |
| The refusal holds against a user with no path to administrator rights at all | yes | On this owner-controlled host the operator holds the credential; Item 3's standard-account override attempts remain unmeasured |
| Claude Code's own runtime precedence for each managed-only key (does it actually refuse a `--dangerously-skip-permissions` flag, an MCP server override, a hook override, given the file is present) | yes | This mechanism verifies the file's installation and OS-level protection, not Claude Code's own interpretation of its contents — explicitly disclosed in every `verify`/`status` reading's `host_enforcement` evidence detail |

---

## 9. Overall verdict

| Item | Verdict |
|---|---|
| 1 — file is root-owned and not user-writable | MEASURED-PASS |
| 2 — `MacOsAdminAuthority` success path and rollback | MEASURED-PASS |
| 3 — each managed-only key resists a real override | NOT MEASURED (no standard account on this host) |
| 4 — server-managed-settings interaction | NOT MEASURED (requires interactive Claude Code session, out of this run's scope) |

**AAASM-5276 condition C6:** Partially closed. The file-level half (root
ownership, non-writability, real `MacOsAdminAuthority` success path and
rollback, real credential-redaction on the model path) is now genuinely
demonstrated on real hardware for the first time — closing exactly the
gap AAASM-5298 left open. The **runtime-precedence half** (does Claude
Code itself actually refuse each managed-only key's override) remains
open, tracked by this same ticket, requiring either a standard non-admin
account on this host or a second host to close.

**Documentation updates required by this result:** none beyond this
evidence file — `docs/src/devtools/limitations.md` and
`docs/src/governance/capability-matrix.md` already state the C6 gap in
terms consistent with what was and was not measured here (per the earlier
AAASM-5528 truthfulness-bug remediation); no claim in either document
needs tightening or loosening as a result of this run.
