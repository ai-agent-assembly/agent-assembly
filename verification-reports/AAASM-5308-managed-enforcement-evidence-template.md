# AAASM-5308 — managed-settings enforcement evidence

Fill this in while running
[`docs/src/devtools/managed-device-measurement.md`](../docs/src/devtools/managed-device-measurement.md),
then attach it to
[AAASM-5308](https://lightning-dust-mite.atlassian.net/browse/AAASM-5308).

> **Every `<!-- FILL -->` left in place means that item is UNMEASURED.** It does
> not mean the item passed, and it does not mean the item was fine. An item you
> did not run is recorded as `NOT MEASURED`, with the reason.
>
> **Nothing here may be simulated.** If a step could not be run on a real host
> against the canonical path, say so. A plausible-looking transcript is worse
> than an empty cell, because an empty cell cannot be mistaken for evidence.

---

## 0. Provenance

| Field | Value |
|---|---|
| Date (UTC) | <!-- FILL --> |
| Operator | <!-- FILL --> |
| Repository commit (`git rev-parse HEAD`) | <!-- FILL --> |
| `aasm --version` | <!-- FILL --> |
| Claude Code version (`claude --version`) | <!-- FILL --> |
| macOS version and build (`sw_vers`) | <!-- FILL --> |
| Hardware (`sysctl -n hw.model`) | <!-- FILL --> |
| Host provenance | `mdm-enrolled` / `admin-provisioned` — <!-- FILL --> |
| MDM vendor (or `n/a — administrator-provisioned`) | <!-- FILL --> |
| `/usr/bin/profiles status -type enrollment` | <!-- FILL --> |
| Invoking uid for the install (`id -u`) | <!-- FILL --> |
| Invoking uid for the override attempts | <!-- FILL --> (must be a **standard**, non-administrator account) |
| Suppressing variables present in the capture shell | <!-- FILL --> (`ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, or `none`) |

### Starting state

```console
<!-- FILL: verbatim output of `ls -ld "/Library/Application Support/ClaudeCode"` before anything was done -->
```

---

## 1. Calibration — the harness refuses before provisioning

```console
$ ./scripts/measure-claude-code-managed-enforcement.sh
<!-- FILL: verbatim -->
```

| Field | Value |
|---|---|
| Exit code | <!-- FILL --> (expected `5`) |
| Verdict | <!-- FILL --> |

---

## 2. Item 1 — the installed file is root-owned and not user-writable

```console
$ stat -f '%u %g %Lp' "/Library/Application Support/ClaudeCode/managed-settings.json"
<!-- FILL: verbatim -->

$ shasum -a 256 "/Library/Application Support/ClaudeCode/managed-settings.json"
<!-- FILL: verbatim -->

$ ls -l@ "/Library/Application Support/ClaudeCode/managed-settings.json"
<!-- FILL: verbatim -->
```

| Check | Expected | Observed | Verdict |
|---|---|---|---|
| Owner uid | `0` | <!-- FILL --> | <!-- FILL --> |
| Owner gid | `0` (wheel) | <!-- FILL --> | <!-- FILL --> |
| Mode | `644` | <!-- FILL --> | <!-- FILL --> |
| Invoking user can write the file | no | <!-- FILL --> | <!-- FILL --> |
| Invoking user can create an entry in `…/ClaudeCode` | no | <!-- FILL --> | <!-- FILL --> |
| Invoking user can create an entry in `/Library/Application Support` | no | <!-- FILL --> | <!-- FILL --> |

**This is the item AAASM-5298 left unexercised (`uid == 0` specifically).**

Verdict: <!-- FILL: MEASURED-PASS / MEASURED-FAIL / NOT MEASURED + reason -->

---

## 3. Item 2 — `MacOsAdminAuthority` success path and rollback

### The install

```console
$ aasm integrations install claude-code --install-managed-settings --profile strict
<!-- FILL: verbatim, INCLUDING the consent disclosure printed before authorization -->
```

| Check | Observed |
|---|---|
| Exact target path shown before authorization | <!-- FILL --> |
| Proposed bytes and SHA-256 shown | <!-- FILL --> |
| Diff against the host shown | <!-- FILL --> |
| Backup and rollback behaviour shown | <!-- FILL --> |
| Authorization prompt actually raised | <!-- FILL --> |
| Read-back verification reported | <!-- FILL --> |
| Exit code | <!-- FILL --> |

### The rollback

```console
$ aasm integrations remove claude-code
<!-- FILL: verbatim -->

$ ls -ld "/Library/Application Support/ClaudeCode"
<!-- FILL: verbatim -->
```

| Check | Expected | Observed |
|---|---|---|
| Host returned to its step-0 state | yes | <!-- FILL --> |
| No managed file left behind (when there was none before) | yes | <!-- FILL --> |

Verdict: <!-- FILL -->

### Refusal paths actually exercised (optional but valuable)

| Refusal | Exercised? | Verbatim message |
|---|---|---|
| Authorization cancelled → `permission required: …` | <!-- FILL --> | <!-- FILL --> |
| Non-interactive run → `unavailable: … needs an interactive terminal` | <!-- FILL --> | <!-- FILL --> |
| Pre-existing foreign file → `… already holds managed settings Agent Assembly did not write` | <!-- FILL --> | <!-- FILL --> |

---

## 4. Item 3 — each managed-only key against a real override attempt

Run every attempt from the **standard, non-administrator** account.

| Managed-only key | Override attempted (exact command / file + content) | Refused? | Verbatim evidence | Verdict |
|---|---|---|---|---|
| `disableBypassPermissionsMode` — `--dangerously-skip-permissions` | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `disableBypassPermissionsMode` — `"defaultMode": "bypassPermissions"` in user settings | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `allowManagedPermissionRulesOnly` — user-scope `permissions.allow` | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `allowManagedPermissionRulesOnly` — project-scope `permissions.allow` | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `allowManagedMcpServersOnly` — user-scope MCP server | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `allowManagedMcpServersOnly` — project-scope MCP server | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `allowManagedHooksOnly` — user-scope hook | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |
| `allowManagedHooksOnly` — project-scope hook | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |

### The direct-rewrite attempt

```console
$ echo '{}' > "/Library/Application Support/ClaudeCode/managed-settings.json"
<!-- FILL: verbatim; expected `Permission denied` -->
```

| Check | Expected | Observed |
|---|---|---|
| The rewrite was refused by the OS | yes | <!-- FILL --> |

> If any key did **not** resist its override, `Host Enforced`'s entry criteria
> must be tightened, not footnoted. Record which criterion changes and why.

---

## 5. Item 4 — server-managed settings and `forceRemoteSettingsRefresh`

| Check | Observed |
|---|---|
| Server-managed-settings fetch occurs with no provider variable set | <!-- FILL --> |
| Setting `ANTHROPIC_BASE_URL` in the shell suppresses the fetch | <!-- FILL --> |
| `forceRemoteSettingsRefresh` fails closed at startup | <!-- FILL --> |
| Verbatim evidence | <!-- FILL --> |

---

## 6. Agent Assembly's own reading

```console
$ aasm integrations status claude-code --output json
<!-- FILL: verbatim -->
```

| Check | Observed |
|---|---|
| Reported level | <!-- FILL --> |
| `HostEnforcement` evidence kind | <!-- FILL --> |
| The evidence detail carries the "has not measured Claude Code's runtime handling of each managed-only key" caveat | <!-- FILL --> |
| Does the reported level match what was actually measured above? | <!-- FILL --> |

---

## 7. Bypasses closed, and bypasses not closed

State these **separately**. A single combined list is how an inferred bypass
becomes a demonstrated one by adjacency.

### Closed by this mechanism, demonstrated

| Bypass | Evidence |
|---|---|
| <!-- FILL --> | <!-- FILL --> |

### Not closed by this mechanism

| Bypass | Why it is out of this mechanism's reach |
|---|---|
| An unmanaged launch (`claude` started directly) | <!-- FILL --> |
| `ANTHROPIC_BASE_URL` redirection | <!-- FILL --> |
| A certificate-pinned client | <!-- FILL --> |
| <!-- FILL --> | <!-- FILL --> |

---

## 8. Residual assumptions — record these even on a clean run

| Assumption | Still open? | Note |
|---|---|---|
| MDM-delivered managed settings behave identically to administrator-installed ones | <!-- FILL --> | Only closable on a genuinely enrolled device |
| The refusal holds against a user with no path to administrator rights at all | <!-- FILL --> | On an owner-controlled host the operator holds the credential |
| <!-- FILL --> | <!-- FILL --> | <!-- FILL --> |

---

## 9. Overall verdict

| Item | Verdict |
|---|---|
| 1 — file is root-owned and not user-writable | <!-- FILL --> |
| 2 — `MacOsAdminAuthority` success path and rollback | <!-- FILL --> |
| 3 — each managed-only key resists a real override | <!-- FILL --> |
| 4 — server-managed-settings interaction | <!-- FILL --> |

**AAASM-5276 condition C6:** <!-- FILL: closed / still open, and precisely which part -->

**Documentation updates required by this result:** <!-- FILL -->
