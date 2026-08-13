# Measuring managed-settings enforcement

[AAASM-5276](https://lightning-dust-mite.atlassian.net/browse/AAASM-5276)
condition **C6** is half closed. The *install* half shipped with
[AAASM-5298](https://lightning-dust-mite.atlassian.net/browse/AAASM-5298): Agent
Assembly can place Claude Code's endpoint managed-settings file under explicit
administrator authorization and verify it by read-back. The *enforcement* half —
whether the managed-only keys actually resist a user override — is
[AAASM-5308](https://lightning-dust-mite.atlassian.net/browse/AAASM-5308) and is
**unmeasured on every host, including this project's own**.

This page is the procedure that closes it. It exists so that the measurement is
mechanical when a suitable host is available, and so that nobody is tempted to
approximate it when one is not.

> **The one rule.** Nothing on this page may be simulated. A mechanism that
> produces something *resembling* managed enforcement — a redirected managed
> root, a hand-written file at a path Claude Code does not read, a `sudo`-owned
> copy somewhere else — is not weak evidence, it is **not evidence**. Record it
> as unmeasured and stop. The claim `Host Enforced` exists precisely to be the
> one claim that is never inferred.

---

## What is actually blocking this, and what is not

The blocker is routinely described as "we need an MDM-managed device". That is
stricter than what AAASM-5308 asks for, whose scope line reads *"a managed/MDM-
enrolled macOS device, **or one where the file can be provisioned with
administrator consent**"*. The distinction matters, because the two halves of
the gap have very different costs.

The mechanism under measurement is a plain filesystem path. Agent Assembly's
privileged step is one `osascript … with administrator privileges` running one
`/usr/bin/install -m 644 -o root -g wheel`
(`aa-devtool-claude-code/src/managed_settings.rs`). No configuration profile, no
`/Library/Managed Preferences`, no MDM API and no preference domain is involved
anywhere in the path. An administrator-provisioned host therefore produces a
**byte-identical, ownership-identical, mode-identical** artifact to an
MDM-enrolled one, and neither Agent Assembly's attestation nor — as far as the
mechanism goes — Claude Code's own precedence resolution has anything to
distinguish them by.

| Alternative to a managed device | Verdict | Why |
|---|---|---|
| Populating the canonical path on an unmanaged host with **administrator consent** | **Real evidence** for the file-level and authority items | It is the same privileged write, producing the same root-owned file at the same path. Nothing about it is a simulation. This is the path AAASM-5308's own scope line allows. |
| Populating the canonical path **without** elevation, or populating a redirected `AASM_CLAUDE_MANAGED_ROOT` | **Not evidence** | A redirected root is a test seam: the adapter anchors its ownership check to the invoking user rather than root, and the file is not the one Claude Code reads. A non-root file at the canonical path fails the ownership check and is refused. |
| A locally installed **configuration profile** (`profiles`, or a `.mobileconfig` approved in System Settings) | **Not applicable** | Claude Code's managed settings are not delivered as a managed preference domain in this mechanism, so a profile does not populate them. Manual profile installation is also user-approved on current macOS, which makes it a weaker provenance than the administrator write, not a stronger one. |
| A **second, standard (non-administrator) account** on the same host | **Real evidence** for the "the user cannot rewrite it" half | The refusal is enforced by the OS against a real account boundary. This is the closest an owner-controlled machine gets to the fleet threat model. |
| A **VM** | **Real evidence, same as the host case**, with one caveat | A macOS VM is a real macOS host; the write and the refusal are real. It buys reversibility (snapshot, roll back), not a different class of evidence. |
| A **`sudo`-provisioned file** placed by hand rather than by `aasm` | **Partial** | It closes the ownership item, and it is a legitimate way to set up items 3 and 4. It does **not** exercise `MacOsAdminAuthority`, so item 2 stays open until the install is driven through `aasm`. |

### What genuinely still requires a managed device

Two things, and only two:

1. **A host where the developer cannot become an administrator at all.** On an
   owner-controlled Mac the operator always holds the administrator credential,
   so "an attacker with the developer's UID cannot escalate" is *assumed*, not
   demonstrated. A standard second account measures the OS refusal honestly, but
   the same human still holds the password. This is a **scope** limit on how far
   the resulting claim reaches, not a measurement that was skipped.
2. **Whether MDM-delivered settings behave identically to administrator-installed
   ones.** The mechanism gives no reason to expect a difference, but "no reason
   to expect" is an assumption and must be recorded as one until a genuinely
   enrolled device is measured.

Everything else — root ownership in production, `MacOsAdminAuthority`'s success
path and rollback, and each managed-only key against a real override attempt —
is measurable on a host the owner controls, and is blocked on **owner
authorization to perform a real privileged write**, not on hardware.

---

## Prerequisites

| Requirement | Why it is required | How to check |
|---|---|---|
| A macOS host you are willing to modify | The privileged write is real and changes host state | `sw_vers` |
| macOS 13 or newer (record the exact version) | The refusal behaviour of `/Library/Application Support` is a host fact, not a constant | `sw_vers -productVersion` |
| An administrator credential on that host | `osascript … with administrator privileges` has to be answerable | you know it, or you do not have one |
| A **second, standard (non-administrator)** local account | Item 3a is measured from an account that is not an admin | System Settings → Users & Groups |
| Claude Code installed, version recorded | The override attempts need a real binary. AAASM-5276 measured `2.1.220` | `claude --version` |
| An `aasm` build from a recorded commit | The evidence has to name what produced it | `aasm --version`, `git rev-parse HEAD` |
| The Agent Assembly runtime running with the DI-API enabled | `aasm integrations` is a DI-API client | `AA_DEVINT_ENABLED`, see [configuration](../quick-start/configuration.md) |
| A shell with **no** `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_USE_BEDROCK` or `CLAUDE_CODE_USE_VERTEX` set | Any of them suppresses Claude Code's server-managed-settings fetch entirely, so item 4 would be measuring the suppression | `env \| grep -E 'ANTHROPIC_\|CLAUDE_CODE_USE'` |
| Nothing already at `/Library/Application Support/ClaudeCode/managed-settings.json` | Agent Assembly refuses to overwrite managed settings it did not write, and that refusal is itself correct behaviour | `ls -l "/Library/Application Support/ClaudeCode"` |

If a prerequisite cannot be met, record it as unmet and record the items it
blocks as unmeasured. Do not substitute for it.

---

## The procedure

Start a copy of the evidence template
(`verification-reports/AAASM-5308-managed-enforcement-evidence-template.md`)
before you begin, and paste **verbatim** output into it as you go. Output that
was retyped or summarised is not evidence.

### Step 0 — record the starting state

```console
$ sw_vers
$ sysctl -n hw.model
$ /usr/bin/profiles status -type enrollment
$ id -u
$ claude --version
$ aasm --version
$ git rev-parse HEAD
$ ls -ld "/Library/Application Support/ClaudeCode"
```

The last command is expected to say `No such file or directory`. If it does not,
stop: something else already owns that path, and step 2 will correctly refuse.

### Step 1 — confirm the measurement harness refuses *before* provisioning

```console
$ ./scripts/measure-claude-code-managed-enforcement.sh
```

Expected — and this is the passing result for this step:

```text
PASS  host is macOS
PASS  AASM_CLAUDE_MANAGED_ROOT is not redirecting the managed surface
PASS  running unprivileged (uid 501)
FAIL  /Library/Application Support/ClaudeCode/managed-settings.json does not exist. …

REFUSED — this host cannot produce real evidence for AAASM-5308.
Nothing was measured and nothing was written.
```

Exit code **5**. A script that produced results here would be a script whose
later results mean nothing, so running it first is the calibration.

### Step 2 — drive the privileged install through `aasm`

This is the step that measures items 1 and 2. Run it from a terminal, as the
administrator-capable account, and **read the disclosure before authorizing it**.

```console
$ aasm integrations install claude-code --install-managed-settings --profile strict
```

| Outcome | What it means | Exit |
|---|---|---|
| The plan prints the target path, the reason, the exact bytes and their SHA-256, the diff, the backup and the rollback, then asks for confirmation, then raises the macOS authorization prompt, then reports a receipt whose managed step fingerprint is `sha256:…` | **Pass.** Items 1 and 2 are measured. | `0` |
| `permission required: administrator authorization to write /Library/Application Support/ClaudeCode/managed-settings.json was not granted (…)` | You cancelled the prompt, or the credential was rejected. Nothing was written. This is a *correct* refusal — re-run and authorize. | non-zero |
| `unavailable: administrator authorization needs an interactive terminal (…)` | You are not on a TTY. **Environment problem**, not a finding. Re-run from a real terminal. | non-zero |
| `unavailable: no administrator authorization mechanism is available on this host (…)` | Not macOS, or the target was not the canonical path. Check `AASM_CLAUDE_MANAGED_ROOT`. **Environment problem.** | non-zero |
| `… already holds managed settings Agent Assembly did not write; …` | Something else owns that file. **Correct refusal**, and the file was left byte-identical. Decide out-of-band whether to move it aside; that decision is yours, not the tool's. | non-zero |
| `the managed settings read back from … are not what was authorized: …` | **A genuine finding.** The write was rolled back and no receipt was issued. Capture everything and stop — this is a defect, not an environment problem. | non-zero |

Then confirm the file independently of `aasm`, because a tool verifying itself
is not corroboration:

```console
$ ls -l@ "/Library/Application Support/ClaudeCode/managed-settings.json"
$ stat -f '%u %g %Lp' "/Library/Application Support/ClaudeCode/managed-settings.json"
$ shasum -a 256 "/Library/Application Support/ClaudeCode/managed-settings.json"
```

`stat` must print `0 0 644`. Anything else — in particular any owner uid other
than `0` — is a finding against item 1 and must be recorded as a failure, not
retried until it looks right.

### Step 3 — run the measurement script for real

```console
$ ./scripts/measure-claude-code-managed-enforcement.sh --out AAASM-5308-evidence.md
```

Now it should reach the recording section. A pass looks like every gate line
reading `PASS`, followed by `NOTE` lines for the host facts, and ending in the
banner:

```text
C6 IS NOT CLOSED BY THIS SCRIPT.
```

That banner is not a caveat to skim past. The script measures the file-level
half; the four key verdicts are still empty in the evidence file.

**Telling a finding from an environment problem here:**

| Exit | Meaning | Finding or environment? |
|---|---|---|
| `2` | not macOS | environment |
| `3` | `AASM_CLAUDE_MANAGED_ROOT` is redirecting | environment — unset it |
| `4` | running as root | environment — the measurement is what a *non-root* user cannot do |
| `5` | the managed file is not there | environment — step 2 did not complete |
| `6` | the file is not owned by uid 0 | **finding** against item 1 |
| `7` | the mode lets others write it | **finding** against item 1 |
| `8` | the invoking user can rewrite or replace it | **finding** — `Host Enforced`'s own definition does not hold |
| `9` | no managed-only keys in the document | **finding** — the elevation had no enforcement purpose |

### Step 4 — the override attempts, from a standard account

Log in as the **standard, non-administrator** account. This is item 3, and it is
the one AAASM-5298 was originally filed to answer.

For each managed-only key, attempt the override the key exists to refuse, and
record what happened. Attempt it from the tool's own configuration — a user
settings file, a project settings file, and a command-line flag where one
exists — never by editing the managed file itself.

| Key | The override to attempt | Recorded as a pass when |
|---|---|---|
| `disableBypassPermissionsMode` | Launch with `--dangerously-skip-permissions`, and separately set `"defaultMode": "bypassPermissions"` in `~/.claude/settings.json` | Both are refused and permission prompting remains in force |
| `allowManagedPermissionRulesOnly` | Add a permissive `permissions.allow` entry in `~/.claude/settings.json` and in `<project>/.claude/settings.json` | Neither widens what the tool will do |
| `allowManagedMcpServersOnly` | Add an MCP server in user scope and in project scope | Neither is loaded |
| `allowManagedHooksOnly` | Add a hook in user scope and in project scope | Neither runs |

Also attempt the direct rewrite, and record the OS's refusal verbatim:

```console
$ echo '{}' > "/Library/Application Support/ClaudeCode/managed-settings.json"
```

Expected: `Permission denied`. If this succeeds, item 3a has **failed** and
`Host Enforced`'s entry criteria must be tightened rather than the result
footnoted.

> A key whose override attempt you did not actually run is **unmeasured**. It is
> not "presumably fine because the other three held", and it is not "documented
> as non-overridable, so pass". Anthropic's documentation is the claim under
> test, not the evidence for it.

### Step 5 — the server-managed-settings interaction

From a shell with none of the suppressing variables set, record whether the
server-managed-settings fetch occurs, and whether `forceRemoteSettingsRefresh`
fails closed at startup. Then set `ANTHROPIC_BASE_URL` in the shell and record
that the fetch is suppressed — that trap is documented, and confirming it is
part of the measurement.

### Step 6 — reverse it, and prove the reversal

```console
$ aasm integrations remove claude-code
$ ls -ld "/Library/Application Support/ClaudeCode"
```

The host must end up as step 0 found it: if there was no file before, there is
none now. Restoration is **semantics-exact, not byte-exact** — see
[Limitations](limitations.md#restore-is-semantics-exact-not-byte-exact) — so
compare meaning, not formatting. A rollback that leaves the managed file in
place is a finding.

---

## Recording the result

Fill in
`verification-reports/AAASM-5308-managed-enforcement-evidence-template.md`
completely and attach it to AAASM-5308. Then:

* Update [Limitations](limitations.md#the-managed-settings-file-can-be-installed-its-enforcement-is-still-unmeasured),
  [Protection levels](protection-levels.md#host-enforced) and the
  [capability matrix](../governance/capability-matrix.md) with **what was
  measured, and only what was measured**.
* List the bypasses the mechanism closed **separately** from those it did not.
* If any managed-only key did not resist its override, tighten `Host Enforced`'s
  entry criteria. Do not footnote it.
* Record the two residual assumptions from
  [above](#what-genuinely-still-requires-a-managed-device) explicitly, even on a
  clean run. A measurement taken on an owner-controlled host closes the
  behaviour question; it does not close the fleet-scope question.

## What stays open even after a perfect run

* Whether MDM-delivered managed settings behave identically to
  administrator-installed ones.
* Whether the refusal holds against a user who has no path to administrator
  rights at all, which is the population `Host Enforced` is ultimately a claim
  about.
* Everything outside this mechanism: an unmanaged launch, a certificate-pinned
  client, a redirected base URL. Those are
  [Limitations](limitations.md), and no managed-settings key addresses them.

## References

* [Protection levels → Host Enforced](protection-levels.md#host-enforced)
* [Limitations and known bypasses](limitations.md)
* [`aasm integrations` CLI](cli.md) · [CLI reference](../cli/integrations.md)
* [ADR 0030 — Developer Integration boundaries and trust model](../adr/0030-developer-integration-boundaries-and-trust-model.md)
* `scripts/measure-claude-code-managed-enforcement.sh`
* `aa-devtool-claude-code/src/managed_settings.rs`
