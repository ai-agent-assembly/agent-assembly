# aasm receipt

Verify a locally-stored execution receipt: a versioned record of one `aasm
run` launch, binding the exact policy, spec, backend and achieved capability
evidence that launch produced, with a content digest that detects tampering
since it was written.

> **Availability.** `aasm receipt` sits inside the same `devtool` region as
> `aasm run` (`aa-cli/src/commands/mod.rs`) — nothing publishes a receipt, so
> nothing needs to read one, outside a source build. See [CLI Reference —
> Overview](overview.md#command-groups).

## Synopsis

```text
aasm receipt verify <PATH> [--json]
```

## Where receipts come from

Every governed `aasm run` launch that establishes an execution-isolation
boundary writes one receipt at the end of the run, to
`${AASM_STATE_DIR:-~/.aasm}/execution-receipts/<recorded_at>-<run_id>.execution-receipt.json`,
owner-only (`0700` directory, `0600` file). A run that never establishes a
boundary — `--isolation` not requested, or the launch refused before
spawning — writes no receipt: there is nothing an execution receipt could
truthfully describe about a program that never started inside a boundary.

Writing the receipt never affects the launch's own exit code. If the receipt
cannot be assembled or written, `aasm run` prints a warning to stderr and the
launched program's own exit code is returned exactly as it always was.

## What receipt integrity proves — and does not prove

This is the one section in this reference that matters most; read it before
trusting a `verify` result for anything.

**A holding seal proves:** the receipt's content has not changed since `aasm
run` wrote it, and the canonicalization the digest was taken over is the one
this build reads.

**A holding seal does NOT prove:**

- **Origin.** The seal is a `sha256` content digest over the receipt's body —
  **not a cryptographic signature, and not a MAC**. There is no key anywhere
  in this design. Anyone with read/write access to the file — which, on a
  single-user machine, is anyone who can already read the process that wrote
  it — can rewrite the body and recompute a seal that holds over the new
  content just as easily as `aasm` did. A holding seal answers "has this file
  changed since it was written", not "did `aasm` write this". Turning this
  into a real guarantee needs a key custody decision and a verifier that does
  not share the writer's host — a SaaS ingestion design, which this ticket
  does not build.
- **The identity of the agent the run is attributed to.** `asserted_identity`
  is exactly that: asserted by the caller, never authenticated by anything in
  this launch path.
- **That every property recorded as unmeasured actually held.** A domain
  whose evidence basis is weaker than `decision` can never carry a prevention
  claim — `verify` checks this independently of the seal, every time, so a
  hand-edited receipt with a freshly recomputed, holding seal still fails
  verification if its claims outrun its own recorded evidence.
- **Which fields the seal itself covers.** The seal digests the receipt's
  *body* only. The schema identifier and the seal's own metadata
  (`sealed_by`, `sealed_at_unix_secs`, `canonical_form`) sit outside the
  digest. Mutating the schema string alone does not break the seal — but
  `verify` flags it as a defect regardless, because `verify` always runs both
  checks and reports failure if either one fails.

If you need "which process on which host, cryptographically, wrote this
record" — this command does not answer that question, and nothing in this
release claims it does.

## Exit codes

`aasm receipt verify` uses this crate's existing binary success/failure
convention (every other `aasm` subcommand's `ExitCode::SUCCESS` /
`ExitCode::FAILURE`) rather than a third status: `0` when the receipt's seal
holds **and** it carries no validation defect, `1` otherwise — for a seal
mismatch, a validation defect, or a file that could not be read or parsed.
Run with `--json` to distinguish those causes programmatically; the human
output also separates "seal: …" from "defects: …" on separate lines so the
two checks are never collapsed into one verdict.

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `<PATH>` | path | _(required)_ | Path to the stored receipt file. |
| `--json` | flag | off | Emit a machine-readable JSON report instead of a human-readable summary. |

## Examples

```console
$ aasm receipt verify ~/.aasm/execution-receipts/1758912345-run-abc123.execution-receipt.json
seal: holds
defects: none
trustworthy: true (the seal covers content integrity since write, never origin — see `aasm receipt verify --help` / docs/src/cli/receipt.md)
```

```console
$ aasm receipt verify --json ./tampered-receipt.json
{"seal":"mismatch","seal_detail":null,"defects":[],"trustworthy":false}
```

## What a receipt records

A receipt binds, per launch: the resolved policy (a digest of the canonical
document, never the document's own free text), the execution spec (program
basename, argument count and an argv digest — never the argument values), the
selected backend's identity and platform boundary, every capability domain's
requested/achieved/claim/evidence-basis outcome (all ten domains, always, in
a fixed order), capability leases (by id and digest, never by basis reason or
scope selector), credential *names* the child inherited or had removed
(never values), measured-versus-asserted host facts (a Linux native launch's
kernel release is *measured*; the same field on a macOS-hosted VM launch is
*unmeasured*, honestly — the guest, not the host, ran the process), and the
launch's actual termination (self-exited, wall-clock ceiling, or a forwarded
operator signal).

Nothing in a receipt is ever a credential value. Every field that carries
runtime text (as opposed to a token from a closed, built-in vocabulary) is
screened for credential-shaped content and, on a match, withheld entirely —
recorded as withheld, never partially redacted, never silently dropped.

## Deferred — not built in this ticket

- Real cryptographic signing, key custody, or a SaaS verification service.
- Receipt-based replay or forensic reconstruction of a run.
- A digest of the guest/runtime image a backend launched — no backend
  computes one today; the field exists in the schema and is always `None`.
- A workspace-transaction diff binding — `aa-workspace-tx` has no consumer
  today; the field exists and is always `None`.
- Retention or garbage collection of stored receipts — one file is written
  per confined run and nothing prunes them.
- A receipt for a launch refused before it started — there is nothing such a
  receipt could truthfully describe.
