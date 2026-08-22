# Risk mapper — `qa/risk-rules.yaml` + `scripts/qa/map-risk.py`

Deterministic path/surface -> risk/lane/journey mapping (AAASM-5829),
consumed by `/release-qa-gate` (AAASM-5821) to derive a conservative starting
verification scope from the verification manifest's changed-path delta
(AAASM-5825), referencing stable journey IDs from `qa/golden-journeys.yaml`
(AAASM-5824) rather than redefining journeys.

## Rules

See `qa/risk-rules.yaml` for the full rule set — HIGH-risk surfaces mirror
[the release QA policy](../docs/src/qa/release-qa-policy.md)'s list (auth,
policy, proxy, IPC/runtime trust, secrets, persistence, privileged execution,
release/supply-chain). Keep the two in sync when either changes.

**Composition**: multiple matching rules union their `lanes`/`journeys` and
take the **highest** risk tier — never first-match-wins.

**Excludes** (`target/`, `node_modules/`, `dist/`, `.venv/`, generated docs
output) never independently drive scope, even under an otherwise HIGH-risk
crate — build output is not source.

**Fallback**: an unmapped path is never LOW and never silently dropped — it
takes the declared conservative fallback (MEDIUM) with an explicit note.

**P0 is unconditional**: every mapper run's output includes the full P0
journey set regardless of what matched, because AAASM-5820 makes P0 mandatory
independently of the mapper — the mapper only ever *adds* P1/P2 journeys on
top of P0, it cannot narrow below it.

## Usage

```bash
python3 scripts/qa/map-risk.py <changed-path> [<changed-path> ...]
# or, from a verification manifest:
python3 scripts/qa/map-risk.py --manifest .qa/verification-manifest.json
```

## Verified representative cases (AAASM-5829 AC)

Run against realistic file-level paths (as `git diff --name-only` produces):

| Input | Result |
|---|---|
| `aa-gateway/src/policy/mod.rs`, `aa-proxy/src/lib.rs`, `aa-auth/src/lib.rs` | `HIGH`, lanes `functional+reliability+security` |
| `aa-sdk-client/src/client.rs` | `HIGH`, lanes `functional+security` |
| `dashboard/src/App.tsx` | `MEDIUM`, lanes `design+functional` |
| `docs/src/qa/release-qa-policy.md` | `LOW`, lane `docs` (+ J21 doc-integrity journey) |
| `scripts/release-readiness.sh`, `.github/workflows/release.yml` | `HIGH`, lanes `reliability+security` |
| `some/totally/unmapped/path.rs` | `MEDIUM` fallback, `fallback_used: true` |
| `target/debug/foo.rlib` (exclude negative control) | `excluded: true`, contributes no scope |
| `docs/src/foo.md` + `aa-proxy/src/lib.rs` together (union negative control) | `HIGH` overall — the low-risk docs path does not dilute the high-risk proxy path |

Every case's overall `journeys` list includes the full P0 set
(`J04,J08,J17,J19,J21,J24,J41,J53,J56,J59`) regardless of which case ran.
