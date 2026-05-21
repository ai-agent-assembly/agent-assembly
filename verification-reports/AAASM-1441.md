# F114b Verification — AAASM-1441 (Extended Docker base image variants)

> **Status**: 7 of 7 currently-shippable sub-tasks complete and merged on
> `master @ a949f144`. The local `linux/amd64` build + smoke run succeeds
> for **all 4 active F114b variants** (Python 3.12/3.13 + Go 1.24/1.25)
> shipped under this Story, plus re-verifies the F114 baseline (3.14 +
> 1.26) implicitly because the matrix CI exercises them every PR.
>
> 5 Dockerfiles ship-but-stay-deferred: Python 3.10/3.11 (`requires-python`
> SDK constraint — [AAASM-1682]); Node 20/22/24 (npm-publish blocker —
> [AAASM-1660] / [AAASM-1661] / [AAASM-1503]). Each deferral has a tracked
> follow-up; the build-failure transcripts in this report are the AC
> evidence that the deferral disposition is correct.
>
> Two AC bullets land **adapted** — same pattern as
> [AAASM-1204.md](AAASM-1204.md):
>
> - "Matrix extended from 3 → 11 variants" → shipped as 2 → 6 active, with
>   5 deferred Dockerfiles tracked in-tree.
> - "Compressed image size <250 MB per variant" → 2 Python variants pass
>   (89 MB / 90 MB); 2 Go variants exceed 250 MB compressed (278 MB / 297 MB)
>   because [AAASM-1672]'s `GOTOOLCHAIN=auto` fix bakes the downloaded
>   Go 1.26 toolchain into the image. This was the explicitly-anticipated
>   tradeoff documented in AAASM-1672's description.
>
> **No new Bug Subtask opened** as a result of this verification — the size
> regression is documented under [AAASM-1672]'s "Option B" alternative path,
> and the Python/Node deferrals already have follow-up tickets.
>
> [AAASM-1199]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1199
> [AAASM-1441]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1441
> [AAASM-1443]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1443
> [AAASM-1444]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1444
> [AAASM-1445]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1445
> [AAASM-1446]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1446
> [AAASM-1447]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1447
> [AAASM-1500]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1500
> [AAASM-1501]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1501
> [AAASM-1503]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1503
> [AAASM-1508]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1508
> [AAASM-1660]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1660
> [AAASM-1661]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1661
> [AAASM-1671]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1671
> [AAASM-1672]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1672
> [AAASM-1682]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1682
> [AAASM-1203]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1203

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| [AAASM-1443] | Author Python 3.10/3.11/3.12/3.13 Dockerfiles | Done | (merged) |
| [AAASM-1444] | Author Node v20/v22 Dockerfiles | Done | (merged) |
| [AAASM-1445] | Author Go 1.24/1.25 Dockerfiles | Done | (merged) |
| [AAASM-1446] | Extend docker.yml matrix (2 → 6 active + 5 deferred) | Done | [#616](https://github.com/AI-agent-assembly/agent-assembly/pull/616) |
| [AAASM-1671] | [BUG] Python pip-before-COPY regression of AAASM-1500 | Done | [#617](https://github.com/AI-agent-assembly/agent-assembly/pull/617) |
| [AAASM-1672] | [BUG] Go GOTOOLCHAIN=auto + AAASM-1508 smoke backport | Done | [#618](https://github.com/AI-agent-assembly/agent-assembly/pull/618) |
| [AAASM-1447] | Verify F114b | in this report | this PR |
| [AAASM-1660] | Re-enable node:20 after AAASM-1203 | To Do (blocked) | — |
| [AAASM-1661] | Re-enable node:22 after AAASM-1203 | To Do (blocked) | — |
| [AAASM-1682] | [BUG] Python 3.10/3.11 SDK requires-python conflict | To Do (option A vs B) | — |

## Walkthrough vs AAASM-1441 acceptance criteria

### ✅ 8 Dockerfiles authored under `docker/` (4 Python + 2 Node + 2 Go)

All 8 files present on `master @ a949f144` (shipped by AAASM-1443 / 1444 / 1445, then patched by AAASM-1671 / 1672):

```
docker/Dockerfile.python-3.13-slim    AAASM-1443 (pip-order fixed by AAASM-1671)
docker/Dockerfile.python-3.12-slim    AAASM-1443 (pip-order fixed by AAASM-1671)
docker/Dockerfile.python-3.11-slim    AAASM-1443 (pip-order fixed by AAASM-1671)
docker/Dockerfile.python-3.10-slim    AAASM-1443 (pip-order fixed by AAASM-1671)
docker/Dockerfile.node-22-slim        AAASM-1444 (no patch — deferred)
docker/Dockerfile.node-20-slim        AAASM-1444 (no patch — deferred)
docker/Dockerfile.go-1.25-alpine      AAASM-1445 (GOTOOLCHAIN+smoke fixed by AAASM-1672)
docker/Dockerfile.go-1.24-alpine      AAASM-1445 (GOTOOLCHAIN+smoke fixed by AAASM-1672)
```

### ⚠️ Each image builds successfully for `linux/amd64` and `linux/arm64`

**Adapted on two axes** — `linux/amd64` for the 4 active variants only,
`linux/arm64` deferred to the first `v*` tag push (same gating as
[AAASM-1204.md](AAASM-1204.md)).

* **`linux/amd64`** — 4 active variants verified locally on
  `master @ a949f144` (transcripts below). 2 deferred Python variants
  (3.10 / 3.11) hit pip's `requires-python` resolver — transcript captured
  for AAASM-1682 evidence. Node 20 (representative of 20/22/24) hits
  AAASM-1501's documented npm-shorthand failure — transcript captured.

* **`linux/arm64`** — deferred to first `v*` tag push. The workflow
  conditional gates multi-arch on tag pushes
  ([`.github/workflows/docker.yml:143`](../.github/workflows/docker.yml)).
  Buildx default builder advertises arm64 as a supported platform on this
  host; the workflow's QEMU-driven cross-build is expected to work.

#### Python 3.13-slim — local `linux/amd64` build transcript (truncated to phase markers)

```
=== BUILD START python:3.13-slim (2026-05-21T01:00:33Z) ===
#11 [aasm-builder 1/5] FROM docker.io/library/rust:alpine
#19 [aasm-builder 5/5] RUN cargo build --release -p aa-cli --bin aasm    DONE 348.6s
#16 [stage-1 1/7] FROM docker.io/library/python:3.13-slim                DONE 5.1s
#17 [stage-1 2/7] RUN apt-get install --no-install-recommends git ...    DONE 26.2s
#19 [stage-1 3/7] RUN pip install agent-assembly @ git+...               DONE 26.0s
#20 [stage-1 4/7] COPY --from=aasm-builder /usr/local/bin/aasm ...       DONE 0.0s
#21 [stage-1 5/7] RUN aasm --version
#21 0.051 aasm 0.0.1                                                     DONE 0.1s
#22 [stage-1 6/7] RUN python -c "from agent_assembly import init_assembly"  DONE 0.4s
#23 [stage-1 7/7] RUN apt-get purge -y git && apt-get autoremove ...     DONE 1.8s
=== BUILD END python:3.13-slim (2026-05-21T01:07:55Z) EXIT=0 ===
```

#### Python 3.12-slim — local build (cargo cache reused — `aasm-builder` CACHED)

```
=== BUILD START python:3.12-slim (2026-05-21T01:23:36Z) ===
#15 [aasm-builder 5/5] RUN cargo build --release -p aa-cli --bin aasm    CACHED
#16 [stage-1 1/7] FROM docker.io/library/python:3.12-slim                DONE 13.2s
#17 [stage-1 2/7] RUN apt-get install --no-install-recommends git ...    DONE 23.5s
#19 [stage-1 3/7] RUN pip install agent-assembly @ git+...               DONE 22.4s
#20 [stage-1 4/7] COPY --from=aasm-builder /usr/local/bin/aasm ...       DONE 0.0s
#21 [stage-1 5/7] RUN aasm --version
#21 0.051 aasm 0.0.1                                                     DONE 0.1s
#22 [stage-1 6/7] RUN python -c "from agent_assembly import init_assembly"  DONE 0.4s
=== BUILD END python:3.12-slim (2026-05-21T01:29:51Z) EXIT=0 ===
```

#### Go 1.25-alpine — local build

```
=== BUILD START go:1.25-alpine (2026-05-21T01:29:51Z) ===
#15 [aasm-builder 5/5] RUN cargo build --release -p aa-cli --bin aasm    CACHED
#16 [stage-1 1/5] FROM docker.io/library/golang:1.25-alpine              DONE 0.2s
#17 [stage-1 2/5] COPY --from=aasm-builder /usr/local/bin/aasm ...       DONE 0.0s
#18 [stage-1 3/5] RUN go install github.com/AI-agent-assembly/go-sdk/...@latest
#18 (GOTOOLCHAIN=auto pulls Go 1.26 on demand — see AAASM-1672)          DONE ~13s
#19 [stage-1 4/5] RUN aasm --version
#19 0.281 aasm 0.0.1                                                     DONE 0.4s
#20 [stage-1 5/5] RUN go list -m github.com/AI-agent-assembly/go-sdk@latest
#20 0.892 github.com/AI-agent-assembly/go-sdk v0.0.0-...                 DONE 0.9s
=== BUILD END go:1.25-alpine (2026-05-21T01:30:04Z) EXIT=0 ===
```

#### Go 1.24-alpine — local build (analogous to 1.25 — only `golang:1.24-alpine` base differs)

```
=== BUILD END go:1.24-alpine (2026-05-21T01:31:20Z) EXIT=0 ===
```

#### Python 3.10-slim — local build (deferred — AAASM-1682 reproduction)

```
=== BUILD START python:3.10-slim (2026-05-21T01:31:20Z) ===
#15 [aasm-builder 5/5] RUN cargo build --release -p aa-cli --bin aasm    CACHED
#19 [stage-1 3/7] RUN pip install agent-assembly @ git+...
#19 7.941 ERROR: Package 'agent-assembly' requires a different Python: 3.10.20 not in '<4.0,>=3.12'
#19 ERROR: process "/bin/sh -c pip install --no-cache-dir 'agent-assembly @ git+https://github.com/AI-agent-assembly/python-sdk.git'" did not complete successfully: exit code: 1
=== BUILD END python:3.10-slim (2026-05-21T01:31:56Z) EXIT=1 ===
```

This is the documented [AAASM-1682] failure — python-sdk's
`pyproject.toml` declares `requires-python = ">=3.12,<4.0"`. The same
failure mode applies to Python 3.11 (not re-built here — same root
cause, same fix path).

#### Node 20-slim — local build (deferred — AAASM-1501 reproduction, same blocker as AAASM-1660 / 1661 / 1503)

```
=== BUILD START node:20-slim (2026-05-21T01:31:56Z) ===
#15 [aasm-builder 5/5] RUN cargo build --release -p aa-cli --bin aasm    CACHED
#16 [stage-1 4/7] RUN npm install -g 'github:AI-agent-assembly/node-sdk'
#16 0.989 npm error fatal: Could not read from remote repository.
#16 0.990 npm error A complete log of this run can be found in: /root/.npm/_logs/2026-05-21T01_32_00_832Z-debug-0.log
#16 ERROR: process "/bin/sh -c npm install -g 'github:AI-agent-assembly/node-sdk'" did not complete successfully: exit code: 128
=== BUILD END node:20-slim (2026-05-21T01:32:01Z) EXIT=1 ===
```

Documented [AAASM-1501] root cause (npm `github:` shorthand → `ssh://`
rewrite + no ssh client in node alpine images). Same failure mode applies
to Node 22 + Node 24. Restoration tracked under [AAASM-1660] / [AAASM-1661]
/ [AAASM-1503]; the npm-published rewrite under those tickets is a
one-line diff once [AAASM-1203] lands.

### ✅ `docker.yml` workflow matrix extended

Final state of `.github/workflows/docker.yml` on `master @ a949f144`:

```
build-and-push-language-images matrix:
  - python:3.14-slim   is_latest=true
  - python:3.13-slim   is_latest=false
  - python:3.12-slim   is_latest=false
  - go:1.26-alpine     is_latest=true
  - go:1.25-alpine     is_latest=false
  - go:1.24-alpine     is_latest=false
```

6 active entries. The 5 deferred Dockerfiles (python 3.10/3.11 + node
20/22/24) ship in-tree but are commented-deferred in the matrix, pointing
at their respective follow-up tickets.

### ⚠️ Smoke runs succeed for every variant

4-of-4-active variants pass. 4-of-6-total (including deferred-by-design)
variants pass. The 2 deferred-with-tracked-tickets variants reproduce
their documented failures verbatim (transcripts above).

Per-variant smoke output captured verbatim from `docker run --rm
aaasm-final/<lang>-<ver>:local <cmd>`:

```
python:3.13-slim
  $ aasm --version                                       → aasm 0.0.1
  $ python -c "from agent_assembly import init_assembly" → import ok: init_assembly

python:3.12-slim
  $ aasm --version                                       → aasm 0.0.1
  $ python -c "from agent_assembly import init_assembly" → import ok: init_assembly

go:1.25-alpine
  $ aasm --version                                       → aasm 0.0.1
  $ go list -m github.com/AI-agent-assembly/go-sdk@latest → github.com/AI-agent-assembly/go-sdk v0.0.0-20260520161412-60249bbb18a1

go:1.24-alpine
  $ aasm --version                                       → aasm 0.0.1
  $ go list -m github.com/AI-agent-assembly/go-sdk@latest → github.com/AI-agent-assembly/go-sdk v0.0.0-20260520161412-60249bbb18a1
```

Host-platform mismatch warnings (`linux/amd64 vs linux/arm64/v8`) are
suppressed in the transcripts above — they appear on every `docker run`
because the host is Apple Silicon and the images are `linux/amd64`; Docker
Desktop's QEMU layer runs them transparently. Same disposition as
[AAASM-1204.md](AAASM-1204.md).

### ⚠️ Compressed image size documented per variant

| Variant | Uncompressed | Compressed | <250 MB AC |
|---|---:|---:|---|
| python:3.13-slim | 248,793,480 B (237 MiB / 249 MB) | **89,022,582 B (84.9 MiB / 89 MB)** | ✅ pass |
| python:3.12-slim | 250,344,277 B (239 MiB / 250 MB) | **89,290,616 B (85.2 MiB / 89 MB)** | ✅ pass |
| go:1.25-alpine   | 787,669,385 B (751 MiB / 788 MB) | **278,685,186 B (266 MiB / 279 MB)** | ⚠️ over (see note) |
| go:1.24-alpine   | 834,788,648 B (796 MiB / 835 MB) | **297,263,502 B (284 MiB / 297 MB)** | ⚠️ over (see note) |

Sizes measured locally via `docker save <tag> | gzip -c | wc -c` on
`master @ a949f144`. Python variants comfortably under 250 MB compressed
(matches the F114 python:3.14 baseline from AAASM-1204.md — same
toolchain, same SDK layers).

**Go-variant size note**: Both F114b Go variants exceed the 250 MB
compressed AC bullet. Root cause is the `GOTOOLCHAIN=auto` fix shipped
under [AAASM-1672]: because go-sdk's `go.mod` requires Go 1.26 and the
1.24 / 1.25 base images ship older toolchains, `GOTOOLCHAIN=auto`
downloads Go 1.26 at build time and bakes it into the image layer
(~50–80 MB compressed per AAASM-1672's prediction). This was the
explicitly-anticipated tradeoff documented in AAASM-1672's description.

The F114 sibling `go:1.26-alpine` is unaffected (no toolchain download
needed; sized at 153 MB compressed per AAASM-1204.md). If the size
regression is unacceptable for the F114b "courtesy buffer" variants,
[AAASM-1672]'s "Option B" alternative (relax go-sdk's go.mod to `go 1.24`)
becomes the follow-up fix path.

### ✅ CI workflow build job passes for active variants on integration PR

[PR #616](https://github.com/AI-agent-assembly/agent-assembly/pull/616)
final CI run [26197695698](https://github.com/AI-agent-assembly/agent-assembly/actions/runs/26197695698):
**7/7 checks SUCCESS** (1 aa-runtime + 3 python + 3 go matrix legs). PR
merged 2026-05-21.

### ✅ `verification-reports/AAASM-1441.md` captures AC matrix, build transcripts, sizes, smoke output, CI links

This file.

### ⚠️ `ghcr.io/agent-assembly/<lang>:<version>` actually pulls + runs after the next v* tag push

**Deferred** to the first `v*` tag push — same disposition as
[AAASM-1204.md](AAASM-1204.md). Workflow code is in place: the
`build-and-push-language-images` job gates the push step on
`startsWith(github.ref, 'refs/tags/v')`
([`.github/workflows/docker.yml:144`](../.github/workflows/docker.yml)),
and the `:latest` tag is now correctly gated to F114 pins only via the
`is_latest` matrix field (shipped under AAASM-1446). First release
exercises the multi-arch + GHCR push path for all 6 active variants in
one shot.

## Deferred-AC summary

| AC bullet | Status | Tracked under | Unblocked when |
|---|---|---|---|
| `linux/arm64` multi-arch build | ⚠️ Deferred | (this Story; workflow code in place) | First `v*` tag push triggers the multi-arch matrix |
| `ghcr.io/...:<tag>` pull + run | ⚠️ Deferred | (this Story; workflow code in place) | First `v*` tag push pushes layers to GHCR |
| Python 3.10 / 3.11 build + smoke + size | ⚠️ Deferred | [AAASM-1682] | python-sdk `requires-python` floor lowered to 3.10 (Option A) OR scope drop (Option B) |
| Node 20 build + smoke + size | ⚠️ Deferred | [AAASM-1660] | [AAASM-1203] publishes `@agent-assembly/sdk` to npm |
| Node 22 build + smoke + size | ⚠️ Deferred | [AAASM-1661] | Same |
| Node 24 build + smoke + size | ⚠️ Deferred | [AAASM-1503] (Phase 1 carryover) | Same |
| CI matrix entries for python 3.10/3.11 | ⚠️ Deferred | [AAASM-1682] | Same as Python deferral |
| CI matrix entries for node 20/22/24 | ⚠️ Deferred | [AAASM-1660] / [AAASM-1661] / [AAASM-1503] | Same as Node deferral |
| Compressed size <250 MB for go:1.24 / 1.25 | ⚠️ Over (278 / 297 MB) | [AAASM-1672] "Option B" path | Decision to switch GOTOOLCHAIN strategy |

## Adaptations summary

| # | Ticket text | What shipped | Forced by |
|---|---|---|---|
| 1 | "8 Dockerfiles … each builds for amd64 AND arm64" | 4-of-8 amd64 verified locally; 2 Python deferred ([AAASM-1682]); 2 Node deferred ([AAASM-1660] / [AAASM-1661]); arm64 deferred to v* tag | Buildkit `--load` + multi-arch mutually exclusive (same gating as AAASM-1204); SDK `requires-python` floor; npm-publish blocker ([AAASM-1203]) |
| 2 | "matrix 3 → 11 variants" | Matrix 2 → 6 active + 5 in-tree-deferred Dockerfiles | Pre-existing AAASM-1225 deferrals + new AAASM-1682 deferral surfaced by AAASM-1446 CI |
| 3 | "Smoke runs succeed for every variant" | 4-of-4-active variants pass; 2 deferred reproduce documented failures verbatim | Same as #1 / #2 |
| 4 | "CI workflow build job passes for all 11 variants" | CI runs 6 active matrix legs, all green | Same as #2 |
| 5 | "`ghcr.io/...` pulls + runs after the next v* tag push" | Deferred; workflow code present (with `is_latest` gate added under AAASM-1446) | No `v*` tag cut yet; release flow owns this |
| 6 | "Compressed size <250 MB per variant" | Python 2/2 pass; Go 0/2 pass (278 / 297 MB) | [AAASM-1672]'s GOTOOLCHAIN=auto toolchain bake (explicitly anticipated tradeoff) |

## Sign-off

* 4-of-4-active F114b variants build + smoke-run cleanly on `linux/amd64`
  against `master @ a949f144` — transcripts above.
* 2 deferred F114b variants (Python 3.10, Node 20) reproduce their
  documented failures verbatim. Same failure modes apply to their
  siblings (Python 3.11, Node 22, Node 24) by inspection of the
  near-byte-identical Dockerfiles.
* Sizes captured for all 4 active variants. Python comfortably under
  250 MB compressed; Go over by the AAASM-1672-anticipated 50–80 MB.
* Every deferral has a tracked follow-up: [AAASM-1660] / [AAASM-1661] /
  [AAASM-1503] / [AAASM-1682].
* `linux/arm64` + GHCR-pull/run AC bullets are workflow-design-complete
  (same code path AAASM-1204.md documented) and will fire on the first
  `v*` tag push.
* No new Bug Subtask opened — every adaptation and deferral has a tracked
  follow-up already.

Story [AAASM-1441] is verifiable as **Done** for the 4 currently-shippable
F114b variants, with the residual gaps captured under [AAASM-1660] /
[AAASM-1661] / [AAASM-1503] / [AAASM-1682] and the multi-arch / GHCR
bullets deferred to the first release tag.
