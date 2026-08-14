# Policy artifact for the confined arm

`allow-all.yaml` is the policy `launchers/sandlock.sh` passes to
`aasm run exec --isolation process --policy ...`. It grants every tool
unconditionally at the **policy** layer, matching this repository's own
"nothing is restricted, deliberately" example
(`aasm run` prints this exact document when a launch refuses on an
unconfigured policy).

## What AAASM-5713 did not verify

`--isolation process` accepts an isolation *class*, not a filesystem or
network grant list — the concrete grant a confined launch gets is derived by
`aa_isolation::lower_policy` from the effective policy's canonical projection
(`aa-cli/src/commands/run.rs`'s `IsolationPlan`, `aa-policy`'s
`PolicyResolution`). This spike did not read that lowering closely enough to
state with confidence which filesystem paths or network destinations
`allow-all.yaml` above actually grants a confined child process under
Sandlock — only that the policy resolves to `permissive` and the launch
proceeds to backend selection.

That matters for the benchmark: every workload family needs write access to
its scratch directory and read access to the repository root at minimum, and
`https_loopback` additionally needs an egress path to the harness's own
loopback TLS server. If `allow-all.yaml`'s lowering does not grant those by
default, workload families will fail under confinement for a **policy or
lowering** reason rather than a genuine backend limitation — and
METHODOLOGY.md's compatibility classification (`policy-change` /
`backend-change` / `unavoidable-upstream`) depends on telling the two apart
correctly.

Whoever runs the confined arm for real should confirm — by reading
`aa_isolation::lower_policy` and `IsolationPlan`, or by running one family
under confinement and inspecting the resulting `EnforcementPlan` /
`IsolationReport` — what `allow-all.yaml` actually grants on the target host
before trusting a compatibility failure's classification.
