# reference — provider-specific fallback sequences

Worked instances of `security.md`'s tool/API fallback sequence (native
tool/MCP → already-authenticated official CLI → documented official API
via a safe client → escalate). Jira/Atlassian and GitHub below are
grounded in real usage found in this workspace; Cloudflare and GCP have
no equivalent dogfooded example and are marked pattern-only — do not read
those two sections as verified workspace history, only as the pattern to
validate against each provider's actual current docs when first
dogfooded.

## Jira / Atlassian — dogfooded (HORO-968)

1. **MCP first.** The connected Jira/Atlassian MCP tools cover ordinary
   Jira issue operations (create/read/edit/transition/comment/search,
   Confluence page operations). Use them directly whenever the operation
   is issue- or Confluence-shaped — no credential ever surfaces to the
   agent.
2. **CLI, if the MCP doesn't cover it.** If an authenticated `jira` CLI
   (or equivalent) session exists, prefer its own commands over
   constructing raw HTTP calls.
3. **Official REST API v3 via a safe client, for what neither covers.**
   When the MCP lacks an operation entirely (as in HORO-968 — Team
   Central/Atlas Goal/Version/Component creation isn't an MCP-exposed
   operation, and issue-level operations that the MCP *does* cover should
   just use the MCP instead of this fallback) and no CLI covers it
   either, fall back to Jira/Atlassian's documented REST API v3, with the
   credential piped through a `curl` config read from **stdin** — never
   assembled as a bare argv token:

   ```bash
   printf 'user = "%s:%s"\nheader = "Accept: application/json"\n' \
       "$JIRA_EMAIL" "$JIRA_API_TOKEN" \
     | curl -sS -K - \
       -X GET "https://<site>.atlassian.net/rest/api/3/project/<key>/version"
   ```

   The credential is composed only inside the pipe between `printf` and
   `curl -K -` — it is never a separate `-u email:token` argv token
   (visible to any co-resident process via `ps` and retained in shell
   history), never echoed, and never assigned to a variable the agent
   prints. A config file on disk (`curl -K /path/to/config`) is a valid
   variant when a reusable config is warranted, but the stdin form is
   preferred — it leaves nothing behind to accidentally commit or leak
   from a stale file. This is the concrete instance of `security.md`'s
   "no secret plaintext in argv when a safer channel exists" prohibition
   for this provider.
4. **Genuinely unsupported → report honestly.** HORO-968's Team
   Central/Atlas Goal creation hit exactly this: the documented API for
   those objects requires OAuth 2.0 3LO, not the Basic Auth (email + API
   token) mechanism used for ordinary issue operations. No 3LO flow was
   authorized for that task, so the honest outcome was a reported
   limitation. Full walkthrough: `examples/jira-api-fallback-safe.md`.

## GitHub — CLI-first pattern (dogfooded elsewhere in the Horonom workspace)

The org-wide baseline instructs using the `gh` CLI for GitHub operations
(PRs, issues, branches) rather than raw API calls. Real authenticated
`gh` usage exists in sibling `horonomy/*` repos (not this repo's own
history, but the same org/workspace, and the same tool/pattern this
section describes): `horonomy/octans`'s
`docs/decisions/0002-branch-protection-unavailable.md` records a real
authenticated `gh api orgs/horonomy --jq .plan.name` /
`gh api repos/horonomy/octans/rulesets` session used to confirm a plan
limitation, and `horonomy/fornax-core`'s `scripts/release-execute.sh` /
`release-readiness.sh` use authenticated `gh api` and `gh release
view/create/edit` calls throughout a release script — in both cases the
token never appears as a bare argv value; the authenticated `gh` session
itself is the safe channel.

1. **MCP first.** A connected GitHub MCP server's tools (issues, PRs,
   branches, file contents, reviews) cover most day-to-day operations —
   use them directly when available.
2. **`gh` CLI, already authenticated, for everything else.** `gh` manages
   its own credential (via `gh auth login`); check readiness with its own
   introspection rather than by reading its config file:

   ```bash
   gh auth status                              # confirms an authenticated session exists
   gh api orgs/horonomy --jq .plan.name        # real pattern from horonomy/octans ADR 0002
   gh release create "$tag" --repo "$repo" ... # real pattern from horonomy/fornax-core
   ```

   `gh`'s own commands (`gh pr`, `gh issue`, `gh api`, `gh release`) are
   the safe channel — the stored credential is never extracted, echoed,
   or passed as a separate argv token.
3. **REST/GraphQL API via a safe client, only if `gh` genuinely can't
   express the call.** Same discipline as Jira: pipe a token through a
   config file or an env var consumed by the client library itself
   (`curl -K -`, or an SDK reading `GITHUB_TOKEN` internally) — never a
   bare `-H "Authorization: token <value>"` built with a literal secret
   substituted into the command string.
4. **Genuinely unsupported → escalate/report.** If an operation needs a
   scope or API surface the authenticated session doesn't have, report
   that rather than attempting to widen scope unilaterally — the same
   `horonomy/octans` ADR is itself an example of this: it hit a real
   GitHub-plan limitation (branch protection needs a paid plan) and
   documented it rather than trying to work around it (a scope/IAM
   expansion is exactly the kind of unrelated-mutation authorization gap
   the "capabilities, not context" principle names).

## Cloudflare — pattern-only for agent credential fallback, not yet dogfooded

No concrete agent-session Cloudflare credential-discovery/fallback
example was found in this workspace's history. Real `wrangler` usage does
exist (`horonomy/ophiuchus`'s and `horonomy/horonom-site`'s GitHub Actions
deploy workflows run `wrangler pages project create` / the
`cloudflare/wrangler-action`), but that's CI-pipeline usage authenticated
via a repo secret injected by the Actions runner, not an agent performing
the discovery-then-fallback sequence this Skill covers — it doesn't
demonstrate the pattern below, it just confirms `wrangler` is the
established CLI for this provider in the workspace. The pattern to
follow, by analogy with Jira/GitHub above, would be: connected Cloudflare
MCP tools first (this workspace does have Cloudflare-bindings/
observability/browser MCP tools available in some sessions — prefer
those when they cover the operation), then an authenticated `wrangler`
CLI session (`wrangler whoami`) for what the MCP doesn't cover, then the
documented Cloudflare API via a safe client (token piped, never in argv)
as a last resort. Treat this section as guidance to validate against
Cloudflare's actual current docs when first dogfooded by an agent, not as
workspace-proven fact for the fallback sequence itself.

## GCP / Application Default Credentials — pattern-only, not yet dogfooded

No concrete GCP ADC usage was found in this workspace's history to ground
a worked example. The pattern to follow, by analogy: check for an
already-authenticated `gcloud` session (`gcloud auth list`,
`gcloud auth application-default print-access-token` is itself a
credential-returning call and should be avoided in favor of letting a
client library consume ADC internally), then a documented GCP API via an
official client library that reads ADC on its own rather than the agent
extracting and re-passing a token. Treat this section as guidance to
validate against GCP's actual current docs and this workspace's real
setup when first dogfooded, not as workspace-proven fact.
