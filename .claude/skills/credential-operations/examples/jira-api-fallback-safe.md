# example — Jira API fallback: the safe attempt-then-honest-limitation pattern (HORO-968)

This is a real worked case from this workspace, not a hypothetical. It
illustrates the pattern this Skill actually asks for: try the fallback
sequence in order, keep every credential channel safe at each step, and
when the operation is genuinely unsupported, **report that honestly
instead of fabricating success or silently giving up early**.

## The situation

HORO-968 needed to create Team Central / Atlas objects (a **Goal**, and
related Version/Component metadata) against a Jira/Atlassian workspace.

1. **Native tool/MCP check.** The connected Jira/Atlassian MCP tools
   (issue, comment, transition, project, and Confluence operations) do
   not expose Goal/Version/Component creation for Team Central/Atlas
   objects — those are a different object model than Jira issues, and no
   connected MCP tool covered them. Per the fallback sequence's step 1,
   this ruled out the least-exposing option; the task moved to step 2.

2. **Official API check.** Atlassian's Team Central/Atlas API for these
   objects requires OAuth 2.0 3LO (three-legged OAuth, a full user
   consent/authorization-code flow) — it is documented as **not**
   reachable via the same Basic Auth (email + API token) mechanism that
   works for ordinary Jira REST v3 issue operations. No 3LO
   client/consent flow was set up or authorized for this task.

3. **Outcome: genuinely unavailable, reported as such.** Steps 1–3 of the
   tool/API fallback sequence in `security.md` were exhausted honestly:
   no MCP coverage, no CLI coverage, and the documented API path requires
   an auth flow that wasn't available. Per the fallback sequence's step
   4, this is "the capability is genuinely unavailable through 1–3" —
   the correct response is to report the limitation, not to:
   - Silently skip the requirement and imply it was handled.
   - Attempt a workaround that would have required a credential class
     this task was never given (e.g. improvising a 3LO consent flow with
     no authorized client).
   - Claim partial success as full success.

## Why this matters as the canonical example

This is the failure mode the "credentials are capabilities, not context"
principle and the tool/API fallback sequence exist to prevent in both
directions:

- It would have been *unsafe* to treat "I have a Jira API token" as
  license to attempt an operation that token's auth mechanism doesn't
  actually support — that's exactly the capability-vs-authorization gap
  the principle names. A Basic Auth token is not automatically capable of
  everything the OAuth-3LO-gated Team Central API exposes just because
  both belong to "the Jira credential."
- It would have been *dishonest* to under-report the situation as "done"
  once ordinary issue-level Jira operations (which the same token *does*
  support) went fine, quietly leaving the Goal/Version/Component request
  unfulfilled without saying so.

The safe pattern is: exhaust the ordered fallback for the *specific
operation*, keep every credential channel opaque along the way (Basic
Auth token piped via a config-file/stdin mechanism for the operations it
does support — never as a bare argv token, per
`references/provider-fallback-examples.md`'s Jira section), and when the
operation itself is out of reach, say so plainly with the actual reason
(3LO required, not available) rather than a vague "couldn't do it."

## Confirmed detail

HORO-968's own ticket record (Jira comment on the ticket, HORO project)
documents this outcome directly: "no MCP tool (Jira or Compass) exposes
Jira Version/Component/Atlassian-Goal creation — confirmed via
ToolSearch... Fell back to the documented Jira REST API v3 using the
existing `JIRA_USERNAME`/`JIRA_API_TOKEN` credential capability...
Credential values were never printed/echoed/logged — passed to `curl`
via a `-K -` stdin config file (`user = "$JIRA_USERNAME:$JIRA_API_TOKEN"`),
never as a bare argv token, never traced." That session created a Fix
Version and five Components via `POST /rest/api/3/version` and
`POST /rest/api/3/component`, then genuinely attempted Team Central/Atlas
Goal creation via two plausible endpoint shapes, both returning 404 —
consistent with Atlassian's documented requirement that Team
Central/Atlas GraphQL needs an OAuth 2.0 3LO session, not a Basic Auth
API token — and left the Goal uncreated with an honest note rather than
a fabricated success, alongside a short manual-UI remediation path for a
human to finish that one step.

## What this example does not claim

This example documents the outcome and mechanism of the real HORO-968
session; it does not reproduce that session's full command transcript or
payloads verbatim (those are not needed to convey the safe pattern, and
copying them here would add no safety value while inviting drift from the
ticket's own record). Treat the mechanism (stdin-piped `curl -K -`
credential config) shown in `references/provider-fallback-examples.md`
as the safe implementation detail to reuse whenever a Jira REST v3 call
*is* reachable with the available Basic Auth token.
