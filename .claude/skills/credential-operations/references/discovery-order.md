# reference — discovery order in operational detail

This is the operational expansion of `governance/engineering/security.md`'s
Credential Discovery & Safe Consumption Protocol (HORO-980). That
section is the rule; this reference is how to actually carry it out.
Stop at the first step that resolves the need — do not "check everything
for completeness," since each step down the list is progressively more
exposed.

## The six steps

### 1. Connected/authenticated MCP or integration

If an MCP server (or another already-wired integration) exposes the
operation directly, use its tools. The credential backing it never
surfaces to the agent — the MCP server holds it, not the conversation.
This is the least-exposing option by construction and should always be
tried first.

Caveat: an MCP tool whose *result* is the secret value itself (e.g. a
hypothetical `get_connection_string`-style call that returns the raw
credential as its return value) is not a safe use of this step, even
though it's nominally "using the MCP" — the value would land in agent
context by construction. Discovery calls that don't return a secret
(list projects, describe a resource, create a non-credential object) are
fine; a credential-returning call is not, regardless of which step
you're notionally on.

### 2. Already-authenticated official CLI / OS credential mechanism

If the provider has an official CLI and a session already exists (`gh
auth status`, `gcloud auth list`, a keychain-backed login), use the CLI's
own authenticated commands. The CLI manages the credential internally;
you never need to see it. Check auth state with the CLI's own
introspection command rather than by grepping its config files for a
token value.

### 3. Environment variable name/presence only

If no MCP/CLI path exists, check whether the expected variable is
*declared* — never read its value. Use
`scripts/probe_env_presence.py VAR_NAME`, which prints only `PRESENT` or
`ABSENT`. This answers "is a credential configured here at all," which is
often enough to decide whether to proceed or to report the capability as
missing.

### 4. Known provider config/credential location, readiness-only

Some providers keep credentials in a well-known config path (a provider
CLI's own config file, a cloud SDK's credential file). If step 3 doesn't
resolve it, check whether such a file exists and looks structurally
complete — file exists, expected keys are present — via a names-only
parser, never a raw read of its content. This is the same discipline as
step 5, applied to a provider-owned location instead of a repo-owned one.

### 5. Repo-declared `.env*` / config, names-only inspection

If a repo declares a `.env`, `.env.example`, or similar config file, check
whether the *key* the task needs is declared, using
`scripts/parse_dotenv_keys.py path/to/.env`. This tells you "this repo
expects `JIRA_API_TOKEN` to be set" without ever reading what it's set
to. If the key isn't present in the file at all, that's useful signal
that the credential must come from elsewhere (environment, a secret
manager, a human) — but it's still just a names-only fact, not a value.

### 6. Unavailable — continue or report per task semantics

If none of the above resolves it, the credential is unavailable. What
happens next depends on the task: a step that can be skipped gracefully
should be skipped and noted; a step the task genuinely requires should be
escalated as a material decision (see `security.md`'s "credentials are
capabilities, not context" — the absence of a capability is not itself an
authorization problem, but proceeding around it might create one). Never
respond to step 6 by broadening the search into arbitrary filesystem
scanning — that is explicitly forbidden regardless of how badly the task
wants the credential.

## Worked walkthrough — a Jira API token

Task: an agent needs to call the Jira REST API for an operation the
connected Jira MCP doesn't support (see
`examples/jira-api-fallback-safe.md` for the concrete HORO-968 case).

1. **Check MCP tool availability first.** Does any connected
   Jira/Atlassian MCP tool cover the operation? If yes, stop here — done,
   no token ever needed by the agent.
2. **Check CLI auth state.** Is there an authenticated `jira` CLI (or
   equivalent) session, or a `gh`-style CLI with Jira support, already
   logged in? `<cli> auth status` (or the CLI's equivalent) answers this
   without ever touching a token value. If authenticated, use the CLI's
   own commands for the operation if it supports it.
3. **Check env var *name* presence only.** Run
   `python3 agents/skills/credential-operations/scripts/probe_env_presence.py JIRA_API_TOKEN`.
   A `PRESENT` result means a token is configured somewhere reachable —
   proceed to actually use it via a safe channel (see
   `references/provider-fallback-examples.md`'s Jira section for exactly
   how, e.g. `curl -K -` reading a config file from stdin, never as a
   bare argv token). An `ABSENT` result means step further down.
4. **Stop — do not read `.env` file contents beyond key names.** If step
   3 comes back `ABSENT`, checking a repo `.env` file for whether
   `JIRA_API_TOKEN` is *declared* (`parse_dotenv_keys.py`) is the next and
   final automated step. If the key isn't declared there either, the
   token is unavailable through safe automated discovery — report that
   plainly rather than opening the `.env` file to "just take a look," and
   rather than searching other locations for it.
