# Policy RBAC Role Matrix

Auto-generated from the `PolicyMutationRequiredRole` table in `aa-gateway/src/policy/rbac.rs`. Do not edit by hand — run `cargo run -p aa-api --bin generate_policy_rbac_doc` to regenerate.

The 5 canonical RBAC roles in privilege order (highest → lowest):
`OrgAdmin > TeamAdmin > Developer > Viewer > Auditor`
`Auditor` may never mutate policies — all write attempts are denied.

| Scope | create | update | delete | 
|---| --- | --- | --- | 
| `global` | `org_admin` | `org_admin` | `org_admin` | 
| `org` | `org_admin` | `org_admin` | `org_admin` | 
| `team` | `team_admin` | `team_admin` | `team_admin` | 
| `agent` | `developer` | `developer` | `developer` | 
| `tool` | `developer` | `developer` | `developer` | 

## Role Descriptions

- **`org_admin`** — Full policy mutation rights across all scopes.
- **`team_admin`** — Can mutate team-scoped policies and below (Agent, Tool).
- **`developer`** — Can mutate agent- and tool-scoped policies only.
- **`viewer`** — Read-only access — no writes permitted.
- **`auditor`** — Read-only audit access — all write attempts denied regardless of scope.
