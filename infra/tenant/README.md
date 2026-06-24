# Tenant subdomain & reserved-slug policy

> **Status: Proposed.** This documents the slug rules the future SaaS control plane
> (the `agent-assembly-cloud` placeholder) must enforce when allocating
> `<tenant>.agent-assembly.com` workspaces. No control plane exists yet; this is the
> contract it must honor, pending owner ratification.

Implements the tenant wildcard from
[ADR 0007 — Public Domain & URL Contract](../../docs/src/adr/0007-public-domain-and-url-contract.md)
and the origin boundary from
[ADR 0008 — SaaS Host Routing, Auth & Cookie Boundaries](../../docs/src/adr/0008-saas-host-routing-auth-cookie-boundaries.md)
(Epic [AAASM-3651](https://lightning-dust-mite.atlassian.net/browse/AAASM-3651),
ticket [AAASM-3655](https://lightning-dust-mite.atlassian.net/browse/AAASM-3655)).

## Slug format

A tenant slug is the leftmost DNS label of `<tenant>.agent-assembly.com`. It must:

- match the regex **`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$`**
  (lowercase letters, digits, internal hyphens; must start and end alphanumeric);
- be **3–63 characters** long (63 is the DNS label limit);
- contain **no consecutive hyphens at positions 3–4** (i.e. reject the `xn--`
  IDN/punycode prefix and similar `--` patterns) to avoid homograph/punycode abuse;
- be stored and compared **lowercased** (DNS labels are case-insensitive).

Reject anything that does not match before it reaches DNS or cert provisioning.

## Reserved list

[`reserved-slugs.txt`](reserved-slugs.txt) is the machine-readable reserved list (one
slug per line, `#` comments and blanks ignored). A slug is **rejected** if, after
lowercasing, it appears in that list. The list covers:

- **First-party hosts** (`www`, `app`, `api`, `docs`, `status`) — a tenant must never
  be able to claim a name that collides with a first-party host (ADR 0007). Explicit
  DNS records for these win over the `*` wildcard, but the reserved list blocks them
  at the **application layer** too, defense-in-depth.
- **Common infra/service names** (`admin`, `cdn`, `mail`, `auth`, `login`,
  `billing`, `static`, `assets`, …) — names that would be confusing, phishing-prone,
  or operationally reserved.

## Collision / validation policy

When a tenant requests slug `S`:

1. Lowercase and trim `S`.
2. **Format check** — reject if `S` fails the regex / length / punycode rules above.
3. **Reserved check** — reject if `S` is in `reserved-slugs.txt`.
4. **Uniqueness check** — reject if `S` is already allocated to another tenant
   (case-insensitive). Slugs are unique across the whole `agent-assembly.com` zone.
5. On success, allocate `S`, provision the tenant origin behind the `*` wildcard
   (no per-tenant DNS record is needed — the wildcard covers it), and confirm the
   wildcard TLS cert covers `S.agent-assembly.com` (see `infra/dns/` wildcard caveat).

Reserved-list changes are **additive and reviewed**: removing a slug from the list
could let a tenant claim a name that later needs to become a first-party host, so
treat the list as append-mostly. Renaming/releasing an allocated slug must go through
a deprovision flow (release DNS/cert references) before the slug is reusable.

## Why this lives here (and what is out of scope)

This is the **naming/allocation** contract only. Tenant **data** isolation
(row-level security, per-tenant keys, query scoping) is enforced server-side and is
out of scope here — see ADR 0008 and the `agent-assembly-cloud` persistence design.
