# Cloudflare DNS — agent-assembly.com Google Workspace HUMAN mail records.
#
# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PREPARATION-ONLY / DISABLED BY DEFAULT.                                     │
# │                                                                             │
# │  Every resource in this file is gated behind `var.enable_workspace_mail`,   │
# │  which defaults to `false`. With the default, `terraform plan` proposes     │
# │  ZERO mail records — this file is a scaffold that cannot mutate the zone     │
# │  until a real Google Workspace tenant exists and an owner sets the tenant-  │
# │  issued values AND flips the flag.                                          │
# │                                                                             │
# │  All example values below are OBVIOUS NON-FUNCTIONAL PLACEHOLDERS           │
# │  (`REPLACE_WITH_TENANT_ISSUED_VALUE`). They are NOT real tenant values and  │
# │  MUST NOT be applied. Applying real values is a PRODUCTION_CHANGE gate —    │
# │  see infra/dns/README.md (§ Workspace mail).                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
# OWNER-GATED — NOT auto-deployable. CI never applies this and holds no secrets.
# Implements ADR 0007 (docs/src/adr/0007-public-domain-and-url-contract.md) and
# the (to-be-merged) Workspace ADR-015 (Epic AAASM-5514).
# Ticket: AAASM-5517.
#
# OWNERSHIP OF MAIL RECORDS in the agent-assembly.com zone:
#   * Workspace HUMAN mail (apex @, MX/SPF/DKIM/DMARC/verification) → THIS file
#     (AAASM-5517). Human inboxes such as people@agent-assembly.com.
#   * TRANSACTIONAL sender domain `mail.agent-assembly.com` → owned by AAASM-5521
#     (separate provider, separate SPF/DKIM subtree). NOT managed here. It must
#     coexist: it lives under the `mail.` label, so it does not collide with the
#     apex SPF/DKIM/DMARC managed here.
#   * Existing WEB/SaaS records (@ CNAME, www, app, api, docs, status, wildcard)
#     → cloudflare.tf. This file adds NO web records and edits none.
#
# NOTE ON APEX: cloudflare.tf owns a proxied CNAME at the apex for web traffic.
# Mail records here are the apex MX + apex TXT (SPF), plus the `_dmarc` and DKIM
# selector labels. MX/TXT records coexist with a CNAME-flattened apex in
# Cloudflare. These records are DNS-only by nature (MX/TXT are never proxied).

# ── enable flag (disabled by default) ────────────────────────────────────────

variable "enable_workspace_mail" {
  type        = bool
  description = <<-EOT
    Master switch for the agent-assembly.com Google Workspace HUMAN mail records
    (verification TXT, MX, apex SPF, DKIM selector, DMARC). DISABLED BY DEFAULT.
    Leave `false` until a real Workspace tenant exists AND all tenant-issued
    values below are populated. Flipping to `true` with incomplete values fails
    validation (see the precondition on `null_resource.workspace_mail_guard`).
  EOT
  default     = false
}

# ── typed, EMPTY-by-default tenant-issued inputs (no invented values) ─────────
# All values are supplied by the Google Workspace Admin Console for the attached
# tenant. They are NOT secrets, but they are tenant-specific and MUST come from
# the real tenant — never guessed. Defaults are empty so an accidental enable
# fails validation rather than publishing a placeholder.

variable "workspace_verification_txt" {
  type        = string
  description = "Google site-verification TXT value issued for the tenant (e.g. 'google-site-verification=...'). Placeholder until tenant exists."
  default     = ""
}

variable "workspace_mx_records" {
  type = list(object({
    priority = number
    value    = string
  }))
  description = <<-EOT
    Google Workspace MX record set issued by Google, with priorities. Example
    shape (DO NOT apply — placeholder):
      [{ priority = 1, value = "REPLACE_WITH_TENANT_ISSUED_VALUE" }]
    Real Workspace tenants are typically issued a single `smtp.google.com` MX at
    priority 1, but the exact set must come from the Admin Console.
  EOT
  default     = []
}

variable "workspace_dkim_selector" {
  type        = string
  description = "Workspace DKIM selector label (e.g. 'google'), generated in Admin Console. Placeholder until key generation."
  default     = ""
}

variable "workspace_dkim_public_key" {
  type        = string
  description = "Workspace DKIM public key TXT value (v=DKIM1; k=rsa; p=...), generated in Admin Console. Not a secret; not applied until real. Placeholder until key generation."
  default     = ""
}

variable "workspace_spf_includes" {
  type        = list(string)
  description = <<-EOT
    SPF `include:` mechanisms to MERGE into the SINGLE apex SPF policy. Workspace
    requires `_spf.google.com`. Any other legitimate sender approved for the apex
    (never the transactional `mail.` subdomain, which has its own SPF) is added
    here so exactly ONE SPF TXT is published at the apex. Placeholder until real.
  EOT
  default     = []
}

variable "workspace_dmarc_rua" {
  type        = string
  description = <<-EOT
    DMARC aggregate-report (rua) destination mailbox, e.g. 'mailto:dmarc-reports@...'.
    Must NOT be a private recovery address. Placeholder until an approved reporting
    destination exists. The initial DMARC posture is observation (p=none).
  EOT
  default     = ""
}

# ── completeness + single-SPF validation (only enforced when enabled) ─────────
# A lifecycle precondition enforces cross-variable completeness only when
# `enable_workspace_mail` is true. When disabled (the default), no precondition
# fires and no records are planned. The single-SPF invariant is structural: the
# apex SPF TXT is authored as exactly ONE resource below, and the precondition
# rejects an empty include set so we never publish an empty/duplicate SPF policy.

resource "null_resource" "workspace_mail_guard" {
  count = var.enable_workspace_mail ? 1 : 0

  lifecycle {
    precondition {
      condition     = length(trimspace(var.workspace_verification_txt)) > 0
      error_message = "enable_workspace_mail=true requires a non-empty workspace_verification_txt (tenant-issued Google site-verification value)."
    }
    precondition {
      condition     = length(var.workspace_mx_records) > 0
      error_message = "enable_workspace_mail=true requires a non-empty workspace_mx_records list (Google-issued MX set with priorities)."
    }
    precondition {
      condition     = length(trimspace(var.workspace_dkim_selector)) > 0 && length(trimspace(var.workspace_dkim_public_key)) > 0
      error_message = "enable_workspace_mail=true requires both workspace_dkim_selector and workspace_dkim_public_key (generated in Admin Console)."
    }
    precondition {
      # Exactly-one-SPF invariant: the apex SPF TXT is authored as a single
      # resource, and its include set must be non-empty when enabled so we never
      # publish an empty or duplicate SPF policy.
      condition     = length(var.workspace_spf_includes) > 0
      error_message = "enable_workspace_mail=true requires at least one entry in workspace_spf_includes (e.g. '_spf.google.com') so exactly one valid apex SPF policy is published."
    }
    precondition {
      condition     = length(trimspace(var.workspace_dmarc_rua)) > 0
      error_message = "enable_workspace_mail=true requires a non-empty workspace_dmarc_rua (approved aggregate-report destination; not a private recovery address)."
    }
    precondition {
      condition     = alltrue([for mx in var.workspace_mx_records : length(trimspace(mx.value)) > 0 && mx.priority >= 0])
      error_message = "each workspace_mx_records entry must have a non-empty value and a non-negative priority."
    }
  }
}

# ── locals: single merged SPF policy ─────────────────────────────────────────
# Exactly ONE SPF TXT is constructed at the apex by joining the approved includes.
# This is the single-merged-SPF pattern: never publish >1 SPF TXT at a hostname.
locals {
  workspace_spf_value = format(
    "v=spf1 %s ~all",
    join(" ", [for inc in var.workspace_spf_includes : "include:${inc}"])
  )
}

# ── Workspace domain-verification TXT (apex) ─────────────────────────────────
resource "cloudflare_record" "workspace_verification" {
  count   = var.enable_workspace_mail ? 1 : 0
  zone_id = var.zone_id
  name    = "@"
  type    = "TXT"
  content = var.workspace_verification_txt
  comment = "Google Workspace domain verification (AAASM-5517 / Workspace ADR-015). Tenant-issued."
  # TXT is DNS-only by nature; no `proxied` attribute applies.
}

# ── Workspace MX set (apex) ──────────────────────────────────────────────────
resource "cloudflare_record" "workspace_mx" {
  for_each = var.enable_workspace_mail ? {
    for idx, mx in var.workspace_mx_records : tostring(idx) => mx
  } : {}
  zone_id  = var.zone_id
  name     = "@"
  type     = "MX"
  content  = each.value.value
  priority = each.value.priority
  comment  = "Google Workspace inbound MX (AAASM-5517). Human mail only; transactional mail.* is AAASM-5521."
}

# ── apex SPF (exactly one TXT) ───────────────────────────────────────────────
resource "cloudflare_record" "workspace_spf" {
  count   = var.enable_workspace_mail ? 1 : 0
  zone_id = var.zone_id
  name    = "@"
  type    = "TXT"
  content = local.workspace_spf_value
  comment = "SINGLE merged apex SPF policy (AAASM-5517). Merge new senders here; never add a 2nd SPF TXT at the apex."
}

# ── DKIM selector TXT ────────────────────────────────────────────────────────
resource "cloudflare_record" "workspace_dkim" {
  count   = var.enable_workspace_mail ? 1 : 0
  zone_id = var.zone_id
  name    = "${var.workspace_dkim_selector}._domainkey"
  type    = "TXT"
  content = var.workspace_dkim_public_key
  comment = "Google Workspace DKIM public key (AAASM-5517). Rotation procedure: infra/dns/README.md."
}

# ── DMARC (observation mode; staged hardening) ───────────────────────────────
resource "cloudflare_record" "workspace_dmarc" {
  count   = var.enable_workspace_mail ? 1 : 0
  zone_id = var.zone_id
  name    = "_dmarc"
  type    = "TXT"
  # Staged DMARC: starts at p=none (observation). Path to quarantine/reject is
  # documented in infra/dns/README.md (§ DMARC hardening trigger). Do NOT ship a
  # stricter initial policy without observing legitimate senders first.
  content = "v=DMARC1; p=none; rua=${var.workspace_dmarc_rua}; fo=1"
  comment = "DMARC observation policy p=none (AAASM-5517). Harden to quarantine/reject only after sender inventory."
}
