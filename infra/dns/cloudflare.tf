# Cloudflare DNS — agent-assembly.com SaaS host surface (IaC source-of-truth).
#
# OWNER-GATED — NOT auto-deployable. Applying this requires Cloudflare API
# credentials and a manual `terraform apply` that only the owner can run. CI does
# not apply this; this repo holds no Cloudflare secrets.
#
# Implements ADR 0007 (docs/src/adr/0007-public-domain-and-url-contract.md).
# Ticket: AAASM-3653 (Epic AAASM-3651).
#
# Usage (owner):
#   export CLOUDFLARE_API_TOKEN=...        # token scoped to Zone:DNS:Edit
#   terraform init
#   terraform plan  -var "zone_id=<agent-assembly.com zone id>" \
#                   -var "marketing_origin=<apex origin hostname>"
#   terraform apply -var ...
#
# Origins for app/api/docs/status/tenant are placeholders until the SaaS control
# plane exists; leave them at their defaults (which resolve to the marketing origin
# or a holding page) until each host comes online, then set the matching var.

terraform {
  required_version = ">= 1.5"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

# The Cloudflare provider reads its token from CLOUDFLARE_API_TOKEN.
provider "cloudflare" {}

# ── variables ────────────────────────────────────────────────────────────────

variable "zone_id" {
  type        = string
  description = "Cloudflare zone id for agent-assembly.com."
}

variable "marketing_origin" {
  type        = string
  description = "Apex origin hostname serving the marketing site (also fronts the /install.sh Worker route via the proxied apex)."
}

variable "app_origin" {
  type        = string
  description = "Origin for app.agent-assembly.com (login / workspace selector). Placeholder until the SaaS app exists."
  default     = "" # empty => not yet created; see `count` guards below.
}

variable "api_origin" {
  type        = string
  description = "Origin for api.agent-assembly.com (public SaaS API). Placeholder."
  default     = ""
}

variable "docs_origin" {
  type        = string
  description = "Origin for docs.agent-assembly.com (canonical docs, Epic AAASM-3659)."
  default     = ""
}

variable "status_origin" {
  type        = string
  description = "Hosted status-page provider target for status.agent-assembly.com (DNS-only / grey-cloud)."
  default     = ""
}

variable "tenant_origin" {
  type        = string
  description = "Origin for the *.agent-assembly.com tenant wildcard. Placeholder until the control plane exists."
  default     = ""
}

# ── apex + www ───────────────────────────────────────────────────────────────

# Apex: proxied so the install Worker route (agent-assembly.com/install.sh*) and
# Always-HTTPS/HSTS apply. Cloudflare CNAME-flattening allows a CNAME at the apex.
resource "cloudflare_record" "apex" {
  zone_id = var.zone_id
  name    = "@"
  type    = "CNAME"
  content = var.marketing_origin
  proxied = true
  comment = "Apex: marketing site + /install.sh Worker route (ADR 0007 / AAASM-3654)."
}

resource "cloudflare_record" "www" {
  zone_id = var.zone_id
  name    = "www"
  type    = "CNAME"
  content = "agent-assembly.com"
  proxied = true
  comment = "Canonicalized to apex via Redirect Rule (infra/redirects/)."
}

# ── first-party SaaS hosts (created only once an origin is set) ───────────────

resource "cloudflare_record" "app" {
  count   = var.app_origin == "" ? 0 : 1
  zone_id = var.zone_id
  name    = "app"
  type    = "CNAME"
  content = var.app_origin
  proxied = true
  comment = "Login / workspace selector (ADR 0007)."
}

resource "cloudflare_record" "api" {
  count   = var.api_origin == "" ? 0 : 1
  zone_id = var.zone_id
  name    = "api"
  type    = "CNAME"
  content = var.api_origin
  proxied = true
  comment = "Public SaaS API (ADR 0007)."
}

resource "cloudflare_record" "docs" {
  count   = var.docs_origin == "" ? 0 : 1
  zone_id = var.zone_id
  name    = "docs"
  type    = "CNAME"
  content = var.docs_origin
  proxied = true
  comment = "Canonical docs host (Epic AAASM-3659)."
}

# Status: DNS-only (grey-cloud) so a third-party status provider terminates TLS.
resource "cloudflare_record" "status" {
  count   = var.status_origin == "" ? 0 : 1
  zone_id = var.zone_id
  name    = "status"
  type    = "CNAME"
  content = var.status_origin
  proxied = false
  comment = "Status page — third-party hosted, DNS-only (ADR 0007 / infra/dns/README.md)."
}

# ── tenant wildcard ──────────────────────────────────────────────────────────
# Requires Advanced Certificate Manager (or wildcard SAN) for TLS on
# *.agent-assembly.com. Reserved-slug policy: infra/tenant/.
resource "cloudflare_record" "tenant_wildcard" {
  count   = var.tenant_origin == "" ? 0 : 1
  zone_id = var.zone_id
  name    = "*"
  type    = "CNAME"
  content = var.tenant_origin
  proxied = true
  comment = "<tenant>.agent-assembly.com customer workspaces (ADR 0007 / infra/tenant/)."
}

# NOTE: tool.agent-assembly.dev is intentionally NOT managed here — it is
# provisioned by the install Worker's `custom_domain = true` route on
# `wrangler deploy` (infra/install-endpoint/). Managing it here would conflict.
