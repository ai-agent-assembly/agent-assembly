# Reference — the semantic admonition system

## Purpose

A small, consistent semantic set for secondary detail, so a reader can
scan a page and know at a glance which callouts matter to them — instead
of every aside being buried in undifferentiated prose, or every aside
getting the same heavyweight visual treatment.

## The eight types

### Note
A contextual fact useful to understand behavior, with no action required
and no risk if skipped. Use for background that helps comprehension but
isn't load-bearing.

### Tip
Optional workflow/productivity advice — a faster or more convenient way
to do something the reader could also do the plain way. Never use Tip for
something that's actually required; that's Important or Warning.

### Important
A detail likely to change the outcome if missed — not catastrophic, but
skipping it produces a wrong result, a confusing error, or wasted effort.
Use when a reader who skips this callout will very likely get stuck or
get the wrong answer.

### Warning
A meaningful failure/data-loss/operational risk — the reader could break
something, lose data, or cause an outage by proceeding without reading
this. Reserve for genuine risk, not routine caveats (that's Important).

### Security / Privacy
Trust, permissions, credentials, or data-exposure implications
specifically — kept distinct from Warning because a reader scanning for
security-relevant callouts (an auditor, a security reviewer) needs to
find them without reading every Warning on the page.

### Limitation / Experimental
Current maturity or an unsupported boundary — what doesn't work yet, what
might change, what's not production-ready. Pairs with the maturity
vocabulary in `governance/engineering/docs-scenario-quality.md`
(`SHIPPED`/`PARTIAL`/`PLANNED`/`INTERNAL-ONLY`/`NOT IMPLEMENTED`) — a
Limitation callout should generally name which of those five states
applies rather than leaving maturity vague ("this may not work" vs. "this
is PARTIAL: X works, Y does not yet").

### Example
A concrete application of a rule or concept just stated — set apart from
the main explanation so a reader who already understands the rule can
skip straight past it, and a reader who needs a concrete case can find it
without re-reading the prose.

### Reference / See also
A pointer to optional deeper material (a Layer 2/3 page, an external
spec, a related concept) — explicitly optional, not something the current
page's understanding depends on.

## Choosing the right type

A quick decision order when a piece of content seems to fit more than
one type:

1. Does skipping this risk security/privacy exposure? → **Security /
   Privacy**, even if it also looks like a Warning.
2. Does skipping this risk data loss or breaking something? → **Warning**.
3. Does skipping this produce a wrong result or a confusing error, without
   catastrophic risk? → **Important**.
4. Is this about what doesn't work yet or isn't supported? → **Limitation
   / Experimental**.
5. Is this purely optional convenience? → **Tip**.
6. Is this background that aids understanding but isn't actionable? →
   **Note**.
7. Is this a concrete illustration of something just explained? →
   **Example**.
8. Is this an optional pointer elsewhere? → **Reference / See also**.

## Warning fatigue is a real failure mode

If every third paragraph is a Warning, none of them mean anything by the
time a reader reaches the one that actually matters — the reader learns
to skim past all of them. High-severity visual treatments (Warning,
Security/Privacy) should be rare enough that a reader's pulse rate
actually changes when they see one. When in doubt, downgrade toward Note
or Important rather than defaulting to Warning for anything
attention-worthy.

A page with more than a handful of Warning/Security callouts is a signal
to restructure — either the underlying feature has too many sharp edges
for a "quick path" framing at all (move it to Layer 2 deep-guidance
content with the risk woven into the narrative), or several of the
callouts are actually Important/Note being over-escalated.

## Map onto the site's native primitive — never invent new rendering

Every real docs framework/site already ships some admonition/callout
mechanism (e.g. Docusaurus's `:::note`/`:::tip`/`:::warning`/`:::danger`
containers, MkDocs Material's `!!! note`/`!!! warning` admonitions, a
static site's own custom `<Callout>` component, or a plain README's bold
"**Note:**" convention). This skill's eight semantic types are a
vocabulary to apply *through* whatever primitive already exists on the
target surface — never a mandate to build new admonition CSS/JS/rendering
infrastructure. Where the native primitive has fewer built-in severities
than eight types (e.g. only note/tip/warning), map the extra semantic
types onto the closest native severity and keep the semantic label in the
callout's heading text (e.g. a Docusaurus `:::warning` container titled
"Security" for a Security/Privacy callout) rather than fabricating a new
container kind. If a target surface has no admonition primitive at all
(a plain README, a markdown file with no framework), use a consistent
bold-label convention (`**Security:**`, `**Warning:**`) instead of
introducing one.
