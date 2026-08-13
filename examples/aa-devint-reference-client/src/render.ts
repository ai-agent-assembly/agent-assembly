/**
 * Presentation, and the exact line where presentation stops.
 *
 * Everything here is a **lookup**, never a computation. A level is displayed
 * because the server put it in `StatusView.achieved_level`; an unrecognised
 * token is displayed verbatim and flagged, not resolved to the nearest thing
 * this build knows. There is no comparison operator, no ordering and no
 * "highest of" anywhere in this module — a client that could rank levels could
 * upgrade one, and deriving or upgrading a protection state client-side is
 * ADR 0030 forbidden design 10.
 *
 * The vocabulary is `docs/src/devtools/product-brief.md` §6 and §7, used
 * verbatim. Synonyms are worse than useless here: a user comparing the CLI, the
 * dashboard and an editor extension must see one word for one thing.
 *
 * Two product rules §7.4 states and this module implements:
 *
 * 1. **`Host Enforced` is rendered as unavailable on this platform, not
 *    omitted.** Silence reads as "there is nothing above what I have", which is
 *    the over-claim the whole level system exists to prevent.
 * 2. **Exercised evidence is shown separately from read-back evidence.** A
 *    configuration that exists is not protection; a user who can see which is
 *    which can reason about their own risk, and a user shown one word cannot.
 */
import type { EvidenceView, ScopedEvent, StatusView, StepView, ToolSummary } from './generated/devint_pb.js';

/** Profile labels — `docs/src/devtools/product-brief.md` §6.1. */
export const PROFILE_LABELS: Readonly<Record<string, string>> = {
  recommended: 'Recommended',
  strict: 'Strict',
  observe_only: 'Observe',
};

/** Protection-level labels — §7. Display only; never ordered, never compared. */
export const LEVEL_LABELS: Readonly<Record<string, string>> = {
  not_installed: 'Not installed',
  detected_not_integrated: 'Detected, not integrated',
  partially_integrated: 'Partially integrated',
  integrated: 'Integrated',
  gateway_protected: 'Gateway Protected',
  host_enforced: 'Host Enforced',
};

/** Overriding-state labels — §7.4 / `StatusView.state`. */
export const STATE_LABELS: Readonly<Record<string, string>> = {
  ladder: '',
  drifted: 'Drifted',
  degraded: 'Degraded',
  incompatible: 'Incompatible',
};

/**
 * The line every status must carry, verbatim.
 *
 * `Host Enforced` is not available in this MVP (§7.3) and the product
 * requirement is that it be **named and reported as unavailable**, so this
 * string is a constant rather than something conditional logic might drop.
 */
export const HOST_ENFORCED_UNAVAILABLE = 'Host Enforced: unavailable on this platform';

/**
 * A level as the user should read it.
 *
 * An unknown token is surfaced as unknown. Mapping it to a neighbour would be
 * this client deciding what the runtime meant, which is the one thing it may
 * never do.
 */
export function levelLabel(wireLevel: string): string {
  return LEVEL_LABELS[wireLevel] ?? `${wireLevel} (unrecognised by this client)`;
}

/** A profile as the user chose it. */
export function profileLabel(wireProfile: string): string {
  return PROFILE_LABELS[wireProfile] ?? `${wireProfile} (unrecognised by this client)`;
}

/** Evidence split into the two kinds a user must be able to tell apart (§7.4). */
export interface EvidenceSplit {
  /** Behaviour that was observed: a probe ran and something happened to it. */
  readonly exercised: readonly EvidenceView[];
  /** Configuration that was read back and compared to the receipt. */
  readonly readBack: readonly EvidenceView[];
  /** Attested by a host-level layer. Empty on every MVP platform. */
  readonly hostAttested: readonly EvidenceView[];
  /** Checks that could not be made, with the reason they were absent. */
  readonly absent: readonly EvidenceView[];
}

/** Partition evidence by kind. */
export function splitEvidence(evidence: readonly EvidenceView[]): EvidenceSplit {
  return {
    exercised: evidence.filter((e) => e.kind === 'exercised'),
    readBack: evidence.filter((e) => e.kind === 'read_back'),
    hostAttested: evidence.filter((e) => e.kind === 'host_attested'),
    absent: evidence.filter((e) => e.kind === 'absent' || e.kind === 'unknown'),
  };
}

/** A status, rendered for a terminal, a webview or a tree view. */
export function renderStatus(status: StatusView): string[] {
  const lines: string[] = [];
  const state = STATE_LABELS[status.state] ?? status.state;

  lines.push(`Tool:               ${status.toolId}`);
  lines.push(`Protection level:   ${levelLabel(status.achievedLevel)}${state === '' ? '' : `  [${state}]`}`);
  lines.push(`Planned level:      ${levelLabel(status.plannedLevel)}`);
  lines.push(`Phase:              ${status.phase}`);
  lines.push(`Tool compatibility: ${status.compatibility}`);
  // "verified at T", not "true now" — a status read without its timestamp
  // over-reads the claim.
  lines.push(`Observed at:        ${formatUnixSecs(status.observedAtUnixSecs)}`);

  if (status.stateReason !== '') lines.push(`Why:                ${status.stateReason}`);
  if (status.stateRemediation !== '') lines.push(`Fix:                ${status.stateRemediation}`);
  if (status.driftMismatched.length > 0) {
    lines.push(`Drifted artifacts:  ${status.driftMismatched.join(', ')}`);
  }

  const split = splitEvidence(status.evidence);
  lines.push('');
  lines.push('Evidence');
  lines.push(`  Exercised (behaviour observed): ${describeEvidence(split.exercised)}`);
  lines.push(`  Read back (configuration):      ${describeEvidence(split.readBack)}`);
  if (split.hostAttested.length > 0) {
    lines.push(`  Host attested:                  ${describeEvidence(split.hostAttested)}`);
  }
  if (split.absent.length > 0) {
    lines.push(`  Not established:                ${describeEvidence(split.absent)}`);
  }

  lines.push('');
  if (status.nextLevel !== undefined) {
    lines.push(`Next level:         ${levelLabel(status.nextLevel.level)} — ${status.nextLevel.blockedBecause}`);
  }
  // §7.4: always report the next level up and why it is not active. For every
  // MVP install that includes this line.
  lines.push(HOST_ENFORCED_UNAVAILABLE);
  return lines;
}

/** A tool list, rendered. */
export function renderTools(tools: readonly ToolSummary[]): string[] {
  if (tools.length === 0) return ['No tools were discovered on this host.'];
  return tools.map((tool) => {
    const version = tool.detected ? (tool.detectedVersion || 'version unknown') : 'not detected';
    const unsupported = tool.capabilities.filter((c) => c.support !== 'supported').length;
    return `${tool.toolId.padEnd(18)} ${tool.displayName.padEnd(18)} ${version.padEnd(16)} ${tool.compatibility}` +
      (unsupported > 0 ? `  (${unsupported} capability/capabilities unsupported)` : '');
  });
}

/**
 * A plan, rendered for review.
 *
 * Step *values* are absent from `StepView` by construction, so a reviewer sees
 * what will change — surface, owned keys, content fingerprint — and cannot read
 * a secret out of it. That is why this renders `content_sha256` rather than
 * apologising for the missing body: the fingerprint is the reviewable artifact.
 */
export function renderSteps(steps: readonly StepView[]): string[] {
  return steps.map((step) => {
    const privileged = step.privilege === 'privileged_host' ? '  ⚠ privileged host step' : '';
    const keys = step.managedKeys.length > 0 ? `\n      AASM-owned keys: ${step.managedKeys.join(', ')}` : '';
    const paths = step.artifactPaths.length > 0 ? `\n      Writes:          ${step.artifactPaths.join(', ')}` : '';
    const digest = step.contentSha256 !== '' ? `\n      Content SHA-256: ${step.contentSha256}` : '';
    const consent = step.consentPrompt !== '' ? `\n      Consent:         ${step.consentPrompt}` : '';
    const reversible = step.reversible ? 'reversible' : 'NOT automatically reversible';
    return `  [${step.requirement}] ${step.summary} (${step.actionKind}, ${reversible})${privileged}${keys}${paths}${digest}${consent}`;
  });
}

/**
 * Recent events, rendered privacy-preservingly.
 *
 * `ScopedEvent` carries counts, verdict kinds, timestamps and redaction
 * *labels* — never the prompt, the tool output or the content that matched. The
 * renderer has nothing more to show because the wire type has nothing more to
 * hold, which is why this cannot be made to leak by a rendering bug.
 */
export function renderEvents(events: readonly ScopedEvent[]): string[] {
  if (events.length === 0) return ['No recent events for this integration.'];
  return events.map((event) => {
    const labels = event.redactionLabels.length > 0 ? ` [${event.redactionLabels.join(', ')}]` : '';
    const folded = event.count > 1 ? ` ×${event.count}` : '';
    return `  ${formatUnixSecs(event.occurredAtUnixSecs)}  ${event.verdictKind.padEnd(18)} ${event.mechanism}${folded}${labels}`;
  });
}

function describeEvidence(evidence: readonly EvidenceView[]): string {
  if (evidence.length === 0) return 'none';
  return evidence
    .map((e) => `${e.mechanism}=${e.outcome} @ ${formatUnixSecs(e.observedAtUnixSecs)}`)
    .join('; ');
}

function formatUnixSecs(secs: bigint): string {
  if (secs === 0n) return 'never';
  return new Date(Number(secs) * 1000).toISOString();
}
