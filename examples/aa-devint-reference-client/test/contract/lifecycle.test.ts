/**
 * The responsibilities the reference client must have, exercised against the
 * real DI-API server.
 *
 * Discovery, enrolment, negotiation, list/status, plan/apply/verify/repair/
 * remove, protection-level display, privacy-preserving events, approval relay,
 * and actionable degraded/incompatible errors — the nine things AAASM-5282
 * scopes in, in the order a client meets them.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { DevIntClient } from '../../src/client.js';
import { CapabilityToken } from '../../src/credential.js';
import { RuntimeNotRunningError } from '../../src/errors.js';
import { DenyCode, Verb } from '../../src/generated/devint_pb.js';
import { discover } from '../../src/discovery.js';
import { projectRoot } from '../../src/project.js';
import {
  HOST_ENFORCED_UNAVAILABLE,
  levelLabel,
  renderEvents,
  renderStatus,
  renderTools,
  splitEvidence,
} from '../../src/render.js';
import { startHarness, type Harness } from '../harness.js';

const CLAUDE = 'claude-code';
const IDENTITY = { name: 'contract-test', version: '0.0.1' } as const;

let harness: Harness;
let scratch: string;

beforeAll(async () => {
  scratch = mkdtempSync(join(tmpdir(), 'devint-lifecycle-'));
  harness = await startHarness(join(scratch, 'devint.sock'));
}, 40_000);

afterAll(async () => {
  await harness?.stop();
  rmSync(scratch, { recursive: true, force: true });
});

function connect(token = harness.tokens.full): Promise<DevIntClient> {
  return DevIntClient.connect(harness.socket, IDENTITY, CapabilityToken.parse(token));
}

describe('discovery and connection', () => {
  it('finds a live socket through the AA_DEVINT_SOCKET override', () => {
    expect(discover({ AA_DEVINT_SOCKET: harness.socket })).toEqual({ kind: 'present', path: harness.socket });
  });

  it('reports an absent socket as a stopped runtime, not a transport error', async () => {
    const missing = join(scratch, 'nothing-here.sock');
    expect(discover({ AA_DEVINT_SOCKET: missing }).kind).toBe('runtime-not-running');
    await expect(DevIntClient.connect(missing, IDENTITY, null)).rejects.toBeInstanceOf(RuntimeNotRunningError);
  });

  it('negotiates before any verb, and reports what was agreed', async () => {
    const client = await connect();
    try {
      expect(client.negotiated.diApiVersion).toBe(2);
      expect(client.negotiated.coreVersion).not.toBe('');
      expect(client.negotiated.lifecycleSchemaVersion).toBeGreaterThan(0);
      expect(client.negotiated.degraded).toBe(false);
    } finally {
      client.close();
    }
  });
});

describe('the lifecycle flows', () => {
  it('lists discovered tools with their capabilities and compatibility', async () => {
    const client = await connect();
    try {
      const list = await client.listTools();
      expect(list.tools.map((t) => t.toolId)).toEqual([CLAUDE, 'codex']);
      const claude = list.tools[0];
      expect(claude?.detected).toBe(true);
      expect(claude?.compatibility).toBe('compatible');
      // A ceiling is a build-time declaration, not a measurement — it is shown
      // alongside the level rather than as one.
      expect(claude?.adapterCeiling).toBe('l2_enforce');
      expect(claude?.capabilities.some((c) => c.capability === 'host_enforcement')).toBe(true);
      expect(renderTools(list.tools)[0]).toContain(CLAUDE);
    } finally {
      client.close();
    }
  });

  it('plans, applies, verifies, repairs and removes without writing anything itself', async () => {
    const client = await connect();
    try {
      const plan = await client.plan(CLAUDE, {
        profile: 'recommended',
        settingsScope: 'user',
        policyProfileId: 'team-default',
        // User scope: the project root is optional context, and this plan states
        // it has none rather than borrowing the test runner's directory.
        projectRoot: '',
      });
      expect(plan.planId).toBe('plan-1');
      // The policy profile arrives by reference: an id, a name and a digest,
      // never the document.
      expect(plan.policyProfile?.id).toBe('team-default');
      expect(plan.policyProfile?.digest).toBe('sha256:abcd');

      const applied = await client.apply(CLAUDE, plan.planId);
      expect(applied.receiptId).toBe('receipt-1');
      // The service downgraded planned → achieved. The client reports that gap
      // rather than smoothing it over.
      expect(applied.plannedLevel).toBe('gateway_protected');
      expect(applied.achievedLevel).toBe('integrated');

      expect((await client.verify(CLAUDE)).outcome).toBe('passed');
      expect((await client.repair(CLAUDE)).repaired).toEqual(['settings']);
      expect((await client.remove(CLAUDE, plan.planId)).planId).toBe('removal-1');
    } finally {
      client.close();
    }
  });

  it('relays a human approval as an input, never as a verdict', async () => {
    const client = await connect();
    try {
      expect(client.supports(Verb.APPROVAL_RELAY)).toBe(true);
      const ack = await client.relayApproval(CLAUDE, 'approval-1', 'approve');
      expect(ack.approvalId).toBe('approval-1');
      expect(ack.relayedInput).toBe('approve');
      // The acknowledgement has no verdict field to render as one.
      expect(Object.keys(ack)).not.toContain('decision');
      expect(Object.keys(ack)).not.toContain('granted');
    } finally {
      client.close();
    }
  });
});

describe('the project a request is for', () => {
  /**
   * AAASM-5913, from the client's side of the socket.
   *
   * The service is the thing that refuses here, and these assertions run against
   * it rather than against a re-statement of its rule in TypeScript — the client
   * would still compile if it dropped the field, so what needs proving is that
   * the value reaches the far side and that the far side is what adjudicates it.
   */
  it('plans at project scope when the caller names the project', async () => {
    const client = await connect();
    try {
      const plan = await client.plan(CLAUDE, {
        profile: 'recommended',
        settingsScope: 'project',
        projectRoot: projectRoot('project', {}, () => scratch),
      });
      expect(plan.planId).toBe('plan-1');
    } finally {
      client.close();
    }
  });

  it('sends the project root it was given, and no value of its own', async () => {
    const client = await connect();
    try {
      // The service quotes the root back when it refuses a relative one, which
      // is the only place this harness echoes the field at all. A client that
      // dropped it would be refused for naming *nothing*, with a different
      // message; a client that substituted its own cwd would be refused with
      // that path quoted instead.
      await expect(
        client.plan(CLAUDE, { profile: 'recommended', settingsScope: 'user', projectRoot: 'not/absolute' }),
      ).rejects.toThrow(/"not\/absolute" is not absolute/);
    } finally {
      client.close();
    }
  });

  it('is refused at project scope when no project was named, rather than defaulted', async () => {
    const client = await connect();
    try {
      // The refusal is the fix. A service that fell back to its own working
      // directory wrote one caller's managed keys into an unrelated repository's
      // checked-in settings, and this client must not talk it into doing that by
      // sending an empty root at the one scope where the root is the answer.
      await expect(
        client.plan(CLAUDE, { profile: 'recommended', settingsScope: 'project', projectRoot: '' }),
      ).rejects.toMatchObject({ code: DenyCode.LIFECYCLE_ERROR });
      await expect(
        client.plan(CLAUDE, { profile: 'recommended', settingsScope: 'project', projectRoot: '' }),
      ).rejects.toThrow(/will not guess/);
    } finally {
      client.close();
    }
  });
});

describe('protection-level display', () => {
  it('renders the level the service computed, never one derived from evidence', async () => {
    const client = await connect();
    try {
      const status = await client.status(CLAUDE);
      // The fixture is deliberately tempting: it carries protective *exercised*
      // evidence (a blocked probe) while the service's own answer is only
      // `integrated`. A client that ranked evidence would show
      // `Gateway Protected` here. This one shows what it was told.
      expect(status.achievedLevel).toBe('integrated');
      expect(status.evidence.some((e) => e.kind === 'exercised' && e.outcome === 'blocked')).toBe(true);

      const lines = renderStatus(status);
      const achieved = lines.find((l) => l.startsWith('Protection level:'));
      expect(achieved).toContain(levelLabel('integrated'));
      // The rung above appears only as the *next* level and only with the
      // reason it is not active — never as the achieved one.
      expect(achieved).not.toContain('Gateway Protected');
      expect(lines.find((l) => l.startsWith('Next level:'))).toContain('Gateway Protected');
    } finally {
      client.close();
    }
  });

  it('shows exercised evidence separately from read-back evidence', async () => {
    const client = await connect();
    try {
      const status = await client.status(CLAUDE);
      const split = splitEvidence(status.evidence);
      expect(split.exercised).toHaveLength(1);
      expect(split.readBack).toHaveLength(1);
      expect(split.absent).toHaveLength(1);

      const rendered = renderStatus(status).join('\n');
      expect(rendered).toContain('Exercised (behaviour observed):');
      expect(rendered).toContain('Read back (configuration):');
      // A configuration that exists is not protection, so the two must never be
      // folded into one line.
      expect(rendered.indexOf('Exercised')).not.toBe(rendered.indexOf('Read back'));
    } finally {
      client.close();
    }
  });

  it('names Host Enforced as unavailable rather than omitting it', async () => {
    const client = await connect();
    try {
      const rendered = renderStatus(await client.status(CLAUDE)).join('\n');
      // Silence here reads as "there is nothing above what I have", which is the
      // over-claim §7.3 exists to prevent.
      expect(rendered).toContain(HOST_ENFORCED_UNAVAILABLE);
    } finally {
      client.close();
    }
  });

  it('carries the observation timestamp, so the claim is "verified at T"', async () => {
    const client = await connect();
    try {
      const status = await client.status(CLAUDE);
      expect(status.observedAtUnixSecs).toBeGreaterThan(0n);
      expect(renderStatus(status).join('\n')).toContain('Observed at:');
    } finally {
      client.close();
    }
  });

  it('shows the next level up and why it is not active', async () => {
    const client = await connect();
    try {
      const status = await client.status(CLAUDE);
      expect(status.nextLevel?.level).toBe('gateway_protected');
      expect(renderStatus(status).join('\n')).toContain('no core-side probe observation');
    } finally {
      client.close();
    }
  });
});

describe('privacy-preserving event display', () => {
  it('shows counts, verdict kinds and redaction labels only', async () => {
    const client = await connect();
    try {
      const rendered = renderEvents((await client.scopedEvents(CLAUDE)).events).join('\n');
      expect(rendered).toContain('redacted');
      expect(rendered).toContain('anthropic_api_key');
      expect(rendered).toContain('×2');
    } finally {
      client.close();
    }
  });
});
