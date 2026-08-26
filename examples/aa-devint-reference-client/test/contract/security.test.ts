/**
 * What a compromised or modified reference client still cannot do.
 *
 * Every test here runs against the **real** `aa_runtime::devint::DevIntServer`
 * over a real Unix socket (see `test/harness.ts`), and most of them drive it
 * through `test/raw.ts` rather than through `DevIntClient` — because a client
 * that has been tampered with would not use the polite wrapper either.
 *
 * The four properties AAASM-5282 names, and where each is proved:
 *
 * | Property | Test |
 * | --- | --- |
 * | Cannot read raw protected content | `no response the client receives carries a secret` |
 * | Cannot invoke unrelated core APIs | `the verb space is closed` + `the request schema has no passthrough` |
 * | Cannot reuse credentials for another integration | `a token scoped to tool A cannot act on tool B` |
 * | Cannot silently downgrade negotiation | `a downgrade is an outcome, not a fallback` |
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { DevIntClient, DI_API_MAX_SUPPORTED } from '../../src/client.js';
import { CapabilityToken } from '../../src/credential.js';
import { DeniedError, IncompatibleError } from '../../src/errors.js';
import { DenyCode, NegotiationOutcome, RequestSchema, Verb } from '../../src/generated/devint_pb.js';
import { renderEvents, renderStatus, renderSteps } from '../../src/render.js';
import { startHarness, type Harness } from '../harness.js';
import { RawClient, TOOL_SCOPED_VERBS } from '../raw.js';

const CLAUDE = 'claude-code';
const CODEX = 'codex';
const IDENTITY = { name: 'contract-test', version: '0.0.1' } as const;

let harness: Harness;
let scratch: string;

beforeAll(async () => {
  scratch = mkdtempSync(join(tmpdir(), 'devint-contract-'));
  harness = await startHarness(join(scratch, 'devint.sock'));
}, 40_000);

afterAll(async () => {
  await harness?.stop();
  rmSync(scratch, { recursive: true, force: true });
});

async function connected(token: string | null): Promise<DevIntClient> {
  return DevIntClient.connect(harness.socket, IDENTITY, token === null ? null : CapabilityToken.parse(token));
}

describe('a token scoped to tool A cannot act on tool B', () => {
  it.each(TOOL_SCOPED_VERBS)('verb %i on codex is refused OUT_OF_SCOPE', async (verb) => {
    const raw = await RawClient.open(harness.socket);
    try {
      await raw.negotiate();
      const frame = await raw.send(verb, CODEX, harness.tokens.claudeOnly);
      expect(frame.kind).toBe('denied');
      if (frame.kind !== 'denied') return;
      expect(frame.message.code).toBe(DenyCode.OUT_OF_SCOPE);
      // The refusal must not be reported as a missing tool or a lifecycle
      // failure: the tool exists, this credential simply does not reach it.
      expect(frame.message.code).not.toBe(DenyCode.UNKNOWN_TOOL);
    } finally {
      raw.close();
    }
  });

  it('the same token works on its own tool, so the denial is about scope', async () => {
    const client = await connected(harness.tokens.claudeOnly);
    try {
      const status = await client.status(CLAUDE);
      expect(status.toolId).toBe(CLAUDE);
      await expect(client.status(CODEX)).rejects.toBeInstanceOf(DeniedError);
    } finally {
      client.close();
    }
  });

  it('a read-only token cannot mutate any tool', async () => {
    const client = await connected(harness.tokens.readOnly);
    try {
      await expect(client.apply(CLAUDE, 'plan-1')).rejects.toMatchObject({ code: DenyCode.OUT_OF_SCOPE });
      await expect(client.repair(CLAUDE)).rejects.toMatchObject({ code: DenyCode.OUT_OF_SCOPE });
      await expect(client.remove(CLAUDE, 'plan-1')).rejects.toMatchObject({ code: DenyCode.OUT_OF_SCOPE });
      // …and can still read, so the scope is a boundary rather than a lockout.
      expect((await client.status(CLAUDE)).toolId).toBe(CLAUDE);
    } finally {
      client.close();
    }
  });

  it('a status-only token cannot even plan on its own tool', async () => {
    const client = await connected(harness.tokens.statusOnly);
    try {
      await expect(
        client.plan(CLAUDE, { profile: 'recommended', settingsScope: 'user', projectRoot: '' }),
      ).rejects.toMatchObject({
        code: DenyCode.OUT_OF_SCOPE,
      });
    } finally {
      client.close();
    }
  });
});

describe('no response the client receives carries a secret', () => {
  it('a poisoned plan reaches the client with its step values gone', async () => {
    const client = await connected(harness.tokens.full);
    try {
      const plan = await client.plan(CLAUDE, {
        profile: 'recommended',
        settingsScope: 'user',
        policyProfileId: 'team-default',
        projectRoot: '',
      });

      // The wire message, everything derived from it, and everything rendered
      // from it. A leak that only survived to the screen is still a leak.
      const surfaces = [
        JSON.stringify(plan, replaceBigInt),
        renderSteps(plan.steps).join('\n'),
      ];
      for (const surface of surfaces) {
        expect(surface).not.toContain(harness.leakSentinel);
      }

      // …and the client still received something worth showing a reviewer, so
      // this is minimisation rather than an empty response.
      expect(plan.steps).toHaveLength(2);
      expect(plan.steps[1]?.actionKind).toBe('inject_launch_environment');
      expect(renderSteps(plan.steps).join('\n')).toContain('Content SHA-256');
    } finally {
      client.close();
    }
  });

  it('the whole lifecycle is secret-free end to end', async () => {
    const client = await connected(harness.tokens.full);
    try {
      const collected = [
        JSON.stringify(await client.listTools(), replaceBigInt),
        JSON.stringify(await client.apply(CLAUDE, 'plan-1'), replaceBigInt),
        JSON.stringify(await client.status(CLAUDE), replaceBigInt),
        JSON.stringify(await client.verify(CLAUDE), replaceBigInt),
        JSON.stringify(await client.repair(CLAUDE), replaceBigInt),
        JSON.stringify(await client.remove(CLAUDE, 'plan-1'), replaceBigInt),
        JSON.stringify(await client.scopedEvents(CLAUDE), replaceBigInt),
        renderStatus(await client.status(CLAUDE)).join('\n'),
        renderEvents((await client.scopedEvents(CLAUDE)).events).join('\n'),
      ].join('\n');

      expect(collected).not.toContain(harness.leakSentinel);
      expect(collected).not.toContain(harness.eventSentinel);
    } finally {
      client.close();
    }
  });

  it('events carry redaction labels and no matched content', async () => {
    const client = await connected(harness.tokens.full);
    try {
      const events = await client.scopedEvents(CLAUDE);
      expect(events.events[0]?.redactionLabels).toEqual(['anthropic_api_key']);
      // The label names the *kind*; there is no field on `ScopedEvent` able to
      // hold the prompt, the tool output or the value that matched.
      expect(Object.keys(events.events[0] ?? {})).toEqual(
        expect.arrayContaining(['occurredAtUnixSecs', 'verdictKind', 'mechanism', 'count', 'redactionLabels']),
      );
      expect(JSON.stringify(events.events[0], replaceBigInt)).not.toContain(harness.eventSentinel);
    } finally {
      client.close();
    }
  });

  it('the token never comes back on the wire, not even in a denial', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      await raw.negotiate();
      const frame = await raw.send(Verb.STATUS, CODEX, harness.tokens.claudeOnly);
      expect(frame.kind).toBe('denied');
      if (frame.kind !== 'denied') return;
      const rendered = JSON.stringify(frame.message, replaceBigInt);
      expect(rendered).not.toContain(harness.tokens.claudeOnly);
      // The message must also not explain how close the credential came to
      // matching, which would turn a denial into an oracle.
      expect(frame.message.message.toLowerCase()).not.toContain('expired');
    } finally {
      raw.close();
    }
  });
});

describe('unrelated core operations are unreachable', () => {
  it('the verb space is closed: an out-of-set discriminant is refused', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      await raw.negotiate();
      for (const bogus of [0, 42, 99, 1_000_000]) {
        const frame = await raw.send(bogus, CLAUDE, harness.tokens.full);
        expect(frame.kind).toBe('denied');
        if (frame.kind !== 'denied') continue;
        expect(frame.message.code).toBe(DenyCode.UNKNOWN_VERB);
      }
    } finally {
      raw.close();
    }
  });

  it('the request schema has no field a caller could smuggle an operation through', () => {
    // Read off the *generated* descriptor, so this assertion tracks
    // proto/devint.proto rather than a transcription of it. A new field named
    // `method`, `path`, `filter` or `payload` fails here at the moment it is
    // generated, not at the moment someone exploits it.
    const fields = RequestSchema.fields.map((f) => f.name).sort();
    expect(fields).toEqual(
      ['approval', 'apply', 'capability_token', 'events', 'plan', 'remove', 'request_id', 'tool_id', 'verb'].sort(),
    );
    for (const forbidden of ['method', 'path', 'url', 'query', 'filter', 'payload', 'body', 'metadata', 'extra']) {
      expect(fields).not.toContain(forbidden);
    }
  });

  it('the verb enum has exactly the nine operations ADR 0030 §5.6.1 closes over', () => {
    const named = Object.values(Verb).filter((v): v is number => typeof v === 'number' && v !== Verb.UNSPECIFIED);
    expect(named).toHaveLength(9);
    // No `check`, no `evaluate`, no `decide`: a policy decision is not
    // obtainable here, it travels SDK → aa-sdk-client → runtime/gateway.
    const names = Object.keys(Verb).filter((k) => Number.isNaN(Number(k)));
    for (const name of names) {
      expect(name.toLowerCase()).not.toMatch(/check|evaluate|decide|authorize|audit/);
    }
  });

  it('an unenrolled client gets nothing at all — there is no anonymous tier', async () => {
    const client = await connected(null);
    try {
      // Negotiation still succeeds: that is how a client learns what to tell
      // the user. Nothing behind it does.
      expect(client.negotiated.diApiVersion).toBeGreaterThan(0);
      expect(client.enrolled).toBe(false);
      await expect(client.listTools()).rejects.toMatchObject({ code: DenyCode.UNAUTHENTICATED });
      await expect(client.status(CLAUDE)).rejects.toMatchObject({ code: DenyCode.UNAUTHENTICATED });
    } finally {
      client.close();
    }
  });

  it('an expired credential is refused, with re-enrolment as the remedy', async () => {
    const client = await connected(harness.tokens.expired);
    try {
      await expect(client.status(CLAUDE)).rejects.toMatchObject({ code: DenyCode.TOKEN_EXPIRED });
    } finally {
      client.close();
    }
  });

  it('a forged credential is indistinguishable from an absent one', async () => {
    const client = await connected('f'.repeat(64));
    try {
      await expect(client.status(CLAUDE)).rejects.toMatchObject({ code: DenyCode.UNAUTHENTICATED });
    } finally {
      client.close();
    }
  });
});

describe('a downgrade is an outcome, not a fallback', () => {
  it('a v1-only client is told, by name, which verbs it does not have', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      const frame = await raw.hello([1]);
      expect(frame.kind).toBe('hello-ack');
      if (frame.kind !== 'hello-ack') return;
      expect(frame.message.outcome).toBe(NegotiationOutcome.DEGRADED);
      expect(frame.message.unavailableVerbs).toContain('scoped_events');
      expect(frame.message.unavailableVerbs).toContain('approval_relay');
      expect(frame.message.remediation).not.toBe('');
    } finally {
      raw.close();
    }
  });

  it('a verb missing at the negotiated version is refused even with a full-scope token', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      await raw.negotiate([1]);
      const frame = await raw.send(Verb.SCOPED_EVENTS, CLAUDE, harness.tokens.full);
      expect(frame.kind).toBe('denied');
      if (frame.kind !== 'denied') return;
      expect(frame.message.code).toBe(DenyCode.UNAVAILABLE_AT_VERSION);
    } finally {
      raw.close();
    }
  });

  it('a second Hello cannot renegotiate the connection down', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      await raw.negotiate([1, 2]);
      const frame = await raw.hello([1]);
      expect(frame.kind).toBe('denied');
      if (frame.kind !== 'denied') return;
      expect(frame.message.code).toBe(DenyCode.PROTOCOL_VIOLATION);
    } finally {
      raw.close();
    }
  });

  it('no shared version is Incompatible with remediation, not a silent v1', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      const frame = await raw.hello([999]);
      expect(frame.kind).toBe('incompatible');
      if (frame.kind !== 'incompatible') return;
      expect(frame.message.remediation).not.toBe('');
      expect(frame.message.minSupported).toBeGreaterThan(0);
    } finally {
      raw.close();
    }
  });

  it('the reference client surfaces incompatibility as an actionable error', async () => {
    // The client always offers its whole window, so this case is reached by
    // making the *server* the far side of the gap — which is what a user with an
    // old runtime and a new extension actually has.
    const raw = await RawClient.open(harness.socket);
    try {
      const frame = await raw.hello([0]);
      expect(frame.kind).toBe('incompatible');
    } finally {
      raw.close();
    }

    // …and the typed error a UI would catch carries the window to show.
    const error = new IncompatibleError({
      $typeName: 'assembly.devint.v1.Incompatible',
      reason: 'r',
      remediation: 'm',
      minSupported: 1,
      maxSupported: 2,
    });
    expect(error.supportedWindow).toBe('1–2');
  });

  it('the client offers its whole version window, so it never degrades itself', async () => {
    const client = await connected(harness.tokens.full);
    try {
      expect(client.negotiated.degraded).toBe(false);
      expect(client.negotiated.unavailableVerbs).toEqual([]);
      expect(client.supports(Verb.SCOPED_EVENTS)).toBe(true);
    } finally {
      client.close();
    }
  });
});

describe('which build answered is a v4 addition, and its absence is legible', () => {
  /**
   * AAASM-5628 added `HelloAck.provenance` at DI-API v4. The TypeScript
   * bindings are generated from the same `proto/devint.proto` the Rust server
   * is, so this is the consumer-side half of the additive-change claim: the
   * field arrives when it is negotiated for, and *is absent* — not empty —
   * otherwise.
   *
   * That distinction is the whole of the older-peer contract. If a v1–v3 peer
   * were sent a zero-valued `RuntimeProvenance`, a client could not tell
   * "this runtime cannot say what it is" from "this runtime says it is
   * nothing", and the second reads as an answer.
   */
  it('a v4 peer receives the message, naming the process that answered', async () => {
    const raw = await RawClient.open(harness.socket);
    try {
      const frame = await raw.hello([4]);
      expect(frame.kind).toBe('hello-ack');
      if (frame.kind !== 'hello-ack') return;
      expect(frame.message.diApiVersion).toBe(4);
      expect(frame.message.outcome).toBe(NegotiationOutcome.SUPPORTED);

      const provenance = frame.message.provenance;
      expect(provenance).toBeDefined();
      if (provenance === undefined) return;
      expect(provenance.pid).toBeGreaterThan(0);
      expect(provenance.executablePath).not.toBe('');
      expect(provenance.coreVersion).not.toBe('');
      // Never fabricated: `build_sha` is a commit or the honest `unknown`
      // sentinel, and `build_id_source` says which mechanism produced it.
      expect(provenance.buildSha).not.toBe('');
      expect(['injected', 'checkout', 'packaged', 'absent']).toContain(provenance.buildIdSource);
    } finally {
      raw.close();
    }
  });

  it('a v1–v3 peer receives no provenance field at all, rather than an empty one', async () => {
    for (const version of [1, 2, 3]) {
      const raw = await RawClient.open(harness.socket);
      try {
        const frame = await raw.hello([version]);
        expect(frame.kind).toBe('hello-ack');
        if (frame.kind !== 'hello-ack') continue;
        expect(frame.message.diApiVersion).toBe(version);
        expect(frame.message.provenance).toBeUndefined();
      } finally {
        raw.close();
      }
    }
  });

  it('a peer that stops below v4 is SUPPORTED rather than degraded', async () => {
    // v3 and v4 add what a peer can *say*, not what it can call, so a peer that
    // never negotiates them must still get a full connection — an additive
    // change that degraded an existing client would not be additive.
    //
    // Asserted through a raw peer that names v2 explicitly. Until AAASM-5913
    // this was asserted through the reference client itself, whose window
    // stopped at 2 — but v6 added a field to a *request*, so that client now
    // offers the whole window (see `DI_API_MAX_SUPPORTED`) and is no longer an
    // older peer. Leaving the assertion there would have made it a claim about
    // the top of the window, which is the opposite of the property.
    const raw = await RawClient.open(harness.socket);
    try {
      const frame = await raw.hello([2]);
      expect(frame.kind).toBe('hello-ack');
      if (frame.kind !== 'hello-ack') return;
      expect(frame.message.diApiVersion).toBe(2);
      expect(frame.message.outcome).toBe(NegotiationOutcome.SUPPORTED);
      expect(frame.message.unavailableVerbs).toEqual([]);
    } finally {
      raw.close();
    }
  });

  it('the reference client negotiates the top of its window, not a degraded connection', async () => {
    const client = await connected(harness.tokens.full);
    try {
      expect(client.negotiated.diApiVersion).toBe(DI_API_MAX_SUPPORTED);
      expect(client.negotiated.degraded).toBe(false);
      expect(client.negotiated.unavailableVerbs).toEqual([]);
    } finally {
      client.close();
    }
  });
});

/** `JSON.stringify` cannot serialise the `bigint` fields the wire uses. */
function replaceBigInt(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}
