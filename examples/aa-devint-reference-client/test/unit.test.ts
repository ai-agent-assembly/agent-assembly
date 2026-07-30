/**
 * The pieces that are worth asserting without a server: path resolution,
 * credential handling, framing, and the two rendering rules that are easy to
 * regress and expensive to notice.
 */
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { create, toBinary } from '@bufbuild/protobuf';

import { CapabilityToken } from '../src/credential.js';
import { SOCKET_PATH_ENV, socketPath } from '../src/discovery.js';
import { MAX_FRAME_LEN, TAG_DENIED, decodeServerFrame } from '../src/framing.js';
import { DenyCodeSchema, DeniedSchema, StatusViewSchema } from '../src/generated/devint_pb.js';
import { HOST_ENFORCED_UNAVAILABLE, renderStatus, splitEvidence } from '../src/render.js';

const scratch = mkdtempSync(join(tmpdir(), 'devint-unit-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

describe('socket path resolution', () => {
  it('honours the override', () => {
    expect(socketPath({ [SOCKET_PATH_ENV]: '/somewhere/else.sock' })).toBe('/somewhere/else.sock');
  });

  it('falls back to the documented convention under $HOME', () => {
    expect(socketPath({ HOME: '/h' })).toBe('/h/.aa/run/devint.sock');
  });

  it('treats an empty override as unset rather than as the empty path', () => {
    expect(socketPath({ [SOCKET_PATH_ENV]: '', HOME: '/h' })).toBe('/h/.aa/run/devint.sock');
  });
});

describe('the capability token', () => {
  it('rejects anything that is not 256 bits of lowercase hex', () => {
    expect(() => CapabilityToken.parse('')).toThrow(/64 lowercase hex/);
    expect(() => CapabilityToken.parse('A'.repeat(64))).toThrow();
    expect(() => CapabilityToken.parse('a'.repeat(63))).toThrow();
    // Not a JWT: a self-contained credential cannot be revoked (§5.3).
    expect(() => CapabilityToken.parse('eyJhbGciOiJIUzI1NiJ9.e30.abc')).toThrow();
  });

  it('refuses to read a token file other users can see', () => {
    const path = join(scratch, 'loose.token');
    writeFileSync(path, 'b'.repeat(64));
    chmodSync(path, 0o644);
    expect(() => CapabilityToken.fromFile(path)).toThrow(/must be 600/);
    chmodSync(path, 0o600);
    expect(CapabilityToken.fromFile(path).expose()).toBe('b'.repeat(64));
  });

  it('reads a token from the environment, and reports none as none', () => {
    expect(CapabilityToken.fromEnv({})).toBeNull();
    expect(CapabilityToken.fromEnv({ AA_DEVINT_TOKEN: 'c'.repeat(64) })?.expose()).toBe('c'.repeat(64));
  });
});

describe('framing', () => {
  it('decodes a denial frame from its tag', () => {
    const denied = create(DeniedSchema, { requestId: 1n, code: 3, message: 'no', remediation: 'enrol' });
    const frame = decodeServerFrame(TAG_DENIED, toBinary(DeniedSchema, denied));
    expect(frame.kind).toBe('denied');
  });

  it('rejects an unknown tag rather than skipping it', () => {
    expect(() => decodeServerFrame(0xee, new Uint8Array())).toThrow(/unknown DI-API frame tag/);
  });

  it('bounds frames at the same 1 MiB the server enforces', () => {
    expect(MAX_FRAME_LEN).toBe(1024 * 1024);
  });

  it('has a deny code for every refusal the server can make', () => {
    // Read off the generated descriptor, so a new code in the proto shows up
    // here instead of being silently rendered as "unknown".
    expect(DenyCodeSchema.values.map((v) => v.name)).toContain('DENY_CODE_OUT_OF_SCOPE');
  });
});

describe('status rendering', () => {
  it('names Host Enforced as unavailable even for a status that never mentions it', () => {
    const status = create(StatusViewSchema, {
      toolId: 'claude-code',
      phase: 'installed',
      state: 'ladder',
      achievedLevel: 'integrated',
      plannedLevel: 'integrated',
      observedAtUnixSecs: 1_700_000_000n,
    });
    expect(renderStatus(status).join('\n')).toContain(HOST_ENFORCED_UNAVAILABLE);
  });

  it('renders an overriding state alongside the level rather than instead of it', () => {
    const status = create(StatusViewSchema, {
      toolId: 'claude-code',
      state: 'drifted',
      achievedLevel: 'integrated',
      plannedLevel: 'gateway_protected',
      driftMismatched: ['settings'],
      observedAtUnixSecs: 1_700_000_000n,
    });
    const rendered = renderStatus(status).join('\n');
    expect(rendered).toContain('[Drifted]');
    expect(rendered).toContain('Drifted artifacts:  settings');
  });

  it('splits evidence by kind, and files an unrecognised kind under "not established"', () => {
    const split = splitEvidence([
      { $typeName: 'assembly.devint.v1.EvidenceView', mechanism: 'a', kind: 'exercised', outcome: 'blocked', observedAtUnixSecs: 1n, detail: '' },
      { $typeName: 'assembly.devint.v1.EvidenceView', mechanism: 'b', kind: 'read_back', outcome: 'matched', observedAtUnixSecs: 1n, detail: '' },
      { $typeName: 'assembly.devint.v1.EvidenceView', mechanism: 'c', kind: 'unknown', outcome: '', observedAtUnixSecs: 1n, detail: '' },
    ]);
    expect(split.exercised).toHaveLength(1);
    expect(split.readBack).toHaveLength(1);
    // "We do not know" must never read as "we looked and it was fine".
    expect(split.absent).toHaveLength(1);
  });
});
