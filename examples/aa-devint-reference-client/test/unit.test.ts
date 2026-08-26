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

import {
  DI_API_MAX_SUPPORTED,
  DI_API_MIN_SUPPORTED,
  DI_API_PROJECT_ROOT_SINCE,
  projectRootRequiresNewerRuntime,
} from '../src/client.js';
import { CapabilityToken } from '../src/credential.js';
import { SOCKET_PATH_ENV, socketPath } from '../src/discovery.js';
import { ProjectRootUnsupportedError, actionable } from '../src/errors.js';
import { MAX_FRAME_LEN, TAG_DENIED, decodeServerFrame } from '../src/framing.js';
import { DenyCodeSchema, DeniedSchema, StatusViewSchema } from '../src/generated/devint_pb.js';
import { PROJECT_ROOT_ENV, projectRoot } from '../src/project.js';
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

describe('project root resolution', () => {
  it('answers with the working directory of the process that asked, which only it knows', () => {
    // Not the runtime's: that is a shared daemon, and its directory is a fact
    // about whoever started it (AAASM-5913).
    expect(projectRoot('project', {})).toBe(process.cwd());
  });

  it('honours the override, and makes a relative one absolute', () => {
    expect(projectRoot('project', { [PROJECT_ROOT_ENV]: '/workspace/repo' })).toBe('/workspace/repo');
    // A relative path is refused by the service, because relative to *its*
    // directory is not relative to ours. Here is the only place it can be
    // resolved to what the caller meant.
    expect(projectRoot('project', { [PROJECT_ROOT_ENV]: 'repo' })).toBe(join(process.cwd(), 'repo'));
  });

  it('treats an empty override as unset rather than as the empty path', () => {
    expect(projectRoot('user', { [PROJECT_ROOT_ENV]: '' }, () => '/workspace/repo')).toBe('/workspace/repo');
  });

  it('refuses a project-scoped request whose directory cannot be determined', () => {
    const deleted = (): string => {
      throw new Error('ENOENT: no such file or directory, uv_cwd');
    };
    // The alternative is sending "" and letting the service refuse. It would,
    // but the user would learn nothing they can act on: only this side knows
    // *why* there is no project to name.
    expect(() => projectRoot('project', {}, deleted)).toThrow(/could not be determined/);
    expect(() => projectRoot('project', {}, deleted)).toThrow(new RegExp(PROJECT_ROOT_ENV));
  });

  it('still proceeds at user scope, where the root is context and not a destination', () => {
    const deleted = (): string => {
      throw new Error('ENOENT: no such file or directory, uv_cwd');
    };
    // The service uses it there only to disclose that a nearby project config
    // exists, so losing that disclosure must not cost the user the operation.
    expect(projectRoot('user', {}, deleted)).toBe('');
    expect(projectRoot('managed', {}, deleted)).toBe('');
  });
});

/**
 * The version gate that resolving a root correctly is not sufficient for.
 *
 * Asserted through the exported predicate rather than through `plan()`, because
 * the constructor is private and the failure being prevented is a request that
 * must never be written: there is no reply to inspect, and a test that needed a
 * live pre-v6 runtime to reach this rule would not run at all.
 */
describe('the project-root version gate', () => {
  it('refuses project scope at every version below the one that honours a root', () => {
    for (let version = DI_API_MIN_SUPPORTED; version < DI_API_PROJECT_ROOT_SINCE; version += 1) {
      expect(projectRootRequiresNewerRuntime(version, 'project')).toBe(true);
    }
  });

  it('allows project scope from that version upward', () => {
    expect(projectRootRequiresNewerRuntime(DI_API_PROJECT_ROOT_SINCE, 'project')).toBe(false);
    expect(projectRootRequiresNewerRuntime(DI_API_PROJECT_ROOT_SINCE + 1, 'project')).toBe(false);
  });

  it('leaves user and managed scope alone, because their destination was never ours to name', () => {
    for (let version = DI_API_MIN_SUPPORTED; version <= DI_API_MAX_SUPPORTED; version += 1) {
      expect(projectRootRequiresNewerRuntime(version, 'user')).toBe(false);
      expect(projectRootRequiresNewerRuntime(version, 'managed')).toBe(false);
    }
  });

  it('does not claim an unrecognised token means project scope', () => {
    // The wire vocabulary is lowercase (`projection::parse_scope`). Answering a
    // typo with "upgrade your runtime" would send the user after the wrong
    // thing; rejecting an unknown scope stays the service's job, and its
    // message is the one that names the actual mistake.
    expect(projectRootRequiresNewerRuntime(DI_API_MIN_SUPPORTED, 'Project')).toBe(false);
    expect(projectRootRequiresNewerRuntime(DI_API_MIN_SUPPORTED, 'PROJECT')).toBe(false);
    expect(projectRootRequiresNewerRuntime(DI_API_MIN_SUPPORTED, '')).toBe(false);
  });

  it('says which side to upgrade, and that two of the three scopes still work', () => {
    // The whole value of raising this before the write is the sentence it
    // produces, so the sentence is part of the contract: an error naming only
    // the version would leave a user unable to tell whether AASM is unusable
    // against this runtime or merely unusable at one scope.
    const error = new ProjectRootUnsupportedError(2, DI_API_PROJECT_ROOT_SINCE);
    expect(error).toBeInstanceOf(ProjectRootUnsupportedError);
    expect(error.message).toContain('DI-API 2');
    expect(error.message).toContain(`DI-API ${DI_API_PROJECT_ROOT_SINCE}`);
    expect(error.remediation).toContain(`DI-API ${DI_API_PROJECT_ROOT_SINCE} or later`);
    expect(error.remediation).toMatch(/user and managed scope are unaffected/i);
    expect(actionable(error)).toBe(`${error.message} — ${error.remediation}`);
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
