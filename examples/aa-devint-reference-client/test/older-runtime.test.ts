/**
 * What this client does when the runtime it reached is older than the field it
 * needs to send (AAASM-5913).
 *
 * `test/contract` runs against the real server built from this same tree, so it
 * can only ever negotiate the top of the window — which is exactly the case that
 * is safe. The dangerous case is a client shipped in a plugin meeting a runtime
 * installed months earlier, and there is no way to stage that against a
 * current-tree server. So the *peer* is faked here, deliberately and narrowly:
 * it answers `Hello` with a version and records the tag of every frame that
 * follows.
 *
 * Nothing about the server's behaviour is asserted through it. The property
 * under test is entirely on this side of the socket — that a `plan` at project
 * scope is **never written** below {@link DI_API_PROJECT_ROOT_SINCE} — and it has
 * to be tested by observing the wire, because `PlanArgs.project_root` is a
 * proto3 field an older peer discards during decode. An ignored root and an
 * unsent one are indistinguishable in any reply, which is the whole defect.
 */
import { createServer, type Server, type Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { create, toBinary } from '@bufbuild/protobuf';

import {
  DevIntClient,
  DI_API_MIN_SUPPORTED,
  DI_API_PROJECT_ROOT_SINCE,
} from '../src/client.js';
import { CapabilityToken } from '../src/credential.js';
import { DeniedError, ProjectRootUnsupportedError } from '../src/errors.js';
import { TAG_DENIED, TAG_HELLO, TAG_HELLO_ACK, TAG_REQUEST } from '../src/framing.js';
import {
  DeniedSchema,
  DenyCode,
  HelloAckSchema,
  NegotiationOutcome,
} from '../src/generated/devint_pb.js';

const IDENTITY = { name: 'older-runtime-test', version: '0.0.1' } as const;
const CLAUDE = 'claude-code';
/** Well-formed and meaningless: this peer authenticates nothing. */
const TOKEN = CapabilityToken.parse('a'.repeat(64));

/** A peer pinned to one DI-API version, which records what it is sent. */
interface OlderRuntime {
  readonly socket: string;
  /** Frame tags received after the opening `Hello`, in arrival order. */
  readonly received: number[];
  stop(): Promise<void>;
}

function encodeVarint(value: number): Uint8Array {
  const bytes: number[] = [];
  let v = value;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (v !== 0);
  return Uint8Array.from(bytes);
}

/** `[1-byte tag][varint length][payload]`, matching `devint/codec.rs`. */
function encodeFrame(tag: number, body: Uint8Array): Uint8Array {
  const len = encodeVarint(body.length);
  const out = new Uint8Array(1 + len.length + body.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(body, 1 + len.length);
  return out;
}

/** Read whole frames out of `buffer`, returning the tags and the remainder. */
function takeFrames(buffer: Buffer): { tags: number[]; rest: Buffer } {
  const tags: number[] = [];
  let cursor = buffer;
  for (;;) {
    if (cursor.length < 2) break;
    let len = 0;
    let shift = 0;
    let offset = 1;
    let complete = true;
    for (;;) {
      if (offset >= cursor.length) {
        complete = false;
        break;
      }
      const byte = cursor[offset] as number;
      offset += 1;
      len |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }
    if (!complete || cursor.length < offset + len) break;
    tags.push(cursor[0] as number);
    cursor = cursor.subarray(offset + len);
  }
  return { tags, rest: cursor };
}

async function startOlderRuntime(socketPath: string, diApiVersion: number): Promise<OlderRuntime> {
  const received: number[] = [];

  const server: Server = createServer((connection: Socket) => {
    let pending: Buffer = Buffer.alloc(0);
    connection.on('data', (chunk: Buffer) => {
      const { tags, rest } = takeFrames(Buffer.concat([pending, chunk]));
      pending = rest;
      for (const tag of tags) {
        if (tag === TAG_HELLO) {
          connection.write(
            encodeFrame(
              TAG_HELLO_ACK,
              toBinary(
                HelloAckSchema,
                create(HelloAckSchema, {
                  diApiVersion,
                  coreVersion: '0.0.1-older',
                  lifecycleSchemaVersion: 1,
                  outcome: NegotiationOutcome.SUPPORTED,
                  minSupported: DI_API_MIN_SUPPORTED,
                  maxSupported: diApiVersion,
                }),
              ),
            ),
          );
          continue;
        }
        received.push(tag);
        // Any verb is refused: this peer serves no lifecycle, and the point of
        // the reply is only to end the call so the client's own gate is what
        // distinguishes the cases rather than a hung socket.
        connection.write(
          encodeFrame(
            TAG_DENIED,
            toBinary(
              DeniedSchema,
              create(DeniedSchema, {
                requestId: 1n,
                code: DenyCode.LIFECYCLE_ERROR,
                message: 'this peer serves no lifecycle',
                remediation: 'Nothing to do; the frame reached the socket, which is what was asserted.',
              }),
            ),
          ),
        );
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });

  return {
    socket: socketPath,
    received,
    stop(): Promise<void> {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

let scratch: string;

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'devint-older-'));
});
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

describe('a runtime older than the project root field', () => {
  it('is refused at project scope before a single byte of the plan is written', async () => {
    // Every version below the gate, not just the one below it: a gate written as
    // `=== 5` would pass a one-version test and let a v2 plugin through.
    for (let version = DI_API_MIN_SUPPORTED; version < DI_API_PROJECT_ROOT_SINCE; version += 1) {
      const runtime = await startOlderRuntime(join(scratch, `v${version}.sock`), version);
      const client = await DevIntClient.connect(runtime.socket, IDENTITY, TOKEN);
      try {
        expect(client.negotiated.diApiVersion).toBe(version);
        const refused = await client
          .plan(CLAUDE, { profile: 'recommended', settingsScope: 'project', projectRoot: '/workspace/repo' })
          .then(
            () => null,
            (error: unknown) => error,
          );
        expect(refused).toBeInstanceOf(ProjectRootUnsupportedError);
        // The assertion the reply cannot make. A root that was sent and dropped
        // decodes exactly like one that was never sent, so "no request arrived"
        // is the only observation that separates the fix from the defect.
        expect(runtime.received).toEqual([]);
      } finally {
        client.close();
        await runtime.stop();
      }
    }
  });

  it('still writes the request at user and managed scope, which name no destination', async () => {
    for (const settingsScope of ['user', 'managed']) {
      const version = DI_API_PROJECT_ROOT_SINCE - 1;
      const runtime = await startOlderRuntime(join(scratch, `${settingsScope}.sock`), version);
      const client = await DevIntClient.connect(runtime.socket, IDENTITY, TOKEN);
      try {
        await expect(
          client.plan(CLAUDE, { profile: 'recommended', settingsScope, projectRoot: '' }),
        ).rejects.toBeInstanceOf(DeniedError);
        // Reached the socket. The refusal came from the peer, so the gate did
        // not quietly widen into "no plan below v6".
        expect(runtime.received).toEqual([TAG_REQUEST]);
      } finally {
        client.close();
        await runtime.stop();
      }
    }
  });
});
