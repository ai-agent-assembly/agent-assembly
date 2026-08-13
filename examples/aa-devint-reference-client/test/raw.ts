/**
 * A hostile client: the wire, with none of the client's discipline.
 *
 * `DevIntClient` cannot send a verb outside the closed set, cannot renegotiate
 * mid-connection and cannot suppress a degraded outcome — which is exactly why
 * it is the wrong tool for proving that the *server* stops those things. A
 * compromised extension would not politely use the reference client either.
 *
 * So the negative tests drive this instead: raw frames, arbitrary discriminants,
 * arbitrary version offers, tokens presented for tools they were never scoped
 * to. If the boundary holds against this, it holds.
 */
import { connect, type Socket } from 'node:net';
import { create } from '@bufbuild/protobuf';

import { FrameReader, encodeHello, encodeRequest, type ServerFrame } from '../src/framing.js';
import {
  ApplyArgsSchema,
  ApprovalRelayArgsSchema,
  HelloSchema,
  PlanArgsSchema,
  RemoveArgsSchema,
  RequestSchema,
  ScopedEventsArgsSchema,
  Verb,
} from '../src/generated/devint_pb.js';

/** Every tool-scoped verb, i.e. everything except `list_tools`. */
export const TOOL_SCOPED_VERBS = [
  Verb.PLAN,
  Verb.APPLY,
  Verb.STATUS,
  Verb.VERIFY,
  Verb.REPAIR,
  Verb.REMOVE,
  Verb.SCOPED_EVENTS,
  Verb.APPROVAL_RELAY,
] as const;

/** A connection that has done no negotiation and obeys no invariant. */
export class RawClient {
  private constructor(
    private readonly socket: Socket,
    private readonly reader: FrameReader,
  ) {}

  static async open(path: string): Promise<RawClient> {
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = connect(path);
      s.once('connect', () => resolve(s));
      s.once('error', reject);
    });
    return new RawClient(socket, new FrameReader(socket));
  }

  /** Send a `Hello` offering exactly `versions`. */
  async hello(versions: number[], lifecycleSchemaVersions = [1]): Promise<ServerFrame> {
    this.socket.write(
      encodeHello(
        create(HelloSchema, {
          clientName: 'hostile-probe',
          clientVersion: '0.0.0',
          diApiVersions: versions,
          lifecycleSchemaVersions,
        }),
      ),
    );
    return this.reader.next();
  }

  /** Send a `Hello` and require it to be accepted. */
  async negotiate(versions = [1, 2]): Promise<void> {
    const frame = await this.hello(versions);
    if (frame.kind !== 'hello-ack') throw new Error(`expected HelloAck, got ${frame.kind}`);
  }

  /**
   * Send a request with whatever verb discriminant is asked for — including one
   * that is not in the generated enum at all.
   */
  async send(verb: number, toolId: string, token: string, requestId = 1n): Promise<ServerFrame> {
    this.socket.write(
      encodeRequest(
        create(RequestSchema, {
          requestId,
          verb: verb as Verb,
          capabilityToken: token,
          toolId,
          ...argsFor(verb),
        }),
      ),
    );
    return this.reader.next();
  }

  close(): void {
    this.socket.destroy();
  }
}

/** Fill in the per-verb sub-message so a request is well-formed. */
function argsFor(verb: number): Record<string, unknown> {
  switch (verb) {
    case Verb.PLAN:
      return {
        plan: create(PlanArgsSchema, {
          profile: 'recommended',
          settingsScope: 'user',
          policyProfileId: 'team-default',
        }),
      };
    case Verb.APPLY:
      return { apply: create(ApplyArgsSchema, { planId: 'plan-1' }) };
    case Verb.REMOVE:
      return { remove: create(RemoveArgsSchema, { planId: 'plan-1' }) };
    case Verb.SCOPED_EVENTS:
      return { events: create(ScopedEventsArgsSchema, { limit: 10, sinceUnixSecs: 0n }) };
    case Verb.APPROVAL_RELAY:
      return { approval: create(ApprovalRelayArgsSchema, { approvalId: 'approval-1', userInput: 'approve' }) };
    default:
      return {};
  }
}
