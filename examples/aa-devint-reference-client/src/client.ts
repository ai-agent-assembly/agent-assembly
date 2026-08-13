/**
 * The thin client: discover, negotiate, present a token, render what came back.
 *
 * This is the whole of the client's authority. It has nine methods because the
 * verb space has nine members (`proto/devint.proto`), and it has no tenth
 * because there is nothing else to ask for — no `call`, no method string, no
 * path, no filter, no forwarded envelope. An operation that does not exist
 * cannot be requested however the request is crafted, which is the property
 * ADR 0030 §5.6.1 makes structural and this class inherits for free by being
 * generated-enum-driven.
 *
 * What it deliberately cannot do, and why each is a property of the code rather
 * than a rule someone follows:
 *
 * | Excluded | Why it is unreachable |
 * | --- | --- |
 * | Evaluate policy | There is no policy verb, and this package cannot decode a policy message — `src/generated/` holds only DI-API types. |
 * | Scan or redact | No scanner is imported, and no response type can carry content to scan. |
 * | Modify tool config | Nothing here writes a file; mutation happens by asking the runtime to apply a plan it authored. |
 * | Hold core credentials | {@link CapabilityToken} is the only credential type in the package. |
 * | Decide a protection level | Every level string this client emits came off the wire; see `render.ts`. |
 * | Start binaries | No process is spawned; lifecycle "runs" are the runtime's `apply`. |
 */
import { connect as connectUnixSocket, type Socket } from 'node:net';
import { create } from '@bufbuild/protobuf';

import type { CapabilityToken } from './credential.js';
import {
  DeniedError,
  IncompatibleError,
  RuntimeNotRunningError,
  TransportError,
  UnexpectedFrameError,
  VerbUnavailableError,
} from './errors.js';
import { FrameReader, encodeHello, encodeRequest } from './framing.js';
import {
  ApprovalRelayArgsSchema,
  ApplyArgsSchema,
  HelloSchema,
  NegotiationOutcome,
  PlanArgsSchema,
  RemoveArgsSchema,
  RequestSchema,
  ScopedEventsArgsSchema,
  Verb,
  type ApplyArgs,
  type ApplyView,
  type ApprovalRelayAck,
  type ApprovalRelayArgs,
  type PlanArgs,
  type PlanView,
  type RemoveArgs,
  type ScopedEventsArgs,
  type RemovalView,
  type RepairView,
  type Response,
  type ScopedEventList,
  type StatusView,
  type ToolList,
  type VerificationView,
} from './generated/devint_pb.js';

/** The DI-API versions this build speaks, offered whole on every connection. */
export const DI_API_MIN_SUPPORTED = 1;
/** @see DI_API_MIN_SUPPORTED */
export const DI_API_MAX_SUPPORTED = 2;

/** The AAASM-5277 lifecycle schema versions this build can read. */
export const LIFECYCLE_SCHEMA_VERSIONS = [1];

/**
 * The stable snake_case verb names, as they appear in a degraded `HelloAck`'s
 * `unavailable_verbs` and in a token scope.
 *
 * Keyed by the *generated* `Verb` enum, so a verb added to the proto without a
 * name here fails to compile rather than silently becoming unnameable.
 */
export const VERB_NAMES: Readonly<Record<Exclude<Verb, Verb.UNSPECIFIED>, string>> = {
  [Verb.LIST_TOOLS]: 'list_tools',
  [Verb.PLAN]: 'plan',
  [Verb.APPLY]: 'apply',
  [Verb.STATUS]: 'status',
  [Verb.VERIFY]: 'verify',
  [Verb.REPAIR]: 'repair',
  [Verb.REMOVE]: 'remove',
  [Verb.SCOPED_EVENTS]: 'scoped_events',
  [Verb.APPROVAL_RELAY]: 'approval_relay',
};

/**
 * What the server said about this connection's version.
 *
 * `degraded` is surfaced, never absorbed. A client that quietly proceeds on a
 * degraded connection shows a user a button for a feature the runtime does not
 * have, and a silent downgrade is precisely what §5.4 forbids.
 */
export interface Negotiated {
  readonly diApiVersion: number;
  readonly coreVersion: string;
  readonly lifecycleSchemaVersion: number;
  readonly degraded: boolean;
  readonly unavailableVerbs: readonly string[];
  readonly degradedReason: string;
  readonly remediation: string;
  readonly minSupported: number;
  readonly maxSupported: number;
}

/** Identity this client reports for audit. Never an authentication factor. */
export interface ClientIdentity {
  readonly name: string;
  readonly version: string;
}

/** What a plan asks for. Every field is something a user may legitimately choose. */
export interface PlanOptions {
  /** `recommended` | `strict` | `observe_only`. */
  readonly profile: string;
  /** `user` | `project` | `managed` — explicit, never inferred from cwd. */
  readonly settingsScope: string;
  /** The policy profile **by name**; the document never crosses this boundary. */
  readonly policyProfileId?: string;
  /** The rung the caller is aiming for. */
  readonly requestedLevel?: string;
  /** Whether the user consented to steps that change host state (§6.6). */
  readonly allowPrivilegedHostSteps?: boolean;
}

/**
 * The typed per-verb arguments a request may carry.
 *
 * Exactly the five sub-messages `Request` declares, and nothing shaped like an
 * opaque blob. There is no `extra`, no `metadata` and no string map here on
 * purpose: a passthrough field is how a closed verb space stops being closed.
 */
interface VerbArgs {
  plan?: PlanArgs;
  apply?: ApplyArgs;
  remove?: RemoveArgs;
  events?: ScopedEventsArgs;
  approval?: ApprovalRelayArgs;
}

/** A connected, negotiated DI-API client. */
export class DevIntClient {
  private nextRequestId = 1n;

  private constructor(
    private readonly socket: Socket,
    private readonly reader: FrameReader,
    private readonly token: CapabilityToken | null,
    /** What was agreed for this connection. Fixed for its lifetime. */
    readonly negotiated: Negotiated,
  ) {}

  /**
   * Connect to `path` and negotiate before anything else.
   *
   * `token` is nullable because a client may legitimately connect without one —
   * to learn the versions and then tell the user to enrol. Every verb is denied
   * until a token is supplied; there is no anonymous tier to fall back to.
   */
  static async connect(
    path: string,
    identity: ClientIdentity,
    token: CapabilityToken | null,
  ): Promise<DevIntClient> {
    const socket = await openSocket(path);
    const reader = new FrameReader(socket);

    socket.write(
      encodeHello(
        create(HelloSchema, {
          clientName: identity.name,
          clientVersion: identity.version,
          // Offer the whole window this build understands. Offering less is how
          // a client talks itself into a degraded connection for no reason.
          diApiVersions: range(DI_API_MIN_SUPPORTED, DI_API_MAX_SUPPORTED),
          lifecycleSchemaVersions: LIFECYCLE_SCHEMA_VERSIONS,
        }),
      ),
    );

    const frame = await reader.next();
    if (frame.kind === 'incompatible') {
      socket.destroy();
      throw new IncompatibleError(frame.message);
    }
    if (frame.kind !== 'hello-ack') {
      socket.destroy();
      throw new UnexpectedFrameError('the DI-API server answered Hello with something else');
    }

    const ack = frame.message;
    return new DevIntClient(socket, reader, token, {
      diApiVersion: ack.diApiVersion,
      coreVersion: ack.coreVersion,
      lifecycleSchemaVersion: ack.lifecycleSchemaVersion,
      degraded: ack.outcome === NegotiationOutcome.DEGRADED,
      unavailableVerbs: ack.unavailableVerbs,
      degradedReason: ack.degradedReason,
      remediation: ack.remediation,
      minSupported: ack.minSupported,
      maxSupported: ack.maxSupported,
    });
  }

  /** Whether `verb` is usable on this connection. */
  supports(verb: Exclude<Verb, Verb.UNSPECIFIED>): boolean {
    return !this.negotiated.unavailableVerbs.includes(VERB_NAMES[verb]);
  }

  /** Whether a token was supplied at all. `false` ⇒ every verb will be denied. */
  get enrolled(): boolean {
    return this.token !== null;
  }

  /** Every tool the runtime's adapters know about. */
  async listTools(): Promise<ToolList> {
    const response = await this.call(Verb.LIST_TOOLS, '');
    return required(response.toolList, 'tool_list');
  }

  /** Author a reviewable dry run. Mutates nothing. */
  async plan(toolId: string, options: PlanOptions): Promise<PlanView> {
    const response = await this.call(Verb.PLAN, toolId, {
      plan: create(PlanArgsSchema, {
        profile: options.profile,
        settingsScope: options.settingsScope,
        policyProfileId: options.policyProfileId ?? '',
        requestedLevel: options.requestedLevel ?? '',
        allowPrivilegedHostSteps: options.allowPrivilegedHostSteps ?? false,
      }),
    });
    return required(response.plan, 'plan');
  }

  /** Execute a plan the user reviewed. The runtime writes; this client does not. */
  async apply(toolId: string, planId: string): Promise<ApplyView> {
    const response = await this.call(Verb.APPLY, toolId, { apply: create(ApplyArgsSchema, { planId }) });
    return required(response.apply, 'apply');
  }

  /**
   * Read the protection state the service derived.
   *
   * Returned verbatim. There is no overload of this method that computes,
   * upgrades or infers a level, because a locally derived state is a claim
   * wearing a measurement's clothes (ADR 0030 forbidden design 10).
   */
  async status(toolId: string): Promise<StatusView> {
    const response = await this.call(Verb.STATUS, toolId);
    return required(response.status, 'status');
  }

  /** Run the protection test. The runtime adjudicates it; the client never self-certifies. */
  async verify(toolId: string): Promise<VerificationView> {
    const response = await this.call(Verb.VERIFY, toolId);
    return required(response.verification, 'verification');
  }

  /** Restore AASM-owned keys that drifted. */
  async repair(toolId: string): Promise<RepairView> {
    const response = await this.call(Verb.REPAIR, toolId);
    return required(response.repair, 'repair');
  }

  /** Author and execute the reversal. */
  async remove(toolId: string, planId = ''): Promise<RemovalView> {
    const response = await this.call(Verb.REMOVE, toolId, { remove: create(RemoveArgsSchema, { planId }) });
    return required(response.removal, 'removal');
  }

  /** Recent, already-redacted security events for this integration. */
  async scopedEvents(toolId: string, limit = 20, sinceUnixSecs = 0n): Promise<ScopedEventList> {
    const response = await this.call(Verb.SCOPED_EVENTS, toolId, {
      events: create(ScopedEventsArgsSchema, { limit, sinceUnixSecs }),
    });
    return required(response.events, 'events');
  }

  /**
   * Relay a human's approval input to the decision authority.
   *
   * The acknowledgement says the input was *accepted for adjudication*. It is
   * not a verdict and must never be rendered as one — the outcome is read back
   * from status, which the service computed.
   */
  async relayApproval(
    toolId: string,
    approvalId: string,
    userInput: 'approve' | 'deny' | 'defer',
  ): Promise<ApprovalRelayAck> {
    const response = await this.call(Verb.APPROVAL_RELAY, toolId, {
      approval: create(ApprovalRelayArgsSchema, { approvalId, userInput }),
    });
    return required(response.approval, 'approval');
  }

  /** Close the connection. */
  close(): void {
    this.socket.destroy();
  }

  private async call(
    verb: Exclude<Verb, Verb.UNSPECIFIED>,
    toolId: string,
    args: VerbArgs = {},
  ): Promise<Response> {
    if (!this.supports(verb)) {
      // Checked before the write so a degraded connection produces the
      // remediation the server already gave us, rather than a round trip.
      throw new VerbUnavailableError(VERB_NAMES[verb], this.negotiated.remediation);
    }

    const requestId = this.nextRequestId;
    this.nextRequestId += 1n;
    const request = create(RequestSchema, {
      requestId,
      verb,
      // The one place the secret leaves the wrapper.
      capabilityToken: this.token?.expose() ?? '',
      toolId,
      ...args,
    });

    this.socket.write(encodeRequest(request));
    const frame = await this.reader.next();
    if (frame.kind === 'denied') {
      if (frame.message.requestId !== requestId) {
        throw new UnexpectedFrameError('a denial arrived for a request this client did not send');
      }
      throw new DeniedError(frame.message);
    }
    if (frame.kind !== 'response') {
      throw new UnexpectedFrameError('the DI-API server sent a negotiation frame mid-connection');
    }
    if (frame.message.requestId !== requestId || frame.message.verb !== verb) {
      throw new UnexpectedFrameError('the DI-API server answered a different request');
    }
    return frame.message;
  }
}

function required<T>(view: T | undefined, name: string): T {
  if (view === undefined) throw new UnexpectedFrameError(`the DI-API response carried no ${name}`);
  return view;
}

function range(from: number, to: number): number[] {
  return Array.from({ length: to - from + 1 }, (_, i) => from + i);
}

function openSocket(path: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connectUnixSocket(path);
    socket.once('connect', () => resolve(socket));
    socket.once('error', (error: NodeJS.ErrnoException) => {
      socket.destroy();
      // ENOENT here is not a transport problem: nothing is listening, so the
      // remedy is to start the runtime rather than to reconnect.
      reject(
        error.code === 'ENOENT'
          ? new RuntimeNotRunningError(path)
          : new TransportError(`cannot connect to the DI-API socket at ${path}: ${error.message}`, error),
      );
    });
  });
}
