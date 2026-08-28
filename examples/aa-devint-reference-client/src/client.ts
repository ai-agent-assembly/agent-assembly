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
  ProjectRootUnsupportedError,
  RuntimeNotRunningError,
  TransportError,
  UnexpectedFrameError,
  UserConfigHomeUnsupportedError,
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
  TargetArgsSchema,
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
  type TargetArgs,
  type RepairView,
  type Response,
  type ScopedEventList,
  type StatusView,
  type ToolList,
  type VerificationView,
} from './generated/devint_pb.js';

/** The DI-API versions this build speaks, offered whole on every connection. */
export const DI_API_MIN_SUPPORTED = 1;
/**
 * @see DI_API_MIN_SUPPORTED
 *
 * Raised from 2 to 6 by AAASM-5913, and the reason is worth stating because it
 * is not the usual one. This client stayed at 2 through v3, v4 and v5 quite
 * deliberately: each of those added a field to a *reply*, and a client gains
 * nothing by claiming to understand a field it does not read. v6 adds a field to
 * a **request** — {@link PlanOptions.projectRoot} — and that inverts the
 * calculation. Sending a v6 field while claiming v2 is not modesty, it is a
 * silent failure: an older runtime discards the field and substitutes its own
 * working directory.
 *
 * The honest consequence, recorded rather than glossed: at v6 this client is
 * *sent* the v3–v5 reply fields (policy posture, runtime provenance, apply
 * outcome) and consumes none of them. Receiving a field and ignoring it is safe
 * — it is fabricating one that is not — but a reader should not mistake this
 * constant for a claim that all four additions are handled.
 *
 * Raised again to 7 by AAASM-5957 for the identical reason, one scope over:
 * {@link PlanOptions.userConfigHome} is a **request** field too.
 */
export const DI_API_MAX_SUPPORTED = 7;

/**
 * The first DI-API version whose `plan` honours a caller-chosen project root.
 *
 * Mirrors `DI_API_PROJECT_ROOT_SINCE` in `aa-runtime/src/devint/negotiate.rs`.
 * Duplicated rather than derived because the two halves are separately
 * deployable: the whole hazard being guarded is a client and a runtime built at
 * different times, so a constant shared between them would assume the thing it
 * is checking.
 */
export const DI_API_PROJECT_ROOT_SINCE = 6;

/**
 * The first DI-API version whose `plan` honours a caller-chosen configuration
 * home.
 *
 * Mirrors `DI_API_USER_CONFIG_HOME_SINCE` in `aa-runtime/src/devint/negotiate.rs`,
 * one version and one scope over from {@link DI_API_PROJECT_ROOT_SINCE}
 * (AAASM-5957). Duplicated for the same reason that constant is.
 */
export const DI_API_USER_CONFIG_HOME_SINCE = 7;

/**
 * Whether a `plan` at `settingsScope` needs a newer runtime than was negotiated.
 *
 * Exported and pure so the rule can be asserted without a socket — which is the
 * only way to assert it at all from this side, since the failure it prevents is
 * a request that must never be written. A test that needed a live pre-v6 runtime
 * to check this would not run, and the check would rot.
 *
 * `settingsScope` is compared against the literal wire vocabulary, matching
 * `projection::parse_scope` in the runtime. A token neither side recognises
 * returns `false` on purpose: rejecting an unknown scope is the service's job,
 * and guessing that `"Project"` *means* project scope would answer a typo with
 * "upgrade your runtime" instead of "that is not a scope".
 */
export function projectRootRequiresNewerRuntime(negotiatedVersion: number, settingsScope: string): boolean {
  return settingsScope === 'project' && negotiatedVersion < DI_API_PROJECT_ROOT_SINCE;
}

/**
 * Whether a call at `settingsScope` needs a newer runtime to carry a
 * configuration home (AAASM-5957).
 *
 * Mirrors {@link projectRootRequiresNewerRuntime}, one scope over: an
 * unstated scope (`""`) is treated as possibly user-scoped rather than as
 * "not user scope", because `""` is what the service resolves to "whichever
 * installation exists" — which may turn out to be the user-scope one.
 */
export function userConfigHomeRequiresNewerRuntime(negotiatedVersion: number, settingsScope: string): boolean {
  return settingsScope !== 'project' && settingsScope !== 'managed' && negotiatedVersion < DI_API_USER_CONFIG_HOME_SINCE;
}

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
  /**
   * The absolute path of the project this plan is for, resolved by the caller —
   * `src/project.ts`, or a plugin's workspace folder (AAASM-5913).
   *
   * Required, and not optional like the three fields above it, because the whole
   * point of the field is that the *caller* states it. An optional project root
   * is one a call site reaches by forgetting, and forgetting is what left the
   * shared runtime with nothing to name but the directory it was spawned in.
   * Pass `""` to say there is none: mandatory at `project` scope, where the
   * service refuses rather than guesses, and optional context elsewhere.
   *
   * This client does not pre-empt that refusal. The rule is the service's, its
   * message is the actionable one, and a second copy of it here would be a
   * second thing to keep true.
   *
   * It *does* pre-empt a different one. A runtime below
   * {@link DI_API_PROJECT_ROOT_SINCE} cannot refuse, because protobuf discards
   * the field before any handler sees it — see
   * {@link ProjectRootUnsupportedError}. That check has to be here; there is no
   * round trip that produces it.
   */
  readonly projectRoot: string;
  /**
   * The caller's Claude Code configuration home — `$CLAUDE_CONFIG_DIR`, or
   * `$HOME/.claude` — resolved by the caller, on the same terms as
   * {@link projectRoot} but for `user` scope (AAASM-5957).
   *
   * Required for the same reason {@link projectRoot} is. Pass `""` to say
   * there is none: mandatory at `user` scope (and unstated scope, which may
   * turn out to be user-scoped), optional context elsewhere.
   *
   * This client does not pre-empt the service's refusal of an empty value at
   * `user` scope. It *does* pre-empt the one the service cannot make: a
   * runtime below {@link DI_API_USER_CONFIG_HOME_SINCE} discards the field
   * before any handler sees it — see {@link UserConfigHomeUnsupportedError}.
   */
  readonly userConfigHome: string;
}

/**
 * Which project a call is about, as the caller resolved it.
 *
 * Both fields are required for the reason {@link PlanOptions.projectRoot} is:
 * an optional field is one a call site reaches by forgetting, and forgetting is
 * the defect. `""` says "nothing to state" explicitly.
 */
export interface TargetOptions {
  /**
   * `user`, `project`, `managed`, or `""` to let the service act on whichever
   * installation exists.
   *
   * Naming a scope tells the service something it can already see; naming it
   * *wrongly* turns "here is your integration" into "nothing is installed". `""`
   * is the right answer for a client that only knows where it is.
   */
  readonly settingsScope: string;
  /**
   * The absolute path of the project this invocation is in, or `""`.
   *
   * Compared by the service against what is on record — a receipt for a read or
   * reverse verb, the authoring project for an apply — and never resolved into a
   * destination.
   */
  readonly projectRoot: string;
  /**
   * The caller's Claude Code configuration home, or `""` (AAASM-5957).
   *
   * Compared by the service against what is on record — a receipt for a read
   * or reverse verb, the authoring home for an apply — and never resolved
   * into a destination.
   */
  readonly userConfigHome: string;
}

/**
 * The typed per-verb arguments a request may carry.
 *
 * Exactly the six sub-messages `Request` declares, and nothing shaped like an
 * opaque blob. There is no `extra`, no `metadata` and no string map here on
 * purpose: a passthrough field is how a closed verb space stops being closed.
 *
 * `target` is request-level rather than per-verb because it answers one question
 * — *which project* — for the five verbs that ask it, and five copies of one
 * question are five places for the answer to drift.
 */
interface VerbArgs {
  plan?: PlanArgs;
  apply?: ApplyArgs;
  remove?: RemoveArgs;
  events?: ScopedEventsArgs;
  approval?: ApprovalRelayArgs;
  target?: TargetArgs;
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
    // Before the write, not after the reply: an ignored root and an unsent one
    // decode identically, so there is nothing in the response to check. The
    // scope token is compared as the literal wire vocabulary, which is what the
    // service parses (`projection::parse_scope`) — a token neither side
    // recognises stays the service's to reject, so a typo is answered with "that
    // is not a scope" rather than with "upgrade your runtime".
    if (projectRootRequiresNewerRuntime(this.negotiated.diApiVersion, options.settingsScope)) {
      throw new ProjectRootUnsupportedError(this.negotiated.diApiVersion, DI_API_PROJECT_ROOT_SINCE);
    }
    if (userConfigHomeRequiresNewerRuntime(this.negotiated.diApiVersion, options.settingsScope)) {
      throw new UserConfigHomeUnsupportedError(this.negotiated.diApiVersion, DI_API_USER_CONFIG_HOME_SINCE);
    }
    const response = await this.call(Verb.PLAN, toolId, {
      plan: create(PlanArgsSchema, {
        profile: options.profile,
        settingsScope: options.settingsScope,
        policyProfileId: options.policyProfileId ?? '',
        requestedLevel: options.requestedLevel ?? '',
        allowPrivilegedHostSteps: options.allowPrivilegedHostSteps ?? false,
        // Sent verbatim, at every scope, with no default of this client's own:
        // the caller resolved it against the directory the *user* is in, and any
        // value substituted here would be about a different project.
        projectRoot: options.projectRoot,
        // Same terms, one scope over (AAASM-5957): the caller resolved this
        // against its own CLAUDE_CONFIG_DIR/HOME, not the runtime's.
        userConfigHome: options.userConfigHome,
      }),
    });
    return required(response.plan, 'plan');
  }

  /**
   * Execute a plan the user reviewed. The runtime writes; this client does not.
   *
   * `target` says which project this invocation is applying *from*. A plan id is
   * handed out by the service and can be presented later, from anywhere, so it
   * is not on its own an answer to "may this caller execute this here" — the
   * service compares the two projects and refuses when they disagree.
   */
  async apply(toolId: string, planId: string, target: TargetOptions): Promise<ApplyView> {
    const response = await this.call(Verb.APPLY, toolId, {
      apply: create(ApplyArgsSchema, { planId }),
      ...this.targeting(target),
    });
    return required(response.apply, 'apply');
  }

  /**
   * Read the protection state the service derived.
   *
   * Returned verbatim. There is no overload of this method that computes,
   * upgrades or infers a level, because a locally derived state is a claim
   * wearing a measurement's clothes (ADR 0030 forbidden design 10).
   */
  async status(toolId: string, target: TargetOptions): Promise<StatusView> {
    const response = await this.call(Verb.STATUS, toolId, this.targeting(target));
    return required(response.status, 'status');
  }

  /** Run the protection test. The runtime adjudicates it; the client never self-certifies. */
  async verify(toolId: string, target: TargetOptions): Promise<VerificationView> {
    const response = await this.call(Verb.VERIFY, toolId, this.targeting(target));
    return required(response.verification, 'verification');
  }

  /** Restore AASM-owned keys that drifted. */
  async repair(toolId: string, target: TargetOptions): Promise<RepairView> {
    const response = await this.call(Verb.REPAIR, toolId, this.targeting(target));
    return required(response.repair, 'repair');
  }

  /** Author and execute the reversal. */
  async remove(toolId: string, planId: string, target: TargetOptions): Promise<RemovalView> {
    const response = await this.call(Verb.REMOVE, toolId, {
      remove: create(RemoveArgsSchema, { planId }),
      ...this.targeting(target),
    });
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

  /**
   * `target` as the wire carries it, refusing first if this connection cannot.
   *
   * One helper for all five targeted verbs rather than five copies of the same
   * two lines: the version refusal is the part that must not be forgotten, and a
   * verb that forgot it would send a project root into a peer that discards it
   * undetectably ({@link ProjectRootUnsupportedError}).
   *
   * The target is attached unconditionally, empty fields included. An absent
   * `TargetArgs` and one saying "no scope, no project" decode identically on a
   * v6 peer, so there is nothing to gain by omitting it and one fewer branch by
   * not trying.
   */
  private targeting(target: TargetOptions): VerbArgs {
    if (projectRootRequiresNewerRuntime(this.negotiated.diApiVersion, target.settingsScope)) {
      throw new ProjectRootUnsupportedError(this.negotiated.diApiVersion, DI_API_PROJECT_ROOT_SINCE);
    }
    if (userConfigHomeRequiresNewerRuntime(this.negotiated.diApiVersion, target.settingsScope)) {
      throw new UserConfigHomeUnsupportedError(this.negotiated.diApiVersion, DI_API_USER_CONFIG_HOME_SINCE);
    }
    return {
      target: create(TargetArgsSchema, {
        settingsScope: target.settingsScope,
        projectRoot: target.projectRoot,
        userConfigHome: target.userConfigHome,
      }),
    };
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
