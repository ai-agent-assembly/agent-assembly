/**
 * Every way a DI-API call can fail, each carrying what the user should do next.
 *
 * The DI-API answers refusals with a *coarse* code plus a remediation sentence
 * (`proto/devint.proto`, `DenyCode`). The client's job is to hand that sentence
 * through unaltered — not to guess a finer reason from it. `UNAUTHENTICATED`
 * covers absent, unknown and malformed tokens on purpose so a probing client
 * cannot tell them apart; a client that "helpfully" inferred which one it was
 * would be reconstructing exactly what the server declined to disclose.
 */
import type { Denied, Incompatible } from './generated/devint_pb.js';

/** Base class so a caller can `catch (e) { if (e instanceof DevIntError) … }`. */
export abstract class DevIntError extends Error {
  /** What the user or the client should do about it. Never "try again". */
  abstract readonly remediation: string;
}

/**
 * No socket at the resolved path.
 *
 * Distinct from a transport failure because the remedy is different: nothing is
 * listening, so the answer is "start the runtime", not "retry".
 */
export class RuntimeNotRunningError extends DevIntError {
  override readonly name = 'RuntimeNotRunningError';
  readonly remediation: string;
  constructor(readonly socketPath: string) {
    super(`the AASM runtime is not running (no socket at ${socketPath})`);
    this.remediation = 'Start the AASM runtime, then reconnect.';
  }
}

/**
 * The server and this client share no DI-API version.
 *
 * The server closes the connection immediately after saying so: there is no
 * degraded-into-nothing state to limp along in, and no version to renegotiate
 * down to (§5.4).
 */
export class IncompatibleError extends DevIntError {
  override readonly name = 'IncompatibleError';
  readonly remediation: string;
  constructor(readonly detail: Incompatible) {
    super(detail.reason);
    this.remediation = detail.remediation;
  }

  /** The server's supported window, for a "which side do I upgrade?" message. */
  get supportedWindow(): string {
    return `${this.detail.minSupported}–${this.detail.maxSupported}`;
  }
}

/** The server refused the request. Carries the coarse code verbatim. */
export class DeniedError extends DevIntError {
  override readonly name = 'DeniedError';
  readonly remediation: string;
  constructor(readonly detail: Denied) {
    super(detail.message);
    this.remediation = detail.remediation;
  }

  /** The wire `DenyCode` discriminant, for a caller that branches on it. */
  get code(): number {
    return this.detail.code;
  }
}

/** Framing, connection or I/O failure. */
export class TransportError extends DevIntError {
  override readonly name = 'TransportError';
  readonly remediation = 'Check that the AASM runtime is healthy; reconnect to retry.';
  constructor(message: string, override readonly cause?: unknown) {
    super(message);
  }
}

/**
 * The server sent a frame this client did not ask for, or a response whose
 * per-verb view was empty.
 *
 * Deliberately an error rather than a fallback to `undefined`: a response body
 * this client cannot account for is a protocol disagreement, and rendering
 * "unknown" for it would hide the disagreement behind a plausible screen.
 */
export class UnexpectedFrameError extends DevIntError {
  override readonly name = 'UnexpectedFrameError';
  readonly remediation = 'Update the client and the runtime to a matching release.';
}

/**
 * The verb is missing at the negotiated version.
 *
 * Raised by the client *before* the request is written, so a degraded
 * connection produces an actionable message instead of a round trip that comes
 * back `UNAVAILABLE_AT_VERSION`.
 */
export class VerbUnavailableError extends DevIntError {
  override readonly name = 'VerbUnavailableError';
  readonly remediation: string;
  constructor(
    readonly verb: string,
    remediation: string,
  ) {
    super(`the runtime does not offer "${verb}" at the negotiated DI-API version`);
    this.remediation = remediation || 'Update the AASM runtime to a version that offers this operation.';
  }
}

/** One line a UI can show for any failure: what happened, then what to do. */
export function actionable(error: unknown): string {
  if (error instanceof DevIntError) return `${error.message} — ${error.remediation}`;
  return error instanceof Error ? error.message : String(error);
}
