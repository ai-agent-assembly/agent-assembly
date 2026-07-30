/**
 * The one credential a thin client is ever allowed to hold.
 *
 * A DI capability token is an opaque 256-bit hex secret, scoped per tool and
 * per verb, absolutely expiring and revocable server-side
 * (`aa-runtime/src/devint/token.rs`). It is the *only* credential type this
 * package can represent: there is no field, constructor or setter anywhere here
 * for a gateway token, an organisation key or an API key, so "the client holds
 * no unrestricted core credential" is a statement about the type system rather
 * than about discipline (ADR 0030 forbidden design 2).
 *
 * Two things this module deliberately does **not** do:
 *
 * - **It does not enrol.** Issuing a token is an explicit, user-visible step
 *   owned by the operator CLI (AAASM-5280). A client that could mint its own
 *   credential would have made enrolment a formality.
 * - **It does not choose where the token lives.** The enroller names the file;
 *   this reads the path it is given. Inventing a second convention here would
 *   be a second place for a secret to be, which is one more than necessary.
 */
import { readFileSync, statSync } from 'node:fs';

/** Environment variable a host may use to pass the token without a file. */
export const TOKEN_ENV = 'AA_DEVINT_TOKEN';

/** 256 bits, lowercase hex. */
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;

/**
 * An opaque DI capability token.
 *
 * `toString`/`toJSON` redact, so a token cannot reach a log, a crash report or
 * an editor's telemetry through an incidental interpolation of some enclosing
 * object. The secret leaves only through {@link CapabilityToken.expose}, which
 * the client calls at exactly one place — building a `Request`.
 */
export class CapabilityToken {
  private constructor(private readonly secret: string) {}

  /**
   * Wrap a token the enroller produced.
   *
   * Rejects anything that is not 64 lowercase hex characters. That is a
   * client-side shape check, not authentication: the server still resolves the
   * secret against its record, and a well-formed token that resolves to nothing
   * is denied exactly like a malformed one.
   */
  static parse(value: string): CapabilityToken {
    const trimmed = value.trim();
    if (!TOKEN_PATTERN.test(trimmed)) {
      throw new Error('a DI capability token is 64 lowercase hex characters; enrol the client to obtain one');
    }
    return new CapabilityToken(trimmed);
  }

  /**
   * Read a token from a file the enroller wrote.
   *
   * Refuses a file that is group- or world-readable. The socket is `0600` and
   * the runtime re-asserts that on every bind; a token sitting in a `0644` file
   * beside it would make the OS layer of the two-layer authentication
   * decorative, so this fails rather than reads.
   */
  static fromFile(path: string): CapabilityToken {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(`token file ${path} is mode ${mode.toString(8)}; it must be 600 (owner-only)`);
    }
    return CapabilityToken.parse(readFileSync(path, 'utf8'));
  }

  /** Read a token from `AA_DEVINT_TOKEN`, or `null` when it is unset. */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): CapabilityToken | null {
    const raw = env[TOKEN_ENV];
    return raw === undefined || raw === '' ? null : CapabilityToken.parse(raw);
  }

  /** The secret, for the one caller that puts it on the wire. */
  expose(): string {
    return this.secret;
  }

  /** Redacted. */
  toString(): string {
    return 'CapabilityToken(<redacted>)';
  }

  /** Redacted, so `JSON.stringify` of any enclosing object is safe. */
  toJSON(): string {
    return '<redacted>';
  }
}
