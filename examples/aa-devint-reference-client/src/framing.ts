/**
 * The DI-API's length-delimited framing, client side.
 *
 * `[1-byte tag][prost varint length][payload]`, the same discipline as
 * `aa-runtime/src/devint/codec.rs`. The tag set is closed and disjoint from the
 * SDK fast-path socket's, which is why a DI client that somehow reached that
 * socket would be speaking a language nothing there parses.
 *
 * The inbound length prefix is server-controlled rather than attacker-
 * controlled here — but it is still bounded before allocation, at the same
 * 1 MiB the server enforces. A client that trusted a length it was told would
 * be one compromised runtime away from an OOM, and "the peer is trusted" is the
 * assumption this whole boundary exists to avoid making.
 */
import type { Socket } from 'node:net';
import { fromBinary, toBinary } from '@bufbuild/protobuf';

import {
  DeniedSchema,
  HelloAckSchema,
  HelloSchema,
  IncompatibleSchema,
  RequestSchema,
  ResponseSchema,
  type Denied,
  type Hello,
  type HelloAck,
  type Incompatible,
  type Request,
  type Response,
} from './generated/devint_pb.js';
import { TransportError } from './errors.js';

/** Client → runtime: the version-negotiation opener. */
export const TAG_HELLO = 1;
/** Client → runtime: a verb invocation. */
export const TAG_REQUEST = 2;

/** Runtime → client: negotiation succeeded (supported or degraded). */
export const TAG_HELLO_ACK = 1;
/** Runtime → client: negotiation failed; the connection closes after this. */
export const TAG_INCOMPATIBLE = 2;
/** Runtime → client: a verb's data-minimised result. */
export const TAG_RESPONSE = 3;
/** Runtime → client: the request was refused. */
export const TAG_DENIED = 4;

/** Maximum accepted payload, matching the server's bound (1 MiB). */
export const MAX_FRAME_LEN = 1024 * 1024;

/** A decoded runtime → client frame. */
export type ServerFrame =
  | { readonly kind: 'hello-ack'; readonly message: HelloAck }
  | { readonly kind: 'incompatible'; readonly message: Incompatible }
  | { readonly kind: 'response'; readonly message: Response }
  | { readonly kind: 'denied'; readonly message: Denied };

/** Encode a `Hello` as a framed client → runtime buffer. */
export function encodeHello(hello: Hello): Uint8Array {
  return frame(TAG_HELLO, toBinary(HelloSchema, hello));
}

/** Encode a `Request` as a framed client → runtime buffer. */
export function encodeRequest(request: Request): Uint8Array {
  return frame(TAG_REQUEST, toBinary(RequestSchema, request));
}

/** Decode one runtime → client frame from `tag` and its payload. */
export function decodeServerFrame(tag: number, payload: Uint8Array): ServerFrame {
  switch (tag) {
    case TAG_HELLO_ACK:
      return { kind: 'hello-ack', message: fromBinary(HelloAckSchema, payload) };
    case TAG_INCOMPATIBLE:
      return { kind: 'incompatible', message: fromBinary(IncompatibleSchema, payload) };
    case TAG_RESPONSE:
      return { kind: 'response', message: fromBinary(ResponseSchema, payload) };
    case TAG_DENIED:
      return { kind: 'denied', message: fromBinary(DeniedSchema, payload) };
    default:
      // Rejected, not skipped: an unrecognised frame is not a frame to read
      // past, because whatever follows it is no longer at a known offset.
      throw new TransportError(`unknown DI-API frame tag: ${tag}`);
  }
}

function frame(tag: number, body: Uint8Array): Uint8Array {
  const len = encodeVarint(body.length);
  const out = new Uint8Array(1 + len.length + body.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(body, 1 + len.length);
  return out;
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

/**
 * Reads whole frames off a socket, one `await` at a time.
 *
 * The DI-API is strictly request/response per connection, so a single-reader
 * queue is the whole state machine — there is no interleaving to correlate and
 * no out-of-order delivery to buffer. `request_id` is still echoed and checked
 * by the client above this layer, because "the protocol says it cannot happen"
 * is a reason to assert it, not a reason to skip it.
 */
export class FrameReader {
  private buffer = Buffer.alloc(0);
  private readonly queue: Array<{
    resolve: (frame: ServerFrame) => void;
    reject: (error: unknown) => void;
  }> = [];
  private ended: Error | null = null;

  constructor(socket: Socket) {
    socket.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.drain();
    });
    socket.on('error', (error) => this.fail(new TransportError(`DI-API socket error: ${error.message}`, error)));
    socket.on('close', () =>
      this.fail(new TransportError('the DI-API connection closed before a reply arrived')),
    );
  }

  /** The next whole frame, or a rejection if the connection ended first. */
  next(): Promise<ServerFrame> {
    if (this.ended !== null) return Promise.reject(this.ended);
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.drain();
    });
  }

  private drain(): void {
    while (this.queue.length > 0) {
      const parsed = this.tryParse();
      if (parsed === null) return;
      this.queue.shift()?.resolve(parsed);
    }
  }

  private tryParse(): ServerFrame | null {
    if (this.buffer.length < 2) return null;
    let len = 0;
    let shift = 0;
    let offset = 1;
    for (;;) {
      if (offset >= this.buffer.length) return null;
      const byte = this.buffer[offset] as number;
      offset += 1;
      len |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
      if (shift > 28) throw new TransportError('DI-API frame length prefix is malformed');
    }
    if (len > MAX_FRAME_LEN) {
      // Checked before the slice, so a bogus length costs nothing to reject.
      throw new TransportError(`DI-API frame length ${len} exceeds maximum ${MAX_FRAME_LEN}`);
    }
    if (this.buffer.length < offset + len) return null;
    const payload = this.buffer.subarray(offset, offset + len);
    const tag = this.buffer[0] as number;
    const frameBytes = Uint8Array.from(payload);
    this.buffer = this.buffer.subarray(offset + len);
    return decodeServerFrame(tag, frameBytes);
  }

  private fail(error: Error): void {
    if (this.ended !== null) return;
    this.ended = error;
    while (this.queue.length > 0) this.queue.shift()?.reject(error);
  }
}
