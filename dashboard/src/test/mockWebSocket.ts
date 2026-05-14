/**
 * Shared `MockWebSocket` for testing WS-driven hooks.
 *
 * Provides a tiny subset of the browser `WebSocket` API plus three
 * test-only helpers that drive the connection lifecycle from the
 * test side:
 *
 * | helper | effect |
 * |---|---|
 * | `open()` | sets `readyState = OPEN` + fires `onopen` |
 * | `emit(data)` | fires `onmessage` with `JSON.stringify(data)` |
 * | `serverClose()` | sets `readyState = CLOSED` + fires `onclose` (idempotent) |
 *
 * Two ways to inject it into a hook under test:
 *
 * ```ts
 * // 1. ctor-injection (preferred — explicit at the call site):
 * useLiveOpsStream({ webSocketCtor: MockWebSocket as unknown as typeof WebSocket })
 *
 * // 2. global stub (when the hook hard-codes `new WebSocket(...)`):
 * vi.stubGlobal('WebSocket', MockWebSocket)
 * ```
 *
 * Per-test cleanup: call `resetMockWebSockets()` in `beforeEach` so
 * the `MockWebSocket.instances` registry doesn't leak across cases.
 */
export class MockWebSocket {
  static instances: MockWebSocket[] = []
  static OPEN = 1
  static CLOSED = 3

  readyState = 0
  url: string
  onopen: ((ev?: Event) => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((ev?: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
  }

  // ── Test helpers ────────────────────────────────────────

  /** Pretend the WS upgrade succeeded. */
  open() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }

  /** Deliver a frame from the server side. */
  emit(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) })
  }

  /** Pretend the server closed the connection. Idempotent. */
  serverClose() {
    if (this.readyState === MockWebSocket.CLOSED) return
    this.readyState = MockWebSocket.CLOSED
    this.onclose?.()
  }

  // ── WebSocket API ──────────────────────────────────────

  close() {
    this.serverClose()
  }
  send() {
    /* noop */
  }
}

/**
 * Clear the `MockWebSocket.instances` registry between test cases.
 * Call this in `beforeEach` to prevent cross-test pollution.
 */
export function resetMockWebSockets(): void {
  MockWebSocket.instances = []
}
