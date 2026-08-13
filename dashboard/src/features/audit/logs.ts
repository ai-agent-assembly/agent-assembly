import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'
import {
  absent,
  certain,
  isKnown,
  known,
  propagateAbsence,
  type Certain,
} from '../../lib/truthfulness'

/**
 * Audit-log data layer for the `/audit` page (AAASM-3510).
 *
 * Reads the gateway's governance trail from `GET /api/v1/logs` (`list_logs`).
 * The wire `LogEntry` is deliberately narrow — `seq`, `timestamp`, `agent_id`,
 * `session_id`, `event_type`, and a pre-serialized `payload` JSON string. The
 * richer fields the design surfaces (`decision`, `trace_id`) are *not* separate
 * columns on the wire type; they are carried inside `payload`, so the page
 * parses them out of the JSON rather than expecting them as top-level fields.
 *
 * ── Why this module was rewritten (AAASM-5117 / 5118 / 5119 / 5120) ─────────
 *
 * The original was a faithful port of `design/v1/hi-fi/audit-log.jsx`, which
 * reads a hand-written fixture (`design/v1/hi-fi/data-audit.jsx`). The port was
 * accurate; the fixture's schema was fictional. Every reader below therefore
 * describes the shape the *gateway* actually emits, verified against the
 * producers rather than the mock:
 *
 *  - `decision` is the **integer** discriminant of the proto enum
 *    `assembly.common.v1.Decision` (`proto/common.proto:30-40`), because
 *    `aa-gateway/src/service/policy_service.rs` writes `response.decision`, a
 *    prost `i32`. `aa-api` already reads it with `as_i64()` — this module was
 *    the last consumer still type-checking it as a string (AAASM-5035 fixed the
 *    same class of bug on the backend).
 *  - `event_type` is one of the 22 `aa_core::audit::AuditEventType` variant
 *    names, emitted by `AuditEventType::as_str()` at `aa-api/src/routes/logs.rs`.
 *  - the payload body is either the runtime's
 *    `{event_id, action_type, source, decision, detail}`
 *    (`aa-runtime/src/audit_publisher/conversion.rs::build_payload`) or the
 *    gateway's `{action_type, decision, reason, policy_rule, latency_us, …}`
 *    (`policy_service.rs::record_audit`). Neither carries the mock's
 *    `blocked_action` / `approver_id` / `prompt_tokens` fields.
 *
 * Absence is reported through the shared truthfulness vocabulary
 * (`src/lib/truthfulness`, AAASM-5173) rather than a local `null` convention,
 * so a row with no verdict can never render as one.
 */

export type LogEntry = components['schemas']['LogEntry']
export type PaginatedLogResponse = components['schemas']['PaginatedLogResponse']

// ── Decision ────────────────────────────────────────────────────────────────

/**
 * The verdicts an audit row may carry, mirroring `assembly.common.v1.Decision`
 * (`proto/common.proto:30-40`). `DECISION_UNSPECIFIED` (0) is deliberately
 * absent: it is proto's "field was never set" default, not a verdict.
 */
export type AuditDecision = 'ALLOW' | 'DENY' | 'PENDING' | 'REDACT'

/**
 * Proto discriminant → verdict. The gateway serialises the enum as its integer
 * discriminant, so this is the primary (not the fallback) lookup.
 */
const DECISION_BY_DISCRIMINANT: Readonly<Record<number, AuditDecision>> = {
  1: 'ALLOW',
  2: 'DENY',
  3: 'PENDING',
  4: 'REDACT',
}

/**
 * Accepted spellings of the string form, which only the shadow path emits.
 *
 * A `Map` rather than a plain object because the key is `raw.toUpperCase()`,
 * derived from a `JSON.parse` of an untrusted audit blob. A plain-object lookup
 * inherits `Object.prototype`, so `"__proto__"` (or any prototype member name)
 * would resolve to a truthy inherited value and be coerced into a fabricated
 * verdict on a governance surface. A `Map` only holds its own keys, so an
 * inherited name misses and the value is reported as an explicit `unknown`
 * (AAASM-5225).
 */
const DECISION_BY_NAME: ReadonlyMap<string, AuditDecision> = new Map([
  ['ALLOW', 'ALLOW'],
  ['DENY', 'DENY'],
  ['PENDING', 'PENDING'],
  ['REDACT', 'REDACT'],
])

/**
 * Interpret one raw `decision`-shaped JSON value.
 *
 * Both wire forms are handled because both are really emitted: the enforced
 * `decision` is an integer (prost `i32`), while `shadow_decision` is a
 * lower-case string (`aa-gateway/src/engine/mod.rs::ShadowEvent`). A value that
 * matches neither vocabulary is *not* coerced into a verdict — it becomes an
 * explicit `unknown`, because inventing a verdict on a governance surface is
 * the failure this whole lane exists to remove.
 */
function readDecisionValue(raw: unknown): Certain<AuditDecision> | null {
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    const mapped = DECISION_BY_DISCRIMINANT[raw]
    if (mapped) return known(mapped)
    // 0 is DECISION_UNSPECIFIED — the proto default, meaning the producer never
    // populated the field. Anything else is a discriminant this build predates.
    return absent(
      'unknown',
      raw === 0
        ? 'Gateway recorded DECISION_UNSPECIFIED (0)'
        : `Unrecognised decision discriminant ${raw}`,
    )
  }
  if (typeof raw === 'string' && raw.length > 0) {
    const mapped = DECISION_BY_NAME.get(raw.toUpperCase())
    if (mapped) return known(mapped)
    return absent('unknown', `Unrecognised decision value "${raw}"`)
  }
  return null
}

/**
 * What a row's payload says about the policy verdict.
 *
 * There is deliberately **no** reader that returns the enforced verdict on its
 * own. In observe mode the gateway rewrites the decision to `ALLOW` and records
 * the verdict it suppressed alongside it, so a caller holding only `enforced`
 * holds a value that reads as permission while a denial is what actually
 * happened. Coupling the two in one type makes that mistake unrepresentable:
 * every consumer that renders, exports or counts a verdict receives the
 * suppression in the same value.
 */
export interface AuditVerdict {
  /** The decision the gateway enforced — what actually happened to the action. */
  readonly enforced: Certain<AuditDecision>
  /** The payload's explicit `dry_run` flag (observe mode). */
  readonly dryRun: boolean
  /**
   * The verdict observe mode suppressed, or `null` when nothing was suppressed.
   *
   * Non-null means `enforced` is **not** a governance outcome the operator can
   * rely on: the action was allowed to proceed only because enforcement was off.
   */
  readonly suppressed: Certain<AuditDecision> | null
  /** The explanation recorded for the suppressed verdict (`shadow_reason`). */
  readonly suppressedReason: string | null
}

/**
 * Read the policy verdict out of a `LogEntry.payload`.
 *
 * ── Why `enforced` and `suppressed` are read together (AAASM-5117 review) ────
 *
 * `aa-gateway/src/engine/mod.rs:144` `transform_for_observe_mode` replaces a
 * `Deny` / `RequiresApproval` result with `PolicyResult::Allow` and returns a
 * `ShadowEvent` carrying the original verdict. `record_audit`
 * (`policy_service.rs:940-949`) then writes
 * `{"decision": 1, "dry_run": true, "shadow_decision": "deny", "shadow_reason": …}`,
 * and its own comment at `:855-857` says the payload carries those fields
 * precisely "so the audit reader can render the would-be event distinctly from
 * live enforcement records".
 *
 * The event type is rewritten too: `record_audit` derives it from the
 * *post-transform* decision (`policy_service.rs:891` →
 * `decision_to_event_type_from_response`, `:1039-1048`), so a suppressed denial
 * is recorded as `ToolCallIntercepted`, not `PolicyViolation`. Nothing in the
 * row's own `decision`, `event_type`, `reason` or `policy_rule` survives to say
 * a denial happened — `reason` and `policy_rule` are emptied by the rewrite
 * (`convert.rs:194-201`). Only `shadow_decision` / `shadow_reason` do.
 *
 * Reporting `enforced` alone would therefore paint an observe-mode deployment —
 * the product's recommended onboarding posture — as a wall of green `allow`
 * chips over suppressed denials.
 *
 * A row with neither field is not a policy decision at all (a budget or session
 * lifecycle event, say), so `enforced` is `not-evaluated` rather than a verdict.
 */
export function extractVerdict(payload: string): AuditVerdict {
  const parsed = parsePayload(payload)
  if (!isKnown(parsed)) {
    return {
      enforced: propagateAbsence(parsed),
      dryRun: false,
      suppressed: null,
      suppressedReason: null,
    }
  }
  const p = parsed.value
  const enforced =
    readDecisionValue(p['decision']) ??
    absent<AuditDecision>('not-evaluated', 'This entry records no policy decision')
  return {
    enforced,
    dryRun: p['dry_run'] === true,
    suppressed: readDecisionValue(p['shadow_decision']),
    suppressedReason: str(p, 'shadow_reason'),
  }
}

/**
 * Whether observe mode suppressed a *restrictive* verdict on this row.
 *
 * This is the predicate that decides whether a row may be counted as an allow,
 * or listed under "no policy violations". A suppressed `ALLOW` would be
 * meaningless (observe mode only ever suppresses `Deny` / `RequiresApproval` —
 * `engine/mod.rs:152-156`), so an unknown or absent suppression does not
 * disqualify the row.
 */
export function isSuppressedDenial(verdict: AuditVerdict): boolean {
  return verdict.suppressed !== null && isKnown(verdict.suppressed) && verdict.suppressed.value !== 'ALLOW'
}

// ── Event types ─────────────────────────────────────────────────────────────

/**
 * Every event type the product actually emits, in discriminant order.
 *
 * Mirrors `aa_core::audit::AuditEventType` (`aa-core/src/audit.rs`), whose
 * `as_str()` names are what `aa-api/src/routes/logs.rs` puts on the wire. The
 * previous list (`LLMCall` / `ToolCall` / `FileOp` / `NetworkCall` /
 * `ApprovalEvent`) existed only in the hi-fi mock's fixture — five of its six
 * names matched no backend variant, so five of six filters were permanently
 * empty in production (AAASM-5118).
 */
export const AUDIT_EVENT_TYPES = [
  'ToolCallIntercepted',
  'PolicyViolation',
  'CredentialLeakBlocked',
  'ApprovalRequested',
  'ApprovalGranted',
  'ApprovalDenied',
  'BudgetLimitApproached',
  'BudgetLimitExceeded',
  'ApprovalTimedOut',
  'ApprovalRouted',
  'ApprovalEscalated',
  'AgentForceDeregistered',
  'MessageBlocked',
  'ToolDispatched',
  'A2ACallIntercepted',
  'A2AImpersonationAttempted',
  'SandboxStarted',
  'SandboxFilesystemBlocked',
  'SandboxCpuTimeout',
  'SandboxOomKilled',
  'SandboxTerminated',
  'SandboxHostFnRateLimited',
] as const

export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number]

const KNOWN_EVENT_TYPES: ReadonlySet<string> = new Set(AUDIT_EVENT_TYPES)

/** Whether `eventType` is a variant this build knows about. */
export function isKnownEventType(eventType: string): eventType is AuditEventType {
  return KNOWN_EVENT_TYPES.has(eventType)
}

/**
 * Families the 22 variants are grouped into for the stats strip and the type
 * filter.
 *
 * 22 tiles would be unreadable, and the filter is what an operator reaches for
 * first. Grouping keeps the mock's one-row strip while every tile now counts
 * real events. `other` is the forward-compatibility bucket: a variant added to
 * `AuditEventType` after this build ships still lands somewhere, so the tiles
 * always sum to the loaded total instead of quietly losing rows.
 */
export const AUDIT_EVENT_GROUPS = [
  { key: 'tool', label: 'Tool Calls', members: ['ToolCallIntercepted', 'ToolDispatched'] },
  {
    key: 'policy',
    label: 'Policy',
    members: ['PolicyViolation', 'MessageBlocked', 'CredentialLeakBlocked'],
  },
  {
    key: 'approval',
    label: 'Approvals',
    members: [
      'ApprovalRequested',
      'ApprovalGranted',
      'ApprovalDenied',
      'ApprovalTimedOut',
      'ApprovalRouted',
      'ApprovalEscalated',
    ],
  },
  { key: 'budget', label: 'Budget', members: ['BudgetLimitApproached', 'BudgetLimitExceeded'] },
  { key: 'a2a', label: 'A2A', members: ['A2ACallIntercepted', 'A2AImpersonationAttempted'] },
  {
    key: 'sandbox',
    label: 'Sandbox',
    members: [
      'SandboxStarted',
      'SandboxFilesystemBlocked',
      'SandboxCpuTimeout',
      'SandboxOomKilled',
      'SandboxTerminated',
      'SandboxHostFnRateLimited',
    ],
  },
  { key: 'lifecycle', label: 'Lifecycle', members: ['AgentForceDeregistered'] },
  { key: 'other', label: 'Unrecognised', members: [] },
] as const satisfies readonly {
  key: string
  label: string
  members: readonly AuditEventType[]
}[]

export type AuditEventGroupKey = (typeof AUDIT_EVENT_GROUPS)[number]['key']

const GROUP_BY_EVENT_TYPE: ReadonlyMap<string, AuditEventGroupKey> = new Map(
  AUDIT_EVENT_GROUPS.flatMap((g) => g.members.map((m) => [m as string, g.key] as const)),
)

/**
 * Which family an event type belongs to. Anything outside the 22 known variants
 * is `other` — reported as unrecognised, never silently dropped or relabelled.
 */
export function eventGroupOf(eventType: string): AuditEventGroupKey {
  return GROUP_BY_EVENT_TYPE.get(eventType) ?? 'other'
}

// ── Payload readers ─────────────────────────────────────────────────────────

/** Read a non-empty string field, or `null`. */
function str(source: Record<string, unknown>, key: string): string | null {
  const v = source[key]
  return typeof v === 'string' && v.length > 0 ? v : null
}

/**
 * Pull the distributed-trace id out of a `LogEntry.payload`.
 *
 * `trace_id` is written into the payload JSON by `record_audit` rather than
 * being a wire field, and only for entries that came through the gRPC
 * `CheckAction` path — runtime-published entries carry no trace id at all, so
 * absence here is `not-supported` for that producer rather than a fault.
 */
export function extractTraceId(payload: string): Certain<string> {
  const p = parsePayload(payload)
  if (!isKnown(p)) return absent('unknown', 'Payload is not valid JSON')
  return certain(str(p.value, 'trace_id'), 'unknown', 'This entry carries no trace id')
}

/** Parse the payload string into an object, or report why it could not be read. */
function parsePayload(payload: string): Certain<Record<string, unknown>> {
  try {
    const parsed: unknown = JSON.parse(payload)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return absent('unknown', 'Payload is not a JSON object')
    }
    return known(parsed as Record<string, unknown>)
  } catch {
    return absent('unknown', 'Payload is not valid JSON')
  }
}

/** Join the parts that are actually present, so a gap never prints `undefined`. */
function joinParts(parts: readonly (string | null)[], separator = ' · '): string | null {
  const present = parts.filter((p): p is string => p !== null && p.length > 0)
  return present.length > 0 ? present.join(separator) : null
}

/**
 * Label a tri-state boolean payload field: present-and-true, present-and-false,
 * or absent.
 *
 * Absent must stay distinguishable from `false` — "the producer did not record
 * whether this succeeded" is not the same claim as "this failed", and folding
 * the two would put an error marker on a row nothing went wrong on.
 */
function boolLabel(value: unknown, whenTrue: string, whenFalse: string): string | null {
  if (typeof value !== 'boolean') return null
  return value ? whenTrue : whenFalse
}

/**
 * One summariser per `detail.kind`, keyed exactly as
 * `aa-runtime/src/audit_publisher/conversion.rs::detail_summary` emits them.
 *
 * A `Map` rather than a plain object because the key comes straight from
 * `detail.kind` — a `JSON.parse` of an untrusted audit blob. A plain-object
 * lookup inherits `Object.prototype`, so a blob whose `kind` is `constructor`,
 * `toString`, `valueOf` or `__proto__` would resolve to a *prototype* member and
 * then be **invoked** as though it were a summariser: `constructor` returns the
 * detail object stringified, `toString` returns `[object Undefined]`, and
 * `valueOf` throws — every one of them either fabricates a summary or crashes
 * the reader on a governance surface. A `Map` only ever contains its own keys,
 * so an inherited name misses and the caller reports an honest absence
 * (AAASM-5223).
 *
 * A table rather than a `switch` so each kind is an independently readable unit
 * and adding a producer-side kind is a one-line change here.
 */
const DETAIL_SUMMARISERS: ReadonlyMap<
  string,
  (detail: Record<string, unknown>) => string | null
> = new Map([
  ['llm_call', (d) => joinParts([str(d, 'model'), str(d, 'provider')])],

  [
    'tool_call',
    (d) => {
      const name = str(d, 'tool_name')
      const source = str(d, 'tool_source')
      const named = name && source ? `${name} (${source})` : (name ?? source)
      return joinParts([named, boolLabel(d['succeeded'], '✓ ok', '✕ error')])
    },
  ],

  [
    'file_op',
    (d) => {
      const operation = str(d, 'operation')
      const verb = operation ? operation.toUpperCase() : null
      return joinParts([joinParts([verb, str(d, 'path')], ' '), str(d, 'source')])
    },
  ],

  [
    'network_call',
    (d) => {
      const protocol = str(d, 'protocol')
      const host = str(d, 'host')
      if (!host) return protocol
      const port = typeof d['port'] === 'number' ? String(d['port']) : null
      const authority = port ? `${host}:${port}` : host
      return protocol ? `${protocol}://${authority}` : authority
    },
  ],

  [
    'process_exec',
    (d) => {
      const exitCode = d['exit_code']
      const exit = typeof exitCode === 'number' ? `exit ${exitCode}` : null
      return joinParts([str(d, 'command'), exit])
    },
  ],

  [
    'policy_violation',
    (d) => {
      const head = joinParts([str(d, 'blocked_action'), str(d, 'reason')], ' — ')
      const rule = str(d, 'policy_rule')
      return joinParts([head, rule ? `rule ${rule}` : null])
    },
  ],

  [
    'approval',
    (d) => joinParts([str(d, 'approval_id'), boolLabel(d['approved'], 'approved', 'denied')], ' '),
  ],
])

/**
 * Summarise the runtime's `detail` object.
 *
 * Kinds and fields are taken verbatim from
 * `aa-runtime/src/audit_publisher/conversion.rs::detail_summary`, which copies
 * only non-secret metadata. Every field is treated as optional: the producer
 * emits whatever the proto oneof carried, and a missing field must shrink the
 * sentence rather than print `undefined`. An unrecognised kind summarises to
 * `null` so the caller reports an absence instead of guessing.
 */
function summariseDetail(detail: Record<string, unknown>): string | null {
  const kind = str(detail, 'kind')
  const summarise = kind === null ? undefined : DETAIL_SUMMARISERS.get(kind)
  return summarise ? summarise(detail) : null
}

/**
 * Build the one-line summary for a row from its payload.
 *
 * Reads, in order: the runtime's `detail` object, then the gateway's
 * `reason` / `policy_rule` pair, then the string form of `action_type`. When
 * none of those carry anything readable the result is an explicit absence — the
 * previous behaviour, dumping 100 characters of raw JSON into the column, made
 * every gateway-produced row unreadable, and the `PolicyViolation` branch read
 * fields (`blocked_action`) the gateway never writes, rendering the literal
 * string `undefined — undefined` (AAASM-5119).
 *
 * Note there is no `eventType` parameter any more: the mock keyed the summary
 * off the event type because its fixture gave each type a bespoke payload
 * shape. The real payload shape is set by the *producer* (runtime vs gateway),
 * not by the event type, so keying off the type could only ever guess wrong.
 */
export function payloadSummary(payload: string): Certain<string> {
  const parsed = parsePayload(payload)
  if (!isKnown(parsed)) return propagateAbsence(parsed)
  const p = parsed.value

  const detail = p['detail']
  if (typeof detail === 'object' && detail !== null && !Array.isArray(detail)) {
    const summary = summariseDetail(detail as Record<string, unknown>)
    if (summary) return known(summary)
  }

  // Observe mode empties `reason` and `policy_rule` on the rewritten Allow
  // response (`aa-gateway/src/service/convert.rs:194-201`) and records the real
  // explanation under `shadow_reason`. Without this fallback a suppressed
  // denial's summary column is blank — the row would carry no trace at all of
  // why the action would have been blocked.
  const gateway = joinParts(
    [str(p, 'reason') ?? str(p, 'shadow_reason'), str(p, 'policy_rule')],
    ' — ',
  )
  if (gateway) return known(gateway)

  // `action_type` is an integer on the gateway path and a string
  // (`ActionType::as_str_name()`) on the runtime path. Only the string form is
  // human-readable, so the integer is deliberately not surfaced here.
  const actionType = str(p, 'action_type')
  if (actionType) return known(actionType)

  return absent('unknown', 'This entry carries no summarisable field')
}

// ── Query ───────────────────────────────────────────────────────────────────

/** The gateway's own ceiling: `PaginationParams::per_page` clamps to 100. */
export const AUDIT_PAGE_SIZE = 100

/**
 * How many pages one query will fetch before it stops and says so.
 *
 * A governance trail can be arbitrarily long, and the page cannot honestly
 * offer "show everything" if that means an unbounded fan-out of requests. The
 * ceiling exists so the *honest* answer at the boundary is "we stopped here and
 * this is not the whole record", never a silent cap presented as completeness.
 */
export const AUDIT_MAX_PAGES = 20

export interface AuditLogFilter {
  /** Hex-encoded agent ID; omitted means "all agents". */
  readonly agentId?: string | null
  /** Event-type variant name (e.g. `PolicyViolation`); omitted means "all types". */
  readonly eventType?: string | null
  /** How many pages of {@link AUDIT_PAGE_SIZE} rows to fetch. Defaults to 1. */
  readonly pages?: number
}

/**
 * One fetched window of the audit trail, plus everything needed to describe
 * honestly how much of the trail it is.
 */
export interface AuditLogWindow {
  readonly entries: LogEntry[]
  /**
   * Rows matching the *server-side* filter, from the `PaginatedLogResponse`
   * envelope. Absent when the gateway omitted it — in which case the page must
   * not claim to know how much it is missing.
   */
  readonly total: Certain<number>
  readonly pagesFetched: number
  /** The fetch stopped at {@link AUDIT_MAX_PAGES} with rows still unread. */
  readonly capped: boolean
}

/**
 * Fetch a window of the audit log.
 *
 * The server applies `agent_id` / `event_type`; the page applies its group and
 * free-text filters client-side over the fetched window. Pages are requested at
 * the gateway's maximum `per_page` and concatenated, so `pages` is the operator's
 * "load more" depth rather than a page cursor — the trail is append-at-head, and
 * re-reading from page 1 each time keeps the window internally consistent
 * instead of interleaving rows shifted by concurrent writes.
 *
 * Previously this sent no pagination at all and returned `data.items`, silently
 * accepting the gateway's 50-row default as though it were the whole trail
 * (AAASM-5120).
 */
export function useAuditLogQuery(
  filter: AuditLogFilter = {},
): UseQueryResult<AuditLogWindow> {
  const agentId = filter.agentId ?? undefined
  const eventType = filter.eventType ?? undefined
  const requestedPages = Math.max(1, Math.min(filter.pages ?? 1, AUDIT_MAX_PAGES))
  return useQuery<AuditLogWindow>({
    queryKey: ['audit', 'logs', agentId ?? null, eventType ?? null, requestedPages],
    // Keep the already-loaded window on screen while a deeper read is in
    // flight: "load more" must never blank the table back to a loading state,
    // which would read as the trail having been lost.
    placeholderData: (previous) => previous,
    queryFn: async () => {
      const entries: LogEntry[] = []
      let total: number | null = null
      let pagesFetched = 0
      let exhausted = false

      for (let page = 1; page <= requestedPages; page += 1) {
        const query: {
          agent_id?: string
          event_type?: string
          page: number
          per_page: number
        } = { page, per_page: AUDIT_PAGE_SIZE }
        if (agentId) query.agent_id = agentId
        if (eventType) query.event_type = eventType

        const { data, error } = await api.GET('/api/v1/logs', { params: { query } })
        if (error) throw new Error('Failed to fetch audit log')

        const items = data?.items ?? []
        if (typeof data?.total === 'number') total = data.total
        entries.push(...items)
        pagesFetched += 1
        if (items.length < AUDIT_PAGE_SIZE) {
          exhausted = true
          break
        }
      }

      const knownTotal = certain(total, 'unknown', 'The gateway reported no total')
      const moreRemain = isKnown(knownTotal) ? entries.length < knownTotal.value : !exhausted
      return {
        entries,
        total: knownTotal,
        pagesFetched,
        capped: pagesFetched >= AUDIT_MAX_PAGES && moreRemain,
      }
    },
  })
}

// ── Coverage ────────────────────────────────────────────────────────────────

/**
 * How much of the trail the operator is actually looking at.
 *
 * Kept as a plain value (rather than derived at each render site) so the table
 * header, the CSV export and the compliance report all state the same thing —
 * the previous defect was precisely that three surfaces each described the same
 * 50-row window in their own, uniformly over-confident, words.
 */
export interface AuditCoverage {
  /** Rows fetched into the window. */
  readonly loaded: number
  /** Rows matching the server-side filter, if the gateway said. */
  readonly total: Certain<number>
  /** The window provably covers every row matching the server-side filter. */
  readonly complete: boolean
  /** More rows remain but the page-fetch ceiling was reached. */
  readonly capped: boolean
  /** More rows remain and can still be fetched. */
  readonly moreAvailable: boolean
}

export function auditCoverage(window: AuditLogWindow | undefined): AuditCoverage {
  if (!window) {
    return {
      loaded: 0,
      total: absent('unavailable', 'The audit log has not been read'),
      complete: false,
      capped: false,
      moreAvailable: false,
    }
  }
  const loaded = window.entries.length
  const complete = isKnown(window.total) && loaded >= window.total.value
  return {
    loaded,
    total: window.total,
    complete,
    capped: window.capped,
    moreAvailable: !complete && !window.capped,
  }
}

/**
 * The single sentence every surface uses to describe the window.
 *
 * There is deliberately no wording in which a partial window sounds finished:
 * the only branch that says "complete" is the one where the envelope's `total`
 * is known *and* every one of those rows was fetched.
 */
export function coverageStatement(coverage: AuditCoverage): string {
  const { loaded, total } = coverage
  if (coverage.complete && isKnown(total)) {
    return `Complete — all ${total.value} entries matching the current filter are loaded.`
  }
  if (isKnown(total)) {
    const suffix = coverage.capped
      ? ' The page-fetch limit was reached; narrow the filter to read the rest.'
      : ''
    return `Partial — ${loaded} of ${total.value} entries matching the current filter are loaded. This is not the complete trail.${suffix}`
  }
  if (total.state === 'unavailable') {
    return 'Coverage unavailable — the audit log could not be read, so nothing can be said about how much of the trail is missing.'
  }
  return `Coverage unknown — ${loaded} entries are loaded, and the gateway did not report how many match the filter. This may not be the complete trail.`
}

/**
 * Stable cross-link path to a single audit entry's detail view. Mirrors the
 * `/audit/event/:id` convention the IAM Access Log already links to
 * (`AccessLogPanel`, AAASM-1398), keyed here by the entry's `seq`.
 */
export function auditEventHref(seq: number): string {
  return `/audit/event/${seq}`
}
