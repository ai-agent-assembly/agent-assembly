import { useId, useState } from 'react'
import { TruthfulValue } from '../../components/truthfulness'
import { absent, isKnown, known, type Certain } from '../../lib/truthfulness'
import { RowActionMenu } from './RowActionMenu'
import type {
  CallStackNode,
  LiveOperation,
  OperationOverride,
  OperationStatus,
} from './types'
import './OperationRow.css'

interface OperationRowProps {
  op: LiveOperation
  /** Initial expanded state (uncontrolled). Stories + tests use this. */
  defaultExpanded?: boolean
  /** Pending row-action; renders an "…ing" hint next to the chip. */
  override?: OperationOverride
  onPause?: () => void
  onResume?: () => void
  onTerminate?: () => void
  /** Optional agent-wide halt; forwarded to the row action menu when set. */
  onHaltAgent?: () => void
}

// OperationStatus is a closed app union, validated onto an op by
// `coerceStatus`/`opStateToStatus` in useLiveOpsStream.ts — narrow-union
// Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const STATUS_LABEL: Record<OperationStatus, string> = {
  running: 'RUNNING',
  pending: 'PENDING',
  blocked: 'BLOCKED',
  completing: 'COMPLETING',
  terminated: 'TERMINATED',
}

// OperationOverride is a closed local union set only by this page's own
// optimistic row-action state, never from the wire — narrow-union Record gap
// (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const OVERRIDE_LABEL: Record<OperationOverride, string> = {
  pausing: 'pausing…',
  resuming: 'resuming…',
  terminating: 'terminating…',
}

function formatStartedAt(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  return `${hh}:${mm}:${ss}`
}

/**
 * Render a latency that was actually measured (AAASM-5129).
 *
 * A measured `0` prints as `0ms`, not `<1ms`. `<1ms` is a claim about a
 * sub-millisecond duration; the wire reports whole milliseconds, so `0` means
 * "under the reporting resolution", and saying so is not the same as inventing
 * a bound. `<1ms` is kept for the fractional values call-stack nodes carry.
 *
 * Only ever called with a value that has already been admitted as measured —
 * `TruthfulValue` formats known values only, and `callStackLatency` is the gate
 * on the tree path. It deliberately does not return a bare `—` for a bad input:
 * a dash emitted from here would land in a plain `<span>` with no state, no
 * tone and no screen-reader sentence, which is the one thing the vocabulary
 * forbids. Rejecting a value is `callStackLatency`'s job, not this function's.
 */
function formatLatency(ms: number): string {
  if (ms === 0) return '0ms'
  if (ms < 1) return '<1ms'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

/**
 * Lift a call-stack node's latency into the vocabulary.
 *
 * `null` means the node carries no duration at all, and the tree simply renders
 * no latency element — a tree row is a label, not a table cell, so there is no
 * column left blank for an operator to read as zero. A value that *is* present
 * but uninterpretable (non-finite, or negative against the wire's
 * `minimum: 0`) is a genuine absence and renders the marker with its state.
 */
function callStackLatency(ms: number | undefined): Certain<number> | null {
  if (ms === undefined) return null
  if (!Number.isFinite(ms) || ms < 0) {
    return absent<number>('unknown', `Uninterpretable latency on the wire: ${String(ms)}`)
  }
  return known(ms)
}

/**
 * Row for a single in-flight operation in the Live Ops event-stream
 * zone. Collapsed by default; clicking the chevron expands a mini
 * call-stack tree (LLM call → tool call → result) inline beneath
 * the row, per AAASM-1282 implementation rule #4 (no drawer, no
 * route change). Row actions land in AAASM-1334.
 */
export function OperationRow({
  op,
  defaultExpanded = false,
  override,
  onPause,
  onResume,
  onTerminate,
  onHaltAgent,
}: Readonly<OperationRowProps>) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const treeId = useId()
  const canExpand = (op.callStack?.length ?? 0) > 0
  const showActions =
    onPause !== undefined && onResume !== undefined && onTerminate !== undefined

  return (
    <div
      className="op-row"
      data-testid="op-row"
      data-op-id={op.id}
      data-status={op.status}
      data-expanded={expanded ? 'true' : 'false'}
      data-override={override}
    >
      <div className="op-row__main">
        <button
          type="button"
          className={`op-row__chevron${expanded ? ' op-row__chevron--open' : ''}`}
          aria-expanded={expanded}
          aria-controls={canExpand ? treeId : undefined}
          aria-label={expanded ? 'Collapse call stack' : 'Expand call stack'}
          disabled={!canExpand}
          onClick={() => setExpanded((v) => !v)}
          data-testid="op-row-chevron"
        >
          ▸
        </button>
        <span className={`op-row__chip op-row__chip--${op.status}`}>
          {STATUS_LABEL[op.status]}
        </span>
        <span className="op-row__agent" title={op.agent}>
          {op.agent}
        </span>
        <span className="op-row__op-type">
          <TruthfulValue value={op.opType} testId="op-row-op-type" />
        </span>
        <span className="op-row__started-at">{formatStartedAt(op.startedAt)}</span>
        <span className="op-row__latency">
          <TruthfulValue
            value={op.latencyMs}
            format={formatLatency}
            testId="op-row-latency"
          />
        </span>
        {/* The tooltip is dropped when the resource is absent — `AbsenceMarker`
            installs its own `title` naming the state, and a wrapping `—` title
            would shadow it. */}
        <span
          className="op-row__resource"
          title={isKnown(op.resource) ? op.resource.value : undefined}
        >
          <TruthfulValue value={op.resource} testId="op-row-resource" />
        </span>
        {override && (
          <span className="op-row__override" data-testid="op-row-override">
            {OVERRIDE_LABEL[override]}
          </span>
        )}
        {showActions && (
          <RowActionMenu
            op={op}
            override={override}
            onPause={onPause}
            onResume={onResume}
            onTerminate={onTerminate}
            onHaltAgent={onHaltAgent}
          />
        )}
      </div>
      {expanded && canExpand && (
        <CallStackTree id={treeId} nodes={op.callStack ?? []} />
      )}
    </div>
  )
}

function CallStackTree({ id, nodes }: Readonly<{ id: string; nodes: CallStackNode[] }>) {
  return (
    <ul
      id={id}
      className="op-row__tree"
      role="tree"
      data-testid="op-row-tree"
    >
      {nodes.map((n) => (
        <CallStackTreeNode key={n.id} node={n} />
      ))}
    </ul>
  )
}

function CallStackTreeNode({ node }: Readonly<{ node: CallStackNode }>) {
  const latency = callStackLatency(node.latencyMs)
  return (
    <li className="op-row__tree-node" role="treeitem">
      <div className="op-row__tree-row">
        <span className={`op-row__tree-kind op-row__tree-kind--${node.kind}`}>
          {node.kind}
        </span>
        <span className="op-row__tree-label">{node.label}</span>
        {latency && (
          <span className="op-row__tree-latency">
            <TruthfulValue
              value={latency}
              format={formatLatency}
              testId="op-row-tree-latency"
            />
          </span>
        )}
      </div>
      {node.children && node.children.length > 0 && (
        <ul className="op-row__tree op-row__tree--nested" role="group">
          {node.children.map((c) => (
            <CallStackTreeNode key={c.id} node={c} />
          ))}
        </ul>
      )}
    </li>
  )
}
