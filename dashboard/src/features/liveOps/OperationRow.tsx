import { useId, useState } from 'react'
import type { CallStackNode, LiveOperation, OperationStatus } from './types'
import './OperationRow.css'

interface OperationRowProps {
  op: LiveOperation
  /** Initial expanded state (uncontrolled). Stories + tests use this. */
  defaultExpanded?: boolean
}

const STATUS_LABEL: Record<OperationStatus, string> = {
  running: 'RUNNING',
  pending: 'PENDING',
  blocked: 'BLOCKED',
  completing: 'COMPLETING',
}

function formatStartedAt(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  return `${hh}:${mm}:${ss}`
}

function formatLatency(ms: number): string {
  if (ms < 1) return '<1ms'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

/**
 * Row for a single in-flight operation in the Live Ops event-stream
 * zone. Collapsed by default; clicking the chevron expands a mini
 * call-stack tree (LLM call → tool call → result) inline beneath
 * the row, per AAASM-1282 implementation rule #4 (no drawer, no
 * route change). Row actions land in AAASM-1334.
 */
export function OperationRow({ op, defaultExpanded = false }: OperationRowProps) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const treeId = useId()
  const canExpand = (op.callStack?.length ?? 0) > 0

  return (
    <div
      className="op-row"
      data-testid="op-row"
      data-op-id={op.id}
      data-status={op.status}
      data-expanded={expanded ? 'true' : 'false'}
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
        <span className="op-row__op-type">{op.opType}</span>
        <span className="op-row__started-at">{formatStartedAt(op.startedAt)}</span>
        <span className="op-row__latency">{formatLatency(op.latencyMs)}</span>
        <span className="op-row__resource" title={op.resource}>
          {op.resource}
        </span>
      </div>
      {expanded && canExpand && (
        <CallStackTree id={treeId} nodes={op.callStack ?? []} />
      )}
    </div>
  )
}

function CallStackTree({ id, nodes }: { id: string; nodes: CallStackNode[] }) {
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

function CallStackTreeNode({ node }: { node: CallStackNode }) {
  return (
    <li className="op-row__tree-node" role="treeitem">
      <div className="op-row__tree-row">
        <span className={`op-row__tree-kind op-row__tree-kind--${node.kind}`}>
          {node.kind}
        </span>
        <span className="op-row__tree-label">{node.label}</span>
        {typeof node.latencyMs === 'number' && (
          <span className="op-row__tree-latency">{formatLatency(node.latencyMs)}</span>
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
