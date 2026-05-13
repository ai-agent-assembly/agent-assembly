import type { LiveOperation, OperationStatus } from './types'
import './OperationRow.css'

interface OperationRowProps {
  op: LiveOperation
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
 * Collapsed row for a single in-flight operation in the Live Ops
 * event-stream zone. Pure presentation: no local state, no actions.
 * Expand + row actions land in AAASM-1328 / AAASM-1334.
 */
export function OperationRow({ op }: OperationRowProps) {
  return (
    <div
      className="op-row"
      data-testid="op-row"
      data-op-id={op.id}
      data-status={op.status}
    >
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
  )
}
