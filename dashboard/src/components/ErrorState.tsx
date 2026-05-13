import type { ReactNode } from 'react'
import './StateView.css'

export type ErrorStateKind = 'generic' | 'live'

interface CopyEntry {
  icon: string
  tag: string
  title: string
  msg: ReactNode
  cta: string | null
  secondary: string | null
}

const COPY: Record<ErrorStateKind, CopyEntry> = {
  generic: {
    icon: '⚠',
    tag: 'request failed',
    title: 'Could not load this view',
    msg: (
      <>
        Backend returned <code>503 service_unavailable</code>. This is usually transient — retry in a few seconds.
        If it persists, check <code>status.agent-assembly.io</code>.
      </>
    ),
    cta: 'Retry',
    secondary: 'Open status page',
  },
  live: {
    icon: '⚠',
    tag: 'runtime · disconnected',
    title: 'Lost connection to enforcement runtime',
    msg: (
      <>
        Stream halted at <code>14:02:47 UTC</code>. Agents continue to operate under their{' '}
        <b>last known policy snapshot</b>; no new policy changes will propagate until reconnect.
      </>
    ),
    cta: 'Reconnect',
    secondary: 'View runtime logs',
  },
}

export interface ErrorStateProps {
  kind?: ErrorStateKind
  onRetry?: () => void
  onSecondary?: () => void
}

export function ErrorState({ kind = 'generic', onRetry, onSecondary }: ErrorStateProps) {
  const c = COPY[kind] ?? COPY.generic
  return (
    <div className="state-page" role="alert" data-testid={`error-state-${kind}`}>
      <div className="state-block">
        <div className="state-icon state-icon--err" aria-hidden>
          {c.icon}
        </div>
        <div className="state-tag">{c.tag}</div>
        <div className="state-title">{c.title}</div>
        <div className="state-msg">{c.msg}</div>
        <div className="state-actions">
          {c.cta && (
            <button type="button" className="state-btn state-btn--primary" onClick={onRetry}>
              ↻ {c.cta}
            </button>
          )}
          {c.secondary && (
            <button type="button" className="state-btn" onClick={onSecondary}>
              {c.secondary}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
