import type { ReactNode } from 'react'
import './StateView.css'

export type EmptyStatePage =
  | 'overview'
  | 'fleet'
  | 'policy'
  | 'scrub'
  | 'capability'
  | 'live'
  | 'agent'
  | 'approvals'

interface CopyEntry {
  icon: string
  tag: string
  title: string
  msg: ReactNode
  cta: string | null
  secondary: string | null
}

const COPY: Record<EmptyStatePage, CopyEntry> = {
  overview: {
    icon: '⊘',
    tag: '0 agents',
    title: 'Waiting for SDK registration',
    msg: (
      <>
        No agents have phoned home. Install the SDK in your agent code; it will self-register on first run.
        <br />
        <br />
        <code>$ pip install agent-assembly-sdk</code>
      </>
    ),
    cta: 'Start setup wizard',
    secondary: 'View install docs',
  },
  fleet: {
    icon: '∅',
    tag: 'fleet · 0 results',
    title: 'No agents match current filters',
    msg: (
      <>All filters can be cleared from the bar above. Or check that agents are still phoning home.</>
    ),
    cta: 'Clear filters',
    secondary: null,
  },
  policy: {
    icon: '⌬',
    tag: 'policies · 0 active',
    title: 'No policies defined',
    msg: (
      <>
        Without policies, all agent calls fall through to the runtime default (<code>sandbox · log-only</code>).
        Define your first allow-list rule to start enforcing.
      </>
    ),
    cta: '+ New policy',
    secondary: 'Import from preset',
  },
  scrub: {
    icon: '✶',
    tag: 'patterns · awaiting input',
    title: 'No payload to scan',
    msg: <>Paste a request body or LLM prompt into the editor on the left.</>,
    cta: null,
    secondary: null,
  },
  capability: {
    icon: '◫',
    tag: 'matrix · 0×0',
    title: 'No capability surface to map',
    msg: (
      <>
        The capability matrix renders once at least one agent has registered AND at least one resource
        integration is connected. Connect a resource (Gmail, S3, GitHub, …) or onboard an agent.
      </>
    ),
    cta: 'Connect resource',
    secondary: 'Onboard agent',
  },
  live: {
    icon: '◌',
    tag: 'runtime · idle',
    title: 'No traffic in the last 60s',
    msg: (
      <>
        The enforcement runtime is connected and healthy — there are simply no agent calls right now.
      </>
    ),
    cta: 'Generate test traffic',
    secondary: 'View 24h history',
  },
  agent: {
    icon: '◇',
    tag: 'agent · awaiting first call',
    title: 'Agent registered, no activity yet',
    msg: (
      <>
        Identity issued and trust score initialized at <code>50</code>. Trust will adjust on first authenticated call.
      </>
    ),
    cta: 'Copy enrollment command',
    secondary: 'View install docs',
  },
  approvals: {
    icon: '✓',
    tag: 'queue · 0 pending',
    title: 'No pending approval requests',
    msg: (
      <>
        All agent actions are currently flowing through policy unchallenged. New approval requests will appear
        here in real time as the policy engine routes them.
      </>
    ),
    cta: null,
    secondary: null,
  },
}

export interface EmptyStateProps {
  page?: EmptyStatePage
  onCta?: () => void
  onSecondary?: () => void
}

export function EmptyState({ page = 'overview', onCta, onSecondary }: EmptyStateProps) {
  const c = COPY[page] ?? COPY.overview
  return (
    <div className="state-page" role="status" data-testid={`empty-state-${page}`}>
      <div className="state-block">
        <div className="state-icon" aria-hidden>
          {c.icon}
        </div>
        <div className="state-tag">{c.tag}</div>
        <div className="state-title">{c.title}</div>
        <div className="state-msg">{c.msg}</div>
        {(c.cta || c.secondary) && (
          <div className="state-actions">
            {c.cta && (
              <button type="button" className="state-btn state-btn--primary" onClick={onCta}>
                ▸ {c.cta}
              </button>
            )}
            {c.secondary && (
              <button type="button" className="state-btn" onClick={onSecondary}>
                {c.secondary}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
