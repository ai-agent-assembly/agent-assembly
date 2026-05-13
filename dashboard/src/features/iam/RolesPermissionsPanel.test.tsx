import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, it, expect } from 'vitest'
import { RolesPermissionsPanel } from './RolesPermissionsPanel'
import { ToastProvider } from '../../components/ToastProvider'
import { _agentsInternal } from './agents'
import { groupBySourceKind } from './groupBySourceKind'
import type { EffectivePermission } from './types'

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>
          <RolesPermissionsPanel />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => { _agentsInternal.reset() })
afterEach(() => { _agentsInternal.reset() })

describe('groupBySourceKind', () => {
  const permissions: EffectivePermission[] = [
    { permission: 'policies.read', source: { kind: 'role', name: 'agent.operator', granted_at: '2026-04-12' } },
    { permission: 'members.read', source: { kind: 'team', name: 'cx', granted_at: '2026-04-10' } },
    { permission: 'audit.export', source: { kind: 'team', name: 'cx', granted_at: '2026-04-10' } },
    { permission: 'tools.invoke', source: { kind: 'policy', name: 'p-v2', granted_at: '2026-05-01' } },
  ]

  it('groups permissions by source.kind into team / role / policy buckets', () => {
    const grouped = groupBySourceKind(permissions)
    expect(grouped.team).toHaveLength(2)
    expect(grouped.role).toHaveLength(1)
    expect(grouped.policy).toHaveLength(1)
    expect(grouped.team.map((p) => p.permission)).toEqual(['members.read', 'audit.export'])
  })

  it('returns empty buckets for empty input', () => {
    const grouped = groupBySourceKind([])
    expect(grouped.team).toEqual([])
    expect(grouped.role).toEqual([])
    expect(grouped.policy).toEqual([])
  })
})

describe('RolesPermissionsPanel — agent registry list', () => {
  it('renders the seed agents', async () => {
    renderPanel()
    expect(await screen.findByTestId('agent-row-agent-001')).toBeInTheDocument()
    expect(screen.getByTestId('agent-row-agent-002')).toBeInTheDocument()
    expect(screen.getByTestId('agent-row-agent-003')).toBeInTheDocument()
    expect(screen.getByTestId('agent-row-agent-004')).toBeInTheDocument()
  })

  it('shows a hint when no agent is selected', async () => {
    renderPanel()
    await screen.findByTestId('agent-row-agent-001')
    expect(screen.getByTestId('agent-permissions-empty-hint')).toBeInTheDocument()
    expect(screen.queryByTestId('agent-permissions-panel')).not.toBeInTheDocument()
  })
})

describe('RolesPermissionsPanel — selection and grouping', () => {
  it('opens the permissions panel and renders the three source groups for the selected agent', async () => {
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('agent-row-agent-001')

    await user.click(screen.getByTestId('agent-row-agent-001'))

    const panel = await screen.findByTestId('agent-permissions-panel')
    expect(within(panel).getByText('support-agent')).toBeInTheDocument()
    expect(await screen.findByTestId('permission-source-team')).toBeInTheDocument()
    expect(screen.getByTestId('permission-source-role')).toBeInTheDocument()
    expect(screen.getByTestId('permission-source-policy')).toBeInTheDocument()
  })

  it('highlights the selected row via aria-selected', async () => {
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('agent-row-agent-002')
    expect(row).toHaveAttribute('aria-selected', 'false')
    await user.click(row)
    expect(row).toHaveAttribute('aria-selected', 'true')
  })

  it('renders the empty state for an agent with no effective permissions', async () => {
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('agent-row-agent-003')

    await user.click(screen.getByTestId('agent-row-agent-003'))

    expect(await screen.findByTestId('agent-permissions-empty')).toHaveTextContent(
      /no effective permissions/i,
    )
    expect(screen.queryByTestId('permission-source-team')).not.toBeInTheDocument()
    expect(screen.queryByTestId('permission-source-role')).not.toBeInTheDocument()
    expect(screen.queryByTestId('permission-source-policy')).not.toBeInTheDocument()
  })

  it('clears the selection when the panel close button is pressed', async () => {
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('agent-row-agent-002')
    await user.click(row)
    await screen.findByTestId('agent-permissions-panel')

    await user.click(screen.getByTestId('agent-permissions-close'))
    expect(screen.queryByTestId('agent-permissions-panel')).not.toBeInTheDocument()
    expect(screen.getByTestId('agent-permissions-empty-hint')).toBeInTheDocument()
  })

  it('supports Enter key for row selection', async () => {
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('agent-row-agent-004')
    row.focus()
    await user.keyboard('{Enter}')
    expect(await screen.findByTestId('agent-permissions-panel')).toBeInTheDocument()
    expect(screen.getByTestId('permission-source-policy')).toBeInTheDocument()
  })
})
