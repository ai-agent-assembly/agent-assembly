import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AuthContext, type AuthContextValue, type Scope } from '../../auth/AuthContext'
import { WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import { known } from '../../lib/truthfulness'
import { RowActionMenu } from './RowActionMenu'
import type { LiveOperation, OperationOverride, OperationStatus } from './types'

function op(status: OperationStatus = 'running'): LiveOperation {
  return {
    id: 'op-1',
    agent: 'support-agent',
    opType: known('write'),
    resource: known('pg.users'),
    status,
    startedAt: '2026-05-14T01:00:00Z',
    latencyMs: known(42),
  }
}

/**
 * Mount inside an AuthProvider-equivalent so the scope under test is the one
 * `usePermissions` reads. Without a provider it now resolves to *no* scopes
 * (AAASM-5180), so a spec that wants the enabled branch has to say so.
 */
function withScopes(scopes: Scope[], ui: React.ReactElement) {
  const auth: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    logout: () => {},
  }
  return <AuthContext.Provider value={auth}>{ui}</AuthContext.Provider>
}

function setup(overrides?: {
  status?: OperationStatus
  override?: OperationOverride
  onHaltAgent?: () => void
  scopes?: Scope[]
}) {
  const onPause = vi.fn()
  const onResume = vi.fn()
  const onTerminate = vi.fn()
  const menu = (
    <RowActionMenu
      op={op(overrides?.status)}
      override={overrides?.override}
      onPause={onPause}
      onResume={onResume}
      onTerminate={onTerminate}
      onHaltAgent={overrides?.onHaltAgent}
    />
  )
  const view = render(withScopes(overrides?.scopes ?? ['read', 'write'], menu))
  return { onPause, onResume, onTerminate, user: userEvent.setup(), view }
}

describe('RowActionMenu', () => {
  it('hides the menu until the kebab is clicked', async () => {
    const { user } = setup()
    expect(screen.queryByTestId('row-action-menu-list')).toBeNull()
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-menu-list')).toBeInTheDocument()
  })

  it('Pause enabled and Resume disabled when status=running', async () => {
    const { user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-pause')).not.toBeDisabled()
    expect(screen.getByTestId('row-action-resume')).toBeDisabled()
    expect(screen.getByTestId('row-action-terminate')).not.toBeDisabled()
  })

  it('Resume enabled and Pause disabled when status=blocked', async () => {
    const { user } = setup({ status: 'blocked' })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-pause')).toBeDisabled()
    expect(screen.getByTestId('row-action-resume')).not.toBeDisabled()
  })

  it.each(['pending', 'completing'] as const)(
    'Pause and Resume both disabled when status=%s',
    async (status) => {
      const { user } = setup({ status })
      await user.click(screen.getByTestId('row-action-trigger'))
      expect(screen.getByTestId('row-action-pause')).toBeDisabled()
      expect(screen.getByTestId('row-action-resume')).toBeDisabled()
    },
  )

  it('all items disabled while override is set', async () => {
    const { user } = setup({ status: 'running', override: 'pausing' })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-pause')).toBeDisabled()
    expect(screen.getByTestId('row-action-resume')).toBeDisabled()
    expect(screen.getByTestId('row-action-terminate')).toBeDisabled()
  })

  it('clicking Pause fires onPause and closes the menu', async () => {
    const { onPause, user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-pause'))
    expect(onPause).toHaveBeenCalledTimes(1)
    expect(screen.queryByTestId('row-action-menu-list')).toBeNull()
  })

  it('clicking Resume fires onResume', async () => {
    const { onResume, user } = setup({ status: 'blocked' })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-resume'))
    expect(onResume).toHaveBeenCalledTimes(1)
  })

  it('clicking Terminate opens the confirmation dialog without firing onTerminate', async () => {
    const { onTerminate, user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    expect(onTerminate).not.toHaveBeenCalled()
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()
  })

  it('confirming the terminate dialog fires onTerminate and closes the dialog', async () => {
    const { onTerminate, user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    expect(onTerminate).toHaveBeenCalledTimes(1)
    expect(screen.queryByTestId('confirm-dialog')).toBeNull()
  })

  it('cancelling the terminate dialog does not fire onTerminate', async () => {
    const { onTerminate, user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    await user.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(onTerminate).not.toHaveBeenCalled()
    expect(screen.queryByTestId('confirm-dialog')).toBeNull()
  })

  it('omits the Halt agent item when no handler is supplied', async () => {
    const { user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.queryByTestId('row-action-halt-agent')).toBeNull()
  })

  it('renders Halt agent when a handler is supplied and confirms before firing', async () => {
    const onHaltAgent = vi.fn()
    const { user } = setup({ status: 'running', onHaltAgent })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-halt-agent'))
    // Opens a confirm dialog rather than firing directly.
    expect(onHaltAgent).not.toHaveBeenCalled()
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()
    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    expect(onHaltAgent).toHaveBeenCalledTimes(1)
    expect(screen.queryByTestId('confirm-dialog')).toBeNull()
  })

  it('disables Halt agent while an override is in flight', async () => {
    const onHaltAgent = vi.fn()
    const { user } = setup({ status: 'running', override: 'pausing', onHaltAgent })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-halt-agent')).toBeDisabled()
  })

  it('Escape closes the menu', async () => {
    const { user } = setup()
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-menu-list')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('row-action-menu-list')).toBeNull()
  })

  it('outside click closes the menu', async () => {
    const { user } = setup()
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-menu-list')).toBeInTheDocument()
    await user.click(document.body)
    expect(screen.queryByTestId('row-action-menu-list')).toBeNull()
  })

  // ── AAASM-5148: RBAC on the op-control mutations ─────────────────────────

  it('disables every item for a read-only caller, with the write hint', async () => {
    const { user } = setup({ status: 'running', scopes: ['read'], onHaltAgent: vi.fn() })
    await user.click(screen.getByTestId('row-action-trigger'))
    for (const id of [
      'row-action-pause',
      'row-action-resume',
      'row-action-terminate',
      'row-action-halt-agent',
    ]) {
      const item = screen.getByTestId(id)
      expect(item).toBeDisabled()
      expect(item).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    }
  })

  it('leaves the status-appropriate items live for a write caller', async () => {
    const { user } = setup({ status: 'running', scopes: ['write'], onHaltAgent: vi.fn() })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-pause')).toBeEnabled()
    expect(screen.getByTestId('row-action-terminate')).toBeEnabled()
    expect(screen.getByTestId('row-action-halt-agent')).toBeEnabled()
  })

  it('admin satisfies the write requirement', async () => {
    const { user } = setup({ status: 'running', scopes: ['admin'] })
    await user.click(screen.getByTestId('row-action-trigger'))
    expect(screen.getByTestId('row-action-pause')).toBeEnabled()
  })

  // The menu item is not the last control before terminate — the confirm
  // dialog is, and it lives in a shared component. This drives the one state
  // that reaches it past a disabled menu item: the operator opens the dialog
  // while holding `write`, then the scope lapses (token refresh) before they
  // confirm. Without the gate on the dialog itself, "Terminate" stays live.
  it('closes an open terminate dialog when the caller loses write scope', async () => {
    const onTerminate = vi.fn()
    const menu = (
      <RowActionMenu
        op={op('running')}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onTerminate={onTerminate}
      />
    )
    const user = userEvent.setup()
    const { rerender } = render(withScopes(['write'], menu))

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()

    rerender(withScopes(['read'], menu))

    expect(screen.queryByTestId('confirm-dialog')).toBeNull()
    expect(onTerminate).not.toHaveBeenCalled()
  })

  it('closes an open halt-agent dialog when the caller loses write scope', async () => {
    const onHaltAgent = vi.fn()
    const menu = (
      <RowActionMenu
        op={op('running')}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onTerminate={vi.fn()}
        onHaltAgent={onHaltAgent}
      />
    )
    const user = userEvent.setup()
    const { rerender } = render(withScopes(['write'], menu))

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-halt-agent'))
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()

    rerender(withScopes(['read'], menu))

    expect(screen.queryByTestId('confirm-dialog')).toBeNull()
    expect(onHaltAgent).not.toHaveBeenCalled()
  })
})
