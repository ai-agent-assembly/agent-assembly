import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { RowActionMenu } from './RowActionMenu'
import type { LiveOperation, OperationOverride, OperationStatus } from './types'

function op(status: OperationStatus = 'running'): LiveOperation {
  return {
    id: 'op-1',
    agent: 'support-agent',
    opType: 'write',
    resource: 'pg.users',
    status,
    startedAt: '2026-05-14T01:00:00Z',
    latencyMs: 42,
  }
}

function setup(overrides?: {
  status?: OperationStatus
  override?: OperationOverride
}) {
  const onPause = vi.fn()
  const onResume = vi.fn()
  const onTerminate = vi.fn()
  render(
    <RowActionMenu
      op={op(overrides?.status)}
      override={overrides?.override}
      onPause={onPause}
      onResume={onResume}
      onTerminate={onTerminate}
    />,
  )
  return { onPause, onResume, onTerminate, user: userEvent.setup() }
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

  it('clicking Terminate fires onTerminate', async () => {
    const { onTerminate, user } = setup({ status: 'running' })
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    expect(onTerminate).toHaveBeenCalledTimes(1)
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
})
