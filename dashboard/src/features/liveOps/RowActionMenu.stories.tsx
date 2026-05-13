import type { Meta, StoryObj } from '@storybook/react'
import { useEffect } from 'react'
import { RowActionMenu } from './RowActionMenu'
import type { LiveOperation } from './types'

function op(status: LiveOperation['status']): LiveOperation {
  return {
    id: 'op-1',
    agent: 'support-agent',
    opType: 'write',
    resource: 'pg.users',
    status,
    startedAt: '2026-05-14T01:00:00Z',
    latencyMs: 84,
  }
}

const meta: Meta<typeof RowActionMenu> = {
  title: 'LiveOps/RowActionMenu',
  component: RowActionMenu,
  decorators: [
    (Story) => (
      <div
        style={{
          padding: 24,
          background: 'var(--paper)',
          display: 'flex',
          justifyContent: 'flex-end',
          width: 320,
        }}
      >
        <Story />
      </div>
    ),
  ],
  args: {
    onPause: () => console.log('pause'),
    onResume: () => console.log('resume'),
    onTerminate: () => console.log('terminate'),
  },
}
export default meta

type Story = StoryObj<typeof RowActionMenu>

/** Running op — Pause + Terminate enabled, Resume disabled. */
export const Default: Story = {
  args: { op: op('running') },
}

/** Blocked op — Resume + Terminate enabled, Pause disabled. */
export const BlockedOp: Story = {
  args: { op: op('blocked') },
}

/** Pending op — both Pause and Resume disabled (only Terminate fires). */
export const PendingOp: Story = {
  args: { op: op('pending') },
}

/** Override set — the whole menu is disabled while the call is in flight. */
export const Pausing: Story = {
  args: { op: op('running'), override: 'pausing' },
}

/**
 * Auto-clicks the trigger on mount so the popover renders for visual
 * comparison without needing the Storybook user to interact.
 */
function OpenedMenuStory(args: React.ComponentProps<typeof RowActionMenu>) {
  useEffect(() => {
    const trigger = document.querySelector<HTMLButtonElement>(
      '[data-testid="row-action-trigger"]',
    )
    trigger?.click()
  }, [])
  return <RowActionMenu {...args} />
}

export const MenuOpen: Story = {
  args: { op: op('running') },
  render: (args) => <OpenedMenuStory {...args} />,
}
