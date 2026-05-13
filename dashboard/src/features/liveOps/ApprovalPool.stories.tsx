import type { Meta, StoryObj } from '@storybook/react'
import { MemoryRouter } from 'react-router-dom'
import { ApprovalPool } from './ApprovalPool'
import type { LiveOperation } from './types'

function pendingOp(id: string, agent: string, opType: string, resource: string): LiveOperation {
  return {
    id,
    agent,
    opType,
    resource,
    status: 'pending',
    startedAt: '2026-05-14T01:00:00Z',
    latencyMs: 0,
  }
}

const FEW: LiveOperation[] = [
  pendingOp('op-1', 'support-agent', 'write', 'pg.users'),
  pendingOp('op-2', 'deploy-agent', 'exec', 'shell.exec'),
  pendingOp('op-3', 'data-analyst', 'read', 'gdrive.read'),
]

const MANY: LiveOperation[] = Array.from({ length: 12 }, (_, i) =>
  pendingOp(
    `op-many-${i}`,
    ['support-agent', 'deploy-agent', 'data-analyst', 'email-agent'][i % 4],
    ['read', 'write', 'delete', 'exec'][i % 4],
    ['pg.users', 's3.write', 'shell.exec', 'gmail.send'][i % 4],
  ),
)

const RUNNING_NOISE: LiveOperation[] = [
  {
    id: 'noise-1',
    agent: 'support-agent',
    opType: 'read',
    resource: 'gmail.send',
    status: 'running',
    startedAt: '2026-05-14T01:00:00Z',
    latencyMs: 100,
  },
]

const meta: Meta<typeof ApprovalPool> = {
  title: 'LiveOps/ApprovalPool',
  component: ApprovalPool,
  decorators: [
    (Story) => (
      <MemoryRouter>
        <div style={{ width: 320, padding: 16, background: 'var(--paper)' }}>
          <Story />
        </div>
      </MemoryRouter>
    ),
  ],
}
export default meta

type Story = StoryObj<typeof ApprovalPool>

export const Empty: Story = {
  args: { ops: [] },
}

export const RunningOpsOnly: Story = {
  args: { ops: RUNNING_NOISE },
}

export const Few: Story = {
  args: { ops: FEW },
}

export const Many: Story = {
  args: { ops: MANY },
}

export const MixedWithRunning: Story = {
  args: { ops: [...FEW, ...RUNNING_NOISE] },
}
