import type { Meta, StoryObj } from '@storybook/react'
import { OperationRow } from './OperationRow'
import type { LiveOperation } from './types'

const meta: Meta<typeof OperationRow> = {
  title: 'LiveOps/OperationRow',
  component: OperationRow,
}
export default meta

type Story = StoryObj<typeof OperationRow>

const base: Omit<LiveOperation, 'id' | 'status'> = {
  agent: 'support-agent',
  opType: 'read',
  resource: 'gmail.send',
  startedAt: '2026-05-13T14:23:01Z',
  latencyMs: 834,
}

export const Running: Story = {
  args: { op: { ...base, id: 'op-1', status: 'running' } },
}

export const Pending: Story = {
  args: {
    op: { ...base, id: 'op-2', status: 'pending', opType: 'write', resource: 'pg.users' },
  },
}

export const Blocked: Story = {
  args: {
    op: {
      ...base,
      id: 'op-3',
      status: 'blocked',
      opType: 'exec',
      resource: 'shell.exec',
      latencyMs: 4523,
    },
  },
}

export const Completing: Story = {
  args: { op: { ...base, id: 'op-4', status: 'completing', latencyMs: 2.3 } },
}
