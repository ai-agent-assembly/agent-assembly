import type { Meta, StoryObj } from '@storybook/react'
import { OperationRow } from './OperationRow'
import type { CallStackNode, LiveOperation } from './types'

const meta: Meta<typeof OperationRow> = {
  title: 'LiveOps/OperationRow',
  component: OperationRow,
}
export default meta

type Story = StoryObj<typeof OperationRow>

const CALL_STACK: CallStackNode[] = [
  {
    id: 'llm-1',
    kind: 'llm',
    label: 'gpt-4o · "fetch user 4521 billing"',
    latencyMs: 834,
    children: [
      {
        id: 'tool-1',
        kind: 'tool',
        label: 'query_db · SELECT * FROM billing WHERE user_id=4521',
        latencyMs: 41,
      },
      { id: 'result-1', kind: 'result', label: '1 row · 2.1 KB' },
    ],
  },
]

const base: Omit<LiveOperation, 'id' | 'status'> = {
  agent: 'support-agent',
  opType: 'read',
  resource: 'gmail.send',
  startedAt: '2026-05-13T14:23:01Z',
  latencyMs: 834,
  callStack: CALL_STACK,
}

export const Running: Story = {
  args: { op: { ...base, id: 'op-1', status: 'running' } },
}

export const Pending: Story = {
  args: {
    op: {
      ...base,
      id: 'op-2',
      status: 'pending',
      opType: 'write',
      resource: 'pg.users',
    },
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

export const Expanded: Story = {
  args: {
    op: { ...base, id: 'op-5', status: 'running' },
    defaultExpanded: true,
  },
}

export const NoCallStack: Story = {
  args: {
    op: { ...base, id: 'op-6', status: 'running', callStack: undefined },
  },
}
