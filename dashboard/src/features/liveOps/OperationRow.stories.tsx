import type { Meta, StoryObj } from '@storybook/react'
import { absent, known } from '../../lib/truthfulness'
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
  opType: known('read'),
  resource: known('gmail.send'),
  startedAt: '2026-05-13T14:23:01Z',
  latencyMs: known(834),
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
      opType: known('write'),
      resource: known('pg.users'),
    },
  },
}

export const Blocked: Story = {
  args: {
    op: {
      ...base,
      id: 'op-3',
      status: 'blocked',
      opType: known('exec'),
      resource: known('shell.exec'),
      latencyMs: known(4523),
    },
  },
}

export const Completing: Story = {
  args: { op: { ...base, id: 'op-4', status: 'completing', latencyMs: known(2.3) } },
}

/**
 * The production shape today: `ViolationPayload.latency_ms` is not populated
 * yet, so the row must say so rather than claim `<1ms` (AAASM-5129).
 */
export const UnmeasuredLatency: Story = {
  args: {
    op: {
      ...base,
      id: 'op-7',
      status: 'running',
      latencyMs: absent<number>(
        'unknown',
        'The audit pipeline does not record per-action duration yet',
      ),
    },
  },
}

/** An `ops_change` row: the payload carries no verb, resource or latency. */
export const OpsChangeRow: Story = {
  args: {
    op: {
      ...base,
      id: 'trace-1:span-2',
      status: 'blocked',
      opType: absent<string>('not-supported', 'not carried on ops_change events'),
      resource: absent<string>('not-supported', 'not carried on ops_change events'),
      latencyMs: absent<number>('not-supported', 'not carried on ops_change events'),
      callStack: undefined,
    },
  },
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
