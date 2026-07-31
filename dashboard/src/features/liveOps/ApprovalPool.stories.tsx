import type { Meta, StoryObj } from '@storybook/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { absent, known } from '../../lib/truthfulness'
import type { Approval } from '../approvals/api'
import { ApprovalPool } from './ApprovalPool'

// The inline ApprovalActions primitive uses react-query mutations, so the
// pool needs a QueryClient in scope to render its pending cards.
const storyClient = new QueryClient()

const inMinutes = (m: number) => new Date(Date.now() + m * 60_000).toISOString()

function approval(id: string, agent: string, action: string, ttlMinutes: number): Approval {
  return {
    id,
    agent_id: agent,
    action,
    reason: 'Policy requires human approval',
    status: 'pending',
    created_at: new Date().toISOString(),
    expires_at: inMinutes(ttlMinutes),
    routing_status: null,
    team_id: null,
  }
}

const FEW: Approval[] = [
  approval('3f1c9a52-0c4e-4a1b-9f2d-6a7b8c9d0e1f', 'support-agent', 'write pg.users', 12),
  approval('7b2d4e60-1a3f-4c5d-8e9f-0a1b2c3d4e5f', 'deploy-agent', 'exec shell.exec', 3),
  approval('c9e8d7f6-5a4b-4c3d-2e1f-0a9b8c7d6e5f', 'data-analyst', 'read gdrive.read', 45),
]

const MANY: Approval[] = Array.from({ length: 12 }, (_, i) =>
  approval(
    `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    ['support-agent', 'deploy-agent', 'data-analyst', 'email-agent'][i % 4],
    ['read pg.users', 'write s3.write', 'delete shell.exec', 'exec gmail.send'][i % 4],
    (i + 1) * 4,
  ),
)

const meta: Meta<typeof ApprovalPool> = {
  title: 'LiveOps/ApprovalPool',
  component: ApprovalPool,
  decorators: [
    (Story) => (
      <QueryClientProvider client={storyClient}>
        <MemoryRouter>
          <div style={{ width: 320, padding: 16, background: 'var(--paper)' }}>
            <Story />
          </div>
        </MemoryRouter>
      </QueryClientProvider>
    ),
  ],
}
export default meta

type Story = StoryObj<typeof ApprovalPool>

/** The queue loaded and is genuinely clear — a known answer, not an absence. */
export const Empty: Story = {
  args: { approvals: known<readonly Approval[]>([]) },
}

/**
 * The queue request failed. This must be visibly different from `Empty`
 * (AAASM-5167) — both used to render as the same blank panel.
 */
export const Unavailable: Story = {
  args: {
    approvals: absent<readonly Approval[]>('unavailable', 'Failed to fetch approvals'),
    onRetry: () => console.log('retry'),
  },
}

/** First load, request still in flight. */
export const Loading: Story = {
  args: { approvals: absent<readonly Approval[]>('unknown', 'Request in flight') },
}

export const Few: Story = {
  args: { approvals: known<readonly Approval[]>(FEW) },
}

export const Many: Story = {
  args: { approvals: known<readonly Approval[]>(MANY) },
}
