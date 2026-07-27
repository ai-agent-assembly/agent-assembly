import type { Meta, StoryObj } from '@storybook/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApprovalDetailDrawer } from './ApprovalDetailDrawer'
import type { Approval } from '../../features/approvals/api'

const client = new QueryClient()

// One hour out so the SLA countdown renders a stable "low" tier for evidence.
const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString()

const PENDING: Approval = {
  id: 'apr-8f3c',
  action: 'http.egress api.stripe.com',
  agent_id: 'billing-agent',
  created_at: '2026-07-25T10:00:00Z',
  expires_at: FUTURE,
  reason: 'external payment API call requires human review',
  status: 'pending',
  team_id: 'payments',
}

const meta: Meta<typeof ApprovalDetailDrawer> = {
  component: ApprovalDetailDrawer,
  title: 'Trace/ApprovalDetailDrawer',
  parameters: { layout: 'fullscreen' },
  decorators: [
    (Story) => (
      <QueryClientProvider client={client}>
        <Story />
      </QueryClientProvider>
    ),
  ],
}

export default meta
type Story = StoryObj<typeof ApprovalDetailDrawer>

/** Pending approval — SLA countdown + request KV + live approve/reject footer. */
export const Pending: Story = {
  args: { approval: PENDING, onClose: () => {} },
}

/** Already decided — no SLA countdown, actions disabled, head chip shows the outcome. */
export const Decided: Story = {
  args: {
    approval: { ...PENDING, status: 'approved', expires_at: '' },
    onClose: () => {},
  },
}

/**
 * A status this build cannot interpret (AAASM-5190). `ApprovalResponse.status`
 * is an unconstrained wire string, so the head renders the neutral absence
 * marker instead of guessing a verdict — a PENDING chip here would be
 * indistinguishable from a genuinely pending approval.
 */
export const UnrecognisedStatus: Story = {
  args: {
    approval: { ...PENDING, status: 'escalated', expires_at: '' },
    onClose: () => {},
  },
}
