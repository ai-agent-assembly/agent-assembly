import type { Meta, StoryObj } from '@storybook/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApprovalActions } from './ApprovalActions'

const client = new QueryClient()

const meta: Meta<typeof ApprovalActions> = {
  component: ApprovalActions,
  title: 'Approvals/ApprovalActions',
  decorators: [
    (Story) => (
      <QueryClientProvider client={client}>
        <div style={{ padding: 16 }}>
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
}

export default meta
type Story = StoryObj<typeof ApprovalActions>

/** Inline density — for Live-ops approval cards / table rows. */
export const InlineSmall: Story = {
  args: { approvalId: 'apr-001', size: 'sm' },
}

/** Larger drawer/footer density. */
export const DrawerMedium: Story = {
  args: { approvalId: 'apr-001', size: 'md' },
}

/** Already decided / expired — both actions disabled. */
export const Disabled: Story = {
  args: { approvalId: 'apr-001', size: 'sm', disabled: true },
}
