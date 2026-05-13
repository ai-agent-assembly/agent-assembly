import type { Meta, StoryObj } from '@storybook/react'
import { StatusChip } from './StatusChip'

const meta: Meta<typeof StatusChip> = {
  title: 'Fleet/StatusChip',
  component: StatusChip,
}
export default meta

type Story = StoryObj<typeof StatusChip>

export const Active: Story = { args: { status: 'active' } }
export const Suspended: Story = { args: { status: 'suspended' } }
export const Error: Story = { args: { status: 'error' } }
