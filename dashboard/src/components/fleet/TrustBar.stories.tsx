import type { Meta, StoryObj } from '@storybook/react'
import { TrustBar } from './TrustBar'

const meta: Meta<typeof TrustBar> = {
  title: 'Fleet/TrustBar',
  component: TrustBar,
}
export default meta

type Story = StoryObj<typeof TrustBar>

export const Healthy: Story = { args: { score: 92 } }
export const Watch: Story = { args: { score: 67 } }
export const AtRisk: Story = { args: { score: 31 } }
export const Unwired: Story = { args: { score: null } }
