import type { Meta, StoryObj } from '@storybook/react'
import { ModeChip } from './ModeChip'

const meta: Meta<typeof ModeChip> = {
  title: 'Fleet/ModeChip',
  component: ModeChip,
}
export default meta

type Story = StoryObj<typeof ModeChip>

export const Enforce: Story = { args: { mode: 'enforce' } }
export const Shadow: Story = { args: { mode: 'shadow' } }
export const Off: Story = { args: { mode: 'off' } }
