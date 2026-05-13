import { useState } from 'react'
import type { Meta, StoryObj } from '@storybook/react'
import { AutoScrollToggle } from './AutoScrollToggle'

function Interactive({
  initialEnabled,
  initialPending,
}: {
  initialEnabled: boolean
  initialPending: number
}) {
  const [enabled, setEnabled] = useState(initialEnabled)
  const [pending, setPending] = useState(initialPending)
  return (
    <AutoScrollToggle
      enabled={enabled}
      onEnabledChange={setEnabled}
      pendingCount={pending}
      onFlushPending={() => setPending(0)}
    />
  )
}

const meta: Meta<typeof AutoScrollToggle> = {
  title: 'LiveOps/AutoScrollToggle',
  component: AutoScrollToggle,
}
export default meta

type Story = StoryObj<typeof Interactive>

export const On: Story = {
  render: () => <Interactive initialEnabled={true} initialPending={0} />,
}

export const PausedNoBacklog: Story = {
  render: () => <Interactive initialEnabled={false} initialPending={0} />,
}

export const PausedWithBacklog: Story = {
  render: () => <Interactive initialEnabled={false} initialPending={12} />,
}

export const PausedWithSingleOp: Story = {
  render: () => <Interactive initialEnabled={false} initialPending={1} />,
}
