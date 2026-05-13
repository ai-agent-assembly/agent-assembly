import type { Meta, StoryObj } from '@storybook/react'
import { PipelineCanvas } from './PipelineCanvas'

const meta: Meta<typeof PipelineCanvas> = {
  title: 'LiveOps/PipelineCanvas',
  component: PipelineCanvas,
}
export default meta

type Story = StoryObj<typeof PipelineCanvas>

export const Default: Story = {
  render: () => (
    <div
      style={{
        width: 800,
        height: 480,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      <PipelineCanvas />
    </div>
  ),
}

export const Wide: Story = {
  render: () => (
    <div
      style={{
        width: 1280,
        height: 480,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      <PipelineCanvas />
    </div>
  ),
}

export const Tall: Story = {
  render: () => (
    <div
      style={{
        width: 600,
        height: 720,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      <PipelineCanvas />
    </div>
  ),
}

export const LowIntensity: Story = {
  render: () => (
    <div
      style={{
        width: 800,
        height: 480,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      <PipelineCanvas intensity={0.5} />
    </div>
  ),
}

export const HighIntensity: Story = {
  render: () => (
    <div
      style={{
        width: 800,
        height: 480,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      <PipelineCanvas intensity={5} />
    </div>
  ),
}

export const Paused: Story = {
  render: () => (
    <div
      style={{
        width: 800,
        height: 480,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      <PipelineCanvas paused intensity={3} />
    </div>
  ),
}
