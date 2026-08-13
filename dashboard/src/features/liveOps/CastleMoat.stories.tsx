import type { Meta, StoryObj } from '@storybook/react'
import { CastleMoat } from './CastleMoat'

const meta: Meta<typeof CastleMoat> = {
  title: 'LiveOps/CastleMoat',
  component: CastleMoat,
}
export default meta

type Story = StoryObj<typeof CastleMoat>

function frame(children: React.ReactNode, w: number, h: number) {
  return (
    <div
      style={{
        width: w,
        height: h,
        position: 'relative',
        border: '1px solid var(--line)',
      }}
    >
      {children}
    </div>
  )
}

export const Default: Story = {
  render: () => frame(<CastleMoat />, 640, 540),
}

export const Wide: Story = {
  render: () => frame(<CastleMoat />, 1024, 540),
}

export const HighIntensity: Story = {
  render: () => frame(<CastleMoat intensity={5} />, 640, 540),
}

export const Paused: Story = {
  render: () => frame(<CastleMoat paused intensity={3} />, 640, 540),
}
