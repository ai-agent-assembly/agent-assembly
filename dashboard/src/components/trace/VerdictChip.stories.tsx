import type { Meta, StoryObj } from '@storybook/react'
import { VerdictChip } from './VerdictChip'
import type { Verdict } from '../../features/trace/decision'

const VERDICTS: Verdict[] = ['allowed', 'narrowed', 'scrubbed', 'pending', 'denied']

const meta: Meta<typeof VerdictChip> = {
  component: VerdictChip,
  title: 'Trace/VerdictChip',
}

export default meta
type Story = StoryObj<typeof VerdictChip>

function Row({ shape }: { readonly shape: 'pill' | 'square' }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      {VERDICTS.map((v) => (
        <VerdictChip key={v} verdict={v} shape={shape} />
      ))}
    </div>
  )
}

/** Default pill rounding — every existing caller (Trace timeline / payload modal) is unchanged. */
export const Pill: Story = {
  render: () => <Row shape="pill" />,
}

/** Ratified square corners (AAASM-5075) — the opt-in shape for Wave-2 surfaces. */
export const Square: Story = {
  render: () => <Row shape="square" />,
}

/** Pill vs square side by side, plus the compact glyph variant. */
export const Gallery: Story = {
  render: () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginBottom: 6 }}>pill (default)</div>
        <Row shape="pill" />
      </div>
      <div>
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginBottom: 6 }}>square (ratified)</div>
        <Row shape="square" />
      </div>
      <div>
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginBottom: 6 }}>compact glyphs</div>
        <div style={{ display: 'flex', gap: 8 }}>
          {VERDICTS.map((v) => (
            <VerdictChip key={v} verdict={v} variant="compact" shape="square" />
          ))}
        </div>
      </div>
    </div>
  ),
}
