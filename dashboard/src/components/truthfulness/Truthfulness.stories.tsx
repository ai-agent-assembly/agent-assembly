import type { Meta, StoryObj } from '@storybook/react'
import { TRUTH_STATES, TRUTH_STATE_META, absent, demo, known } from '../../lib/truthfulness'
import { StatusState } from './StatusState'
import { TruthfulValue } from './TruthfulValue'

/**
 * The complete truthfulness vocabulary in one place.
 *
 * Three of the six states — `unknown`, `not-supported`, and `demo` — have no
 * production path on any surface wired so far, so this gallery is where they
 * are reviewed until a page lane renders them for real. Keeping them here
 * rather than staging a fake page for a screenshot is the point: a governance
 * surface should not manufacture data to photograph.
 */
const meta: Meta = {
  title: 'Truthfulness/Vocabulary',
}
export default meta

type Story = StoryObj

/** Every state as the inline `—` affordance, beside a real value for contrast. */
export const InlineValues: Story = {
  render: () => (
    <table style={{ borderCollapse: 'collapse' }}>
      <tbody>
        <tr>
          <td style={{ padding: '0.5rem 1rem' }}>known (a measured zero)</td>
          <td style={{ padding: '0.5rem 1rem' }}>
            <TruthfulValue value={known(0)} />
          </td>
        </tr>
        {TRUTH_STATES.filter((state) => state !== 'demo').map((state) => (
          <tr key={state}>
            <td style={{ padding: '0.5rem 1rem' }}>{state}</td>
            <td style={{ padding: '0.5rem 1rem' }}>
              <TruthfulValue value={absent<number>(state, TRUTH_STATE_META[state].label)} showLabel />
            </td>
          </tr>
        ))}
        <tr>
          <td style={{ padding: '0.5rem 1rem' }}>demo (sample plus permanent badge)</td>
          <td style={{ padding: '0.5rem 1rem' }}>
            <TruthfulValue value={demo(1234)} />
          </td>
        </tr>
      </tbody>
    </table>
  ),
}

/** Every state as the block-level panel surface. */
export const BlockSurfaces: Story = {
  render: () => (
    <div style={{ display: 'grid', gap: '1rem', maxWidth: '40rem' }}>
      <StatusState
        state={null}
        title="No policies yet"
        description="The query succeeded and returned zero rows — a real answer, not an absence."
      />
      {TRUTH_STATES.map((state) => (
        <StatusState
          key={state}
          state={state}
          title={TRUTH_STATE_META[state].label}
          description={TRUTH_STATE_META[state].announcement}
          testId={`status-state-${state}`}
        />
      ))}
    </div>
  ),
}
