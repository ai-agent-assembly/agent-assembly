import { render, screen } from '@testing-library/react'
import {
  NO_DATA,
  TRUTH_STATES,
  TRUTH_STATE_META,
  absent,
  demo,
  known,
} from '../../lib/truthfulness'
import { AbsenceMarker, TruthfulValue } from './TruthfulValue'

describe('AbsenceMarker', () => {
  it.each(TRUTH_STATES)('renders the %s state distinctly and accessibly', (state) => {
    render(<AbsenceMarker state={state} />)
    const marker = screen.getByTestId('truth-absent')

    // One learnable glyph everywhere...
    expect(marker).toHaveTextContent(NO_DATA)
    // ...but the state is always recoverable, by attribute, tooltip, and voice.
    expect(marker).toHaveAttribute('data-truth-state', state)
    expect(marker).toHaveAttribute('title', TRUTH_STATE_META[state].label)
    expect(marker).toHaveTextContent(TRUTH_STATE_META[state].announcement)
    expect(marker.className).toContain(`truth-tone--${TRUTH_STATE_META[state].tone}`)
  })

  it('gives each state its own tone class so they are visually separable', () => {
    const { rerender } = render(<AbsenceMarker state="unavailable" />)
    expect(screen.getByTestId('truth-absent').className).toContain('truth-tone--fault')
    rerender(<AbsenceMarker state="not-supported" />)
    expect(screen.getByTestId('truth-absent').className).toContain('truth-tone--neutral')
  })

  it('appends the detail to the tooltip and the announcement', () => {
    render(<AbsenceMarker state="unavailable" detail="HTTP 503" />)
    const marker = screen.getByTestId('truth-absent')
    expect(marker).toHaveAttribute('title', 'Unavailable — HTTP 503')
    expect(marker).toHaveTextContent('HTTP 503')
  })

  it('shows the label inline only when asked', () => {
    const { rerender } = render(<AbsenceMarker state="unconfigured" />)
    expect(screen.getByTestId('truth-absent').querySelector('.truth-absent__label')).toBeNull()
    rerender(<AbsenceMarker state="unconfigured" showLabel />)
    expect(
      screen.getByTestId('truth-absent').querySelector('.truth-absent__label'),
    ).toHaveTextContent('Unconfigured')
  })
})

describe('TruthfulValue', () => {
  it('renders a known value, optionally formatted', () => {
    const { rerender } = render(<TruthfulValue value={known(12)} />)
    expect(screen.getByTestId('truth-value')).toHaveTextContent('12')
    expect(screen.getByTestId('truth-value')).toHaveAttribute('data-truth-state', 'known')

    rerender(<TruthfulValue value={known(12)} format={(n) => `${n} cells`} />)
    expect(screen.getByTestId('truth-value')).toHaveTextContent('12 cells')
  })

  it('renders a legitimate zero as a value, not as an absence', () => {
    render(<TruthfulValue value={known(0)} />)
    const el = screen.getByTestId('truth-value')
    expect(el).toHaveAttribute('data-truth-state', 'known')
    expect(el).toHaveTextContent('0')
  })

  it.each(['unknown', 'unavailable', 'unconfigured', 'not-evaluated', 'not-supported'] as const)(
    'renders the %s absence instead of a number',
    (state) => {
      render(<TruthfulValue value={absent<number>(state)} />)
      const el = screen.getByTestId('truth-value')
      expect(el).toHaveAttribute('data-truth-state', state)
      expect(el).toHaveTextContent(NO_DATA)
      expect(el).toHaveTextContent(TRUTH_STATE_META[state].announcement)
    },
  )

  it('renders a demo sample only alongside a permanent visible label', () => {
    render(<TruthfulValue value={demo(42)} />)
    const el = screen.getByTestId('truth-value')
    expect(el).toHaveAttribute('data-truth-state', 'demo')
    expect(el).toHaveTextContent('42')
    // The badge is a sibling element, not a tooltip, so it survives a
    // screenshot and cannot be mistaken for a production figure.
    expect(el.querySelector('.truth-demo__badge')).toHaveTextContent('Demo data')
    expect(el).toHaveTextContent(TRUTH_STATE_META.demo.announcement)
  })

  it('falls back to the plain marker for a demo entry carrying no sample', () => {
    render(<TruthfulValue value={absent<number>('demo')} />)
    const el = screen.getByTestId('truth-value')
    expect(el).toHaveTextContent(NO_DATA)
    expect(el.querySelector('.truth-demo__badge')).toBeNull()
  })

  it('honours a custom test id', () => {
    render(<TruthfulValue value={absent<number>('unknown')} testId="cap-summary-allow" />)
    expect(screen.getByTestId('cap-summary-allow')).toBeInTheDocument()
  })
})
