import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Step5EnrollAgent } from './Step5EnrollAgent'
import { EMPTY_STATE, type WizardState } from '../types'

const ENROLLED_STATE: WizardState = { ...EMPTY_STATE, enrolled: true }

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.runOnlyPendingTimers()
  vi.useRealTimers()
})

describe('Step5EnrollAgent', () => {
  it('shows the full ping stack immediately when already enrolled (resume)', () => {
    render(<Step5EnrollAgent state={ENROLLED_STATE} onEnrolled={vi.fn()} />)
    expect(screen.getByTestId('onboarding-enroll-ping-1')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-enroll-ping-2')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-enroll-ping-3')).toBeInTheDocument()
  })

  it('streams pings one at a time rather than dumping them all at once', () => {
    const onEnrolled = vi.fn()
    render(<Step5EnrollAgent state={EMPTY_STATE} onEnrolled={onEnrolled} />)
    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    // Connect resolves at 800ms: enrolled fires and the first ping lands.
    act(() => {
      vi.advanceTimersByTime(800)
    })
    expect(onEnrolled).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('onboarding-enroll-ping-1')).toBeInTheDocument()
    expect(screen.queryByTestId('onboarding-enroll-ping-2')).toBeNull()
    expect(screen.queryByTestId('onboarding-enroll-ping-3')).toBeNull()

    // Subsequent pings arrive on the stagger interval.
    act(() => {
      vi.advanceTimersByTime(500)
    })
    expect(screen.getByTestId('onboarding-enroll-ping-2')).toBeInTheDocument()
    expect(screen.queryByTestId('onboarding-enroll-ping-3')).toBeNull()

    act(() => {
      vi.advanceTimersByTime(500)
    })
    expect(screen.getByTestId('onboarding-enroll-ping-3')).toBeInTheDocument()
  })
})
