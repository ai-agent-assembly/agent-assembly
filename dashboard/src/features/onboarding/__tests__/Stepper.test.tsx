import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { Stepper } from '../Stepper'

describe('Stepper', () => {
  it('renders a button per step with the right status attributes', () => {
    render(<Stepper currentStep="identity" />)
    expect(screen.getByTestId('onboarding-stepper-framework')).toHaveAttribute(
      'data-status',
      'done',
    )
    expect(screen.getByTestId('onboarding-stepper-install')).toHaveAttribute(
      'data-status',
      'done',
    )
    expect(screen.getByTestId('onboarding-stepper-identity')).toHaveAttribute(
      'data-status',
      'current',
    )
    expect(screen.getByTestId('onboarding-stepper-policy')).toHaveAttribute(
      'data-status',
      'future',
    )
    expect(screen.getByTestId('onboarding-stepper-enroll')).toHaveAttribute(
      'data-status',
      'future',
    )
  })

  it('disables future-step buttons but allows past-step click-jumps', () => {
    const onJump = vi.fn()
    render(<Stepper currentStep="identity" onJump={onJump} />)
    expect(screen.getByTestId('onboarding-stepper-policy')).toBeDisabled()
    expect(screen.getByTestId('onboarding-stepper-enroll')).toBeDisabled()
    expect(screen.getByTestId('onboarding-stepper-framework')).not.toBeDisabled()

    fireEvent.click(screen.getByTestId('onboarding-stepper-framework'))
    expect(onJump).toHaveBeenCalledWith('framework')
  })

  it('does not call onJump for future steps', () => {
    const onJump = vi.fn()
    render(<Stepper currentStep="framework" onJump={onJump} />)
    fireEvent.click(screen.getByTestId('onboarding-stepper-enroll'))
    expect(onJump).not.toHaveBeenCalled()
  })
})
