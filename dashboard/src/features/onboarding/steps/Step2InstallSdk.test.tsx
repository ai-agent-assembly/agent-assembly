import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Step2InstallSdk } from './Step2InstallSdk'
import { EMPTY_STATE, type WizardState } from '../types'

const VERIFIED_STATE: WizardState = { ...EMPTY_STATE, installVerified: true }

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.runOnlyPendingTimers()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('Step2InstallSdk', () => {
  it('defaults to the pip command and switches to npm/go on tab click', () => {
    render(<Step2InstallSdk state={EMPTY_STATE} onVerified={vi.fn()} />)
    expect(screen.getByTestId('onboarding-install-cmd')).toHaveTextContent('pip install agent-assembly')

    fireEvent.click(screen.getByTestId('onboarding-install-tab-npm'))
    expect(screen.getByTestId('onboarding-install-cmd')).toHaveTextContent('npm install @agent-assembly/sdk')

    fireEvent.click(screen.getByTestId('onboarding-install-tab-go'))
    expect(screen.getByTestId('onboarding-install-cmd')).toHaveTextContent(
      'go get github.com/agent-assembly/sdk-go',
    )
  })

  it('copies the active command to the clipboard and flips the label back after the timeout', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })

    render(<Step2InstallSdk state={EMPTY_STATE} onVerified={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-install-copy'))
    // Flush the async clipboard handler's state update (setCopied) without
    // wrapping the fireEvent call itself — the label flips on a microtask.
    await act(async () => {})

    expect(writeText).toHaveBeenCalledWith('pip install agent-assembly')
    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('✓ copied')

    act(() => {
      vi.advanceTimersByTime(1400)
    })
    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('copy')
  })

  it('swallows a clipboard write rejection without throwing', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    Object.assign(navigator, { clipboard: { writeText } })

    render(<Step2InstallSdk state={EMPTY_STATE} onVerified={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-install-copy'))
    // Flush the async clipboard handler's state update (setCopied) without
    // wrapping the fireEvent call itself — the label flips on a microtask.
    await act(async () => {})
    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('✓ copied')
  })

  it('runs verify and calls onVerified once the terminal resolves', () => {
    const onVerified = vi.fn()
    render(<Step2InstallSdk state={EMPTY_STATE} onVerified={onVerified} />)

    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    expect(screen.getByText('verifying…')).toBeInTheDocument()

    act(() => {
      vi.advanceTimersByTime(600)
    })

    expect(onVerified).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('onboarding-install-ok')).toBeInTheDocument()
  })

  it('ignores a verify click that arrives mid-run', () => {
    const onVerified = vi.fn()
    render(<Step2InstallSdk state={EMPTY_STATE} onVerified={onVerified} />)
    const verify = screen.getByTestId('onboarding-install-verify')
    fireEvent.click(verify)
    fireEvent.click(verify)
    act(() => {
      vi.advanceTimersByTime(600)
    })
    expect(onVerified).toHaveBeenCalledTimes(1)
  })

  it('hydrates straight into the verified terminal when state.installVerified is true', () => {
    render(<Step2InstallSdk state={VERIFIED_STATE} onVerified={vi.fn()} />)
    expect(screen.getByTestId('onboarding-install-ok')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-install-verify')).toHaveTextContent('↻ re-run')
  })
})
