import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Step2InstallSdk } from './Step2InstallSdk'
import { probeGatewayHealth, type GatewayHealth } from '../api'

vi.mock('../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api')>()),
  probeGatewayHealth: vi.fn(),
}))

const probe = vi.mocked(probeGatewayHealth)

const HEALTHY: GatewayHealth = {
  status: 'ok',
  version: '0.0.1',
  api_version: 'v1',
  uptime_secs: 900,
  active_connections: 2,
  pipeline_lag_ms: 0,
  checks: { storage: 'ok', policy_engine: 'ok' },
}

/**
 * The exact strings the pre-AAASM-5132 step printed unconditionally.
 *
 * Asserted absent on the *successful* path too: reintroducing any of them means
 * the step has gone back to inventing an answer instead of reporting the
 * gateway's.
 */
const FABRICATIONS = [
  '1.4.2',
  'api.agent-assembly.com',
  'aa-cli verify',
  'ready to enroll',
  'connecting to runtime',
]

/** Drive the probe button and let its promise settle. */
async function clickProbe() {
  await act(async () => {
    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
  })
}

beforeEach(() => {
  probe.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('Step2InstallSdk — package commands', () => {
  it('defaults to the pip command and switches to npm/go on tab click', () => {
    render(<Step2InstallSdk onReachable={vi.fn()} />)
    expect(screen.getByTestId('onboarding-install-cmd')).toHaveTextContent(
      'pip install agent-assembly',
    )

    fireEvent.click(screen.getByTestId('onboarding-install-tab-npm'))
    expect(screen.getByTestId('onboarding-install-cmd')).toHaveTextContent(
      'npm install @agent-assembly/sdk',
    )

    fireEvent.click(screen.getByTestId('onboarding-install-tab-go'))
    expect(screen.getByTestId('onboarding-install-cmd')).toHaveTextContent(
      'go get github.com/agent-assembly/sdk-go',
    )
  })
})

describe('Step2InstallSdk — AAASM-5145 clipboard outcome', () => {
  it('reports success only after the write resolves, and resets on the timer', async () => {
    vi.useFakeTimers()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })

    render(<Step2InstallSdk onReachable={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-install-copy'))
    await act(async () => {})

    expect(writeText).toHaveBeenCalledWith('pip install agent-assembly')
    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('✓ copied')
    expect(screen.queryByTestId('onboarding-install-copy-error')).toBeNull()

    act(() => {
      vi.advanceTimersByTime(1400)
    })
    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('copy')
  })

  it('reports a rejected clipboard write as a failure, not as "copied"', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    Object.assign(navigator, { clipboard: { writeText } })

    render(<Step2InstallSdk onReachable={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-install-copy'))
    await act(async () => {})

    const button = screen.getByTestId('onboarding-install-copy')
    expect(button).toHaveTextContent('✗ copy failed')
    expect(button).not.toHaveTextContent('✓ copied')
    expect(button).toHaveAttribute('data-copy-state', 'failed')
    expect(screen.getByTestId('onboarding-install-copy-error')).toHaveAttribute('role', 'alert')
  })

  it('reports a failure when navigator.clipboard is undefined — the non-secure-context case', async () => {
    // http://<gateway-host>:<port>, i.e. every self-hosted deployment. The
    // member access throws a TypeError; the pre-fix code turned the button
    // green anyway.
    Object.assign(navigator, { clipboard: undefined })

    render(<Step2InstallSdk onReachable={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-install-copy'))
    await act(async () => {})

    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('✗ copy failed')
    expect(screen.getByTestId('onboarding-install-copy-error')).toBeInTheDocument()
  })
})

describe('Step2InstallSdk — AAASM-5132 gateway probe', () => {
  it('claims nothing before the operator asks', () => {
    const onReachable = vi.fn()
    render(<Step2InstallSdk onReachable={onReachable} />)

    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(screen.queryByTestId('onboarding-install-err')).toBeNull()
    expect(screen.getByTestId('onboarding-install-terminal')).toHaveTextContent(
      /cannot observe your SDK/i,
    )
    expect(onReachable).not.toHaveBeenCalled()
    expect(probe).not.toHaveBeenCalled()
  })

  it('reports the gateway’s own version, api version and checks on a healthy answer', async () => {
    probe.mockResolvedValue({ data: HEALTHY })
    const onReachable = vi.fn()
    render(<Step2InstallSdk onReachable={onReachable} />)

    await clickProbe()

    const terminal = screen.getByTestId('onboarding-install-terminal')
    expect(terminal).toHaveTextContent('GET /api/v1/health')
    expect(terminal).toHaveTextContent('0.0.1')
    expect(terminal).toHaveTextContent('storage=ok')
    expect(screen.getByTestId('onboarding-install-ok')).toHaveTextContent('gateway reachable')
    expect(onReachable).toHaveBeenCalledTimes(1)
  })

  it('never prints the fabricated transcript, even on the success path', async () => {
    probe.mockResolvedValue({ data: HEALTHY })
    render(<Step2InstallSdk onReachable={vi.fn()} />)

    await clickProbe()

    const terminal = screen.getByTestId('onboarding-install-terminal')
    for (const fabrication of FABRICATIONS) {
      expect(terminal).not.toHaveTextContent(fabrication)
    }
  })

  it('renders a failed probe as an error and refuses to report the step verified', async () => {
    probe.mockResolvedValue({ isError: true, error: new TypeError('Failed to fetch') })
    const onReachable = vi.fn()
    render(<Step2InstallSdk onReachable={onReachable} />)

    await clickProbe()

    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    const err = screen.getAllByTestId('onboarding-install-err')
    expect(err[0]).toHaveTextContent('unavailable')
    expect(err[1]).toHaveTextContent('Failed to fetch')
    // The shared absence marker carries the state and its screen-reader sentence.
    expect(screen.getByTestId('onboarding-install-absent')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    expect(onReachable).not.toHaveBeenCalled()
  })

  it('does not claim reachability when the gateway answers but reports itself degraded', async () => {
    probe.mockResolvedValue({ data: { ...HEALTHY, status: 'degraded' } })
    const onReachable = vi.fn()
    render(<Step2InstallSdk onReachable={onReachable} />)

    await clickProbe()

    expect(screen.getByTestId('onboarding-install-warn')).toHaveTextContent('degraded')
    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(onReachable).not.toHaveBeenCalled()
  })

  it('renders an empty 200 body as unknown rather than as a healthy gateway', async () => {
    probe.mockResolvedValue({ data: null })
    const onReachable = vi.fn()
    render(<Step2InstallSdk onReachable={onReachable} />)

    await clickProbe()

    expect(screen.getByTestId('onboarding-install-absent')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(onReachable).not.toHaveBeenCalled()
  })

  it('ignores a second click while a probe is in flight', async () => {
    let release: (() => void) | undefined
    probe.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ data: HEALTHY })
        }),
    )
    render(<Step2InstallSdk onReachable={vi.fn()} />)

    const button = screen.getByTestId('onboarding-install-verify')
    fireEvent.click(button)
    await act(async () => {})
    expect(button).toHaveTextContent('checking…')
    expect(button).toBeDisabled()

    fireEvent.click(button)
    await act(async () => {
      release?.()
    })

    expect(probe).toHaveBeenCalledTimes(1)
  })

  it('lets a re-check succeed after a failure, replacing the error transcript', async () => {
    probe.mockResolvedValueOnce({ isError: true, error: new Error('ECONNREFUSED') })
    probe.mockResolvedValueOnce({ data: HEALTHY })
    const onReachable = vi.fn()
    render(<Step2InstallSdk onReachable={onReachable} />)

    await clickProbe()
    expect(screen.getAllByTestId('onboarding-install-err').length).toBeGreaterThan(0)
    expect(screen.getByTestId('onboarding-install-verify')).toHaveTextContent('↻ re-check')

    await clickProbe()
    expect(screen.queryByTestId('onboarding-install-err')).toBeNull()
    expect(screen.getByTestId('onboarding-install-ok')).toBeInTheDocument()
    expect(onReachable).toHaveBeenCalledTimes(1)
  })
})
