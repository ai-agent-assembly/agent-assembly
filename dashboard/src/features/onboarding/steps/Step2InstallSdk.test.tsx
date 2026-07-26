/**
 * Mocks the HTTP client rather than `probeGatewayHealth`, so every case below
 * drives the real probe → `certainFromQuery` → `buildProbeLines` chain from a
 * genuine `{ data, error, response }` triple.
 *
 * That matters for the degraded case in particular: `aa-api/src/routes/health.rs`
 * pairs `status: "degraded"` with a **503**, so a mocked 200-carrying-degraded
 * would exercise a state the gateway cannot produce while leaving the real one
 * untested. (`openapi-fetch` captures `globalThis.fetch` at module load, so the
 * client is the only interceptable seam — see `features/onboarding/api.test.tsx`.)
 */
import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Step2InstallSdk } from './Step2InstallSdk'
import { api } from '../../../api/client'
import type { GatewayHealth } from '../api'

vi.mock('../../../api/client', () => ({ api: { GET: vi.fn() } }))

const apiGet = api.GET as unknown as ReturnType<typeof vi.fn>

const HEALTHY: GatewayHealth = {
  status: 'ok',
  version: '0.0.1',
  api_version: 'v1',
  uptime_secs: 900,
  active_connections: 2,
  pipeline_lag_ms: 0,
  checks: { storage: 'ok', policy_engine: 'ok' },
}

/** What a gateway with a broken storage backend actually answers. */
const DEGRADED: GatewayHealth = {
  ...HEALTHY,
  status: 'degraded',
  checks: { storage: 'degraded', policy_engine: 'ok' },
}

/** The subset of `Response` the probe reads. */
function res(status: number): Response {
  return { ok: status >= 200 && status < 300, status } as Response
}

/** A 200 answer. */
function ok(data: unknown) {
  return { data, error: undefined, response: res(200) }
}

/** A non-2xx answer; `openapi-fetch` puts the parsed body in `error`. */
function failure(status: number, error: unknown) {
  return { data: undefined, error, response: res(status) }
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
  apiGet.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('Step2InstallSdk — package commands', () => {
  it('defaults to the pip command and switches to npm/go on tab click', () => {
    render(<Step2InstallSdk onProbed={vi.fn()} />)
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

    render(<Step2InstallSdk onProbed={vi.fn()} />)
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

    render(<Step2InstallSdk onProbed={vi.fn()} />)
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

    render(<Step2InstallSdk onProbed={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-install-copy'))
    await act(async () => {})

    expect(screen.getByTestId('onboarding-install-copy')).toHaveTextContent('✗ copy failed')
    expect(screen.getByTestId('onboarding-install-copy-error')).toBeInTheDocument()
  })
})

describe('Step2InstallSdk — AAASM-5132 gateway probe', () => {
  it('claims nothing before the operator asks', () => {
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(screen.queryByTestId('onboarding-install-err')).toBeNull()
    expect(screen.getByTestId('onboarding-install-terminal')).toHaveTextContent(
      /cannot observe your SDK/i,
    )
    expect(onProbed).not.toHaveBeenCalled()
    expect(apiGet).not.toHaveBeenCalled()
  })

  it('reports the gateway’s own version, api version and checks on a healthy answer', async () => {
    apiGet.mockResolvedValue(ok(HEALTHY))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    await clickProbe()

    const terminal = screen.getByTestId('onboarding-install-terminal')
    expect(terminal).toHaveTextContent('GET /api/v1/health')
    expect(terminal).toHaveTextContent('0.0.1')
    expect(terminal).toHaveTextContent('storage=ok')
    expect(screen.getByTestId('onboarding-install-ok')).toHaveTextContent('gateway reachable')
    expect(onProbed).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('never prints the fabricated transcript, even on the success path', async () => {
    apiGet.mockResolvedValue(ok(HEALTHY))
    render(<Step2InstallSdk onProbed={vi.fn()} />)

    await clickProbe()

    const terminal = screen.getByTestId('onboarding-install-terminal')
    for (const fabrication of FABRICATIONS) {
      expect(terminal).not.toHaveTextContent(fabrication)
    }
  })

  it('renders a failed probe as an error and refuses to report the step verified', async () => {
    apiGet.mockRejectedValue(new TypeError('Failed to fetch'))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

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
    expect(onProbed).toHaveBeenCalledWith(false)
  })

  it('renders a real 503-with-body as degraded — an answer, not silence', async () => {
    // The production degraded path: 503 carrying a complete HealthResponse.
    // Nothing here is a mocked 200.
    apiGet.mockResolvedValue(failure(503, DEGRADED))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    await clickProbe()

    // It is NOT reported as "the gateway did not answer".
    expect(screen.queryByTestId('onboarding-install-err')).toBeNull()
    expect(screen.queryByTestId('onboarding-install-absent')).toBeNull()
    const terminal = screen.getByTestId('onboarding-install-terminal')
    expect(terminal).not.toHaveTextContent('did not answer')
    // The subsystem the gateway named is on screen, twice over.
    expect(terminal).toHaveTextContent('storage=degraded')
    expect(screen.getByTestId('onboarding-install-warn')).toHaveTextContent('storage')
    // Still not healthy, so the step does not pass.
    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(onProbed).toHaveBeenCalledWith(false)
  })

  it('renders a 503 whose body is not a health report as unavailable', async () => {
    apiGet.mockResolvedValue(failure(503, { type: 'about:blank', title: 'Unavailable' }))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    await clickProbe()

    expect(screen.getByTestId('onboarding-install-absent')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    expect(screen.getAllByTestId('onboarding-install-err')[1]).toHaveTextContent('HTTP 503')
    expect(onProbed).toHaveBeenCalledWith(false)
  })

  it('renders an empty 200 body as unknown rather than as a healthy gateway', async () => {
    apiGet.mockResolvedValue(ok(null))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    await clickProbe()

    expect(screen.getByTestId('onboarding-install-absent')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(onProbed).toHaveBeenCalledWith(false)
  })

  it('ignores a second click while a probe is in flight', async () => {
    let release: (() => void) | undefined
    apiGet.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve(ok(HEALTHY))
        }),
    )
    render(<Step2InstallSdk onProbed={vi.fn()} />)

    const button = screen.getByTestId('onboarding-install-verify')
    fireEvent.click(button)
    await act(async () => {})
    expect(button).toHaveTextContent('checking…')
    expect(button).toBeDisabled()

    fireEvent.click(button)
    await act(async () => {
      release?.()
    })

    expect(apiGet).toHaveBeenCalledTimes(1)
  })

  it('lets a re-check succeed after a failure, replacing the error transcript', async () => {
    apiGet.mockRejectedValueOnce(new Error('ECONNREFUSED'))
    apiGet.mockResolvedValueOnce(ok(HEALTHY))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    await clickProbe()
    expect(screen.getAllByTestId('onboarding-install-err').length).toBeGreaterThan(0)
    expect(screen.getByTestId('onboarding-install-verify')).toHaveTextContent('↻ re-check')

    await clickProbe()
    expect(screen.queryByTestId('onboarding-install-err')).toBeNull()
    expect(screen.getByTestId('onboarding-install-ok')).toBeInTheDocument()
    expect(onProbed.mock.calls).toEqual([[false], [true]])
  })

  it('withdraws the healthy verdict when a re-check fails — the flag never latches', async () => {
    // AAASM-5132 review: reporting only successes latched the wizard's flag
    // `true` for good, so a failing re-check rendered the red UNAVAILABLE
    // transcript while the footer still read "✓ ready to continue".
    apiGet.mockResolvedValueOnce(ok(HEALTHY))
    apiGet.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    const onProbed = vi.fn()
    render(<Step2InstallSdk onProbed={onProbed} />)

    await clickProbe()
    expect(onProbed).toHaveBeenLastCalledWith(true)

    await clickProbe()
    expect(onProbed).toHaveBeenLastCalledWith(false)
    expect(onProbed.mock.calls).toEqual([[true], [false]])
    expect(screen.queryByTestId('onboarding-install-ok')).toBeNull()
    expect(screen.getByTestId('onboarding-install-absent')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
  })
})
