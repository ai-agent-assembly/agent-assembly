import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { KpiCard } from './KpiCard'
import { KpiStrip } from './KpiStrip'
import type { KpiMetric } from './kpi-delta'

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeQC() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={makeQC()}>
      <MemoryRouter initialEntries={['/analytics']}>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

function mockFetchKpi(metric: KpiMetric, value: number, delta: number) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ metric, value, delta }),
  } as Response)
}

// ── KpiCard unit tests ───────────────────────────────────────────────────────

describe('KpiCard', () => {
  it('renders skeleton placeholders while loading', () => {
    render(
      <KpiCard metric="agents" label="Total Agents" value={undefined} delta={undefined} isLoading isError={false} />,
    )
    expect(screen.getByTestId('kpi-agents')).toBeInTheDocument()
    // skeletons are aria-hidden; value text must NOT appear
    expect(screen.queryByText(/\d/)).toBeNull()
  })

  it('renders value and label when loaded', () => {
    render(
      <KpiCard metric="agents" label="Total Agents" value={42} delta={0.05} isLoading={false} isError={false} />,
    )
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('Total Agents')).toBeInTheDocument()
  })

  it('renders unit alongside value', () => {
    render(
      <KpiCard metric="p99" label="p99 Latency" value={120} delta={-0.08} unit="ms" isLoading={false} isError={false} />,
    )
    expect(screen.getByText('ms')).toBeInTheDocument()
  })

  it('colors delta with --trend-positive when trend is positive for agents', () => {
    render(
      <KpiCard metric="agents" label="Total Agents" value={10} delta={0.12} isLoading={false} isError={false} />,
    )
    const delta = screen.getByText('+12.0%')
    expect(delta).toHaveStyle({ color: 'var(--trend-positive)' })
  })

  it('colors delta with --trend-negative when trend is negative for agents', () => {
    render(
      <KpiCard metric="agents" label="Total Agents" value={10} delta={-0.05} isLoading={false} isError={false} />,
    )
    const delta = screen.getByText('-5.0%')
    expect(delta).toHaveStyle({ color: 'var(--trend-negative)' })
  })

  it('colors delta green for p99 when delta is negative (lower latency = good)', () => {
    render(
      <KpiCard metric="p99" label="p99 Latency" value={95} delta={-0.08} unit="ms" isLoading={false} isError={false} />,
    )
    const delta = screen.getByText('-8.0%')
    expect(delta).toHaveStyle({ color: 'var(--trend-positive)' })
  })

  it('colors delta red for p99 when delta is positive (higher latency = bad)', () => {
    render(
      <KpiCard metric="p99" label="p99 Latency" value={150} delta={0.2} unit="ms" isLoading={false} isError={false} />,
    )
    const delta = screen.getByText('+20.0%')
    expect(delta).toHaveStyle({ color: 'var(--trend-negative)' })
  })

  it('colors delta green for cost when delta is negative (lower cost = good)', () => {
    render(
      <KpiCard metric="cost" label="Total Cost" value={50} delta={-0.1} unit="USD" isLoading={false} isError={false} />,
    )
    expect(screen.getByText('-10.0%')).toHaveStyle({ color: 'var(--trend-positive)' })
  })

  it('colors delta green for anomalies when delta is negative (fewer anomalies = good)', () => {
    render(
      <KpiCard metric="anomalies" label="Anomaly Count" value={3} delta={-0.5} isLoading={false} isError={false} />,
    )
    expect(screen.getByText('-50.0%')).toHaveStyle({ color: 'var(--trend-positive)' })
  })

  it('renders dash on error state', () => {
    render(
      <KpiCard metric="agents" label="Total Agents" value={undefined} delta={undefined} isLoading={false} isError />,
    )
    expect(screen.getByText('—')).toBeInTheDocument()
  })
})

// ── KpiCard data-testid ──────────────────────────────────────────────────────

describe('KpiCard data-testid', () => {
  const METRICS: KpiMetric[] = ['agents', 'invocations', 'p99', 'cost', 'anomalies']
  it.each(METRICS)('has data-testid="kpi-%s"', metric => {
    render(
      <KpiCard metric={metric} label={metric} value={1} delta={0} isLoading={false} isError={false} />,
    )
    expect(screen.getByTestId(`kpi-${metric}`)).toBeInTheDocument()
  })
})

// ── KpiStrip integration ─────────────────────────────────────────────────────

describe('KpiStrip', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders all 5 KPI card test-ids in loading state', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))  // never resolves
    render(<KpiStrip />, { wrapper: Wrapper })
    expect(screen.getByTestId('kpi-agents')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-invocations')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-p99')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-cost')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-anomalies')).toBeInTheDocument()
  })

  it('renders correct value for agents card after query resolves', async () => {
    mockFetchKpi('agents', 99, 0.1)
    render(<KpiStrip />, { wrapper: Wrapper })
    expect(await screen.findByText('99')).toBeInTheDocument()
  })

  it('renders delta with correct sign for invocations', async () => {
    mockFetchKpi('invocations', 5000, 0.25)
    render(<KpiStrip />, { wrapper: Wrapper })
    expect(await screen.findByText('+25.0%')).toBeInTheDocument()
  })
})
