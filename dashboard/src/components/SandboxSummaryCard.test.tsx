import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SandboxSummaryCard } from './SandboxSummaryCard'

const baseCounts = {
  wouldBeDenies: 47,
  wouldBeRedactions: 12,
  wouldBePendingApprovals: 3,
}

describe('SandboxSummaryCard', () => {
  it('renders the policy name + default window label in the header', () => {
    render(<SandboxSummaryCard policyName="coding-team-sandbox" counts={baseCounts} />)

    const card = screen.getByTestId('sandbox-summary-card')
    expect(within(card).getByRole('heading', { name: /sandbox summary/i })).toBeInTheDocument()
    expect(within(card).getByText('coding-team-sandbox')).toBeInTheDocument()
    expect(within(card).getByText(/last 24h/)).toBeInTheDocument()
  })

  it('honours a custom window label when provided', () => {
    render(
      <SandboxSummaryCard
        policyName="team-alpha"
        windowLabel="last 7d"
        counts={baseCounts}
      />,
    )
    expect(screen.getByText(/last 7d/)).toBeInTheDocument()
  })

  it('renders each would-be count under the matching label', () => {
    render(<SandboxSummaryCard policyName="p" counts={baseCounts} />)

    expect(within(screen.getByTestId('would-be-denies')).getByText('47')).toBeInTheDocument()
    expect(within(screen.getByTestId('would-be-redactions')).getByText('12')).toBeInTheDocument()
    expect(within(screen.getByTestId('would-be-pending-approvals')).getByText('3')).toBeInTheDocument()
  })

  it('omits the top-rule line when topRule is undefined', () => {
    render(<SandboxSummaryCard policyName="p" counts={baseCounts} />)
    expect(screen.queryByTestId('top-rule')).not.toBeInTheDocument()
  })

  it('renders the top-rule line with id and count when provided', () => {
    render(
      <SandboxSummaryCard
        policyName="p"
        counts={baseCounts}
        topRule={{ id: 'block-bash-rm-rf', count: 31 }}
      />,
    )
    const line = screen.getByTestId('top-rule')
    expect(line).toHaveTextContent('Top matched rule')
    expect(within(line).getByText('block-bash-rm-rf')).toBeInTheDocument()
    expect(line).toHaveTextContent('31×')
  })

  it('disables every action button when no handlers are supplied', () => {
    render(<SandboxSummaryCard policyName="p" counts={baseCounts} />)

    expect(screen.getByRole('button', { name: /view all events/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /export csv/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /enable live enforcement/i })).toBeDisabled()
  })

  it('fires the respective callback when each enabled action button is clicked', async () => {
    const user = userEvent.setup()
    const onView = vi.fn()
    const onExport = vi.fn()
    const onEnforce = vi.fn()

    render(
      <SandboxSummaryCard
        policyName="p"
        counts={baseCounts}
        onViewAllEvents={onView}
        onExportCsv={onExport}
        onEnableLiveEnforcement={onEnforce}
      />,
    )

    await user.click(screen.getByRole('button', { name: /view all events/i }))
    await user.click(screen.getByRole('button', { name: /export csv/i }))
    await user.click(screen.getByRole('button', { name: /enable live enforcement/i }))

    expect(onView).toHaveBeenCalledTimes(1)
    expect(onExport).toHaveBeenCalledTimes(1)
    expect(onEnforce).toHaveBeenCalledTimes(1)
  })

  it('renders a zero count without crashing or hiding the row', () => {
    // Guard against an "empty state masquerading as nothing happened" — even
    // when every count is zero the card should render the three rows so
    // operators see that observe mode IS active for the window.
    render(
      <SandboxSummaryCard
        policyName="p"
        counts={{ wouldBeDenies: 0, wouldBeRedactions: 0, wouldBePendingApprovals: 0 }}
      />,
    )
    expect(within(screen.getByTestId('would-be-denies')).getByText('0')).toBeInTheDocument()
    expect(within(screen.getByTestId('would-be-redactions')).getByText('0')).toBeInTheDocument()
    expect(within(screen.getByTestId('would-be-pending-approvals')).getByText('0')).toBeInTheDocument()
  })
})
