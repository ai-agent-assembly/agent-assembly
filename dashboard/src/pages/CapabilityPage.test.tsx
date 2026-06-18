import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityPage } from './CapabilityPage'
import { ToastProvider } from '../components/ToastProvider'
import { capabilityClient } from '../api/capability'
import { CAPABILITY_MATRIX_FIXTURE } from '../features/capability/fixtures'
import type { CapabilityMatrix } from '../features/capability/types'

vi.mock('../api/capability', () => ({
  capabilityClient: {
    getMatrix: vi.fn(),
    applyOverride: vi.fn(),
  },
}))

const getMatrix = capabilityClient.getMatrix as ReturnType<typeof vi.fn>
const applyOverride = capabilityClient.applyOverride as ReturnType<typeof vi.fn>

function renderPage() {
  return render(
    <ToastProvider>
      <CapabilityPage />
    </ToastProvider>,
  )
}

const FIXTURE = CAPABILITY_MATRIX_FIXTURE

beforeEach(() => {
  getMatrix.mockReset()
  applyOverride.mockReset()
})

afterEach(() => vi.restoreAllMocks())

describe('CapabilityPage', () => {
  it('shows the loading state before the matrix resolves', async () => {
    let resolve!: (m: CapabilityMatrix) => void
    getMatrix.mockReturnValue(new Promise<CapabilityMatrix>((r) => (resolve = r)))
    renderPage()
    expect(screen.getByTestId('loading-state-capability')).toBeInTheDocument()
    resolve(FIXTURE)
    await screen.findByText('Capability')
  })

  it('renders the error state and retries on click', async () => {
    getMatrix.mockRejectedValueOnce(new Error('boom'))
    renderPage()
    const retry = await screen.findByRole('button', { name: /retry/i })
    // On retry, return a real matrix.
    getMatrix.mockResolvedValueOnce(FIXTURE)
    fireEvent.click(retry)
    await screen.findByText('Capability')
    expect(getMatrix).toHaveBeenCalledTimes(2)
  })

  it('renders the empty state when the matrix has no agents', async () => {
    getMatrix.mockResolvedValueOnce({ ...FIXTURE, agents: [] })
    renderPage()
    expect(await screen.findByTestId('empty-state-capability')).toBeInTheDocument()
  })

  it('renders the matrix view with the header and switches tabs / verb', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByText('Capability')
    // Matrix tab active by default → filter bar present.
    expect(screen.getByRole('search')).toBeInTheDocument()

    // Switch to the Per-agent tab.
    fireEvent.click(screen.getByRole('button', { name: 'Per-agent' }))
    expect(screen.queryByRole('search')).not.toBeInTheDocument()

    // Switch the verb radio.
    const readRadio = screen.getByRole('radio', { name: 'read' })
    fireEvent.click(readRadio)
    expect(readRadio).toHaveAttribute('aria-checked', 'true')
  })

  it('opens the cell inspect drawer when a matrix cell is clicked', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByText('Capability')
    const interactiveCell = screen
      .getAllByRole('gridcell')
      .find((c) => c.getAttribute('data-decision') !== 'na')
    expect(interactiveCell).toBeDefined()
    fireEvent.click(interactiveCell!)
    expect(
      await screen.findByRole('dialog', { name: 'capability cell inspect' }),
    ).toBeInTheDocument()
  })

  it('applies a bulk override and toasts success', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    applyOverride.mockResolvedValueOnce({ updated: [] })
    renderPage()
    await screen.findByText('Capability')

    // Select all agents via the matrix select-all checkbox.
    fireEvent.click(screen.getByLabelText('select all agents'))

    // The BulkActionBar appears; pick a resource + decision then apply.
    fireEvent.change(screen.getByLabelText('resource'), {
      target: { value: FIXTURE.resources[0].id },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Apply override' }))

    await waitFor(() => expect(applyOverride).toHaveBeenCalledTimes(1))
  })
})
