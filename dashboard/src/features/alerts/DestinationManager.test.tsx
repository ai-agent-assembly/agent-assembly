import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DestinationManager } from './DestinationManager'
import * as api from './api'
import type { Destination } from './types'

const toastSpy = vi.fn()
vi.mock('../../components/Toast', async () => {
  const actual = await vi.importActual<typeof import('../../components/Toast')>(
    '../../components/Toast',
  )
  return { ...actual, useToast: () => ({ toast: toastSpy }) }
})

const DESTINATIONS: Destination[] = [
  {
    id: 'dest-1',
    kind: 'webhook',
    name: 'Ops webhook',
    enabled: true,
    config: { url: 'https://hooks.internal/x' },
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
  },
]

function mockQuery(partial: Record<string, unknown>) {
  return partial as unknown as ReturnType<typeof api.useDestinationsQuery>
}

function mockMutation(overrides: Record<string, unknown> = {}) {
  return {
    mutateAsync: vi.fn().mockResolvedValue(undefined),
    isPending: false,
    ...overrides,
  } as unknown as never
}

let createMut: { mutateAsync: ReturnType<typeof vi.fn>; isPending: boolean }
let testMut: { mutateAsync: ReturnType<typeof vi.fn>; isPending: boolean }
let deleteMut: { mutateAsync: ReturnType<typeof vi.fn>; isPending: boolean }

beforeEach(() => {
  toastSpy.mockClear()
  createMut = { mutateAsync: vi.fn().mockResolvedValue({}), isPending: false }
  testMut = {
    mutateAsync: vi.fn().mockResolvedValue({ connectorResponseStatus: 200 }),
    isPending: false,
  }
  deleteMut = { mutateAsync: vi.fn().mockResolvedValue(undefined), isPending: false }
  vi.spyOn(api, 'useCreateDestinationMutation').mockReturnValue(
    createMut as unknown as never,
  )
  vi.spyOn(api, 'useUpdateDestinationMutation').mockReturnValue(mockMutation())
  vi.spyOn(api, 'useDeleteDestinationMutation').mockReturnValue(
    deleteMut as unknown as never,
  )
  vi.spyOn(api, 'useTestDestinationMutation').mockReturnValue(
    testMut as unknown as never,
  )
})

afterEach(() => vi.restoreAllMocks())

function renderManager(open = true) {
  return render(<DestinationManager open={open} onClose={vi.fn()} />)
}

describe('DestinationManager', () => {
  it('renders nothing when closed', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    const { container } = renderManager(false)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the loading state', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: true, isError: false }),
    )
    renderManager()
    expect(screen.getByTestId('destination-manager-loading')).toBeInTheDocument()
  })

  it('renders the error state', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({
        data: undefined,
        isLoading: false,
        isError: true,
        error: new Error('nope'),
      }),
    )
    renderManager()
    expect(screen.getByTestId('destination-manager-error')).toHaveTextContent('nope')
  })

  it('renders the empty state when there are no destinations', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    renderManager()
    expect(screen.getByTestId('destination-manager-empty')).toBeInTheDocument()
  })

  it('renders a row per destination', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    expect(screen.getByTestId('destination-row-dest-1')).toBeInTheDocument()
    expect(screen.getByText('Ops webhook')).toBeInTheDocument()
  })

  it('rejects submit when the config JSON is invalid', async () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.change(screen.getByTestId('destination-form-config'), {
      target: { value: '{not json' },
    })
    fireEvent.click(screen.getByTestId('destination-form-submit'))
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith('Config is not valid JSON', 'error'),
    )
    expect(createMut.mutateAsync).not.toHaveBeenCalled()
  })

  it('rejects submit when the name is blank', async () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-form-submit'))
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith('Name is required', 'error'),
    )
    expect(createMut.mutateAsync).not.toHaveBeenCalled()
  })

  it('creates a new destination on submit and resets the draft', async () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.change(screen.getByTestId('destination-form-name'), {
      target: { value: 'New hook' },
    })
    fireEvent.click(screen.getByTestId('destination-form-submit'))
    await waitFor(() => expect(createMut.mutateAsync).toHaveBeenCalledTimes(1))
    expect(toastSpy).toHaveBeenCalledWith('Created destination "New hook"', 'success')
  })

  it('switches into edit mode when a row Edit button is clicked', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-edit-dest-1'))
    expect(screen.getByText('Edit destination')).toBeInTheDocument()
    expect(screen.getByTestId('destination-form-cancel-edit')).toBeInTheDocument()
    // Cancel returns to create mode.
    fireEvent.click(screen.getByTestId('destination-form-cancel-edit'))
    expect(screen.getByText('New destination')).toBeInTheDocument()
  })

  it('test-fires a destination and reports the connector status', async () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-test-dest-1'))
    await waitFor(() => expect(testMut.mutateAsync).toHaveBeenCalledTimes(1))
    expect(toastSpy).toHaveBeenCalledWith(
      'Test fired → 200 (Ops webhook)',
      'success',
    )
  })

  it('deletes a destination', async () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-delete-dest-1'))
    await waitFor(() => expect(deleteMut.mutateAsync).toHaveBeenCalledWith('dest-1'))
    expect(toastSpy).toHaveBeenCalledWith('Deleted destination "Ops webhook"', 'success')
  })

  it('surfaces a delete failure as an error toast', async () => {
    deleteMut.mutateAsync.mockRejectedValueOnce(new Error('gateway down'))
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-delete-dest-1'))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith('gateway down', 'error'))
  })

  it('updates an existing destination when submitting in edit mode', async () => {
    const updateMut = { mutateAsync: vi.fn().mockResolvedValue({}), isPending: false }
    vi.spyOn(api, 'useUpdateDestinationMutation').mockReturnValue(updateMut as unknown as never)
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-edit-dest-1'))
    fireEvent.click(screen.getByTestId('destination-form-submit'))
    await waitFor(() =>
      expect(updateMut.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'dest-1' }),
      ),
    )
    expect(toastSpy).toHaveBeenCalledWith('Updated destination "Ops webhook"', 'success')
  })

  it('surfaces a create failure as an error toast', async () => {
    createMut.mutateAsync.mockRejectedValueOnce(new Error('create boom'))
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.change(screen.getByTestId('destination-form-name'), {
      target: { value: 'New hook' },
    })
    fireEvent.click(screen.getByTestId('destination-form-submit'))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith('create boom', 'error'))
  })

  it('reports a non-2xx test fire as an error toast', async () => {
    testMut.mutateAsync.mockResolvedValueOnce({ connectorResponseStatus: 500 })
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-test-dest-1'))
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith('Test fired → 500 (Ops webhook)', 'error'),
    )
  })

  it('surfaces a test fire failure as an error toast', async () => {
    testMut.mutateAsync.mockRejectedValueOnce(new Error('connector unreachable'))
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: DESTINATIONS, isLoading: false, isError: false }),
    )
    renderManager()
    fireEvent.click(screen.getByTestId('destination-test-dest-1'))
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith('connector unreachable', 'error'),
    )
  })

  it('updates the draft kind when the kind select changes', () => {
    vi.spyOn(api, 'useDestinationsQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false }),
    )
    renderManager()
    const select = screen.getByTestId('destination-form-kind') as HTMLSelectElement
    const other = Array.from(select.options).find((o) => o.value !== select.value)
    expect(other).toBeDefined()
    fireEvent.change(select, { target: { value: other!.value } })
    expect(select.value).toBe(other!.value)
  })
})
