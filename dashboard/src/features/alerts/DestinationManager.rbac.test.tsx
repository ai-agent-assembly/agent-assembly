/**
 * Write gates on the alert-destination manager (AAASM-5180).
 *
 * "Test fire" is the one worth spelling out: it looks like a diagnostic, but it
 * makes the gateway deliver a real notification to the configured connector, so
 * it is a write in every sense that matters. Create / edit / delete are the
 * obvious three.
 *
 * Each spec asserts the mutation hook was never invoked — the request the click
 * would have issued — rather than only that the control renders disabled.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DestinationManager } from './DestinationManager'
import { GrantScopes } from '../../auth/GrantScopes'
import { WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import type { Scope } from '../../auth/AuthContext'
import * as api from './api'
import type { Destination } from './types'

const toastSpy = vi.fn()
vi.mock('../../components/Toast', async () => {
  const actual = await vi.importActual<typeof import('../../components/Toast')>(
    '../../components/Toast',
  )
  return { ...actual, useToast: () => ({ toast: toastSpy }) }
})

const DESTINATION: Destination = {
  id: 'dest-1',
  kind: 'webhook',
  name: 'Ops webhook',
  enabled: true,
  config: { url: 'https://hooks.internal/x' },
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

interface MutationStub {
  mutateAsync: ReturnType<typeof vi.fn>
  isPending: boolean
}

let createMut: MutationStub
let updateMut: MutationStub
let deleteMut: MutationStub
let testMut: MutationStub

function stub(resolved: unknown = undefined): MutationStub {
  return { mutateAsync: vi.fn().mockResolvedValue(resolved), isPending: false }
}

beforeEach(() => {
  toastSpy.mockClear()
  createMut = stub({})
  updateMut = stub({})
  deleteMut = stub()
  testMut = stub({ connectorResponseStatus: 200 })

  vi.spyOn(api, 'useDestinationsQuery').mockReturnValue({
    data: [DESTINATION],
    isLoading: false,
    isError: false,
  } as unknown as ReturnType<typeof api.useDestinationsQuery>)
  vi.spyOn(api, 'useCreateDestinationMutation').mockReturnValue(createMut as unknown as never)
  vi.spyOn(api, 'useUpdateDestinationMutation').mockReturnValue(updateMut as unknown as never)
  vi.spyOn(api, 'useDeleteDestinationMutation').mockReturnValue(deleteMut as unknown as never)
  vi.spyOn(api, 'useTestDestinationMutation').mockReturnValue(testMut as unknown as never)
})

afterEach(() => vi.restoreAllMocks())

function renderWithScopes(scopes: Scope[]) {
  return render(
    <GrantScopes scopes={scopes}>
      <DestinationManager open onClose={vi.fn()} />
    </GrantScopes>,
  )
}

/** Every mutating request this component can issue. */
function writesIssued(): number {
  return (
    createMut.mutateAsync.mock.calls.length +
    updateMut.mutateAsync.mock.calls.length +
    deleteMut.mutateAsync.mock.calls.length +
    testMut.mutateAsync.mock.calls.length
  )
}

describe('DestinationManager write gates', () => {
  it('disables every mutating control for a read-only caller', () => {
    renderWithScopes(['read'])

    for (const testId of [
      'destination-test-dest-1',
      'destination-edit-dest-1',
      'destination-delete-dest-1',
      'destination-form-submit',
    ]) {
      const control = screen.getByTestId(testId)
      expect(control).toBeDisabled()
      expect(control).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    }
  })

  it('issues no request when a read-only caller clicks every mutating control', () => {
    renderWithScopes(['read'])

    fireEvent.click(screen.getByTestId('destination-test-dest-1'))
    fireEvent.click(screen.getByTestId('destination-delete-dest-1'))
    fireEvent.change(screen.getByTestId('destination-form-name'), {
      target: { value: 'New hook' },
    })
    fireEvent.click(screen.getByTestId('destination-form-submit'))

    expect(writesIssued()).toBe(0)
  })

  it('loads nothing into the edit form for a read-only caller', () => {
    renderWithScopes(['read'])

    // Edit issues no request itself — it seeds the form that submit posts. If it
    // were left live, a read-only caller would reach a populated update draft.
    fireEvent.click(screen.getByTestId('destination-edit-dest-1'))

    expect(screen.queryByTestId('destination-form-cancel-edit')).toBeNull()
    expect(writesIssued()).toBe(0)
  })

  it('fires the connector test for a write caller, proving the path is live', async () => {
    renderWithScopes(['write'])

    expect(screen.getByTestId('destination-test-dest-1')).toBeEnabled()
    fireEvent.click(screen.getByTestId('destination-test-dest-1'))

    await waitFor(() =>
      expect(testMut.mutateAsync).toHaveBeenCalledWith({ id: 'dest-1', severity: 'LOW' }),
    )
  })

  it('deletes for a write caller, proving the path is live', async () => {
    renderWithScopes(['write'])

    fireEvent.click(screen.getByTestId('destination-delete-dest-1'))

    await waitFor(() => expect(deleteMut.mutateAsync).toHaveBeenCalledWith('dest-1'))
  })

  it('admin satisfies the write requirement', () => {
    renderWithScopes(['admin'])
    expect(screen.getByTestId('destination-delete-dest-1')).toBeEnabled()
    expect(screen.getByTestId('destination-form-submit')).toBeEnabled()
  })
})
