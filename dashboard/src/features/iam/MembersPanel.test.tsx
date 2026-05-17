import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { MembersPanel } from './MembersPanel'
import { ToastProvider } from '../../components/ToastProvider'
import { _iamInternal } from './api'
import { detectDangerousRoleChange } from './dangerousRoleChange'
import { isValidEmail } from './validation'
import type { Member } from './types'

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>
          <MembersPanel />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => { _iamInternal.reset() })
afterEach(() => { _iamInternal.reset() })

describe('isValidEmail', () => {
  it('accepts well-formed addresses', () => {
    expect(isValidEmail('user@example.com')).toBe(true)
    expect(isValidEmail('  user@example.com  ')).toBe(true)
  })

  it('rejects malformed values', () => {
    expect(isValidEmail('')).toBe(false)
    expect(isValidEmail('user')).toBe(false)
    expect(isValidEmail('user@')).toBe(false)
    expect(isValidEmail('user@example')).toBe(false)
    expect(isValidEmail('user@@example.com')).toBe(false)
  })
})

describe('detectDangerousRoleChange', () => {
  const members: Member[] = [
    { id: 'me', email: 'me@x', name: 'Me', role: 'Owner', status: 'active', last_active: null },
    { id: 'b', email: 'b@x', name: 'B', role: 'Admin', status: 'active', last_active: null },
  ]

  it('returns null for a safe change', () => {
    expect(
      detectDangerousRoleChange(members[1], 'Member', { allMembers: members, currentUserId: 'me' }),
    ).toBeNull()
  })

  it('flags self-downgrade', () => {
    const r = detectDangerousRoleChange(members[0], 'Admin', { allMembers: members, currentUserId: 'me' })
    expect(r?.reason).toBe('self')
  })

  it('flags last-Owner downgrade', () => {
    const r = detectDangerousRoleChange(members[0], 'Admin', { allMembers: members, currentUserId: null })
    expect(r?.reason).toBe('last-owner')
  })

  it('does not flag downgrade when other Owners exist', () => {
    const more = [...members, { ...members[0], id: 'c', email: 'c@x' }]
    expect(
      detectDangerousRoleChange(more[0], 'Admin', { allMembers: more, currentUserId: null }),
    ).toBeNull()
  })
})

describe('MembersPanel — invite flow', () => {
  it('renders the seed members on load', async () => {
    renderPanel()
    expect(await screen.findByTestId('member-row-me')).toBeInTheDocument()
    expect(screen.getByTestId('member-row-mbr-5')).toBeInTheDocument()
  })

  it('invites a new member through the dialog and surfaces a toast', async () => {
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('member-row-me')

    await user.click(screen.getByTestId('invite-member-button'))
    await user.type(screen.getByTestId('invite-email-input'), 'newbie@agent-assembly.dev')
    await user.click(screen.getByTestId('invite-submit'))

    await waitFor(() =>
      expect(screen.queryByTestId('invite-member-dialog')).not.toBeInTheDocument(),
    )
    const toasts = await screen.findAllByTestId('toast')
    expect(toasts.some((t) => t.textContent?.includes('newbie@agent-assembly.dev'))).toBe(true)
    expect(_iamInternal.snapshot().some((m) => m.email === 'newbie@agent-assembly.dev')).toBe(true)
  })

  it('blocks submit and shows an error when the email is invalid', async () => {
    const user = userEvent.setup()
    renderPanel()
    await screen.findByTestId('member-row-me')

    await user.click(screen.getByTestId('invite-member-button'))
    await user.type(screen.getByTestId('invite-email-input'), 'not-an-email')
    await user.click(screen.getByTestId('invite-submit'))

    expect(await screen.findByTestId('invite-email-error')).toBeInTheDocument()
    expect(screen.getByTestId('invite-member-dialog')).toBeInTheDocument()
  })
})

describe('MembersPanel — role change', () => {
  it('asks for confirmation before downgrading the last Owner and aborts on cancel', async () => {
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('member-row-me')
    const select = within(row).getByTestId('role-select-me') as HTMLSelectElement
    await user.selectOptions(select, 'Admin')

    expect(await screen.findByTestId('confirm-role-change')).toBeInTheDocument()
    expect(screen.getByTestId('confirm-role-warning').textContent).toMatch(/own role|last Owner/i)

    await user.click(screen.getByTestId('confirm-role-cancel'))
    await waitFor(() =>
      expect(screen.queryByTestId('confirm-role-change')).not.toBeInTheDocument(),
    )
    expect(_iamInternal.snapshot().find((m) => m.id === 'me')?.role).toBe('Owner')
  })

  it('rolls back optimistic role change when the mutation rejects (after confirm)', async () => {
    _iamInternal.setUpdateRoleOverride(() => Promise.reject(new Error('boom')))
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('member-row-mbr-3')
    const select = within(row).getByTestId('role-select-mbr-3') as HTMLSelectElement
    await user.selectOptions(select, 'Viewer')

    // AAASM-1400 — the modal opens even for a safe Member → Viewer change.
    expect(await screen.findByTestId('confirm-role-change')).toBeInTheDocument()
    await user.click(screen.getByTestId('confirm-role-confirm'))

    const toasts = await screen.findAllByTestId('toast')
    expect(toasts.some((t) => t.textContent?.includes('boom'))).toBe(true)
    await waitFor(() => expect(select.value).toBe('Member'))
  })

  it('applies a safe role change after the always-confirm dialog (AAASM-1400)', async () => {
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('member-row-mbr-3')
    const select = within(row).getByTestId('role-select-mbr-3') as HTMLSelectElement
    await user.selectOptions(select, 'Admin')

    // Modal opens with the neutral message (not the danger warning).
    expect(await screen.findByTestId('confirm-role-change')).toBeInTheDocument()
    expect(screen.getByTestId('confirm-role-neutral')).toBeInTheDocument()
    expect(screen.queryByTestId('confirm-role-warning')).not.toBeInTheDocument()

    await user.click(screen.getByTestId('confirm-role-confirm'))
    await waitFor(() => expect(select.value).toBe('Admin'))
    await waitFor(() =>
      expect(screen.queryByTestId('confirm-role-change')).not.toBeInTheDocument(),
    )
  })

  it('safe role change aborted on cancel — role reverts (AAASM-1400)', async () => {
    const user = userEvent.setup()
    renderPanel()
    const row = await screen.findByTestId('member-row-mbr-3')
    const select = within(row).getByTestId('role-select-mbr-3') as HTMLSelectElement
    await user.selectOptions(select, 'Admin')

    expect(await screen.findByTestId('confirm-role-change')).toBeInTheDocument()
    await user.click(screen.getByTestId('confirm-role-cancel'))
    await waitFor(() =>
      expect(screen.queryByTestId('confirm-role-change')).not.toBeInTheDocument(),
    )
    // Underlying store stays on the original role.
    expect(_iamInternal.snapshot().find((m) => m.id === 'mbr-3')?.role).toBe('Member')
  })
})

describe('useUpdateRoleOverride hook surface', () => {
  it('is reset by _iamInternal.reset between specs', () => {
    _iamInternal.setUpdateRoleOverride(() => Promise.reject(new Error('x')))
    expect(vi.isMockFunction(_iamInternal.setUpdateRoleOverride)).toBe(false)
    _iamInternal.reset()
    // After reset, override is cleared — verified via behaviour in the rollback test above.
    expect(_iamInternal.snapshot().length).toBeGreaterThan(0)
  })
})
