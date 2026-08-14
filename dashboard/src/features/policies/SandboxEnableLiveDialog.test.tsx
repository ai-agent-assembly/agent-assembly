import type { ReactNode } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SandboxEnableLiveDialog } from './SandboxEnableLiveDialog'
import type { Policy } from './api'

const POLICY_A: Policy = {
  name: 'policy-a',
  version: '1.0.0',
  rule_count: 3,
  active: true,
  policy_yaml: 'metadata:\n  name: policy-a\nenforcement_mode: observe\nrules: []\n',
}

const POLICY_B: Policy = {
  name: 'policy-b',
  version: '0.9.0',
  rule_count: 1,
  active: true,
  policy_yaml: 'metadata:\n  name: policy-b\nenforcement_mode: observe\nrules: []\n',
}

// Simple wrapper — the component portals into document.body so no router
// or QueryClient is needed.
function Wrapper({ children }: Readonly<{ children: ReactNode }>) {
  return <>{children}</>
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('SandboxEnableLiveDialog', () => {
  it('renders the single-policy prompt when exactly one observe-mode policy exists', () => {
    render(
      <SandboxEnableLiveDialog
        open
        observePolicies={[POLICY_A]}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.getByTestId('sandbox-enable-live-single')).toHaveTextContent('policy-a')
    expect(screen.queryByTestId('sandbox-enable-live-picker')).not.toBeInTheDocument()
  })

  it('renders a <select> picker defaulted to the first policy when multiple exist', () => {
    render(
      <SandboxEnableLiveDialog
        open
        observePolicies={[POLICY_A, POLICY_B]}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
      { wrapper: Wrapper },
    )
    const picker = screen.getByTestId('sandbox-enable-live-picker') as HTMLSelectElement
    expect(picker.value).toBe('policy-a')
    expect(picker.options).toHaveLength(2)
  })

  it('renders an empty-state body when there are no observe-mode policies', () => {
    render(
      <SandboxEnableLiveDialog
        open
        observePolicies={[]}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.getByText('No observe-mode policies to enforce.')).toBeInTheDocument()
  })

  it('fires onConfirm with the picked policy and YAML rewritten to enforcement_mode: enforce', async () => {
    const onConfirm = vi.fn()
    const user = userEvent.setup()
    render(
      <SandboxEnableLiveDialog
        open
        observePolicies={[POLICY_A, POLICY_B]}
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
      { wrapper: Wrapper },
    )
    await user.selectOptions(screen.getByTestId('sandbox-enable-live-picker'), 'policy-b')
    await user.click(screen.getByText('Enable live enforcement'))

    expect(onConfirm).toHaveBeenCalledTimes(1)
    const [policy, modifiedYaml] = onConfirm.mock.calls[0]
    expect(policy.name).toBe('policy-b')
    // Modified YAML should now declare enforce, not observe.
    expect(modifiedYaml).toContain('enforcement_mode: enforce')
    expect(modifiedYaml).not.toContain('enforcement_mode: observe')
  })

  it('does not render anything when open is false', () => {
    render(
      <SandboxEnableLiveDialog
        open={false}
        observePolicies={[POLICY_A]}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.queryByTestId('sandbox-enable-live-single')).not.toBeInTheDocument()
  })

  it('disables the confirm button label while submitting is true', () => {
    render(
      <SandboxEnableLiveDialog
        open
        observePolicies={[POLICY_A]}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
        submitting
      />,
      { wrapper: Wrapper },
    )
    expect(screen.getByRole('button', { name: 'Enabling…' })).toBeInTheDocument()
  })
})
