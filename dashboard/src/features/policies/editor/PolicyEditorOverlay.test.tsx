import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { PolicyEditorOverlay } from './PolicyEditorOverlay'
import { ToastProvider } from '../../../components/ToastProvider'
import { defaultRule } from './constants'
import type { PolicyDraft } from './types'

function makeDraft(patch: Partial<PolicyDraft> = {}): PolicyDraft {
  return {
    id: 'pol-test',
    name: 'test-policy',
    scope: 'global',
    version: '1.0.0',
    status: 'proposed',
    rules: [defaultRule()],
    ...patch,
  }
}

function Wrapper({ children }: { children: ReactNode }) {
  return <ToastProvider>{children}</ToastProvider>
}

describe('PolicyEditorOverlay — header', () => {
  it('renders id, name, status, and version chips', () => {
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft({ status: 'active' })}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    const chips = screen.getByTestId('editor-meta-chips')
    expect(chips).toHaveTextContent('pol-test')
    expect(chips).toHaveTextContent('test-policy')
    expect(chips).toHaveTextContent('v1.0.0')
    expect(screen.getByTestId('editor-status-chip')).toHaveTextContent('active')
  })

  it('shows the "draft · unsaved" chip once a field changes', async () => {
    const user = userEvent.setup()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft()}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.queryByTestId('editor-dirty-chip')).not.toBeInTheDocument()
    await user.clear(screen.getByTestId('editor-scope-input'))
    await user.type(screen.getByTestId('editor-scope-input'), 'team:platform')
    expect(screen.getByTestId('editor-dirty-chip')).toBeInTheDocument()
  })
})

describe('PolicyEditorOverlay — draft callout', () => {
  it('renders the callout when status is "proposed"', () => {
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft({ status: 'proposed' })}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.getByTestId('editor-draft-callout')).toBeInTheDocument()
  })

  it('hides the callout when status is "active"', () => {
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft({ status: 'active' })}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.queryByTestId('editor-draft-callout')).not.toBeInTheDocument()
  })
})

describe('PolicyEditorOverlay — body', () => {
  it('renders one RuleCard per rule plus a "+ add rule" button', () => {
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft({ rules: [defaultRule(), defaultRule()] })}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.getByTestId('editor-rule-0')).toBeInTheDocument()
    expect(screen.getByTestId('editor-rule-1')).toBeInTheDocument()
    expect(screen.getByTestId('editor-add-rule')).toBeInTheDocument()
  })

  it('"+ add rule" appends a new rule card', async () => {
    const user = userEvent.setup()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft({ rules: [defaultRule()] })}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.queryByTestId('editor-rule-1')).not.toBeInTheDocument()
    await user.click(screen.getByTestId('editor-add-rule'))
    expect(screen.getByTestId('editor-rule-1')).toBeInTheDocument()
  })

  it('removes a rule card via the rule remove button', async () => {
    const user = userEvent.setup()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft({ rules: [defaultRule(), defaultRule()] })}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    await user.click(screen.getByTestId('editor-rule-0-remove'))
    expect(screen.queryByTestId('editor-rule-1')).not.toBeInTheDocument()
    expect(screen.getByTestId('editor-rule-0')).toBeInTheDocument()
  })
})

describe('PolicyEditorOverlay — footer', () => {
  it('Save is enabled when there are no validation errors', () => {
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft()}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.getByTestId('editor-save-btn')).not.toBeDisabled()
  })

  it('Save is disabled when validation errors are present', async () => {
    const user = userEvent.setup()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft()}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    // Force a validation error by removing the only verb on rule 0.
    await user.click(screen.getByTestId('editor-rule-0-verb-read'))
    expect(screen.getByTestId('editor-save-btn')).toBeDisabled()
  })

  it('Save fires onSave with the live draft when clicked', async () => {
    const user = userEvent.setup()
    const onSave = vi.fn()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft()}
        onSave={onSave}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    await user.click(screen.getByTestId('editor-save-btn'))
    expect(onSave).toHaveBeenCalledTimes(1)
    expect(onSave.mock.calls[0][0]).toMatchObject({ name: 'test-policy' })
  })

  it('Cancel fires onClose', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft()}
        onSave={() => {}}
        onClose={onClose}
      />,
      { wrapper: Wrapper },
    )
    await user.click(screen.getByTestId('editor-cancel-btn'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('Revert button appears only when the draft is dirty and resets it on click', async () => {
    const user = userEvent.setup()
    render(
      <PolicyEditorOverlay
        initialDraft={makeDraft()}
        onSave={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    )
    expect(screen.queryByTestId('editor-revert-btn')).not.toBeInTheDocument()
    await user.type(screen.getByTestId('editor-scope-input'), '!')
    expect(screen.getByTestId('editor-revert-btn')).toBeInTheDocument()
    await user.click(screen.getByTestId('editor-revert-btn'))
    expect(screen.queryByTestId('editor-revert-btn')).not.toBeInTheDocument()
    expect(screen.getByTestId('editor-scope-input')).toHaveValue('global')
  })
})
