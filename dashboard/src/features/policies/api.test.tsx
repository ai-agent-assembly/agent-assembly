import { render, screen, waitFor, fireEvent, act } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { PoliciesPage } from '../../pages/PoliciesPage'
import { PolicyEditorPage } from '../../pages/PolicyEditorPage'
import * as policiesApi from './api'
import type { Policy } from './api'
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'

// Monaco editor is browser-only; stub both exports used by PolicyEditorPage
vi.mock('@monaco-editor/react', () => ({
  default: ({ value, onChange }: { value: string; onChange?: (v: string) => void }) => (
    <textarea
      data-testid="monaco-editor"
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
  DiffEditor: ({ original, modified }: { original: string; modified: string }) => (
    <div data-testid="diff-editor">
      <pre data-testid="diff-original">{original}</pre>
      <pre data-testid="diff-modified">{modified}</pre>
    </div>
  ),
}))

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({
  children,
  path = '/',
  initialPath = '/',
}: {
  children: React.ReactNode
  path?: string
  initialPath?: string
}) {
  return (
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path={path} element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function mockMutation<TData, TVariables>(
  partial: Partial<UseMutationResult<TData, Error, TVariables>>,
): UseMutationResult<TData, Error, TVariables> {
  return partial as unknown as UseMutationResult<TData, Error, TVariables>
}

const MOCK_POLICY: Policy = {
  name: 'default-policy',
  version: '1.0.0',
  rule_count: 5,
  active: true,
}

const MOCK_INACTIVE: Policy = {
  name: 'old-policy',
  version: '0.9.0',
  rule_count: 3,
  active: false,
}

describe('PoliciesPage', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('renders skeleton rows while loading', () => {
    vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    render(<PoliciesPage />, { wrapper: ({ children }) => <Wrapper>{children}</Wrapper> })
    expect(screen.getAllByTestId('policy-row-skeleton')).toHaveLength(3)
  })

  it('renders a row for each policy', async () => {
    vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({
        data: [MOCK_POLICY, MOCK_INACTIVE],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<PoliciesPage />, { wrapper: ({ children }) => <Wrapper>{children}</Wrapper> })
    await waitFor(() => expect(screen.getAllByTestId('policy-row')).toHaveLength(2))
    expect(screen.getByText('default-policy')).toBeInTheDocument()
    expect(screen.getByText('old-policy')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('inactive')).toBeInTheDocument()
  })

  it('shows empty state when no policies', async () => {
    vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    render(<PoliciesPage />, { wrapper: ({ children }) => <Wrapper>{children}</Wrapper> })
    await waitFor(() => expect(screen.getByTestId('policies-empty')).toBeInTheDocument())
  })

  it('shows error banner with retry button on failure', () => {
    vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: undefined, isLoading: false, isError: true, refetch: vi.fn() }),
    )
    render(<PoliciesPage />, { wrapper: ({ children }) => <Wrapper>{children}</Wrapper> })
    expect(screen.getByTestId('policies-error')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})

const VALID_YAML = `metadata:\n  name: test-policy\n  version: "1.0.0"\nrules: []\n`
const INVALID_YAML = `\t  broken\n`

describe('PolicyEditorPage', () => {
  afterEach(() => { vi.restoreAllMocks() })

  function renderEditor(initialPath = '/policies/editor') {
    const mutateFn = vi.fn().mockResolvedValue({})
    vi.spyOn(policiesApi, 'useCreatePolicy').mockReturnValue(
      mockMutation<Policy | undefined, policiesApi.CreatePolicyRequest>({
        mutateAsync: mutateFn,
        isPending: false,
      }),
    )
    render(
      <Wrapper path="/policies/editor" initialPath={initialPath}>
        <PolicyEditorPage />
      </Wrapper>,
    )
    return { mutateFn }
  }

  it('renders editor and shows validation errors for empty-template invalid input', async () => {
    renderEditor()
    // Initial EMPTY_POLICY template is valid (has metadata: and rules:)
    // Force invalid input through the textarea
    const textarea = await screen.findByTestId('monaco-editor')
    await act(async () => {
      fireEvent.change(textarea, { target: { value: INVALID_YAML } })
      // Wait for debounce (400ms)
      await new Promise((r) => setTimeout(r, 500))
    })
    await waitFor(() => expect(screen.getByTestId('validation-errors')).toBeInTheDocument())
    expect(screen.getByTestId('validation-errors').textContent).toMatch(/tab indentation|Missing required/)
  })

  it('disables the Apply button when there are validation errors', async () => {
    renderEditor()
    const textarea = await screen.findByTestId('monaco-editor')
    await act(async () => {
      fireEvent.change(textarea, { target: { value: INVALID_YAML } })
      await new Promise((r) => setTimeout(r, 500))
    })
    await waitFor(() => {
      expect(screen.getByTestId('apply-btn')).toBeDisabled()
    })
  })

  it('enables the Apply button when YAML is valid', async () => {
    renderEditor()
    const textarea = await screen.findByTestId('monaco-editor')
    await act(async () => {
      fireEvent.change(textarea, { target: { value: VALID_YAML } })
      await new Promise((r) => setTimeout(r, 500))
    })
    await waitFor(() => {
      expect(screen.queryByTestId('validation-errors')).not.toBeInTheDocument()
      expect(screen.getByTestId('apply-btn')).not.toBeDisabled()
    })
  })

  it('shows diff editor when Diff button is clicked', async () => {
    renderEditor()
    await screen.findByTestId('monaco-editor')
    fireEvent.click(screen.getByTestId('toggle-diff-btn'))
    await waitFor(() => expect(screen.getByTestId('diff-editor')).toBeInTheDocument())
  })
})
