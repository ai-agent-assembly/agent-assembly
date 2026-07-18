import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { Theme } from '../../theme/useTheme'
import { RuleYamlViewer } from './RuleYamlViewer'

// Mock @monaco-editor/react so the test stays fast and deterministic:
// the real Editor pulls Monaco from a CDN and won't render in jsdom.
// The mock captures all props on a data-* attribute string so the
// assertions below can read them back synchronously.
vi.mock('@monaco-editor/react', () => ({
  __esModule: true,
  default: (props: Record<string, unknown>) => (
    <div
      data-testid="monaco-editor-mock"
      data-language={props.language as string}
      data-theme={props.theme as string}
      data-height={String(props.height)}
      data-options={JSON.stringify(props.options)}
    >
      {(props.value as string) ?? ''}
    </div>
  ),
}))

// Mock useTheme so each test can drive the active app theme and assert
// that the editor's Monaco theme follows it (AAASM-3507).
let mockTheme: Theme = 'dark'
vi.mock('../../theme/useTheme', () => ({
  useTheme: () => ({ theme: mockTheme, setTheme: vi.fn(), toggleTheme: vi.fn() }),
}))

beforeEach(() => {
  mockTheme = 'dark'
})

const YAML_SAMPLE = `name: "Budget guardrail"
metric: budget_spent_pct
operator: ">"
threshold: 90
severity: CRITICAL
`

describe('RuleYamlViewer', () => {
  it('renders the alert-detail-rule-yaml wrapper around Monaco', async () => {
    render(<RuleYamlViewer yaml={YAML_SAMPLE} />)

    // Wrapper is rendered synchronously — keeps the existing e2e selector working.
    const wrapper = screen.getByTestId('alert-detail-rule-yaml')
    expect(wrapper).toBeInTheDocument()

    // The lazy-loaded Editor resolves via the vi.mock above; wait for it.
    const editor = await screen.findByTestId('monaco-editor-mock')
    expect(wrapper.contains(editor)).toBe(true)
  })

  it('passes the YAML body verbatim to the Monaco Editor', async () => {
    render(<RuleYamlViewer yaml={YAML_SAMPLE} />)
    const editor = await screen.findByTestId('monaco-editor-mock')
    expect(editor.textContent).toBe(YAML_SAMPLE)
  })

  it('configures Monaco for read-only YAML rendering at 200px height', async () => {
    render(<RuleYamlViewer yaml={YAML_SAMPLE} />)
    const editor = await screen.findByTestId('monaco-editor-mock')

    expect(editor).toHaveAttribute('data-language', 'yaml')
    expect(editor).toHaveAttribute('data-height', '200')

    const options = JSON.parse(editor.dataset.options ?? '{}') as Record<string, unknown>
    // Read-only contract — locked in to prevent any future regression that
    // would let an alert-rule snapshot get edited from the drawer.
    expect(options.readOnly).toBe(true)
    expect(options.domReadOnly).toBe(true)
    // Minimap off keeps the drawer's 200px height usable.
    expect((options.minimap as { enabled: boolean }).enabled).toBe(false)
    expect(options.scrollBeyondLastLine).toBe(false)
    expect(options.lineNumbers).toBe('off')
    expect(options.folding).toBe(false)
    expect(options.wordWrap).toBe('on')
  })

  it("uses Monaco's light theme 'vs' when the app theme is light", async () => {
    mockTheme = 'light'
    render(<RuleYamlViewer yaml={YAML_SAMPLE} />)
    const editor = await screen.findByTestId('monaco-editor-mock')
    expect(editor).toHaveAttribute('data-theme', 'vs')
  })

  it("uses Monaco's dark theme 'vs-dark' when the app theme is dark", async () => {
    mockTheme = 'dark'
    render(<RuleYamlViewer yaml={YAML_SAMPLE} />)
    const editor = await screen.findByTestId('monaco-editor-mock')
    expect(editor).toHaveAttribute('data-theme', 'vs-dark')
  })
})
