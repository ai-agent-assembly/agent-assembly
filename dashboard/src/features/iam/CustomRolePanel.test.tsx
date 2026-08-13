import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CustomRolePanel } from './CustomRolePanel'
import {
  BUILTIN_ROLE_CATALOGUE,
  IAM_CUSTOM_ROLES_COPY,
  IAM_UPSELL_EVENT,
} from './copy'

describe('CustomRolePanel', () => {
  beforeEach(() => {
    vi.spyOn(console, 'info').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the title and description copy', () => {
    render(<CustomRolePanel />)
    expect(screen.getByText(IAM_CUSTOM_ROLES_COPY.title)).toBeInTheDocument()
    expect(screen.getByText(IAM_CUSTOM_ROLES_COPY.description)).toBeInTheDocument()
  })

  it('points the upgrade CTA at the docs URL in a safe new tab', () => {
    render(<CustomRolePanel />)
    const cta = screen.getByTestId('upgrade-cta')
    expect(cta).toHaveAttribute('href', IAM_CUSTOM_ROLES_COPY.upgradeUrl)
    expect(cta).toHaveAttribute('target', '_blank')
    expect(cta).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('lists every built-in role from the catalogue', () => {
    render(<CustomRolePanel />)
    for (const role of BUILTIN_ROLE_CATALOGUE) {
      expect(screen.getByTestId(`builtin-role-${role.id}`)).toHaveTextContent(role.description)
    }
  })

  it('fires the upsell analytics event when the CTA is clicked', async () => {
    const user = userEvent.setup()
    render(<CustomRolePanel />)
    await user.click(screen.getByTestId('upgrade-cta'))
    expect(console.info).toHaveBeenCalledWith(
      `[analytics] ${IAM_UPSELL_EVENT}`,
      { source: 'custom-roles-panel' },
    )
  })
})
