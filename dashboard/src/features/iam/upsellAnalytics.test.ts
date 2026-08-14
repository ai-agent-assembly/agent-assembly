import { fireUpsellClicked } from './upsellAnalytics'
import { IAM_UPSELL_EVENT } from './copy'

describe('fireUpsellClicked', () => {
  beforeEach(() => {
    vi.spyOn(console, 'info').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns the upsell event name', () => {
    expect(fireUpsellClicked()).toBe(IAM_UPSELL_EVENT)
  })

  it('logs the event with the default source', () => {
    fireUpsellClicked()
    expect(console.info).toHaveBeenCalledWith(
      `[analytics] ${IAM_UPSELL_EVENT}`,
      { source: 'custom-roles-panel' },
    )
  })

  it('forwards a custom source in the analytics payload', () => {
    const result = fireUpsellClicked('settings-banner')
    expect(result).toBe(IAM_UPSELL_EVENT)
    expect(console.info).toHaveBeenCalledWith(
      `[analytics] ${IAM_UPSELL_EVENT}`,
      { source: 'settings-banner' },
    )
  })
})
