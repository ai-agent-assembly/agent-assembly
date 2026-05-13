import { Link, useSearchParams } from 'react-router-dom'
import { MembersPanel } from '../features/iam/MembersPanel'
import { IAM_DEFAULT_TAB, IAM_TAB_KEYS, IAM_TAB_LABELS, parseIamTab, type IamTabKey } from '../features/iam/tabs'
import './IdentityPage.css'

function TabPlaceholder({ tab }: { tab: IamTabKey }) {
  return (
    <section className="iam-tab-panel" data-testid={`iam-panel-${tab}`}>
      <h2>{IAM_TAB_LABELS[tab]}</h2>
      <p className="iam-tab-panel__placeholder">
        Content for the {IAM_TAB_LABELS[tab]} tab lands in a follow-up Sub-task.
      </p>
    </section>
  )
}

function ActiveTabContent({ tab }: { tab: IamTabKey }) {
  if (tab === 'members') return <MembersPanel />
  return <TabPlaceholder tab={tab} />
}

export function IdentityPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = parseIamTab(searchParams)

  const selectTab = (tab: IamTabKey) => {
    const next = new URLSearchParams(searchParams)
    if (tab === IAM_DEFAULT_TAB) {
      next.delete('tab')
    } else {
      next.set('tab', tab)
    }
    setSearchParams(next, { replace: true })
  }

  return (
    <main className="iam-page" data-testid="identity-page">
      <header className="iam-page__header">
        <h1>Identity &amp; Access</h1>
        <Link
          to="/audit"
          className="iam-page__audit-link"
          data-testid="iam-audit-link"
        >
          View full audit log →
        </Link>
      </header>

      <div className="iam-page__tabs" role="tablist" data-testid="iam-tabs">
        {IAM_TAB_KEYS.map((tab) => (
          <button
            key={tab}
            type="button"
            role="tab"
            aria-selected={activeTab === tab}
            data-testid={`iam-tab-${tab}`}
            className={`iam-page__tab${activeTab === tab ? ' iam-page__tab--active' : ''}`}
            onClick={() => selectTab(tab)}
          >
            {IAM_TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      <ActiveTabContent tab={activeTab} />
    </main>
  )
}
