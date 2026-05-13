import { useState } from 'react'
import { IAM_DEFAULT_TAB, IAM_TAB_KEYS, IAM_TAB_LABELS, type IamTabKey } from '../features/iam/tabs'
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

export function IdentityPage() {
  const [activeTab, setActiveTab] = useState<IamTabKey>(IAM_DEFAULT_TAB)

  return (
    <main className="iam-page" data-testid="identity-page">
      <header className="iam-page__header">
        <h1>Identity &amp; Access</h1>
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
            onClick={() => setActiveTab(tab)}
          >
            {IAM_TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      <TabPlaceholder tab={activeTab} />
    </main>
  )
}
