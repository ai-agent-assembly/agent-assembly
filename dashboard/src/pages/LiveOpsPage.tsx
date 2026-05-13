import './LiveOpsPage.css'

export function LiveOpsPage() {
  return (
    <main className="live-page" data-testid="live-ops-page">
      <header className="live-page__header">
        <h1 className="live-page__title">Live Operations</h1>
        <p className="live-page__subtitle">
          Real-time governance pipeline: traffic flow, event stream, and pending approvals.
        </p>
      </header>

      <div className="live-page__grid">
        <section
          className="live-page__pane"
          aria-label="Traffic pipeline"
          data-testid="live-ops-pipeline-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">▤ traffic pipeline</h2>
          </header>
          <div className="live-page__pane-body" />
        </section>

        <section
          className="live-page__pane"
          aria-label="Event stream"
          data-testid="live-ops-stream-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">▶ tail -f · event stream</h2>
          </header>
          <div className="live-page__pane-body" />
        </section>

        <section
          className="live-page__pane"
          aria-label="Approval queue"
          data-testid="live-ops-approvals-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">⚑ approval queue</h2>
          </header>
          <div className="live-page__pane-body" />
        </section>
      </div>
    </main>
  )
}
