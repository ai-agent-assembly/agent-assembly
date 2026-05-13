/**
 * Live Operations page — entry stub for AAASM-1282 (Dashboard PR 9).
 *
 * Renders the page header only; the real content (PipelineCanvas, row
 * stream, ApprovalPool, filters, auto-scroll, WebSocket wiring) lands
 * in follow-up subtasks of AAASM-1282.
 */
export function LiveOpsPage() {
  return (
    <main data-testid="live-ops-page" style={{ padding: '2rem', maxWidth: '60rem' }}>
      <h1 style={{ marginTop: 0 }}>Live Operations</h1>
    </main>
  )
}
