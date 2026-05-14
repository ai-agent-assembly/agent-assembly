import { useEffect } from 'react'

interface AlertDetailDrawerProps {
  open: boolean
  onClose: () => void
  children?: React.ReactNode
}

export function AlertDetailDrawer({ open, onClose, children }: AlertDetailDrawerProps) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Alert detail"
      data-testid="alert-detail-drawer"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.35)',
        display: 'flex',
        justifyContent: 'flex-end',
        zIndex: 900,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <aside
        style={{
          width: 'min(520px, 95vw)',
          height: '100%',
          background: 'var(--surface-card)',
          boxShadow: '-10px 0 25px rgba(0, 0, 0, 0.15)',
          padding: '1.25rem',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <header
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: '1px solid var(--surface-card-border)',
            paddingBottom: '0.5rem',
          }}
        >
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Alert detail</h2>
          <button
            type="button"
            data-testid="alert-detail-drawer-close"
            aria-label="Close"
            onClick={onClose}
            style={{
              border: 'none',
              background: 'transparent',
              fontSize: '1.25rem',
              cursor: 'pointer',
              color: 'var(--text-muted)',
            }}
          >
            ✕
          </button>
        </header>
        {children}
      </aside>
    </div>
  )
}
