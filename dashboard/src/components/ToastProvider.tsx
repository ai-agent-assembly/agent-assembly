import { useState, useCallback, type ReactNode } from 'react'
import { ToastContext, type ToastVariant, type ToastMessage } from './ToastContext'

let _nextId = 0

const TOAST_TTL_MS = 4000

/** Remove the toast with `id` from a toast list (module-scope to avoid deep nesting). */
function removeToast(list: ToastMessage[], id: number): ToastMessage[] {
  return list.filter((t) => t.id !== id)
}

const TOAST_BACKGROUND: Record<ToastVariant, string> = {
  success: 'var(--status-success-solid)',
  error: 'var(--status-danger-solid)',
  info: 'var(--status-info-solid)',
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  const toast = useCallback((message: string, variant: ToastVariant = 'info') => {
    const id = _nextId++
    setToasts((prev) => [...prev, { id, message, variant }])
    setTimeout(() => setToasts((prev) => removeToast(prev, id)), TOAST_TTL_MS)
  }, [])

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div
        style={{
          position: 'fixed',
          bottom: '1rem',
          right: '1rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem',
          zIndex: 9999,
        }}
        data-testid="toast-container"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            data-testid="toast"
            data-variant={t.variant}
            style={{
              padding: '0.75rem 1rem',
              borderRadius: '0.375rem',
              background: TOAST_BACKGROUND[t.variant],
              color: 'var(--toast-text)',
              fontSize: '0.875rem',
              maxWidth: '24rem',
            }}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
