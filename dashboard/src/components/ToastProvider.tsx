import { useState, useCallback, type ReactNode } from 'react'
import { ToastContext, type ToastVariant, type ToastMessage } from './ToastContext'

let _nextId = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  const toast = useCallback((message: string, variant: ToastVariant = 'info') => {
    const id = _nextId++
    setToasts((prev) => [...prev, { id, message, variant }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 4000)
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
              background:
                t.variant === 'success' ? '#16a34a' : t.variant === 'error' ? '#dc2626' : '#2563eb',
              color: '#fff',
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
