import { useContext } from 'react'
import { ToastContext } from './ToastContext'

export type { ToastVariant } from './ToastContext'

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}
