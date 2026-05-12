import { useContext } from 'react'
import { ToastContext, type ToastVariant } from './ToastContext'

export type { ToastVariant }

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}
