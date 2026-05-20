import { useEffect, useRef, useState } from 'react'
import { formatCountdown, getCountdownTier, getRemainingMs } from './urgency'

const TICK_FAST_MS = 1_000
const TICK_SLOW_MS = 10_000
const FAST_THRESHOLD_MS = 60_000

const TIER_COLOR: Record<ReturnType<typeof getCountdownTier>, string> = {
  high: 'var(--danger)',
  medium: 'var(--warn)',
  low: 'var(--ink-3)',
}

interface ApprovalCountdownProps {
  expiresAt: string
  onExpire?: () => void
}

export function ApprovalCountdown({ expiresAt, onExpire }: ApprovalCountdownProps) {
  const [now, setNow] = useState(() => Date.now())
  const firedRef = useRef(false)
  const remainingMs = getRemainingMs(expiresAt, now)

  useEffect(() => {
    firedRef.current = false
  }, [expiresAt])

  useEffect(() => {
    if (remainingMs > 0) return
    if (firedRef.current) return
    firedRef.current = true
    onExpire?.()
  }, [remainingMs, onExpire])

  useEffect(() => {
    if (remainingMs === 0) return
    const period = remainingMs < FAST_THRESHOLD_MS ? TICK_FAST_MS : TICK_SLOW_MS
    const timer = setTimeout(() => setNow(Date.now()), period)
    return () => clearTimeout(timer)
  }, [remainingMs])

  const tier = getCountdownTier(remainingMs)
  return (
    <span
      data-testid="approval-countdown"
      data-tier={tier}
      style={{ color: TIER_COLOR[tier], fontVariantNumeric: 'tabular-nums' }}
    >
      {formatCountdown(remainingMs)}
    </span>
  )
}
