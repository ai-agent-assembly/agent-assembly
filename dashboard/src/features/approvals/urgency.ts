export type Urgency = 'high' | 'medium' | 'low'

const ONE_HOUR_MS = 60 * 60 * 1000
const SIX_HOURS_MS = 6 * ONE_HOUR_MS

export function getUrgency(createdAt: string, now: number = Date.now()): Urgency {
  const ageMs = now - new Date(createdAt).getTime()
  if (ageMs < ONE_HOUR_MS) return 'high'
  if (ageMs < SIX_HOURS_MS) return 'medium'
  return 'low'
}

// Countdown helpers — time-remaining-until-expiry. Distinct from `getUrgency`
// (age-since-creation): the parent AAASM-1478 spec reuses the red/orange/gray
// visual tiers but inverts the meaning (low remaining → high severity).

export type CountdownTier = Urgency

const ONE_MINUTE_MS = 60 * 1000
const FIVE_MINUTES_MS = 5 * ONE_MINUTE_MS

export function getRemainingMs(expiresAt: string, now: number = Date.now()): number {
  const target = new Date(expiresAt).getTime()
  if (Number.isNaN(target)) return 0
  return Math.max(0, target - now)
}

export function getCountdownTier(remainingMs: number): CountdownTier {
  if (remainingMs < ONE_MINUTE_MS) return 'high'
  if (remainingMs < FIVE_MINUTES_MS) return 'medium'
  return 'low'
}

export function formatCountdown(remainingMs: number): string {
  const totalSecs = Math.max(0, Math.floor(remainingMs / 1000))
  if (totalSecs < ONE_HOUR_MS / 1000) {
    const m = Math.floor(totalSecs / 60)
    const s = totalSecs % 60
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  }
  const h = Math.floor(totalSecs / 3600)
  const m = Math.floor((totalSecs % 3600) / 60)
  return `${h}h ${m}m`
}
