export type Urgency = 'high' | 'medium' | 'low'

const ONE_HOUR_MS = 60 * 60 * 1000
const SIX_HOURS_MS = 6 * ONE_HOUR_MS

export function getUrgency(createdAt: string, now: number = Date.now()): Urgency {
  const ageMs = now - new Date(createdAt).getTime()
  if (ageMs < ONE_HOUR_MS) return 'high'
  if (ageMs < SIX_HOURS_MS) return 'medium'
  return 'low'
}
