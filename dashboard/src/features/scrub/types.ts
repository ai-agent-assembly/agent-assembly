export type ScrubSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface ScrubPattern {
  id: string
  name: string
  regex: string
  example: string
  replace: string
  severity: ScrubSeverity
  hits24h: number
  enabled: boolean
}

export interface ScrubPlainToken {
  kind: 'plain'
  text: string
}

export interface ScrubMatchToken {
  kind: 'match'
  text: string
  pattern: ScrubPattern
}

export type ScrubToken = ScrubPlainToken | ScrubMatchToken
