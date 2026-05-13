import type { Framework, PolicyPreset, StepMeta } from './types'

export const STEPS: ReadonlyArray<StepMeta> = [
  { id: 'framework', num: '01', label: 'pick framework' },
  { id: 'install', num: '02', label: 'install sdk' },
  { id: 'identity', num: '03', label: 'issue identity' },
  { id: 'policy', num: '04', label: 'baseline policy' },
  { id: 'enroll', num: '05', label: 'enroll agent' },
]

export const FRAMEWORKS: ReadonlyArray<Framework> = [
  {
    id: 'langchain',
    name: 'LangChain',
    glyph: '⌬',
    sub: 'python · async agents · tool calling',
    popular: true,
  },
  {
    id: 'autogen',
    name: 'AutoGen',
    glyph: '⊞',
    sub: 'multi-agent conversations · ms-research',
    popular: false,
  },
  {
    id: 'crewai',
    name: 'CrewAI',
    glyph: '◇',
    sub: 'role-based crews · sequential tasks',
    popular: false,
  },
  {
    id: 'custom',
    name: 'Custom / SDK',
    glyph: '✦',
    sub: 'plain HTTP · any runtime · BYO agent',
    popular: false,
  },
]

export const POLICY_PRESETS: ReadonlyArray<PolicyPreset> = [
  {
    id: 'default-deny',
    name: 'Default deny',
    sub: 'maximum safety · explicit allow-list',
    desc: 'Every capability is blocked unless an explicit Allow rule is added. Recommended for production. New agents start with zero capabilities.',
    blocks: [
      'all writes',
      'all external network',
      'all PII reads',
      'sandbox: log-only',
    ],
    allows: [],
    risk: 'low',
  },
  {
    id: 'read-only',
    name: 'Read-only baseline',
    sub: 'recommended · sensible defaults',
    desc: 'Allows reads on common SaaS resources (Gmail, Drive, GitHub issues). Writes, scripts, deletes, and PII fields require an explicit policy.',
    blocks: ['all writes', 'PII fields (email/phone/ssn)', 'shell.exec'],
    allows: [
      'gmail.read',
      'drive.read',
      'github.issues.read',
      'http.GET (allow-listed domains)',
    ],
    risk: 'medium',
  },
  {
    id: 'monitor-only',
    name: 'Monitor only',
    sub: 'observe first · enforce later',
    desc: "No blocking. All requests pass through but are logged and scored. Use for the first 7 days while you map your agent's actual surface area before turning enforcement on.",
    blocks: [],
    allows: ['everything (logged + scored)'],
    risk: 'high',
  },
]
