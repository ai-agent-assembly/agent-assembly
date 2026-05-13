import type { ScrubPattern } from './types'

export const PATTERNS: ScrubPattern[] = [
  {
    id: 'AWS_KEY',
    name: 'AWS access key ID',
    regex: 'AKIA[0-9A-Z]{16}',
    example: 'AKIAIOSFODNN7EXAMPLE',
    replace: '[REDACTED:AWS_KEY]',
    severity: 'critical',
    hits24h: 14,
    enabled: true,
  },
  {
    id: 'AWS_SECRET',
    name: 'AWS secret key',
    regex: '[A-Za-z0-9/+=]{40}',
    example: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    replace: '[REDACTED:AWS_SECRET]',
    severity: 'critical',
    hits24h: 9,
    enabled: true,
  },
  {
    id: 'OPENAI_KEY',
    name: 'OpenAI API key',
    regex: 'sk-[A-Za-z0-9]{48,}',
    example: 'sk-proj-abc123def456ghi789jkl0mnopqrs...',
    replace: '[REDACTED:OPENAI_KEY]',
    severity: 'critical',
    hits24h: 22,
    enabled: true,
  },
  {
    id: 'GH_TOKEN',
    name: 'GitHub token',
    regex: 'gh[ps]_[A-Za-z0-9]{36}',
    example: 'ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z',
    replace: '[REDACTED:GH_TOKEN]',
    severity: 'critical',
    hits24h: 6,
    enabled: true,
  },
  {
    id: 'JWT',
    name: 'JWT bearer',
    regex: 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
    example: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIi…',
    replace: '[REDACTED:JWT]',
    severity: 'high',
    hits24h: 31,
    enabled: true,
  },
  {
    id: 'SLACK_TOKEN',
    name: 'Slack webhook',
    regex: 'xox[baprs]-[A-Za-z0-9-]+',
    example: 'xoxb-12345-67890-aBcDeFgHiJk',
    replace: '[REDACTED:SLACK]',
    severity: 'high',
    hits24h: 4,
    enabled: true,
  },
  {
    id: 'EMAIL_PII',
    name: 'Email address (PII)',
    regex: '[a-z0-9._%+-]+@[a-z0-9.-]+',
    example: 'jane.doe@acme.com',
    replace: '[REDACTED:EMAIL]',
    severity: 'medium',
    hits24h: 87,
    enabled: true,
  },
  {
    id: 'CC_NUMBER',
    name: 'Credit card',
    regex: '[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}',
    example: '4111 1111 1111 1111',
    replace: '[REDACTED:CC]',
    severity: 'critical',
    hits24h: 0,
    enabled: true,
  },
  {
    id: 'SSN',
    name: 'US Social Security',
    regex: '[0-9]{3}-[0-9]{2}-[0-9]{4}',
    example: '123-45-6789',
    replace: '[REDACTED:SSN]',
    severity: 'critical',
    hits24h: 0,
    enabled: true,
  },
  {
    id: 'PRIVATE_KEY',
    name: 'PEM private key',
    regex: '-----BEGIN [A-Z ]+PRIVATE KEY-----',
    example: '-----BEGIN RSA PRIVATE KEY-----\\nMIIE…',
    replace: '[REDACTED:PEM]',
    severity: 'critical',
    hits24h: 1,
    enabled: true,
  },
  {
    id: 'INTERNAL_URL',
    name: 'Internal URL',
    regex: 'https?://[^/]*\\.acme\\.internal',
    example: 'https://billing.acme.internal/api',
    replace: '[REDACTED:INT_URL]',
    severity: 'medium',
    hits24h: 18,
    enabled: true,
  },
  {
    id: 'PHONE',
    name: 'Phone (E.164)',
    regex: '\\+?[0-9]{10,15}',
    example: '+886912345678',
    replace: '[REDACTED:PHONE]',
    severity: 'low',
    hits24h: 12,
    enabled: false,
  },
]

export const SAMPLE_PAYLOAD = `Hi team — quick note from research-bot-04 sync.

Connecting to billing.acme.internal/api with AKIAIOSFODNN7EXAMPLE
and writing back to s3://customer-pii/ as service principal.

Found one customer record:
  name:  Jane Doe
  email: jane.doe@acme.com
  phone: +886912345678
  card:  4111 1111 1111 1111

Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNlIn0.tEsT_signature
will expire at 2026-05-12T08:00Z.

Forwarding to support@external-vendor.io for follow-up.`
