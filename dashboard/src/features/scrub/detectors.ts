/**
 * The gateway's real credential-detector catalogue (AAASM-5156).
 *
 * Transcribed from `aa-security/src/scanner.rs` — `AC_PATTERNS` / `AC_KINDS`
 * (the Aho-Corasick literal set), the `CredentialKind` enum and its doc
 * comments, and `CredentialKind::as_str()` (the `[REDACTED:<kind>]` label).
 *
 * The list it replaces was a byte-for-byte copy of the design mock's `PATTERNS`
 * array. Four of its twelve entries — `AWS_SECRET`, `JWT`, `INTERNAL_URL`,
 * `PHONE` — had **no detector in the shipped scanner at all**, so the page
 * asserted coverage that does not exist; roughly fifteen real kinds were
 * missing; and the labels it taught (`[REDACTED:PEM]`, `[REDACTED:AWS_KEY]`)
 * are labels the gateway never emits, against ADR 0015's redaction contract.
 *
 * This catalogue is still static — there is no endpoint that serves the
 * effective pattern set (AAASM-5174 item 1) — but every entry is now checkable
 * against a shipped source file. It carries **no counts and no enabled flag**:
 * those were the fabricated parts, and neither has a source.
 *
 * ## Ordering is load-bearing
 *
 * The literal-prefix entries appear in `AC_PATTERNS` order. Aho-Corasick
 * resolves a same-position collision by lowest pattern index — the scanner
 * comment at `scanner.rs:10-12` notes `sk-ant-` must precede `sk-` or Anthropic
 * keys are misclassified as OpenAI keys — and the payload preview builds one
 * alternation in array order, where JS regex alternation is likewise
 * leftmost-first. Preserving the order is what keeps the preview's tie-breaks
 * matching the scanner's. Do not sort this array for display.
 */
import { redactionLabel, type ScrubDetector } from './types'

/** Fields of a detector that are not mechanically derived. */
type DetectorSpec = Omit<ScrubDetector, 'replace' | 'origin'> & {
  readonly origin?: ScrubDetector['origin']
}

/**
 * Attach the redaction label rather than letting each entry spell it out.
 *
 * The label is `format!("[REDACTED:{}]", kind.as_str())` in
 * `CredentialFinding::new`; deriving it from `id` here makes the previous
 * defect — an id and a label that disagree, e.g. `PRIVATE_KEY` labelled
 * `[REDACTED:PEM]` — unrepresentable.
 */
function detector(spec: DetectorSpec): ScrubDetector {
  return { ...spec, origin: spec.origin ?? 'built-in', replace: redactionLabel(spec.id) }
}

export const BUILT_IN_DETECTORS: readonly ScrubDetector[] = [
  // ── Aho-Corasick literal prefixes, in AC_PATTERNS index order ────────────
  detector({
    id: 'AnthropicKey',
    name: 'Anthropic API key',
    category: 'api-key',
    detection: 'literal prefix `sk-ant-`',
    previewRegex: 'sk-ant-[A-Za-z0-9_-]{8,}',
    example: 'sk-ant-api03-EXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'OpenAiKey',
    name: 'OpenAI API key',
    category: 'api-key',
    detection: 'literal prefix `sk-` (matched after `sk-ant-`, which wins)',
    previewRegex: 'sk-[A-Za-z0-9_-]{8,}',
    example: 'sk-proj-EXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'AwsAccessKey',
    name: 'AWS access key ID',
    category: 'api-key',
    detection: 'literal prefixes `AKIA` (long-term) and `ASIA` (STS temporary)',
    previewRegex: '(?:AKIA|ASIA)[0-9A-Z]{8,}',
    example: 'AKIAIOSFODNN7EXAMPLE',
  }),
  detector({
    id: 'GcpServiceAccount',
    name: 'GCP service-account JSON',
    category: 'api-key',
    detection: 'literal `"type": "service_account"`, in four whitespace variants',
    previewRegex: String.raw`"type"\s*:\s*"service_account"`,
    example: '"type": "service_account"',
  }),
  detector({
    id: 'AzureConnectionString',
    name: 'Azure Storage connection string',
    category: 'cloud-credential',
    detection: 'literal prefix `DefaultEndpointsProtocol=`',
    previewRegex: String.raw`DefaultEndpointsProtocol=\S+`,
    example: 'DefaultEndpointsProtocol=https;AccountName=example',
  }),
  detector({
    id: 'GitHubPat',
    name: 'GitHub personal access token',
    category: 'auth-token',
    detection: 'literal prefixes `ghp_` (classic) and `github_pat_` (fine-grained)',
    previewRegex: '(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}',
    example: 'ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'GitHubAppToken',
    name: 'GitHub App installation token',
    category: 'auth-token',
    detection: 'literal prefix `ghs_`',
    previewRegex: 'ghs_[A-Za-z0-9_]{8,}',
    example: 'ghs_EXAMPLEEXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'SlackBotToken',
    name: 'Slack bot token',
    category: 'auth-token',
    detection: 'literal prefix `xoxb-`',
    previewRegex: 'xoxb-[A-Za-z0-9-]+',
    example: 'xoxb-000000-000000-EXAMPLE',
  }),
  detector({
    id: 'SlackUserToken',
    name: 'Slack user token',
    category: 'auth-token',
    detection: 'literal prefix `xoxp-`',
    previewRegex: 'xoxp-[A-Za-z0-9-]+',
    example: 'xoxp-000000-000000-EXAMPLE',
  }),
  detector({
    id: 'SlackOAuthToken',
    name: 'Slack OAuth token',
    category: 'auth-token',
    detection: 'literal prefix `xoxa-`',
    previewRegex: 'xoxa-[A-Za-z0-9-]+',
    example: 'xoxa-000000-000000-EXAMPLE',
  }),
  detector({
    id: 'PostgresUrl',
    name: 'PostgreSQL connection URI',
    category: 'database-url',
    detection: 'literal prefix `postgres://`',
    previewRegex: String.raw`postgres://\S+`,
    example: 'postgres://user:pw@db.example/app',
  }),
  detector({
    id: 'MysqlUrl',
    name: 'MySQL connection URI',
    category: 'database-url',
    detection: 'literal prefix `mysql://`',
    previewRegex: String.raw`mysql://\S+`,
    example: 'mysql://user:pw@db.example/app',
  }),
  detector({
    id: 'MongodbUrl',
    name: 'MongoDB connection URI',
    category: 'database-url',
    detection: 'literal prefix `mongodb://`',
    previewRegex: String.raw`mongodb://\S+`,
    example: 'mongodb://user:pw@db.example/app',
  }),
  detector({
    id: 'RsaPrivateKey',
    name: 'PEM RSA private key',
    category: 'private-key',
    detection: 'literal header `-----BEGIN RSA PRIVATE KEY-----`',
    previewRegex: '-----BEGIN RSA PRIVATE KEY-----',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  }),
  detector({
    id: 'EcPrivateKey',
    name: 'PEM EC private key',
    category: 'private-key',
    detection: 'literal header `-----BEGIN EC PRIVATE KEY-----`',
    previewRegex: '-----BEGIN EC PRIVATE KEY-----',
    example: '-----BEGIN EC PRIVATE KEY-----',
  }),
  detector({
    id: 'OpensshPrivateKey',
    name: 'PEM OpenSSH private key',
    category: 'private-key',
    detection: 'literal header `-----BEGIN OPENSSH PRIVATE KEY-----`',
    previewRegex: '-----BEGIN OPENSSH PRIVATE KEY-----',
    example: '-----BEGIN OPENSSH PRIVATE KEY-----',
  }),
  detector({
    id: 'PrivateKey',
    name: 'PEM PKCS#8 private key',
    category: 'private-key',
    detection: 'literal header `-----BEGIN PRIVATE KEY-----`',
    previewRegex: '-----BEGIN PRIVATE KEY-----',
    example: '-----BEGIN PRIVATE KEY-----',
  }),
  detector({
    id: 'PgpPrivateKey',
    name: 'PGP private key block',
    category: 'private-key',
    detection: 'literal header `-----BEGIN PGP PRIVATE KEY BLOCK-----`',
    previewRegex: '-----BEGIN PGP PRIVATE KEY BLOCK-----',
    example: '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  }),
  detector({
    id: 'GitHubOAuthToken',
    name: 'GitHub OAuth access token',
    category: 'auth-token',
    detection: 'literal prefix `gho_`',
    previewRegex: 'gho_[A-Za-z0-9_]{8,}',
    example: 'gho_EXAMPLEEXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'GitHubUserToken',
    name: 'GitHub user-to-server token',
    category: 'auth-token',
    detection: 'literal prefix `ghu_`',
    previewRegex: 'ghu_[A-Za-z0-9_]{8,}',
    example: 'ghu_EXAMPLEEXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'GitHubRefreshToken',
    name: 'GitHub refresh token',
    category: 'auth-token',
    detection: 'literal prefix `ghr_`',
    previewRegex: 'ghr_[A-Za-z0-9_]{8,}',
    example: 'ghr_EXAMPLEEXAMPLEEXAMPLEEXAMPLE',
  }),
  detector({
    id: 'SlackAppToken',
    name: 'Slack app-level token',
    category: 'auth-token',
    detection: 'literal prefix `xapp-`',
    previewRegex: 'xapp-[A-Za-z0-9-]+',
    example: 'xapp-1-EXAMPLE-000000-EXAMPLE',
  }),
  detector({
    id: 'SlackRefreshToken',
    name: 'Slack refresh token',
    category: 'auth-token',
    detection: 'literal prefix `xoxr-`',
    previewRegex: 'xoxr-[A-Za-z0-9-]+',
    example: 'xoxr-000000-000000-EXAMPLE',
  }),

  // ── Heuristic detectors (no literal prefix) ──────────────────────────────
  detector({
    id: 'CreditCardLuhn',
    name: 'Credit card number',
    category: 'pii',
    detection: '13–19 digit run that passes the Luhn checksum',
    // Approximation only: a browser regex cannot run the Luhn check, so the
    // preview flags digit runs the gateway would then accept or reject.
    previewRegex: String.raw`\b(?:[0-9]{4}[ -]?){3}[0-9]{4}\b`,
    example: '4111 1111 1111 1111',
  }),
  detector({
    id: 'EmailAddress',
    name: 'Email address',
    category: 'pii',
    detection: 'address containing `@` and a dot-separated domain',
    previewRegex: String.raw`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`,
    example: 'jane.doe@acme.com',
  }),
  detector({
    id: 'SsnPattern',
    name: 'US Social Security number',
    category: 'pii',
    detection: '`DDD-DD-DDDD` format',
    previewRegex: String.raw`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`,
    example: '123-45-6789',
  }),
  detector({
    id: 'GenericHighEntropy',
    name: 'High-entropy token',
    category: 'generic',
    detection:
      'whitespace token of length 20–64 with Shannon entropy above 4.5 bits/char, ' +
      'a contiguous hex run of 64 or more, or a base64 run of 20 or more above the same gate',
    // No previewRegex: entropy is not expressible as a regex, so the local
    // preview cannot stand in for this detector and must not pretend to.
  }),

  // ── Policy-defined ───────────────────────────────────────────────────────
  detector({
    id: 'Custom',
    name: 'Policy-defined pattern',
    category: 'policy-defined',
    origin: 'policy-defined',
    detection:
      'literal prefixes supplied by a policy document’s `data.sensitive_patterns`, ' +
      'compiled alongside the built-ins',
    // No previewRegex: the dashboard cannot read the effective policy patterns
    // (AAASM-5174 item 1), so it has nothing to approximate.
  }),
] as const

/**
 * The compiled-in detectors, excluding the policy-defined `Custom` kind.
 *
 * Counted separately because "N detectors ship with the scanner" is only true
 * of these: `Custom` is a label the scanner applies to patterns an operator's
 * own policy supplies, so folding it into the shipped count would overstate what
 * the gateway brings by one.
 */
export const COMPILED_IN_DETECTORS: readonly ScrubDetector[] = BUILT_IN_DETECTORS.filter(
  (d) => d.origin === 'built-in',
)

/** Detectors the in-page preview can approximate, in scanner-collision order. */
export const PREVIEWABLE_DETECTORS: readonly ScrubDetector[] = BUILT_IN_DETECTORS.filter(
  (d) => d.previewRegex !== undefined,
)

/** Detectors that ship in the scanner but cannot be previewed in the browser. */
export const UNPREVIEWABLE_DETECTORS: readonly ScrubDetector[] = BUILT_IN_DETECTORS.filter(
  (d) => d.previewRegex === undefined,
)
