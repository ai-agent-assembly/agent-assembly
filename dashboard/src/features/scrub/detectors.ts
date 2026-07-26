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
 * ## Why a tuple table rather than object literals
 *
 * One row per detector, positional. Twenty-eight repetitions of a keyed literal
 * is twenty-eight copies of the same six field names, which reads as
 * boilerplate and measures as duplication; the row form keeps a detector on one
 * line, so the whole catalogue can be diffed against `scanner.rs` by eye.
 *
 * ## Ordering is load-bearing
 *
 * The literal-prefix rows appear in `AC_PATTERNS` order. Aho-Corasick resolves
 * a same-position collision by lowest pattern index — the scanner comment at
 * `scanner.rs:10-12` notes `sk-ant-` must precede `sk-` or Anthropic keys are
 * misclassified as OpenAI keys — and the payload preview builds one alternation
 * in array order, where JS regex alternation is likewise leftmost-first.
 * Preserving the order is what keeps the preview's tie-breaks matching the
 * scanner's. Do not sort this table for display.
 */
import { redactionLabel, type ScrubDetector, type ScrubDetectorCategory } from './types'

/**
 * `[id, name, category, detection, previewRegex?, example?]`.
 *
 * `previewRegex` and `example` are omitted for the detectors a browser cannot
 * approximate — entropy scoring, and policy-authored literals the dashboard
 * cannot read. Those rows still belong in the catalogue: they are part of the
 * shipped set, they simply do not participate in the local preview, and the
 * preview says so rather than implying they found nothing.
 */
type DetectorRow = readonly [
  id: string,
  name: string,
  category: ScrubDetectorCategory,
  detection: string,
  previewRegex?: string,
  example?: string,
]

const PEM = (kind: string) => `literal header \`-----BEGIN ${kind}-----\``
const PREFIX = (literal: string) => `literal prefix \`${literal}\``

const ROWS: readonly DetectorRow[] = [
  // ── Aho-Corasick literal prefixes, in AC_PATTERNS index order ────────────
  ['AnthropicKey', 'Anthropic API key', 'api-key', PREFIX('sk-ant-'), 'sk-ant-[A-Za-z0-9_-]{8,}', 'sk-ant-api03-EXAMPLEEXAMPLEEXAMPLE'],
  ['OpenAiKey', 'OpenAI API key', 'api-key', `${PREFIX('sk-')} (matched after \`sk-ant-\`, which wins)`, 'sk-[A-Za-z0-9_-]{8,}', 'sk-proj-EXAMPLEEXAMPLEEXAMPLE'],
  ['AwsAccessKey', 'AWS access key ID', 'api-key', 'literal prefixes `AKIA` (long-term) and `ASIA` (STS temporary)', '(?:AKIA|ASIA)[0-9A-Z]{8,}', 'AKIAIOSFODNN7EXAMPLE'],
  ['GcpServiceAccount', 'GCP service-account JSON', 'api-key', 'literal `"type": "service_account"`, in four whitespace variants', String.raw`"type"\s*:\s*"service_account"`, '"type": "service_account"'],
  ['AzureConnectionString', 'Azure Storage connection string', 'cloud-credential', PREFIX('DefaultEndpointsProtocol='), String.raw`DefaultEndpointsProtocol=\S+`, 'DefaultEndpointsProtocol=https;AccountName=example'],
  ['GitHubPat', 'GitHub personal access token', 'auth-token', 'literal prefixes `ghp_` (classic) and `github_pat_` (fine-grained)', '(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}', 'ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE'],
  ['GitHubAppToken', 'GitHub App installation token', 'auth-token', PREFIX('ghs_'), 'ghs_[A-Za-z0-9_]{8,}', 'ghs_EXAMPLEEXAMPLEEXAMPLEEXAMPLE'],
  ['SlackBotToken', 'Slack bot token', 'auth-token', PREFIX('xoxb-'), 'xoxb-[A-Za-z0-9-]+', 'xoxb-000000-000000-EXAMPLE'],
  ['SlackUserToken', 'Slack user token', 'auth-token', PREFIX('xoxp-'), 'xoxp-[A-Za-z0-9-]+', 'xoxp-000000-000000-EXAMPLE'],
  ['SlackOAuthToken', 'Slack OAuth token', 'auth-token', PREFIX('xoxa-'), 'xoxa-[A-Za-z0-9-]+', 'xoxa-000000-000000-EXAMPLE'],
  ['PostgresUrl', 'PostgreSQL connection URI', 'database-url', PREFIX('postgres://'), String.raw`postgres://\S+`, 'postgres://user:pw@db.example/app'],
  ['MysqlUrl', 'MySQL connection URI', 'database-url', PREFIX('mysql://'), String.raw`mysql://\S+`, 'mysql://user:pw@db.example/app'],
  ['MongodbUrl', 'MongoDB connection URI', 'database-url', PREFIX('mongodb://'), String.raw`mongodb://\S+`, 'mongodb://user:pw@db.example/app'],
  ['RsaPrivateKey', 'PEM RSA private key', 'private-key', PEM('RSA PRIVATE KEY'), '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----'],
  ['EcPrivateKey', 'PEM EC private key', 'private-key', PEM('EC PRIVATE KEY'), '-----BEGIN EC PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----'],
  ['OpensshPrivateKey', 'PEM OpenSSH private key', 'private-key', PEM('OPENSSH PRIVATE KEY'), '-----BEGIN OPENSSH PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----'],
  ['PrivateKey', 'PEM PKCS#8 private key', 'private-key', PEM('PRIVATE KEY'), '-----BEGIN PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----'],
  ['PgpPrivateKey', 'PGP private key block', 'private-key', PEM('PGP PRIVATE KEY BLOCK'), '-----BEGIN PGP PRIVATE KEY BLOCK-----', '-----BEGIN PGP PRIVATE KEY BLOCK-----'],
  ['GitHubOAuthToken', 'GitHub OAuth access token', 'auth-token', PREFIX('gho_'), 'gho_[A-Za-z0-9_]{8,}', 'gho_EXAMPLEEXAMPLEEXAMPLEEXAMPLE'],
  ['GitHubUserToken', 'GitHub user-to-server token', 'auth-token', PREFIX('ghu_'), 'ghu_[A-Za-z0-9_]{8,}', 'ghu_EXAMPLEEXAMPLEEXAMPLEEXAMPLE'],
  ['GitHubRefreshToken', 'GitHub refresh token', 'auth-token', PREFIX('ghr_'), 'ghr_[A-Za-z0-9_]{8,}', 'ghr_EXAMPLEEXAMPLEEXAMPLEEXAMPLE'],
  ['SlackAppToken', 'Slack app-level token', 'auth-token', PREFIX('xapp-'), 'xapp-[A-Za-z0-9-]+', 'xapp-1-EXAMPLE-000000-EXAMPLE'],
  ['SlackRefreshToken', 'Slack refresh token', 'auth-token', PREFIX('xoxr-'), 'xoxr-[A-Za-z0-9-]+', 'xoxr-000000-000000-EXAMPLE'],

  // ── Heuristic detectors (no literal prefix) ──────────────────────────────
  // The credit-card and email rows are approximations only: a browser regex
  // cannot run the Luhn checksum, so the preview flags digit runs the gateway
  // would then accept or reject.
  ['CreditCardLuhn', 'Credit card number', 'pii', '13–19 digit run that passes the Luhn checksum', String.raw`\b(?:[0-9]{4}[ -]?){3}[0-9]{4}\b`, '4111 1111 1111 1111'],
  ['EmailAddress', 'Email address', 'pii', 'address containing `@` and a dot-separated domain', String.raw`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, 'jane.doe@acme.com'],
  ['SsnPattern', 'US Social Security number', 'pii', '`DDD-DD-DDDD` format', String.raw`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, '123-45-6789'],
  // No preview regex below: entropy is not expressible as a regex, and the
  // dashboard cannot read a policy's effective patterns (AAASM-5174 item 1).
  ['GenericHighEntropy', 'High-entropy token', 'generic', 'whitespace token of length 20–64 with Shannon entropy above 4.5 bits/char, a contiguous hex run of 64 or more, or a base64 run of 20 or more above the same gate'],

  // ── Policy-defined ───────────────────────────────────────────────────────
  ['Custom', 'Policy-defined pattern', 'policy-defined', 'literal prefixes supplied by a policy document’s `data.sensitive_patterns`, compiled alongside the built-ins'],
]

/**
 * Attach the redaction label rather than letting each row spell it out.
 *
 * The label is `format!("[REDACTED:{}]", kind.as_str())` in
 * `CredentialFinding::new`; deriving it from `id` here makes the previous
 * defect — an id and a label that disagree, e.g. `PRIVATE_KEY` labelled
 * `[REDACTED:PEM]` — unrepresentable.
 */
function toDetector([
  id,
  name,
  category,
  detection,
  previewRegex,
  example,
]: DetectorRow): ScrubDetector {
  return {
    id,
    name,
    category,
    detection,
    origin: category === 'policy-defined' ? 'policy-defined' : 'built-in',
    replace: redactionLabel(id),
    previewRegex,
    example,
  }
}

export const BUILT_IN_DETECTORS: readonly ScrubDetector[] = ROWS.map(toDetector)

/**
 * The compiled-in detectors, excluding the policy-defined `Custom` kind.
 *
 * Counted separately because "N detectors ship with the scanner" is only true
 * of these: `Custom` is a label the scanner applies to patterns an operator's
 * own policy supplies, so folding it into the shipped count would overstate
 * what the gateway brings by one.
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
