/* ============================================================
   Sample data for hi-fi prototype
   over-permissioned narrative: agent "research-bot-04"
   ============================================================ */

const RESOURCES = [
  { id: 'gmail',     name: 'Gmail',           group: 'comm',  paths: ['gmail/*', 'gmail/labels/INBOX/*', 'gmail/labels/INBOX/read', 'gmail/send'] },
  { id: 'gdrive',    name: 'Google Drive',    group: 'files', paths: ['gdrive/*', 'gdrive/shared/*', 'gdrive/personal/*'] },
  { id: 's3',        name: 'AWS S3',          group: 'files', paths: ['s3://*', 's3://reports/*', 's3://customer-pii/*'] },
  { id: 'pg',        name: 'Postgres',        group: 'data',  paths: ['pg.public.*', 'pg.public.users', 'pg.public.orders', 'pg.public.audit_log'] },
  { id: 'shell',     name: 'Shell exec',      group: 'infra', paths: ['shell:*'] },
  { id: 'http',      name: 'HTTP egress',     group: 'infra', paths: ['http://*', 'https://*'] },
  { id: 'github',    name: 'GitHub',          group: 'code',  paths: ['github.com/acme/*', 'github.com/acme/infra/*'] },
  { id: 'slack',     name: 'Slack',           group: 'comm',  paths: ['slack/channels/*', 'slack/dm/*'] },
];

// effective decision per (agent, resource): allow | narrow | approval | deny | na
// flags: red dot if recent incident or sus
const AGENTS = [
  {
    id: 'research-bot-04',
    name: 'research-bot-04',
    framework: 'LangChain',
    owner: 'data-platform',
    trust: 42,
    mode: 'enforce',
    status: 'active',
    blocked24h: 87,
    scrubbed24h: 12,
    lastSeen: '2m ago',
    flagged: true,
    note: 'over-permissioned · 6 resources still allow, 4 narrowed, 0 deny',
    caps: {
      gmail:  { read: 'allow',    write: 'allow',    delete: 'allow',    exec: 'na',       flag: true },
      gdrive: { read: 'allow',    write: 'narrow',   delete: 'allow',    exec: 'na',       flag: true },
      s3:     { read: 'allow',    write: 'allow',    delete: 'approval', exec: 'na',       flag: true },
      pg:     { read: 'allow',    write: 'approval', delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'allow',    flag: true },
      http:   { read: 'allow',    write: 'allow',    delete: 'na',       exec: 'na',       flag: true },
      github: { read: 'allow',    write: 'narrow',   delete: 'deny',     exec: 'na' },
      slack:  { read: 'allow',    write: 'narrow',   delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'support-triage',
    name: 'support-triage',
    framework: 'CrewAI',
    owner: 'cx-tools',
    trust: 78,
    mode: 'enforce',
    status: 'active',
    blocked24h: 14,
    scrubbed24h: 28,
    lastSeen: '12s ago',
    caps: {
      gmail:  { read: 'allow',    write: 'narrow',   delete: 'deny',     exec: 'na' },
      gdrive: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      s3:     { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      pg:     { read: 'narrow',   write: 'approval', delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'deny' },
      http:   { read: 'narrow',   write: 'narrow',   delete: 'na',       exec: 'na' },
      github: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      slack:  { read: 'allow',    write: 'narrow',   delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'infra-ops-bot',
    name: 'infra-ops-bot',
    framework: 'AutoGen',
    owner: 'platform',
    trust: 88,
    mode: 'enforce',
    status: 'active',
    blocked24h: 6,
    scrubbed24h: 0,
    lastSeen: '1m ago',
    caps: {
      gmail:  { read: 'deny',     write: 'deny',     delete: 'deny',     exec: 'na' },
      gdrive: { read: 'deny',     write: 'deny',     delete: 'deny',     exec: 'na' },
      s3:     { read: 'narrow',   write: 'narrow',   delete: 'approval', exec: 'na' },
      pg:     { read: 'narrow',   write: 'narrow',   delete: 'approval', exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'narrow' },
      http:   { read: 'allow',    write: 'narrow',   delete: 'na',       exec: 'na' },
      github: { read: 'allow',    write: 'narrow',   delete: 'approval', exec: 'na' },
      slack:  { read: 'narrow',   write: 'approval', delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'analytics-runner',
    name: 'analytics-runner',
    framework: 'LangChain',
    owner: 'analytics',
    trust: 71,
    mode: 'enforce',
    status: 'active',
    blocked24h: 22,
    scrubbed24h: 45,
    lastSeen: '4s ago',
    caps: {
      gmail:  { read: 'deny',     write: 'deny',     delete: 'deny',     exec: 'na' },
      gdrive: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      s3:     { read: 'allow',    write: 'narrow',   delete: 'deny',     exec: 'na' },
      pg:     { read: 'allow',    write: 'narrow',   delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'deny' },
      http:   { read: 'narrow',   write: 'deny',     delete: 'na',       exec: 'na' },
      github: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      slack:  { read: 'narrow',   write: 'deny',     delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'sales-outreach-v2',
    name: 'sales-outreach-v2',
    framework: 'LangGraph',
    owner: 'rev-ops',
    trust: 64,
    mode: 'shadow',
    status: 'active',
    blocked24h: 0,
    scrubbed24h: 31,
    lastSeen: '20s ago',
    caps: {
      gmail:  { read: 'allow',    write: 'approval', delete: 'deny',     exec: 'na' },
      gdrive: { read: 'narrow',   write: 'narrow',   delete: 'deny',     exec: 'na' },
      s3:     { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      pg:     { read: 'narrow',   write: 'approval', delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'deny' },
      http:   { read: 'narrow',   write: 'narrow',   delete: 'na',       exec: 'na' },
      github: { read: 'deny',     write: 'deny',     delete: 'deny',     exec: 'na' },
      slack:  { read: 'allow',    write: 'narrow',   delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'docs-summarizer',
    name: 'docs-summarizer',
    framework: 'LlamaIndex',
    owner: 'knowledge',
    trust: 92,
    mode: 'enforce',
    status: 'active',
    blocked24h: 1,
    scrubbed24h: 8,
    lastSeen: '8s ago',
    caps: {
      gmail:  { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      gdrive: { read: 'allow',    write: 'deny',     delete: 'deny',     exec: 'na' },
      s3:     { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      pg:     { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'deny' },
      http:   { read: 'narrow',   write: 'deny',     delete: 'na',       exec: 'na' },
      github: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      slack:  { read: 'deny',     write: 'deny',     delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'incident-responder',
    name: 'incident-responder',
    framework: 'AutoGen',
    owner: 'sre',
    trust: 81,
    mode: 'enforce',
    status: 'active',
    blocked24h: 3,
    scrubbed24h: 2,
    lastSeen: '5m ago',
    caps: {
      gmail:  { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      gdrive: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      s3:     { read: 'narrow',   write: 'narrow',   delete: 'deny',     exec: 'na' },
      pg:     { read: 'narrow',   write: 'approval', delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'narrow' },
      http:   { read: 'allow',    write: 'narrow',   delete: 'na',       exec: 'na' },
      github: { read: 'allow',    write: 'narrow',   delete: 'deny',     exec: 'na' },
      slack:  { read: 'allow',    write: 'narrow',   delete: 'na',       exec: 'na' },
    },
  },
  {
    id: 'finance-bot',
    name: 'finance-bot',
    framework: 'CrewAI',
    owner: 'finance',
    trust: 55,
    mode: 'enforce',
    status: 'suspended',
    blocked24h: 0,
    scrubbed24h: 0,
    lastSeen: '2h ago',
    flagged: true,
    note: 'suspended after attempted cross-org S3 access',
    caps: {
      gmail:  { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      gdrive: { read: 'narrow',   write: 'deny',     delete: 'deny',     exec: 'na' },
      s3:     { read: 'deny',     write: 'deny',     delete: 'deny',     exec: 'na', flag: true },
      pg:     { read: 'narrow',   write: 'approval', delete: 'deny',     exec: 'na' },
      shell:  { read: 'na',       write: 'na',       delete: 'na',       exec: 'deny' },
      http:   { read: 'narrow',   write: 'deny',     delete: 'na',       exec: 'na' },
      github: { read: 'deny',     write: 'deny',     delete: 'deny',     exec: 'na' },
      slack:  { read: 'narrow',   write: 'deny',     delete: 'na',       exec: 'na' },
    },
  },
];

// Policies — what produces the narrowing
const POLICIES = [
  {
    id: 'P-014',
    name: 'PII-bearing tables require approval',
    scope: 'pg.public.users, pg.public.orders',
    status: 'active',
    version: 'v3.4.1',
    hits24h: 142,
    affects: ['research-bot-04', 'support-triage', 'sales-outreach-v2', 'docs-summarizer'],
    rules: [
      { resource: 'pg', verb: ['write', 'delete'], action: 'approval', condition: 'table contains PII columns' },
    ],
  },
  {
    id: 'P-021',
    name: 'No outbound email without scrub',
    scope: 'gmail/send · all agents',
    status: 'active',
    version: 'v3.4.1',
    hits24h: 89,
    affects: ['research-bot-04', 'support-triage', 'sales-outreach-v2'],
    rules: [
      { resource: 'gmail', verb: ['write'], action: 'scrub-then-allow', condition: 'always' },
      { resource: 'gmail', verb: ['write'], action: 'approval', condition: 'recipient not in @acme.com' },
    ],
  },
  {
    id: 'P-035',
    name: 'Customer-PII bucket lockdown',
    scope: 's3://customer-pii/*',
    status: 'active',
    version: 'v3.3.0',
    hits24h: 7,
    affects: ['research-bot-04', 'analytics-runner', 'finance-bot'],
    rules: [
      { resource: 's3', verb: ['read', 'write', 'delete'], action: 'approval', condition: 'path matches customer-pii/*' },
    ],
  },
  {
    id: 'P-042',
    name: 'Shell exec — break-glass only',
    scope: 'shell:* · all agents',
    status: 'active',
    version: 'v3.4.1',
    hits24h: 4,
    affects: ['research-bot-04', 'infra-ops-bot', 'incident-responder'],
    rules: [
      { resource: 'shell', verb: ['exec'], action: 'approval', condition: 'always · 2-person review' },
    ],
  },
  {
    id: 'P-058',
    name: 'GitHub write to infra repo · approval',
    scope: 'github.com/acme/infra/*',
    status: 'active',
    version: 'v3.4.1',
    hits24h: 12,
    affects: ['infra-ops-bot', 'incident-responder'],
    rules: [
      { resource: 'github', verb: ['write'], action: 'approval', condition: 'repo matches acme/infra/*' },
    ],
  },
  {
    id: 'P-066',
    name: '⚠ proposed: research-bot-04 narrowing',
    scope: 'agent: research-bot-04',
    status: 'proposed',
    version: 'draft',
    hits24h: 0,
    affects: ['research-bot-04'],
    rules: [
      { resource: 'gmail', verb: ['write', 'delete'], action: 'deny', condition: 'always' },
      { resource: 's3',    verb: ['write'], action: 'narrow', condition: 'path in [s3://reports/*]' },
      { resource: 'http',  verb: ['write'], action: 'narrow', condition: 'host in allowlist' },
      { resource: 'shell', verb: ['exec'], action: 'deny', condition: 'always' },
    ],
  },
];

// Sample events for simulate replay
const SAMPLE_CALLS = [
  { ts: '14:02:11', agent: 'research-bot-04', verb: 'write', resource: 'gmail/send', detail: 'to: ext@vendor.com', currentDecision: 'allow', proposedDecision: 'deny', changeType: 'newly-blocked' },
  { ts: '14:01:47', agent: 'research-bot-04', verb: 'exec',  resource: 'shell:rm -rf /tmp/*', detail: 'shell command', currentDecision: 'allow', proposedDecision: 'deny', changeType: 'newly-blocked' },
  { ts: '13:58:22', agent: 'research-bot-04', verb: 'write', resource: 's3://reports/q3.csv', detail: 'CSV upload, 4MB', currentDecision: 'allow', proposedDecision: 'narrow', changeType: 'narrowed' },
  { ts: '13:54:09', agent: 'research-bot-04', verb: 'read',  resource: 'gdrive/personal/*', detail: 'list files', currentDecision: 'allow', proposedDecision: 'allow', changeType: 'unchanged' },
  { ts: '13:51:33', agent: 'research-bot-04', verb: 'write', resource: 'http://api.foo.io/log', detail: 'POST 2KB', currentDecision: 'allow', proposedDecision: 'narrow', changeType: 'narrowed' },
  { ts: '13:48:10', agent: 'research-bot-04', verb: 'delete', resource: 'gmail/labels/INBOX/msg-9941', detail: 'delete email', currentDecision: 'allow', proposedDecision: 'deny', changeType: 'newly-blocked' },
  { ts: '13:42:58', agent: 'research-bot-04', verb: 'write', resource: 'gmail/send', detail: 'to: alice@acme.com', currentDecision: 'allow', proposedDecision: 'deny', changeType: 'false-positive', fpReason: 'internal recipient — should still allow' },
  { ts: '13:40:12', agent: 'research-bot-04', verb: 'exec',  resource: 'shell:python report.py', detail: 'scheduled report job', currentDecision: 'allow', proposedDecision: 'deny', changeType: 'false-positive', fpReason: 'legit cron job — needs exception' },
  { ts: '13:35:44', agent: 'research-bot-04', verb: 'read',  resource: 'pg.public.orders', detail: 'SELECT count(*)', currentDecision: 'allow', proposedDecision: 'allow', changeType: 'unchanged' },
  { ts: '13:31:02', agent: 'research-bot-04', verb: 'write', resource: 's3://customer-pii/seg.csv', detail: 'attempted upload', currentDecision: 'approval', proposedDecision: 'deny', changeType: 'tightened' },
];

// Verb / decision metadata
const VERBS = ['read', 'write', 'delete', 'exec'];
const DECISIONS = {
  allow:    { label: 'allow',    color: '--ink-3',   bg: '--paper-2' },
  narrow:   { label: 'narrow',   color: '--warn',    bg: '--warn-bg' },
  approval: { label: 'approval', color: '--info',    bg: '--info-bg' },
  deny:     { label: 'deny',     color: '--danger',  bg: '--danger-bg' },
  na:       { label: 'n/a',      color: '--ink-5',   bg: '--paper-3' },
};

// Pending approvals — appears in top-bar bell drawer + Live Ops queue
const APPROVALS = [
  {
    id: 'AP-9412',
    agent: 'research-bot-04',
    verb: 'write',
    resource: 's3://customer-pii/segment-2026-q2.csv',
    detail: 'CSV upload · 4.2 MB · contains 12k email addresses',
    layer: 'L2',
    policy: 'P-035',
    requestedBy: 'agent autonomous',
    age: '12s',
    urgent: true,
    reason: 'PII bucket lockdown',
    trace: 'tr-9a4f',
  },
  {
    id: 'AP-9408',
    agent: 'finance-bot',
    verb: 'exec',
    resource: 'shell:psql -c "DROP TABLE staging_q1"',
    detail: 'shell command · destructive',
    layer: 'L2',
    policy: 'P-042',
    requestedBy: 'human via Slack',
    age: '34s',
    urgent: true,
    reason: 'Shell exec break-glass',
    trace: 'tr-9a4d',
  },
  {
    id: 'AP-9402',
    agent: 'sales-outreach-v2',
    verb: 'write',
    resource: 'gmail/send',
    detail: 'to: prospect@unknown-domain.io · 1 recipient · 4 KB',
    layer: 'L2',
    policy: 'P-021',
    requestedBy: 'agent autonomous',
    age: '1m',
    urgent: false,
    reason: 'External recipient',
    trace: 'tr-9a44',
  },
  {
    id: 'AP-9398',
    agent: 'infra-ops-bot',
    verb: 'write',
    resource: 'github.com/acme/infra/terraform/prod.tf',
    detail: 'commit · 142 lines · Terraform plan attached',
    layer: 'L2',
    policy: 'P-058',
    requestedBy: 'agent autonomous',
    age: '2m',
    urgent: false,
    reason: 'Infra repo write',
    trace: 'tr-9a3e',
  },
  {
    id: 'AP-9395',
    agent: 'incident-responder',
    verb: 'exec',
    resource: 'shell:kubectl rollout restart deploy/api',
    detail: 'rollout restart · prod cluster',
    layer: 'L2',
    policy: 'P-042',
    requestedBy: 'agent autonomous',
    age: '3m',
    urgent: false,
    reason: 'Shell exec',
    trace: 'tr-9a3a',
  },
  {
    id: 'AP-9391',
    agent: 'analytics-runner',
    verb: 'read',
    resource: 's3://customer-pii/raw/*',
    detail: 'list + read · estimated 8GB scan',
    layer: 'L2',
    policy: 'P-035',
    requestedBy: 'agent autonomous',
    age: '4m',
    urgent: false,
    reason: 'PII bucket lockdown',
    trace: 'tr-9a35',
  },
  {
    id: 'AP-9388',
    agent: 'support-triage',
    verb: 'write',
    resource: 'pg.public.tickets',
    detail: 'UPDATE 47 rows',
    layer: 'L2',
    policy: 'P-014',
    requestedBy: 'agent autonomous',
    age: '5m',
    urgent: false,
    reason: 'PII table write',
    trace: 'tr-9a31',
  },
  {
    id: 'AP-9384',
    agent: 'research-bot-04',
    verb: 'write',
    resource: 'gmail/send',
    detail: 'to: ext@vendor.com · attachment 200KB',
    layer: 'L2',
    policy: 'P-021',
    requestedBy: 'agent autonomous',
    age: '6m',
    urgent: false,
    reason: 'External recipient',
    trace: 'tr-9a2c',
  },
];

// ─── Topology data — mirrors GET /api/v1/topology/* + POST /topology/edges ──

const TOPO_TEAMS = [
  { id: 'data-platform', label: 'data-platform' },
  { id: 'cx-tools',      label: 'cx-tools'      },
  { id: 'platform',      label: 'platform'       },
  { id: 'rev-ops',       label: 'rev-ops'        },
  { id: 'knowledge',     label: 'knowledge'      },
  { id: 'finance',       label: 'finance'        },
  { id: '__orphan__',    label: 'unclaimed'      }, // agents with no team_id — mirrors TopologyStats.orphan_count
];

// Each node mirrors AgentTree from GET /api/v1/topology/tree/{root_id}.
// Layout grid: 3 cols × 2 rows  →  col = teamIdx % 3, row = floor(teamIdx / 3)
const TOPO_NODES = [
  // data-platform — col 0, row 0 (3-level tree)
  { id: 'data-ops-orch',     name: 'data-ops-orch',     team: 'data-platform', depth: 0, parentId: null,              framework: 'LangGraph',  status: 'active',    trust: 85, mode: 'enforce', flagged: false },
  { id: 'research-bot-04',   name: 'research-bot-04',   team: 'data-platform', depth: 1, parentId: 'data-ops-orch',   framework: 'LangChain',  status: 'active',    trust: 42, mode: 'enforce', flagged: true  },
  { id: 'analytics-runner',  name: 'analytics-runner',  team: 'data-platform', depth: 2, parentId: 'research-bot-04', framework: 'LangChain',  status: 'active',    trust: 71, mode: 'enforce', flagged: false },
  { id: 'pii-scanner',       name: 'pii-scanner',       team: 'data-platform', depth: 2, parentId: 'research-bot-04', framework: 'LlamaIndex', status: 'active',    trust: 79, mode: 'enforce', flagged: false },
  // cx-tools — col 1, row 0
  { id: 'support-triage',    name: 'support-triage',    team: 'cx-tools',      depth: 0, parentId: null,              framework: 'CrewAI',     status: 'active',    trust: 78, mode: 'enforce', flagged: false },
  { id: 'ticket-clf',        name: 'ticket-classifier', team: 'cx-tools',      depth: 1, parentId: 'support-triage',  framework: 'CrewAI',     status: 'active',    trust: 82, mode: 'enforce', flagged: false },
  // platform — col 2, row 0
  { id: 'infra-ops-bot',     name: 'infra-ops-bot',     team: 'platform',      depth: 0, parentId: null,              framework: 'AutoGen',    status: 'active',    trust: 88, mode: 'enforce', flagged: false },
  { id: 'incident-responder',name: 'incident-responder',team: 'platform',      depth: 1, parentId: 'infra-ops-bot',   framework: 'AutoGen',    status: 'active',    trust: 81, mode: 'enforce', flagged: false },
  // rev-ops — col 0, row 1 (standalone root)
  { id: 'sales-outreach-v2', name: 'sales-outreach-v2', team: 'rev-ops',       depth: 0, parentId: null,              framework: 'LangGraph',  status: 'active',    trust: 64, mode: 'shadow',  flagged: false },
  // knowledge — col 1, row 1
  { id: 'docs-summarizer',   name: 'docs-summarizer',   team: 'knowledge',     depth: 0, parentId: null,              framework: 'LlamaIndex', status: 'active',    trust: 92, mode: 'enforce', flagged: false },
  // finance — col 2, row 1 (suspended)
  { id: 'finance-bot',       name: 'finance-bot',       team: 'finance',       depth: 0, parentId: null,              framework: 'CrewAI',     status: 'suspended', trust: 55, mode: 'enforce', flagged: true  },
  // data-platform — second root (1-to-many roots per team)
  { id: 'data-ingestion',    name: 'data-ingestion',    team: 'data-platform', depth: 0, parentId: null,              framework: 'LangGraph',  status: 'active',    trust: 80, mode: 'enforce', flagged: false },
  { id: 'etl-worker',        name: 'etl-worker',        team: 'data-platform', depth: 1, parentId: 'data-ingestion',  framework: 'LangChain',  status: 'active',    trust: 68, mode: 'enforce', flagged: false },
  // unclaimed / orphan agents — no team_id, mirrors backend orphan_count
  { id: 'shadow-scraper',    name: 'shadow-scraper',    team: '__orphan__',    depth: 0, parentId: null,              framework: 'Custom',     status: 'active',    trust: 31, mode: 'shadow',  flagged: true  },
];

// Directed edges — mirrors EdgeType enum (delegates_to / calls / reads / writes / approves / messages)
const TOPO_EDGES = [
  // intra-team delegation / call edges
  { id: 'te1', source: 'data-ops-orch',    target: 'research-bot-04',    type: 'delegates_to', crossTeam: false },
  { id: 'te2', source: 'research-bot-04',  target: 'analytics-runner',   type: 'calls',         crossTeam: false },
  { id: 'te3', source: 'research-bot-04',  target: 'pii-scanner',        type: 'calls',         crossTeam: false },
  { id: 'te4', source: 'support-triage',   target: 'ticket-clf',         type: 'delegates_to',  crossTeam: false },
  { id: 'te5', source: 'infra-ops-bot',    target: 'incident-responder', type: 'delegates_to',  crossTeam: false },
  // cross-team edges
  { id: 'te6', source: 'analytics-runner', target: 'docs-summarizer',    type: 'reads',         crossTeam: true },
  { id: 'te7', source: 'research-bot-04',  target: 'support-triage',     type: 'messages',      crossTeam: true },
  { id: 'te8', source: 'infra-ops-bot',    target: 'data-ops-orch',      type: 'approves',      crossTeam: true },
  { id: 'te9',  source: 'sales-outreach-v2',target: 'research-bot-04',    type: 'reads',         crossTeam: true  },
  // data-platform second root subtree
  { id: 'te10', source: 'data-ingestion',  target: 'etl-worker',          type: 'delegates_to',  crossTeam: false },
  // Cycle: research-bot-04 → analytics-runner → etl-worker → research-bot-04
  // Mirrors Tarjan SCC detection in aa-core/src/topology/cycle.rs
  { id: 'te11', source: 'etl-worker',      target: 'research-bot-04',     type: 'calls',         crossTeam: false },
  { id: 'te12', source: 'analytics-runner',target: 'etl-worker',          type: 'reads',         crossTeam: false },
  // Orphan agent cross-team edge
  { id: 'te13', source: 'shadow-scraper',  target: 'research-bot-04',     type: 'reads',         crossTeam: true  },
];

Object.assign(window, { RESOURCES, AGENTS, POLICIES, SAMPLE_CALLS, VERBS, DECISIONS, APPROVALS, TOPO_TEAMS, TOPO_NODES, TOPO_EDGES });
