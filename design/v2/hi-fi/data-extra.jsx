/* global React */
/* ============================================================
   Extra sample data — Alerts, Costs, Identity, Teams
   Loaded after data.jsx so it can reference window.TOPO_NODES etc.
   ============================================================ */

// ── Alerts  (mirrors GET /api/v1/alerts) ─────────────────────────────────────
const ALERTS = [
  { id: 'ALT-0041', severity: 'critical', category: 'budget',           agent_id: 'research-bot-04',   message: 'Daily spend crossed 95 % of limit ($47.50 / $50.00)',                                        timestamp: '2026-05-11T14:02:11Z', age: '4m ago'  },
  { id: 'ALT-0040', severity: 'critical', category: 'policy_violation', agent_id: 'finance-bot',        message: 'Attempted cross-org S3 access blocked by P-035 — 3 attempts in 10 min',                    timestamp: '2026-05-11T13:55:44Z', age: '11m ago', policy_id: 'P-035' },
  { id: 'ALT-0039', severity: 'warning',  category: 'policy_violation', agent_id: 'research-bot-04',   message: 'Shell exec attempted outside break-glass window — blocked by P-042',                         timestamp: '2026-05-11T13:48:10Z', age: '18m ago', policy_id: 'P-042' },
  { id: 'ALT-0038', severity: 'warning',  category: 'budget',           agent_id: 'analytics-runner',  message: 'Daily spend crossed 80 % of limit ($40.10 / $50.00)',                                        timestamp: '2026-05-11T13:42:58Z', age: '24m ago' },
  { id: 'ALT-0037', severity: 'warning',  category: 'anomaly',          agent_id: 'sales-outreach-v2', message: 'Spike in outbound email volume — 4× normal rate in last 30 min',                             timestamp: '2026-05-11T13:31:02Z', age: '35m ago' },
  { id: 'ALT-0036', severity: 'critical', category: 'policy_violation', agent_id: 'research-bot-04',   message: 'PII exfiltration attempt via HTTP POST to external host — blocked by P-021',                 timestamp: '2026-05-11T13:15:22Z', age: '51m ago', policy_id: 'P-021' },
  { id: 'ALT-0035', severity: 'warning',  category: 'anomaly',          agent_id: 'shadow-scraper',    message: 'Unregistered agent detected in mesh — no policy assigned, running in shadow mode',           timestamp: '2026-05-11T12:58:03Z', age: '1h ago'  },
  { id: 'ALT-0034', severity: 'warning',  category: 'budget',           agent_id: 'infra-ops-bot',     message: 'Monthly spend on track to exceed limit at current burn rate ($183.96 / $200.00 projected)',  timestamp: '2026-05-11T12:44:30Z', age: '1h ago'  },
  { id: 'ALT-0033', severity: 'warning',  category: 'policy_violation', agent_id: 'support-triage',    message: '12 PII table writes held for approval in 1 hour — queue backlog building',                   timestamp: '2026-05-11T12:22:11Z', age: '2h ago',  policy_id: 'P-014' },
  { id: 'ALT-0032', severity: 'warning',  category: 'anomaly',          agent_id: 'incident-responder',message: 'eBPF layer degraded — kernel probe failed to attach on prod-node-07; falling back to proxy', timestamp: '2026-05-11T11:30:00Z', age: '3h ago'  },
  { id: 'ALT-0031', severity: 'warning',  category: 'policy_violation', agent_id: 'analytics-runner',  message: 'Attempted access to s3://customer-pii/raw/* without approved session',                       timestamp: '2026-05-11T10:58:30Z', age: '3h ago',  policy_id: 'P-035' },
  { id: 'ALT-0030', severity: 'warning',  category: 'anomaly',          agent_id: null,                message: 'Topology cycle detected: research-bot-04 → analytics-runner → etl-worker → research-bot-04', timestamp: '2026-05-11T09:12:00Z', age: '5h ago'  },
];

// ── Costs  (mirrors GET /api/v1/costs) ───────────────────────────────────────
const COSTS = {
  date:               '2026-05-11',
  daily_spend_usd:    '47.82',
  daily_limit_usd:    '100.00',
  monthly_spend_usd:  '891.44',
  monthly_limit_usd:  '2500.00',
  history_7d: [
    { date: '05-05', spend: 38.2 },
    { date: '05-06', spend: 42.1 },
    { date: '05-07', spend: 35.8 },
    { date: '05-08', spend: 44.5 },
    { date: '05-09', spend: 51.2 },
    { date: '05-10', spend: 48.9 },
    { date: '05-11', spend: 47.8 },
  ],
  per_agent: [
    { agent_id: 'research-bot-04',    daily_spend_usd: '14.22', monthly_spend_usd: '287.40', date: '2026-05-11', trend: [1.2, 3.1, 4.8, 6.2, 8.5, 11.0, 14.2] },
    { agent_id: 'analytics-runner',   daily_spend_usd: '11.04', monthly_spend_usd: '198.72', date: '2026-05-11', trend: [2.0, 3.8, 5.2, 7.1, 8.4, 9.6, 11.0]  },
    { agent_id: 'infra-ops-bot',      daily_spend_usd:  '7.91', monthly_spend_usd: '142.38', date: '2026-05-11', trend: [0.9, 1.8, 2.9, 4.1, 5.5, 6.8, 7.9]   },
    { agent_id: 'support-triage',     daily_spend_usd:  '6.42', monthly_spend_usd: '115.56', date: '2026-05-11', trend: [1.0, 2.2, 3.0, 3.9, 4.8, 5.6, 6.4]   },
    { agent_id: 'sales-outreach-v2',  daily_spend_usd:  '4.18', monthly_spend_usd:  '75.24', date: '2026-05-11', trend: [0.6, 1.1, 1.8, 2.4, 3.0, 3.6, 4.2]   },
    { agent_id: 'incident-responder', daily_spend_usd:  '2.31', monthly_spend_usd:  '41.58', date: '2026-05-11', trend: [0.3, 0.6, 0.9, 1.3, 1.7, 2.0, 2.3]   },
    { agent_id: 'docs-summarizer',    daily_spend_usd:  '1.74', monthly_spend_usd:  '31.32', date: '2026-05-11', trend: [0.2, 0.4, 0.7, 0.9, 1.2, 1.5, 1.7]   },
  ],
  per_team: [
    { team_id: 'data-platform', daily_spend_usd: '25.26', monthly_spend_usd: '486.12', agent_count: 5 },
    { team_id: 'platform',      daily_spend_usd: '10.22', monthly_spend_usd: '183.96', agent_count: 2 },
    { team_id: 'cx-tools',      daily_spend_usd:  '6.42', monthly_spend_usd: '115.56', agent_count: 2 },
    { team_id: 'rev-ops',       daily_spend_usd:  '4.18', monthly_spend_usd:  '75.24', agent_count: 1 },
    { team_id: 'knowledge',     daily_spend_usd:  '1.74', monthly_spend_usd:  '31.32', agent_count: 1 },
  ],
};

// ── Identity / RBAC  (mirrors /auth + policy RBAC) ───────────────────────────
const MEMBERS = [
  { id: 'kelly',  name: 'Kelly Chen',    email: 'kelly@acme.com',  role: 'org_admin',  teams: ['*'],                              lastActive: '4m ago',  status: 'active'   },
  { id: 'marcus', name: 'Marcus Rivera', email: 'marcus@acme.com', role: 'team_admin', teams: ['data-platform', 'cx-tools'],      lastActive: '1h ago',  status: 'active'   },
  { id: 'priya',  name: 'Priya Nair',    email: 'priya@acme.com',  role: 'operator',   teams: ['platform'],                       lastActive: '22m ago', status: 'active'   },
  { id: 'daniel', name: 'Daniel Park',   email: 'daniel@acme.com', role: 'operator',   teams: ['rev-ops', 'cx-tools'],            lastActive: '3h ago',  status: 'active'   },
  { id: 'anya',   name: 'Anya Sokolova', email: 'anya@acme.com',   role: 'viewer',     teams: ['data-platform'],                  lastActive: '1d ago',  status: 'active'   },
  { id: 'ben',    name: 'Ben Kowalski',  email: 'ben@acme.com',    role: 'viewer',     teams: ['finance'],                        lastActive: '2d ago',  status: 'inactive' },
];

const ROLES = [
  {
    id: 'org_admin',
    label: 'Org Admin',
    desc: 'Full access — create / delete global policies, manage all teams and members, issue any token scope, approve any action.',
    capabilities: ['manage_policies:global', 'manage_members', 'approve:any', 'view_all_logs', 'manage_budgets', 'issue_tokens:any'],
  },
  {
    id: 'team_admin',
    label: 'Team Admin',
    desc: 'Manage policies and members scoped to assigned teams. Cannot touch global policies or other teams.',
    capabilities: ['manage_policies:team', 'manage_members:team', 'approve:team', 'view_logs:team', 'issue_tokens:team'],
  },
  {
    id: 'operator',
    label: 'Operator',
    desc: 'Approve / reject pending actions, suspend / resume agents within assigned teams. No policy or member management.',
    capabilities: ['approve:team', 'suspend_agent:team', 'resume_agent:team', 'view_logs:team'],
  },
  {
    id: 'viewer',
    label: 'Viewer',
    desc: 'Read-only access to dashboards, logs, and topology. Cannot take any governance action.',
    capabilities: ['view_logs:all', 'view_topology', 'view_policies', 'view_costs'],
  },
];

const API_TOKENS = [
  { id: 'TK-001', name: 'ci-pipeline-prod',    scopes: ['audit:read', 'agents:read'],            createdBy: 'kelly',  expiresAt: '2026-08-01', lastUsed: '14s ago', status: 'active'  },
  { id: 'TK-002', name: 'grafana-integration', scopes: ['metrics:read', 'alerts:read'],           createdBy: 'marcus', expiresAt: '2026-06-15', lastUsed: '2m ago',  status: 'active'  },
  { id: 'TK-003', name: 'slack-bot-approvals', scopes: ['approvals:read', 'approvals:write'],     createdBy: 'kelly',  expiresAt: '2026-07-01', lastUsed: '1h ago',  status: 'active'  },
  { id: 'TK-004', name: 'audit-export-cron',   scopes: ['audit:read'],                            createdBy: 'priya',  expiresAt: '2026-05-20', lastUsed: '6h ago',  status: 'active'  },
  { id: 'TK-005', name: 'old-monitoring',      scopes: ['agents:read', 'metrics:read'],           createdBy: 'ben',    expiresAt: '2026-04-01', lastUsed: '32d ago', status: 'expired' },
];

// ── Team detail  (extends TOPO_TEAMS for Teams page) ─────────────────────────
const TEAM_DETAILS = {
  'data-platform': {
    budget_daily: 50.00, budget_daily_used: 25.26,
    budget_monthly: 1200.00, budget_monthly_used: 486.12,
    policy_ids: ['P-014', 'P-035'],
    approval_routing: 'marcus (Team Admin) → kelly (Org Admin if escalated)',
  },
  'cx-tools': {
    budget_daily: 20.00, budget_daily_used: 6.42,
    budget_monthly: 500.00, budget_monthly_used: 115.56,
    policy_ids: ['P-014', 'P-021'],
    approval_routing: 'daniel (Operator)',
  },
  'platform': {
    budget_daily: 25.00, budget_daily_used: 10.22,
    budget_monthly: 600.00, budget_monthly_used: 183.96,
    policy_ids: ['P-042', 'P-058'],
    approval_routing: 'priya (Operator) → kelly (Org Admin if escalated)',
  },
  'rev-ops': {
    budget_daily: 15.00, budget_daily_used: 4.18,
    budget_monthly: 300.00, budget_monthly_used: 75.24,
    policy_ids: ['P-021'],
    approval_routing: 'daniel (Operator)',
  },
  'knowledge': {
    budget_daily: 10.00, budget_daily_used: 1.74,
    budget_monthly: 200.00, budget_monthly_used: 31.32,
    policy_ids: ['P-014'],
    approval_routing: 'kelly (Org Admin)',
  },
  'finance': {
    budget_daily: 10.00, budget_daily_used: 0,
    budget_monthly: 200.00, budget_monthly_used: 0,
    policy_ids: ['P-035', 'P-014'],
    approval_routing: 'kelly (Org Admin)',
  },
  '__orphan__': {
    budget_daily: 0, budget_daily_used: 0,
    budget_monthly: 0, budget_monthly_used: 0,
    policy_ids: [],
    approval_routing: '— none assigned',
  },
};

// ── Budget Subtree Tree  (mirrors GET /api/v1/topology/tree + /costs hierarchy) ──
// Represents hierarchical budget inheritance: parent limit constrains all descendants.
// subtree_spend = node's own_spend + sum of all descendants' own_spend.
// budget_kind: 'daily' resets at midnight; 'session' resets per agent session.
const BUDGET_TREE = {
  id: '__org__', label: 'acme-corp', kind: 'org', budget_kind: 'daily',
  depth: 0, budget_limit: 100.00, own_spend: 0, subtree_spend: 47.82,
  governance_level: null,
  children: [
    {
      id: 'data-platform', label: 'data-platform', kind: 'team', budget_kind: 'daily',
      depth: 1, budget_limit: 50.00, own_spend: 0, subtree_spend: 25.26,
      governance_level: null,
      children: [
        {
          id: 'research-bot-04', label: 'research-bot-04', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 20.00, own_spend: 9.50, subtree_spend: 14.22,
          governance_level: 'L2',
          children: [
            {
              id: 'etl-worker-01', label: 'etl-worker-01', kind: 'agent', budget_kind: 'session',
              depth: 3, budget_limit: 8.00, own_spend: 3.22, subtree_spend: 3.22,
              governance_level: 'L2', children: [],
            },
            {
              id: 'etl-worker-02', label: 'etl-worker-02', kind: 'agent', budget_kind: 'session',
              depth: 3, budget_limit: 8.00, own_spend: 1.50, subtree_spend: 1.50,
              governance_level: 'L2', children: [],
            },
          ],
        },
        {
          id: 'analytics-runner', label: 'analytics-runner', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 13.00, own_spend: 11.04, subtree_spend: 11.04,
          governance_level: 'L3', children: [],
        },
      ],
    },
    {
      id: 'platform', label: 'platform', kind: 'team', budget_kind: 'daily',
      depth: 1, budget_limit: 25.00, own_spend: 0, subtree_spend: 10.22,
      governance_level: null,
      children: [
        {
          id: 'infra-ops-bot', label: 'infra-ops-bot', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 15.00, own_spend: 7.91, subtree_spend: 7.91,
          governance_level: 'L3', children: [],
        },
        {
          id: 'incident-responder', label: 'incident-responder', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 10.00, own_spend: 2.31, subtree_spend: 2.31,
          governance_level: 'L2', children: [],
        },
      ],
    },
    {
      id: 'cx-tools', label: 'cx-tools', kind: 'team', budget_kind: 'daily',
      depth: 1, budget_limit: 20.00, own_spend: 0, subtree_spend: 6.42,
      governance_level: null,
      children: [
        {
          id: 'support-triage', label: 'support-triage', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 20.00, own_spend: 6.42, subtree_spend: 6.42,
          governance_level: 'L2', children: [],
        },
      ],
    },
    {
      id: 'rev-ops', label: 'rev-ops', kind: 'team', budget_kind: 'daily',
      depth: 1, budget_limit: 15.00, own_spend: 0, subtree_spend: 4.18,
      governance_level: null,
      children: [
        {
          id: 'sales-outreach-v2', label: 'sales-outreach-v2', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 15.00, own_spend: 4.18, subtree_spend: 4.18,
          governance_level: 'L2', children: [],
        },
      ],
    },
    {
      id: 'knowledge', label: 'knowledge', kind: 'team', budget_kind: 'daily',
      depth: 1, budget_limit: 10.00, own_spend: 0, subtree_spend: 1.74,
      governance_level: null,
      children: [
        {
          id: 'knowledge-docs-summarizer', label: 'docs-summarizer', kind: 'agent', budget_kind: 'daily',
          depth: 2, budget_limit: 10.00, own_spend: 1.74, subtree_spend: 1.74,
          governance_level: 'L1', children: [],
        },
      ],
    },
  ],
};

Object.assign(window, { ALERTS, COSTS, MEMBERS, ROLES, API_TOKENS, TEAM_DETAILS, BUDGET_TREE });
