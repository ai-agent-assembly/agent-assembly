/* global React */
const { useState, useMemo } = React;

// =============================================================
// Shared atoms
// =============================================================

const SketchBox = ({ children, style, className = '', thick, dashed, double }) => (
  <div
    className={`sketch ${thick ? 'sketch-thick' : ''} ${dashed ? 'sketch-dashed' : ''} ${double ? 'sketch-double' : ''} ${className}`}
    style={style}
  >
    {children}
  </div>
);

const Kicker = ({ children }) => <div className="kicker">{children}</div>;

const Tag = ({ children, kind }) => (
  <span className={`tag ${kind ? `tag-${kind}` : ''}`}>{children}</span>
);

const Placeholder = ({ label, h = 60 }) => (
  <div className="placeholder" style={{ height: h }}>
    {label}
  </div>
);

const Bar = ({ pct, color }) => (
  <div className="bar">
    <div className="bar-fill" style={{ width: `${pct}%`, background: color || 'var(--ink)' }} />
  </div>
);

// =============================================================
// MOCK DATA — three scales
// =============================================================

const MOCK = {
  small: {
    fleetSize: 8,
    blockedToday: 14,
    redacted: 47,
    secretsScrubbed: 19,
    awaitingApproval: 2,
    activeIncidents: 0,
    framework: { LangGraph: 3, CrewAI: 2, 'Pydantic AI': 2, Custom: 1 },
  },
  medium: {
    fleetSize: 142,
    blockedToday: 312,
    redacted: 1847,
    secretsScrubbed: 226,
    awaitingApproval: 8,
    activeIncidents: 1,
    framework: { LangGraph: 58, CrewAI: 31, 'Pydantic AI': 24, AutoGen: 18, Custom: 11 },
  },
  large: {
    fleetSize: 1284,
    blockedToday: 4319,
    redacted: 28104,
    secretsScrubbed: 3417,
    awaitingApproval: 41,
    activeIncidents: 3,
    framework: { LangGraph: 487, CrewAI: 312, 'Pydantic AI': 198, AutoGen: 156, ADK: 89, Custom: 42 },
  },
};

const AGENTS = [
  { id: 'aa:did:7f3a…21c4', name: 'sales-outreach',  framework: 'LangGraph', trust: 87, mode: 'enforced',  status: 'active',    blocked: 4 },
  { id: 'aa:did:9b1e…4d02', name: 'support-triage',  framework: 'CrewAI',    trust: 92, mode: 'enforced',  status: 'active',    blocked: 1 },
  { id: 'aa:did:2c8d…ff31', name: 'code-maintainer', framework: 'Pydantic',  trust: 64, mode: 'enforced',  status: 'suspended', blocked: 12 },
  { id: 'aa:did:5e72…aa19', name: 'research-agent',  framework: 'AutoGen',   trust: 58, mode: 'advisory',  status: 'active',    blocked: 6 },
  { id: 'aa:did:1a44…7e88', name: 'data-pipeliner',  framework: 'Custom',    trust: 78, mode: 'enforced',  status: 'active',    blocked: 0 },
];

const EVENTS = [
  { t: '09:31:14', agent: 'sales-outreach',  layer: 'PROXY',  decision: 'APPROVAL', action: 'POST gmail.com/send', why: 'OUTBOUND_EMAIL_APPROVAL' },
  { t: '09:31:15', agent: 'sales-outreach',  layer: 'eBPF',   decision: 'BLOCKED',  action: 'open ~/.ssh/id_rsa', why: 'SENSITIVE_PATH_BLOCKLIST' },
  { t: '09:42:03', agent: 'code-maintainer', layer: 'eBPF',   decision: 'BLOCKED',  action: 'execve /bin/sh',     why: 'SHELL_INJECTION_DENY' },
  { t: '09:48:22', agent: 'support-triage',  layer: 'SDK',    decision: 'REDACTED', action: 'LLM call (anthropic)', why: 'PII_REDACT_BEFORE_LLM' },
  { t: '09:55:10', agent: 'research-agent',  layer: 'PROXY',  decision: 'LEAK',     action: 'LLM egress (openai)',   why: 'LEAK_SUSPECTED_POSTURE' },
  { t: '10:02:41', agent: 'data-pipeliner',  layer: 'SDK',    decision: 'ALLOWED',  action: 'read s3://logs',       why: 'READ_ALLOWED' },
  { t: '10:03:57', agent: 'sales-outreach',  layer: 'PROXY',  decision: 'SCRUB',    action: 'LLM call w/ AWS key',  why: 'SECRET_PATTERN_AKIA…' },
  { t: '10:04:11', agent: 'code-maintainer', layer: 'SDK',    decision: 'BLOCKED',  action: 'tool: github.delete_repo', why: 'WRITE_DENY_READ_ONLY' },
];

const decisionTag = (d) => {
  if (d === 'BLOCKED' || d === 'LEAK') return 'danger';
  if (d === 'APPROVAL') return 'warn';
  if (d === 'REDACTED' || d === 'SCRUB') return 'scrub';
  return 'ok';
};

// =============================================================
// Top bar shared across wireframes
// =============================================================

const WfTopBar = ({ title, subtitle }) => (
  <div className="row between" style={{ marginBottom: 12 }}>
    <div>
      <Kicker>WIREFRAME · LO-FI · v1</Kicker>
      <h1 style={{ marginTop: 4 }}>{title}</h1>
      <div className="note">{subtitle}</div>
    </div>
    <div className="row" style={{ gap: 6 }}>
      <Tag kind="ok"><span className="dot dot-ok" />runtime ok</Tag>
      <Tag kind="warn"><span className="dot dot-warn" />proxy degraded</Tag>
      <Tag>fleet: {'{scale}'}</Tag>
    </div>
  </div>
);

// =============================================================
// V1 — Capability Narrowing as the hero
// =============================================================

const V1 = ({ data }) => (
  <div className="wf" style={{ width: 1280, minHeight: 900 }}>
    <WfTopBar
      title="V1 — Capability Narrowing 為主角"
      subtitle="把 'agent 自稱權限 vs Assembly 縮限後的有效權限' 直接攤開比較。最重要的不是看到了什麼，是看不到了什麼。"
    />

    {/* Hero: capability narrowing matrix */}
    <SketchBox thick double style={{ marginBottom: 12 }}>
      <div className="row between" style={{ marginBottom: 8 }}>
        <div>
          <Kicker>HERO · capability narrowing matrix</Kicker>
          <h2>Claimed vs Effective — 你以為 agent 能做的 vs 實際能做的</h2>
        </div>
        <div className="row" style={{ gap: 6 }}>
          <Tag kind="info">5 agents · 12 resources</Tag>
          <button className="tag">+ add resource</button>
          <button className="tag">edit policy →</button>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="wf-table" style={{ minWidth: 900 }}>
          <thead>
            <tr>
              <th style={{ width: 180 }}>agent · resource</th>
              <th>read</th><th>write</th><th>delete</th><th>execute</th><th>net send</th><th>file write</th>
              <th>narrowed by</th>
            </tr>
          </thead>
          <tbody>
            {[
              { a: 'sales-outreach',  r: 'gmail',     row: ['claim', 'allow', 'narrow', 'deny', 'deny',   'approval', 'na', 'OUTBOUND_EMAIL_APPROVAL'] },
              { a: 'sales-outreach',  r: 'salesforce',row: ['claim', 'allow', 'allow',  'narrow→deny', 'deny', 'allow', 'na', 'WRITE_DENY_READ_ONLY'] },
              { a: 'support-triage',  r: 'zendesk',   row: ['claim', 'allow', 'narrow', 'deny', 'deny',   'allow',    'na', 'TICKET_DRAFT_ONLY'] },
              { a: 'code-maintainer', r: 'github:org',row: ['claim', 'allow', 'narrow', 'deny', 'deny',   'allow',    'na', 'PR_ONLY_NO_FORCE_PUSH'] },
              { a: 'research-agent',  r: 'fs:home',   row: ['claim', 'allow', 'allow',  'allow', 'allow', 'na',       'narrow→workspace', 'WORKSPACE_SCOPE'] },
              { a: 'data-pipeliner',  r: 's3:logs',   row: ['claim', 'allow', 'deny',   'deny', 'deny',   'allow',    'na', '(unchanged · already RO)'] },
            ].map((row, i) => (
              <tr key={i}>
                <td><strong>{row.a}</strong><br/><small>{row.r}</small></td>
                {row.row.slice(1).map((cell, j) => (
                  <td key={j} style={{ verticalAlign: 'top' }}>
                    {cell === 'allow' && <Tag kind="ok">allow</Tag>}
                    {cell === 'deny' && <Tag kind="danger">deny</Tag>}
                    {cell === 'narrow' && <Tag kind="warn">narrow</Tag>}
                    {cell === 'approval' && <Tag kind="warn">approval</Tag>}
                    {cell === 'narrow→deny' && (
                      <span><Tag kind="ok">claim:allow</Tag><br/><Tag kind="danger">→ deny</Tag></span>
                    )}
                    {cell === 'narrow→workspace' && (
                      <span><Tag kind="ok">~/</Tag><br/><Tag kind="warn">→ ~/work/</Tag></span>
                    )}
                    {cell === 'na' && <small>—</small>}
                    {!['allow','deny','narrow','approval','narrow→deny','narrow→workspace','na'].includes(cell) && (
                      <small className="wf-mono">{cell}</small>
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ marginTop: 8, fontStyle: 'italic', color: 'var(--ink-soft)', fontSize: 14 }}>
        legend: <Tag kind="ok">allow</Tag> claimed & effective · <Tag kind="warn">narrow</Tag> reduced by policy ·
        <Tag kind="danger">deny</Tag> claim overridden to forbidden · click any cell → policy rule editor
      </div>
    </SketchBox>

    {/* Three-up: identity, scrubbing, recent enforcement */}
    <div className="grid-3" style={{ marginBottom: 12 }}>
      <SketchBox>
        <Kicker>identity layer</Kicker>
        <h3>Who is calling?</h3>
        <div className="col" style={{ gap: 6, marginTop: 6 }}>
          {AGENTS.slice(0, 4).map((a) => (
            <div key={a.id} className="row between" style={{ borderBottom: '1.5px dashed var(--ink-faint)', paddingBottom: 4 }}>
              <div>
                <strong>{a.name}</strong>
                <div className="id-card">{a.id}</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div className="metric-label">trust</div>
                <strong style={{ color: a.trust > 80 ? 'var(--ok)' : a.trust > 65 ? 'var(--warn)' : 'var(--danger)' }}>
                  {a.trust}
                </strong>
              </div>
            </div>
          ))}
        </div>
      </SketchBox>

      <SketchBox>
        <Kicker>secret scrubbing · L4 proxy</Kicker>
        <h3>Stripped before LLM saw them</h3>
        <div className="metric-big" style={{ color: 'var(--scrub)' }}>{data.secretsScrubbed}</div>
        <div className="metric-label">tokens / keys / PII removed today</div>
        <div className="col" style={{ marginTop: 8, gap: 4 }}>
          <div className="row between"><span>AWS access keys</span><strong>41</strong></div>
          <div className="row between"><span>GitHub PAT</span><strong>17</strong></div>
          <div className="row between"><span>JWTs</span><strong>62</strong></div>
          <div className="row between"><span>Email + phone (PII)</span><strong>{Math.max(0, data.secretsScrubbed - 120)}</strong></div>
        </div>
        <div className="note" style={{ marginTop: 6 }}>
          regex+entropy match → replace with [REDACTED] before TLS re-encrypt
        </div>
      </SketchBox>

      <SketchBox>
        <Kicker>live enforcement ticker</Kicker>
        <h3>Last 60s</h3>
        <div className="col" style={{ gap: 4, marginTop: 6 }}>
          {EVENTS.slice(0, 6).map((e, i) => (
            <div key={i} className="row" style={{ gap: 6, fontSize: 13 }}>
              <span className="wf-mono" style={{ color: 'var(--ink-faint)' }}>{e.t}</span>
              <Tag kind={decisionTag(e.decision)}>{e.decision}</Tag>
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <strong>{e.agent}</strong> · {e.action}
              </span>
            </div>
          ))}
        </div>
      </SketchBox>
    </div>

    {/* Bottom: policy editor preview */}
    <SketchBox dashed>
      <div className="row between" style={{ marginBottom: 6 }}>
        <Kicker>inline policy editor — click any matrix cell to land here</Kicker>
        <Tag kind="info">YAML · OPA · Wasm</Tag>
      </div>
      <pre className="wf-mono" style={{ background: 'var(--paper-warm)', padding: 10, borderRadius: 4, fontSize: 12, overflow: 'auto' }}>
{`# rule: WRITE_DENY_READ_ONLY  (active · v3 · 41 hits today)
match:
  agent.framework: ["langgraph", "crewai"]
  resource: "salesforce.*"
  action: ["create", "update", "delete"]
effect: deny
reason: "agent declared read-only mode at registration"
on_violation:
  - emit: audit.violation
  - notify: slack#sec-agents`}
      </pre>
    </SketchBox>
  </div>
);

// =============================================================
// V2 — Identity-first (agent passport + trust score)
// =============================================================

const V2 = ({ data }) => (
  <div className="wf" style={{ width: 1280, minHeight: 900 }}>
    <WfTopBar
      title="V2 — Identity-first · agent 身份證 + 信任分數"
      subtitle="先告訴你誰在裡面，再告訴你他們做了什麼。每個 agent 都是一張身份證，治理從 'who' 開始。"
    />

    {/* Identity strip — top hero */}
    <SketchBox thick style={{ marginBottom: 12 }}>
      <Kicker>fleet identity strip · {data.fleetSize} registered agents</Kicker>
      <div className="row" style={{ overflowX: 'auto', gap: 10, marginTop: 8, paddingBottom: 4 }}>
        {AGENTS.map((a, i) => (
          <SketchBox key={a.id} style={{ minWidth: 220, flexShrink: 0 }} className={`wonky-${(i % 3) + 1}`}>
            <div className="row between">
              <div>
                <Kicker>did</Kicker>
                <div className="id-card" style={{ marginTop: 2 }}>{a.id}</div>
              </div>
              <div className="placeholder" style={{ width: 32, height: 32, borderRadius: '50%' }}>id</div>
            </div>
            <h4 style={{ marginTop: 6 }}>{a.name}</h4>
            <div className="row" style={{ gap: 4, marginBottom: 4 }}>
              <Tag>{a.framework}</Tag>
              <Tag kind={a.mode === 'enforced' ? 'ok' : 'warn'}>{a.mode}</Tag>
            </div>
            <div className="row between" style={{ marginTop: 6 }}>
              <span className="metric-label">trust</span>
              <strong style={{ fontSize: 22, color: a.trust > 80 ? 'var(--ok)' : a.trust > 65 ? 'var(--warn)' : 'var(--danger)' }}>
                {a.trust}
              </strong>
            </div>
            <Bar pct={a.trust} color={a.trust > 80 ? 'var(--ok)' : a.trust > 65 ? 'var(--warn)' : 'var(--danger)'} />
            <div className="row between" style={{ marginTop: 6, fontSize: 12 }}>
              <span><span className={`dot dot-${a.status === 'active' ? 'ok' : 'danger'}`}></span>{a.status}</span>
              <span className="wf-mono">blocked {a.blocked}</span>
            </div>
          </SketchBox>
        ))}
        <div className="placeholder" style={{ minWidth: 80 }}>+{data.fleetSize - 5} more</div>
      </div>
    </SketchBox>

    {/* Two-column: trust scoring breakdown + capabilities granted by identity */}
    <div className="grid-2" style={{ marginBottom: 12 }}>
      <SketchBox>
        <Kicker>trust score · how it's calculated</Kicker>
        <h3>sales-outreach · trust 87</h3>
        <div className="col" style={{ gap: 6, marginTop: 8 }}>
          {[
            { f: 'Identity proof (Ed25519 signed registration)', s: 100, w: 0.20 },
            { f: 'Policy compliance (last 30d)', s: 92, w: 0.30 },
            { f: 'Action variance (vs declared tools)', s: 78, w: 0.20 },
            { f: 'Secret-leak posture', s: 100, w: 0.15 },
            { f: 'Human approval acceptance rate', s: 64, w: 0.15 },
          ].map((r, i) => (
            <div key={i}>
              <div className="row between" style={{ marginBottom: 2 }}>
                <span style={{ fontSize: 14 }}>{r.f}</span>
                <span className="wf-mono" style={{ fontSize: 12 }}>{r.s} × {r.w}</span>
              </div>
              <Bar pct={r.s} color={r.s > 80 ? 'var(--ok)' : r.s > 65 ? 'var(--warn)' : 'var(--danger)'} />
            </div>
          ))}
        </div>
        <div className="note" style={{ marginTop: 8 }}>
          ↳ low trust → more aggressive narrowing + mandatory approval gates
        </div>
      </SketchBox>

      <SketchBox>
        <Kicker>capabilities granted to this identity</Kicker>
        <h3>What sales-outreach is allowed to touch</h3>
        <div className="col" style={{ gap: 6, marginTop: 6 }}>
          {[
            { r: 'gmail',         claim: 'full',  effective: 'draft + approval-on-send', kind: 'warn' },
            { r: 'salesforce',    claim: 'rw',    effective: 'read-only',                  kind: 'danger' },
            { r: 'slack #sales',  claim: 'post',  effective: 'post (rate-limited 5/hr)',  kind: 'warn' },
            { r: 'fs:/tmp',       claim: 'rw',    effective: 'rw',                          kind: 'ok' },
            { r: 'fs:~/.ssh',     claim: 'r',     effective: 'BLOCKED · sensitive path',   kind: 'danger' },
            { r: 'shell exec',    claim: 'none',  effective: 'BLOCKED · ebpf trap',        kind: 'danger' },
          ].map((c, i) => (
            <div key={i} className="row between" style={{ borderBottom: '1.5px dashed var(--ink-faint)', paddingBottom: 4 }}>
              <div>
                <strong>{c.r}</strong>
                <div style={{ fontSize: 12, color: 'var(--ink-soft)' }}>claim: {c.claim}</div>
              </div>
              <Tag kind={c.kind}>{c.effective}</Tag>
            </div>
          ))}
        </div>
      </SketchBox>
    </div>

    {/* Bottom: timeline of identity events */}
    <SketchBox>
      <Kicker>identity audit trail</Kicker>
      <h3>Who registered, suspended, escalated — with signed evidence</h3>
      <div className="col" style={{ gap: 6, marginTop: 8 }}>
        {[
          { t: '08:14:02', e: 'register', who: 'data-pipeliner', sig: 'Ed25519 ✓', tone: 'ok' },
          { t: '08:42:18', e: 'trust drop', who: 'code-maintainer', sig: '92 → 64 · 12 violations', tone: 'warn' },
          { t: '09:15:55', e: 'suspend', who: 'code-maintainer', sig: 'by alice@org · reason: PR force-push attempt', tone: 'danger' },
          { t: '09:31:14', e: 'capability narrowed', who: 'sales-outreach', sig: 'gmail.send → approval', tone: 'warn' },
          { t: '10:02:41', e: 'mode escalation', who: 'research-agent', sig: 'advisory → enforced (auto)', tone: 'info' },
        ].map((r, i) => (
          <div key={i} className="row" style={{ gap: 8, alignItems: 'center' }}>
            <span className="wf-mono" style={{ fontSize: 12, color: 'var(--ink-faint)' }}>{r.t}</span>
            <Tag kind={r.tone}>{r.e}</Tag>
            <strong>{r.who}</strong>
            <span style={{ flex: 1, fontSize: 13, color: 'var(--ink-soft)' }}>{r.sig}</span>
          </div>
        ))}
      </div>
    </SketchBox>
  </div>
);

// =============================================================
// V3 — Three-layer pipeline (traffic flow viz)
// =============================================================

const V3 = ({ data }) => (
  <div className="wf" style={{ width: 1280, minHeight: 900 }}>
    <WfTopBar
      title="V3 — 三層防禦管線 · 流量管線視覺化"
      subtitle="把每個 agent action 想成一條水流，從上方 'agent 想做的事' 流入，經過三道閘門：身份 → 能力 → 機敏資料淨化。看哪一層擋下了什麼。"
    />

    {/* The pipeline diagram */}
    <SketchBox thick style={{ marginBottom: 12 }}>
      <Kicker>pipeline view · last 1h</Kicker>
      <h2 style={{ marginBottom: 8 }}>從 intent 到 external system 的完整水流</h2>
      <svg viewBox="0 0 1200 360" style={{ width: '100%', height: 360 }}>
        {/* inflow */}
        <rect x="10" y="20" width="180" height="60" className="stroke-thick fill-paper" />
        <text x="100" y="45" textAnchor="middle" fontFamily="Kalam" fontSize="16" fontWeight="700">agent intent</text>
        <text x="100" y="65" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#666">4,829 actions/h</text>

        <path d="M 190 50 L 240 50" className="stroke-thick" markerEnd="url(#arr)" />

        {/* layer 1 */}
        <rect x="240" y="10" width="200" height="80" rx="8" className="stroke-thick fill-paper" />
        <text x="340" y="32" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">L1 · IDENTITY (SDK)</text>
        <text x="340" y="50" textAnchor="middle" fontFamily="Kalam" fontSize="12">who is this agent?</text>
        <text x="340" y="68" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#c1272d">↓ rejected: 12 unsigned</text>
        <text x="340" y="82" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#666">passed: 4,817</text>

        <path d="M 440 50 L 490 50" className="stroke-thick" markerEnd="url(#arr)" />

        {/* layer 2 */}
        <rect x="490" y="10" width="220" height="80" rx="8" className="stroke-thick fill-paper" />
        <text x="600" y="32" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">L2 · CAPABILITY (policy)</text>
        <text x="600" y="50" textAnchor="middle" fontFamily="Kalam" fontSize="12">are you allowed to?</text>
        <text x="600" y="68" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#c1272d">↓ blocked: 312</text>
        <text x="600" y="82" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#d97706">approval queue: 8</text>

        <path d="M 710 50 L 760 50" className="stroke-thick" markerEnd="url(#arr)" />

        {/* layer 3 */}
        <rect x="760" y="10" width="220" height="80" rx="8" className="stroke-thick fill-paper" />
        <text x="870" y="32" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">L3 · SCRUB (proxy/eBPF)</text>
        <text x="870" y="50" textAnchor="middle" fontFamily="Kalam" fontSize="12">strip secrets from payload</text>
        <text x="870" y="68" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#6b21a8">↓ scrubbed: {data.secretsScrubbed}</text>
        <text x="870" y="82" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#666">passed clean: 4,228</text>

        <path d="M 980 50 L 1030 50" className="stroke-thick" markerEnd="url(#arr)" />

        {/* outflow */}
        <rect x="1030" y="20" width="160" height="60" className="stroke-thick fill-paper" />
        <text x="1110" y="45" textAnchor="middle" fontFamily="Kalam" fontSize="16" fontWeight="700">external system</text>
        <text x="1110" y="65" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11" fill="#666">LLM · MCP · API</text>

        {/* drop-down rejection lanes */}
        <path d="M 340 90 L 340 200" className="stroke-dashed" />
        <rect x="240" y="200" width="200" height="60" rx="6" className="stroke-ink fill-paper" style={{ fill: '#f4d8d8' }} />
        <text x="340" y="222" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">unknown agents</text>
        <text x="340" y="240" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11">no DID · refused at SDK init</text>
        <text x="340" y="254" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="14" fontWeight="700">12</text>

        <path d="M 600 90 L 600 200" className="stroke-dashed" />
        <rect x="490" y="200" width="220" height="60" rx="6" className="stroke-ink fill-paper" style={{ fill: '#f4d8d8' }} />
        <text x="600" y="222" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">policy violations</text>
        <text x="600" y="240" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11">write/exec/sensitive-path</text>
        <text x="600" y="254" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="14" fontWeight="700">312</text>

        <path d="M 870 90 L 870 200" className="stroke-dashed" />
        <rect x="760" y="200" width="220" height="60" rx="6" className="stroke-ink fill-paper" style={{ fill: '#e8dbf3' }} />
        <text x="870" y="222" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">secrets stripped</text>
        <text x="870" y="240" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11">AWS · JWT · PAT · PII</text>
        <text x="870" y="254" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="14" fontWeight="700">{data.secretsScrubbed}</text>

        <path d="M 600 260 L 600 300" className="stroke-dashed" />
        <rect x="450" y="300" width="300" height="50" rx="6" className="stroke-ink fill-paper" style={{ fill: '#fce7c8' }} />
        <text x="600" y="322" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">human approval queue</text>
        <text x="600" y="340" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="11">{data.awaitingApproval} waiting · oldest 4m</text>

        <defs>
          <marker id="arr" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
            <path d="M0,0 L8,5 L0,10 z" fill="#1a1a1a" />
          </marker>
        </defs>
      </svg>
      <div className="note">click any block → drill into the agents/events that hit that lane</div>
    </SketchBox>

    {/* Bottom row: per-layer detail */}
    <div className="grid-3">
      <SketchBox>
        <Kicker>L1 · identity rejects</Kicker>
        <h4>Why rejected</h4>
        <ul style={{ margin: '6px 0', paddingLeft: 18, fontSize: 14 }}>
          <li>9 × no Ed25519 signature on init</li>
          <li>2 × DID expired</li>
          <li>1 × revoked by org admin</li>
        </ul>
        <div className="placeholder" style={{ height: 60 }}>identity rejection trend (24h sparkline)</div>
      </SketchBox>

      <SketchBox>
        <Kicker>L2 · top blocked policies</Kicker>
        <h4>What got stopped</h4>
        <table className="wf-table">
          <tbody>
            <tr><td>WRITE_DENY_READ_ONLY</td><td><strong>118</strong></td></tr>
            <tr><td>SHELL_INJECTION_DENY</td><td><strong>74</strong></td></tr>
            <tr><td>SENSITIVE_PATH_BLOCKLIST</td><td><strong>52</strong></td></tr>
            <tr><td>OUTBOUND_EMAIL_APPROVAL</td><td><strong>41</strong></td></tr>
            <tr><td>(others)</td><td><strong>27</strong></td></tr>
          </tbody>
        </table>
      </SketchBox>

      <SketchBox>
        <Kicker>L3 · secret patterns hit</Kicker>
        <h4>What got scrubbed</h4>
        <table className="wf-table">
          <tbody>
            <tr><td>email + phone (PII)</td><td><strong>106</strong></td></tr>
            <tr><td>JWT bearer</td><td><strong>62</strong></td></tr>
            <tr><td>AWS AKIA…</td><td><strong>41</strong></td></tr>
            <tr><td>GitHub PAT ghp_</td><td><strong>17</strong></td></tr>
            <tr><td>generic high-entropy</td><td><strong>{Math.max(0, data.secretsScrubbed - 226)}</strong></td></tr>
          </tbody>
        </table>
      </SketchBox>
    </div>
  </div>
);

// =============================================================
// V4 — Castle / moat metaphor
// =============================================================

const V4 = ({ data }) => (
  <div className="wf" style={{ width: 1280, minHeight: 900 }}>
    <WfTopBar
      title="V4 — 城堡護城河 · multi-layer 視覺隱喻"
      subtitle="高階主管視角：用同心圓表達 '深度防禦'。最內層是你最珍貴的東西（資料），最外層是 agent 想觸碰它必須穿越的關卡。"
    />

    <div className="grid-2" style={{ gap: 12 }}>
      <SketchBox thick style={{ minHeight: 600 }}>
        <Kicker>defense-in-depth · concentric view</Kicker>
        <h2>The castle</h2>
        <svg viewBox="0 0 600 600" style={{ width: '100%', height: 540 }}>
          <defs>
            <pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(-45)">
              <line x1="0" y1="0" x2="0" y2="6" stroke="#1a1a1a" strokeWidth="0.5" />
            </pattern>
          </defs>
          {/* outer ring — agent zoo */}
          <circle cx="300" cy="300" r="280" className="stroke-thick fill-paper" style={{ strokeDasharray: '6 4' }} />
          <text x="300" y="40" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">untrusted zone · agent processes</text>

          {/* L1 identity */}
          <circle cx="300" cy="300" r="220" className="stroke-thick fill-paper" />
          <text x="300" y="100" textAnchor="middle" fontFamily="Kalam" fontSize="13">L1 · IDENTITY GATE</text>
          <text x="300" y="116" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">DID · Ed25519 · trust score</text>

          {/* L2 capability */}
          <circle cx="300" cy="300" r="160" className="stroke-thick fill-paper" />
          <text x="300" y="160" textAnchor="middle" fontFamily="Kalam" fontSize="13">L2 · CAPABILITY GATE</text>
          <text x="300" y="176" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">policy engine · narrowing rules</text>

          {/* L3 scrub */}
          <circle cx="300" cy="300" r="100" className="stroke-thick fill-paper" />
          <text x="300" y="220" textAnchor="middle" fontFamily="Kalam" fontSize="13">L3 · SCRUBBING</text>
          <text x="300" y="236" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">strip secrets at network layer</text>

          {/* core */}
          <circle cx="300" cy="300" r="48" fill="url(#hatch)" stroke="#1a1a1a" strokeWidth="3" />
          <text x="300" y="296" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">CROWN</text>
          <text x="300" y="312" textAnchor="middle" fontFamily="Kalam" fontSize="11">DATA · SECRETS</text>

          {/* attempted breaches as arrows */}
          <g opacity="0.85">
            <path d="M 80 80 Q 200 200 270 280" className="stroke-ink" markerEnd="url(#a4)" />
            <text x="60" y="74" fontFamily="Kalam" fontSize="11" fill="#c1272d">unsigned init</text>
            <text x="60" y="88" fontFamily="JetBrains Mono" fontSize="10" fill="#c1272d">stopped at L1 · 12</text>

            <path d="M 540 90 Q 420 200 350 270" className="stroke-ink" markerEnd="url(#a4)" />
            <text x="440" y="80" fontFamily="Kalam" fontSize="11" fill="#c1272d">write attempt</text>
            <text x="440" y="94" fontFamily="JetBrains Mono" fontSize="10" fill="#c1272d">stopped at L2 · 312</text>

            <path d="M 100 540 Q 200 400 280 320" className="stroke-ink" markerEnd="url(#a4)" />
            <text x="20" y="540" fontFamily="Kalam" fontSize="11" fill="#6b21a8">leaked secret</text>
            <text x="20" y="554" fontFamily="JetBrains Mono" fontSize="10" fill="#6b21a8">scrubbed at L3 · {data.secretsScrubbed}</text>

            <path d="M 530 540 Q 420 420 340 330" className="stroke-ink" markerEnd="url(#a4)" />
            <text x="430" y="556" fontFamily="Kalam" fontSize="11" fill="#d97706">human-gated</text>
            <text x="430" y="570" fontFamily="JetBrains Mono" fontSize="10" fill="#d97706">held · {data.awaitingApproval}</text>
          </g>
          <defs>
            <marker id="a4" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L7,4 L0,8 z" fill="#1a1a1a" />
            </marker>
          </defs>
        </svg>
        <div className="note">每一層下方累計擋下的次數 → 點擊圈進入該層的事件流</div>
      </SketchBox>

      {/* right column */}
      <div className="col">
        <SketchBox>
          <Kicker>today's posture</Kicker>
          <div className="grid-2">
            <div>
              <div className="metric-big" style={{ color: 'var(--danger)' }}>{data.activeIncidents}</div>
              <div className="metric-label">active leak incidents</div>
            </div>
            <div>
              <div className="metric-big">{data.blockedToday}</div>
              <div className="metric-label">total blocks today</div>
            </div>
            <div>
              <div className="metric-big" style={{ color: 'var(--scrub)' }}>{data.secretsScrubbed}</div>
              <div className="metric-label">secrets scrubbed</div>
            </div>
            <div>
              <div className="metric-big" style={{ color: 'var(--warn)' }}>{data.awaitingApproval}</div>
              <div className="metric-label">approvals waiting</div>
            </div>
          </div>
        </SketchBox>

        <SketchBox dashed>
          <Kicker>posture history · 7 days</Kicker>
          <Placeholder label="layered area chart · L1 / L2 / L3 blocks per hour" h={180} />
        </SketchBox>

        <SketchBox>
          <Kicker>incidents that broke through</Kicker>
          <h3>Where the moat failed</h3>
          <div className="col" style={{ gap: 6, marginTop: 6 }}>
            <div className="row between">
              <div>
                <Tag kind="danger">leak</Tag>
                <strong>research-agent</strong>
                <div className="note">PII reached openai · scrubber rule missed regex</div>
              </div>
              <button className="tag tag-danger">investigate →</button>
            </div>
            <div className="row between">
              <div>
                <Tag kind="warn">drift</Tag>
                <strong>code-maintainer</strong>
                <div className="note">trust 92 → 64 in 24h · auto-suspended</div>
              </div>
              <button className="tag">resume →</button>
            </div>
          </div>
        </SketchBox>
      </div>
    </div>
  </div>
);

// =============================================================
// V5 — High-density ops terminal
// =============================================================

const V5 = ({ data }) => (
  <div className="wf wf-mono" style={{ width: 1280, minHeight: 900, fontFamily: 'JetBrains Mono, monospace' }}>
    <div className="row between" style={{ marginBottom: 8 }}>
      <div>
        <Kicker>WIREFRAME · LO-FI · v5</Kicker>
        <h1 style={{ marginTop: 4, fontFamily: 'Kalam' }}>V5 — High-density ops terminal</h1>
        <div className="note">SRE 視角：所有東西塞在一頁，不滾動，可掃讀。情境是 on-call、incident 中。</div>
      </div>
    </div>

    {/* Top status strip */}
    <SketchBox style={{ marginBottom: 8, padding: 6 }}>
      <div className="row" style={{ gap: 12, fontSize: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <span><span className="dot dot-ok"></span>RUNTIME ok</span>
        <span><span className="dot dot-warn"></span>PROXY degraded · 1 node</span>
        <span><span className="dot dot-ok"></span>eBPF active</span>
        <span>FLEET <strong>{data.fleetSize}</strong></span>
        <span>BLOCKED <strong style={{ color: 'var(--danger)' }}>{data.blockedToday}</strong></span>
        <span>SCRUB <strong style={{ color: 'var(--scrub)' }}>{data.secretsScrubbed}</strong></span>
        <span>APPROVAL <strong style={{ color: 'var(--warn)' }}>{data.awaitingApproval}</strong></span>
        <span>INCIDENTS <strong style={{ color: 'var(--danger)' }}>{data.activeIncidents}</strong></span>
        <span style={{ marginLeft: 'auto' }}>p99 policy {`<`}0.08ms · audit lag 14ms</span>
      </div>
    </SketchBox>

    <div className="grid-3" style={{ gap: 8, marginBottom: 8 }}>
      {/* fleet table */}
      <SketchBox style={{ gridColumn: 'span 2' }}>
        <Kicker>fleet · sortable · filter: status:active</Kicker>
        <table className="wf-table" style={{ marginTop: 4 }}>
          <thead>
            <tr><th>did</th><th>name</th><th>fw</th><th>mode</th><th>trust</th><th>blk</th><th>scrub</th><th>last</th></tr>
          </thead>
          <tbody>
            {AGENTS.map((a) => (
              <tr key={a.id} style={{ fontSize: 12 }}>
                <td className="wf-mono">{a.id.slice(0, 14)}…</td>
                <td><strong>{a.name}</strong></td>
                <td>{a.framework}</td>
                <td><Tag kind={a.mode === 'enforced' ? 'ok' : 'warn'}>{a.mode}</Tag></td>
                <td style={{ color: a.trust > 80 ? 'var(--ok)' : a.trust > 65 ? 'var(--warn)' : 'var(--danger)' }}>{a.trust}</td>
                <td>{a.blocked}</td>
                <td>{Math.floor(Math.random() * 80)}</td>
                <td className="wf-mono" style={{ color: 'var(--ink-faint)' }}>{['12s','41s','1m','3m','7m'][Math.floor(Math.random()*5)]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </SketchBox>

      {/* approval queue */}
      <SketchBox>
        <Kicker>approval queue · {data.awaitingApproval} waiting</Kicker>
        <div className="col" style={{ gap: 4, marginTop: 6 }}>
          {[
            { a: 'sales-outreach', w: 'send email to ext domain', t: '4m' },
            { a: 'support-triage', w: 'refund $500 via stripe', t: '2m' },
            { a: 'data-pipeliner', w: 'export 50k rows', t: '1m' },
          ].map((r, i) => (
            <div key={i} style={{ borderBottom: '1.5px dashed var(--ink-faint)', padding: '4px 0', fontSize: 12 }}>
              <div className="row between">
                <strong>{r.a}</strong>
                <span style={{ color: 'var(--warn)' }}>{r.t}</span>
              </div>
              <div style={{ color: 'var(--ink-soft)', margin: '2px 0 4px' }}>{r.w}</div>
              <div className="row" style={{ gap: 4 }}>
                <button className="tag tag-ok">approve</button>
                <button className="tag tag-danger">reject</button>
                <button className="tag">trace</button>
              </div>
            </div>
          ))}
        </div>
      </SketchBox>
    </div>

    {/* event stream + heatmap + scrub feed */}
    <div className="grid-3" style={{ gap: 8, marginBottom: 8 }}>
      <SketchBox style={{ gridColumn: 'span 2' }}>
        <Kicker>live event stream · ▶ tail -f · pause</Kicker>
        <pre style={{ fontSize: 11, lineHeight: 1.5, margin: '6px 0 0', maxHeight: 220, overflow: 'auto' }}>
{EVENTS.concat(EVENTS).map((e, i) => {
  const c = e.decision === 'BLOCKED' || e.decision === 'LEAK' ? '#c1272d'
          : e.decision === 'APPROVAL' ? '#d97706'
          : e.decision === 'REDACTED' || e.decision === 'SCRUB' ? '#6b21a8'
          : '#2e7d32';
  return (
    <div key={i} style={{ color: c }}>
      {`${e.t}  [${e.layer.padEnd(5)}]  ${e.decision.padEnd(8)}  ${e.agent.padEnd(18)}  ${e.action}  // ${e.why}`}
    </div>
  );
})}
        </pre>
      </SketchBox>

      <SketchBox>
        <Kicker>tool / MCP heatmap · 1h</Kicker>
        <Placeholder label="grid 8x6 · agent × tool · cell = call count" h={220} />
      </SketchBox>
    </div>

    {/* policy editor inline */}
    <div className="grid-2" style={{ gap: 8 }}>
      <SketchBox>
        <Kicker>active policy · v3.4.1 · click rule to edit</Kicker>
        <pre style={{ fontSize: 11, margin: '6px 0 0' }}>
{`policies:
  - id: WRITE_DENY_READ_ONLY        hits: 118  ▶
  - id: SHELL_INJECTION_DENY        hits: 74   ▶
  - id: SENSITIVE_PATH_BLOCKLIST    hits: 52   ▶
  - id: OUTBOUND_EMAIL_APPROVAL     hits: 41   ▶
  - id: SECRET_PATTERN_AKIA         hits: 41   ▶
  - id: PII_REDACT_BEFORE_LLM       hits: 106  ▶
  - id: SHELL_DESCENDANT_OF_AGENT   hits: 0    ▶ (proposed)`}
        </pre>
        <div className="row" style={{ gap: 4, marginTop: 6 }}>
          <button className="tag">+ inject rule (live)</button>
          <button className="tag">simulate</button>
          <button className="tag">rollback v3.4.0</button>
        </div>
      </SketchBox>

      <SketchBox>
        <Kicker>incident · 1 active</Kicker>
        <div style={{ background: 'var(--danger-soft)', padding: 8, borderRadius: 4, fontSize: 12 }}>
          <strong style={{ color: 'var(--danger)' }}>INC-2841 · suspected PII leak</strong>
          <div>agent: research-agent · trace: run_92862</div>
          <div>provider: openai (api.openai.com)</div>
          <div>evidence: tls plaintext · pii_detected=true · scrub_applied=false</div>
          <div className="row" style={{ gap: 4, marginTop: 6 }}>
            <button className="tag tag-danger">page on-call</button>
            <button className="tag">freeze agent</button>
            <button className="tag">open trace</button>
          </div>
        </div>
      </SketchBox>
    </div>
  </div>
);

// expose to global
Object.assign(window, { V1, V2, V3, V4, V5, MOCK });
