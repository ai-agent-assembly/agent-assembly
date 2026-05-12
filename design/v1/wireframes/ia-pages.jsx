/* global React */
const { useState: useStateIA } = React;

const IASketch = ({ children, style, thick, dashed, double, className = '' }) => (
  <div
    className={`sketch ${thick ? 'sketch-thick' : ''} ${dashed ? 'sketch-dashed' : ''} ${double ? 'sketch-double' : ''} ${className}`}
    style={style}
  >
    {children}
  </div>
);

const IATag = ({ children, kind }) => (
  <span className={`tag ${kind ? `tag-${kind}` : ''}`}>{children}</span>
);

const IAKick = ({ children }) => <div className="kicker">{children}</div>;

const IAPlaceholder = ({ label, h = 60 }) => (
  <div className="placeholder" style={{ height: h }}>{label}</div>
);

// =============================================================
// Sitemap — global navigation overview
// =============================================================

const PAGES = [
  { id: 'overview',   name: '1 · Overview',           who: 'Eng VP / 合規',   from: 'V4 + V3', why: '一眼看 fleet 健康度' },
  { id: 'fleet',      name: '2 · Fleet',              who: 'SRE / DevOps',    from: 'V2 + V5', why: 'agent 管理、搜尋、suspend/resume' },
  { id: 'capability', name: '3 · Capability ⭐',      who: 'Security',        from: 'V1',      why: '能力縮限設定 — 差異化核心' },
  { id: 'policy',     name: '4 · Policy',             who: 'Security / Plat', from: '新',       why: '規則編輯 / simulate / rollout' },
  { id: 'live',       name: '5 · Live Ops',           who: 'on-call',         from: 'V5',      why: '事件流 + 審批' },
  { id: 'scrub',      name: '6 · Secret Scrubbing ⭐', who: 'Security',        from: '新',       why: '機敏淨化中心' },
];

const Sitemap = () => (
  <div className="wf" style={{ width: 1280, minHeight: 760 }}>
    <div style={{ marginBottom: 12 }}>
      <IAKick>information architecture · stage A · 全景圖</IAKick>
      <h1 style={{ marginTop: 4 }}>Agent Assembly Dashboard · 6 大頁面結構</h1>
      <div className="note">每頁服務不同角色與深度。⭐ 是這產品最大的兩個亮點頁，建議下一階段進 hi-fi。</div>
    </div>

    <div className="grid-2" style={{ gap: 16, alignItems: 'flex-start' }}>
      {/* left — left-rail nav mockup */}
      <IASketch thick style={{ minHeight: 600 }}>
        <IAKick>persistent left rail · 在每一頁都看得到</IAKick>
        <h3 style={{ marginTop: 4 }}>Navigation</h3>
        <div className="col" style={{ gap: 6, marginTop: 10 }}>
          <div style={{ borderBottom: '2px solid var(--line)', paddingBottom: 6, marginBottom: 6 }}>
            <div className="row between">
              <strong>AA Agent Assembly</strong>
              <IATag kind="ok">runtime ok</IATag>
            </div>
            <small className="wf-mono">org: acme · env: prod</small>
          </div>
          {PAGES.map((p) => (
            <div key={p.id} className="row between" style={{
              padding: '6px 8px',
              border: p.id === 'overview' ? '2px solid var(--line)' : '1.5px dashed var(--ink-faint)',
              background: p.id === 'overview' ? 'var(--paper-warm)' : 'transparent',
              borderRadius: 4,
            }}>
              <div>
                <strong>{p.name}</strong>
                <div style={{ fontSize: 12, color: 'var(--ink-soft)' }}>{p.who} · from {p.from}</div>
              </div>
              <span style={{ fontSize: 11, color: 'var(--ink-faint)' }}>{p.why}</span>
            </div>
          ))}
          <div style={{ marginTop: 12, paddingTop: 8, borderTop: '1.5px dashed var(--ink-faint)' }}>
            <small className="wf-mono">↳ settings · audit export · API keys</small>
          </div>
        </div>
      </IASketch>

      {/* right — flow between pages */}
      <IASketch thick style={{ minHeight: 600 }}>
        <IAKick>cross-page navigation · drill-down 路徑</IAKick>
        <h3 style={{ marginTop: 4 }}>How users flow between pages</h3>
        <svg viewBox="0 0 600 540" style={{ width: '100%', height: 520, marginTop: 8 }}>
          <defs>
            <marker id="ia-a" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L7,4 L0,8 z" fill="#1a1a1a" />
            </marker>
          </defs>
          {/* overview hub */}
          <rect x="220" y="20" width="160" height="60" rx="6" className="stroke-thick fill-paper" />
          <text x="300" y="44" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">1 · Overview</text>
          <text x="300" y="62" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">posture · drill-down hub</text>

          {/* level 2 — operating views */}
          <rect x="20" y="160" width="140" height="56" rx="6" className="stroke-thick fill-paper" />
          <text x="90" y="184" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">2 · Fleet</text>
          <text x="90" y="200" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">list / search / group</text>

          <rect x="230" y="160" width="140" height="56" rx="6" className="stroke-thick fill-paper" style={{ fill: '#fce7c8' }} />
          <text x="300" y="184" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">5 · Live Ops</text>
          <text x="300" y="200" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">stream + approvals</text>

          <rect x="440" y="160" width="140" height="56" rx="6" className="stroke-thick fill-paper" style={{ fill: '#e8dbf3' }} />
          <text x="510" y="184" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">6 · Scrubbing ⭐</text>
          <text x="510" y="200" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">leak posture</text>

          {/* level 3 — control surfaces */}
          <rect x="60" y="320" width="200" height="60" rx="6" className="stroke-thick fill-paper" style={{ fill: '#d6dffa' }} />
          <text x="160" y="344" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">3 · Capability ⭐</text>
          <text x="160" y="362" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">claimed vs effective</text>

          <rect x="340" y="320" width="200" height="60" rx="6" className="stroke-thick fill-paper" />
          <text x="440" y="344" textAnchor="middle" fontFamily="Kalam" fontSize="13" fontWeight="700">4 · Policy</text>
          <text x="440" y="362" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">edit · simulate · rollout</text>

          {/* deep dives */}
          <rect x="40" y="450" width="180" height="56" rx="6" className="stroke-ink fill-paper" style={{ strokeDasharray: '4 3' }} />
          <text x="130" y="474" textAnchor="middle" fontFamily="Kalam" fontSize="12" fontWeight="700">Agent Detail</text>
          <text x="130" y="490" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">passport · trust · trace</text>

          <rect x="240" y="450" width="160" height="56" rx="6" className="stroke-ink fill-paper" style={{ strokeDasharray: '4 3' }} />
          <text x="320" y="474" textAnchor="middle" fontFamily="Kalam" fontSize="12" fontWeight="700">Trace View</text>
          <text x="320" y="490" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">single run timeline</text>

          <rect x="420" y="450" width="160" height="56" rx="6" className="stroke-ink fill-paper" style={{ strokeDasharray: '4 3' }} />
          <text x="500" y="474" textAnchor="middle" fontFamily="Kalam" fontSize="12" fontWeight="700">Policy Simulator</text>
          <text x="500" y="490" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">replay 24h traffic</text>

          {/* edges from overview */}
          <path d="M 260 80 Q 180 120 110 160" className="stroke-ink" markerEnd="url(#ia-a)" />
          <path d="M 300 80 L 300 160" className="stroke-ink" markerEnd="url(#ia-a)" />
          <path d="M 340 80 Q 420 120 490 160" className="stroke-ink" markerEnd="url(#ia-a)" />

          {/* fleet -> agent detail / capability */}
          <path d="M 90 216 Q 90 280 130 450" className="stroke-dashed" markerEnd="url(#ia-a)" />
          <path d="M 110 216 Q 130 270 160 320" className="stroke-dashed" markerEnd="url(#ia-a)" />

          {/* live -> trace / approvals */}
          <path d="M 290 216 Q 290 320 320 450" className="stroke-dashed" markerEnd="url(#ia-a)" />

          {/* capability -> policy / simulator */}
          <path d="M 260 350 L 340 350" className="stroke-ink" markerEnd="url(#ia-a)" />
          <path d="M 460 380 Q 480 410 500 450" className="stroke-dashed" markerEnd="url(#ia-a)" />

          {/* scrubbing -> policy */}
          <path d="M 510 216 Q 510 270 480 320" className="stroke-dashed" markerEnd="url(#ia-a)" />
        </svg>
        <div className="row" style={{ gap: 10, marginTop: 4, fontSize: 12 }}>
          <span><span style={{ borderBottom: '2px solid var(--ink)', paddingBottom: 1 }}>━━</span> primary nav</span>
          <span><span style={{ borderBottom: '2px dashed var(--ink)', paddingBottom: 1 }}>┄┄</span> drill-down</span>
        </div>
      </IASketch>
    </div>
  </div>
);

// =============================================================
// Page thumbnails — quick low-detail page sketches
// =============================================================

const PageHeader = ({ n, name, who, primaryCtas }) => (
  <div className="row between" style={{ marginBottom: 8 }}>
    <div>
      <IAKick>page {n} · {who}</IAKick>
      <h2 style={{ marginTop: 2 }}>{name}</h2>
    </div>
    <div className="row" style={{ gap: 4 }}>
      {primaryCtas.map((c, i) => <IATag key={i} kind={c.kind}>{c.label}</IATag>)}
    </div>
  </div>
);

const PageShell = ({ children, page }) => (
  <div className="wf" style={{ width: 1280, minHeight: 760 }}>
    <div className="row" style={{ gap: 10, marginBottom: 8 }}>
      <IASketch style={{ width: 220, padding: 8 }}>
        <small className="wf-mono">left rail</small>
        <div className="col" style={{ gap: 3, marginTop: 6, fontSize: 12 }}>
          {PAGES.map((p) => (
            <div key={p.id} style={{
              padding: '4px 6px',
              background: p.id === page ? 'var(--ink)' : 'transparent',
              color: p.id === page ? 'var(--paper)' : 'var(--ink)',
              borderRadius: 3,
            }}>{p.name}</div>
          ))}
        </div>
      </IASketch>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  </div>
);

// 1. Overview
const PageOverview = () => (
  <PageShell page="overview">
    <PageHeader n="1" name="Overview · 高階姿態" who="Eng VP / 合規"
      primaryCtas={[{ label: 'last 24h', kind: 'info' }, { label: 'export PDF' }]} />
    <div className="grid-4" style={{ gap: 8, marginBottom: 8 }}>
      <IASketch><div className="metric-label">fleet</div><div className="metric-big">142</div></IASketch>
      <IASketch><div className="metric-label">blocked</div><div className="metric-big" style={{ color: 'var(--danger)' }}>312</div></IASketch>
      <IASketch><div className="metric-label">scrubbed</div><div className="metric-big" style={{ color: 'var(--scrub)' }}>226</div></IASketch>
      <IASketch><div className="metric-label">incidents</div><div className="metric-big" style={{ color: 'var(--danger)' }}>1</div></IASketch>
    </div>
    <div className="grid-2" style={{ gap: 8 }}>
      <IASketch thick><IAKick>城堡護城河 (from V4)</IAKick><IAPlaceholder label="concentric circles · 4 attack arrows" h={300} /></IASketch>
      <div className="col">
        <IASketch><IAKick>三層防禦小卡</IAKick><IAPlaceholder label="L1 / L2 / L3 stacked counts" h={120} /></IASketch>
        <IASketch><IAKick>趨勢</IAKick><IAPlaceholder label="7-day stacked area chart" h={140} /></IASketch>
      </div>
    </div>
    <IASketch dashed style={{ marginTop: 8 }}>
      <IAKick>break-throughs</IAKick>
      <small>列出近期 incident · 點擊 → drill into Trace View</small>
    </IASketch>
  </PageShell>
);

// 2. Fleet
const PageFleet = () => (
  <PageShell page="fleet">
    <PageHeader n="2" name="Fleet · agent 管理" who="SRE / DevOps"
      primaryCtas={[{ label: '+ register' }, { label: 'bulk: suspend' }, { label: 'group by framework', kind: 'info' }]} />
    <div className="row" style={{ gap: 8, marginBottom: 8 }}>
      <IASketch style={{ flex: 1, padding: 8 }}>
        <div className="row" style={{ gap: 4, fontSize: 12 }}>
          <IATag>search: name / DID / tool</IATag>
          <IATag>filter: framework</IATag>
          <IATag>filter: trust ≤ 70</IATag>
          <IATag>filter: status</IATag>
          <IATag>filter: mode</IATag>
        </div>
      </IASketch>
    </div>
    <IASketch>
      <IAKick>agents · sortable table · row click → Agent Detail drawer</IAKick>
      <IAPlaceholder label="cols: did · name · framework · trust · mode · blocked · scrubbed · last seen · actions" h={360} />
    </IASketch>
    <IASketch dashed style={{ marginTop: 8 }}>
      <IAKick>right-side drawer (slides in on row click)</IAKick>
      <div className="row" style={{ gap: 8 }}>
        <IAPlaceholder label="passport (V2) · trust breakdown" h={120} />
        <IAPlaceholder label="recent traces · suspend / resume / rotate cred" h={120} />
      </div>
    </IASketch>
  </PageShell>
);

// 3. Capability ⭐
const PageCapability = () => (
  <PageShell page="capability">
    <PageHeader n="3 ⭐" name="Capability · 能力縮限設定" who="Security"
      primaryCtas={[{ label: 'matrix', kind: 'ok' }, { label: 'per-resource' }, { label: 'per-agent' }, { label: 'simulate change', kind: 'info' }]} />
    <IASketch thick style={{ marginBottom: 8 }}>
      <IAKick>差異化核心 · claimed vs effective</IAKick>
      <h3>What agents say they can do — and what Assembly actually allows</h3>
      <IAPlaceholder label="big matrix · agents (rows) × actions (cols) · cells = allow / narrow / deny / approval" h={260} />
      <small className="note">每格 hover → tooltip 顯示是哪條 policy 縮限的；click → 開 inline policy editor</small>
    </IASketch>
    <div className="grid-2" style={{ gap: 8 }}>
      <IASketch>
        <IAKick>per-resource view</IAKick>
        <h4>Who can touch resource X?</h4>
        <IAPlaceholder label="resource picker → list of agents with effective perms" h={140} />
      </IASketch>
      <IASketch>
        <IAKick>per-agent view</IAKick>
        <h4>What can agent X actually do?</h4>
        <IAPlaceholder label="agent picker → flat list of resources + effective verbs" h={140} />
      </IASketch>
    </div>
    <IASketch dashed style={{ marginTop: 8 }}>
      <IAKick>narrowing template gallery</IAKick>
      <small>常用模板：read-only · workspace-scope · approval-on-write · scrub-egress · no-shell</small>
    </IASketch>
  </PageShell>
);

// 4. Policy
const PagePolicy = () => (
  <PageShell page="policy">
    <PageHeader n="4" name="Policy · 規則編輯 / simulate / rollout" who="Security / Platform"
      primaryCtas={[{ label: '+ new rule' }, { label: 'simulate', kind: 'info' }, { label: 'rollback' }]} />
    <div className="grid-2" style={{ gap: 8, marginBottom: 8 }}>
      <IASketch>
        <IAKick>policy list · v3.4.1 active</IAKick>
        <IAPlaceholder label="rule rows · id · scope · hits · status (active/proposed)" h={260} />
      </IASketch>
      <IASketch>
        <IAKick>editor (YAML / Rego / Wasm upload)</IAKick>
        <IAPlaceholder label="syntax-highlighted code editor" h={260} />
      </IASketch>
    </div>
    <IASketch thick>
      <IAKick>simulate panel ⭐ — 把規則套到過去 24h 流量重放</IAKick>
      <div className="grid-3" style={{ gap: 6, marginTop: 6 }}>
        <IAPlaceholder label="would-block delta" h={80} />
        <IAPlaceholder label="false-positive samples" h={80} />
        <IAPlaceholder label="affected agents list" h={80} />
      </div>
      <div className="row" style={{ gap: 4, marginTop: 8 }}>
        <IATag kind="ok">canary 5%</IATag>
        <IATag>canary 25%</IATag>
        <IATag>full rollout</IATag>
      </div>
    </IASketch>
  </PageShell>
);

// 5. Live Ops
const PageLive = () => (
  <PageShell page="live">
    <PageHeader n="5" name="Live Ops · 事件流 + 審批" who="on-call SRE"
      primaryCtas={[{ label: 'pause', kind: 'warn' }, { label: 'filter' }, { label: 'page on-call', kind: 'danger' }]} />
    <div className="grid-3" style={{ gap: 8 }}>
      <IASketch style={{ gridColumn: 'span 2' }}>
        <IAKick>tail -f · live event stream</IAKick>
        <IAPlaceholder label="terminal-style scroll · color by decision" h={340} />
      </IASketch>
      <IASketch>
        <IAKick>approval queue · 8 waiting</IAKick>
        <IAPlaceholder label="cards · approve / reject / view trace" h={340} />
      </IASketch>
    </div>
    <div className="grid-2" style={{ gap: 8, marginTop: 8 }}>
      <IASketch>
        <IAKick>incident list</IAKick>
        <IAPlaceholder label="active incidents + freeze agent / open trace" h={120} />
      </IASketch>
      <IASketch dashed>
        <IAKick>quick policy injection (live · scoped to incident)</IAKick>
        <IAPlaceholder label="one-line rule · auto-expire 1h" h={120} />
      </IASketch>
    </div>
  </PageShell>
);

// 6. Secret Scrubbing ⭐
const PageScrub = () => (
  <PageShell page="scrub">
    <PageHeader n="6 ⭐" name="Secret Scrubbing · 機敏淨化中心" who="Security"
      primaryCtas={[{ label: '+ pattern' }, { label: 'upload secret dict' }, { label: 'leak audit', kind: 'danger' }]} />
    <div className="grid-3" style={{ gap: 8, marginBottom: 8 }}>
      <IASketch><div className="metric-label">scrubbed today</div><div className="metric-big" style={{ color: 'var(--scrub)' }}>226</div></IASketch>
      <IASketch><div className="metric-label">patterns active</div><div className="metric-big">38</div></IASketch>
      <IASketch><div className="metric-label">false negatives</div><div className="metric-big" style={{ color: 'var(--danger)' }}>1</div><small>verified leaks</small></IASketch>
    </div>
    <div className="grid-2" style={{ gap: 8 }}>
      <IASketch>
        <IAKick>pattern library</IAKick>
        <IAPlaceholder label="rows: pattern · type (regex/entropy/dict) · hits · last hit · enabled" h={220} />
      </IASketch>
      <IASketch>
        <IAKick>egress posture · per provider</IAKick>
        <IAPlaceholder label="openai / anthropic / gemini · scrub success rate · pii_detected vs scrubbed" h={220} />
      </IASketch>
    </div>
    <IASketch dashed style={{ marginTop: 8 }}>
      <IAKick>leak audit · false negatives</IAKick>
      <small>已洩漏案例追溯：哪個 pattern 應該命中卻沒命中、補丁建議</small>
    </IASketch>
  </PageShell>
);

Object.assign(window, {
  Sitemap, PageOverview, PageFleet, PageCapability, PagePolicy, PageLive, PageScrub,
});
