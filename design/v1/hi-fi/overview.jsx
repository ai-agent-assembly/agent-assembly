/* global React */
const { useState: useSOV } = React;

// ============================================================
// Overview page — exec-level health, three-layer summary,
// drill-down hooks into Capability / Policy / Live / Fleet
// ============================================================

function HealthRing({ score, label, sublabel, color }) {
  const c = 2 * Math.PI * 30;
  const dash = (score / 100) * c;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <svg width="76" height="76" viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--line)" strokeWidth="6" />
        <circle cx="38" cy="38" r="30" fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${c}`} strokeLinecap="round"
          transform="rotate(-90 38 38)" />
        <text x="38" y="42" textAnchor="middle" fontFamily="JetBrains Mono"
          fontSize="16" fontWeight="700" fill="var(--ink)">{score}</text>
      </svg>
      <div>
        <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>{label}</div>
        <div style={{ fontSize: 13, color: 'var(--ink-2)', marginTop: 2 }}>{sublabel}</div>
      </div>
    </div>
  );
}

function MiniBar({ data, color, max }) {
  const m = max || Math.max(...data);
  return (
    <svg viewBox={`0 0 ${data.length * 8} 24`} preserveAspectRatio="none" style={{ width: '100%', height: 28 }}>
      {data.map((v, i) => (
        <rect key={i} x={i * 8} y={24 - (v / m) * 22} width={6} height={(v / m) * 22} fill={color} opacity={0.85} />
      ))}
    </svg>
  );
}

function LayerCard({ icon, name, sub, stats, accent, footer, onClick }) {
  return (
    <div className="card" style={{ borderLeft: `3px solid ${accent}`, cursor: 'pointer' }} onClick={onClick}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>
            {icon} · {name}
          </div>
          <div style={{ fontSize: 14, marginTop: 2, color: 'var(--ink-2)' }}>{sub}</div>
        </div>
        <span className="chip" style={{ fontSize: 9 }}>open ↗</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginTop: 14 }}>
        {stats.map((s, i) => (
          <div key={i}>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 22, fontWeight: 700, color: s.color || 'var(--ink)' }}>{s.v}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.5, fontFamily: 'JetBrains Mono' }}>{s.l}</div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px dashed var(--line)', fontSize: 11, color: 'var(--ink-3)' }}>
        {footer}
      </div>
    </div>
  );
}

function OverviewPage({ goRoute, openCell, openApprovals }) {
  const [window24h, setWindow24h] = useSOV('24h');
  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="overview" />;
  if (ps === 'empty')   return <window.EmptyState page="overview" onCta={() => goRoute && goRoute('onboarding')} onSecondary={() => {}} />;
  if (ps === 'error')   return <window.ErrorState kind="generic" onRetry={() => {}} onSecondary={() => {}} />;
  const flagged = window.AGENTS.filter((a) => a.flagged).length;
  const total = window.AGENTS.length;
  const blocked = window.AGENTS.reduce((s, a) => s + a.blocked24h, 0);
  const scrubbed = window.AGENTS.reduce((s, a) => s + a.scrubbed24h, 0);
  const sample24 = [12, 18, 9, 22, 16, 28, 19, 24, 31, 18, 14, 22, 26, 19, 15, 23, 30, 25, 19, 27, 33, 21, 16, 14];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Overview
            <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14, marginLeft: 8 }}>
              · 治理態勢儀表
            </span>
          </h1>
          <div className="page-sub">
            Posture, enforcement, and exposure across all agents — last {window24h}.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['1h', '24h', '7d', '30d'].map((w) => (
            <button key={w} className={`btn btn-sm ${w === window24h ? 'btn-active' : ''}`} onClick={() => setWindow24h(w)}>{w}</button>
          ))}
          <button className="btn">⏏ export report</button>
        </div>
      </div>

      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* Hero strip — three layer rings + flagged callout */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
            <div>
              <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>posture · three-layer defense</div>
              <h2 style={{ margin: '4px 0 0', fontSize: 18 }}>Enforcement is healthy. <span style={{ color: 'var(--danger)', fontWeight: 600 }}>1 agent over-permissioned.</span></h2>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn btn-sm" onClick={() => goRoute('capability')}>open Capability →</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, paddingTop: 12, borderTop: '1px solid var(--line)' }}>
            <HealthRing score={97} label="L1 · identity" sublabel="DID verified · 0 spoof attempts" color="#1a1a1a" />
            <HealthRing score={73} label="L2 · capability" sublabel="1 over-permissioned agent" color="#b8291e" />
            <HealthRing score={91} label="L3 · scrub" sublabel="226 secrets stripped today" color="#5a1a8a" />
            <HealthRing score={84} label="overall" sublabel="weighted across all layers" color="#22592a" />
          </div>
        </div>

        {/* Top issues row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 12 }}>
          <div className="card" style={{ borderLeft: '3px solid var(--danger)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--danger)' }}>
                ▲ critical · top issue
              </div>
              <span className="chip chip-danger" style={{ fontSize: 9 }}>1 of 1</span>
            </div>
            <h3 style={{ margin: 0, fontSize: 16 }}>research-bot-04 is over-permissioned</h3>
            <div style={{ fontSize: 12, color: 'var(--ink-3)', marginTop: 4 }}>
              Self-claimed full access on <b>6 of 8 resources</b>. Effective allows narrowed by P-014, P-021, P-035 — but remaining attack surface includes <code>shell.exec</code>, <code>http.*</code>, and <code>gmail/send</code>.
            </div>
            <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
              <button className="btn btn-sm" onClick={() => openCell('research-bot-04', 's3', 'write')}>inspect cell</button>
              <button className="btn btn-sm" onClick={() => goRoute('policy')}>review proposed P-066 →</button>
              <button className="btn btn-sm btn-ghost">snooze 24h</button>
            </div>
          </div>

          <div className="card">
            <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>
              ⚑ pending approvals
            </div>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 32, fontWeight: 700, marginTop: 4, color: 'var(--info)' }}>{window.APPROVALS.length}</div>
            <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>
              <span style={{ color: 'var(--danger)', fontWeight: 600 }}>2 urgent (PII)</span> · oldest 6m
            </div>
            <div style={{ display: 'flex', gap: 6, marginTop: 12 }}>
              <button className="btn btn-sm" onClick={openApprovals}>review queue →</button>
              <button className="btn btn-sm" onClick={() => goRoute('live')}>open Live Ops</button>
            </div>
          </div>
        </div>

        {/* Three-layer detail cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          <LayerCard
            icon="L1"
            name="Identity"
            sub="DID + trust scoring"
            accent="#1a1a1a"
            stats={[
              { l: 'agents verified', v: total },
              { l: 'spoof blocks', v: 2, color: 'var(--danger)' },
              { l: 'avg trust', v: 71 },
            ]}
            footer={<>2 spoofing attempts blocked at edge · all from <code>finance-bot</code> (now suspended)</>}
            onClick={() => goRoute('fleet')}
          />
          <LayerCard
            icon="L2"
            name="Capability"
            sub="Policy enforcement"
            accent="#8a5a00"
            stats={[
              { l: 'active policies', v: window.POLICIES.length },
              { l: 'blocked / 24h', v: blocked, color: 'var(--danger)' },
              { l: 'narrowed', v: 412, color: 'var(--warn)' },
            ]}
            footer={<>1 proposed policy <b>P-066</b> ready for simulate → rollout</>}
            onClick={() => goRoute('capability')}
          />
          <LayerCard
            icon="L3"
            name="Scrub"
            sub="Secret sanitization"
            accent="#5a1a8a"
            stats={[
              { l: 'patterns', v: 47 },
              { l: 'stripped / 24h', v: scrubbed, color: 'var(--scrub)' },
              { l: 'leaked', v: 0, color: 'var(--ok)' },
            ]}
            footer={<>0 secrets reached external endpoints in last 30d</>}
            onClick={() => goRoute('scrub')}
          />
        </div>

        {/* Activity strip + recent events */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 12 }}>
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>
                ▤ enforcement timeline · 24h
              </div>
              <div style={{ display: 'flex', gap: 12, fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                <span style={{ color: 'var(--ok)' }}>● allow</span>
                <span style={{ color: 'var(--warn)' }}>● narrow</span>
                <span style={{ color: 'var(--danger)' }}>● deny</span>
                <span style={{ color: 'var(--scrub)' }}>● scrub</span>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '60px 1fr', gap: 4, alignItems: 'center', rowGap: 4 }}>
              <div style={{ fontSize: 10, color: 'var(--ink-4)', fontFamily: 'JetBrains Mono' }}>allow</div>
              <MiniBar data={sample24} color="#22592a" />
              <div style={{ fontSize: 10, color: 'var(--ink-4)', fontFamily: 'JetBrains Mono' }}>narrow</div>
              <MiniBar data={sample24.map((x) => Math.round(x * 0.7))} color="#8a5a00" />
              <div style={{ fontSize: 10, color: 'var(--ink-4)', fontFamily: 'JetBrains Mono' }}>deny</div>
              <MiniBar data={sample24.map((x) => Math.round(x * 0.18))} color="#b8291e" />
              <div style={{ fontSize: 10, color: 'var(--ink-4)', fontFamily: 'JetBrains Mono' }}>scrub</div>
              <MiniBar data={sample24.map((x) => Math.round(x * 0.4))} color="#5a1a8a" />
            </div>
            <div style={{ marginTop: 8, fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', display: 'flex', justifyContent: 'space-between' }}>
              <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>now</span>
            </div>
          </div>

          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>
                ◷ recent decisions
              </div>
              <button className="btn btn-sm" onClick={() => goRoute('live')}>tail →</button>
            </div>
            {[
              { t: '14:02:08', d: 'deny',   a: 'research-bot-04', r: 'shell.exec', col: 'var(--danger)' },
              { t: '14:01:54', d: 'narrow', a: 'support-triage',  r: 'pg.users',   col: 'var(--warn)' },
              { t: '14:01:41', d: 'scrub',  a: 'sales-outreach',  r: 'gmail/send', col: 'var(--scrub)' },
              { t: '14:01:22', d: 'approval', a: 'finance-bot',   r: 'shell:psql', col: 'var(--info)' },
              { t: '14:00:58', d: 'deny',   a: 'finance-bot',     r: 's3.write',   col: 'var(--danger)' },
            ].map((x, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '60px 70px 1fr', gap: 8, padding: '5px 0', borderBottom: '1px dashed var(--line)', fontFamily: 'JetBrains Mono', fontSize: 11 }}>
                <span style={{ color: 'var(--ink-4)' }}>{x.t}</span>
                <span style={{ color: x.col, fontWeight: 600 }}>{x.d}</span>
                <span style={{ color: 'var(--ink-2)' }}>{x.a} <span style={{ color: 'var(--ink-4)' }}>· {x.r}</span></span>
              </div>
            ))}
          </div>
        </div>

        {/* Fleet snapshot */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>
              ▦ fleet snapshot · {total} agents
            </div>
            <button className="btn btn-sm" onClick={() => goRoute('fleet')}>open Fleet →</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <div><div style={{ fontFamily: 'JetBrains Mono', fontSize: 26, fontWeight: 700 }}>{total}</div><div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)' }}>TOTAL AGENTS</div></div>
            <div><div style={{ fontFamily: 'JetBrains Mono', fontSize: 26, fontWeight: 700, color: 'var(--ok)' }}>{total - 1}</div><div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)' }}>ENFORCING</div></div>
            <div><div style={{ fontFamily: 'JetBrains Mono', fontSize: 26, fontWeight: 700, color: 'var(--warn)' }}>1</div><div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)' }}>SHADOW MODE</div></div>
            <div><div style={{ fontFamily: 'JetBrains Mono', fontSize: 26, fontWeight: 700, color: 'var(--danger)' }}>{flagged}</div><div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)' }}>FLAGGED</div></div>
          </div>
        </div>
      </div>
    </>
  );
}

Object.assign(window, { OverviewPage });
