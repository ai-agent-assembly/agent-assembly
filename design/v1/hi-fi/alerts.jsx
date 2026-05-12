/* global React */
const { useState: useAL } = React;

/* ============================================================
   Alerts page  —  AAASM-118
   Mirrors GET /api/v1/alerts + WS /ws/events (violation/budget)
   ============================================================ */

const AL_SEV = {
  critical: { label: 'critical', chipCls: 'chip-danger', dot: 'var(--danger)' },
  warning:  { label: 'warning',  chipCls: 'chip-warn',   dot: 'var(--warn)'   },
};
const AL_CAT = {
  policy_violation: { label: 'policy viol.', chipCls: 'chip-danger' },
  budget:           { label: 'budget',        chipCls: 'chip-warn'   },
  anomaly:          { label: 'anomaly',       chipCls: 'chip-info'   },
};

function AlertRow({ a, expanded, onToggle, goAgent, goPolicy }) {
  const sev = AL_SEV[a.severity] || AL_SEV.warning;
  const cat = AL_CAT[a.category] || { label: a.category, chipCls: '' };

  return (
    <div
      style={{
        borderBottom: '1px solid var(--line)',
        borderLeft: `3px solid ${a.severity === 'critical' ? 'var(--danger)' : 'var(--warn)'}`,
        background: expanded ? 'var(--paper-2)' : 'transparent',
        cursor: 'pointer',
      }}
      onClick={onToggle}
    >
      {/* Main row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, padding: '10px 20px' }}>
        <div style={{ paddingTop: 2, flexShrink: 0 }}>
          <span className={`chip ${sev.chipCls}`}>{sev.label}</span>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3, flexWrap: 'wrap' }}>
            <span className={`chip ${cat.chipCls}`} style={{ fontSize: 9 }}>{cat.label}</span>
            {a.agent_id && (
              <span
                onClick={(e) => { e.stopPropagation(); goAgent && goAgent(a.agent_id); }}
                style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-2)', textDecoration: 'underline dotted', cursor: 'pointer' }}
              >{a.agent_id}</span>
            )}
          </div>
          <div style={{ fontSize: 13, color: 'var(--ink)', lineHeight: 1.45 }}>{a.message}</div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', marginTop: 4 }}>
            {a.id} · {a.age}
          </div>
        </div>
        <div style={{ color: 'var(--ink-4)', fontSize: 10, paddingTop: 4, flexShrink: 0, fontFamily: 'JetBrains Mono, monospace' }}>
          {expanded ? '▲' : '▼'}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ background: 'var(--paper-3)', borderTop: '1px dashed var(--line)', padding: '12px 20px 14px' }}>
          <div className="kv" style={{ gridTemplateColumns: '100px 1fr', marginBottom: 10 }}>
            <span className="kv-k">timestamp</span>
            <span className="kv-v mono" style={{ fontSize: 11 }}>{a.timestamp}</span>
            <span className="kv-k">severity</span>
            <span className="kv-v"><span className={`chip ${sev.chipCls}`}>{a.severity}</span></span>
            <span className="kv-k">category</span>
            <span className="kv-v"><span className={`chip ${cat.chipCls}`}>{cat.label}</span></span>
            {a.agent_id && (
              <><span className="kv-k">agent</span><span className="kv-v mono" style={{ fontSize: 11 }}>{a.agent_id}</span></>
            )}
            {a.policy_id && (
              <><span className="kv-k">policy</span><span className="kv-v mono" style={{ fontSize: 11 }}>{a.policy_id}</span></>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {a.agent_id && (
              <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); goAgent && goAgent(a.agent_id); }}>
                Agent detail →
              </button>
            )}
            {a.policy_id && (
              <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); goPolicy && goPolicy(a.policy_id); }}>
                Policy {a.policy_id} →
              </button>
            )}
            <button className="btn btn-sm btn-ghost" style={{ marginLeft: 'auto' }} onClick={(e) => e.stopPropagation()}>
              Acknowledge
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function AlertsPage({ goAgent, goPolicy, toast }) {
  const [sev, setSev] = useAL('all');
  const [cat, setCat] = useAL('all');
  const [q,   setQ]   = useAL('');
  const [exp, setExp] = useAL(null);

  const all = window.ALERTS || [];

  const counts = {
    critical:  all.filter((a) => a.severity === 'critical').length,
    warning:   all.filter((a) => a.severity === 'warning').length,
    violation: all.filter((a) => a.category === 'policy_violation').length,
    budget:    all.filter((a) => a.category === 'budget').length,
    anomaly:   all.filter((a) => a.category === 'anomaly').length,
  };

  const filtered = all.filter((a) => {
    if (sev !== 'all' && a.severity !== sev) return false;
    if (cat !== 'all' && a.category !== cat) return false;
    if (q) {
      const haystack = `${a.message} ${a.agent_id || ''} ${a.id}`.toLowerCase();
      if (!haystack.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Page header */}
      <div className="page-head">
        <div>
          <div className="page-title">Alerts</div>
          <div className="page-sub">
            Policy violations, budget threshold events, and anomaly detections across all governed agents.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-sm" onClick={() => toast('Acknowledged all (mock)')}>Acknowledge all</button>
          <button className="btn btn-sm btn-primary" onClick={() => toast('Alert rule config — Sprint 3')}>Configure rules →</button>
        </div>
      </div>

      {/* Stats strip — clickable to filter */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 1, background: 'var(--line)', borderBottom: '1px solid var(--line)', flexShrink: 0 }}>
        {[
          { label: 'critical',     val: counts.critical,  color: 'var(--danger)', activeWhen: () => sev === 'critical',           toggle: () => setSev(sev === 'critical' ? 'all' : 'critical') },
          { label: 'warning',      val: counts.warning,   color: 'var(--warn)',   activeWhen: () => sev === 'warning',            toggle: () => setSev(sev === 'warning'  ? 'all' : 'warning')  },
          { label: 'policy viol.', val: counts.violation, color: 'var(--ink)',    activeWhen: () => cat === 'policy_violation',   toggle: () => setCat(cat === 'policy_violation' ? 'all' : 'policy_violation') },
          { label: 'budget',       val: counts.budget,    color: 'var(--ink)',    activeWhen: () => cat === 'budget',             toggle: () => setCat(cat === 'budget'  ? 'all' : 'budget')    },
          { label: 'anomaly',      val: counts.anomaly,   color: 'var(--ink)',    activeWhen: () => cat === 'anomaly',            toggle: () => setCat(cat === 'anomaly' ? 'all' : 'anomaly')   },
        ].map((s) => (
          <div
            key={s.label}
            onClick={s.toggle}
            style={{
              background: s.activeWhen() ? 'var(--ink)' : 'var(--paper-2)',
              padding: '10px 18px',
              cursor: 'pointer',
              transition: 'background 0.12s',
            }}
          >
            <div style={{
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 24,
              fontWeight: 700,
              color: s.activeWhen() ? '#fff' : s.color,
            }}>{s.val}</div>
            <div style={{
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 10,
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              color: s.activeWhen() ? 'rgba(255,255,255,0.65)' : 'var(--ink-4)',
              marginTop: 2,
            }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div className="filterbar">
        <div className="search">
          <span style={{ color: 'var(--ink-4)', fontSize: 13 }}>⌕</span>
          <input
            placeholder="search message or agent…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <span className="fdivider"></span>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>sev</span>
        {['all', 'critical', 'warning'].map((v) => (
          <button key={v} className={`btn btn-sm ${sev === v ? 'btn-active' : ''}`} onClick={() => setSev(v)}>{v}</button>
        ))}
        <span className="fdivider"></span>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>cat</span>
        {[
          { v: 'all',              l: 'all'          },
          { v: 'policy_violation', l: 'policy viol.' },
          { v: 'budget',           l: 'budget'       },
          { v: 'anomaly',          l: 'anomaly'      },
        ].map(({ v, l }) => (
          <button key={v} className={`btn btn-sm ${cat === v ? 'btn-active' : ''}`} onClick={() => setCat(v)}>{l}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)' }}>
          {filtered.length} / {all.length}
        </span>
      </div>

      {/* Alert feed */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        {filtered.length === 0
          ? <div className="empty">no alerts match filters</div>
          : filtered.map((a) => (
              <AlertRow
                key={a.id}
                a={a}
                expanded={exp === a.id}
                onToggle={() => setExp(exp === a.id ? null : a.id)}
                goAgent={(id) => { goAgent && goAgent(id); }}
                goPolicy={goPolicy}
              />
            ))
        }
      </div>
    </div>
  );
}

Object.assign(window, { AlertsPage });
