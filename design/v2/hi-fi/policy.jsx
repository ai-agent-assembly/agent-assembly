/* global React */
const { useState: useSP, useMemo: useMP } = React;

// ============================================================
// Policy page — list / visual builder / simulate
// ============================================================

const RESOURCE_OPTS = ['gmail', 'gdrive', 's3', 'pg', 'shell', 'http', 'github', 'slack'];
const VERB_OPTS = ['read', 'write', 'delete', 'exec'];
const ACTION_OPTS = ['allow', 'narrow', 'approval', 'scrub-then-allow', 'deny'];
const COND_OPTS = [
  'always',
  'recipient not in @acme.com',
  'host in allowlist',
  'path matches customer-pii/*',
  'table contains PII columns',
  '2-person review required',
  'amount < $100',
];

function PolicyPage({ initialId, openSimulate, toast }) {
  const [selectedId, setSelectedId] = useSP(initialId || 'P-066');
  const [filter, setFilter] = useSP('all');
  const policy = useMP(() => window.POLICIES.find((p) => p.id === selectedId), [selectedId]);

  const list = useMP(() => {
    if (filter === 'all') return window.POLICIES;
    if (filter === 'active') return window.POLICIES.filter((p) => p.status === 'active');
    if (filter === 'proposed') return window.POLICIES.filter((p) => p.status === 'proposed');
    return window.POLICIES;
  }, [filter]);

  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="policy" />;
  if (ps === 'empty')   return <window.EmptyState page="policy" onCta={() => toast && toast('new policy (mock)')} onSecondary={() => toast && toast('preset gallery (mock)')} />;
  if (ps === 'error')   return <window.ErrorState kind="generic" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Policy ★ <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14 }}>規則編輯 · simulate · rollout</span></h1>
          <div className="page-sub">
            Visual builder for narrowing rules. Every change can be replayed against the last 24h of traffic before it ships.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn">+ new policy</button>
          <button className="btn">history</button>
          <button className="btn btn-primary" onClick={openSimulate}>▸ Simulate</button>
        </div>
      </div>

      <div className="tabs">
        <div className={`tab ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>
          All <span className="tab-count">{window.POLICIES.length}</span>
        </div>
        <div className={`tab ${filter === 'active' ? 'active' : ''}`} onClick={() => setFilter('active')}>
          Active <span className="tab-count">{window.POLICIES.filter((p) => p.status === 'active').length}</span>
        </div>
        <div className={`tab ${filter === 'proposed' ? 'active' : ''}`} onClick={() => setFilter('proposed')}>
          Proposed <span className="tab-count" style={{ background: 'var(--warn)', color: '#fff' }}>1</span>
        </div>
      </div>

      <div className="split">
        <div className="split-pane">
          <div className="pane-head">
            <div className="pane-title">policies</div>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)' }}>{list.length} rules</span>
          </div>
          <div className="policy-list">
            {list.map((p) => (
              <div
                key={p.id}
                className={`policy-item ${p.id === selectedId ? 'active' : ''}`}
                onClick={() => setSelectedId(p.id)}
              >
                <div className="policy-item-id">{p.id}</div>
                <div>
                  <div className="policy-item-name">
                    {p.name}
                    {p.status === 'proposed' && <span className="chip chip-warn" style={{ marginLeft: 8 }}>draft</span>}
                  </div>
                  <div className="policy-item-scope">scope: {p.scope}</div>
                  <div style={{ marginTop: 4, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {p.affects.slice(0, 3).map((a) => (
                      <span key={a} className="chip" style={{ fontSize: 9 }}>{a}</span>
                    ))}
                    {p.affects.length > 3 && <span className="chip" style={{ fontSize: 9 }}>+{p.affects.length - 3}</span>}
                  </div>
                </div>
                <div className="policy-item-hits">
                  <b>{p.hits24h}</b>
                  <div>hits/24h</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="split-pane">
          {policy ? <window.PolicyEditor policy={policy} openSimulate={openSimulate} toast={toast} /> :
            <div className="empty">select a policy</div>}
        </div>
      </div>
    </>
  );
}

// PolicyEditor lives in policy-editor.jsx (window.PolicyEditor)

// ============================================================
// Simulate modal
// ============================================================

function SimulateModal({ onClose, onRollout, toast }) {
  const [window24, setWindow] = useSP('24h');
  const [agentScope, setAgentScope] = useSP('research-bot-04');
  const [phase, setPhase] = useSP('preview'); // preview | rollout

  const stats = useMP(() => {
    const calls = window.SAMPLE_CALLS;
    const newly = calls.filter((c) => c.changeType === 'newly-blocked').length;
    const narrowed = calls.filter((c) => c.changeType === 'narrowed').length;
    const fp = calls.filter((c) => c.changeType === 'false-positive').length;
    const unchanged = calls.filter((c) => c.changeType === 'unchanged').length;
    return { newly, narrowed, fp, unchanged, total: calls.length };
  }, []);

  return (
    <div className="scrim scrim-center" onClick={onClose}>
      <div className="modal" style={{ width: 920, maxHeight: '92vh' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>policy simulator</div>
            <h2 style={{ margin: '4px 0 0', fontSize: 18 }}>P-066 · proposed narrowing for research-bot-04</h2>
          </div>
          <button className="btn btn-ghost" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body" style={{ padding: 0 }}>
          {/* Controls */}
          <div className="simulate-bar" style={{ margin: '14px 18px' }}>
            <div className="simulate-controls">
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>replay window</span>
              {['1h', '6h', '24h', '7d'].map((w) => (
                <div key={w} className={`select ${window24 === w ? 'select-em' : ''}`} onClick={() => setWindow(w)}>{w}</div>
              ))}
              <div className="fdivider" />
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>scope</span>
              <div className="select select-em">agent: research-bot-04</div>
              <div className="select">+ baseline: current policies</div>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button className="btn btn-sm">A/B compare</button>
                <button className="btn btn-sm">re-run</button>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div style={{ padding: '0 18px' }}>
            <div className="simulate-stats">
              <div className="sim-stat">
                <div className="sim-stat-label">newly blocked</div>
                <div className="sim-stat-val" style={{ color: 'var(--danger)' }}>{stats.newly}</div>
                <div className="sim-stat-delta delta-good">↑ would prevent</div>
              </div>
              <div className="sim-stat">
                <div className="sim-stat-label">narrowed in scope</div>
                <div className="sim-stat-val" style={{ color: 'var(--warn)' }}>{stats.narrowed}</div>
                <div className="sim-stat-delta">paths trimmed but allowed</div>
              </div>
              <div className="sim-stat">
                <div className="sim-stat-label">false positives</div>
                <div className="sim-stat-val" style={{ color: 'var(--danger)' }}>{stats.fp}</div>
                <div className="sim-stat-delta delta-bad">⚠ legit traffic blocked</div>
              </div>
              <div className="sim-stat">
                <div className="sim-stat-label">unchanged</div>
                <div className="sim-stat-val">{stats.unchanged}</div>
                <div className="sim-stat-delta">no behavior change</div>
              </div>
            </div>
          </div>

          {/* Sample calls diff */}
          <div style={{ padding: '14px 18px 4px' }}>
            <div className="section-title">sample calls — last {window24} · click row to except</div>
          </div>
          <div style={{ padding: '0 18px 14px' }}>
            <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, overflow: 'auto', maxHeight: 240 }}>
              <table className="calls-table">
                <thead>
                  <tr>
                    <th>time</th>
                    <th>verb</th>
                    <th>resource</th>
                    <th>current</th>
                    <th>proposed</th>
                    <th>change</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {window.SAMPLE_CALLS.map((c, i) => (
                    <tr key={i}>
                      <td>{c.ts}</td>
                      <td><b style={{ textTransform: 'uppercase', fontSize: 10 }}>{c.verb}</b></td>
                      <td style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.resource}</td>
                      <td><span className={`dot dot-${c.currentDecision}`}></span>{c.currentDecision}</td>
                      <td><span className={`dot dot-${c.proposedDecision}`}></span>{c.proposedDecision}</td>
                      <td>
                        {c.changeType === 'newly-blocked' && <span className="chip chip-danger">newly blocked</span>}
                        {c.changeType === 'narrowed' && <span className="chip chip-warn">narrowed</span>}
                        {c.changeType === 'unchanged' && <span className="chip">unchanged</span>}
                        {c.changeType === 'false-positive' && <span className="chip chip-danger">⚠ false-positive</span>}
                        {c.changeType === 'tightened' && <span className="chip chip-info">tightened</span>}
                      </td>
                      <td>
                        {c.changeType === 'false-positive' && <button className="btn btn-sm">+ exception</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Impact analysis */}
          <div style={{ padding: '0 18px 14px' }}>
            <div className="section-title">impact analysis</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div className="callout danger">
                <div className="callout-title">⚠ false-positive risk</div>
                2 legit calls would be blocked. Recommend adding exceptions for:
                <ul style={{ margin: '6px 0 0', paddingLeft: 18, fontFamily: 'JetBrains Mono', fontSize: 11 }}>
                  <li>recipient @acme.com → allow</li>
                  <li>shell:python report.py → allow (cron)</li>
                </ul>
              </div>
              <div className="callout ok">
                <div className="callout-title">✓ posture improvement</div>
                Reduces over-permissioning surface for research-bot-04 by 64%.
                <ul style={{ margin: '6px 0 0', paddingLeft: 18, fontFamily: 'JetBrains Mono', fontSize: 11 }}>
                  <li>4 verbs newly denied</li>
                  <li>2 resources narrowed to specific paths</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div className="modal-foot">
          <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>
            Replayed {stats.total} calls from {window24} window · 2.4s
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn">Save & don't ship</button>
            <button className="btn">Canary 5%</button>
            <button className="btn">Canary 25%</button>
            <button className="btn btn-primary" onClick={() => { onRollout(); onClose(); toast('P-066 rolled out · enforcing on research-bot-04'); }}>Rollout to 100%</button>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PolicyPage, SimulateModal });
