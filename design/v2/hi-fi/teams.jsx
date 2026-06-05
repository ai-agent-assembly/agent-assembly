/* global React */
const { useState: useTeamSt } = React;

/* ============================================================
   Teams page  —  AAASM-218
   Mirrors GET /api/v1/topology/team/{team_id}  +  TEAM_DETAILS
   Two-pane: team list  |  team detail
   ============================================================ */

function BudgetMiniBar({ used, limit }) {
  const pct   = limit > 0 ? Math.min(100, (used / limit) * 100) : 0;
  const color = pct >= 95 ? 'var(--danger)' : pct >= 80 ? 'var(--warn)' : 'var(--ok)';
  return (
    <div>
      <div style={{ height: 3, background: 'var(--paper-3)', borderRadius: 2, overflow: 'hidden', marginBottom: 2 }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }}></div>
      </div>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: pct >= 80 ? color : 'var(--ink-4)' }}>
        ${used.toFixed(2)} / ${limit.toFixed(0)}
      </div>
    </div>
  );
}

/* ── Right pane: team detail ─────────────────────────────────────────────── */
function TeamDetail({ teamId, goAgent, goPolicy, toast }) {
  if (!teamId) {
    return <div className="empty">← select a team</div>;
  }

  const team    = (window.TOPO_TEAMS  || []).find((t) => t.id === teamId);
  const det     = (window.TEAM_DETAILS || {})[teamId] || {};
  const agents  = (window.TOPO_NODES  || []).filter((n) => n.team === teamId);
  const members = (window.MEMBERS     || []).filter((m) => m.teams.includes(teamId) || m.teams.includes('*'));

  const budgetPct     = det.budget_daily   > 0 ? (det.budget_daily_used   / det.budget_daily)   * 100 : 0;
  const budgetMoPct   = det.budget_monthly > 0 ? (det.budget_monthly_used / det.budget_monthly) * 100 : 0;
  const budgetColor   = (p) => p >= 95 ? 'var(--danger)' : p >= 80 ? 'var(--warn)' : 'var(--ok)';

  const isOrphan = teamId === '__orphan__';

  return (
    <div style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 18 }}>

      {/* Team header */}
      <div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--ink-4)', marginBottom: 4 }}>
          {isOrphan ? 'unclaimed' : 'team'}
        </div>
        <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>{team?.label || teamId}</div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span className="chip">{agents.length} agent{agents.length !== 1 ? 's' : ''}</span>
          {agents.filter((a) => a.status === 'suspended').length > 0 && (
            <span className="chip chip-warn">{agents.filter((a) => a.status === 'suspended').length} suspended</span>
          )}
          {agents.filter((a) => a.flagged).length > 0 && (
            <span className="chip chip-danger">{agents.filter((a) => a.flagged).length} flagged</span>
          )}
          {!isOrphan && members.length > 0 && (
            <span className="chip">{members.length} member{members.length !== 1 ? 's' : ''}</span>
          )}
        </div>
      </div>

      {/* Budget — only non-orphan teams */}
      {!isOrphan && det.budget_daily > 0 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>Budget</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            {[
              { label: 'Daily',   used: det.budget_daily_used,   limit: det.budget_daily,   pct: budgetPct   },
              { label: 'Monthly', used: det.budget_monthly_used, limit: det.budget_monthly, pct: budgetMoPct },
            ].map((b) => (
              <div key={b.label}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {b.label}
                </div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 20, fontWeight: 700, marginBottom: 6, color: budgetColor(b.pct) }}>
                  ${b.used.toFixed(2)}
                  <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--ink-4)' }}> / ${b.limit.toFixed(0)}</span>
                </div>
                <div style={{ height: 5, background: 'var(--paper-3)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min(100, b.pct)}%`, background: budgetColor(b.pct), borderRadius: 3 }}></div>
                </div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)', marginTop: 3 }}>
                  {b.pct.toFixed(1)}% used
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Approval routing */}
      {!isOrphan && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 6 }}>Approval routing</div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-2)', lineHeight: 1.7 }}>
            {det.approval_routing || '— not configured'}
          </div>
          <button className="btn btn-sm" style={{ marginTop: 10 }} onClick={() => toast('Routing config — Sprint 3')}>
            Edit routing →
          </button>
        </div>
      )}

      {/* Active policies */}
      {(det.policy_ids || []).length > 0 && (
        <div>
          <div className="section-title" style={{ marginBottom: 8 }}>Active policies</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {det.policy_ids.map((pid) => {
              const p = (window.POLICIES || []).find((x) => x.id === pid);
              return (
                <div
                  key={pid}
                  className="card"
                  style={{ padding: '8px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}
                  onClick={() => goPolicy && goPolicy(pid)}
                >
                  <div>
                    <span className="chip" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, marginRight: 8 }}>{pid}</span>
                    <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{p?.name || '—'}</span>
                  </div>
                  {p && (
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>
                      {p.hits24h} hits/24h
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Orphan callout */}
      {isOrphan && (
        <div className="callout danger">
          <div className="callout-title">No governance applied</div>
          Orphan agents have no team assignment and no policy scoped to them. They run in whatever mode was set at registration.
          Assign them to a team or apply an agent-scoped policy.
        </div>
      )}

      {/* Agents */}
      <div>
        <div className="section-title" style={{ marginBottom: 8 }}>Agents ({agents.length})</div>
        {agents.length === 0
          ? <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)' }}>none</div>
          : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {agents.map((a) => (
                <div
                  key={a.id}
                  className="card"
                  style={{
                    padding: '8px 12px', cursor: 'pointer',
                    borderLeft: `3px solid ${a.flagged ? 'var(--danger)' : a.status === 'suspended' ? 'var(--warn)' : 'var(--line)'}`,
                  }}
                  onClick={() => goAgent && goAgent(a.id)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <div>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600 }}>{a.name}</span>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)', marginLeft: 8 }}>
                        depth:{a.depth} · {a.framework}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {a.flagged && <span className="chip chip-danger" style={{ fontSize: 9 }}>flagged</span>}
                      <span className={`chip ${a.status === 'active' ? 'chip-ok' : 'chip-warn'}`} style={{ fontSize: 9 }}>{a.status}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )
        }
      </div>

      {/* Members with access */}
      {!isOrphan && members.length > 0 && (
        <div>
          <div className="section-title" style={{ marginBottom: 8 }}>Members with access ({members.length})</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {members.map((m) => {
              const roleMeta = { org_admin: 'chip-danger', team_admin: 'chip-warn', operator: 'chip-info', viewer: '' };
              const rc = roleMeta[m.role] || '';
              return (
                <div key={m.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px dashed var(--line)' }}>
                  <div style={{
                    width: 28, height: 28, borderRadius: '50%',
                    background: 'var(--paper-3)', border: '1px solid var(--line-2)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontWeight: 700, fontSize: 12, flexShrink: 0,
                  }}>{m.name[0]}</div>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 12, fontWeight: 500 }}>{m.name}</span>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', marginLeft: 8 }}>{m.email}</span>
                  </div>
                  <span className={`chip ${rc}`} style={{ fontSize: 9 }}>{m.role.replace('_', ' ')}</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>{m.lastActive}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */
function TeamsPage({ goAgent, goPolicy, toast }) {
  const [selected, setSelected] = useTeamSt('data-platform');

  const teams   = window.TOPO_TEAMS   || [];
  const details = window.TEAM_DETAILS || {};
  const nodes   = window.TOPO_NODES   || [];

  const named   = teams.filter((t) => t.id !== '__orphan__');
  const orphans = nodes.filter((n) => n.team === '__orphan__');

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '264px 1fr', height: 'calc(100vh - 56px)', background: 'var(--line)', gap: 1 }}>

      {/* ── Left: team list ── */}
      <div style={{ background: 'var(--paper)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="pane-head">
          <span className="pane-title">Agent Groups</span>
          <button className="btn btn-sm" onClick={() => toast('Team creation — Sprint 3')}>+ New</button>
        </div>

        <div style={{ flex: 1, overflow: 'auto' }}>
          {named.map((t) => {
            const det      = details[t.id] || {};
            const teamAgents = nodes.filter((n) => n.team === t.id);
            const flagCnt  = teamAgents.filter((a) => a.flagged).length;
            const suspCnt  = teamAgents.filter((a) => a.status === 'suspended').length;
            const isActive = selected === t.id;

            return (
              <div
                key={t.id}
                onClick={() => setSelected(t.id)}
                style={{
                  padding: '10px 14px',
                  cursor: 'pointer',
                  borderBottom: '1px solid var(--line)',
                  background: isActive ? 'var(--paper-2)' : 'var(--paper)',
                  borderLeft: `3px solid ${isActive ? 'var(--ink)' : 'transparent'}`,
                  paddingLeft: isActive ? 11 : 14,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: isActive ? 700 : 500 }}>
                    {t.label}
                  </span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>
                    {teamAgents.length}×
                  </span>
                </div>
                <div style={{ display: 'flex', gap: 5, alignItems: 'center', flexWrap: 'wrap' }}>
                  {flagCnt > 0 && <span className="chip chip-danger" style={{ fontSize: 9 }}>{flagCnt} flagged</span>}
                  {suspCnt > 0 && <span className="chip chip-warn"   style={{ fontSize: 9 }}>{suspCnt} susp.</span>}
                  {det.budget_daily > 0 && (
                    <div style={{ flex: 1, minWidth: 70 }}>
                      <BudgetMiniBar used={det.budget_daily_used} limit={det.budget_daily} />
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {/* Orphan section */}
          <div style={{ borderTop: '1px solid var(--line)', background: 'var(--paper-3)' }}>
            <div style={{ padding: '8px 14px 4px', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--ink-4)' }}>
              unclaimed
            </div>
            <div
              onClick={() => setSelected('__orphan__')}
              style={{
                padding: '8px 14px 10px',
                cursor: 'pointer',
                background: selected === '__orphan__' ? 'var(--paper-2)' : 'transparent',
                borderLeft: `3px solid ${selected === '__orphan__' ? 'var(--danger)' : 'transparent'}`,
                paddingLeft: selected === '__orphan__' ? 11 : 14,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: selected === '__orphan__' ? 700 : 400 }}>
                  orphan agents
                </span>
                <span className={`chip ${orphans.length > 0 ? 'chip-warn' : ''}`} style={{ fontSize: 9 }}>
                  {orphans.length}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Right: team detail ── */}
      <div style={{ background: 'var(--paper)', overflow: 'auto' }}>
        <TeamDetail
          teamId={selected}
          goAgent={(id) => { goAgent && goAgent(id); }}
          goPolicy={goPolicy}
          toast={toast}
        />
      </div>
    </div>
  );
}

Object.assign(window, { TeamsPage });
