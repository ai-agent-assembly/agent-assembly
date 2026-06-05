/* global React */
const { useState: useSFL, useMemo: useMFL } = React;

/* ── Active Sessions sub-view ─────────────────────────────────────────────── */
function ActiveSessionsView({ goAgent }) {
  const sessions = window.ACTIVE_SESSIONS || [];
  const now = new Date('2026-05-11T14:02:11Z');
  const elapsed = (iso) => {
    const diff = Math.floor((now - new Date(iso)) / 1000);
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m`;
    return `${Math.floor(diff / 3600)}h`;
  };
  return (
    <div style={{ flex: 1, overflow: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Session</th>
            <th>Agent</th>
            <th>Current task</th>
            <th style={{ textAlign: 'right' }}>Actions</th>
            <th>Running</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => {
            const node = (window.TOPO_NODES || []).find((n) => n.id === s.agent_id);
            return (
              <tr key={s.session_id}>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, fontWeight: 600 }}>{s.session_id}</span>
                </td>
                <td>
                  <span
                    style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, cursor: 'pointer', textDecoration: 'underline dotted', textUnderlineOffset: 2 }}
                    onClick={() => goAgent && goAgent(s.agent_id)}
                  >{s.agent_id}</span>
                  {node && <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)', marginTop: 1 }}>{node.team}</div>}
                </td>
                <td>
                  <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{s.current_task}</span>
                </td>
                <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600 }}>
                  {s.actions_count}
                </td>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-3)' }}>
                    <span className="live-pulse" style={{ width: 6, height: 6, marginRight: 5 }}></span>
                    {elapsed(s.started_at)}
                  </span>
                </td>
                <td>
                  <span className="chip chip-ok" style={{ fontSize: 9 }}>● {s.status}</span>
                </td>
                <td>
                  <button className="btn btn-sm btn-ghost" onClick={() => goAgent && goAgent(s.agent_id)}>inspect →</button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ============================================================
// Fleet page — all agents, dense table + filters + bulk actions
// ============================================================

function TrustBar({ score }) {
  const color = score >= 80 ? 'var(--ok)' : score >= 60 ? 'var(--warn)' : 'var(--danger)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'JetBrains Mono', fontSize: 11 }}>
      <div style={{ width: 60, height: 6, background: 'var(--line)', borderRadius: 1, overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color }}></div>
      </div>
      <span style={{ color, fontWeight: 600 }}>{score}</span>
    </div>
  );
}

function ModeChip({ mode }) {
  if (mode === 'enforce') return <span className="chip chip-ok" style={{ fontSize: 9 }}>● enforce</span>;
  if (mode === 'shadow')  return <span className="chip chip-warn" style={{ fontSize: 9 }}>◐ shadow</span>;
  return <span className="chip" style={{ fontSize: 9 }}>○ {mode}</span>;
}

function StatusChip({ status }) {
  if (status === 'active')    return <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ok)' }}>● active</span>;
  if (status === 'suspended') return <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--danger)' }}>■ suspended</span>;
  return <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-4)' }}>○ {status}</span>;
}

function FleetPage({ goCapability, goAgent, toast }) {
  const [view, setView] = useSFL('agents');
  const [search, setSearch] = useSFL('');
  const [filterFw, setFilterFw] = useSFL('all');
  const [filterStatus, setFilterStatus] = useSFL('all');
  const [filterFlag, setFilterFlag] = useSFL(false);
  const [sortKey, setSortKey] = useSFL('trust');
  const [sortDir, setSortDir] = useSFL('asc');
  const [selected, setSelected] = useSFL(new Set());

  const frameworks = ['all', ...new Set(window.AGENTS.map((a) => a.framework))];
  const statuses = ['all', 'active', 'suspended'];

  const filtered = useMFL(() => {
    let rows = window.AGENTS.filter((a) => {
      if (search && !a.name.toLowerCase().includes(search.toLowerCase()) && !a.owner.toLowerCase().includes(search.toLowerCase())) return false;
      if (filterFw !== 'all' && a.framework !== filterFw) return false;
      if (filterStatus !== 'all' && a.status !== filterStatus) return false;
      if (filterFlag && !a.flagged) return false;
      return true;
    });
    rows.sort((a, b) => {
      const av = a[sortKey] ?? '';
      const bv = b[sortKey] ?? '';
      if (typeof av === 'number') return sortDir === 'asc' ? av - bv : bv - av;
      return sortDir === 'asc' ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });
    return rows;
  }, [search, filterFw, filterStatus, filterFlag, sortKey, sortDir]);

  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="fleet" />;
  if (ps === 'empty')   return <window.EmptyState page="fleet" onCta={() => { setSearch(''); setFilterFw('all'); setFilterStatus('all'); setFilterFlag(false); toast && toast('filters cleared'); }} />;
  if (ps === 'error')   return <window.ErrorState kind="generic" />;

  const toggleSelect = (id) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelected(next);
  };
  const toggleAll = () => {
    if (selected.size === filtered.length) setSelected(new Set());
    else setSelected(new Set(filtered.map((a) => a.id)));
  };

  const sortBy = (k) => {
    if (sortKey === k) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    else { setSortKey(k); setSortDir('desc'); }
  };

  const SortIcon = ({ k }) => (
    sortKey === k ? <span style={{ marginLeft: 3, opacity: 0.6 }}>{sortDir === 'asc' ? '▲' : '▼'}</span> : <span style={{ marginLeft: 3, opacity: 0.2 }}>↕</span>
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Fleet
            <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14, marginLeft: 8 }}>
              · {filtered.length} of {window.AGENTS.length} agents
            </span>
          </h1>
          <div className="page-sub">
            All registered agents across frameworks. Click a row to inspect, or select multiple for bulk actions.
          </div>
        </div>
        <div style={{ flex: 1, gap: 6 }}>
          <button className="btn">+ register agent</button>
          <button className="btn">⏏ export csv</button>
        </div>
      </div>

      {/* View tabs */}
      <div className="tabs">
        <div className={`tab ${view === 'agents' ? 'active' : ''}`} onClick={() => setView('agents')}>
          Agents <span className="tab-count">{window.AGENTS.length}</span>
        </div>
        <div className={`tab ${view === 'sessions' ? 'active' : ''}`} onClick={() => setView('sessions')}>
          Active Sessions
          <span className="tab-count" style={view !== 'sessions' ? { background: 'var(--ok-bg)', color: 'var(--ok)', border: '1px solid var(--ok)' } : undefined}>
            {(window.ACTIVE_SESSIONS || []).length}
          </span>
        </div>
      </div>

      {view === 'sessions' && <ActiveSessionsView goAgent={goAgent} />}

      {view === 'agents' && <>
      {/* Filter bar */}
      <div style={{ padding: '10px 24px', background: 'var(--paper-2)', borderBottom: '1px solid var(--line)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          placeholder="search name, owner…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ padding: '5px 10px', border: '1px solid var(--line-2)', borderRadius: 3, fontSize: 12, fontFamily: 'inherit', minWidth: 220, background: 'var(--paper)' }}
        />
        <span className="fdivider" />
        <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)' }}>framework:</span>
        {frameworks.map((f) => (
          <button key={f} className={`btn btn-sm ${filterFw === f ? 'btn-active' : ''}`} onClick={() => setFilterFw(f)}>{f}</button>
        ))}
        <span className="fdivider" />
        <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)' }}>status:</span>
        {statuses.map((s) => (
          <button key={s} className={`btn btn-sm ${filterStatus === s ? 'btn-active' : ''}`} onClick={() => setFilterStatus(s)}>{s}</button>
        ))}
        <span className="fdivider" />
        <label style={{ fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', gap: 5, alignItems: 'center', cursor: 'pointer' }}>
          <input type="checkbox" checked={filterFlag} onChange={(e) => setFilterFlag(e.target.checked)} />
          <span style={{ color: 'var(--danger)' }}>⚑ flagged only</span>
        </label>

        {selected.size > 0 && (
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--ink-3)' }}>{selected.size} selected</span>
            <button className="btn btn-sm" onClick={() => toast(`Switched ${selected.size} agents to shadow mode (mock)`)}>→ shadow mode</button>
            <button className="btn btn-sm btn-danger" onClick={() => toast(`Suspended ${selected.size} agents (mock)`)}>■ suspend</button>
            <button className="btn btn-sm btn-ghost" onClick={() => setSelected(new Set())}>clear</button>
          </div>
        )}
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 28 }}>
                <input type="checkbox"
                  checked={selected.size === filtered.length && filtered.length > 0}
                  onChange={toggleAll}
                />
              </th>
              <th onClick={() => sortBy('name')} style={{ cursor: 'pointer' }}>agent <SortIcon k="name" /></th>
              <th onClick={() => sortBy('framework')} style={{ cursor: 'pointer' }}>framework <SortIcon k="framework" /></th>
              <th onClick={() => sortBy('owner')} style={{ cursor: 'pointer' }}>owner <SortIcon k="owner" /></th>
              <th>mode</th>
              <th onClick={() => sortBy('status')} style={{ cursor: 'pointer' }}>status <SortIcon k="status" /></th>
              <th onClick={() => sortBy('trust')} style={{ cursor: 'pointer' }}>trust <SortIcon k="trust" /></th>
              <th onClick={() => sortBy('blocked24h')} style={{ cursor: 'pointer', textAlign: 'right' }}>blocked / 24h <SortIcon k="blocked24h" /></th>
              <th onClick={() => sortBy('scrubbed24h')} style={{ cursor: 'pointer', textAlign: 'right' }}>scrubbed / 24h <SortIcon k="scrubbed24h" /></th>
              <th onClick={() => sortBy('lastSeen')} style={{ cursor: 'pointer' }}>last seen <SortIcon k="lastSeen" /></th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.id}
                style={{ background: selected.has(a.id) ? 'var(--paper-3)' : (a.flagged ? 'rgba(184,41,30,0.04)' : undefined), cursor: 'pointer' }}
                onClick={(e) => { if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') return; goAgent && goAgent(a.id); }}>
                <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selected.has(a.id)} onChange={() => toggleSelect(a.id)} /></td>
                <td>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontWeight: 600, color: 'var(--ink)', textDecoration: 'underline', textDecorationColor: 'var(--line-2)', textUnderlineOffset: 3 }}>
                      {a.flagged && <span className="flag-dot" style={{ color: 'var(--danger)', marginRight: 5 }}>●</span>}
                      {a.name}
                    </span>
                    {a.note && <span style={{ fontSize: 10, color: 'var(--ink-4)', fontStyle: 'italic' }}>{a.note}</span>}
                  </div>
                </td>
                <td><span className="chip" style={{ fontSize: 9 }}>{a.framework}</span></td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-3)' }}>@{a.owner}</td>
                <td><ModeChip mode={a.mode} /></td>
                <td><StatusChip status={a.status} /></td>
                <td><TrustBar score={a.trust} /></td>
                <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', color: a.blocked24h > 50 ? 'var(--danger)' : 'var(--ink-2)', fontWeight: a.blocked24h > 50 ? 600 : 400 }}>{a.blocked24h}</td>
                <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', color: a.scrubbed24h > 0 ? 'var(--scrub)' : 'var(--ink-4)' }}>{a.scrubbed24h}</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-3)' }}>{a.lastSeen}</td>
                <td>
                  <button className="btn btn-sm" onClick={() => goCapability(a.id)}>caps →</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="empty" style={{ padding: 60 }}>no agents match these filters</div>
        )}
      </div>
      </>}
    </>
  );
}

Object.assign(window, { FleetPage });
