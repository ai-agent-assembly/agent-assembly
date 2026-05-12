/* global React */
const { useState: useS, useMemo: useM } = React;
const RowGroup = ({ children }) => <div style={{ display: 'contents' }}>{children}</div>;

// ============================================================
// Capability page — matrix / per-resource / per-agent
// ============================================================

function CapabilityPage({ goPolicy, openAgent, openCell, agents, agentSubset, toast }) {
  const [tab, setTab] = useS('matrix');
  const [verb, setVerb] = useS('write'); // which verb to display in the matrix cells
  const [filter, setFilter] = useS('');
  const [selectedRes, setSelectedRes] = useS('gmail');
  const [selectedAgent, setSelectedAgent] = useS('research-bot-04');

  const visibleAgents = useM(() => {
    const list = agentSubset ? agents.filter((a) => agentSubset.includes(a.id)) : agents;
    if (!filter) return list;
    const q = filter.toLowerCase();
    return list.filter((a) =>
      a.name.toLowerCase().includes(q) ||
      a.framework.toLowerCase().includes(q) ||
      a.owner.toLowerCase().includes(q)
    );
  }, [agents, filter, agentSubset]);

  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="capability" />;
  if (ps === 'empty')   return <window.EmptyState page="capability" onCta={() => toast && toast('connect resource (mock)')} onSecondary={() => toast && toast('open onboarding (mock)')} />;
  if (ps === 'error')   return <window.ErrorState kind="generic" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Capability ★ <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14 }}>能力縮限設定</span></h1>
          <div className="page-sub">
            What agents <em>say</em> they can do — and what Assembly <em>actually</em> allows.
            Click any cell to see the policy responsible and edit inline.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn"><span>⊞</span> Templates</button>
          <button className="btn"><span>↧</span> Export CSV</button>
          <button className="btn btn-primary" onClick={goPolicy}><span>▸</span> Open Policy editor</button>
        </div>
      </div>

      <div className="tabs">
        <div className={`tab ${tab === 'matrix' ? 'active' : ''}`} onClick={() => setTab('matrix')}>
          Matrix <span className="tab-count">{visibleAgents.length} × 8</span>
        </div>
        <div className={`tab ${tab === 'resource' ? 'active' : ''}`} onClick={() => setTab('resource')}>
          Per-resource
        </div>
        <div className={`tab ${tab === 'agent' ? 'active' : ''}`} onClick={() => setTab('agent')}>
          Per-agent
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', padding: '6px 0' }}>
          <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1, marginRight: 8 }}>verb</span>
          <div className="verbs">
            {window.VERBS.map((v) => (
              <div
                key={v}
                className={`verb ${verb === v ? 'on' : ''}`}
                onClick={() => setVerb(v)}
              >{v}</div>
            ))}
          </div>
        </div>
      </div>

      {tab === 'matrix' && (
        <>
          <div className="filterbar">
            <div className="search">
              <span>⌕</span>
              <input
                placeholder="search agent · framework · owner · DID"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            </div>
            <div className="select">framework: any</div>
            <div className="select">owner: any</div>
            <div className="select select-em">trust ≤ 70</div>
            <div className="select">mode: any</div>
            <div className="fdivider" />
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>
              {visibleAgents.length} of {agents.length} agents
            </span>
            <div style={{ marginLeft: 'auto' }} className="legend">
              <span><span className="legend-sw" style={{ background: '#fbfaf6' }}></span>allow</span>
              <span><span className="legend-sw" style={{ background: 'var(--warn-bg)', borderColor: 'var(--warn)' }}></span>narrow</span>
              <span><span className="legend-sw" style={{ background: 'var(--info-bg)', borderColor: 'var(--info)' }}></span>approval</span>
              <span><span className="legend-sw" style={{ background: 'var(--danger-bg)', borderColor: 'var(--danger)' }}></span>deny</span>
              <span><span className="legend-sw" style={{ background: 'var(--paper-3)' }}></span>n/a</span>
            </div>
          </div>

          <div className="matrix-wrap">
            <div className="matrix-meta">
              <span>verb: <b style={{ color: 'var(--ink)', textTransform: 'uppercase' }}>{verb}</b> · cells show effective decision</span>
              <span>● red dot = recent flag · click cell to inspect</span>
            </div>
            <div className="matrix">
              <div
                className="matrix-grid"
                style={{
                  gridTemplateColumns: `260px repeat(${window.RESOURCES.length}, minmax(110px, 1fr))`,
                }}
              >
                <div className="mx-corner">agent ↓ · resource →</div>
                {window.RESOURCES.map((r) => (
                  <div key={r.id} className="mx-col-h">
                    <div className="mx-col-h-group">{r.group}</div>
                    {r.name}
                  </div>
                ))}
                {visibleAgents.map((a) => (
                  <RowGroup key={a.id}>
                    <div className="mx-row-h" onClick={() => openAgent(a)}>
                      <div className="mx-row-h-name">
                        {a.name}
                        {a.flagged && <span className="flag-dot" style={{ color: 'var(--danger)', marginLeft: 6 }}>●</span>}
                      </div>
                      <div className="mx-row-h-meta">
                        <span>{a.framework}</span>
                        <span>·</span>
                        <span>{a.owner}</span>
                        <span style={{ marginLeft: 'auto' }}>trust {a.trust}</span>
                      </div>
                      <div className="trust-bar" style={{ marginTop: 4 }}>
                        <div
                          style={{
                            width: `${a.trust}%`,
                            background:
                              a.trust < 60 ? 'var(--danger)' :
                              a.trust < 80 ? 'var(--warn)' :
                              'var(--ok)',
                          }}
                        />
                      </div>
                    </div>
                    {window.RESOURCES.map((r) => {
                      const cap = a.caps[r.id];
                      const decision = cap[verb] || 'na';
                      const flag = cap.flag && verb !== 'na';
                      return (
                        <div
                          key={r.id}
                          className={`mx-cell mx-cell-${decision}`}
                          onClick={() => decision !== 'na' && openCell({ agent: a, resource: r, verb, decision })}
                        >
                          {window.DECISIONS[decision]?.label || decision}
                          {flag && decision !== 'na' && <span className="mx-cell-flag" />}
                        </div>
                      );
                    })}
                  </RowGroup>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 12, marginTop: 16, flexWrap: 'wrap' }}>
              <SummaryStat n={visibleAgents.reduce((s, a) => s + window.RESOURCES.filter((r) => a.caps[r.id][verb] === 'allow').length, 0)} label={`total "allow" cells (${verb})`} />
              <SummaryStat n={visibleAgents.reduce((s, a) => s + window.RESOURCES.filter((r) => a.caps[r.id][verb] === 'narrow').length, 0)} label="narrowed" tone="warn" />
              <SummaryStat n={visibleAgents.reduce((s, a) => s + window.RESOURCES.filter((r) => a.caps[r.id][verb] === 'deny').length, 0)} label="denied" tone="ok" />
              <SummaryStat n={visibleAgents.filter((a) => a.flagged).length} label="flagged agents" tone="danger" />
            </div>
          </div>
        </>
      )}

      {tab === 'resource' && <PerResourceView selected={selectedRes} setSelected={setSelectedRes} agents={visibleAgents} verb={verb} openCell={openCell} />}
      {tab === 'agent' && <PerAgentView selected={selectedAgent} setSelected={setSelectedAgent} agents={visibleAgents} openCell={openCell} />}
    </>
  );
}

function SummaryStat({ n, label, tone }) {
  const color = tone === 'warn' ? 'var(--warn)' : tone === 'danger' ? 'var(--danger)' : tone === 'ok' ? 'var(--ok)' : 'var(--ink)';
  return (
    <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', padding: '10px 14px', borderRadius: 3, minWidth: 160 }}>
      <div style={{ fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>{label}</div>
      <div style={{ fontFamily: 'JetBrains Mono', fontSize: 22, fontWeight: 700, color }}>{n}</div>
    </div>
  );
}

function PerResourceView({ selected, setSelected, agents, verb, openCell }) {
  const res = window.RESOURCES.find((r) => r.id === selected);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 1, background: 'var(--line)', minHeight: 'calc(100vh - 56px - 41px - 40px)' }}>
      <div className="tree">
        <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)', marginBottom: 8 }}>Resources</div>
        {window.RESOURCES.map((r) => (
          <div
            key={r.id}
            className={`tree-node ${r.id === selected ? 'active' : ''}`}
            onClick={() => setSelected(r.id)}
          >
            <span className="tree-caret">▸</span>
            <span style={{ flex: 1 }}>{r.name}</span>
            <span style={{ fontSize: 10, opacity: 0.6 }}>{agents.filter((a) => a.caps[r.id][verb] !== 'na').length}</span>
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--paper)', padding: 20, overflow: 'auto' }}>
        <div style={{ marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Who can <span style={{ color: 'var(--warn)' }}>{verb}</span> on <span className="mono">{res?.name}</span>?</h2>
          <div style={{ color: 'var(--ink-3)', fontSize: 12, marginTop: 4 }}>{res?.paths?.length} resource paths · {agents.length} agents in scope</div>
        </div>

        <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
          <table className="calls-table" style={{ fontSize: 12 }}>
            <thead>
              <tr><th>agent</th><th>trust</th><th>effective</th><th>narrowed by</th><th>last call</th><th></th></tr>
            </thead>
            <tbody>
              {agents.map((a) => {
                const d = a.caps[selected][verb] || 'na';
                if (d === 'na') return null;
                return (
                  <tr key={a.id}>
                    <td><b>{a.name}</b> {a.flagged && <span className="flag-dot" style={{ color: 'var(--danger)' }}>●</span>}</td>
                    <td>{a.trust}</td>
                    <td><span className={`dot dot-${d}`}></span><span style={{ color: `var(${window.DECISIONS[d].color})`, fontWeight: 600, textTransform: 'uppercase' }}>{d}</span></td>
                    <td style={{ color: 'var(--ink-3)' }}>{d === 'allow' ? '— (no policy)' : d === 'narrow' ? 'P-021' : d === 'approval' ? 'P-014, P-035' : 'P-066'}</td>
                    <td style={{ color: 'var(--ink-4)' }}>{a.lastSeen}</td>
                    <td><button className="btn btn-sm" onClick={() => openCell({ agent: a, resource: res, verb, decision: d })}>inspect</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function PerAgentView({ selected, setSelected, agents, openCell }) {
  const agent = agents.find((a) => a.id === selected) || agents[0];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 1, background: 'var(--line)', minHeight: 'calc(100vh - 56px - 41px - 40px)' }}>
      <div className="tree">
        <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)', marginBottom: 8 }}>Agents</div>
        {agents.map((a) => (
          <div
            key={a.id}
            className={`tree-node ${a.id === agent?.id ? 'active' : ''}`}
            onClick={() => setSelected(a.id)}
          >
            <span className="tree-caret">▸</span>
            <span style={{ flex: 1 }}>{a.name}</span>
            {a.flagged && <span className="flag-dot" style={{ color: a.id === agent?.id ? '#fca5a5' : 'var(--danger)' }}>●</span>}
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--paper)', padding: 20, overflow: 'auto' }}>
        {agent && <>
          <div style={{ marginBottom: 16 }}>
            <h2 style={{ margin: 0, fontSize: 18 }}>{agent.name} {agent.flagged && <span className="flag-dot" style={{ color: 'var(--danger)' }}>●</span>}</h2>
            <div style={{ color: 'var(--ink-3)', fontSize: 12, marginTop: 4 }}>
              {agent.framework} · {agent.owner} · trust {agent.trust} · {agent.mode} mode
              {agent.note && <span style={{ marginLeft: 8, color: 'var(--danger)' }}>— {agent.note}</span>}
            </div>
          </div>

          <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
            <table className="calls-table" style={{ fontSize: 12 }}>
              <thead>
                <tr><th>resource</th><th>read</th><th>write</th><th>delete</th><th>exec</th><th></th></tr>
              </thead>
              <tbody>
                {window.RESOURCES.map((r) => (
                  <tr key={r.id}>
                    <td><b>{r.name}</b> <span style={{ color: 'var(--ink-4)' }}>· {r.group}</span></td>
                    {window.VERBS.map((v) => {
                      const d = agent.caps[r.id][v] || 'na';
                      return (
                        <td key={v} onClick={() => d !== 'na' && openCell({ agent, resource: r, verb: v, decision: d })} style={{ cursor: d === 'na' ? 'default' : 'pointer' }}>
                          {d !== 'na' && <span className={`dot dot-${d}`}></span>}
                          <span style={{ color: `var(${window.DECISIONS[d].color})`, fontWeight: d === 'na' ? 400 : 600, textTransform: 'uppercase', fontSize: 10 }}>{d}</span>
                        </td>
                      );
                    })}
                    <td><button className="btn btn-sm">narrow…</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>}
      </div>
    </div>
  );
}

// ============================================================
// Cell-inspect drawer
// ============================================================

function CellInspectDrawer({ cell, onClose, goPolicy }) {
  if (!cell) return null;
  const { agent, resource, verb, decision } = cell;
  const responsiblePolicies = window.POLICIES.filter((p) =>
    p.affects.includes(agent.id) &&
    p.rules.some((r) => r.resource === resource.id && r.verb.includes(verb))
  );

  return (
    <div className="scrim" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>capability cell</div>
            <h2 style={{ margin: '4px 0 0', fontSize: 18 }}>
              <span className="mono">{agent.name}</span> · <span style={{ color: 'var(--warn)' }}>{verb}</span> · <span className="mono">{resource.name}</span>
            </h2>
            <div style={{ marginTop: 6, display: 'flex', gap: 6 }}>
              <span className={`chip chip-${decision === 'allow' ? '' : decision}`} style={{ textTransform: 'uppercase' }}>
                effective: {window.DECISIONS[decision].label}
              </span>
              <span className="chip">claimed: full access</span>
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose}>✕</button>
        </div>

        <div className="drawer-body">
          <div className="section-title">claimed vs effective</div>
          <div style={{ background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 3, padding: 12, marginBottom: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>agent claims</div>
                <div className="mono" style={{ fontSize: 12 }}>{verb}({resource.id}/*)</div>
                <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 4 }}>declared in agent manifest at registration</div>
              </div>
              <div>
                <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>assembly grants</div>
                <div className="mono" style={{ fontSize: 12, color: `var(${window.DECISIONS[decision].color})`, fontWeight: 600 }}>
                  {decision === 'narrow' ? `${verb}(${resource.id}/labels/INBOX/*)` : `${verb}(${resource.id}/*) → ${decision}`}
                </div>
                <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 4 }}>computed from {responsiblePolicies.length} policies</div>
              </div>
            </div>
          </div>

          <div className="section-title">policies responsible</div>
          {responsiblePolicies.length === 0 && (
            <div style={{ background: 'var(--paper)', border: '1px dashed var(--line-2)', padding: 12, fontSize: 12, color: 'var(--ink-4)', borderRadius: 3 }}>
              No policy narrows this — agent has full claimed permission.
            </div>
          )}
          {responsiblePolicies.map((p) => (
            <div key={p.id} style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, padding: 12, marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--ink-4)' }}>{p.id} · {p.version}</span>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</div>
                </div>
                <button className="btn btn-sm" onClick={() => goPolicy(p.id)}>edit →</button>
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 6, fontFamily: 'JetBrains Mono' }}>scope: {p.scope}</div>
            </div>
          ))}

          <div className="section-title" style={{ marginTop: 16 }}>recent calls (24h)</div>
          <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, overflow: 'hidden' }}>
            <table className="calls-table">
              <thead><tr><th>time</th><th>path</th><th>decision</th></tr></thead>
              <tbody>
                {window.SAMPLE_CALLS.filter((c) => c.agent === agent.id && c.verb === verb).slice(0, 5).map((c, i) => (
                  <tr key={i}>
                    <td>{c.ts}</td>
                    <td>{c.resource}</td>
                    <td><span className={`dot dot-${c.currentDecision}`}></span>{c.currentDecision}</td>
                  </tr>
                ))}
                {window.SAMPLE_CALLS.filter((c) => c.agent === agent.id && c.verb === verb).length === 0 && (
                  <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--ink-4)', padding: 14 }}>no recent calls</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="drawer-foot">
          <button className="btn">simulate change</button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn">narrow further…</button>
            <button className="btn btn-primary" onClick={() => goPolicy('P-066')}>open in Policy editor</button>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { CapabilityPage, CellInspectDrawer });
