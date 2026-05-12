/* global React */
const { useState: useSAD } = React;

// ============================================================
// Agent Detail page — drill-down from Fleet
// Header (identity card) · tabs: overview / capability snapshot / recent traffic / policies / config
// ============================================================

function TrustGauge({ score }) {
  const color = score < 50 ? '#b8291e' : score < 75 ? '#8a5a00' : '#22592a';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <svg width="48" height="48" viewBox="0 0 48 48">
        <circle cx="24" cy="24" r="20" fill="none" stroke="var(--line-2)" strokeWidth="4" />
        <circle cx="24" cy="24" r="20" fill="none" stroke={color} strokeWidth="4"
          strokeDasharray={`${(score / 100) * 125.6} 125.6`}
          strokeDashoffset="0"
          transform="rotate(-90 24 24)"
          strokeLinecap="round"
        />
        <text x="24" y="28" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="13" fontWeight="600" fill={color}>{score}</text>
      </svg>
      <div>
        <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)' }}>trust score</div>
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 2 }}>{score < 50 ? 'low — needs review' : score < 75 ? 'moderate' : 'good standing'}</div>
      </div>
    </div>
  );
}

function MiniBar({ label, value, max, color, suffix }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
      <div style={{ width: 110, fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--ink-3)' }}>{label}</div>
      <div style={{ flex: 1, height: 6, background: 'var(--paper-3)', borderRadius: 1, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color }}></div>
      </div>
      <div style={{ width: 60, textAlign: 'right', fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-2)', fontWeight: 600 }}>{value}{suffix || ''}</div>
    </div>
  );
}

function CapMatrixMini({ agent, openCell }) {
  const verbs = ['read', 'write', 'delete', 'exec'];
  const decisionLabel = (d) => d === 'allow' ? '✓' : d === 'narrow' ? '↓' : d === 'deny' ? '✕' : d === 'approval' ? '?' : '—';
  return (
    <div style={{ overflow: 'auto', border: '1px solid var(--line)', borderRadius: 3 }}>
      <table className="data-table" style={{ minWidth: 'unset' }}>
        <thead>
          <tr>
            <th style={{ minWidth: 110 }}>resource</th>
            {verbs.map((v) => <th key={v} style={{ textAlign: 'center', minWidth: 60 }}>{v}</th>)}
          </tr>
        </thead>
        <tbody>
          {window.RESOURCES.map((r) => (
            <tr key={r.id}>
              <td style={{ fontSize: 12 }}>
                <div style={{ fontWeight: 600 }}>{r.name}</div>
                <div className="wf-mono" style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)' }}>{r.id}</div>
              </td>
              {verbs.map((v) => {
                const cell = agent.caps[r.id]?.[v];
                if (!cell || cell === 'na') {
                  return <td key={v} style={{ textAlign: 'center', color: 'var(--ink-5)' }}>—</td>;
                }
                const bg = cell === 'allow' ? '#fbfaf6'
                  : cell === 'narrow' ? 'var(--warn-bg)'
                  : cell === 'approval' ? 'var(--info-bg)'
                  : cell === 'deny' ? 'var(--danger-bg)' : '#fbfaf6';
                const color = cell === 'allow' ? 'var(--ink-3)'
                  : cell === 'narrow' ? 'var(--warn)'
                  : cell === 'approval' ? 'var(--info)'
                  : cell === 'deny' ? 'var(--danger)' : 'var(--ink)';
                const flag = agent.caps[r.id]?.flag;
                return (
                  <td key={v}
                    style={{ textAlign: 'center', background: bg, color, cursor: 'pointer', position: 'relative', fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 600 }}
                    onClick={() => openCell({ agent, resource: r, verb: v })}>
                    {decisionLabel(cell)}{' '}{cell}
                    {flag && v === 'write' && <span style={{ position: 'absolute', top: 2, right: 4, color: 'var(--danger)', fontSize: 8 }}>●</span>}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RecentTraffic({ agent }) {
  const decisions = ['allow', 'allow', 'narrow', 'allow', 'scrub', 'allow', 'allow', 'narrow', 'allow', 'deny', 'allow', 'narrow', 'scrub', 'allow', 'allow'];
  const verbs = ['read', 'write', 'read', 'read', 'write', 'read', 'write', 'read', 'read'];
  const resources = ['gmail.send', 'pg.users', 'gdrive.read', 's3.write', 'github.commit', 'http.post', 'gmail.read', 'pg.orders'];
  const rows = [];
  for (let i = 0; i < 18; i++) {
    const t = new Date(Date.now() - i * 23000);
    rows.push({
      ts: `${t.getHours().toString().padStart(2,'0')}:${t.getMinutes().toString().padStart(2,'0')}:${t.getSeconds().toString().padStart(2,'0')}`,
      verb: verbs[i % verbs.length],
      res: resources[i % resources.length],
      dec: decisions[i % decisions.length],
      latency: 12 + Math.round(Math.random() * 80),
    });
  }
  return (
    <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
      <div className="live-pane-head">
        <div className="live-pane-title">▶ recent decisions · last 5min</div>
        <div style={{ display: 'flex', gap: 4 }}>
          <button className="btn btn-sm">tail in Live Ops →</button>
          <button className="btn btn-sm">⏏ export</button>
        </div>
      </div>
      <table className="data-table" style={{ minWidth: 'unset' }}>
        <thead>
          <tr>
            <th>ts</th>
            <th>verb</th>
            <th>resource</th>
            <th>decision</th>
            <th style={{ textAlign: 'right' }}>latency</th>
            <th>policy</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const color = r.dec === 'allow' ? 'var(--ok)' : r.dec === 'narrow' ? 'var(--warn)' : r.dec === 'scrub' ? 'var(--scrub)' : 'var(--danger)';
            return (
              <tr key={i}>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-3)' }}>{r.ts}</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10 }}>{r.verb}</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-2)' }}>{r.res}</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10, fontWeight: 600, color, textTransform: 'uppercase' }}>● {r.dec}</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10, textAlign: 'right', color: 'var(--ink-4)' }}>{r.latency}ms</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)' }}>{r.dec === 'narrow' || r.dec === 'deny' ? 'P-066' : r.dec === 'scrub' ? 'P-100' : '—'}</td>
                <td><button className="btn btn-sm btn-ghost">trace ↗</button></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function PoliciesAffecting({ agent }) {
  const policies = [
    { id: 'P-001', name: 'global default-deny', match: 'all agents', impact: 'baseline' },
    { id: 'P-066', name: 'narrow research-bot writes', match: agent.id === 'research-bot-04' ? 'targeted' : 'matched by tag', impact: agent.id === 'research-bot-04' ? '4 narrows' : 'inactive', emphasize: agent.id === 'research-bot-04' },
    { id: 'P-100', name: 'L3 secret scrubbing', match: 'all egress', impact: `${agent.scrubbed24h} scrubs / 24h` },
    { id: 'P-122', name: 'PII destinations require approval', match: 's3://customer-pii/*', impact: agent.id === 'research-bot-04' ? '8 awaiting' : '0 awaiting' },
  ];
  return (
    <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
      <div className="live-pane-head">
        <div className="live-pane-title">⚖ policies affecting this agent</div>
        <button className="btn btn-sm">+ apply policy</button>
      </div>
      <table className="data-table" style={{ minWidth: 'unset' }}>
        <thead>
          <tr>
            <th>id</th><th>name</th><th>matched via</th><th>impact (24h)</th><th></th>
          </tr>
        </thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id} style={{ background: p.emphasize ? 'rgba(184,41,30,0.04)' : undefined }}>
              <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 600 }}>{p.id}</td>
              <td>
                <div style={{ fontWeight: 600, fontSize: 12 }}>
                  {p.emphasize && <span style={{ color: 'var(--danger)', marginRight: 5 }}>●</span>}
                  {p.name}
                </div>
              </td>
              <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-3)' }}>{p.match}</td>
              <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: p.emphasize ? 'var(--danger)' : 'var(--ink-2)', fontWeight: p.emphasize ? 600 : 400 }}>{p.impact}</td>
              <td><button className="btn btn-sm">open ↗</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AgentDetailPage({ agentId, goRoute, openCell, goPolicy, toast }) {
  const [tab, setTab] = useSAD('overview');
  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="agent" />;
  if (ps === 'error')   return <window.ErrorState kind="generic" />;
  const agent = window.AGENTS.find((a) => a.id === agentId) || window.AGENTS[0];

  return (
    <>
      <div className="page-head">
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <a onClick={() => goRoute('fleet')} style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', cursor: 'pointer', textDecoration: 'underline' }}>← fleet</a>
            <span style={{ color: 'var(--ink-5)' }}>›</span>
            <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--ink-3)' }}>{agent.id}</span>
          </div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {agent.flagged && <span className="flag-dot" style={{ color: 'var(--danger)' }}>●</span>}
            {agent.name}
            <span className="chip" style={{ fontSize: 10 }}>{agent.framework}</span>
            <span style={{ fontSize: 12, color: 'var(--ink-3)', fontWeight: 400, fontFamily: 'JetBrains Mono' }}>@{agent.owner}</span>
          </h1>
          {agent.note && <div className="page-sub" style={{ color: 'var(--danger)', fontWeight: 500 }}>⚠ {agent.note}</div>}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className="btn" onClick={() => toast(`Opened trace for ${agent.id}`)}>⎈ trace last call</button>
          <button className="btn" onClick={() => toast(`Switched ${agent.id} to shadow mode`)}>→ shadow mode</button>
          <button className="btn btn-danger" onClick={() => toast(`Suspended ${agent.id}`)}>■ suspend</button>
        </div>
      </div>

      {/* Identity card strip */}
      <div style={{ padding: '14px 24px', background: 'var(--paper-2)', borderBottom: '1px solid var(--line)', display: 'grid', gridTemplateColumns: '1.2fr 1fr 1fr 1fr 1fr', gap: 16 }}>
        <div>
          <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)' }}>identity (DID)</div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-2)', marginTop: 4, wordBreak: 'break-all' }}>did:agent:acme:{agent.id}</div>
          <div style={{ fontSize: 10, color: 'var(--ink-4)', marginTop: 4 }}>signed by acme-issuer · expires 2026-09-12</div>
        </div>
        <TrustGauge score={agent.trust} />
        <div>
          <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)' }}>mode / status</div>
          <div style={{ marginTop: 4, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <span className={`chip ${agent.mode === 'enforce' ? 'chip-solid' : 'chip-warn'}`} style={{ fontSize: 10 }}>{agent.mode}</span>
            <span className={`chip ${agent.status === 'active' ? 'chip-ok' : 'chip-danger'}`} style={{ fontSize: 10 }}>● {agent.status}</span>
          </div>
          <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-3)', marginTop: 6 }}>last seen {agent.lastSeen}</div>
        </div>
        <div>
          <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)' }}>blocked / 24h</div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 22, fontWeight: 700, color: agent.blocked24h > 50 ? 'var(--danger)' : 'var(--ink)', marginTop: 4 }}>{agent.blocked24h}</div>
          <div style={{ fontSize: 10, color: 'var(--ink-4)' }}>capability denials</div>
        </div>
        <div>
          <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)' }}>scrubbed / 24h</div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 22, fontWeight: 700, color: 'var(--scrub)', marginTop: 4 }}>{agent.scrubbed24h}</div>
          <div style={{ fontSize: 10, color: 'var(--ink-4)' }}>secrets stripped at L3</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        {[
          ['overview',   'Overview'],
          ['capability', 'Capability snapshot'],
          ['traffic',    'Recent traffic'],
          ['policies',   'Policies'],
          ['lineage',    'Lineage'],
          ['config',     'Config'],
        ].map(([id, label]) => (
          <div key={id} className={`tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>{label}</div>
        ))}
      </div>

      {/* Tab body */}
      <div style={{ flex: 1, overflow: 'auto', padding: 20, background: 'var(--paper)' }}>
        {tab === 'overview' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, padding: 16 }}>
              <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)', marginBottom: 10 }}>posture summary</div>
              <MiniBar label="resources allow" value={Object.values(agent.caps).filter((c) => c.read === 'allow' || c.write === 'allow').length} max={8} color="#22592a" />
              <MiniBar label="resources narrow" value={Object.values(agent.caps).filter((c) => c.read === 'narrow' || c.write === 'narrow').length} max={8} color="#8a5a00" />
              <MiniBar label="resources deny" value={Object.values(agent.caps).filter((c) => c.read === 'deny' && c.write === 'deny').length} max={8} color="#b8291e" />
              <MiniBar label="approvals required" value={Object.values(agent.caps).filter((c) => c.read === 'approval' || c.write === 'approval').length} max={8} color="#1d3a7a" />
              <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px dashed var(--line)' }}>
                <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)', marginBottom: 6 }}>recommendation</div>
                {agent.id === 'research-bot-04' ? (
                  <div style={{ fontSize: 12, color: 'var(--danger)', lineHeight: 1.5 }}>
                    Apply <b>P-066</b> to narrow gmail/write, gdrive/write, http/write to specific paths. Estimated impact: <b>−43%</b> blocked calls without service degradation.
                    <div style={{ marginTop: 8 }}>
                      <button className="btn btn-sm btn-danger" onClick={() => goPolicy('P-066')}>review P-066 →</button>
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: 'var(--ink-3)' }}>Posture is balanced. No urgent action required.</div>
                )}
              </div>
            </div>

            <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, padding: 16 }}>
              <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)', marginBottom: 10 }}>traffic mix · last 24h</div>
              <div style={{ display: 'flex', height: 36, border: '1px solid var(--line-2)', borderRadius: 2, overflow: 'hidden', marginTop: 6 }}>
                <div style={{ flex: 0.62, background: '#fbfaf6', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ok)', borderRight: '1px solid var(--line-2)' }}>allow 62%</div>
                <div style={{ flex: 0.18, background: 'var(--warn-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--warn)', borderRight: '1px solid var(--line-2)' }}>narrow 18%</div>
                <div style={{ flex: 0.10, background: 'var(--scrub-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--scrub)', borderRight: '1px solid var(--line-2)' }}>scrub 10%</div>
                <div style={{ flex: 0.06, background: 'var(--info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--info)', borderRight: '1px solid var(--line-2)' }}>?</div>
                <div style={{ flex: 0.04, background: 'var(--danger-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--danger)' }}>✕</div>
              </div>
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)', marginBottom: 6 }}>top resources accessed</div>
                <MiniBar label="pg.public.users" value={1284} max={1500} color="var(--ink-2)" />
                <MiniBar label="gdrive.read" value={892} max={1500} color="var(--ink-2)" />
                <MiniBar label="gmail.send" value={341} max={1500} color="var(--ink-2)" />
                <MiniBar label="http.post" value={218} max={1500} color="var(--ink-2)" />
                <MiniBar label="s3.write" value={97} max={1500} color="var(--ink-2)" />
              </div>
            </div>

            <div style={{ gridColumn: 'span 2' }}>
              <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)', marginBottom: 8 }}>capability snapshot · click any cell to inspect</div>
              <CapMatrixMini agent={agent} openCell={(c) => { goRoute('capability'); setTimeout(() => openCell(c), 50); }} />
            </div>
          </div>
        )}

        {tab === 'capability' && (
          <div>
            <div style={{ marginBottom: 12, fontSize: 13, color: 'var(--ink-3)' }}>
              Same matrix as Capability page, scoped to this agent. Click any cell to open the inspect drawer with claimed-vs-effective breakdown.
            </div>
            <CapMatrixMini agent={agent} openCell={(c) => { goRoute('capability'); setTimeout(() => openCell(c), 50); }} />
          </div>
        )}

        {tab === 'traffic' && <RecentTraffic agent={agent} />}

        {tab === 'policies' && <PoliciesAffecting agent={agent} />}

        {tab === 'lineage' && (() => {
          // Build ancestry chain by walking parentId up through TOPO_NODES
          const nodes = window.TOPO_NODES || [];
          const chain = [];
          let cur = nodes.find((n) => n.id === agent.id);
          while (cur) {
            chain.unshift(cur);
            if (!cur.parentId) break;
            cur = nodes.find((n) => n.id === cur.parentId);
          }
          // Also list children
          const children = nodes.filter((n) => n.parentId === agent.id);

          return (
            <div style={{ maxWidth: 640 }}>
              {/* Lineage chain */}
              <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, padding: 18, marginBottom: 14 }}>
                <div className="section-title" style={{ marginBottom: 12 }}>
                  delegation chain — root → current
                </div>
                {chain.length === 0 ? (
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)' }}>
                    Agent not found in topology graph.
                  </div>
                ) : chain.map((node, i) => {
                  const isCurrent = node.id === agent.id;
                  const isRoot    = i === 0;
                  return (
                    <div key={node.id} style={{ display: 'flex', flexDirection: 'column' }}>
                      {/* Connector line above (skip for first) */}
                      {i > 0 && (
                        <div style={{ display: 'flex', alignItems: 'stretch', gap: 0, paddingLeft: 15 }}>
                          <div style={{ width: 1, background: 'var(--line-2)', margin: '0 0 0 0', height: 20 }}></div>
                          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)', paddingLeft: 10, paddingTop: 4 }}>
                            {node.parentId && (() => {
                              const edge = (window.TOPO_EDGES || []).find((e) =>
                                e.source === chain[i - 1].id && e.target === node.id
                              );
                              return edge ? `${edge.type} · depth ${node.depth}` : `depth ${node.depth}`;
                            })()}
                          </div>
                        </div>
                      )}
                      {/* Node card */}
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 12,
                        padding: '10px 14px',
                        background: isCurrent ? 'var(--ink)' : isRoot ? 'var(--paper-3)' : 'var(--paper)',
                        border: `1px solid ${isCurrent ? 'var(--ink)' : 'var(--line-2)'}`,
                        borderRadius: 3,
                        marginLeft: i * 20,
                      }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: '50%',
                          background: isCurrent ? 'rgba(255,255,255,0.15)' : 'var(--paper-3)',
                          border: `1px solid ${isCurrent ? 'rgba(255,255,255,0.3)' : 'var(--line-2)'}`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontFamily: 'JetBrains Mono, monospace', fontSize: 10, fontWeight: 700,
                          color: isCurrent ? '#fff' : 'var(--ink-3)', flexShrink: 0,
                        }}>{node.depth}</div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 700, color: isCurrent ? '#fff' : 'var(--ink)' }}>
                            {node.name}
                            {isCurrent && <span style={{ marginLeft: 8, fontWeight: 400, fontSize: 10, opacity: 0.7 }}>← current</span>}
                            {isRoot && !isCurrent && <span style={{ marginLeft: 8, fontWeight: 400, fontSize: 10, color: 'var(--ink-4)' }}>root</span>}
                          </div>
                          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: isCurrent ? 'rgba(255,255,255,0.55)' : 'var(--ink-4)', marginTop: 2 }}>
                            {node.framework} · {node.team}
                          </div>
                        </div>
                        <span className={`chip ${node.status === 'active' ? 'chip-ok' : 'chip-warn'}`} style={{ fontSize: 9, background: isCurrent ? 'rgba(255,255,255,0.12)' : undefined, borderColor: isCurrent ? 'rgba(255,255,255,0.25)' : undefined, color: isCurrent ? '#fff' : undefined }}>
                          {node.status}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Children */}
              {children.length > 0 && (
                <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, padding: 18 }}>
                  <div className="section-title" style={{ marginBottom: 10 }}>
                    direct sub-agents ({children.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {children.map((c) => (
                      <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 3 }}>
                        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, background: 'var(--paper-3)', border: '1px solid var(--line-2)', borderRadius: '50%', width: 22, height: 22, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>
                          {c.depth}
                        </div>
                        <div style={{ flex: 1 }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600 }}>{c.name}</span>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)', marginLeft: 8 }}>{c.framework}</span>
                        </div>
                        {(() => {
                          const edge = (window.TOPO_EDGES || []).find((e) => e.source === agent.id && e.target === c.id);
                          return edge ? <span className="chip" style={{ fontSize: 9 }}>{edge.type}</span> : null;
                        })()}
                        <span className={`chip ${c.status === 'active' ? 'chip-ok' : 'chip-warn'}`} style={{ fontSize: 9 }}>{c.status}</span>
                        {c.flagged && <span className="chip chip-danger" style={{ fontSize: 9 }}>flagged</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {chain.length === 1 && children.length === 0 && (
                <div className="callout info">
                  <div className="callout-title">Root agent — no parent or children</div>
                  This agent sits at depth 0 and has not spawned any sub-agents in this session.
                </div>
              )}
            </div>
          );
        })()}

        {tab === 'config' && (
          <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 3, padding: 18, fontFamily: 'JetBrains Mono', fontSize: 12, lineHeight: 1.6 }}>
            <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-4)', marginBottom: 8 }}>config (read-only · last applied 4d ago)</div>
            <pre style={{ margin: 0, color: 'var(--ink-2)', whiteSpace: 'pre-wrap' }}>
{`agent:
  id: "${agent.id}"
  framework: ${agent.framework.toLowerCase()}
  owner: "@${agent.owner}"
  identity:
    issuer: acme-issuer
    did: did:agent:acme:${agent.id}
  enforcement:
    mode: ${agent.mode}
    fail_open: false
  policies:
    - P-001    # global default-deny
    - P-066    # narrow research-bot writes
    - P-100    # L3 secret scrubbing
    - P-122    # PII destinations require approval
  rate_limit:
    rpm: 600
    burst: 30
  observability:
    trace_sampling: 0.1
    audit_log: true`}
            </pre>
          </div>
        )}
      </div>
    </>
  );
}

Object.assign(window, { AgentDetailPage });
