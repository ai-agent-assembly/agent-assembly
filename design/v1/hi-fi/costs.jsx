/* global React */
const { useState: useCostSt } = React;

/* ============================================================
   Cost & Budget page  —  AAASM-120
   Mirrors GET /api/v1/costs  (daily + monthly + per-agent + per-team)
   ============================================================ */

function BudgetBar({ used, limit, showLabel }) {
  const pct   = limit > 0 ? Math.min(100, (used / limit) * 100) : 0;
  const color = pct >= 95 ? 'var(--danger)' : pct >= 80 ? 'var(--warn)' : 'var(--ok)';
  return (
    <div style={{ width: '100%' }}>
      {showLabel && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>
          <span>${used.toFixed(2)}</span>
          <span style={{ color: pct >= 80 ? color : undefined }}>{pct.toFixed(0)}%</span>
        </div>
      )}
      <div style={{ height: 4, background: 'var(--paper-3)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.4s' }}></div>
      </div>
    </div>
  );
}

function Sparkline({ data, color }) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, 0.01);
  const W = 64, H = 22;
  const pts = data.map((v, i) =>
    `${(i / (data.length - 1)) * W},${H - 2 - ((v / max) * (H - 4))}`
  ).join(' ');
  return (
    <svg width={W} height={H} style={{ display: 'block' }}>
      <polyline points={pts} fill="none" stroke={color || 'var(--ink-3)'} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function HistoryChart({ data }) {
  if (!data || !data.length) return null;
  const max = Math.max(...data.map((d) => d.spend), 1);
  const W = 560, H = 90, barW = 52, gap = (W - barW * data.length) / (data.length + 1);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: '100%', height: H }}>
      {data.map((d, i) => {
        const h    = Math.max(4, (d.spend / max) * (H - 26));
        const x    = gap + i * (barW + gap);
        const y    = H - 18 - h;
        const last = i === data.length - 1;
        return (
          <g key={d.date}>
            <rect x={x} y={y} width={barW} height={h}
              fill={last ? 'var(--ink)' : 'var(--line-2)'} rx="2" />
            <text x={x + barW / 2} y={H - 3}
              textAnchor="middle" fontSize="9" fill="var(--ink-4)"
              fontFamily="JetBrains Mono, monospace">{d.date}</text>
            <text x={x + barW / 2} y={y - 4}
              textAnchor="middle" fontSize="9"
              fill={last ? 'var(--ink)' : 'var(--ink-4)'}
              fontFamily="JetBrains Mono, monospace">${d.spend.toFixed(0)}</text>
          </g>
        );
      })}
    </svg>
  );
}

/* ── Budget Subtree Tree ─────────────────────────────────────────────────── */

function BudgetTreeNode({ node, parentLimit, expanded, onToggle }) {
  const hasKids    = node.children && node.children.length > 0;
  const open       = expanded.has(node.id);
  const childSpend = Math.max(0, node.subtree_spend - node.own_spend);
  const ownPct     = node.budget_limit > 0 ? Math.min(100, (node.own_spend    / node.budget_limit) * 100) : 0;
  const childPct   = node.budget_limit > 0 ? Math.min(100 - ownPct, (childSpend / node.budget_limit) * 100) : 0;
  const totalPct   = node.budget_limit > 0 ? Math.min(100, (node.subtree_spend / node.budget_limit) * 100) : 0;
  const parentPct  = parentLimit > 0 ? Math.min(100, (node.subtree_spend / parentLimit) * 100) : null;
  const col        = totalPct >= 85 ? 'var(--danger)' : totalPct >= 70 ? 'var(--warn)' : 'var(--ok)';
  const rowBg      = totalPct >= 85 ? 'rgba(220,53,69,0.03)' : 'transparent';

  const kindBg    = { org: 'var(--paper-3)', team: '#e8f0fe', agent: 'var(--paper-3)' }[node.kind] || 'var(--paper-3)';
  const kindColor = { org: 'var(--ink-4)',   team: '#1a56db',  agent: 'var(--ink-3)'  }[node.kind] || 'var(--ink-4)';
  const INDENT    = 20;

  return (
    <div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 80px 80px 72px 180px 72px',
          alignItems: 'center',
          padding: '8px 24px',
          borderBottom: '1px solid var(--line)',
          background: rowBg,
          gap: 10,
          cursor: hasKids ? 'pointer' : 'default',
          transition: 'background 0.15s',
        }}
        onClick={() => hasKids && onToggle(node.id)}
      >
        {/* Name column */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, paddingLeft: node.depth * INDENT, minWidth: 0 }}>
          <span style={{ width: 12, fontSize: 10, color: 'var(--ink-4)', flexShrink: 0, userSelect: 'none' }}>
            {hasKids ? (open ? '▾' : '▸') : '·'}
          </span>
          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, background: kindBg, color: kindColor, flexShrink: 0 }}>
            {node.kind}
          </span>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: node.depth <= 1 ? 600 : 400, color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {node.label}
          </span>
          {node.budget_kind === 'session' && (
            <span style={{ fontSize: 9, color: 'var(--ink-4)', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>per-session</span>
          )}
          {node.governance_level && (
            <span style={{ fontSize: 9, padding: '1px 4px', borderRadius: 3, background: 'var(--paper-3)', color: 'var(--ink-4)', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>
              {node.governance_level}
            </span>
          )}
        </div>

        {/* Own spend */}
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: node.own_spend > 0 ? 'var(--ink-2)' : 'var(--ink-4)', textAlign: 'right' }}>
          {node.own_spend > 0 ? `$${node.own_spend.toFixed(2)}` : '—'}
        </div>

        {/* Subtree spend */}
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, fontWeight: 700, color: col, textAlign: 'right' }}>
          ${node.subtree_spend.toFixed(2)}
        </div>

        {/* Limit */}
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)', textAlign: 'right' }}>
          ${node.budget_limit.toFixed(0)}
        </div>

        {/* Stacked burn bar */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}>
            <span style={{ color: col, fontWeight: 600 }}>{totalPct.toFixed(1)}%</span>
            {hasKids && childPct > 1 && (
              <span style={{ color: 'var(--ink-4)' }}>+{childPct.toFixed(0)}% sub-agents</span>
            )}
          </div>
          <div style={{ height: 5, background: 'var(--paper-3)', borderRadius: 3, overflow: 'hidden', position: 'relative' }}>
            {/* Full subtree band (lighter) */}
            <div style={{ position: 'absolute', left: 0, width: `${totalPct}%`, height: '100%', background: col, opacity: 0.25 }} />
            {/* Own spend overlay (solid) */}
            {ownPct > 0 && (
              <div style={{ position: 'absolute', left: 0, width: `${ownPct}%`, height: '100%', background: col }} />
            )}
          </div>
        </div>

        {/* % of parent */}
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: parentPct !== null ? (parentPct >= 70 ? col : 'var(--ink-3)') : 'var(--ink-4)', textAlign: 'right' }}>
          {parentPct !== null ? `${parentPct.toFixed(0)}%` : '—'}
        </div>
      </div>

      {hasKids && open && node.children.map((child) => (
        <BudgetTreeNode
          key={child.id}
          node={child}
          parentLimit={node.budget_limit}
          expanded={expanded}
          onToggle={onToggle}
        />
      ))}
    </div>
  );
}

function BudgetTreeTab() {
  const [expanded, setExpanded] = useCostSt(
    () => new Set(['__org__', 'data-platform', 'platform', 'cx-tools', 'rev-ops', 'knowledge'])
  );
  const onToggle = (id) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const tree = window.BUDGET_TREE;
  if (!tree) return <div className="empty">no budget tree data</div>;

  return (
    <div>
      {/* Explainer */}
      <div style={{ margin: '12px 24px 0', padding: '10px 14px', background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 6, fontSize: 12, color: 'var(--ink-3)', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--ink-2)' }}>Subtree spend</strong> = this node's own spend + all spawned descendants'.&ensp;
        A parent's budget constrains the entire subtree — exceeding it blocks all children regardless of their individual limits.&ensp;
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)' }}>Darker bar = own · lighter = sub-agents</span>
      </div>

      {/* Column header */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 80px 80px 72px 180px 72px',
        padding: '8px 24px',
        borderTop: '1px solid var(--line)',
        borderBottom: '1px solid var(--line)',
        background: 'var(--paper-2)',
        marginTop: 12,
        gap: 10,
      }}>
        {[
          { label: 'Node',         align: 'left'  },
          { label: 'Own spend',    align: 'right' },
          { label: 'Subtree',      align: 'right' },
          { label: 'Limit',        align: 'right' },
          { label: 'Subtree burn', align: 'left'  },
          { label: '% parent',     align: 'right' },
        ].map((h) => (
          <div key={h.label} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--ink-4)', textAlign: h.align }}>
            {h.label}
          </div>
        ))}
      </div>

      {/* Tree */}
      <BudgetTreeNode node={tree} parentLimit={0} expanded={expanded} onToggle={onToggle} />
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */

function CostsPage({ toast }) {
  const [tab, setTab] = useCostSt('agents');
  const C = window.COSTS;
  if (!C) return <div className="empty">no cost data available</div>;

  const dailyPct   = parseFloat(C.daily_spend_usd)   / parseFloat(C.daily_limit_usd)   * 100;
  const monthlyPct = parseFloat(C.monthly_spend_usd) / parseFloat(C.monthly_limit_usd) * 100;

  const kpiColor = (p) => p >= 95 ? 'var(--danger)' : p >= 80 ? 'var(--warn)' : 'var(--ink)';

  return (
    <div>
      {/* Page header */}
      <div className="page-head">
        <div>
          <div className="page-title">Cost &amp; Budget</div>
          <div className="page-sub">
            LLM inference spend across all agents — daily / monthly breakdown with configured budget limits.
          </div>
        </div>
        <button className="btn btn-sm btn-primary" onClick={() => toast('Budget limit config — Sprint 3')}>
          Configure limits →
        </button>
      </div>

      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1, background: 'var(--line)', borderBottom: '1px solid var(--line)' }}>
        {[
          {
            label: 'Daily spend',
            val: `$${C.daily_spend_usd}`,
            sub: `of $${C.daily_limit_usd} daily limit`,
            pct: dailyPct,
            color: kpiColor(dailyPct),
          },
          {
            label: 'Monthly spend',
            val: `$${C.monthly_spend_usd}`,
            sub: `of $${C.monthly_limit_usd} monthly limit`,
            pct: monthlyPct,
            color: kpiColor(monthlyPct),
          },
          {
            label: 'Agents tracked',
            val: C.per_agent.length,
            sub: `across ${C.per_team.length} teams`,
            pct: null,
            color: 'var(--ink)',
          },
          {
            label: 'Avg / agent today',
            val: `$${(parseFloat(C.daily_spend_usd) / C.per_agent.length).toFixed(2)}`,
            sub: C.date,
            pct: null,
            color: 'var(--ink)',
          },
        ].map((k, i) => (
          <div key={i} style={{ background: 'var(--paper-2)', padding: '14px 20px' }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--ink-4)', marginBottom: 4 }}>
              {k.label}
            </div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 26, fontWeight: 700, color: k.color, marginBottom: 4 }}>
              {k.val}
            </div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)', marginBottom: 8 }}>
              {k.sub}
            </div>
            {k.pct !== null && (
              <>
                <BudgetBar used={parseFloat(k.val.replace('$', ''))} limit={parseFloat(k.pct >= 0 ? (parseFloat(k.val.replace('$','')) / k.pct * 100) : 1)} />
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: k.color, marginTop: 3 }}>
                  {k.pct.toFixed(1)}% used
                </div>
              </>
            )}
          </div>
        ))}
      </div>

      {/* Callouts */}
      {dailyPct >= 95 && (
        <div className="callout danger" style={{ margin: '12px 24px 0' }}>
          <div className="callout-title">Daily budget critical — {dailyPct.toFixed(1)}%</div>
          At current burn rate the daily limit will be exhausted before end of day. High-spend agents may be throttled.
        </div>
      )}
      {dailyPct >= 80 && dailyPct < 95 && (
        <div className="callout" style={{ margin: '12px 24px 0' }}>
          <div className="callout-title">Daily budget warning — {dailyPct.toFixed(1)}%</div>
          Daily spend is approaching the configured limit of ${C.daily_limit_usd}.
        </div>
      )}

      {/* 7-day chart */}
      <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--line)' }}>
        <div className="section-title" style={{ marginBottom: 10 }}>7-day spend history</div>
        <HistoryChart data={C.history_7d} />
      </div>

      {/* Tabs */}
      <div className="tabs">
        {[
          { id: 'agents',   label: 'Per-agent',    count: C.per_agent.length },
          { id: 'teams',    label: 'Per-team',     count: C.per_team.length  },
          { id: 'subtree',  label: 'Budget tree',  count: null               },
        ].map((t) => (
          <div key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
            <span className="tab-count">{t.count}</span>
          </div>
        ))}
      </div>

      {/* Per-agent table */}
      {tab === 'agents' && (
        <div style={{ overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Team</th>
                <th>Daily spend</th>
                <th>Monthly spend</th>
                <th style={{ minWidth: 80 }}>7-day trend</th>
              </tr>
            </thead>
            <tbody>
              {C.per_agent.map((a) => {
                const node  = (window.TOPO_NODES || []).find((n) => n.id === a.agent_id);
                const daily = parseFloat(a.daily_spend_usd);
                const top   = C.per_agent[0] ? parseFloat(C.per_agent[0].daily_spend_usd) : 1;
                const pct   = (daily / top) * 100;
                const col   = pct >= 80 ? 'var(--danger)' : pct >= 50 ? 'var(--warn)' : 'var(--ink-3)';
                return (
                  <tr key={a.agent_id}>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600 }}>
                        {a.agent_id}
                      </span>
                    </td>
                    <td>
                      <span className="chip" style={{ fontSize: 9 }}>{node?.team || '—'}</span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 14, fontWeight: 700, color: col, minWidth: 52 }}>
                          ${a.daily_spend_usd}
                        </span>
                        <div style={{ width: 80 }}>
                          <div style={{ height: 3, background: 'var(--paper-3)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${Math.min(100, pct)}%`, background: col, borderRadius: 2 }}></div>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--ink-2)' }}>
                        ${a.monthly_spend_usd}
                      </span>
                    </td>
                    <td>
                      <Sparkline data={a.trend} color={col} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Budget tree tab */}
      {tab === 'subtree' && <BudgetTreeTab />}

      {/* Per-team table */}
      {tab === 'teams' && (
        <div style={{ overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Team</th>
                <th>Agents</th>
                <th>Daily spend</th>
                <th style={{ minWidth: 180 }}>vs daily limit</th>
                <th>Monthly spend</th>
                <th>Monthly limit</th>
              </tr>
            </thead>
            <tbody>
              {C.per_team.map((t) => {
                const det    = (window.TEAM_DETAILS || {})[t.team_id] || {};
                const limit  = det.budget_daily  || 50;
                const mlimit = det.budget_monthly || 500;
                const used   = parseFloat(t.daily_spend_usd);
                const pct    = (used / limit) * 100;
                const col    = pct >= 95 ? 'var(--danger)' : pct >= 80 ? 'var(--warn)' : 'var(--ok)';
                return (
                  <tr key={t.team_id}>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600 }}>{t.team_id}</span>
                    </td>
                    <td>
                      <span className="chip" style={{ fontSize: 10 }}>{t.agent_count}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 14, fontWeight: 700, color: col }}>
                        ${t.daily_spend_usd}
                      </span>
                    </td>
                    <td style={{ minWidth: 180 }}>
                      <BudgetBar used={used} limit={limit} showLabel />
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)', marginTop: 2 }}>
                        limit: ${limit.toFixed(0)}/day
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>${t.monthly_spend_usd}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)' }}>${mlimit.toFixed(0)}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

Object.assign(window, { CostsPage });
