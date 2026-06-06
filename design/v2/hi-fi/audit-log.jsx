/* global React */
const { useState: useAuditSt } = React;

/* ============================================================
   Audit Log page  —  GET /api/v1/logs
   Immutable governance trail across all agents and sessions.
   ============================================================ */

const EVENT_META = {
  LLMCall:         { label: 'LLM Call',        chipCls: 'chip-info',   icon: '◈' },
  ToolCall:        { label: 'Tool Call',        chipCls: 'chip-info',   icon: '⚙' },
  FileOp:          { label: 'File Op',          chipCls: 'chip-warn',   icon: '▤' },
  NetworkCall:     { label: 'Network',          chipCls: '',            icon: '⇥' },
  PolicyViolation: { label: 'Policy Violation', chipCls: 'chip-danger', icon: '⚑' },
  ApprovalEvent:   { label: 'Approval',         chipCls: 'chip-ok',     icon: '✓' },
};

const DECISION_META = {
  ALLOW:   { chipCls: 'chip-ok',     label: 'allow'   },
  DENY:    { chipCls: 'chip-danger', label: 'deny'    },
  PENDING: { chipCls: 'chip-info',   label: 'pending' },
  REDACT:  { chipCls: 'chip-scrub',  label: 'redact'  },
  APPROVE: { chipCls: 'chip-ok',     label: 'approved'},
};

function payloadSummary(event_type, payload) {
  try {
    const p = typeof payload === 'string' ? JSON.parse(payload) : payload;
    switch (event_type) {
      case 'LLMCall':         return `${p.model} · ${p.prompt_tokens}+${p.completion_tokens} tok · ${p.latency_ms}ms${p.pii_detected ? ' · ⚠ PII detected' : ''}`;
      case 'ToolCall':        return `${p.tool_name} (${p.tool_source}) · ${p.succeeded ? '✓ ok' : '✕ error'} · ${p.latency_ms}ms`;
      case 'FileOp':          return `${p.operation.toUpperCase()} ${p.path}${p.bytes ? ` · ${(p.bytes / 1048576).toFixed(1)} MB` : ''}`;
      case 'NetworkCall':     return `${p.protocol}://${p.host} → ${p.status_code} · ${p.latency_ms}ms`;
      case 'PolicyViolation': return `${p.blocked_action} — ${p.reason}`;
      case 'ApprovalEvent':   return `${p.approval_id} ${p.approved ? 'approved' : 'rejected'} by ${p.approver_id} after ${(p.wait_time_ms / 1000).toFixed(0)}s`;
      default:                return JSON.stringify(p).slice(0, 100);
    }
  } catch { return '—'; }
}

function AuditLogPage({ goAgent, toast }) {
  const [agentFilter, setAgentFilter] = useAuditSt('all');
  const [typeFilter,  setTypeFilter]  = useAuditSt('all');
  const [q,           setQ]           = useAuditSt('');
  const [exp,         setExp]         = useAuditSt(null);

  const all    = window.AUDIT_LOG || [];
  const agents = ['all', ...new Set(all.map((e) => e.agent_id))];

  // counts per event type
  const counts = {};
  all.forEach((e) => { counts[e.event_type] = (counts[e.event_type] || 0) + 1; });

  const filtered = all.filter((e) => {
    if (agentFilter !== 'all' && e.agent_id !== agentFilter) return false;
    if (typeFilter  !== 'all' && e.event_type !== typeFilter) return false;
    if (q) {
      const summary = payloadSummary(e.event_type, e.payload);
      const hay = `${e.agent_id} ${e.event_type} ${summary} ${e.session_id}`.toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Page header */}
      <div className="page-head">
        <div>
          <div className="page-title">Audit Log</div>
          <div className="page-sub">
            Immutable governance trail — LLM calls, tool invocations, file ops, network requests, policy verdicts, and approval decisions across all agents.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-sm" onClick={() => toast('Export CSV (mock)')}>⏏ Export CSV</button>
          <button className="btn btn-sm btn-primary" onClick={() => toast('Compliance report — Sprint 3')}>Compliance report →</button>
        </div>
      </div>

      {/* Stats strip — clickable to filter by type */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Object.keys(EVENT_META).length + 1}, 1fr)`, gap: 1, background: 'var(--line)', borderBottom: '1px solid var(--line)', flexShrink: 0 }}>
        {[{ key: 'all', label: 'Total', count: all.length }, ...Object.entries(EVENT_META).map(([key, m]) => ({ key, label: m.label, count: counts[key] || 0 }))].map(({ key, label, count }) => {
          const active = typeFilter === key;
          return (
            <div
              key={key}
              onClick={() => setTypeFilter(active ? 'all' : key)}
              style={{ background: active ? 'var(--ink)' : 'var(--paper-2)', padding: '10px 14px', cursor: 'pointer', minWidth: 0 }}
            >
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 22, fontWeight: 700, color: active ? '#fff' : (key === 'PolicyViolation' ? 'var(--danger)' : 'var(--ink)') }}>
                {count}
              </div>
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.5px', color: active ? 'rgba(255,255,255,0.6)' : 'var(--ink-4)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Filter bar */}
      <div className="filterbar">
        <div className="search">
          <span style={{ color: 'var(--ink-4)', fontSize: 13 }}>⌕</span>
          <input placeholder="search agent, action, session…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <span className="fdivider" />
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>agent</span>
        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          style={{ height: 28, padding: '0 8px', background: 'var(--paper)', border: '1px solid var(--line-2)', borderRadius: 3, fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink)', cursor: 'pointer' }}
        >
          {agents.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <span className="fdivider" />
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 1 }}>type</span>
        {['all', ...Object.keys(EVENT_META)].map((v) => {
          const meta = EVENT_META[v];
          return (
            <button key={v} className={`btn btn-sm ${typeFilter === v ? 'btn-active' : ''}`} onClick={() => setTypeFilter(v)}>
              {meta ? meta.label : 'all'}
            </button>
          );
        })}
        <span style={{ marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-4)' }}>
          {filtered.length} / {all.length}
        </span>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 52 }}>seq</th>
              <th style={{ width: 96 }}>time</th>
              <th style={{ width: 150 }}>agent</th>
              <th style={{ width: 140 }}>event type</th>
              <th style={{ width: 80 }}>decision</th>
              <th>summary</th>
              <th style={{ width: 84 }}>session</th>
              <th style={{ width: 28 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: 48, color: 'var(--ink-4)', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                  no entries match
                </td>
              </tr>
            ) : filtered.map((e) => {
              const meta = EVENT_META[e.event_type] || { label: e.event_type, chipCls: '', icon: '·' };
              const dm   = DECISION_META[e.decision] || { chipCls: '', label: e.decision || '—' };
              const summary = payloadSummary(e.event_type, e.payload);
              const isExp   = exp === e.seq;

              return (
                <React.Fragment key={e.seq}>
                  <tr
                    style={{ cursor: 'pointer', background: isExp ? 'var(--paper-2)' : (e.event_type === 'PolicyViolation' ? 'rgba(184,41,30,0.03)' : undefined) }}
                    onClick={() => setExp(isExp ? null : e.seq)}
                  >
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>{e.seq}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-2)' }}>{e.timestamp.slice(11, 19)}</span>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-5)' }}>{e.timestamp.slice(0, 10)}</div>
                    </td>
                    <td>
                      <span
                        style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, fontWeight: 600, cursor: 'pointer', textDecoration: 'underline dotted', textUnderlineOffset: 2 }}
                        onClick={(ev) => { ev.stopPropagation(); goAgent && goAgent(e.agent_id); }}
                      >{e.agent_id}</span>
                    </td>
                    <td>
                      <span className={`chip ${meta.chipCls}`} style={{ fontSize: 9 }}>{meta.icon} {meta.label}</span>
                    </td>
                    <td>
                      <span className={`chip ${dm.chipCls}`} style={{ fontSize: 9 }}>{dm.label}</span>
                    </td>
                    <td>
                      <span style={{
                        fontSize: 11,
                        color: e.event_type === 'PolicyViolation' ? 'var(--danger)' : 'var(--ink-2)',
                        fontFamily: ['LLMCall','ToolCall','NetworkCall'].includes(e.event_type) ? 'JetBrains Mono, monospace' : 'inherit',
                        fontWeight: e.event_type === 'PolicyViolation' ? 500 : 400,
                      }}>{summary}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)' }}>{e.session_id}</span>
                    </td>
                    <td style={{ color: 'var(--ink-4)', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', textAlign: 'center' }}>
                      {isExp ? '▲' : '▼'}
                    </td>
                  </tr>

                  {/* Expanded payload detail */}
                  {isExp && (
                    <tr>
                      <td colSpan={8} style={{ padding: 0, background: 'var(--paper-3)', borderBottom: '2px solid var(--line-2)' }}>
                        <div style={{ padding: '14px 18px', display: 'grid', gridTemplateColumns: '240px 1fr', gap: 20 }}>
                          <div>
                            <div className="section-title" style={{ marginBottom: 8 }}>metadata</div>
                            <div className="kv" style={{ gridTemplateColumns: '80px 1fr' }}>
                              <span className="kv-k">seq</span>      <span className="kv-v mono" style={{ fontSize: 11 }}>{e.seq}</span>
                              <span className="kv-k">timestamp</span><span className="kv-v mono" style={{ fontSize: 11 }}>{e.timestamp}</span>
                              <span className="kv-k">session</span>  <span className="kv-v mono" style={{ fontSize: 11 }}>{e.session_id}</span>
                              <span className="kv-k">trace</span>    <span className="kv-v mono" style={{ fontSize: 11 }}>{e.trace_id || '—'}</span>
                              <span className="kv-k">decision</span>
                              <span className="kv-v">
                                <span className={`chip ${dm.chipCls}`} style={{ fontSize: 9 }}>{dm.label}</span>
                              </span>
                            </div>
                          </div>
                          <div>
                            <div className="section-title" style={{ marginBottom: 8 }}>payload</div>
                            <div className="trc-payload" style={{ maxHeight: 130, borderRadius: 3 }}>
                              {JSON.stringify(typeof e.payload === 'string' ? JSON.parse(e.payload) : e.payload, null, 2)}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

Object.assign(window, { AuditLogPage });
