/* global React */
const { useState: useIdSt } = React;

/* ============================================================
   Identity & Access page  —  AAASM-119
   Mirrors POST /auth/token + policy RBAC (scope / role)
   ============================================================ */

const ROLE_META = {
  org_admin:  { label: 'Org Admin',   chipCls: 'chip-danger', color: 'var(--danger)' },
  team_admin: { label: 'Team Admin',  chipCls: 'chip-warn',   color: 'var(--warn)'   },
  operator:   { label: 'Operator',    chipCls: 'chip-info',   color: 'var(--info)'   },
  viewer:     { label: 'Viewer',      chipCls: '',            color: 'var(--ink-3)'  },
};

/* ── Members tab ──────────────────────────────────────────────────────────── */
function MembersTab({ toast }) {
  const members = window.MEMBERS || [];
  return (
    <div style={{ overflow: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Member</th>
            <th>Role</th>
            <th>Teams</th>
            <th>Last active</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {members.map((m) => {
            const rm = ROLE_META[m.role] || ROLE_META.viewer;
            return (
              <tr key={m.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: '50%',
                      background: 'var(--paper-3)', border: '1px solid var(--line-2)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontWeight: 700, fontSize: 12, flexShrink: 0, color: 'var(--ink-2)',
                    }}>
                      {m.name[0]}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{m.name}</div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>{m.email}</div>
                    </div>
                  </div>
                </td>
                <td><span className={`chip ${rm.chipCls}`}>{rm.label}</span></td>
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                    {m.teams.map((t) => (
                      <span key={t} className="chip" style={{ fontSize: 9 }}>{t}</span>
                    ))}
                  </div>
                </td>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-3)' }}>
                    {m.lastActive}
                  </span>
                </td>
                <td>
                  <span className={`chip ${m.status === 'active' ? 'chip-ok' : 'chip-warn'}`}>{m.status}</span>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button className="btn btn-sm btn-ghost" onClick={() => toast(`Edit ${m.name} (mock)`)}>Edit</button>
                    {m.status === 'active' && m.role !== 'org_admin' && (
                      <button className="btn btn-sm btn-ghost" style={{ color: 'var(--danger)' }} onClick={() => toast(`Remove ${m.name} (mock)`)}>Remove</button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ── API Tokens tab ───────────────────────────────────────────────────────── */
function TokensTab({ toast }) {
  const tokens = window.API_TOKENS || [];
  return (
    <div style={{ overflow: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Scopes</th>
            <th>Created by</th>
            <th>Expires</th>
            <th>Last used</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {tokens.map((tk) => {
            const expired = tk.status === 'expired';
            return (
              <tr key={tk.id} style={expired ? { opacity: 0.55 } : undefined}>
                <td>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600 }}>{tk.name}</div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--ink-4)' }}>{tk.id}</div>
                </td>
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                    {tk.scopes.map((s) => (
                      <span key={s} className="chip" style={{ fontSize: 9, fontFamily: 'JetBrains Mono, monospace' }}>{s}</span>
                    ))}
                  </div>
                </td>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{tk.createdBy}</span>
                </td>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: expired ? 'var(--danger)' : 'var(--ink-3)' }}>
                    {tk.expiresAt}
                  </span>
                </td>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-3)' }}>{tk.lastUsed}</span>
                </td>
                <td>
                  <span className={`chip ${expired ? 'chip-danger' : 'chip-ok'}`}>{tk.status}</span>
                </td>
                <td>
                  <button
                    className="btn btn-sm btn-ghost"
                    style={expired ? { color: 'var(--ink-4)' } : { color: 'var(--danger)' }}
                    onClick={() => toast(`${expired ? 'Delete' : 'Revoke'} ${tk.name} (mock)`)}
                  >
                    {expired ? 'Delete' : 'Revoke'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ── Roles tab ────────────────────────────────────────────────────────────── */
function RolesTab() {
  const roles   = window.ROLES   || [];
  const members = window.MEMBERS || [];

  return (
    <div style={{ padding: '16px 24px', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
      {roles.map((r) => {
        const rm    = ROLE_META[r.id] || ROLE_META.viewer;
        const count = members.filter((m) => m.role === r.id).length;
        const assignees = members.filter((m) => m.role === r.id);
        return (
          <div key={r.id} className="card">
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`chip ${rm.chipCls}`}>{rm.label}</span>
              </div>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-4)' }}>
                {count} member{count !== 1 ? 's' : ''}
              </span>
            </div>

            {/* Description */}
            <div style={{ fontSize: 12, color: 'var(--ink-3)', marginBottom: 12, lineHeight: 1.5 }}>{r.desc}</div>

            {/* Capabilities */}
            <div className="section-title" style={{ marginBottom: 6 }}>capabilities</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 12 }}>
              {r.capabilities.map((c) => (
                <span key={c} className="chip" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}>{c}</span>
              ))}
            </div>

            {/* Assigned members */}
            {assignees.length > 0 && (
              <>
                <div className="section-title" style={{ marginBottom: 6 }}>assigned</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {assignees.map((m) => (
                    <div key={m.id} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{
                        width: 22, height: 22, borderRadius: '50%',
                        background: 'var(--paper-3)', border: `1px solid ${rm.color}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: 10, fontWeight: 700, color: rm.color,
                      }}>{m.name[0]}</div>
                      <span style={{ fontSize: 11, color: 'var(--ink-2)' }}>{m.name.split(' ')[0]}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */
function IdentityPage({ toast }) {
  const [tab, setTab] = useIdSt('members');

  const members = window.MEMBERS    || [];
  const tokens  = window.API_TOKENS || [];
  const roles   = window.ROLES      || [];

  const expiredCount = tokens.filter((t) => t.status === 'expired').length;

  return (
    <div>
      {/* Page header */}
      <div className="page-head">
        <div>
          <div className="page-title">Members &amp; Access</div>
          <div className="page-sub">
            Human operators, RBAC role assignments, and API token management.
            Role scopes mirror policy <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>scope:</span> hierarchy (global / team / agent).
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-sm" onClick={() => toast('Invite member — Sprint 3')}>+ Invite</button>
          <button className="btn btn-sm btn-primary" onClick={() => toast('Token issuance — Sprint 3')}>+ Issue token</button>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        {[
          { id: 'members', label: 'Members',    count: members.length },
          { id: 'tokens',  label: 'API Tokens', count: tokens.length, warn: expiredCount > 0 },
          { id: 'roles',   label: 'Roles',      count: roles.length   },
        ].map((t) => (
          <div key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
            <span className={`tab-count ${t.warn && tab !== t.id ? 'chip-warn' : ''}`} style={t.warn && tab !== t.id ? { background: 'var(--warn-bg)', color: 'var(--warn)', border: '1px solid var(--warn)' } : undefined}>
              {t.count}
            </span>
            {t.warn && expiredCount > 0 && (
              <span className="chip chip-warn" style={{ fontSize: 9, marginLeft: 4 }}>{expiredCount} expired</span>
            )}
          </div>
        ))}
      </div>

      {tab === 'members' && <MembersTab toast={toast} />}
      {tab === 'tokens'  && <TokensTab  toast={toast} />}
      {tab === 'roles'   && <RolesTab />}
    </div>
  );
}

Object.assign(window, { IdentityPage });
