/* global React */
const { useState: useStateShell } = React;

const ROUTES = [
  { id: 'overview',   num: '01', label: 'Overview',          group: 'monitor', enabled: true },
  { id: 'fleet',      num: '02', label: 'Fleet',             group: 'monitor', enabled: true },
  { id: 'topology',   num: '03', label: 'Topology',          group: 'monitor', enabled: true,  star: true },
  { id: 'live',       num: '04', label: 'Live Ops',          group: 'monitor', enabled: true },
  { id: 'alerts',     num: '05', label: 'Alerts',            group: 'monitor', enabled: true, badgeFn: () => ((window.ALERTS || []).filter((a) => a.severity === 'critical').length || null) },
  { id: 'audit',      num: '06', label: 'Audit Log',         group: 'monitor', enabled: true },
  { id: 'capability', num: '07', label: 'Capability',        group: 'control', enabled: true,  star: true },
  { id: 'policy',     num: '08', label: 'Policy',            group: 'control', enabled: true,  star: true, badge: '1' },
  { id: 'scrub',      num: '09', label: 'Secret Scrubbing',  group: 'control', enabled: true },
  { id: 'costs',      num: '10', label: 'Cost & Budget',     group: 'manage',  enabled: true },
  { id: 'teams',      num: '11', label: 'Agent Groups',      group: 'manage',  enabled: true },
  { id: 'identity',   num: '12', label: 'Members & Access',  group: 'manage',  enabled: true },
];

function LeftRail({ route, setRoute }) {
  return (
    <nav className="rail">
      <div className="rail-brand">
        <div className="rail-brand-title">▣ {window.TWEAKS?.brandName || 'Agent Assembly'}</div>
        <div className="rail-brand-sub">{window.TWEAKS?.brandSub || 'acme · prod · v3.4.1'}</div>
      </div>

      <div className="rail-section">monitor</div>
      {ROUTES.filter((r) => r.group === 'monitor').map((r) => (
        <RailItem key={r.id} r={r} active={route === r.id} onClick={() => r.enabled && setRoute(r.id)} />
      ))}

      <div className="rail-section">control</div>
      {ROUTES.filter((r) => r.group === 'control').map((r) => (
        <RailItem key={r.id} r={r} active={route === r.id} onClick={() => r.enabled && setRoute(r.id)} />
      ))}

      <div className="rail-section">manage</div>
      {ROUTES.filter((r) => r.group === 'manage').map((r) => (
        <RailItem key={r.id} r={r} active={route === r.id} onClick={() => r.enabled && setRoute(r.id)} />
      ))}

      <div className="rail-foot">
        <span><span className="rail-status-dot"></span>runtime ok</span>
        <span>142 agents</span>
      </div>
    </nav>
  );
}

function RailItem({ r, active, onClick }) {
  return (
    <div
      className={`rail-item ${active ? 'active' : ''}`}
      onClick={onClick}
      style={!r.enabled ? { opacity: 0.45, cursor: 'not-allowed' } : null}
      title={!r.enabled ? 'Not in this hi-fi prototype' : ''}
    >
      <span style={{ display: 'flex', alignItems: 'center' }}>
        <span className="rail-num">{r.num}</span>
        {r.label}
        {r.star && <span style={{ marginLeft: 6, color: '#facc15' }}>★</span>}
      </span>
      {(r.badge || (r.badgeFn && r.badgeFn())) && (
    <span className="rail-badge">{r.badge || r.badgeFn()}</span>
  )}
    </div>
  );
}

function TopBar({ route, crumbExtra, rightExtra, pendingCount, onBell }) {
  const r = ROUTES.find((x) => x.id === route);
  return (
    <div className="topbar">
      <div className="crumbs">
        <span>acme</span>
        <span className="sep">›</span>
        <span>prod</span>
        <span className="sep">›</span>
        <span className="here">{r?.label}</span>
        {crumbExtra && <>
          <span className="sep">›</span>
          <span className="here">{crumbExtra}</span>
        </>}
      </div>
      <div className="topbar-right">
        {rightExtra}
        <span>last sync 4s ago</span>
        <span>·</span>
        <button
          onClick={onBell}
          title="Approval queue"
          style={{
            position: 'relative',
            background: 'transparent',
            border: '1px solid var(--line)',
            borderRadius: 3,
            padding: '4px 10px',
            cursor: 'pointer',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 11,
            color: 'var(--ink-2)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 5,
          }}
        >
          <span style={{ fontSize: 13 }}>⚑</span>
          <span>approvals</span>
          {pendingCount > 0 && (
            <span style={{
              background: 'var(--danger)',
              color: '#fff',
              fontSize: 10,
              fontWeight: 700,
              padding: '1px 6px',
              borderRadius: 999,
              marginLeft: 2,
            }}>{pendingCount}</span>
          )}
        </button>
        <span>kelly @security</span>
      </div>
    </div>
  );
}

function Toast({ msg, onDone }) {
  React.useEffect(() => {
    const t = setTimeout(onDone, 2400);
    return () => clearTimeout(t);
  }, [msg]);
  return <div className="toast">{msg}</div>;
}

Object.assign(window, { LeftRail, TopBar, Toast, ROUTES });
