/* global React */
// Shared empty / loading / error states for hi-fi pages.
// SRE / log-style tone — terse, monospace, no illustrations.
//
// Usage at top of each page component:
//   const ps = window.TWEAKS?.pageState;
//   if (ps === 'loading') return <LoadingState page="overview" />;
//   if (ps === 'empty')   return <EmptyState page="overview" onCta={() => ...} />;
//   if (ps === 'error')   return <ErrorState page="overview" onRetry={() => ...} />;

const STATE_STYLE = `
  .state-page {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--paper);
  }
  .state-block {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 80px 24px;
    color: var(--ink-3);
  }
  .state-icon {
    width: 64px; height: 64px;
    border: 1px solid var(--line-2);
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 22px;
    color: var(--ink-3);
    background: var(--paper-2);
    margin-bottom: 18px;
  }
  .state-icon.err { border-color: var(--danger); color: var(--danger); background: var(--danger-bg); }
  .state-icon.warn { border-color: var(--warn); color: var(--warn); background: var(--warn-bg); }

  .state-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: var(--ink-4);
    margin-bottom: 10px;
  }
  .state-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    font-weight: 600;
    color: var(--ink);
    margin-bottom: 8px;
  }
  .state-msg {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--ink-3);
    text-align: center;
    max-width: 420px;
    line-height: 1.6;
  }
  .state-msg code {
    background: var(--paper-3);
    padding: 1px 6px;
    border-radius: 2px;
    color: var(--ink-2);
    font-size: 11px;
  }
  .state-actions {
    display: flex;
    gap: 8px;
    margin-top: 22px;
  }

  /* skeleton primitives */
  .sk { background: var(--paper-3); border-radius: 2px; display: inline-block; }
  .sk-line { height: 12px; }
  .sk-block { height: 38px; }
  .sk-pulse {
    animation: sk-pulse 1.4s ease-in-out infinite;
  }
  @keyframes sk-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.55; }
  }

  /* page-head skeleton (used by all loading states) */
  .sk-page-head {
    padding: var(--tk-page-pad, 22px 24px 18px);
    border-bottom: 1px solid var(--line);
    background: var(--paper-2);
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }
  .sk-page-head .sk-line { width: 240px; }
  .sk-page-head .sk-line.sub { width: 320px; height: 9px; margin-top: 8px; }

  /* tabular skeleton */
  .sk-table {
    padding: 12px 24px;
  }
  .sk-row {
    display: grid;
    grid-template-columns: 220px 80px 100px 1fr 80px;
    gap: 16px;
    padding: 10px 0;
    border-bottom: 1px solid var(--line);
  }

  /* card-grid skeleton for overview */
  .sk-card-grid {
    padding: 20px 24px;
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }
  .sk-card {
    background: var(--paper-2);
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 16px;
    height: 140px;
  }

  /* live ops disconnected banner */
  .runtime-down {
    background: var(--danger-bg);
    border-bottom: 1px solid var(--danger);
    color: var(--danger);
    padding: 8px 24px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .runtime-down .pulse {
    width: 8px; height: 8px;
    background: var(--danger);
    border-radius: 50%;
    animation: pulse-red 1s ease-in-out infinite;
  }
  @keyframes pulse-red {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
`;

(function injectStateStyle() {
  if (document.getElementById('hi-fi-states-style')) return;
  const s = document.createElement('style');
  s.id = 'hi-fi-states-style';
  s.textContent = STATE_STYLE;
  document.head.appendChild(s);
})();

// ─────────────────────────────────────────────────────────────────
// Page-specific copy (SRE / log-style, terse)
// ─────────────────────────────────────────────────────────────────

const EMPTY_COPY = {
  overview: {
    icon: '⊘',
    tag: '0 agents',
    title: 'Waiting for SDK registration',
    msg: <>No agents have phoned home. Install the SDK in your agent code; it will self-register on first run.<br /><br /><code>$ pip install agent-assembly-sdk</code></>,
    cta: 'Start setup wizard',
    secondary: 'View install docs',
  },
  fleet: {
    icon: '∅',
    tag: 'fleet · 0 results',
    title: 'No agents match current filters',
    msg: <>All filters can be cleared from the bar above. Or check that agents are still phoning home — last fleet sync <code>4s ago</code>.</>,
    cta: 'Clear filters',
    secondary: null,
  },
  policy: {
    icon: '⌬',
    tag: 'policies · 0 active',
    title: 'No policies defined',
    msg: <>Without policies, all agent calls fall through to the runtime default (<code>sandbox · log-only</code>). Define your first allow-list rule to start enforcing.</>,
    cta: '+ New policy',
    secondary: 'Import from preset',
  },
  scrub: {
    icon: '✶',
    tag: 'patterns · awaiting input',
    title: 'No payload to scan',
    msg: <>Paste a request body or LLM prompt into the editor on the left. Patterns marked enabled will scan and replace matches in real time.</>,
    cta: null,
    secondary: null,
  },
  capability: {
    icon: '◫',
    tag: 'matrix · 0×0',
    title: 'No capability surface to map',
    msg: <>The capability matrix renders once at least one agent has registered AND at least one resource integration is connected. Connect a resource (Gmail, S3, GitHub, …) or onboard an agent to populate this view.</>,
    cta: 'Connect resource',
    secondary: 'Onboard agent',
  },
  live: {
    icon: '◌',
    tag: 'runtime · idle',
    title: 'No traffic in the last 60s',
    msg: <>The enforcement runtime is connected and healthy — there are simply no agent calls right now. Particle stream and approval queue will populate automatically as requests arrive. <code>last event 3m 14s ago</code></>,
    cta: 'Generate test traffic',
    secondary: 'View 24h history',
  },
  agent: {
    icon: '◇',
    tag: 'agent · awaiting first call',
    title: 'Agent registered, no activity yet',
    msg: <>Identity issued and trust score initialized at <code>50</code>. Trust will adjust on first authenticated call. If the agent never phones home, check that <code>AGENT_ASSEMBLY_TOKEN</code> is set in its runtime env.</>,
    cta: 'Copy enrollment command',
    secondary: 'View install docs',
  },
};

const ERROR_COPY = {
  live: {
    icon: '⚠',
    tag: 'runtime · disconnected',
    title: 'Lost connection to enforcement runtime',
    msg: <>Stream halted at <code>14:02:47 UTC</code>. Agents continue to operate under their <b>last known policy snapshot</b>; no new policy changes will propagate until the runtime reconnects.</>,
    cta: 'Reconnect',
    secondary: 'View runtime logs',
  },
  generic: {
    icon: '⚠',
    tag: 'request failed',
    title: 'Could not load this view',
    msg: <>Backend returned <code>503 service_unavailable</code>. This is usually transient — retry in a few seconds. If it persists, check <code>status.agent-assembly.io</code>.</>,
    cta: 'Retry',
    secondary: 'Open status page',
  },
};

// ─────────────────────────────────────────────────────────────────
// Components
// ─────────────────────────────────────────────────────────────────

function EmptyState({ page = 'overview', onCta, onSecondary }) {
  const c = EMPTY_COPY[page] || EMPTY_COPY.overview;
  return (
    <div className="state-page">
      <div className="state-block">
        <div className="state-icon">{c.icon}</div>
        <div className="state-tag">{c.tag}</div>
        <div className="state-title">{c.title}</div>
        <div className="state-msg">{c.msg}</div>
        {(c.cta || c.secondary) && (
          <div className="state-actions">
            {c.cta && <button className="btn btn-primary" onClick={onCta}>▸ {c.cta}</button>}
            {c.secondary && <button className="btn" onClick={onSecondary}>{c.secondary}</button>}
          </div>
        )}
      </div>
    </div>
  );
}

function ErrorState({ kind = 'generic', onRetry, onSecondary }) {
  const c = ERROR_COPY[kind] || ERROR_COPY.generic;
  return (
    <div className="state-page">
      {kind === 'live' && (
        <div className="runtime-down">
          <span className="pulse"></span>
          <b>RUNTIME DISCONNECTED</b>
          <span style={{ color: 'var(--ink-3)' }}>· last heartbeat 47s ago · auto-retry in 8s</span>
          <span style={{ marginLeft: 'auto' }}>severity: P1</span>
        </div>
      )}
      <div className="state-block">
        <div className="state-icon err">{c.icon}</div>
        <div className="state-tag">{c.tag}</div>
        <div className="state-title">{c.title}</div>
        <div className="state-msg">{c.msg}</div>
        <div className="state-actions">
          {c.cta && <button className="btn btn-primary" onClick={onRetry}>↻ {c.cta}</button>}
          {c.secondary && <button className="btn" onClick={onSecondary}>{c.secondary}</button>}
        </div>
      </div>
    </div>
  );
}

// Loading layouts mimic the structure of the real page so the swap-in
// feels stable. Each variant is a small skeleton scene.

function LoadingState({ page = 'overview' }) {
  return (
    <div className="state-page sk-pulse">
      <div className="sk-page-head">
        <div>
          <span className="sk sk-line" />
          <div><span className="sk sk-line sub" /></div>
        </div>
        <span className="sk sk-block" style={{ width: 120 }} />
      </div>
      {page === 'overview' && <SkOverview />}
      {page === 'fleet' && <SkFleet />}
      {page === 'capability' && <SkMatrix />}
      {page === 'policy' && <SkPolicy />}
      {page === 'live' && <SkLive />}
      {page === 'scrub' && <SkScrub />}
      {page === 'agent' && <SkAgent />}
    </div>
  );
}

function SkOverview() {
  return (
    <>
      <div style={{ padding: '20px 24px' }}>
        <div className="sk-card" style={{ height: 220, marginBottom: 12 }} />
      </div>
      <div className="sk-card-grid">
        <div className="sk-card" />
        <div className="sk-card" />
        <div className="sk-card" />
      </div>
    </>
  );
}
function SkFleet() {
  return (
    <>
      <div style={{ padding: '10px 24px', borderBottom: '1px solid var(--line)', background: 'var(--paper-2)', display: 'flex', gap: 8 }}>
        <span className="sk sk-block" style={{ width: 280, height: 28 }} />
        <span className="sk sk-block" style={{ width: 100, height: 28 }} />
        <span className="sk sk-block" style={{ width: 100, height: 28 }} />
      </div>
      <div className="sk-table">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="sk-row">
            <span className="sk sk-line" style={{ width: '80%' }} />
            <span className="sk sk-line" style={{ width: 60 }} />
            <span className="sk sk-line" style={{ width: 80 }} />
            <span className="sk sk-line" style={{ width: '60%' }} />
            <span className="sk sk-line" style={{ width: 50 }} />
          </div>
        ))}
      </div>
    </>
  );
}
function SkMatrix() {
  return (
    <div style={{ padding: '16px 24px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '160px repeat(8, 1fr)', gap: 1, background: 'var(--line)', border: '1px solid var(--line)' }}>
        {[...Array(9 * 7)].map((_, i) => (
          <div key={i} style={{ background: 'var(--paper-2)', height: 38 }}>
            <span className="sk sk-line" style={{ width: '60%', margin: '13px 8px' }} />
          </div>
        ))}
      </div>
    </div>
  );
}
function SkPolicy() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--line)', height: 'calc(100vh - 56px - 41px)' }}>
      <div style={{ background: 'var(--paper)', padding: 12 }}>
        {[...Array(6)].map((_, i) => (
          <div key={i} style={{ padding: '12px 8px', borderBottom: '1px solid var(--line)' }}>
            <span className="sk sk-line" style={{ width: 80, height: 8 }} />
            <div><span className="sk sk-line" style={{ width: '70%', marginTop: 4 }} /></div>
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--paper)', padding: 16 }}>
        <div className="sk-card" style={{ height: 180, marginBottom: 12 }} />
        <div className="sk-card" style={{ height: 140 }} />
      </div>
    </div>
  );
}
function SkLive() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.55fr 1fr 1fr', gap: 1, background: 'var(--line)', height: 'calc(100vh - 56px - 50px - 80px)' }}>
      <div style={{ background: 'var(--paper)' }} />
      <div style={{ background: '#0e0e0e' }} />
      <div style={{ background: 'var(--paper)', padding: 8 }}>
        {[...Array(4)].map((_, i) => (
          <div key={i} className="sk-card" style={{ height: 80, marginBottom: 6 }} />
        ))}
      </div>
    </div>
  );
}
function SkScrub() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 1, background: 'var(--line)', padding: 0, height: 'calc(100vh - 56px - 50px)' }}>
      <div style={{ background: 'var(--paper-2)', padding: 12 }}>
        {[...Array(8)].map((_, i) => (
          <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--line)' }}>
            <span className="sk sk-line" style={{ width: '70%' }} />
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--paper)', padding: 16 }}>
        <div className="sk-card" style={{ height: 180, marginBottom: 12 }} />
        <div className="sk-card" style={{ height: 200 }} />
      </div>
    </div>
  );
}
function SkAgent() {
  return (
    <div style={{ padding: 24 }}>
      <div className="sk-card" style={{ height: 120, marginBottom: 12 }} />
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
        <div className="sk-card" style={{ height: 280 }} />
        <div className="sk-card" style={{ height: 280 }} />
      </div>
    </div>
  );
}

Object.assign(window, { EmptyState, LoadingState, ErrorState });
