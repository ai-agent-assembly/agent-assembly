/* global React */
// First-run onboarding wizard.
// Center modal · narrow & focused · dashboard dimmed underneath.
// 5 steps · per-step skip · top-right "Skip onboarding" · finish → Overview + toast.

const { useState: useSOB, useEffect: useEOB, useRef: useROB } = React;

// ─────────────────────────────────────────────────────────────────
// Step metadata
// ─────────────────────────────────────────────────────────────────

const STEPS = [
  { id: 'framework', num: '01', label: 'pick framework' },
  { id: 'install',   num: '02', label: 'install sdk'    },
  { id: 'identity',  num: '03', label: 'issue identity' },
  { id: 'policy',    num: '04', label: 'baseline policy' },
  { id: 'enroll',    num: '05', label: 'enroll agent'   },
];

const FRAMEWORKS = [
  { id: 'langchain', name: 'LangChain',  glyph: '⌬', sub: 'python · async agents · tool calling',  pop: 'most common' },
  { id: 'autogen',   name: 'AutoGen',    glyph: '⊞', sub: 'multi-agent conversations · ms-research', pop: '' },
  { id: 'crewai',    name: 'CrewAI',     glyph: '◇', sub: 'role-based crews · sequential tasks',     pop: '' },
  { id: 'custom',    name: 'Custom / SDK', glyph: '✦', sub: 'plain HTTP · any runtime · BYO agent',  pop: '' },
];

const POLICY_PRESETS = [
  {
    id: 'default-deny',
    name: 'Default deny',
    sub: 'maximum safety · explicit allow-list',
    desc: 'Every capability is blocked unless an explicit Allow rule is added. Recommended for production. New agents start with zero capabilities.',
    blocks: ['all writes', 'all external network', 'all PII reads', 'sandbox: log-only'],
    allows: [],
    risk: 'low',
  },
  {
    id: 'read-only',
    name: 'Read-only baseline',
    sub: 'recommended · sensible defaults',
    desc: 'Allows reads on common SaaS resources (Gmail, Drive, GitHub issues). Writes, scripts, deletes, and PII fields require an explicit policy.',
    blocks: ['all writes', 'PII fields (email/phone/ssn)', 'shell.exec'],
    allows: ['gmail.read', 'drive.read', 'github.issues.read', 'http.GET (allow-listed domains)'],
    risk: 'medium',
  },
  {
    id: 'monitor-only',
    name: 'Monitor only',
    sub: 'observe first · enforce later',
    desc: 'No blocking. All requests pass through but are logged and scored. Use for the first 7 days while you map your agent\'s actual surface area before turning enforcement on.',
    blocks: [],
    allows: ['everything (logged + scored)'],
    risk: 'high',
  },
];

// ─────────────────────────────────────────────────────────────────
// Style block
// ─────────────────────────────────────────────────────────────────

const ONB_STYLE = `
  .onb-scrim {
    position: fixed; inset: 0;
    background: rgba(8, 9, 11, 0.78);
    backdrop-filter: blur(2px);
    z-index: 9000;
    display: flex; align-items: center; justify-content: center;
    padding: 32px;
    animation: onb-scrim-in 240ms ease;
  }
  @keyframes onb-scrim-in { from { opacity: 0; } to { opacity: 1; } }

  .onb-modal {
    width: 760px; max-width: 100%; max-height: calc(100vh - 64px);
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 4px;
    box-shadow: 0 32px 80px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04);
    display: flex; flex-direction: column;
    animation: onb-modal-in 280ms cubic-bezier(.2,.8,.2,1);
    overflow: hidden;
    font-family: 'Inter', sans-serif;
  }
  @keyframes onb-modal-in { from { opacity: 0; transform: translateY(8px) scale(0.98); } to { opacity: 1; transform: none; } }

  .onb-head {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 22px;
    border-bottom: 1px solid var(--line-2);
    background: var(--paper-2);
  }
  .onb-head-left { display: flex; align-items: center; gap: 10px; }
  .onb-head-mark {
    width: 24px; height: 24px;
    background: var(--ink); color: var(--paper);
    display: inline-flex; align-items: center; justify-content: center;
    font-family: 'JetBrains Mono'; font-size: 13px;
    border-radius: 2px;
  }
  .onb-head-title {
    font-family: 'JetBrains Mono'; font-size: 11px;
    text-transform: uppercase; letter-spacing: 1.4px; color: var(--ink);
  }
  .onb-head-sub {
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-4); letter-spacing: 0.5px;
    margin-left: 10px; padding-left: 10px;
    border-left: 1px solid var(--line-2);
  }
  .onb-skip-all {
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-4); background: transparent;
    border: 1px solid var(--line-2); padding: 5px 10px;
    border-radius: 2px; cursor: pointer;
    text-transform: uppercase; letter-spacing: 0.6px;
    transition: all 120ms;
  }
  .onb-skip-all:hover { color: var(--ink-2); border-color: var(--ink-4); }

  .onb-rail {
    display: flex;
    padding: 10px 22px;
    gap: 0;
    background: var(--paper);
    border-bottom: 1px solid var(--line-2);
    overflow-x: auto;
  }
  .onb-rail-step {
    flex: 1; min-width: 100px;
    display: flex; align-items: center; gap: 8px;
    padding: 8px 6px;
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-4);
    text-transform: lowercase; letter-spacing: 0.6px;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: all 120ms;
    position: relative;
  }
  .onb-rail-step:not(:last-child)::after {
    content: '';
    position: absolute;
    right: -1px; top: 50%;
    width: 6px; height: 1px;
    background: var(--line-2);
    transform: translateY(-50%);
  }
  .onb-rail-step.done {
    color: var(--ok);
  }
  .onb-rail-step.current {
    color: var(--ink);
    border-bottom-color: var(--ink);
  }
  .onb-rail-step.future {
    opacity: 0.5; cursor: not-allowed;
  }
  .onb-rail-num {
    width: 18px; height: 18px;
    display: inline-flex; align-items: center; justify-content: center;
    border: 1px solid currentColor;
    border-radius: 999px;
    font-size: 9px;
  }
  .onb-rail-step.done .onb-rail-num {
    background: var(--ok); color: white; border-color: var(--ok);
  }
  .onb-rail-step.current .onb-rail-num {
    background: var(--ink); color: var(--paper); border-color: var(--ink);
  }

  .onb-body {
    padding: 28px 32px 24px;
    flex: 1; min-height: 320px;
    overflow-y: auto;
  }
  .onb-body-title {
    font-size: 18px; font-weight: 600; color: var(--ink);
    margin: 0 0 4px;
    letter-spacing: -0.2px;
  }
  .onb-body-sub {
    font-size: 13px; color: var(--ink-3);
    margin: 0 0 22px;
    line-height: 1.5;
  }
  .onb-body-sub code {
    font-family: 'JetBrains Mono'; font-size: 11px;
    background: var(--paper-2); padding: 1px 5px; border-radius: 2px;
    border: 1px solid var(--line-2);
  }

  .onb-foot {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 22px;
    border-top: 1px solid var(--line-2);
    background: var(--paper-2);
  }
  .onb-foot-meta {
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-4); letter-spacing: 0.5px;
  }
  .onb-foot-actions { display: flex; gap: 8px; align-items: center; }
  .onb-btn {
    font-family: 'JetBrains Mono'; font-size: 11px;
    padding: 7px 14px; border-radius: 2px;
    cursor: pointer;
    text-transform: lowercase; letter-spacing: 0.4px;
    border: 1px solid var(--line);
    background: var(--paper); color: var(--ink-2);
    transition: all 120ms;
  }
  .onb-btn:hover { color: var(--ink); border-color: var(--ink-4); }
  .onb-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .onb-btn-skip {
    color: var(--ink-4); border-color: transparent;
    text-decoration: underline; text-decoration-color: var(--line-2);
    text-underline-offset: 3px;
  }
  .onb-btn-skip:hover { color: var(--ink-3); }
  .onb-btn-primary {
    background: var(--ink); color: var(--paper);
    border-color: var(--ink);
  }
  .onb-btn-primary:hover { background: var(--ink-2); border-color: var(--ink-2); color: var(--paper); }
  .onb-btn-primary:disabled { background: var(--ink-4); border-color: var(--ink-4); }

  /* ── Step 1: framework cards ────────────────────────── */
  .onb-fw-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  .onb-fw-card {
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 14px 16px;
    cursor: pointer;
    transition: all 120ms;
    position: relative;
    background: var(--paper);
    display: flex; gap: 12px; align-items: flex-start;
  }
  .onb-fw-card:hover { border-color: var(--ink-4); background: var(--paper-2); }
  .onb-fw-card.selected {
    border-color: var(--ink);
    background: var(--paper-2);
    box-shadow: 0 0 0 1px var(--ink) inset;
  }
  .onb-fw-glyph {
    font-size: 22px; line-height: 1; color: var(--ink);
    margin-top: 1px;
  }
  .onb-fw-info { flex: 1; min-width: 0; }
  .onb-fw-name {
    font-size: 13px; font-weight: 600; color: var(--ink);
  }
  .onb-fw-sub {
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-4); margin-top: 3px;
    letter-spacing: 0.3px;
  }
  .onb-fw-pop {
    position: absolute; top: 8px; right: 10px;
    font-family: 'JetBrains Mono'; font-size: 9px;
    background: var(--ok); color: white;
    padding: 1px 6px; border-radius: 2px;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .onb-fw-radio {
    width: 14px; height: 14px;
    border: 1px solid var(--ink-4);
    border-radius: 999px;
    position: relative;
    flex-shrink: 0; margin-top: 3px;
  }
  .onb-fw-card.selected .onb-fw-radio {
    border-color: var(--ink);
  }
  .onb-fw-card.selected .onb-fw-radio::after {
    content: ''; position: absolute;
    inset: 3px;
    background: var(--ink);
    border-radius: 999px;
  }

  /* ── Step 2: terminal ────────────────────────── */
  .onb-term {
    background: #0d0e10; color: #d4d4d4;
    border-radius: 3px;
    padding: 14px 16px;
    font-family: 'JetBrains Mono'; font-size: 12px;
    line-height: 1.55;
    min-height: 200px;
    border: 1px solid #1a1b1d;
    overflow: hidden;
  }
  .onb-term-line { white-space: pre-wrap; word-break: break-word; }
  .onb-term-prompt { color: #4a9eff; user-select: none; }
  .onb-term-cmd { color: #f0f0f0; }
  .onb-term-out { color: #a0a0a0; }
  .onb-term-ok  { color: #5fd17a; }
  .onb-term-warn { color: #f3c14b; }
  .onb-term-err { color: #ff6b6b; }
  .onb-term-faint { color: #6e6e6e; }
  .onb-term-cursor {
    display: inline-block; width: 7px; height: 13px;
    background: #d4d4d4; vertical-align: text-bottom;
    animation: onb-cursor 1s steps(1) infinite;
  }
  @keyframes onb-cursor { 50% { opacity: 0; } }

  .onb-pkg-row {
    display: flex; gap: 10px; align-items: center;
    margin-top: 14px;
    padding: 10px 12px;
    background: var(--paper-2);
    border: 1px solid var(--line-2);
    border-radius: 3px;
  }
  .onb-pkg-tabs {
    display: flex; gap: 1px;
    background: var(--line);
    padding: 1px; border-radius: 2px;
  }
  .onb-pkg-tab {
    padding: 4px 10px;
    font-family: 'JetBrains Mono'; font-size: 10px;
    background: var(--paper); color: var(--ink-3);
    cursor: pointer;
    border-radius: 1px;
    transition: all 100ms;
  }
  .onb-pkg-tab.active { background: var(--ink); color: var(--paper); }
  .onb-pkg-cmd {
    flex: 1;
    font-family: 'JetBrains Mono'; font-size: 11px;
    color: var(--ink-2);
    background: var(--paper);
    border: 1px solid var(--line-2);
    border-radius: 2px;
    padding: 6px 10px;
    user-select: all;
  }
  .onb-pkg-copy {
    font-family: 'JetBrains Mono'; font-size: 10px;
    padding: 6px 10px;
    background: var(--ink); color: var(--paper);
    border: none; border-radius: 2px;
    cursor: pointer;
    text-transform: lowercase; letter-spacing: 0.4px;
  }
  .onb-pkg-copy.copied { background: var(--ok); }

  /* ── Step 3: identity ──────────────────────── */
  .onb-id-card {
    background: var(--paper-2);
    border: 1px solid var(--line-2);
    border-radius: 3px;
    padding: 22px 22px;
    text-align: center;
    min-height: 220px;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .onb-id-glyph-wrap {
    width: 80px; height: 80px;
    border: 2px solid var(--line);
    border-radius: 999px;
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 16px;
    position: relative;
    background: var(--paper);
  }
  .onb-id-glyph-wrap.idle::before {
    content: '◯';
    font-size: 32px; color: var(--ink-4);
    font-family: 'JetBrains Mono';
  }
  .onb-id-glyph-wrap.spinning {
    border-color: var(--accent, var(--ink));
    animation: onb-id-spin 1.4s linear infinite;
  }
  .onb-id-glyph-wrap.spinning::before {
    content: '';
    position: absolute; inset: -2px;
    border: 2px solid transparent;
    border-top-color: var(--accent, var(--ink));
    border-radius: 999px;
    animation: onb-id-spin 0.8s linear infinite;
  }
  .onb-id-glyph-wrap.done::before {
    content: '✓'; font-size: 36px; color: var(--ok); font-weight: bold;
    animation: onb-pop 280ms cubic-bezier(.2,1.8,.2,1);
  }
  @keyframes onb-id-spin { to { transform: rotate(360deg); } }
  @keyframes onb-pop { from { transform: scale(0.4); opacity: 0; } to { transform: scale(1); opacity: 1; } }

  .onb-id-action-btn {
    font-family: 'JetBrains Mono'; font-size: 11px;
    padding: 9px 18px;
    background: var(--ink); color: var(--paper);
    border: none; border-radius: 2px;
    cursor: pointer;
    text-transform: lowercase; letter-spacing: 0.5px;
  }
  .onb-id-action-btn:hover { background: var(--ink-2); }
  .onb-id-action-btn:disabled { background: var(--ink-4); cursor: not-allowed; }

  .onb-id-out {
    margin-top: 20px;
    padding: 14px 16px;
    background: #0d0e10;
    color: #d4d4d4;
    font-family: 'JetBrains Mono'; font-size: 11px;
    line-height: 1.7;
    border-radius: 3px;
    text-align: left;
    animation: onb-fade-up 360ms ease;
  }
  @keyframes onb-fade-up {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: none; }
  }
  .onb-id-row { display: flex; gap: 10px; }
  .onb-id-key { color: #6e94c2; min-width: 90px; }
  .onb-id-val { color: #d4d4d4; word-break: break-all; }
  .onb-id-val.fp { color: #5fd17a; }

  .onb-id-hint {
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-4);
    margin-top: 12px; letter-spacing: 0.4px;
  }

  /* ── Step 4: policy preset ────────────────── */
  .onb-pp-grid {
    display: grid; grid-template-columns: 1fr 1fr 1fr;
    gap: 10px;
  }
  .onb-pp-card {
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 14px 14px;
    cursor: pointer;
    background: var(--paper);
    transition: all 120ms;
    display: flex; flex-direction: column;
    min-height: 140px;
  }
  .onb-pp-card:hover { background: var(--paper-2); border-color: var(--ink-4); }
  .onb-pp-card.selected {
    border-color: var(--ink);
    background: var(--paper-2);
    box-shadow: 0 0 0 1px var(--ink) inset;
  }
  .onb-pp-name {
    font-size: 13px; font-weight: 600; color: var(--ink);
  }
  .onb-pp-sub {
    font-family: 'JetBrains Mono'; font-size: 9.5px;
    color: var(--ink-4); margin-top: 3px;
    letter-spacing: 0.4px; text-transform: lowercase;
  }
  .onb-pp-risk {
    font-family: 'JetBrains Mono'; font-size: 9px;
    margin-top: 8px;
    padding: 1px 6px; border-radius: 2px;
    align-self: flex-start;
    text-transform: uppercase; letter-spacing: 0.6px;
  }
  .onb-pp-risk.low    { background: rgba(70, 180, 110, 0.15); color: var(--ok); }
  .onb-pp-risk.medium { background: rgba(220, 180, 60, 0.15); color: var(--warn); }
  .onb-pp-risk.high   { background: rgba(220, 90, 90, 0.15); color: var(--danger); }

  .onb-pp-preview {
    margin-top: 14px;
    padding: 14px 16px;
    background: var(--paper-2);
    border: 1px solid var(--line-2);
    border-left: 3px solid var(--ink);
    border-radius: 2px;
  }
  .onb-pp-preview-h {
    font-family: 'JetBrains Mono'; font-size: 10px;
    color: var(--ink-3); margin-bottom: 8px;
    letter-spacing: 0.6px; text-transform: uppercase;
  }
  .onb-pp-preview-desc {
    font-size: 12px; color: var(--ink-2); line-height: 1.55;
    margin-bottom: 12px;
  }
  .onb-pp-cols {
    display: grid; grid-template-columns: 1fr 1fr; gap: 14px;
  }
  .onb-pp-col-h {
    font-family: 'JetBrains Mono'; font-size: 9px;
    color: var(--ink-4); margin-bottom: 6px;
    text-transform: uppercase; letter-spacing: 0.6px;
  }
  .onb-pp-rule {
    font-family: 'JetBrains Mono'; font-size: 11px;
    padding: 3px 0;
    color: var(--ink-2);
    display: flex; align-items: center; gap: 6px;
  }
  .onb-pp-rule.block::before {
    content: '⊘'; color: var(--danger); font-weight: bold;
  }
  .onb-pp-rule.allow::before {
    content: '✓'; color: var(--ok); font-weight: bold;
  }
  .onb-pp-rule.empty {
    color: var(--ink-4); font-style: italic;
  }

  /* ── Step 5: enroll ──────────────────────── */
  .onb-enroll-meter {
    background: var(--paper-2);
    border: 1px solid var(--line-2);
    border-radius: 3px;
    padding: 18px 20px;
    margin-bottom: 16px;
  }
  .onb-enroll-row {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 12px;
  }
  .onb-enroll-label {
    font-family: 'JetBrains Mono'; font-size: 11px;
    color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.6px;
  }
  .onb-enroll-count {
    font-family: 'JetBrains Mono'; font-size: 28px;
    color: var(--ink); font-weight: 500;
    letter-spacing: -1px;
    transition: color 200ms;
  }
  .onb-enroll-count.live {
    color: var(--ok);
  }
  .onb-enroll-bar {
    height: 4px; background: var(--line); border-radius: 2px; overflow: hidden;
  }
  .onb-enroll-bar-fill {
    height: 100%; background: var(--ok);
    transition: width 800ms cubic-bezier(.2,.8,.2,1);
  }

  .onb-enroll-pings {
    background: #0d0e10; color: #d4d4d4;
    font-family: 'JetBrains Mono'; font-size: 11px;
    padding: 12px 14px;
    border-radius: 3px;
    height: 130px; overflow: hidden;
    position: relative;
  }
  .onb-enroll-pings-empty {
    color: #6e6e6e; padding: 4px 0;
  }
  .onb-enroll-ping {
    padding: 2px 0;
    animation: onb-ping-in 320ms ease;
  }
  @keyframes onb-ping-in {
    from { opacity: 0; transform: translateX(-6px); }
    to { opacity: 1; transform: none; }
  }
  .onb-ping-time { color: #6e94c2; }
  .onb-ping-action { color: #d4d4d4; }
  .onb-ping-tag { color: #5fd17a; }
  .onb-ping-tag.warn { color: #f3c14b; }

  .onb-id-action-btn.live {
    background: var(--paper); color: var(--ink-3);
    border: 1px solid var(--line);
    pointer-events: none;
  }
  .onb-id-action-btn.live::before {
    content: ''; display: inline-block;
    width: 7px; height: 7px; border-radius: 999px;
    background: var(--ok);
    margin-right: 7px;
    animation: onb-pulse 1.4s ease-in-out infinite;
  }
  @keyframes onb-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }
`;

// ─────────────────────────────────────────────────────────────────
// Step components — each receives { state, setState } and renders
// step body + decides whether Next is enabled.
// ─────────────────────────────────────────────────────────────────

function Step1Framework({ state, setState }) {
  return (
    <>
      <h2 className="onb-body-title">Pick the framework you're enrolling.</h2>
      <p className="onb-body-sub">
        We support most agent runtimes. Your choice determines which SDK package and identity
        format we install in the next step.
      </p>
      <div className="onb-fw-grid">
        {FRAMEWORKS.map((fw) => (
          <div
            key={fw.id}
            className={`onb-fw-card ${state.framework === fw.id ? 'selected' : ''}`}
            onClick={() => setState({ framework: fw.id })}
          >
            <span className="onb-fw-radio"></span>
            <span className="onb-fw-glyph">{fw.glyph}</span>
            <div className="onb-fw-info">
              <div className="onb-fw-name">{fw.name}</div>
              <div className="onb-fw-sub">{fw.sub}</div>
            </div>
            {fw.pop && <span className="onb-fw-pop">{fw.pop}</span>}
          </div>
        ))}
      </div>
    </>
  );
}

function Step2Install({ state, setState }) {
  const [pkg, setPkg] = useSOB('pip');
  const [copied, setCopied] = useSOB(false);
  const [phase, setPhase] = useSOB(state.installVerified ? 'verified' : 'idle'); // idle | running | verified
  const [lines, setLines] = useSOB(state.installVerified ? completedLines() : []);

  function completedLines() {
    return [
      { kind: 'prompt', text: '$ ' }, { kind: 'cmd', text: 'aa-cli verify' },
      { kind: 'out', text: 'connecting to runtime…  done.' },
      { kind: 'out', text: 'sdk version    1.4.2 (latest)' },
      { kind: 'out', text: 'control-plane  https://api.agent-assembly.io' },
      { kind: 'ok',  text: '✓ verified · ready to enroll' },
    ];
  }

  const cmd = pkg === 'pip' ? 'pip install agent-assembly' :
              pkg === 'npm' ? 'npm install @agent-assembly/sdk' :
              'go get github.com/agent-assembly/sdk-go';

  const copy = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };

  const runVerify = () => {
    if (phase === 'running') return;
    setPhase('running');
    const seq = [
      { kind: 'prompt', text: '$ ' }, { kind: 'cmd', text: 'aa-cli verify' },
      { kind: 'out', text: 'connecting to runtime…' },
    ];
    setLines(seq);
    setTimeout(() => setLines((l) => [...l.slice(0, -1), { kind: 'out', text: 'connecting to runtime…  done.' }]), 600);
    setTimeout(() => setLines((l) => [...l, { kind: 'out', text: 'sdk version    1.4.2 (latest)' }]), 900);
    setTimeout(() => setLines((l) => [...l, { kind: 'out', text: 'control-plane  https://api.agent-assembly.io' }]), 1150);
    setTimeout(() => {
      setLines((l) => [...l, { kind: 'ok', text: '✓ verified · ready to enroll' }]);
      setPhase('verified');
      setState({ installVerified: true });
    }, 1500);
  };

  return (
    <>
      <h2 className="onb-body-title">Install the SDK.</h2>
      <p className="onb-body-sub">
        Drop this in your agent project. It auto-loads on first import — no boilerplate.
      </p>

      <div className="onb-pkg-row">
        <div className="onb-pkg-tabs">
          {['pip', 'npm', 'go'].map((p) => (
            <div key={p} className={`onb-pkg-tab ${pkg === p ? 'active' : ''}`} onClick={() => setPkg(p)}>{p}</div>
          ))}
        </div>
        <code className="onb-pkg-cmd">$ {cmd}</code>
        <button className={`onb-pkg-copy ${copied ? 'copied' : ''}`} onClick={copy}>
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>

      <div style={{ marginTop: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.6 }}>verify connection</span>
          <button className="onb-btn" onClick={runVerify} disabled={phase === 'running'}>
            {phase === 'idle' ? '▸ run aa-cli verify' : phase === 'running' ? 'verifying…' : '↻ re-run'}
          </button>
        </div>
        <div className="onb-term">
          {lines.length === 0 && (
            <div className="onb-term-line onb-term-faint"># run verify above to check the SDK reaches the control-plane</div>
          )}
          {lines.map((l, i) => (
            <div key={i} className="onb-term-line">
              {l.kind === 'prompt' && <span className="onb-term-prompt">{l.text}</span>}
              {l.kind === 'cmd' && <span className="onb-term-cmd">{l.text}</span>}
              {l.kind === 'out' && <span className="onb-term-out">{l.text}</span>}
              {l.kind === 'ok' && <span className="onb-term-ok">{l.text}</span>}
              {l.kind === 'warn' && <span className="onb-term-warn">{l.text}</span>}
              {l.kind === 'err' && <span className="onb-term-err">{l.text}</span>}
            </div>
          ))}
          {phase === 'running' && <span className="onb-term-cursor"></span>}
        </div>
      </div>
    </>
  );
}

function Step3Identity({ state, setState }) {
  const [phase, setPhase] = useSOB(state.identity ? 'done' : 'idle'); // idle | spinning | done

  const generate = () => {
    if (phase !== 'idle') return;
    setPhase('spinning');
    setTimeout(() => {
      const did = `did:aa:${randHex(16)}`;
      const fp = `${randHex(2)}:${randHex(2)}:${randHex(2)}:${randHex(2)}:${randHex(2)}:${randHex(2)}:${randHex(2)}:${randHex(2)}`.toUpperCase();
      const issued = new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z';
      setState({ identity: { did, fp, issued, alg: 'Ed25519' } });
      setPhase('done');
    }, 1400);
  };

  function randHex(n) {
    let s = '';
    const chars = '0123456789abcdef';
    for (let i = 0; i < n * 2; i++) s += chars[Math.floor(Math.random() * 16)];
    return s;
  }

  const id = state.identity;

  return (
    <>
      <h2 className="onb-body-title">Issue first agent identity.</h2>
      <p className="onb-body-sub">
        Every agent gets a unique cryptographic identity (DID). The keypair is generated locally —
        the private key never leaves your control plane.
      </p>

      <div className="onb-id-card">
        <div className={`onb-id-glyph-wrap ${phase}`}></div>
        {phase === 'idle' && (
          <>
            <button className="onb-id-action-btn" onClick={generate}>▸ generate keypair</button>
            <div className="onb-id-hint">Ed25519 · 256-bit · ~1.4s</div>
          </>
        )}
        {phase === 'spinning' && (
          <>
            <button className="onb-id-action-btn" disabled>generating…</button>
            <div className="onb-id-hint">deriving curve point · signing CSR · publishing to registry</div>
          </>
        )}
        {phase === 'done' && id && (
          <>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ok)', letterSpacing: 0.5 }}>✓ identity issued</div>
            <div className="onb-id-out">
              <div className="onb-id-row"><span className="onb-id-key">DID</span><span className="onb-id-val">{id.did}</span></div>
              <div className="onb-id-row"><span className="onb-id-key">algorithm</span><span className="onb-id-val">{id.alg}</span></div>
              <div className="onb-id-row"><span className="onb-id-key">fingerprint</span><span className="onb-id-val fp">{id.fp}</span></div>
              <div className="onb-id-row"><span className="onb-id-key">issued</span><span className="onb-id-val">{id.issued}</span></div>
            </div>
            <div className="onb-id-hint">private key stored in your <code style={{background:'var(--paper)',padding:'1px 4px',border:'1px solid var(--line-2)',borderRadius:2}}>~/.aa/keys/</code> · do not commit</div>
          </>
        )}
      </div>
    </>
  );
}

function Step4PolicyPreset({ state, setState }) {
  const selected = state.policyPreset || 'read-only';
  const preset = POLICY_PRESETS.find((p) => p.id === selected);

  React.useEffect(() => {
    if (!state.policyPreset) setState({ policyPreset: 'read-only' });
  }, []);

  return (
    <>
      <h2 className="onb-body-title">Pick a baseline policy.</h2>
      <p className="onb-body-sub">
        Every agent starts under this policy. You can refine per-agent rules in the Policy editor
        afterwards.
      </p>

      <div className="onb-pp-grid">
        {POLICY_PRESETS.map((p) => (
          <div
            key={p.id}
            className={`onb-pp-card ${selected === p.id ? 'selected' : ''}`}
            onClick={() => setState({ policyPreset: p.id })}
          >
            <div className="onb-pp-name">{p.name}</div>
            <div className="onb-pp-sub">{p.sub}</div>
            <div className={`onb-pp-risk ${p.risk}`}>risk · {p.risk}</div>
          </div>
        ))}
      </div>

      {preset && (
        <div className="onb-pp-preview" key={preset.id}>
          <div className="onb-pp-preview-h">{preset.name} · what this looks like</div>
          <div className="onb-pp-preview-desc">{preset.desc}</div>
          <div className="onb-pp-cols">
            <div>
              <div className="onb-pp-col-h">blocks</div>
              {preset.blocks.length === 0 ? <div className="onb-pp-rule empty">— no blocking rules —</div> :
                preset.blocks.map((b, i) => <div key={i} className="onb-pp-rule block">{b}</div>)}
            </div>
            <div>
              <div className="onb-pp-col-h">allows</div>
              {preset.allows.length === 0 ? <div className="onb-pp-rule empty">— no allow rules —</div> :
                preset.allows.map((a, i) => <div key={i} className="onb-pp-rule allow">{a}</div>)}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function Step5Enroll({ state, setState }) {
  const [phase, setPhase] = useSOB(state.enrolled ? 'live' : 'idle'); // idle | listening | live
  const [pings, setPings] = useSOB(state.enrolled ? completedPings() : []);
  const [count, setCount] = useSOB(state.enrolled ? 1 : 0);
  const idRef = useROB(0);

  function completedPings() {
    return [
      { id: 1, time: '14:02:11', action: 'phone-home (heartbeat)', tag: 'identity-verified', warn: false },
      { id: 2, time: '14:02:13', action: 'capability.list', tag: 'cached', warn: false },
      { id: 3, time: '14:02:14', action: 'gmail.read', tag: 'allowed-by-baseline', warn: false },
    ];
  }

  const startListen = () => {
    if (phase !== 'idle') return;
    setPhase('listening');
    // After ~2s, "agent connects"
    setTimeout(() => {
      setCount(1);
      setPhase('live');
      setState({ enrolled: true });
      // start streaming pings
      const seq = [
        { time: '14:02:11', action: 'phone-home (heartbeat)', tag: 'identity-verified' },
        { time: '14:02:13', action: 'capability.list', tag: 'cached' },
        { time: '14:02:14', action: 'gmail.read', tag: 'allowed-by-baseline' },
      ];
      seq.forEach((p, i) => {
        setTimeout(() => {
          idRef.current += 1;
          setPings((cur) => [{ id: idRef.current, ...p }, ...cur]);
        }, i * 600);
      });
    }, 2000);
  };

  return (
    <>
      <h2 className="onb-body-title">Enroll your first agent.</h2>
      <p className="onb-body-sub">
        Run your agent now (or any test script that imports the SDK). The control plane will detect
        the first authenticated call and complete enrollment.
      </p>

      <div className="onb-enroll-meter">
        <div className="onb-enroll-row">
          <span className="onb-enroll-label">enrolled agents</span>
          <span className={`onb-enroll-count ${count > 0 ? 'live' : ''}`}>
            {count} <span style={{ fontSize: 14, color: 'var(--ink-4)' }}>/ ∞</span>
          </span>
        </div>
        <div className="onb-enroll-bar">
          <div className="onb-enroll-bar-fill" style={{ width: count > 0 ? '8%' : '0%' }}></div>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.6 }}>incoming agent calls</span>
        {phase === 'idle' && <button className="onb-btn" onClick={startListen}>▸ start listener</button>}
        {phase === 'listening' && <button className="onb-id-action-btn live">listening…</button>}
        {phase === 'live' && <button className="onb-id-action-btn live">connected</button>}
      </div>

      <div className="onb-enroll-pings">
        {pings.length === 0 && phase === 'idle' && (
          <div className="onb-enroll-pings-empty">// no calls yet — run your agent to phone home</div>
        )}
        {pings.length === 0 && phase === 'listening' && (
          <div className="onb-enroll-pings-empty">// awaiting first authenticated call…</div>
        )}
        {pings.map((p) => (
          <div key={p.id} className="onb-enroll-ping">
            <span className="onb-ping-time">{p.time}</span>{' '}
            <span className="onb-ping-action">{p.action}</span>{' '}
            <span className={`onb-ping-tag ${p.warn ? 'warn' : ''}`}>· {p.tag}</span>
          </div>
        ))}
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────
// Main Wizard
// ─────────────────────────────────────────────────────────────────

function OnboardingWizard({ open, initialStep = 0, onFinish, onSkipAll }) {
  const [stepIdx, setStepIdx] = useSOB(initialStep);
  const [state, setStateRaw] = useSOB({
    framework: null,
    installVerified: false,
    identity: null,
    policyPreset: null,
    enrolled: false,
  });
  const setState = (patch) => setStateRaw((s) => ({ ...s, ...patch }));

  // jump to initialStep when changed externally (Tweaks panel)
  useEOB(() => { setStepIdx(initialStep); }, [initialStep]);

  if (!open) return null;

  const cur = STEPS[stepIdx];

  const canAdvance = (() => {
    if (cur.id === 'framework') return !!state.framework;
    if (cur.id === 'install')   return !!state.installVerified;
    if (cur.id === 'identity')  return !!state.identity;
    if (cur.id === 'policy')    return !!state.policyPreset;
    if (cur.id === 'enroll')    return !!state.enrolled;
    return true;
  })();

  const next = () => {
    if (stepIdx < STEPS.length - 1) setStepIdx(stepIdx + 1);
    else onFinish && onFinish(state);
  };
  const back = () => stepIdx > 0 && setStepIdx(stepIdx - 1);
  const skipStep = () => {
    if (stepIdx < STEPS.length - 1) setStepIdx(stepIdx + 1);
    else onFinish && onFinish(state);
  };

  return (
    <>
      <style>{ONB_STYLE}</style>
      <div className="onb-scrim">
        <div className="onb-modal" onClick={(e) => e.stopPropagation()}>
          <div className="onb-head">
            <div className="onb-head-left">
              <span className="onb-head-mark">▣</span>
              <span className="onb-head-title">Agent Assembly · setup</span>
              <span className="onb-head-sub">step {stepIdx + 1} of {STEPS.length}</span>
            </div>
            <button className="onb-skip-all" onClick={onSkipAll}>skip onboarding ✕</button>
          </div>

          <div className="onb-rail">
            {STEPS.map((s, i) => {
              const cls = i < stepIdx ? 'done' : i === stepIdx ? 'current' : 'future';
              return (
                <div
                  key={s.id}
                  className={`onb-rail-step ${cls}`}
                  onClick={() => i <= stepIdx && setStepIdx(i)}
                >
                  <span className="onb-rail-num">{i < stepIdx ? '✓' : s.num}</span>
                  <span>{s.label}</span>
                </div>
              );
            })}
          </div>

          <div className="onb-body">
            {cur.id === 'framework' && <Step1Framework  state={state} setState={setState} />}
            {cur.id === 'install'   && <Step2Install    state={state} setState={setState} />}
            {cur.id === 'identity'  && <Step3Identity   state={state} setState={setState} />}
            {cur.id === 'policy'    && <Step4PolicyPreset state={state} setState={setState} />}
            {cur.id === 'enroll'    && <Step5Enroll     state={state} setState={setState} />}
          </div>

          <div className="onb-foot">
            <span className="onb-foot-meta">
              {canAdvance ? '✓ ready to continue' : `complete this step to advance · or skip`}
            </span>
            <div className="onb-foot-actions">
              {stepIdx > 0 && <button className="onb-btn" onClick={back}>← back</button>}
              <button className="onb-btn onb-btn-skip" onClick={skipStep}>skip step →</button>
              <button
                className="onb-btn onb-btn-primary"
                onClick={next}
                disabled={!canAdvance}
              >
                {stepIdx === STEPS.length - 1 ? 'finish setup ✓' : 'continue →'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

Object.assign(window, { OnboardingWizard });
