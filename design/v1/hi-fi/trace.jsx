/* global React */
const {
  useState:  useTST,
  useEffect: useTEF,
  useMemo:   useTMM,
} = React;

// ============================================================
// Trace / Decision Explainer  (items 1 + 2)
// shared by Live Ops stream click, approval card click,
// and cell inspect drawer.
// ============================================================

// ---- Synthetic trace data -----------------------------------

function guessPolicyId(verb, res) {
  const r = (res || '').toLowerCase();
  if ((r.includes('gmail') || r.includes('email')) && verb === 'write') return 'P-021';
  if (r.includes('pg') && (verb === 'write' || verb === 'delete'))       return 'P-014';
  if (r.includes('s3'))     return 'P-035';
  if (r.includes('shell'))  return 'P-042';
  if (r.includes('github')) return 'P-058';
  return null;
}

const RULE_DETAIL = {
  'P-021': 'Rule R2  ·  gmail write  if recipient not in @acme.com',
  'P-014': 'Rule R1  ·  pg write/delete  if table contains PII columns',
  'P-035': 'Rule R1  ·  s3 *  if path matches customer-pii/*',
  'P-042': 'Rule R1  ·  shell exec  always (2-person review required)',
  'P-058': 'Rule R1  ·  github write  if repo matches acme/infra/*',
};

function buildSteps(agent, verb, res, dec, policy) {
  const aObj  = (window.AGENTS   || []).find((a) => a.id === agent) || {};
  const pObj  = (window.POLICIES || []).find((p) => p.id === policy);
  const trust = aObj.trust    ?? 70;
  const mode  = aObj.mode     || 'enforce';
  const fw    = aObj.framework || '—';
  const owner = aObj.owner     || '—';

  const l2status =
    dec === 'deny'     ? 'fail'    :
    dec === 'approval' ? 'pending' :
    dec === 'narrow'   ? 'narrow'  : 'pass';

  const ruleDetail = policy && RULE_DETAIL[policy]
    ? `${RULE_DETAIL[policy]}  →  ${dec}`
    : policy
      ? `${policy} matched  →  ${dec}`
      : `no matching policy — default: ${dec}`;

  return [
    {
      id: 'l0', label: 'L0 · REQUEST',
      status: 'pass',
      detail: `tool call: ${verb}("${res}")`,
      meta:   `session: sess_${20000 + Math.floor(Math.random() * 79999)}  ·  DID: did:web:${agent}`,
      ms: 1,
    },
    {
      id: 'l1', label: 'L1 · IDENTITY',
      status: 'pass',
      detail: `DID verified · trust score ${trust} · mode ${mode}`,
      meta:   `framework: ${fw}  ·  owner: ${owner}`,
      ms: 3 + Math.floor(Math.random() * 8),
    },
    {
      id: 'l2', label: 'L2 · CAPABILITY',
      status: l2status,
      detail: ruleDetail,
      meta:   policy
        ? `policy: ${policy}${pObj ? `  ·  ${pObj.hits24h} hits/24h` : ''}`
        : '',
      ms: 6 + Math.floor(Math.random() * 12),
    },
    {
      id: 'l3', label: 'L3 · SCRUB',
      status:
        dec === 'scrub'                           ? 'scrub'     :
        dec === 'deny' || dec === 'approval'      ? 'unreached' : 'skip',
      detail:
        dec === 'scrub'                           ? 'redacted: emails (2), phone numbers (1)' :
        dec === 'deny' || dec === 'approval'      ? '— not reached (blocked at L2)' :
                                                    'no PII detected — pass through',
      meta: dec === 'scrub' ? 'presidio-v2' : '',
      ms:   dec === 'scrub' ? 3 + Math.floor(Math.random() * 6) : null,
    },
  ];
}

function buildPayload(verb, res, agent) {
  const r = (res || '').toLowerCase();
  if (r.includes('gmail') || r.includes('email')) return {
    type: 'email',
    lines: [
      `TO:      ████████████@██████████.com`,
      `FROM:    ${agent}@agent.acme.io`,
      `SUBJECT: Q3 report update`,
      ``,
      `Hi ████████,`,
      ``,
      `Please find the attached report.`,
      `Account ref: ████-████-████`,
    ],
    redactions: ['recipient email', 'contact name', 'account number'],
  };
  if (r.includes('pg') || r.includes('sql')) return {
    type: 'sql',
    lines: [
      `${verb.toUpperCase()} public.████████`,
      `   SET  email = '████████@██.com',`,
      `        phone = '████-████-████'`,
      ` WHERE  id    = ████████`,
      `RETURNING *;`,
    ],
    redactions: ['table name', 'email value', 'phone value', 'user ID'],
  };
  if (r.includes('s3')) return {
    type: 's3',
    lines: [
      `PUT s3://████████-pii/████████-q2.csv`,
      `Content-Type:   text/csv`,
      `Content-Length: 4,398,182`,
      ``,
      `[preview · first 2 rows]`,
      `id, name, email, ssn`,
      `████, ████████, ████@██.com, ███-██-████`,
    ],
    redactions: ['bucket', 'filename', 'name col', 'email col', 'SSN col'],
  };
  if (r.includes('shell')) return {
    type: 'shell',
    lines: [
      `$ ${res.replace(/^shell[.:]/i, '')}`,
      `PATH=/usr/bin:/usr/local/bin`,
      `USER=agent-svc  CWD=/home/agent`,
    ],
    redactions: [],
  };
  if (r.includes('github')) return {
    type: 'git',
    lines: [
      `POST /repos/acme/████████/git/commits`,
      `message: "chore: update prod config"`,
      ``,
      `diff --git a/terraform/████████.tf`,
      `-  source = "████████████"`,
      `+  source = "████████████"`,
    ],
    redactions: ['repo name', 'resource IDs'],
  };
  return {
    type: 'http',
    lines: [
      `POST /api/v1/${res}`,
      `Authorization: Bearer ████████████████`,
      `Content-Type: application/json`,
      ``,
      `{"data": "████████████", "size": 2048}`,
    ],
    redactions: ['auth token', 'payload body'],
  };
}

function makeTraceFromEvent(event) {
  const policy = guessPolicyId(event.verb, event.res);
  const steps  = buildSteps(event.agent, event.verb, event.res, event.dec, policy);
  return {
    id:       `tr-${(Math.random() * 0xfffff | 0).toString(16).padStart(5, '0')}`,
    ts:       event.ts,
    agent:    event.agent,
    verb:     event.verb,
    resource: event.res,
    decision: event.dec,
    policy,
    steps,
    totalMs: steps.reduce((s, st) => s + (st.ms || 0), 0),
    payload: buildPayload(event.verb, event.res, event.agent),
  };
}

function makeTraceFromApproval(ap) {
  const policy = ap.policy;
  const steps  = buildSteps(ap.agent, ap.verb, ap.resource, 'approval', policy);
  return {
    id:       ap.trace || `tr-${(Math.random() * 0xfffff | 0).toString(16).padStart(5, '0')}`,
    ts:       new Date().toLocaleTimeString(),
    agent:    ap.agent,
    verb:     ap.verb,
    resource: ap.resource,
    decision: 'approval',
    policy,
    steps,
    totalMs: steps.reduce((s, st) => s + (st.ms || 0), 0),
    payload: buildPayload(ap.verb, ap.resource, ap.agent),
  };
}

// ---- Shared visual primitives --------------------------------

const STATUS_META = {
  pass:      { icon: '✓', color: 'var(--ok)',      bg: 'var(--ok-bg)' },
  fail:      { icon: '✕', color: 'var(--danger)',  bg: 'var(--danger-bg)' },
  pending:   { icon: '⏸', color: 'var(--info)',    bg: 'var(--info-bg)' },
  narrow:    { icon: '↘', color: 'var(--warn)',    bg: 'var(--warn-bg)' },
  scrub:     { icon: '◈', color: 'var(--scrub)',   bg: 'var(--scrub-bg)' },
  skip:      { icon: '·', color: 'var(--ink-4)',   bg: 'var(--paper-3)' },
  unreached: { icon: '—', color: 'var(--ink-5)',   bg: 'var(--paper-3)' },
};

const DEC_CHIP  = { allow: 'ok', narrow: 'warn', scrub: 'scrub', approval: 'info', deny: 'danger' };
const DEC_LABEL = { allow: '✓ ALLOWED', narrow: '↘ NARROWED', scrub: '◈ SCRUBBED', approval: '⏸ PENDING', deny: '✕ DENIED' };
const DEC_COLOR = { allow: 'var(--ok)', narrow: 'var(--warn)', scrub: 'var(--scrub)', approval: 'var(--info)', deny: 'var(--danger)' };

function TraceStep({ step, isLast }) {
  const sm = STATUS_META[step.status] || STATUS_META.skip;
  return (
    <div className="trc-step">
      <div className="trc-step-left">
        <div className="trc-icon" style={{ background: sm.bg, color: sm.color }}>{sm.icon}</div>
        {!isLast && <div className="trc-line" />}
      </div>
      <div className="trc-step-body">
        <div className="trc-step-head">
          <span className="trc-step-label">{step.label}</span>
          {step.ms != null && <span className="trc-ms">{step.ms}ms</span>}
          <span className="trc-status" style={{ color: sm.color }}>{step.status}</span>
        </div>
        <div className="trc-detail">{step.detail}</div>
        {step.meta && <div className="trc-meta">{step.meta}</div>}
      </div>
    </div>
  );
}

function PayloadBlock({ payload }) {
  const renderLine = (line, i) => {
    const parts = line.split(/(█+)/);
    return (
      <div key={i} className="trc-payload-line">
        {parts.map((p, j) =>
          /█/.test(p)
            ? <span key={j} className="trc-redact">{p}</span>
            : p
        )}
      </div>
    );
  };
  return (
    <div>
      <div className="section-title" style={{ marginBottom: 6 }}>
        payload preview <span style={{ color: 'var(--ink-5)', fontSize: 9 }}>· {payload.type}</span>
      </div>
      <div className="trc-payload">{payload.lines.map(renderLine)}</div>
      {payload.redactions.length > 0 && (
        <div className="trc-redact-list">
          <span className="chip chip-scrub" style={{ fontSize: 9 }}>redacted</span>
          {payload.redactions.map((r, i) => (
            <span key={i} className="trc-redact-tag">{r}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---- TraceDrawer -------------------------------------------

function TraceDrawer({ event, onClose, goPolicy }) {
  const trace = useTMM(() => makeTraceFromEvent(event), [event.id]);

  return (
    <div className="scrim" style={{ background: 'rgba(0,0,0,0.22)' }} onClick={onClose}>
      <div className="drawer" style={{ width: 500 }} onClick={(e) => e.stopPropagation()}>

        <div className="drawer-head">
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className={`chip chip-${DEC_CHIP[trace.decision] || ''}`}>{trace.decision}</span>
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 600 }}>
                {event.verb} · {event.res}
              </span>
            </div>
            <div style={{ marginTop: 5, fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-3)' }}>
              {trace.agent} · {trace.ts} · {trace.totalMs}ms total
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose}>✕</button>
        </div>

        <div className="drawer-body" style={{ padding: '14px 20px', overflow: 'auto', flex: 1 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>
            decision trace · <span style={{ color: 'var(--ink-3)' }}>{trace.id}</span>
          </div>
          <div className="trc-steps">
            {trace.steps.map((step, i) => (
              <TraceStep key={step.id} step={step} isLast={i === trace.steps.length - 1} />
            ))}
          </div>

          <div className="trc-outcome" style={{ borderColor: DEC_COLOR[trace.decision] || 'var(--line)' }}>
            <span style={{ color: DEC_COLOR[trace.decision], fontWeight: 700 }}>
              {DEC_LABEL[trace.decision] || trace.decision.toUpperCase()}
            </span>
            <span style={{ fontSize: 11, color: 'var(--ink-3)', marginLeft: 12 }}>
              {trace.totalMs}ms total
            </span>
            {trace.policy && (
              <span
                style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--info)', cursor: 'pointer', textDecoration: 'underline' }}
                onClick={() => goPolicy && goPolicy(trace.policy)}
              >
                policy {trace.policy} →
              </span>
            )}
          </div>

          <PayloadBlock payload={trace.payload} />
        </div>

        <div className="drawer-foot">
          <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)' }}>{trace.id}</span>
          <button className="btn" onClick={onClose}>close</button>
        </div>
      </div>
    </div>
  );
}

// ---- ApprovalDetailDrawer ----------------------------------

function ageToSec(age) {
  if (!age) return 0;
  const n = parseInt(age);
  if (age.endsWith('s')) return n;
  if (age.endsWith('m')) return n * 60;
  if (age.endsWith('h')) return n * 3600;
  return 0;
}

function ApprovalDetailDrawer({ approval, onClose, onApprove, onReject, toast, goPolicy }) {
  const trace = useTMM(() => makeTraceFromApproval(approval), [approval.id]);

  const [withCond,   setWithCond]   = useTST(false);
  const [condType,   setCondType]   = useTST('this-once');
  const [condExpiry, setCondExpiry] = useTST('24h');
  const [note,       setNote]       = useTST('');
  const [elapsed,    setElapsed]    = useTST(0);

  useTEF(() => {
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const SLA_SECONDS  = 30 * 60;
  const totalElapsed = elapsed + ageToSec(approval.age);
  const remaining    = Math.max(0, SLA_SECONDS - totalElapsed);
  const slaFrac      = Math.min(1, totalElapsed / SLA_SECONDS);
  const slaColor     = slaFrac > 0.8 ? 'var(--danger)' : slaFrac > 0.6 ? 'var(--warn)' : 'var(--ok)';

  const handleApprove = () => { onApprove && onApprove(approval); toast && toast(`✓ Approved ${approval.id}`); onClose(); };
  const handleReject  = () => { onReject  && onReject(approval);  toast && toast(`Rejected ${approval.id}`);  onClose(); };

  return (
    <div className="scrim" style={{ background: 'rgba(0,0,0,0.28)' }} onClick={onClose}>
      <div className="drawer" style={{ width: 560 }} onClick={(e) => e.stopPropagation()}>

        {/* head */}
        <div className="drawer-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 13, fontWeight: 700 }}>{approval.id}</span>
              {approval.urgent && <span className="chip chip-danger" style={{ fontSize: 9 }}>⚠ urgent</span>}
              <span className="chip chip-info" style={{ fontSize: 10 }}>L2 · pending</span>
              <span className="chip" style={{ fontFamily: 'JetBrains Mono', fontSize: 9, marginLeft: 'auto' }}>{approval.policy}</span>
            </div>
            <div style={{ marginTop: 4, fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 600, color: 'var(--ink-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {approval.agent} · <b>{approval.verb}</b> · {approval.resource.length > 42 ? approval.resource.slice(0, 42) + '…' : approval.resource}
            </div>
          </div>
          <button className="btn btn-ghost" style={{ flexShrink: 0 }} onClick={onClose}>✕</button>
        </div>

        {/* body */}
        <div className="drawer-body" style={{ padding: '14px 20px', overflow: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* SLA bar */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
              <span className="section-title" style={{ margin: 0 }}>SLA · 30m</span>
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: slaColor }}>
                {remaining > 0
                  ? `${Math.floor(remaining / 60)}m ${remaining % 60}s remaining`
                  : '⚠ SLA breached'}
              </span>
            </div>
            <div className="sla-bar">
              <div className="sla-fill" style={{ width: `${slaFrac * 100}%`, background: slaColor }} />
            </div>
          </div>

          {/* Trace */}
          <div>
            <div className="section-title" style={{ marginBottom: 8 }}>
              decision trace · <span style={{ color: 'var(--ink-3)' }}>{trace.id}</span>
            </div>
            <div className="trc-steps">
              {trace.steps.map((step, i) => (
                <TraceStep key={step.id} step={step} isLast={i === trace.steps.length - 1} />
              ))}
            </div>
            <div className="trc-outcome" style={{ borderColor: 'var(--info)' }}>
              <span style={{ color: 'var(--info)', fontWeight: 700 }}>⏸ AWAITING APPROVAL</span>
              <span style={{ fontSize: 11, color: 'var(--ink-3)', marginLeft: 12 }}>{approval.reason}</span>
              {trace.policy && (
                <span
                  style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--info)', cursor: 'pointer', textDecoration: 'underline' }}
                  onClick={() => { goPolicy && goPolicy(trace.policy); onClose(); }}
                >
                  policy {trace.policy} →
                </span>
              )}
            </div>
          </div>

          {/* Approvers */}
          <div>
            <div className="section-title" style={{ marginBottom: 6 }}>approvers · 0 of 1 responded</div>
            <div className="approver-row">
              <div className="approver-avatar approver-pending">K</div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>
                  kelly @security
                  <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 11, marginLeft: 6 }}>(you)</span>
                </div>
                <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)' }}>
                  security-oncall · waiting · 1-of-1 required
                </div>
              </div>
              <span className="chip chip-info" style={{ marginLeft: 'auto', fontSize: 10 }}>0 / 1</span>
            </div>
          </div>

          {/* Detail KV */}
          <div>
            <div className="section-title" style={{ marginBottom: 6 }}>request detail</div>
            <div className="kv" style={{ marginBottom: 0 }}>
              <div className="kv-k">requested by</div>
              <div className="kv-v">{approval.requestedBy}</div>
              <div className="kv-k">layer</div>
              <div className="kv-v mono">{approval.layer}</div>
              <div className="kv-k">waiting</div>
              <div className="kv-v mono">{approval.age}</div>
              <div className="kv-k">detail</div>
              <div className="kv-v" style={{ fontFamily: 'JetBrains Mono', fontSize: 11 }}>{approval.detail}</div>
            </div>
          </div>

          {/* Payload */}
          <PayloadBlock payload={trace.payload} />

          {/* Approve with conditions (inline expand) */}
          {withCond && (
            <div className="cond-form">
              <div className="section-title" style={{ marginBottom: 8 }}>approve with conditions</div>
              <div style={{ display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
                {[['this-once', 'this instance only'], ['exception', 'add policy exception'], ['temp', 'temp allow']].map(([v, l]) => (
                  <span key={v} className={`pill ${condType === v ? 'pill-on pill-warn' : ''}`} style={{ cursor: 'pointer' }} onClick={() => setCondType(v)}>{l}</span>
                ))}
              </div>
              {condType === 'temp' && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>expires in</span>
                  {['1h', '4h', '24h', '7d'].map((v) => (
                    <span key={v} className={`pill ${condExpiry === v ? 'pill-on pill-warn' : ''}`} style={{ cursor: 'pointer' }} onClick={() => setCondExpiry(v)}>{v}</span>
                  ))}
                </div>
              )}
              <textarea
                className="cond-note"
                placeholder="note (optional) — reason for conditional approval…"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={2}
              />
            </div>
          )}
        </div>

        {/* foot — primary action area */}
        <div className="drawer-foot" style={{ flexDirection: 'column', gap: 8, alignItems: 'stretch' }}>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="aq-btn-approve" style={{ flex: 1, height: 34, fontSize: 13 }} onClick={handleApprove}>
              ✓ {withCond ? 'approve with conditions' : 'approve'}
            </button>
            <button className="aq-btn-reject" style={{ flex: 1, height: 34, fontSize: 13 }} onClick={handleReject}>
              ✕ reject
            </button>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn" style={{ flex: 1 }} onClick={() => setWithCond((w) => !w)}>
              {withCond ? '↑ cancel conditions' : '⊕ approve with conditions'}
            </button>
            <button className="btn" onClick={() => toast && toast('Forwarded to data-platform-lead (mock)')}>↪ forward</button>
            <button className="btn" onClick={onClose}>close</button>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { TraceDrawer, ApprovalDetailDrawer, makeTraceFromEvent, makeTraceFromApproval });
