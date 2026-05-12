/* global React */
const { useState: useSSC, useMemo: useMSC } = React;

// ============================================================
// Secret Scrubbing page — L3 sanitization detail
// patterns library + sample input/output diff + per-agent stats
// ============================================================

const PATTERNS = [
  { id: 'AWS_KEY',       name: 'AWS access key ID',     regex: 'AKIA[0-9A-Z]{16}',                example: 'AKIAIOSFODNN7EXAMPLE',                       replace: '[REDACTED:AWS_KEY]',       severity: 'critical', hits24h: 14, enabled: true },
  { id: 'AWS_SECRET',    name: 'AWS secret key',        regex: '[A-Za-z0-9/+=]{40}',              example: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  replace: '[REDACTED:AWS_SECRET]',    severity: 'critical', hits24h: 9,  enabled: true },
  { id: 'OPENAI_KEY',    name: 'OpenAI API key',        regex: 'sk-[A-Za-z0-9]{48,}',             example: 'sk-proj-abc123def456ghi789jkl0mnopqrs...', replace: '[REDACTED:OPENAI_KEY]',    severity: 'critical', hits24h: 22, enabled: true },
  { id: 'GH_TOKEN',      name: 'GitHub token',          regex: 'gh[ps]_[A-Za-z0-9]{36}',          example: 'ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z',  replace: '[REDACTED:GH_TOKEN]',      severity: 'critical', hits24h: 6,  enabled: true },
  { id: 'JWT',           name: 'JWT bearer',            regex: 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+', example: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIi…',          replace: '[REDACTED:JWT]',           severity: 'high',     hits24h: 31, enabled: true },
  { id: 'SLACK_TOKEN',   name: 'Slack webhook',         regex: 'xox[baprs]-[A-Za-z0-9-]+',        example: 'xoxb-12345-67890-aBcDeFgHiJk',             replace: '[REDACTED:SLACK]',         severity: 'high',     hits24h: 4,  enabled: true },
  { id: 'EMAIL_PII',     name: 'Email address (PII)',   regex: '[a-z0-9._%+-]+@[a-z0-9.-]+',      example: 'jane.doe@acme.com',                        replace: '[REDACTED:EMAIL]',         severity: 'medium',   hits24h: 87, enabled: true },
  { id: 'CC_NUMBER',     name: 'Credit card',           regex: '[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}', example: '4111 1111 1111 1111',                       replace: '[REDACTED:CC]',            severity: 'critical', hits24h: 0,  enabled: true },
  { id: 'SSN',           name: 'US Social Security',    regex: '[0-9]{3}-[0-9]{2}-[0-9]{4}',      example: '123-45-6789',                              replace: '[REDACTED:SSN]',           severity: 'critical', hits24h: 0,  enabled: true },
  { id: 'PRIVATE_KEY',   name: 'PEM private key',       regex: '-----BEGIN [A-Z ]+PRIVATE KEY-----',  example: '-----BEGIN RSA PRIVATE KEY-----\\nMIIE…',  replace: '[REDACTED:PEM]',           severity: 'critical', hits24h: 1,  enabled: true },
  { id: 'INTERNAL_URL',  name: 'Internal URL',          regex: 'https?://[^/]*\\.acme\\.internal', example: 'https://billing.acme.internal/api',        replace: '[REDACTED:INT_URL]',       severity: 'medium',   hits24h: 18, enabled: true },
  { id: 'PHONE',         name: 'Phone (E.164)',         regex: '\\+?[0-9]{10,15}',                example: '+886912345678',                            replace: '[REDACTED:PHONE]',         severity: 'low',      hits24h: 12, enabled: false },
];

const SAMPLE_PAYLOAD = `Hi team — quick note from research-bot-04 sync.

Connecting to billing.acme.internal/api with AKIAIOSFODNN7EXAMPLE
and writing back to s3://customer-pii/ as service principal.

Found one customer record:
  name:  Jane Doe
  email: jane.doe@acme.com
  phone: +886912345678
  card:  4111 1111 1111 1111

Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNlIn0.tEsT_signature
will expire at 2026-05-12T08:00Z.

Forwarding to support@external-vendor.io for follow-up.`;

function tokenize(text, patterns) {
  // Build a single combined regex from enabled patterns; tag each match with pattern id
  const enabled = patterns.filter((p) => p.enabled);
  if (enabled.length === 0) return [{ kind: 'plain', text }];
  const combined = new RegExp(enabled.map((p) => `(?<${p.id}>${p.regex})`).join('|'), 'g');
  const tokens = [];
  let last = 0;
  let m;
  while ((m = combined.exec(text)) !== null) {
    if (m.index > last) tokens.push({ kind: 'plain', text: text.slice(last, m.index) });
    const matchedId = Object.keys(m.groups || {}).find((k) => m.groups[k] !== undefined);
    const pat = enabled.find((p) => p.id === matchedId);
    tokens.push({ kind: 'match', text: m[0], pattern: pat });
    last = m.index + m[0].length;
    if (m[0].length === 0) combined.lastIndex++;
  }
  if (last < text.length) tokens.push({ kind: 'plain', text: text.slice(last) });
  return tokens;
}

function severityColor(s) {
  if (s === 'critical') return 'var(--danger)';
  if (s === 'high') return 'var(--warn)';
  if (s === 'medium') return 'var(--info)';
  return 'var(--ink-3)';
}

function ScrubPage({ toast }) {
  const [patterns, setPatterns] = useSSC(PATTERNS);
  const [selected, setSelected] = useSSC('OPENAI_KEY');
  const [payload, setPayload] = useSSC(SAMPLE_PAYLOAD);
  const [showDetail, setShowDetail] = useSSC(true);

  const sel = patterns.find((p) => p.id === selected);
  const togglePattern = (id) => setPatterns((prev) => prev.map((p) => p.id === id ? { ...p, enabled: !p.enabled } : p));

  const tokens = useMSC(() => tokenize(payload, patterns), [payload, patterns]);
  const matchCount = tokens.filter((t) => t.kind === 'match').length;
  const matchByPattern = {};
  tokens.filter((t) => t.kind === 'match').forEach((t) => {
    matchByPattern[t.pattern.id] = (matchByPattern[t.pattern.id] || 0) + 1;
  });

  const totalHits = patterns.filter((p) => p.enabled).reduce((s, p) => s + p.hits24h, 0);
  const enabledCount = patterns.filter((p) => p.enabled).length;

  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="scrub" />;
  if (ps === 'empty')   return <window.EmptyState page="scrub" />;
  if (ps === 'error')   return <window.ErrorState kind="generic" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Secret Scrubbing
            <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14, marginLeft: 8 }}>
              · L3 · network-layer sanitization
            </span>
          </h1>
          <div className="page-sub">
            Patterns redact secrets and PII from agent traffic <em>before</em> it reaches external endpoints. {enabledCount} of {patterns.length} patterns active · {totalHits} hits today.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className="btn">+ add pattern</button>
          <button className="btn">⏏ export config</button>
        </div>
      </div>

      <div style={{
        padding: '8px 24px',
        background: 'var(--paper-2)',
        borderBottom: '1px solid var(--line)',
        display: 'flex',
        gap: 14,
        alignItems: 'center',
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 11,
      }}>
        <span style={{ color: 'var(--ink-3)' }}>posture: <b style={{ color: 'var(--ok)' }}>● 0 leaks (30d)</b></span>
        <span className="fdivider" />
        <span style={{ color: 'var(--scrub)' }}>● {totalHits} stripped / 24h</span>
        <span className="fdivider" />
        <span>{enabledCount}/{patterns.length} patterns enabled</span>
        <span className="fdivider" />
        <span>covers: <b>http egress · gmail · slack</b></span>
        <span style={{ marginLeft: 'auto', color: 'var(--ink-4)' }}>policy: P-100 · default-allow with scrub</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '420px 1fr', gap: 1, background: 'var(--line)', flex: 1, overflow: 'hidden' }}>

        {/* Left — patterns library */}
        <div style={{ background: 'var(--paper)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="live-pane-head">
            <div className="live-pane-title">▤ patterns library</div>
            <input placeholder="search…" style={{ padding: '3px 8px', border: '1px solid var(--line-2)', borderRadius: 2, fontSize: 11, fontFamily: 'inherit', width: 110 }} />
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 28 }}></th>
                  <th>pattern</th>
                  <th>sev</th>
                  <th style={{ textAlign: 'right' }}>24h</th>
                </tr>
              </thead>
              <tbody>
                {patterns.map((p) => (
                  <tr key={p.id}
                    onClick={() => setSelected(p.id)}
                    style={{ cursor: 'pointer', background: selected === p.id ? 'var(--paper-3)' : (p.enabled ? undefined : 'rgba(0,0,0,0.02)'), opacity: p.enabled ? 1 : 0.55 }}>
                    <td onClick={(e) => { e.stopPropagation(); togglePattern(p.id); }}>
                      <input type="checkbox" checked={p.enabled} readOnly />
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>
                        {p.name}
                        {matchByPattern[p.id] && <span className="chip chip-scrub" style={{ marginLeft: 5, fontSize: 9 }}>{matchByPattern[p.id]} in sample</span>}
                      </div>
                      <div className="wf-mono" style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', marginTop: 1 }}>{p.id}</div>
                    </td>
                    <td>
                      <span style={{ color: severityColor(p.severity), fontFamily: 'JetBrains Mono', fontSize: 10, textTransform: 'uppercase', fontWeight: 600 }}>● {p.severity}</span>
                    </td>
                    <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', fontSize: 11, color: p.hits24h > 0 ? 'var(--scrub)' : 'var(--ink-4)' }}>{p.hits24h}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right — pattern detail + sample diff */}
        <div style={{ background: 'var(--paper)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

          {sel && showDetail && (
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--line)', background: 'var(--paper-2)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>
                    selected pattern · {sel.id}
                  </div>
                  <h3 style={{ margin: '2px 0 0', fontSize: 16 }}>
                    {sel.name}
                    <span style={{ color: severityColor(sel.severity), fontFamily: 'JetBrains Mono', fontSize: 11, marginLeft: 8, textTransform: 'uppercase' }}>● {sel.severity}</span>
                  </h3>
                </div>
                <button className="btn btn-sm btn-ghost" onClick={() => setShowDetail(false)}>− collapse</button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14, marginTop: 12 }}>
                <div>
                  <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.5 }}>regex</div>
                  <code style={{ fontSize: 11, background: 'var(--paper)', border: '1px solid var(--line)', padding: '4px 6px', borderRadius: 2, display: 'block', marginTop: 3, wordBreak: 'break-all' }}>{sel.regex}</code>
                </div>
                <div>
                  <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.5 }}>example match</div>
                  <code style={{ fontSize: 11, background: 'var(--danger-bg)', color: 'var(--danger)', padding: '4px 6px', borderRadius: 2, display: 'block', marginTop: 3, textDecoration: 'line-through', wordBreak: 'break-all' }}>{sel.example}</code>
                </div>
                <div>
                  <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.5 }}>replaced with</div>
                  <code style={{ fontSize: 11, background: 'var(--scrub-bg)', color: 'var(--scrub)', padding: '4px 6px', borderRadius: 2, display: 'block', marginTop: 3 }}>{sel.replace}</code>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 6, marginTop: 12 }}>
                <button className="btn btn-sm" onClick={() => toast(`Edited ${sel.id} (mock)`)}>edit regex</button>
                <button className="btn btn-sm" onClick={() => toast(`Tested against last 24h traffic (mock)`)}>test on traffic</button>
                <button className="btn btn-sm btn-danger" onClick={() => toast(`Disabled ${sel.id}`)}>disable</button>
              </div>
            </div>
          )}

          {/* Sample diff */}
          <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gridTemplateRows: 'auto 1fr', minHeight: 0 }}>
            <div className="live-pane-head" style={{ borderRight: '1px solid var(--line)' }}>
              <div className="live-pane-title">▶ raw payload <span style={{ marginLeft: 8, color: 'var(--ink-3)', textTransform: 'none', letterSpacing: 0 }}>(what agent tried to send)</span></div>
              <span className="chip chip-danger" style={{ fontSize: 9 }}>{matchCount} secrets detected</span>
            </div>
            <div className="live-pane-head">
              <div className="live-pane-title">◀ scrubbed output <span style={{ marginLeft: 8, color: 'var(--ink-3)', textTransform: 'none', letterSpacing: 0 }}>(what reached destination)</span></div>
              <span className="chip chip-ok" style={{ fontSize: 9 }}>safe to forward</span>
            </div>

            <div style={{ borderRight: '1px solid var(--line)', overflow: 'auto', padding: 16, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, lineHeight: 1.6, background: 'var(--paper)' }}>
              <textarea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                style={{
                  width: '100%',
                  minHeight: 280,
                  border: 'none',
                  outline: 'none',
                  resize: 'vertical',
                  font: 'inherit',
                  background: 'transparent',
                  color: 'var(--ink)',
                  padding: 0,
                }}
                spellCheck={false}
              />
              <div style={{ marginTop: 12, paddingTop: 8, borderTop: '1px dashed var(--line)' }}>
                <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>highlighted preview</div>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 11, lineHeight: 1.55 }}>
                  {tokens.map((t, i) => t.kind === 'plain' ? (
                    <span key={i}>{t.text}</span>
                  ) : (
                    <span key={i}
                      title={`${t.pattern.name} · ${t.pattern.id}`}
                      style={{
                        background: 'var(--danger-bg)',
                        color: 'var(--danger)',
                        padding: '0 2px',
                        borderRadius: 2,
                        textDecoration: 'line-through',
                        textDecorationColor: 'rgba(184,41,30,0.6)',
                      }}>{t.text}</span>
                  ))}
                </pre>
              </div>
            </div>

            <div style={{ overflow: 'auto', padding: 16, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, lineHeight: 1.6, background: 'var(--paper-2)' }}>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {tokens.map((t, i) => t.kind === 'plain' ? (
                  <span key={i}>{t.text}</span>
                ) : (
                  <span key={i}
                    title={`replaced by ${t.pattern.id}`}
                    style={{
                      background: 'var(--scrub-bg)',
                      color: 'var(--scrub)',
                      padding: '0 4px',
                      borderRadius: 2,
                      fontWeight: 600,
                    }}>{t.pattern.replace}</span>
                ))}
              </pre>
              <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px dashed var(--line)' }}>
                <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>match summary</div>
                {matchCount === 0 ? (
                  <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>no secrets matched in this payload</div>
                ) : (
                  Object.entries(matchByPattern).map(([id, n]) => {
                    const p = patterns.find((x) => x.id === id);
                    return (
                      <div key={id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0', borderBottom: '1px dashed var(--line)', fontSize: 11 }}>
                        <span>
                          <span style={{ color: severityColor(p.severity), marginRight: 6 }}>●</span>
                          {p.name} <span style={{ color: 'var(--ink-4)', fontFamily: 'JetBrains Mono', fontSize: 10, marginLeft: 4 }}>{id}</span>
                        </span>
                        <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--scrub)', fontWeight: 600 }}>×{n}</span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

Object.assign(window, { ScrubPage });
