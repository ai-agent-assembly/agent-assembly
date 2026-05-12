/* global React */
const { useState: useSL } = React;

const LSketch = ({ children, style, thick, dashed, className = '' }) => (
  <div className={`sketch ${thick ? 'sketch-thick' : ''} ${dashed ? 'sketch-dashed' : ''} ${className}`} style={style}>{children}</div>
);
const LKick = ({ children }) => <div className="kicker">{children}</div>;
const LPH = ({ label, h = 60 }) => <div className="placeholder" style={{ height: h }}>{label}</div>;
const LTag = ({ children, kind }) => <span className={`tag ${kind ? `tag-${kind}` : ''}`}>{children}</span>;

// ---- A · Three-zone layout -------------------------------------
const LiveA = () => (
  <div className="wf" style={{ width: 1280, minHeight: 760 }}>
    <LKick>variant A · three zones · 推薦</LKick>
    <h1 style={{ marginTop: 4 }}>Live Ops — 三區並列</h1>
    <div className="note">流量管線 (主視覺) + event stream (中間) + approval queue (右側卡片)。粒子流動是這頁的英雄敘事。</div>

    <div className="row" style={{ gap: 4, marginTop: 6 }}>
      <LTag kind="info">env: prod</LTag>
      <LTag>last 60s</LTag>
      <LTag kind="warn">⏸ pause stream</LTag>
      <LTag kind="danger">page on-call</LTag>
      <span style={{ marginLeft: 'auto' }}><LTag>● 142 agents · 3.2k req/min</LTag></span>
    </div>

    <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 1fr', gap: 10, marginTop: 10 }}>
      {/* Pipeline */}
      <LSketch thick style={{ minHeight: 540 }}>
        <LKick>traffic pipeline · 流體粒子流動</LKick>
        <h3 style={{ marginTop: 4 }}>Three-layer defense (live)</h3>
        <svg viewBox="0 0 580 460" style={{ width: '100%', height: 470, marginTop: 6 }}>
          <defs>
            <marker id="la-a" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L7,4 L0,8 z" fill="#1a1a1a" /></marker>
          </defs>
          {/* Agents (left) */}
          <text x="50" y="20" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">AGENTS</text>
          {[0,1,2,3,4].map((i) => (
            <g key={i}>
              <rect x="20" y={40 + i * 70} width="60" height="40" rx="4" className="stroke-ink fill-paper" />
              <text x="50" y={64 + i * 70} fontFamily="Kalam" fontSize="11" textAnchor="middle">agent {i+1}</text>
            </g>
          ))}

          {/* L1 Identity */}
          <text x="190" y="20" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">L1 · IDENTITY</text>
          <rect x="140" y="40" width="100" height="380" rx="6" className="stroke-thick fill-paper" />
          <text x="190" y="60" fontFamily="Kalam" fontSize="13" fontWeight="700" textAnchor="middle">verify DID</text>
          <text x="190" y="78" fontFamily="JetBrains Mono" fontSize="9" textAnchor="middle">trust check</text>
          {/* particles trail */}
          {[120, 180, 240, 300, 360].map((y, i) => (
            <circle key={i} cx={130 + i * 8} cy={y} r="3" fill="#1a1a1a" opacity={0.3 + i * 0.15} />
          ))}
          <text x="190" y="400" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">passed: 3198</text>
          <text x="190" y="414" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle" fill="#b8291e">blocked: 2</text>

          {/* L2 Capability */}
          <text x="320" y="20" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">L2 · CAPABILITY</text>
          <rect x="270" y="40" width="100" height="380" rx="6" className="stroke-thick fill-paper" style={{ fill: '#fbeed1' }} />
          <text x="320" y="60" fontFamily="Kalam" fontSize="13" fontWeight="700" textAnchor="middle">policy enforce</text>
          <text x="320" y="78" fontFamily="JetBrains Mono" fontSize="9" textAnchor="middle">narrow / approve</text>
          {/* stuck particles in approval pool */}
          <ellipse cx="320" cy="220" rx="36" ry="14" fill="#d6dfee" stroke="#1d3a7a" strokeWidth="1.5" strokeDasharray="3 2" />
          <text x="320" y="224" fontFamily="JetBrains Mono" fontSize="9" textAnchor="middle" fill="#1d3a7a">⏸ 8 await</text>
          {[200, 215, 230, 245].map((x, i) => (
            <circle key={i} cx={x} cy={220} r="3" fill="#1d3a7a" />
          ))}
          <text x="320" y="400" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">narrowed: 87</text>
          <text x="320" y="414" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle" fill="#1d3a7a">approval: 8</text>

          {/* L3 Scrub */}
          <text x="450" y="20" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">L3 · SCRUB</text>
          <rect x="400" y="40" width="100" height="380" rx="6" className="stroke-thick fill-paper" style={{ fill: '#e8dbf3' }} />
          <text x="450" y="60" fontFamily="Kalam" fontSize="13" fontWeight="700" textAnchor="middle">sanitize</text>
          <text x="450" y="78" fontFamily="JetBrains Mono" fontSize="9" textAnchor="middle">strip secrets</text>
          {/* purple particles */}
          {[140, 190, 240, 290, 340].map((y, i) => (
            <circle key={i} cx={450} cy={y} r="3" fill="#5a1a8a" opacity={0.4 + i * 0.1} />
          ))}
          <text x="450" y="400" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">scrubbed: 226</text>

          {/* External */}
          <text x="550" y="20" fontFamily="JetBrains Mono" fontSize="10" textAnchor="middle">→ EXT</text>
          <rect x="525" y="40" width="50" height="380" rx="4" className="stroke-dashed fill-paper" />
          <text x="550" y="220" fontFamily="Kalam" fontSize="11" textAnchor="middle" transform="rotate(90 550 220)">openai · http · s3</text>

          {/* arrows agent -> L1 */}
          {[60, 130, 200, 270, 340].map((y, i) => (
            <line key={i} x1="80" y1={y} x2="140" y2={y} className="stroke-ink" markerEnd="url(#la-a)" />
          ))}
          {/* L1 -> L2 */}
          <line x1="240" y1="220" x2="270" y2="220" className="stroke-ink" markerEnd="url(#la-a)" />
          {/* L2 -> L3 */}
          <line x1="370" y1="220" x2="400" y2="220" className="stroke-ink" markerEnd="url(#la-a)" />
          {/* L3 -> EXT */}
          <line x1="500" y1="220" x2="525" y2="220" className="stroke-ink" markerEnd="url(#la-a)" />

          {/* Blocked branch */}
          <path d="M 240 380 Q 260 420 380 440" className="stroke-ink" strokeDasharray="3 2" markerEnd="url(#la-a)" />
          <text x="320" y="450" fontFamily="JetBrains Mono" fontSize="9" textAnchor="middle" fill="#b8291e">denied → audit log</text>
        </svg>
        <small className="note">即時粒子：通過時順流，被擋住時卡在該層 (warn 池)，洩漏阻擋時有紫色閃光</small>
      </LSketch>

      {/* Stream */}
      <LSketch style={{ minHeight: 540 }}>
        <LKick>tail -f · live event stream</LKick>
        <h3 style={{ marginTop: 4, fontSize: 15 }}>Recent decisions</h3>
        <div style={{ background: '#1a1a1a', color: '#e6e1d4', fontFamily: 'JetBrains Mono', fontSize: 10, padding: 8, borderRadius: 3, marginTop: 6, height: 460, overflow: 'hidden', lineHeight: 1.45 }}>
          {[
            ['14:02:11', 'allow', 'research-bot-04', 'pg.read'],
            ['14:02:10', 'narrow', 'support-triage', 'gmail.write'],
            ['14:02:09', 'scrub', 'sales-outreach', 'http.post'],
            ['14:02:09', 'approve', 'finance-bot', 's3.write'],
            ['14:02:08', 'deny', 'research-bot-04', 'shell.exec'],
            ['14:02:07', 'allow', 'docs-summary', 'gdrive.read'],
            ['14:02:07', 'narrow', 'analytics', 's3.read'],
            ['14:02:06', 'scrub', 'support-triage', 'http.post'],
            ['14:02:05', 'approve', 'infra-ops', 'github.write'],
            ['14:02:04', 'allow', 'research-bot-04', 'pg.read'],
            ['14:02:04', 'deny', 'finance-bot', 's3.write'],
            ['14:02:03', 'narrow', 'support-triage', 'pg.read'],
          ].map(([t, d, a, r], i) => (
            <div key={i} style={{ opacity: 1 - i * 0.06 }}>
              <span style={{ color: '#8a8880' }}>{t}</span>{' '}
              <span style={{ color: d==='deny'?'#fca5a5':d==='narrow'?'#fde68a':d==='approve'?'#bfdbfe':d==='scrub'?'#d8b4fe':'#a8a89c' }}>{d.padEnd(7)}</span>
              <span> {a.padEnd(18)}</span>
              <span style={{ color: '#a8a89c' }}>{r}</span>
            </div>
          ))}
        </div>
      </LSketch>

      {/* Approval queue */}
      <LSketch style={{ minHeight: 540 }}>
        <LKick>approval queue · 8 待審</LKick>
        <h3 style={{ marginTop: 4, fontSize: 15 }}>Awaiting approval</h3>
        <div className="col" style={{ gap: 6, marginTop: 6 }}>
          {[
            { agent: 'research-bot-04', verb: 'write', target: 's3://customer-pii/', urgent: true, age: '12s' },
            { agent: 'finance-bot', verb: 'exec', target: 'shell:psql', urgent: true, age: '34s' },
            { agent: 'sales-outreach', verb: 'write', target: 'gmail/send (ext)', age: '1m' },
            { agent: 'infra-ops', verb: 'write', target: 'github acme/infra', age: '2m' },
          ].map((x, i) => (
            <div key={i} style={{ border: x.urgent ? '2px solid #b8291e' : '1.5px solid #2a2a2a', background: 'var(--paper)', padding: 8, borderRadius: 3 }}>
              <div className="row between">
                <strong style={{ fontSize: 12 }}>{x.agent}</strong>
                {x.urgent && <LTag kind="danger">⚠ pii</LTag>}
              </div>
              <div className="wf-mono" style={{ fontSize: 10, color: 'var(--ink-soft)', marginTop: 2 }}>{x.verb} → {x.target}</div>
              <div className="row" style={{ gap: 4, marginTop: 6 }}>
                <LTag kind="ok">✓ approve</LTag>
                <LTag kind="danger">✕ reject</LTag>
                <LTag>view trace</LTag>
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--ink-faint)' }}>{x.age}</span>
              </div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 10, paddingTop: 8, borderTop: '1.5px dashed var(--ink-faint)' }}>
          <small className="note">同一個 queue 也以 🔔 出現在每頁 top bar，dev 可隨時 approve</small>
        </div>
      </LSketch>
    </div>
  </div>
);

// ---- B · Castle moat 中央視覺 -------------------------------------
const LiveB = () => (
  <div className="wf" style={{ width: 1280, minHeight: 760 }}>
    <LKick>variant B · castle moat 為中心 · 視覺爆發力最強</LKick>
    <h1 style={{ marginTop: 4 }}>Live Ops — 城堡護城河 (live)</h1>
    <div className="note">同心圓資產層 = 公司核心資料；箭頭粒子 = 即時請求；被擋下的請求停留在該層紅光閃爍。</div>

    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 10, marginTop: 10 }}>
      <LSketch thick style={{ minHeight: 580 }}>
        <LKick>asset rings · live attacks</LKick>
        <svg viewBox="0 0 700 540" style={{ width: '100%', height: 540 }}>
          {/* concentric rings */}
          {[260, 200, 140, 80].map((r, i) => (
            <circle key={i} cx="350" cy="270" r={r} className="stroke-thick fill-paper" style={{ fill: ['#fff', '#f5f4f0', '#ebe9e2', '#fbeed1'][i] }} />
          ))}
          <text x="350" y="275" textAnchor="middle" fontFamily="Kalam" fontSize="14" fontWeight="700">crown jewels</text>
          <text x="350" y="290" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="9">customer-pii / secrets</text>

          {/* ring labels */}
          <text x="350" y="40" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">L1 · IDENTITY (outer)</text>
          <text x="350" y="100" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">L2 · CAPABILITY</text>
          <text x="350" y="160" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10">L3 · SCRUB</text>

          {/* incoming arrows from 4 directions */}
          {[
            { x1: 50,  y1: 60,  label: 'research-bot-04', stop: 'L2', kind: 'block' },
            { x1: 650, y1: 90,  label: 'support-triage',  stop: 'L3', kind: 'scrub' },
            { x1: 80,  y1: 480, label: 'finance-bot',     stop: 'L1', kind: 'block' },
            { x1: 640, y1: 470, label: 'analytics',       stop: 'core', kind: 'allow' },
            { x1: 350, y1: 20,  label: 'docs-summary',    stop: 'L2', kind: 'narrow' },
          ].map((a, i) => {
            const targetR = a.stop === 'L1' ? 260 : a.stop === 'L2' ? 200 : a.stop === 'L3' ? 140 : 60;
            const dx = 350 - a.x1, dy = 270 - a.y1;
            const len = Math.sqrt(dx*dx+dy*dy);
            const tx = a.x1 + (dx/len) * (len - targetR);
            const ty = a.y1 + (dy/len) * (len - targetR);
            const color = a.kind === 'block' ? '#b8291e' : a.kind === 'scrub' ? '#5a1a8a' : a.kind === 'narrow' ? '#8a5a00' : '#22592a';
            return (
              <g key={i}>
                <line x1={a.x1} y1={a.y1} x2={tx} y2={ty} stroke={color} strokeWidth="2" strokeDasharray={a.kind==='allow'?'':'4 2'} />
                <circle cx={a.x1} cy={a.y1} r="5" fill={color} />
                <text x={a.x1} y={a.y1 - 10} fontFamily="JetBrains Mono" fontSize="9" textAnchor="middle" fill={color}>{a.label}</text>
                {/* burst at stop point */}
                <circle cx={tx} cy={ty} r="6" fill={color} opacity="0.4" />
                <circle cx={tx} cy={ty} r="9" fill="none" stroke={color} strokeWidth="1.5" strokeDasharray="2 2" />
                <text x={tx} y={ty + 22} fontFamily="JetBrains Mono" fontSize="8" textAnchor="middle" fill={color}>{a.kind}</text>
              </g>
            );
          })}
        </svg>
      </LSketch>

      <div className="col" style={{ gap: 8 }}>
        <LSketch>
          <LKick>now (60s)</LKick>
          <div className="row" style={{ gap: 8 }}>
            <div><div className="metric-big" style={{ fontSize: 26, color: 'var(--danger)' }}>14</div><small>blocked</small></div>
            <div><div className="metric-big" style={{ fontSize: 26, color: 'var(--scrub)' }}>22</div><small>scrubbed</small></div>
            <div><div className="metric-big" style={{ fontSize: 26, color: 'var(--info)' }}>8</div><small>await</small></div>
          </div>
        </LSketch>
        <LSketch dashed>
          <LKick>approval queue · top bar 通用 🔔</LKick>
          <LPH label="同 A 案：右側卡片列表" h={300} />
        </LSketch>
        <LSketch>
          <LKick>event stream</LKick>
          <LPH label="terminal tail (compact)" h={140} />
        </LSketch>
      </div>
    </div>
  </div>
);

// ---- C · Compact dashboard 風 -------------------------------------
const LiveC = () => (
  <div className="wf" style={{ width: 1280, minHeight: 760 }}>
    <LKick>variant C · compact · 監控站台風格</LKick>
    <h1 style={{ marginTop: 4 }}>Live Ops — 高密度監控</h1>
    <div className="note">沒有粒子英雄畫面，純資料密度；給已經很熟悉的 SRE 用。</div>

    <div className="grid-4" style={{ gap: 8, marginTop: 10 }}>
      {[
        ['req/min', '3.2k'],['blocked', '14'],['scrubbed', '22'],['await', '8'],
      ].map(([l, v]) => (
        <LSketch key={l}><div className="metric-label">{l}</div><div className="metric-big">{v}</div></LSketch>
      ))}
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 8, marginTop: 8 }}>
      <LSketch thick><LKick>3-layer pipeline (compact)</LKick><LPH label="horizontal flow chart, no particles" h={200} /></LSketch>
      <LSketch><LKick>per-layer breakdown</LKick><LPH label="L1/L2/L3 stacked bars" h={200} /></LSketch>
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8, marginTop: 8 }}>
      <LSketch><LKick>events table (sortable)</LKick><LPH label="20-row dense table · ts/agent/verb/decision/policy" h={230} /></LSketch>
      <LSketch><LKick>approval queue</LKick><LPH label="card list" h={230} /></LSketch>
    </div>
  </div>
);

Object.assign(window, { LiveA, LiveB, LiveC });
