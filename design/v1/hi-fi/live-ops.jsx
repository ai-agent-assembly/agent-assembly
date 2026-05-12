/* global React */
const { useEffect: useELO, useRef: useRLO, useState: useSLO } = React;

// ============================================================
// Live Ops page — three zones: pipeline / stream / approvals
// ============================================================

// Pipeline geometry — relative coords, scaled to canvas size at draw time
const LANES = [
  { id: 'agents',     label: 'AGENTS',     x: 0.06, color: '#1a1a1a' },
  { id: 'l1',         label: 'L1 IDENTITY', x: 0.28, color: '#1a1a1a', w: 0.13 },
  { id: 'l2',         label: 'L2 CAPABILITY', x: 0.50, color: '#8a5a00', w: 0.13 },
  { id: 'l3',         label: 'L3 SCRUB',    x: 0.72, color: '#5a1a8a', w: 0.13 },
  { id: 'ext',        label: '→ EXTERNAL', x: 0.94, color: '#1a1a1a' },
];

// A particle has: id, lane y-track, current phase, x progress within phase
//  phase: 'a-l1' | 'l1-l2' | 'l2-l3' | 'l3-ext'  | stuck-l1 / stuck-l2 / stuck-l3 / blocked
function PipelineCanvas({ paused, intensity, onCounters }) {
  const canvasRef = useRLO(null);
  const stateRef = useRLO({ particles: [], counters: { req: 0, allow: 0, narrow: 0, deny: 0, scrub: 0, approval: 0, t0: Date.now() } });
  const rafRef = useRLO(null);
  const sizeRef = useRLO({ w: 800, h: 480 });

  useELO(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const parent = canvas.parentElement;
      const rect = parent ? parent.getBoundingClientRect() : canvas.getBoundingClientRect();
      const w = Math.max(rect.width || 800, 400);
      const h = Math.max(rect.height || 400, 300);
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      sizeRef.current = { w, h };
    };
    resize();
    // re-measure after layout settles
    const t1 = setTimeout(resize, 50);
    const t2 = setTimeout(resize, 250);
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    let lastSpawn = 0;
    let lastCounter = 0;

    const draw = (ts) => {
      const { w, h } = sizeRef.current;
      const state = stateRef.current;

      // background
      ctx.clearRect(0, 0, w, h);

      // lane backgrounds
      const laneCols = {
        agents: { x: 0.04 * w,  w: 0.10 * w, fill: '#fafaf7' },
        l1:     { x: 0.22 * w,  w: 0.13 * w, fill: '#fafaf7' },
        l2:     { x: 0.43 * w,  w: 0.13 * w, fill: '#fbf2dc' },
        l3:     { x: 0.64 * w,  w: 0.13 * w, fill: '#f0e3f7' },
        ext:    { x: 0.85 * w,  w: 0.10 * w, fill: '#fafaf7' },
      };
      Object.values(laneCols).forEach((l) => {
        ctx.fillStyle = l.fill;
        ctx.fillRect(l.x, 28, l.w, h - 56);
        ctx.strokeStyle = '#d8d4c7';
        ctx.lineWidth = 1;
        ctx.strokeRect(l.x, 28, l.w, h - 56);
      });

      // lane labels (top)
      ctx.fillStyle = '#5a5a5a';
      ctx.font = '9px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText('AGENTS',       laneCols.agents.x + laneCols.agents.w / 2, 18);
      ctx.fillText('L1 · IDENTITY', laneCols.l1.x + laneCols.l1.w / 2, 18);
      ctx.fillText('L2 · CAPABILITY', laneCols.l2.x + laneCols.l2.w / 2, 18);
      ctx.fillText('L3 · SCRUB',      laneCols.l3.x + laneCols.l3.w / 2, 18);
      ctx.fillText('→ EXTERNAL',      laneCols.ext.x + laneCols.ext.w / 2, 18);

      // gates rendered as solid borders
      ctx.fillStyle = '#1a1a1a';
      ctx.font = '10px Inter';
      ctx.textBaseline = 'middle';
      ctx.fillText('verify DID', laneCols.l1.x + laneCols.l1.w / 2, 50);
      ctx.fillStyle = '#8a5a00';
      ctx.fillText('policy enforce', laneCols.l2.x + laneCols.l2.w / 2, 50);
      ctx.fillStyle = '#5a1a8a';
      ctx.fillText('sanitize', laneCols.l3.x + laneCols.l3.w / 2, 50);

      // approval pool rendering — semi-transparent inside L2
      const stuckL2 = state.particles.filter((p) => p.phase === 'stuck-l2');
      if (stuckL2.length > 0) {
        const cx = laneCols.l2.x + laneCols.l2.w / 2;
        const cy = h * 0.55;
        ctx.fillStyle = 'rgba(29, 58, 122, 0.10)';
        ctx.strokeStyle = 'rgba(29, 58, 122, 0.55)';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([3, 2]);
        ctx.beginPath();
        ctx.ellipse(cx, cy, 38, 16 + Math.min(stuckL2.length, 8) * 1.5, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = '#1d3a7a';
        ctx.font = '9px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`⏸ ${stuckL2.length} await`, cx, cy);
      }

      // spawn particles
      if (!paused && ts - lastSpawn > (1100 / intensity)) {
        lastSpawn = ts;
        // determine fate from a weighted random
        const r = Math.random();
        let fate;
        if (r < 0.55) fate = 'allow';
        else if (r < 0.75) fate = 'narrow';
        else if (r < 0.85) fate = 'scrub';
        else if (r < 0.95) fate = 'approval'; // gets stuck in L2
        else if (r < 0.98) fate = 'deny';
        else fate = 'identity-fail';

        state.particles.push({
          id: Math.random(),
          y: 60 + Math.random() * (h - 110),
          x: laneCols.agents.x + laneCols.agents.w,
          phase: 'to-l1',
          fate,
          age: 0,
          speed: 1.2 + Math.random() * 0.6,
        });
        state.counters.req += 1;
      }

      // update + draw particles
      const survivors = [];
      for (const p of state.particles) {
        p.age += 1;

        const colorFor = () => {
          if (p.fate === 'allow') return '#1a1a1a';
          if (p.fate === 'narrow') return '#8a5a00';
          if (p.fate === 'scrub') return '#5a1a8a';
          if (p.fate === 'approval') return '#1d3a7a';
          if (p.fate === 'deny' || p.fate === 'identity-fail') return '#b8291e';
          return '#1a1a1a';
        };

        // movement logic
        if (p.phase === 'to-l1') {
          p.x += p.speed;
          if (p.x >= laneCols.l1.x) {
            p.x = laneCols.l1.x;
            if (p.fate === 'identity-fail') { p.phase = 'blocked'; p.blockedAt = 'l1'; state.counters.deny++; }
            else { p.phase = 'in-l1'; p.tEnter = ts; }
          }
        } else if (p.phase === 'in-l1') {
          if (ts - p.tEnter > 200) { p.phase = 'to-l2'; }
        } else if (p.phase === 'to-l2') {
          p.x += p.speed;
          if (p.x >= laneCols.l2.x) {
            p.x = laneCols.l2.x;
            if (p.fate === 'deny') { p.phase = 'blocked'; p.blockedAt = 'l2'; state.counters.deny++; }
            else if (p.fate === 'approval') { p.phase = 'stuck-l2'; p.stuckAt = ts; state.counters.approval++; }
            else { p.phase = 'in-l2'; p.tEnter = ts; if (p.fate === 'narrow') state.counters.narrow++; }
          }
        } else if (p.phase === 'in-l2') {
          if (ts - p.tEnter > 200) { p.phase = 'to-l3'; }
        } else if (p.phase === 'to-l3') {
          p.x += p.speed;
          if (p.x >= laneCols.l3.x) {
            p.x = laneCols.l3.x;
            p.phase = 'in-l3';
            p.tEnter = ts;
            if (p.fate === 'scrub') state.counters.scrub++;
          }
        } else if (p.phase === 'in-l3') {
          if (ts - p.tEnter > 200) { p.phase = 'to-ext'; }
        } else if (p.phase === 'to-ext') {
          p.x += p.speed * 1.4;
          if (p.x >= laneCols.ext.x + laneCols.ext.w) { state.counters.allow++; continue; }
        } else if (p.phase === 'stuck-l2') {
          // jitter
          if (ts - p.stuckAt > 4500) continue; // age out
        } else if (p.phase === 'blocked') {
          p.fadeAge = (p.fadeAge || 0) + 1;
          if (p.fadeAge > 50) continue;
        }

        // draw particle
        const c = colorFor();
        ctx.fillStyle = c;
        ctx.globalAlpha = p.phase === 'blocked' ? Math.max(0, 1 - p.fadeAge / 50) : 1;

        if (p.phase === 'stuck-l2') {
          // draw inside approval pool with gentle drift
          const cx = laneCols.l2.x + laneCols.l2.w / 2;
          const cy = h * 0.55;
          const angle = (p.id * 9.7 + ts * 0.001) % (Math.PI * 2);
          const r = 12 + (p.id * 13) % 10;
          ctx.beginPath();
          ctx.arc(cx + Math.cos(angle) * r, cy + Math.sin(angle) * r, 2.5, 0, Math.PI * 2);
          ctx.fill();
        } else if (p.phase === 'blocked') {
          // burst at gate
          ctx.beginPath();
          ctx.arc(p.x, p.y, 3 + p.fadeAge / 6, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = Math.max(0, 0.4 - p.fadeAge / 60);
          ctx.beginPath();
          ctx.arc(p.x, p.y, 6 + p.fadeAge / 3, 0, Math.PI * 2);
          ctx.stroke();
          ctx.strokeStyle = c;
          ctx.lineWidth = 1.2;
        } else {
          // trail
          ctx.beginPath();
          ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 0.25;
          ctx.beginPath();
          ctx.arc(p.x - 6, p.y, 1.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.beginPath();
          ctx.arc(p.x - 12, p.y, 1, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.globalAlpha = 1;
        survivors.push(p);
      }
      state.particles = survivors;

      // counter labels under each lane
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      const passedL1 = state.counters.req - state.particles.filter((p) => p.phase === 'to-l1' || (p.phase === 'blocked' && p.blockedAt === 'l1')).length;
      ctx.fillStyle = '#5a5a5a';
      ctx.fillText(`passed: ${passedL1}`, laneCols.l1.x + laneCols.l1.w / 2, h - 22);

      ctx.fillStyle = '#8a5a00';
      ctx.fillText(`narrow: ${state.counters.narrow}`, laneCols.l2.x + laneCols.l2.w / 2, h - 22);

      ctx.fillStyle = '#5a1a8a';
      ctx.fillText(`scrub: ${state.counters.scrub}`, laneCols.l3.x + laneCols.l3.w / 2, h - 22);

      ctx.fillStyle = '#22592a';
      ctx.fillText(`out: ${state.counters.allow}`, laneCols.ext.x + laneCols.ext.w / 2, h - 22);

      // counters back to React every 500ms
      if (ts - lastCounter > 500) {
        lastCounter = ts;
        const elapsed = (Date.now() - state.counters.t0) / 1000;
        onCounters && onCounters({
          rpm: Math.round((state.counters.req / Math.max(elapsed, 1)) * 60),
          allow: state.counters.allow,
          narrow: state.counters.narrow,
          deny: state.counters.deny,
          scrub: state.counters.scrub,
          approval: state.particles.filter((p) => p.phase === 'stuck-l2').length,
        });
      }

      rafRef.current = requestAnimationFrame(draw);
    };

    // Run draw synchronously once so static structure (lanes, labels, gates)
    // is painted even before rAF kicks in (or if rAF is throttled in a hidden tab).
    draw(performance.now());

    rafRef.current = requestAnimationFrame(draw);

    // Fallback: if rAF is throttled (hidden tab), drive draw with setInterval too.
    // Cheap; rAF will still take precedence when visible.
    const fallbackInt = setInterval(() => {
      if (document.hidden) draw(performance.now());
    }, 80);

    return () => {
      cancelAnimationFrame(rafRef.current);
      clearTimeout(t1);
      clearTimeout(t2);
      clearInterval(fallbackInt);
      ro.disconnect();
    };
  }, [paused, intensity]);

  // aa-pulse-lane event → highlight the relevant lane briefly
  useELO(() => {
    const FATE_LANE = { allow: 'ext', narrow: 'l2', scrub: 'l3', approval: 'l2', deny: 'l2', 'identity-fail': 'l1' };
    const FATE_COLOR = {
      allow: 'rgba(34,89,42,0.13)', narrow: 'rgba(138,90,0,0.15)', scrub: 'rgba(90,26,138,0.14)',
      approval: 'rgba(29,58,122,0.18)', deny: 'rgba(184,41,30,0.16)', 'identity-fail': 'rgba(184,41,30,0.14)',
    };
    const onPulse = (e) => {
      highlightRef.current = {
        lane: FATE_LANE[e.detail.fate] || null,
        color: FATE_COLOR[e.detail.fate] || null,
        startTs: Date.now(),
      };
    };
    window.addEventListener('aa-pulse-lane', onPulse);
    return () => window.removeEventListener('aa-pulse-lane', onPulse);
  }, []);

  // click in the L2 approval-pool ellipse → open approval detail
  const handleCanvasClick = (e) => {
    const { w, h } = sizeRef.current;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const l2cx = 0.43 * w + (0.13 * w) / 2;
    const l2cy = h * 0.55;
    const dx = (x - l2cx) / 54;
    const dy = (y - l2cy) / 28;
    if (dx * dx + dy * dy <= 1) onApprovalPoolClick && onApprovalPoolClick();
  };

  return <canvas ref={canvasRef} className="pipeline-canvas" style={{ cursor: 'default' }} onClick={handleCanvasClick} />;
}

// ----- Event Stream -------------------------------------------

function EventStream({ paused, onLineClick }) {
  const [lines, setLines] = useSLO([]);
  const lastIdRef = useRLO(0);

  useELO(() => {
    if (paused) return;
    const i = setInterval(() => {
      const agents = window.AGENTS.map((a) => a.id);
      const verbs = ['read', 'write', 'delete', 'exec'];
      const resources = ['gmail.send', 'pg.users', 'gdrive.read', 's3.write', 'github.commit', 'http.post', 'shell.exec', 'gmail.read'];
      const decisions = ['allow', 'allow', 'allow', 'allow', 'narrow', 'narrow', 'scrub', 'scrub', 'approval', 'deny'];

      const a = agents[Math.floor(Math.random() * agents.length)];
      const v = verbs[Math.floor(Math.random() * verbs.length)];
      const r = resources[Math.floor(Math.random() * resources.length)];
      const d = decisions[Math.floor(Math.random() * decisions.length)];
      const t = new Date();
      const ts = `${t.getHours().toString().padStart(2,'0')}:${t.getMinutes().toString().padStart(2,'0')}:${t.getSeconds().toString().padStart(2,'0')}`;

      lastIdRef.current += 1;
      setLines((prev) => [
        { id: lastIdRef.current, ts, agent: a, verb: v, res: r, dec: d, fresh: true },
        ...prev.slice(0, 60),
      ]);
    }, 600);
    return () => clearInterval(i);
  }, [paused]);

  // mark non-fresh after their flash animation
  useELO(() => {
    if (lines.some((l) => l.fresh)) {
      const t = setTimeout(() => {
        setLines((prev) => prev.map((l) => ({ ...l, fresh: false })));
      }, 450);
      return () => clearTimeout(t);
    }
  }, [lines]);

  return (
    <div className="stream">
      {lines.map((l) => (
        <div key={l.id} className={`stream-line ${l.fresh ? 'flash' : ''}`} style={{ cursor: 'pointer' }}
          onClick={() => {
            window.dispatchEvent(new CustomEvent('aa-pulse-lane', { detail: { fate: l.dec } }));
            onLineClick && onLineClick(l);
          }}>
          <span className="s-ts">{l.ts}</span>{' '}
          <span className={`s-${l.dec}`}>{l.dec.padEnd(8)}</span>
          <span> {l.agent.padEnd(20)}</span>
          <span style={{ color: '#a8a89c' }}>{l.verb.padEnd(7)}</span>
          <span style={{ color: '#c9c5b6' }}>{l.res}</span>
        </div>
      ))}
      {lines.length === 0 && (
        <div style={{ color: '#6a6a60', textAlign: 'center', padding: 20 }}>waiting for events…</div>
      )}
    </div>
  );
}

// ----- Approval Queue -----------------------------------------

function ApprovalCard({ a, onApprove, onReject, onTrace, onCardClick, compact }) {
  return (
    <div className={`aq-card ${a.urgent ? 'urgent' : ''}`} style={{ cursor: 'pointer' }} onClick={() => onCardClick && onCardClick(a)}>
      <div className="aq-card-head">
        <div style={{ flex: 1 }}>
          <div className="aq-id">{a.id} · {a.policy} · L2 ({a.reason})</div>
          <div className="aq-agent">
            {a.agent}
            {a.urgent && <span className="chip chip-danger" style={{ marginLeft: 6, fontSize: 9 }}>⚠ urgent</span>}
          </div>
        </div>
        <div className="aq-age">{a.age}</div>
      </div>
      <div className="aq-action"><b>{a.verb}</b>{a.resource}</div>
      {!compact && <div className="aq-detail">{a.detail}</div>}
      <div className="aq-actions">
        <button className="aq-btn-approve" onClick={(e) => { e.stopPropagation(); onApprove(a); }}>✓ approve</button>
        <button className="aq-btn-reject" onClick={(e) => { e.stopPropagation(); onReject(a); }}>✕ reject</button>
        {!compact && <button className="aq-btn-trace" onClick={(e) => { e.stopPropagation(); (onCardClick || onTrace)(a); }}>↗ detail</button>}
      </div>
    </div>
  );
}

function ApprovalQueue({ approvals, onApprove, onReject, onTrace, onCardClick, compact }) {
  if (approvals.length === 0) {
    return <div className="empty">no pending approvals</div>;
  }
  return (
    <div className="aq-list">
      {approvals.map((a) => (
        <ApprovalCard key={a.id} a={a} onApprove={onApprove} onReject={onReject} onTrace={onTrace} onCardClick={onCardClick} compact={compact} />
      ))}
    </div>
  );
}

// ----- Castle Moat View (alternate visualization) -------------

function CastleMoat({ paused, intensity }) {
  const canvasRef = useRLO(null);
  const stateRef = useRLO({ arrows: [], counters: { blocked: 0, scrubbed: 0, narrowed: 0, allowed: 0 } });
  const rafRef = useRLO(null);
  const sizeRef = useRLO({ w: 800, h: 540 });

  useELO(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const parent = canvas.parentElement;
      const rect = parent ? parent.getBoundingClientRect() : canvas.getBoundingClientRect();
      const w = Math.max(rect.width || 800, 400);
      const h = Math.max(rect.height || 540, 400);
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      sizeRef.current = { w, h };
    };
    resize();
    const t1 = setTimeout(resize, 50);
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    let lastSpawn = 0;

    const draw = (ts) => {
      const { w, h } = sizeRef.current;
      const cx = w / 2;
      const cy = h / 2;
      const rings = [
        { r: Math.min(w, h) * 0.42, fill: '#fafaf7', label: 'L1 · IDENTITY' },
        { r: Math.min(w, h) * 0.32, fill: '#f4f2eb', label: 'L2 · CAPABILITY' },
        { r: Math.min(w, h) * 0.22, fill: '#ebe9e2', label: 'L3 · SCRUB' },
        { r: Math.min(w, h) * 0.12, fill: '#fbeed1', label: 'CROWN' },
      ];

      ctx.clearRect(0, 0, w, h);

      // rings
      rings.forEach((ring, i) => {
        ctx.beginPath();
        ctx.arc(cx, cy, ring.r, 0, Math.PI * 2);
        ctx.fillStyle = ring.fill;
        ctx.fill();
        ctx.strokeStyle = i === 3 ? '#8a5a00' : '#d8d4c7';
        ctx.lineWidth = i === 3 ? 1.5 : 1;
        ctx.stroke();
      });

      // ring labels (top of each ring)
      ctx.fillStyle = '#5a5a5a';
      ctx.font = '9px JetBrains Mono';
      ctx.textAlign = 'center';
      rings.slice(0, 3).forEach((ring) => {
        ctx.fillText(ring.label, cx, cy - ring.r + 12);
      });

      // crown jewel center
      ctx.fillStyle = '#8a5a00';
      ctx.font = '11px Inter';
      ctx.textBaseline = 'middle';
      ctx.fillText('crown jewels', cx, cy - 6);
      ctx.fillStyle = '#5a5a5a';
      ctx.font = '8px JetBrains Mono';
      ctx.fillText('customer-pii', cx, cy + 8);

      // spawn arrows
      if (!paused && ts - lastSpawn > (1400 / intensity)) {
        lastSpawn = ts;
        const angle = Math.random() * Math.PI * 2;
        const startR = Math.min(w, h) * 0.49;
        const startX = cx + Math.cos(angle) * startR;
        const startY = cy + Math.sin(angle) * startR;
        const r = Math.random();
        let stopRing, fate;
        if (r < 0.45) { stopRing = 0; fate = 'allow'; }    // through outer (no harm)
        else if (r < 0.65) { stopRing = 2; fate = 'narrow'; }
        else if (r < 0.78) { stopRing = 2; fate = 'scrub'; }
        else if (r < 0.90) { stopRing = 1; fate = 'block'; }
        else { stopRing = 0; fate = 'identity-fail'; }

        stateRef.current.arrows.push({
          id: Math.random(),
          startX, startY, angle,
          stopR: rings[stopRing].r,
          fate,
          progress: 0,
          age: 0,
          burstAge: 0,
        });
      }

      // update + draw arrows
      const survivors = [];
      for (const a of stateRef.current.arrows) {
        a.age += 1;
        const startR = Math.min(w, h) * 0.49;
        const distance = startR - a.stopR;

        if (a.progress < 1) {
          a.progress += (0.012 + intensity * 0.004);
          const curR = startR - distance * Math.min(a.progress, 1);
          const x = cx + Math.cos(a.angle) * curR;
          const y = cy + Math.sin(a.angle) * curR;

          const color = a.fate === 'block' || a.fate === 'identity-fail' ? '#b8291e'
            : a.fate === 'scrub' ? '#5a1a8a'
            : a.fate === 'narrow' ? '#8a5a00'
            : '#22592a';

          // arrow line from start to current pos
          ctx.strokeStyle = color;
          ctx.lineWidth = 2;
          ctx.setLineDash(a.fate === 'allow' ? [] : [4, 2]);
          ctx.beginPath();
          ctx.moveTo(a.startX, a.startY);
          ctx.lineTo(x, y);
          ctx.stroke();
          ctx.setLineDash([]);

          // arrowhead
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(x, y, 3, 0, Math.PI * 2);
          ctx.fill();

          // start marker
          ctx.beginPath();
          ctx.arc(a.startX, a.startY, 3, 0, Math.PI * 2);
          ctx.fill();

          if (a.progress >= 1) {
            a.burstAge = 0;
            // count
            if (a.fate === 'block' || a.fate === 'identity-fail') stateRef.current.counters.blocked++;
            else if (a.fate === 'scrub') stateRef.current.counters.scrubbed++;
            else if (a.fate === 'narrow') stateRef.current.counters.narrowed++;
            else stateRef.current.counters.allowed++;
          }
          survivors.push(a);
        } else {
          // burst fade
          a.burstAge += 1;
          const x = cx + Math.cos(a.angle) * a.stopR;
          const y = cy + Math.sin(a.angle) * a.stopR;
          const color = a.fate === 'block' || a.fate === 'identity-fail' ? '#b8291e'
            : a.fate === 'scrub' ? '#5a1a8a'
            : a.fate === 'narrow' ? '#8a5a00'
            : '#22592a';
          const alpha = Math.max(0, 1 - a.burstAge / 30);
          ctx.globalAlpha = alpha;
          ctx.strokeStyle = color;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(x, y, 4 + a.burstAge / 2, 0, Math.PI * 2);
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(x, y, 8 + a.burstAge, 0, Math.PI * 2);
          ctx.stroke();
          ctx.globalAlpha = 1;
          if (a.burstAge < 30) survivors.push(a);
        }
      }
      stateRef.current.arrows = survivors;

      rafRef.current = requestAnimationFrame(draw);
    };

    draw(performance.now());
    rafRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(rafRef.current);
      clearTimeout(t1);
      ro.disconnect();
    };
  }, [paused, intensity]);

  return <canvas ref={canvasRef} className="pipeline-canvas" />;
}

// ----- Live Ops Page ------------------------------------------

function LiveOpsPage({ approvals, onApprove, onReject, onTrace, toast }) {
  const tw = window.TWEAKS || {};
  const [paused, setPaused] = useSLO(!!tw.livePaused);
  const [intensity, setIntensity] = useSLO(tw.liveIntensity ?? 2);
  const [view, setView] = useSLO(tw.liveView || 'pipeline'); // 'pipeline' | 'moat'

  // Sync from tweaks panel: when the user changes the slider/toggle/radio
  // in the floating panel, mirror it into local state.
  React.useEffect(() => {
    const onTick = (e) => {
      const t = e.detail;
      setPaused(!!t.livePaused);
      setIntensity(t.liveIntensity ?? 2);
      setView(t.liveView || 'pipeline');
    };
    window.addEventListener('tweaksTick', onTick);
    return () => window.removeEventListener('tweaksTick', onTick);
  }, []);
  const [counters, setCounters] = useSLO({ rpm: 0, allow: 0, narrow: 0, deny: 0, scrub: 0, approval: 0 });
  const [traceEvent,    setTraceEvent]    = useSLO(null);
  const [detailApproval, setDetailApproval] = useSLO(null);

  const openApprovalDetail = (a) => {
    window.dispatchEvent(new CustomEvent('aa-pulse-lane', { detail: { fate: 'approval' } }));
    setDetailApproval(a);
  };

  const ps = window.TWEAKS?.pageState;
  if (ps === 'loading') return <window.LoadingState page="live" />;
  if (ps === 'empty')   return <window.EmptyState page="live" onCta={() => toast && toast('seed test traffic (mock)')} onSecondary={() => toast && toast('open 24h history (mock)')} />;
  if (ps === 'error')   return <window.ErrorState kind="live" onRetry={() => toast && toast('reconnecting…')} onSecondary={() => toast && toast('open runtime logs (mock)')} />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Live Ops <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14 }}>· 即時管線</span>
            <span className="live-pulse" style={{ marginLeft: 10 }}></span>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--ok)', fontWeight: 500 }}>
              {paused ? 'PAUSED' : 'LIVE'}
            </span>
          </h1>
          <div className="page-sub">
            Three-layer defense in real time. Particles flow left to right; blocked requests pulse red, approvals collect in the L2 pool.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => setIntensity(Math.max(0.5, intensity - 0.5))}>− slow</button>
          <button className="btn" onClick={() => setIntensity(Math.min(5, intensity + 0.5))}>+ fast</button>
          <button className="btn" onClick={() => setPaused(!paused)}>{paused ? '▸ resume' : '⏸ pause'}</button>
          <button className="btn btn-danger">page on-call</button>
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
        <span style={{ color: 'var(--ink-3)' }}>env: <b style={{ color: 'var(--ink)' }}>prod</b></span>
        <span className="fdivider" />
        <span><b style={{ color: 'var(--ink)' }}>{counters.rpm}</b> req/min</span>
        <span className="fdivider" />
        <span style={{ color: 'var(--ok)' }}>● {counters.allow} allowed</span>
        <span style={{ color: 'var(--warn)' }}>● {counters.narrow} narrowed</span>
        <span style={{ color: 'var(--scrub)' }}>● {counters.scrub} scrubbed</span>
        <span style={{ color: 'var(--info)' }}>● {counters.approval} await</span>
        <span style={{ color: 'var(--danger)' }}>● {counters.deny} denied</span>
        <span style={{ marginLeft: 'auto', color: 'var(--ink-4)' }}>intensity ×{intensity.toFixed(1)} · {window.AGENTS.length} active agents</span>
      </div>

      <div className="live-grid">
        <div className="live-pane">
          <div className="live-pane-head">
            <div style={{ display: 'flex', gap: 0, alignItems: 'center' }}>
              <div className="live-pane-title" style={{ marginRight: 12 }}>{view === 'pipeline' ? '▤ traffic pipeline · live particles' : '◎ castle moat · live attacks'}</div>
              <div style={{ display: 'flex', border: '1px solid var(--line-2)', borderRadius: 2, overflow: 'hidden' }}>
                <button
                  className="btn btn-sm"
                  style={{
                    borderRadius: 0,
                    border: 'none',
                    height: 22,
                    background: view === 'pipeline' ? 'var(--ink)' : 'transparent',
                    color: view === 'pipeline' ? 'var(--paper-2)' : 'var(--ink-3)',
                  }}
                  onClick={() => setView('pipeline')}
                >▤ pipeline</button>
                <button
                  className="btn btn-sm"
                  style={{
                    borderRadius: 0,
                    border: 'none',
                    borderLeft: '1px solid var(--line-2)',
                    height: 22,
                    background: view === 'moat' ? 'var(--ink)' : 'transparent',
                    color: view === 'moat' ? 'var(--paper-2)' : 'var(--ink-3)',
                  }}
                  onClick={() => setView('moat')}
                >◎ castle moat</button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <span className="chip" style={{ fontSize: 9 }}>● allow</span>
              <span className="chip chip-warn" style={{ fontSize: 9 }}>● narrow</span>
              <span className="chip chip-info" style={{ fontSize: 9 }}>● approval</span>
              <span className="chip chip-scrub" style={{ fontSize: 9 }}>● scrub</span>
              <span className="chip chip-danger" style={{ fontSize: 9 }}>● deny</span>
            </div>
          </div>
          <div className="pipeline-wrap">
            {view === 'pipeline'
              ? <PipelineCanvas paused={paused} intensity={intensity} onCounters={setCounters} onApprovalPoolClick={() => approvals[0] && openApprovalDetail(approvals[0])} />
              : <CastleMoat paused={paused} intensity={intensity} />}
          </div>
        </div>

        <div className="live-pane">
          <div className="live-pane-head">
            <div className="live-pane-title">▶ tail -f · event stream</div>
            <div style={{ display: 'flex', gap: 4 }}>
              <button className="btn btn-sm">filter</button>
              <button className="btn btn-sm">⏏ export</button>
            </div>
          </div>
          <div className="live-pane-body" style={{ padding: 0 }}>
            <EventStream paused={paused} onLineClick={setTraceEvent} />
          </div>
        </div>

        <div className="live-pane">
          <div className="live-pane-head">
            <div className="live-pane-title">⚑ approval queue</div>
            <span className="chip chip-danger" style={{ fontSize: 9 }}>{approvals.length} waiting</span>
          </div>
          <div className="live-pane-body">
            <ApprovalQueue
              approvals={approvals}
              onApprove={(a) => { onApprove(a); toast(`Approved ${a.id} · ${a.agent} · ${a.verb}`); }}
              onReject={(a) => { onReject(a); toast(`Rejected ${a.id}`); }}
              onTrace={(a) => openApprovalDetail(a)}
              onCardClick={(a) => openApprovalDetail(a)}
            />
          </div>
        </div>
      </div>

      {traceEvent && (
        <window.TraceDrawer
          event={traceEvent}
          onClose={() => setTraceEvent(null)}
        />
      )}
      {detailApproval && (
        <window.ApprovalDetailDrawer
          approval={detailApproval}
          onClose={() => setDetailApproval(null)}
          onApprove={(a) => { onApprove(a); setDetailApproval(null); }}
          onReject={(a)  => { onReject(a);  setDetailApproval(null); }}
          toast={toast}
        />
      )}
    </>
  );
}

// ----- Bell drawer (top bar shortcut) -------------------------

function BellDrawer({ approvals, onClose, onApprove, onReject, goLive }) {
  return (
    <>
      <div className="scrim" style={{ background: 'rgba(0,0,0,0.15)' }} onClick={onClose}>
        <div className="bell-drawer" onClick={(e) => e.stopPropagation()}>
          <div className="bell-head">
            <div>
              <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--ink-4)' }}>top-bar shortcut</div>
              <div style={{ fontWeight: 600, fontSize: 15, marginTop: 2 }}>
                Approvals queue <span style={{ color: 'var(--ink-4)', fontFamily: 'JetBrains Mono', fontSize: 12, marginLeft: 6 }}>{approvals.length} pending</span>
              </div>
            </div>
            <button className="btn btn-ghost" onClick={onClose}>✕</button>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            <ApprovalQueue
              approvals={approvals.slice(0, 5)}
              onApprove={onApprove}
              onReject={onReject}
              onTrace={() => {}}
              compact
            />
            {approvals.length > 5 && (
              <div style={{ padding: '8px 14px', fontSize: 11, color: 'var(--ink-3)', textAlign: 'center' }}>
                + {approvals.length - 5} more
              </div>
            )}
          </div>
          <div className="bell-foot">
            <a onClick={() => { onClose(); goLive(); }}>open Live Ops →</a>
          </div>
        </div>
      </div>
    </>
  );
}

Object.assign(window, { LiveOpsPage, BellDrawer });
