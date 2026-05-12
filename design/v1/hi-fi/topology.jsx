/* global React */
const {
  useState: useTopoSt, useMemo: useTopoMemo,
  useRef: useTopoRef,  useEffect: useTopoEff,
} = React;

// ─── Layout constants ──────────────────────────────────────────────────────
const TL_NW = 148, TL_NH = 56;
const TL_SGAP = 14, TL_LGAP = 70;
const TL_HDR = 34, TL_PT = 18, TL_PS = 20, TL_PB = 22;
const TL_TGX = 58, TL_TGY = 58, TL_CPAD = 44;
const TL_COLS = 3;

const TOPO_EC = {
  delegates_to: { color: '#374151', dash: null,  w: 2,   label: 'delegates_to' },
  calls:        { color: '#1d4ed8', dash: '7 3', w: 1.5, label: 'calls'        },
  reads:        { color: '#166534', dash: '3 4', w: 1.5, label: 'reads'        },
  writes:       { color: '#b45309', dash: '3 4', w: 1.5, label: 'writes'       },
  approves:     { color: '#7c3aed', dash: '8 3', w: 1.5, label: 'approves'     },
  messages:     { color: '#6b7280', dash: '2 5', w: 1,   label: 'messages'     },
};

// ─── Cycle detection (JS port of aa-core/src/topology/cycle.rs — Tarjan SCC) ─
function topoDetectCycles(edges) {
  const adj = {}, nodes = new Set();
  edges.forEach(e => {
    nodes.add(e.source); nodes.add(e.target);
    if (!adj[e.source]) adj[e.source] = [];
    adj[e.source].push(e.target);
  });

  let ctr = 0;
  const idxMap = {}, low = {}, stk = [], onStk = new Set(), cycles = [];

  function sc(v) {
    idxMap[v] = low[v] = ctr++;
    stk.push(v); onStk.add(v);
    for (const w of (adj[v] || [])) {
      if (!(w in idxMap)) { sc(w); low[v] = Math.min(low[v], low[w]); }
      else if (onStk.has(w)) { low[v] = Math.min(low[v], idxMap[w]); }
    }
    if (low[v] === idxMap[v]) {
      const scc = [];
      let w; do { w = stk.pop(); onStk.delete(w); scc.push(w); } while (w !== v);
      if (scc.length > 1 || (adj[v] || []).includes(v)) cycles.push(new Set(scc));
    }
  }
  for (const n of nodes) if (!(n in idxMap)) sc(n);
  return cycles; // array of Set<nodeId>
}

// ─── Layout computation ────────────────────────────────────────────────────
function topoLayout(nodes) {
  const TEAM_ORDER = window.TOPO_TEAMS.map(t => t.id);
  const byTeam = {};
  nodes.forEach(n => {
    if (!byTeam[n.team]) byTeam[n.team] = { byParent: {}, roots: [] };
    const td = byTeam[n.team];
    if (n.parentId) { if (!td.byParent[n.parentId]) td.byParent[n.parentId] = []; td.byParent[n.parentId].push(n); }
    else td.roots.push(n);
  });

  // BFS per team to assign levels
  const teamLvls = {};
  TEAM_ORDER.forEach(tid => {
    const td = byTeam[tid] || { roots: [], byParent: {} };
    const lvls = {};
    const q = td.roots.map(r => ({ n: r, lv: 0 }));
    while (q.length) {
      const { n, lv } = q.shift();
      if (!lvls[lv]) lvls[lv] = [];
      lvls[lv].push(n);
      (td.byParent[n.id] || []).forEach(c => q.push({ n: c, lv: lv + 1 }));
    }
    teamLvls[tid] = lvls;
  });

  // Team box dimensions
  const teamDims = {};
  TEAM_ORDER.forEach(tid => {
    const lvls = teamLvls[tid] || {};
    const maxSib = Object.values(lvls).reduce((m, l) => Math.max(m, l.length), 0);
    const maxLv  = Object.keys(lvls).length ? Math.max(...Object.keys(lvls).map(Number)) : -1;
    const w = Math.max(200, TL_PS * 2 + Math.max(1, maxSib) * TL_NW + (Math.max(1, maxSib) - 1) * TL_SGAP);
    const h = maxLv < 0 ? 80 : TL_HDR + TL_PT + (maxLv + 1) * (TL_NH + TL_LGAP) - TL_LGAP + TL_PB;
    teamDims[tid] = { w, h };
  });

  // Normalize per-column width and per-row height
  const colW = [0, 0, 0]; const rowH = {};
  TEAM_ORDER.forEach((tid, i) => {
    const col = i % TL_COLS, row = Math.floor(i / TL_COLS);
    colW[col] = Math.max(colW[col], teamDims[tid].w);
    rowH[row] = Math.max(rowH[row] || 0, teamDims[tid].h);
  });

  // Column / row start offsets
  const colX = [TL_CPAD];
  for (let c = 1; c < TL_COLS; c++) colX[c] = colX[c - 1] + colW[c - 1] + TL_TGX;
  const maxRow = Math.floor((TEAM_ORDER.length - 1) / TL_COLS);
  const rowY = [TL_CPAD];
  for (let r = 1; r <= maxRow; r++) rowY[r] = rowY[r - 1] + (rowH[r - 1] || 0) + TL_TGY;

  // Absolute team boxes
  const teamBoxes = {};
  TEAM_ORDER.forEach((tid, i) => {
    const col = i % TL_COLS, row = Math.floor(i / TL_COLS);
    teamBoxes[tid] = { x: colX[col], y: rowY[row], w: colW[col], h: teamDims[tid].h, col, row };
  });

  // Absolute node positions
  const nodePos = {};
  TEAM_ORDER.forEach(tid => {
    const box = teamBoxes[tid];
    if (!box) return;
    Object.entries(teamLvls[tid] || {}).forEach(([lvStr, lvNodes]) => {
      const lv = parseInt(lvStr);
      const relY = TL_HDR + TL_PT + lv * (TL_NH + TL_LGAP);
      const totW = lvNodes.length * TL_NW + (lvNodes.length - 1) * TL_SGAP;
      const sx   = (box.w - totW) / 2;
      lvNodes.forEach((nd, si) => {
        const rx = sx + si * (TL_NW + TL_SGAP);
        nodePos[nd.id] = {
          x: box.x + rx,  y: box.y + relY,
          cx:   box.x + rx + TL_NW / 2,  cy: box.y + relY + TL_NH / 2,
          topX: box.x + rx + TL_NW / 2,  topY: box.y + relY,
          botX: box.x + rx + TL_NW / 2,  botY: box.y + relY + TL_NH,
        };
      });
    });
  });

  const canvasW = colX[TL_COLS - 1] + colW[TL_COLS - 1] + TL_CPAD;
  const canvasH = rowY[maxRow] + (rowH[maxRow] || 0) + TL_CPAD;
  return { teamBoxes, nodePos, canvasW, canvasH };
}

// ─── Live simulation events (mirrors WebSocket topology feed) ─────────────
const LIVE_SIM = [
  { type: 'trust', nodeId: 'analytics-runner',  delta: -2, msg: 'analytics-runner trust drift −2' },
  { type: 'trust', nodeId: 'research-bot-04',   delta: -1, msg: 'research-bot-04 trust drift −1' },
  { type: 'edge',  edge: { id: 'lv1', source: 'incident-responder', target: 'docs-summarizer', type: 'reads', crossTeam: true }, msg: 'new edge: incident-responder → docs-summarizer' },
  { type: 'trust', nodeId: 'support-triage',    delta: +1, msg: 'support-triage trust +1' },
  { type: 'mode',  nodeId: 'etl-worker', mode: 'shadow',  msg: 'etl-worker → shadow mode' },
  { type: 'trust', nodeId: 'pii-scanner',       delta: -3, msg: 'pii-scanner trust drift −3' },
  { type: 'mode',  nodeId: 'etl-worker', mode: 'enforce', msg: 'etl-worker → enforce restored' },
  { type: 'trust', nodeId: 'infra-ops-bot',     delta: +2, msg: 'infra-ops-bot trust +2' },
  { type: 'trust', nodeId: 'etl-worker',        delta: -4, msg: 'etl-worker trust drift −4' },
];

// ─── SVG: Arrow marker defs ───────────────────────────────────────────────
function TopoArrowDefs() {
  return (
    <defs>
      {Object.entries(TOPO_EC).map(([t, c]) => (
        <marker key={t} id={`ta-${t}`} markerWidth="7" markerHeight="7" refX="5.5" refY="3" orient="auto">
          <path d="M0 0 L0 6 L7 3z" fill={c.color} />
        </marker>
      ))}
      <marker id="ta-cycle" markerWidth="7" markerHeight="7" refX="5.5" refY="3" orient="auto">
        <path d="M0 0 L0 6 L7 3z" fill="#b8291e" />
      </marker>
    </defs>
  );
}

// ─── SVG: Team group box ──────────────────────────────────────────────────
function TopoTeamBox({ team, box, count, rootCount, isSel, onClick }) {
  const isOrphan = team.id === '__orphan__';
  return (
    <g onClick={onClick} style={{ cursor: 'pointer' }}>
      <rect x={box.x} y={box.y} width={box.w} height={box.h} rx={5}
        fill={isOrphan ? 'rgba(184,41,30,0.03)' : isSel ? 'rgba(80,80,80,0.07)' : 'rgba(80,80,80,0.025)'}
        stroke={isOrphan ? '#b8291e' : isSel ? '#5a5a5a' : '#d8d4c7'}
        strokeWidth={isSel ? 1.5 : 1}
        strokeDasharray={isOrphan ? '3 3' : isSel ? undefined : '4 3'}
      />
      <rect x={box.x} y={box.y} width={box.w} height={TL_HDR} rx={5}
        fill={isOrphan ? 'rgba(184,41,30,0.05)' : 'rgba(80,80,80,0.04)'} />
      <rect x={box.x} y={box.y + TL_HDR - 1} width={box.w} height={1} fill="#d8d4c7" opacity={0.7} />
      <text x={box.x + 11} y={box.y + 22}
        fontFamily="JetBrains Mono" fontSize={10} fontWeight={700}
        fill={isOrphan ? '#b8291e' : '#5a5a5a'}>
        {isOrphan ? '⚠ ' : ''}{team.label}
      </text>
      <text x={box.x + box.w - 10} y={box.y + 22}
        fontFamily="JetBrains Mono" fontSize={9} fill="#b8b6ae" textAnchor="end">
        {count} agent{count !== 1 ? 's' : ''}{rootCount > 1 ? ` · ${rootCount} roots` : ''}
      </text>
    </g>
  );
}

// ─── SVG: Node box ────────────────────────────────────────────────────────
function TopoNodeEl({ node, pos, isSel, isLit, inCycle, isNew, crossTeamBadge, onClick }) {
  const statusC = node.status === 'active' ? '#22592a' : node.status === 'suspended' ? '#b8291e' : '#8a5a00';
  const dimmed  = isLit === false;
  return (
    <g transform={`translate(${pos.x},${pos.y})`} opacity={dimmed ? 0.2 : 1}
      onClick={e => { e.stopPropagation(); onClick(node); }} style={{ cursor: 'pointer' }}>
      {/* shadow */}
      <rect x={1.5} y={2} width={TL_NW} height={TL_NH} rx={4} fill="rgba(0,0,0,0.07)" />
      {/* background */}
      <rect x={0} y={0} width={TL_NW} height={TL_NH} rx={4}
        fill={isSel ? '#eeece5' : '#f5f4f0'}
        stroke={inCycle ? '#b8291e' : isSel ? '#2a2a2a' : node.flagged ? '#b8291e' : '#d8d4c7'}
        strokeWidth={inCycle ? 2 : isSel ? 1.8 : 1}
        strokeDasharray={inCycle ? '4 2' : undefined}
      />
      {/* live-update pulse ring */}
      {isNew && (
        <rect x={-2} y={-2} width={TL_NW + 4} height={TL_NH + 4} rx={5}
          fill="none" stroke="#1d4ed8" strokeWidth={1.5} opacity={0.75}
          style={{ animation: 'topo-flash 2.2s ease-out forwards' }} />
      )}
      {/* status stripe */}
      <rect x={0} y={0} width={3} height={TL_NH} rx={2} fill={statusC} />
      {/* depth/root badge */}
      {node.depth === 0
        ? <text x={TL_NW - 6} y={12} fontFamily="JetBrains Mono" fontSize={8} fill="#1d3a7a" textAnchor="end" opacity={0.85}>root</text>
        : <text x={TL_NW - 6} y={12} fontFamily="JetBrains Mono" fontSize={8} fill="#b8b6ae" textAnchor="end">L{node.depth}</text>}
      {/* cycle warning badge */}
      {inCycle && (
        <g>
          <rect x={TL_NW - 38} y={TL_NH - 15} width={36} height={13} rx={2} fill="#b8291e" />
          <text x={TL_NW - 20} y={TL_NH - 5} fontFamily="JetBrains Mono" fontSize={7} fill="white" textAnchor="middle" fontWeight={700}>⟳ CYCLE</text>
        </g>
      )}
      {/* name */}
      <text x={11} y={22} fontFamily="JetBrains Mono" fontSize={10} fontWeight={700}
        fill={node.flagged ? '#b8291e' : node.status === 'suspended' ? '#8a8a8a' : '#0e0e0e'}>
        {node.flagged ? '⚑ ' : ''}{node.name.length > 15 ? node.name.slice(0, 14) + '…' : node.name}
      </text>
      {/* framework */}
      <text x={11} y={35} fontFamily="JetBrains Mono" fontSize={8.5} fill="#8a8a8a">{node.framework}</text>
      {/* mode + trust (+ cross-team badge when filtered) */}
      <text x={11} y={49} fontFamily="JetBrains Mono" fontSize={8} fill={node.mode === 'enforce' ? '#22592a' : '#8a5a00'}>
        {node.mode === 'enforce' ? '●' : '◐'} {node.mode} · {node.trust}
        {crossTeamBadge > 0 ? `  ⇆${crossTeamBadge}` : ''}
      </text>
    </g>
  );
}

// ─── SVG: Edge path ───────────────────────────────────────────────────────
function TopoEdgeEl({ edge, fpos, tpos, dimmed, isCycle, isNew }) {
  if (!fpos || !tpos) return null;
  const cfg   = TOPO_EC[edge.type] || TOPO_EC.calls;
  const color = isCycle ? '#b8291e' : cfg.color;
  const dash  = isCycle ? '5 3' : (cfg.dash || undefined);
  const opac  = dimmed ? 0.07 : isCycle ? 0.88 : edge.crossTeam ? 0.48 : 0.72;
  let d;
  if (edge.crossTeam) {
    const fx = fpos.cx, fy = fpos.topY, tx = tpos.cx, ty = tpos.topY;
    const ctrlY = Math.min(fy, ty) - 55 - Math.abs(fx - tx) * 0.07;
    d = `M${fx} ${fy} C${fx} ${ctrlY} ${tx} ${ctrlY} ${tx} ${ty}`;
  } else {
    d = `M${fpos.botX} ${fpos.botY} L${tpos.topX} ${tpos.topY}`;
  }
  return (
    <path d={d} fill="none" stroke={color} strokeWidth={isCycle ? 2 : cfg.w}
      strokeDasharray={dash} opacity={opac}
      markerEnd={isCycle ? 'url(#ta-cycle)' : `url(#ta-${edge.type})`}
      style={isNew ? { animation: 'topo-flash 3s ease-out forwards' } : undefined}
    />
  );
}

// ─── Cascade diff modal ───────────────────────────────────────────────────
function CascadeDiffModal({ sourceNode, descendants, onApply, onClose }) {
  const capSum = nd => {
    const ag = window.AGENTS?.find(a => a.id === nd.id);
    if (!ag) return { allow: 3, narrow: 2, deny: 1 }; // fallback for new nodes
    const vals = Object.values(ag.caps || {}).flatMap(c => Object.values(c).filter(v => v !== 'na'));
    return {
      allow:  vals.filter(v => v === 'allow').length,
      narrow: vals.filter(v => v === 'narrow').length,
      deny:   vals.filter(v => v === 'deny' || v === 'approval').length,
    };
  };
  return (
    <div className="scrim scrim-center" onClick={onClose} style={{ zIndex: 80 }}>
      <div className="modal" style={{ maxWidth: 540 }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div style={{ fontWeight: 700, fontSize: 14 }}>Policy Cascade Preview</div>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--ink-4)', marginTop: 2 }}>
              P-066 applied to {sourceNode.name} + {descendants.length} sub-agent{descendants.length !== 1 ? 's' : ''}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 16, color: 'var(--ink-4)' }}>✕</button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginBottom: 10 }}>Agents affected by cascade</div>
          {descendants.map(nd => {
            const { allow, narrow } = capSum(nd);
            return (
              <div key={nd.id} style={{ background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 3, padding: '10px 12px', marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 7, alignItems: 'center' }}>
                  <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 700 }}>{nd.name}</span>
                  <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-4)' }}>L{nd.depth} · {nd.team}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6 }}>
                  <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 2, padding: '6px 8px' }}>
                    <div style={{ fontFamily: 'JetBrains Mono', fontSize: 8, color: 'var(--ink-4)', marginBottom: 3 }}>current</div>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ok)' }}>{allow} allow</span>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-4)' }}> · </span>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--warn)' }}>{narrow} narrow</span>
                  </div>
                  <div style={{ background: '#fff9ed', border: '1px solid var(--warn)', borderRadius: 2, padding: '6px 8px' }}>
                    <div style={{ fontFamily: 'JetBrains Mono', fontSize: 8, color: 'var(--warn)', marginBottom: 3 }}>after cascade</div>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ok)' }}>{Math.max(0, allow - 1)} allow</span>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-4)' }}> · </span>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--warn)' }}>{narrow + 1} narrow</span>
                  </div>
                  <div style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 2, padding: '6px 8px' }}>
                    <div style={{ fontFamily: 'JetBrains Mono', fontSize: 8, color: 'var(--ink-4)', marginBottom: 3 }}>strategy</div>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-3)' }}>most_restrictive</span>
                  </div>
                </div>
              </div>
            );
          })}
          {/* Backend API preview */}
          <div style={{ marginTop: 12, background: '#0e0e0e', borderRadius: 3, padding: '10px 12px', fontFamily: 'JetBrains Mono', fontSize: 10, color: '#9ca38f', lineHeight: 1.7, whiteSpace: 'pre' }}>
            <span style={{ color: '#6a6a60' }}>{'POST /api/v1/policies/cascade\n'}</span>
            {`{ "policy_id": "P-066",\n  "root_agent": "${sourceNode.id}",\n  "cascade": true,\n  "strategy": "most_restrictive" }`}
          </div>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-danger" onClick={onApply}>Apply P-066 cascade →</button>
        </div>
      </div>
    </div>
  );
}

// ─── Main canvas with pan + zoom ──────────────────────────────────────────
function TopoCanvas({ layout, nodes, liveEdges, selId, selTeam, visEdges, showCross, onNode, onTeam, cycleNodeIds, cycleEdgeIds, recentIds, filterTeam }) {
  const [pan, setPan]         = useTopoSt({ x: 0, y: 0 });
  const [zoom, setZoom]       = useTopoSt(1);
  const [dragging, setDragging] = useTopoSt(false);
  const dragRef = useTopoRef(null);
  const svgRef  = useTopoRef(null);

  const { teamBoxes, nodePos } = layout;
  const teams   = window.TOPO_TEAMS;
  const nodeIds = new Set(nodes.map(n => n.id));

  const teamCnt = {}, teamRootCnt = {};
  nodes.forEach(n => {
    teamCnt[n.team] = (teamCnt[n.team] || 0) + 1;
    if (!n.parentId) teamRootCnt[n.team] = (teamRootCnt[n.team] || 0) + 1;
  });

  // Cross-team edge count per node (for badge when team is filtered)
  const crossCnt = {};
  liveEdges.filter(e => e.crossTeam).forEach(e => {
    crossCnt[e.source] = (crossCnt[e.source] || 0) + 1;
    crossCnt[e.target] = (crossCnt[e.target] || 0) + 1;
  });

  const visEdgeList = liveEdges.filter(e =>
    visEdges.has(e.type) &&
    (showCross || !e.crossTeam) &&
    nodePos[e.source] && nodePos[e.target] &&
    nodeIds.has(e.source) && nodeIds.has(e.target)
  );

  const connectedIds = useTopoMemo(() => {
    if (!selId) return null;
    const ids = new Set([selId]);
    liveEdges.forEach(e => { if (e.source === selId) ids.add(e.target); if (e.target === selId) ids.add(e.source); });
    return ids;
  }, [selId, liveEdges]);

  const handleDown = e => {
    if (e.target.closest('[data-nid]') || e.target.closest('[data-tid]')) return;
    setDragging(true);
    dragRef.current = { mx: e.clientX, my: e.clientY, px: pan.x, py: pan.y };
  };
  const handleMove = e => {
    if (!dragging || !dragRef.current) return;
    const { mx, my, px, py } = dragRef.current;
    setPan({ x: px + e.clientX - mx, y: py + e.clientY - my });
  };
  const handleUp = () => { setDragging(false); dragRef.current = null; };

  useTopoEff(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = e => { e.preventDefault(); setZoom(z => Math.max(0.25, Math.min(2.5, z * (e.deltaY > 0 ? 0.91 : 1.09)))); };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      <svg ref={svgRef} width="100%" height="100%"
        style={{ cursor: dragging ? 'grabbing' : 'grab', userSelect: 'none', background: '#f5f4f0' }}
        onMouseDown={handleDown} onMouseMove={handleMove} onMouseUp={handleUp} onMouseLeave={handleUp}
        onClick={e => { if (!e.target.closest('[data-nid]') && !e.target.closest('[data-tid]')) { onNode(null); onTeam(null); } }}>
        <TopoArrowDefs />
        <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
          {/* Team boxes */}
          {teams.map(t => {
            const box = teamBoxes[t.id];
            if (!box || !teamCnt[t.id]) return null;
            return (
              <g key={t.id} data-tid={t.id} onClick={e => { e.stopPropagation(); onTeam(t.id); onNode(null); }}>
                <TopoTeamBox team={t} box={box} count={teamCnt[t.id] || 0} rootCount={teamRootCnt[t.id] || 0}
                  isSel={selTeam === t.id && !selId} onClick={() => {}} />
              </g>
            );
          })}

          {/* Intra-team edges (behind nodes) */}
          {visEdgeList.filter(e => !e.crossTeam).map(e => {
            const dimmed  = connectedIds ? !connectedIds.has(e.source) && !connectedIds.has(e.target) : false;
            const isCycle = cycleEdgeIds ? cycleEdgeIds.has(e.id) : false;
            return <TopoEdgeEl key={e.id} edge={e} fpos={nodePos[e.source]} tpos={nodePos[e.target]} dimmed={dimmed} isCycle={isCycle} isNew={recentIds.has(e.id)} />;
          })}

          {/* Nodes */}
          {nodes.map(nd => {
            const pos = nodePos[nd.id];
            if (!pos) return null;
            const isLit = connectedIds ? connectedIds.has(nd.id) : true;
            const inCyc = cycleNodeIds ? cycleNodeIds.has(nd.id) : false;
            return (
              <g key={nd.id} data-nid={nd.id}>
                <TopoNodeEl node={nd} pos={pos}
                  isSel={selId === nd.id} isLit={selId ? isLit : true}
                  inCycle={inCyc} isNew={recentIds.has(nd.id)}
                  crossTeamBadge={filterTeam !== 'all' ? (crossCnt[nd.id] || 0) : 0}
                  onClick={onNode} />
              </g>
            );
          })}

          {/* Cross-team edges (on top) */}
          {showCross && visEdgeList.filter(e => e.crossTeam).map(e => {
            const dimmed  = connectedIds ? !connectedIds.has(e.source) && !connectedIds.has(e.target) : false;
            const isCycle = cycleEdgeIds ? cycleEdgeIds.has(e.id) : false;
            return <TopoEdgeEl key={e.id} edge={e} fpos={nodePos[e.source]} tpos={nodePos[e.target]} dimmed={dimmed} isCycle={isCycle} isNew={recentIds.has(e.id)} />;
          })}
        </g>
      </svg>

      {/* Zoom controls */}
      <div style={{ position: 'absolute', bottom: 14, right: 14, display: 'flex', flexDirection: 'column', gap: 3 }}>
        {[['＋', () => setZoom(z => Math.min(2.5, +(z * 1.2).toFixed(2)))],
          ['－', () => setZoom(z => Math.max(0.25, +(z * 0.8).toFixed(2)))],
          ['⤢',  () => { setPan({ x: 0, y: 0 }); setZoom(1); }],
        ].map(([lbl, fn]) => (
          <button key={lbl} onClick={fn}
            style={{ width: 28, height: 28, display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: 'JetBrains Mono', fontSize: 13, border: '1px solid #d8d4c7',
              background: '#ffffff', borderRadius: 3, cursor: 'pointer', color: '#5a5a5a' }}>
            {lbl}
          </button>
        ))}
        <div style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: '#b8b6ae', textAlign: 'center', marginTop: 2 }}>
          {Math.round(zoom * 100)}%
        </div>
      </div>
    </div>
  );
}

// ─── Right panel: Node detail ─────────────────────────────────────────────
function TopoNodePanel({ node, allNodes, liveEdges, onClose, goPolicy, toast, inCycle, cycleNodeIds }) {
  const lineage = [];
  let cur = node;
  while (cur) { lineage.unshift(cur); cur = allNodes.find(n => n.id === cur.parentId); }
  const children    = allNodes.filter(n => n.parentId === node.id);
  const getAllDesc   = id => { const d = allNodes.filter(n => n.parentId === id); return [...d, ...d.flatMap(c => getAllDesc(c.id))]; };
  const descendants = getAllDesc(node.id);
  const crossEdges  = liveEdges.filter(e => e.crossTeam && (e.source === node.id || e.target === node.id));

  const [cascade,  setCascade]  = useTopoSt(true);
  const [showDiff, setShowDiff] = useTopoSt(false);
  const statusC = node.status === 'active' ? 'var(--ok)' : node.status === 'suspended' ? 'var(--danger)' : 'var(--warn)';
  const SH = { fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginTop: 14, marginBottom: 7 };
  const parentNode = allNodes.find(n => n.id === node.parentId);

  return (
    <>
      {showDiff && descendants.length > 0 && (
        <CascadeDiffModal
          sourceNode={node} descendants={descendants}
          onApply={() => { setShowDiff(false); toast(`✓ P-066 cascade applied: ${node.name} + ${descendants.length} sub-agents (mock)`); }}
          onClose={() => setShowDiff(false)}
        />
      )}
      <div style={{ width: 276, background: 'var(--paper-2)', borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
        <div style={{ padding: '11px 14px 9px', borderBottom: '1px solid var(--line)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 700, color: node.flagged ? 'var(--danger)' : 'var(--ink)' }}>
              {node.flagged ? '⚑ ' : ''}{inCycle ? '⟳ ' : ''}{node.name}
            </div>
            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-4)', marginTop: 3, display: 'flex', gap: 5 }}>
              <span>{node.team}</span><span>·</span><span>L{node.depth}</span><span>·</span><span>{node.framework}</span>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ink-4)', fontSize: 15, padding: '2px 4px', lineHeight: 1 }}>✕</button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '0 14px 16px' }}>
          {/* Cycle alert */}
          {inCycle && (
            <div style={{ marginTop: 10, background: '#f6dad6', border: '1px solid #b8291e', borderRadius: 3, padding: '7px 10px', fontFamily: 'JetBrains Mono', fontSize: 9, color: '#b8291e' }}>
              <div style={{ fontWeight: 700, marginBottom: 2 }}>⟳ Part of a delegation cycle</div>
              <div style={{ opacity: 0.85 }}>
                {[...cycleNodeIds].map(id => allNodes.find(n => n.id === id)?.name || id).join(' → ')} → …
              </div>
              <div style={{ marginTop: 5, fontSize: 8.5, opacity: 0.7 }}>Risk: potential privilege escalation loop. Review and break the cycle.</div>
            </div>
          )}

          {/* Status row */}
          <div style={{ display: 'flex', gap: 6, marginTop: 11, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: statusC, fontWeight: 600 }}>● {node.status}</span>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: node.mode === 'enforce' ? 'var(--ok)' : 'var(--warn)', fontWeight: 600 }}>
              {node.mode === 'enforce' ? '●' : '◐'} {node.mode}
            </span>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, fontWeight: 600, color: node.trust < 50 ? 'var(--danger)' : node.trust < 75 ? 'var(--warn)' : 'var(--ok)' }}>
              trust {node.trust}
            </span>
          </div>

          {/* Policy inheritance chain */}
          <div style={SH}>Policy Inheritance</div>
          <div style={{ border: '1px solid var(--line)', borderRadius: 3, overflow: 'hidden', fontSize: 10 }}>
            {[
              { label: '① org baseline',                    value: 'P-001 default-deny',        color: 'var(--ink-3)' },
              { label: `② team (${node.team})`,             value: 'no team policy',             color: 'var(--ink-4)' },
              { label: `③ parent (${parentNode?.name || 'none'})`, value: parentNode ? 'no override' : '—', color: 'var(--ink-4)' },
              { label: '④ this agent',                      value: node.flagged ? '⚠ P-066 proposed' : 'no override', color: node.flagged ? 'var(--danger)' : 'var(--ink-4)' },
            ].map((row, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 9px', borderBottom: '1px solid var(--line)', background: i % 2 ? 'var(--paper-2)' : 'var(--paper)' }}>
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: 8.5, color: 'var(--ink-3)' }}>{row.label}</span>
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: 8.5, color: row.color, fontWeight: 600 }}>{row.value}</span>
              </div>
            ))}
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 9px', background: 'var(--paper-3)' }}>
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 8.5, fontWeight: 700, color: 'var(--ink-2)' }}>→ effective</span>
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 8.5, fontWeight: 700, color: node.flagged ? 'var(--danger)' : 'var(--ok)' }}>
                {node.flagged ? 'narrowed (pending)' : 'baseline'}
              </span>
            </div>
          </div>

          {/* Lineage */}
          <div style={SH}>Lineage</div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, lineHeight: 1.95, background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 3, padding: '8px 10px' }}>
            {lineage.map((n, i) => (
              <div key={n.id} style={{ paddingLeft: i * 10, color: n.id === node.id ? 'var(--ink)' : 'var(--ink-3)', fontWeight: n.id === node.id ? 700 : 400 }}>
                {i > 0 ? '└ ' : ''}{n.name}{n.id === node.id && <span style={{ color: 'var(--ink-5)', fontSize: 8, marginLeft: 5 }}>← here</span>}
              </div>
            ))}
            {children.map(c => (
              <div key={c.id} style={{ paddingLeft: lineage.length * 10, color: 'var(--ink-4)' }}>└ {c.name}</div>
            ))}
          </div>

          {/* Cross-team edges */}
          {crossEdges.length > 0 && (
            <>
              <div style={SH}>Cross-team edges</div>
              {crossEdges.map(e => {
                const cfg  = TOPO_EC[e.type] || TOPO_EC.calls;
                const peer = window.TOPO_NODES.find(n => n.id === (e.source === node.id ? e.target : e.source));
                return (
                  <div key={e.id} style={{ fontFamily: 'JetBrains Mono', fontSize: 9, display: 'flex', gap: 6, alignItems: 'center', marginBottom: 5 }}>
                    <span style={{ color: cfg.color, fontWeight: 800 }}>{e.type}</span>
                    <span style={{ color: 'var(--ink-4)' }}>{e.source === node.id ? '→' : '←'}</span>
                    <span style={{ color: 'var(--ink-3)' }}>{peer?.name || '—'}</span>
                    <span style={{ color: 'var(--ink-5)' }}>({peer?.team})</span>
                  </div>
                );
              })}
            </>
          )}

          {/* Policy controls */}
          <div style={SH}>Policy Controls</div>
          <div style={{ background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 4, padding: 11 }}>
            <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 9, color: 'var(--ink-2)' }}>Apply restriction</div>
            <button className="btn btn-sm" style={{ width: '100%', textAlign: 'left', marginBottom: 6 }}
              onClick={() => goPolicy && goPolicy('P-066')}>
              ⚖ Restrict this agent only →
            </button>
            {descendants.length > 0 && (
              <div style={{ marginTop: 8, paddingTop: 9, borderTop: '1px dashed var(--line)' }}>
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 7, cursor: 'pointer', fontSize: 11 }}>
                  <input type="checkbox" checked={cascade} onChange={e => setCascade(e.target.checked)} style={{ marginTop: 1 }} />
                  <span>
                    <span style={{ fontWeight: 600 }}>Cascade to {descendants.length} sub-agent{descendants.length !== 1 ? 's' : ''}</span>
                    <div style={{ fontFamily: 'JetBrains Mono', fontSize: 8.5, color: 'var(--ink-4)', marginTop: 3, lineHeight: 1.5 }}>
                      Strategy: most_restrictive · enforced at runtime via evaluators.rs
                    </div>
                  </span>
                </label>
                <button className="btn btn-sm" style={{ width: '100%', marginTop: 8, textAlign: 'left' }}
                  onClick={() => cascade ? setShowDiff(true) : toast('Policy applied (single agent, mock)')}>
                  {cascade ? '↓ Preview cascade diff →' : '↓ Apply single →'}
                </button>
              </div>
            )}
          </div>

          {/* Quick actions */}
          <div style={SH}>Quick Actions</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <button className="btn btn-sm" style={{ textAlign: 'left' }} onClick={() => toast(`◐ ${node.name} → shadow (mock)`)}>◐ Switch to shadow mode</button>
            <button className={`btn btn-sm${node.status !== 'suspended' ? ' btn-danger' : ''}`} style={{ textAlign: 'left' }}
              onClick={() => toast(`${node.status === 'suspended' ? '▶ Resumed' : '■ Suspended'}: ${node.name} (mock)`)}>
              {node.status === 'suspended' ? '▶ Resume agent' : '■ Suspend agent'}
            </button>
          </div>

          {/* Nav links */}
          <div style={SH}>Navigate</div>
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
            <button className="btn btn-sm" onClick={() => toast('open Fleet (mock)')}>Fleet ↗</button>
            <button className="btn btn-sm" onClick={() => toast('open Capability (mock)')}>Capability ↗</button>
            {node.flagged && <button className="btn btn-sm" onClick={() => goPolicy && goPolicy('P-066')}>Policy ↗</button>}
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Right panel: Team detail ─────────────────────────────────────────────
function TopoTeamPanel({ teamId, allNodes, liveEdges, onClose, toast }) {
  const members  = allNodes.filter(n => n.team === teamId);
  const roots    = members.filter(n => !n.parentId);
  const nonRoots = members.filter(n => n.parentId);
  const statusC  = s => s === 'active' ? 'var(--ok)' : s === 'suspended' ? 'var(--danger)' : 'var(--warn)';
  const isOrphan = teamId === '__orphan__';
  const SH = { fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginTop: 14, marginBottom: 7 };

  return (
    <div style={{ width: 276, background: 'var(--paper-2)', borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      <div style={{ padding: '11px 14px 9px', borderBottom: '1px solid var(--line)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, fontWeight: 700, color: isOrphan ? 'var(--danger)' : 'var(--ink)' }}>
            {isOrphan ? '⚠ ' : ''}team: {teamId}
          </div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-4)', marginTop: 3 }}>
            {members.length} agents · {roots.length} root{roots.length !== 1 ? 's' : ''}
          </div>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ink-4)', fontSize: 15, padding: '2px 4px', lineHeight: 1 }}>✕</button>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '0 14px 16px' }}>
        {/* Orphan explanation */}
        {isOrphan && (
          <div style={{ marginTop: 10, background: '#f6dad6', border: '1px solid #b8291e', borderRadius: 3, padding: '7px 10px', fontFamily: 'JetBrains Mono', fontSize: 9, color: '#b8291e' }}>
            <div style={{ fontWeight: 700, marginBottom: 2 }}>Unclaimed agents</div>
            <div style={{ opacity: 0.85 }}>These agents have no team_id and depth &gt; 0 — they were spawned but never registered to a team. Mirrors backend TopologyStats.orphan_count.</div>
          </div>
        )}

        {/* 1-to-many root info badge */}
        {roots.length > 1 && !isOrphan && (
          <div style={{ marginTop: 10, background: 'var(--info-bg)', border: '1px solid var(--info)', borderRadius: 3, padding: '7px 10px', fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--info)' }}>
            {roots.length} independent root agents — each manages its own delegation subtree within this team.
          </div>
        )}

        {/* Root agents (show individually when multiple) */}
        {roots.length > 1 && (
          <>
            <div style={SH}>Root agents</div>
            {roots.map(r => (
              <div key={r.id} style={{ fontFamily: 'JetBrains Mono', fontSize: 10, display: 'flex', justifyContent: 'space-between', background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 3, padding: '6px 9px', marginBottom: 4 }}>
                <span style={{ fontWeight: 700 }}>{r.name}</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <span style={{ color: statusC(r.status) }}>●</span>
                  <span style={{ color: 'var(--ink-4)' }}>trust {r.trust}</span>
                </div>
              </div>
            ))}
          </>
        )}

        {/* All members */}
        <div style={SH}>All members ({members.length})</div>
        <div style={{ border: '1px solid var(--line)', borderRadius: 4, overflow: 'hidden' }}>
          {members.sort((a, b) => a.depth - b.depth).map((m, i) => (
            <div key={m.id} style={{ padding: '7px 10px', borderTop: i > 0 ? '1px solid var(--line)' : 'none', background: m.flagged ? 'rgba(184,41,30,0.04)' : 'var(--paper-2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10, fontWeight: m.depth === 0 ? 700 : 400, paddingLeft: m.depth * 8, color: m.flagged ? 'var(--danger)' : 'var(--ink)' }}>
                {m.depth > 0 ? '└ ' : ''}{m.flagged ? '⚑ ' : ''}{m.name}
              </span>
              <div style={{ display: 'flex', gap: 5 }}>
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: 8, color: statusC(m.status) }}>●</span>
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: 8, color: 'var(--ink-4)' }}>{m.trust}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Team policy */}
        {!isOrphan && (
          <>
            <div style={SH}>Team Policy</div>
            <div style={{ background: 'var(--paper)', border: '1px solid var(--line)', borderRadius: 4, padding: 11 }}>
              <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6, color: 'var(--ink-2)' }}>Apply to all {members.length} agents</div>
              <div style={{ fontFamily: 'JetBrains Mono', fontSize: 8.5, color: 'var(--ink-4)', marginBottom: 9, lineHeight: 1.5 }}>
                Policy registered at team scope — enforced at runtime via evaluators.rs
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button className="btn btn-sm" style={{ textAlign: 'left' }} onClick={() => toast(`⚖ Team policy applied: ${teamId} (mock)`)}>⚖ Apply team policy →</button>
                <button className="btn btn-sm" style={{ textAlign: 'left' }} onClick={() => toast(`◐ ${teamId} → shadow mode (mock)`)}>◐ Shadow mode entire team</button>
              </div>
              {roots.length > 0 && nonRoots.length > 0 && (
                <div style={{ marginTop: 11, paddingTop: 10, borderTop: '1px dashed var(--line)' }}>
                  <div style={{ fontSize: 10, color: 'var(--ink-3)', marginBottom: 8 }}>
                    Cascade from each root (backend enforced, most_restrictive strategy):
                  </div>
                  {roots.map(r => (
                    <button key={r.id} className="btn btn-sm" style={{ textAlign: 'left', width: '100%', marginBottom: 5 }}
                      onClick={() => toast(`↓ Cascade from ${r.name} through ${teamId} (mock)`)}>
                      ↓ Restrict {r.name} + subtree →
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div style={SH}>Quick Actions</div>
            <button className="btn btn-sm btn-danger" style={{ textAlign: 'left', width: '100%' }} onClick={() => toast(`■ ${teamId} suspended (mock)`)}>■ Suspend entire team</button>
          </>
        )}
        {isOrphan && (
          <>
            <div style={SH}>Actions</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <button className="btn btn-sm" style={{ textAlign: 'left' }} onClick={() => toast('Assign agents to team (mock)')}>⊕ Assign to team →</button>
              <button className="btn btn-sm btn-danger" style={{ textAlign: 'left' }} onClick={() => toast('Suspend all unclaimed agents (mock)')}>■ Suspend all unclaimed</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Left sidebar ─────────────────────────────────────────────────────────
function TopoSidebar({ filterTeam, setFilterTeam, visEdges, setVisEdges, showCross, setShowCross, liveMode, setLiveMode, hasCycles, liveMsg }) {
  const teams = window.TOPO_TEAMS;
  const toggle = type => { const n = new Set(visEdges); n.has(type) ? n.delete(type) : n.add(type); setVisEdges(n); };
  return (
    <div style={{ width: 192, borderRight: '1px solid var(--line)', background: 'var(--paper-2)', display: 'flex', flexDirection: 'column', overflow: 'auto', flexShrink: 0 }}>
      {/* Team filter */}
      <div style={{ padding: '11px 13px 8px' }}>
        <div style={{ fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginBottom: 7 }}>Teams</div>
        {[{ id: 'all', label: 'All teams' }, ...teams.map(t => ({ id: t.id, label: t.label || t.id }))].map(t => {
          const isOrphan = t.id === '__orphan__';
          return (
            <div key={t.id} onClick={() => setFilterTeam(t.id)}
              style={{ padding: '5px 8px', borderRadius: 3, cursor: 'pointer', marginBottom: 1,
                background: filterTeam === t.id ? 'var(--paper-3)' : 'transparent',
                fontFamily: 'JetBrains Mono', fontSize: 10,
                color: filterTeam === t.id ? 'var(--ink)' : isOrphan ? 'var(--danger)' : 'var(--ink-3)',
                fontWeight: filterTeam === t.id ? 700 : 400 }}>
              {t.id === 'all' ? '◎ ' : isOrphan ? '⚠ ' : '○ '}{t.label}
            </div>
          );
        })}
      </div>

      {/* Edge types */}
      <div style={{ borderTop: '1px solid var(--line)', padding: '11px 13px 8px' }}>
        <div style={{ fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginBottom: 7 }}>Edge types</div>
        {Object.entries(TOPO_EC).map(([type, cfg]) => (
          <label key={type} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', marginBottom: 6, fontFamily: 'JetBrains Mono', fontSize: 9 }}>
            <input type="checkbox" checked={visEdges.has(type)} onChange={() => toggle(type)} />
            <span style={{ color: cfg.color, fontWeight: 800, fontSize: 12 }}>—</span>
            <span style={{ color: 'var(--ink-3)' }}>{type}</span>
          </label>
        ))}
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', marginTop: 8, fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-3)' }}>
          <input type="checkbox" checked={showCross} onChange={e => setShowCross(e.target.checked)} />
          show cross-team
        </label>
      </div>

      {/* Live mode */}
      <div style={{ borderTop: '1px solid var(--line)', padding: '11px 13px 8px' }}>
        <div style={{ fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginBottom: 7 }}>Live feed</div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontFamily: 'JetBrains Mono', fontSize: 9 }}>
          <input type="checkbox" checked={liveMode} onChange={e => setLiveMode(e.target.checked)} />
          <span style={{ color: liveMode ? 'var(--ok)' : 'var(--ink-3)', fontWeight: liveMode ? 700 : 400 }}>
            {liveMode
              ? <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--ok)', animation: 'pulse 1.4s ease-in-out infinite' }} />live on</span>
              : 'live off'}
          </span>
        </label>
        {liveMsg && (
          <div style={{ marginTop: 6, fontFamily: 'JetBrains Mono', fontSize: 8.5, color: 'var(--info)', background: 'var(--info-bg)', borderRadius: 2, padding: '3px 7px', animation: 'toast-in 0.2s ease-out' }}>
            ⚡ {liveMsg}
          </div>
        )}
        <div style={{ marginTop: 5, fontFamily: 'JetBrains Mono', fontSize: 8, color: 'var(--ink-4)', lineHeight: 1.5 }}>
          Simulates WebSocket feed from /api/v1/topology/edges
        </div>
      </div>

      {/* Cycle alert */}
      {hasCycles && (
        <div style={{ borderTop: '1px solid var(--line)', padding: '11px 13px 8px' }}>
          <div style={{ background: '#f6dad6', border: '1px solid #b8291e', borderRadius: 3, padding: '7px 9px', fontFamily: 'JetBrains Mono', fontSize: 9, color: '#b8291e' }}>
            <div style={{ fontWeight: 700, marginBottom: 2 }}>⟳ Cycle detected</div>
            <div style={{ opacity: 0.85 }}>Highlighted in red on canvas. Requires immediate review.</div>
          </div>
        </div>
      )}

      {/* Status legend */}
      <div style={{ borderTop: '1px solid var(--line)', padding: '11px 13px', marginTop: 'auto' }}>
        <div style={{ fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--ink-4)', marginBottom: 7 }}>Status stripe</div>
        {[['var(--ok)', 'active'], ['var(--warn)', 'shadow'], ['var(--danger)', 'suspended']].map(([c, l]) => (
          <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, fontFamily: 'JetBrains Mono', fontSize: 9, color: 'var(--ink-3)' }}>
            <span style={{ display: 'inline-block', width: 3, height: 14, background: c, borderRadius: 2 }} />
            {l}
          </div>
        ))}
        <div style={{ marginTop: 8, fontSize: 8.5, fontFamily: 'JetBrains Mono', color: 'var(--ink-4)', lineHeight: 1.55 }}>
          Scroll = zoom · drag = pan
        </div>
      </div>
    </div>
  );
}

// ─── TopologyPage — main container ────────────────────────────────────────
function TopologyPage({ goPolicy, toast }) {
  const [selId,      setSelId]      = useTopoSt(null);
  const [selTeam,    setSelTeam]    = useTopoSt(null);
  const [filterTeam, setFilterTeam] = useTopoSt('all');
  const [visEdges,   setVisEdges]   = useTopoSt(new Set(Object.keys(TOPO_EC)));
  const [showCross,  setShowCross]  = useTopoSt(true);
  const [liveMode,   setLiveMode]   = useTopoSt(true);
  const [liveNodes,  setLiveNodes]  = useTopoSt(() => window.TOPO_NODES.map(n => ({ ...n })));
  const [liveEdges,  setLiveEdges]  = useTopoSt(() => [...window.TOPO_EDGES]);
  const [recentIds,  setRecentIds]  = useTopoSt(new Set());
  const [liveMsg,    setLiveMsg]    = useTopoSt('');
  const simIdx = useTopoRef(0);

  const ps = window.TWEAKS?.pageState;

  // Derived: filter nodes
  const nodes = useTopoMemo(() =>
    filterTeam === 'all' ? liveNodes : liveNodes.filter(n => n.team === filterTeam),
    [filterTeam, liveNodes]
  );

  const layout = useTopoMemo(() => topoLayout(nodes), [nodes]);

  // Cycle detection (runs on every edge change)
  const { cycleNodeIds, cycleEdgeIds } = useTopoMemo(() => {
    const cycles = topoDetectCycles(liveEdges);
    if (!cycles.length) return { cycleNodeIds: null, cycleEdgeIds: null };
    const nodeIds = new Set(cycles.flatMap(s => [...s]));
    const edgeIds = new Set(liveEdges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target)).map(e => e.id));
    return { cycleNodeIds: nodeIds, cycleEdgeIds: edgeIds };
  }, [liveEdges]);

  // Live simulation loop (simulates WebSocket events from topology API)
  useTopoEff(() => {
    if (!liveMode) return;
    const iv = setInterval(() => {
      const evt = LIVE_SIM[simIdx.current % LIVE_SIM.length];
      simIdx.current++;
      if (evt.type === 'trust') {
        setLiveNodes(prev => prev.map(n => n.id === evt.nodeId ? { ...n, trust: Math.max(0, Math.min(100, n.trust + evt.delta)) } : n));
        setRecentIds(prev => new Set([...prev, evt.nodeId]));
        setTimeout(() => setRecentIds(prev => { const s = new Set(prev); s.delete(evt.nodeId); return s; }), 2300);
      } else if (evt.type === 'edge') {
        setLiveEdges(prev => [...prev.filter(e => e.id !== evt.edge.id), evt.edge]);
        setRecentIds(prev => new Set([...prev, evt.edge.source]));
        setTimeout(() => setRecentIds(prev => { const s = new Set(prev); s.delete(evt.edge.source); return s; }), 2300);
      } else if (evt.type === 'mode') {
        setLiveNodes(prev => prev.map(n => n.id === evt.nodeId ? { ...n, mode: evt.mode } : n));
        setRecentIds(prev => new Set([...prev, evt.nodeId]));
        setTimeout(() => setRecentIds(prev => { const s = new Set(prev); s.delete(evt.nodeId); return s; }), 2300);
      }
      setLiveMsg(evt.msg);
      setTimeout(() => setLiveMsg(''), 2600);
    }, 5000);
    return () => clearInterval(iv);
  }, [liveMode]);

  if (ps === 'loading') return <window.LoadingState page="topology" />;
  if (ps === 'error')   return <window.ErrorState kind="generic" />;

  const selNode     = selId ? liveNodes.find(n => n.id === selId) : null;
  const activeCount = liveNodes.filter(n => n.status === 'active').length;
  const flaggedCnt  = liveNodes.filter(n => n.flagged).length;
  const crossCnt    = liveEdges.filter(e => e.crossTeam).length;
  const orphanCnt   = liveNodes.filter(n => n.team === '__orphan__').length;
  const teamCount   = window.TOPO_TEAMS.filter(t => t.id !== '__orphan__').length;

  const handleNode = nd => { if (!nd) { setSelId(null); return; } setSelId(nd.id); setSelTeam(nd.team); };
  const handleTeam = tid => { if (!tid) { setSelTeam(null); return; } setSelTeam(tid); setSelId(null); };

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Topology
            <span style={{ color: 'var(--ink-4)', fontWeight: 400, fontSize: 14, marginLeft: 8 }}>
              · {liveNodes.length} agents · {teamCount} teams
            </span>
          </h1>
          <div className="page-sub">
            Agent delegation trees and mesh edge map. Click a node or team group to inspect and apply policy controls.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0 }}>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--ink-3)', display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--ok)' }}>● {activeCount} active</span>
            {flaggedCnt  > 0 && <span style={{ color: 'var(--danger)' }}>⚑ {flaggedCnt} flagged</span>}
            {cycleNodeIds && <span style={{ color: 'var(--danger)', fontWeight: 700 }}>⟳ cycle</span>}
            {orphanCnt   > 0 && <span style={{ color: 'var(--warn)' }}>⚠ {orphanCnt} unclaimed</span>}
            <span style={{ color: 'var(--ink-4)' }}>⇆ {crossCnt} cross-team</span>
            {liveMode && <span style={{ color: 'var(--ok)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--ok)', animation: 'pulse 1.4s ease-in-out infinite' }} />LIVE
            </span>}
          </div>
          <button className="btn btn-sm" onClick={() => toast('graph export (mock)')}>⏏ export graph</button>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <TopoSidebar
          filterTeam={filterTeam}
          setFilterTeam={t => { setFilterTeam(t); setSelId(null); setSelTeam(null); }}
          visEdges={visEdges} setVisEdges={setVisEdges}
          showCross={showCross} setShowCross={setShowCross}
          liveMode={liveMode} setLiveMode={setLiveMode}
          hasCycles={!!cycleNodeIds}
          liveMsg={liveMsg}
        />

        <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
          <TopoCanvas
            layout={layout} nodes={nodes} liveEdges={liveEdges}
            selId={selId} selTeam={selTeam}
            visEdges={visEdges} showCross={showCross}
            onNode={handleNode} onTeam={handleTeam}
            cycleNodeIds={cycleNodeIds} cycleEdgeIds={cycleEdgeIds}
            recentIds={recentIds} filterTeam={filterTeam}
          />
        </div>

        {selNode && (
          <TopoNodePanel
            node={selNode} allNodes={liveNodes} liveEdges={liveEdges}
            onClose={() => setSelId(null)}
            goPolicy={goPolicy} toast={toast}
            inCycle={!!(cycleNodeIds && cycleNodeIds.has(selNode.id))}
            cycleNodeIds={cycleNodeIds || new Set()}
          />
        )}
        {selTeam && !selNode && (
          <TopoTeamPanel
            teamId={selTeam} allNodes={liveNodes} liveEdges={liveEdges}
            onClose={() => setSelTeam(null)} toast={toast}
          />
        )}
      </div>
    </>
  );
}

Object.assign(window, { TopologyPage });
