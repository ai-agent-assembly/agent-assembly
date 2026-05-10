import { useMemo, useState } from "react";
import { hierarchy, tree } from "d3-hierarchy";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ViolationNode {
  agent_id: string;
  parent_agent_id: string | null;
  team_id: string | null;
  depth: number | null;
  violation_count: number;
  top_policies: string[];
}

interface Props {
  nodes: ViolationNode[];
  /** Maximum nodes to render before showing a "show more" affordance. */
  maxNodes?: number;
}

// ---------------------------------------------------------------------------
// Color scale  green(0) → yellow(low) → red(high)
// ---------------------------------------------------------------------------

function violationColor(count: number, max: number): string {
  if (max === 0) return "#22c55e"; // green
  const ratio = Math.min(count / max, 1);
  if (ratio < 0.5) {
    // green → yellow
    const t = ratio * 2;
    const r = Math.round(34 + t * (234 - 34));
    const g = Math.round(197 + t * (179 - 197));
    const b = Math.round(94 + t * (8 - 94));
    return `rgb(${r},${g},${b})`;
  } else {
    // yellow → red
    const t = (ratio - 0.5) * 2;
    const r = Math.round(234 + t * (239 - 234));
    const g = Math.round(179 + t * (68 - 179));
    const b = Math.round(8 + t * (68 - 8));
    return `rgb(${r},${g},${b})`;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const NODE_R = 18;
const WIDTH = 900;
const HEIGHT = 560;

export function ViolationHeatmap({ nodes, maxNodes = 1000 }: Props) {
  const [tooltip, setTooltip] = useState<{
    x: number;
    y: number;
    node: ViolationNode;
  } | null>(null);
  const [showAll, setShowAll] = useState(false);

  const visibleNodes = showAll ? nodes : nodes.slice(0, maxNodes);
  const truncated = nodes.length > maxNodes && !showAll;

  const maxViolations = useMemo(
    () => Math.max(...visibleNodes.map((n) => n.violation_count), 0),
    [visibleNodes]
  );

  // Build a d3-hierarchy from the flat node list.
  const root = useMemo(() => {
    const idMap = new Map(visibleNodes.map((n) => [n.agent_id, n]));

    // Find root(s): nodes with no parent in the visible set.
    const roots = visibleNodes.filter(
      (n) => !n.parent_agent_id || !idMap.has(n.parent_agent_id)
    );

    // If multiple roots, create a synthetic root.
    const syntheticRoot: ViolationNode & { children?: ViolationNode[] } = {
      agent_id: "__root__",
      parent_agent_id: null,
      team_id: null,
      depth: null,
      violation_count: 0,
      top_policies: [],
      children: roots,
    };

    function buildChildren(node: ViolationNode): ViolationNode & { children?: ViolationNode[] } {
      const children = visibleNodes.filter(
        (n) => n.parent_agent_id === node.agent_id
      );
      if (children.length === 0) return node;
      return {
        ...node,
        children: children.map(buildChildren),
      };
    }

    const treeRoot = {
      ...syntheticRoot,
      children: roots.map(buildChildren),
    };

    return hierarchy(treeRoot);
  }, [visibleNodes]);

  const layout = useMemo(() => {
    const t = tree<ViolationNode & { children?: ViolationNode[] }>()
      .size([WIDTH - 80, HEIGHT - 80]);
    return t(root as Parameters<typeof t>[0]);
  }, [root]);

  const links = layout.links();
  const descendants = layout.descendants().filter((d) => d.data.agent_id !== "__root__");

  return (
    <div style={{ position: "relative", fontFamily: "monospace" }}>
      {/* Legend */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, fontSize: 12 }}>
        <span>0</span>
        {[0, 0.25, 0.5, 0.75, 1].map((r) => (
          <div
            key={r}
            style={{
              width: 24,
              height: 14,
              background: violationColor(r * maxViolations, maxViolations),
              border: "1px solid #ccc",
            }}
          />
        ))}
        <span>{maxViolations} violations</span>
      </div>

      <svg
        width={WIDTH}
        height={HEIGHT}
        style={{ border: "1px solid #e5e7eb", borderRadius: 6, background: "#fafafa" }}
      >
        {/* Links */}
        <g transform="translate(40,40)">
          {links.map((link, i) => {
            if (link.source.data.agent_id === "__root__") return null;
            return (
              <line
                key={i}
                x1={link.source.x}
                y1={link.source.y}
                x2={link.target.x}
                y2={link.target.y}
                stroke="#d1d5db"
                strokeWidth={1.5}
              />
            );
          })}

          {/* Nodes */}
          {descendants.map((d) => {
            const color = violationColor(d.data.violation_count, maxViolations);
            return (
              <g
                key={d.data.agent_id}
                transform={`translate(${d.x},${d.y})`}
                style={{ cursor: "pointer" }}
                onMouseEnter={() => {
                  setTooltip({
                    x: d.x + 40,
                    y: d.y + 40,
                    node: d.data as ViolationNode,
                  });
                }}
                onMouseLeave={() => setTooltip(null)}
                data-testid={`heatmap-node-${d.data.agent_id}`}
              >
                <circle r={NODE_R} fill={color} stroke="#6b7280" strokeWidth={1} />
                <text
                  textAnchor="middle"
                  dy="0.35em"
                  fontSize={9}
                  fill="#1f2937"
                  style={{ pointerEvents: "none" }}
                >
                  {d.data.violation_count}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {/* Tooltip */}
      {tooltip && (
        <div
          style={{
            position: "absolute",
            left: tooltip.x + 60,
            top: tooltip.y + 10,
            background: "white",
            border: "1px solid #d1d5db",
            borderRadius: 6,
            padding: "8px 12px",
            boxShadow: "0 2px 8px rgba(0,0,0,.15)",
            fontSize: 12,
            maxWidth: 260,
            zIndex: 10,
            pointerEvents: "none",
          }}
        >
          <div style={{ fontWeight: "bold", marginBottom: 4, wordBreak: "break-all" }}>
            {tooltip.node.agent_id.slice(0, 16)}…
          </div>
          <div>Violations: <strong>{tooltip.node.violation_count}</strong></div>
          {tooltip.node.team_id && <div>Team: {tooltip.node.team_id}</div>}
          {tooltip.node.depth != null && <div>Depth: {tooltip.node.depth}</div>}
          {tooltip.node.top_policies.length > 0 && (
            <div style={{ marginTop: 4 }}>
              <div style={{ fontWeight: "bold" }}>Top policies:</div>
              <ul style={{ margin: "2px 0 0 12px", padding: 0 }}>
                {tooltip.node.top_policies.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {truncated && (
        <div style={{ marginTop: 8, fontSize: 12, color: "#6b7280" }}>
          Showing {maxNodes} of {nodes.length} agents.{" "}
          <button
            style={{ color: "#2563eb", background: "none", border: "none", cursor: "pointer", padding: 0 }}
            onClick={() => setShowAll(true)}
          >
            Show all
          </button>
        </div>
      )}
    </div>
  );
}
