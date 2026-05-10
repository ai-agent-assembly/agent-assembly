import { useEffect, useState } from "react";
import { ViolationHeatmap, ViolationNode } from "../components/ViolationHeatmap";

interface ApiResponse {
  nodes: ViolationNode[];
  window_secs: number;
  generated_at: string;
}

export function ViolationHeatmapPage() {
  const [data, setData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [window_, setWindow_] = useState("24h");
  const [root, setRoot] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ window: window_ });
    if (root) params.set("root", root);

    fetch(`/api/v1/audit/violations-by-lineage?${params}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<ApiResponse>;
      })
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [window_, root]);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h2 style={{ marginTop: 0 }}>Policy Violations by Lineage</h2>

      <div style={{ display: "flex", gap: 12, marginBottom: 16, alignItems: "center" }}>
        <label style={{ fontSize: 13 }}>
          Window:{" "}
          <select value={window_} onChange={(e) => setWindow_(e.target.value)}>
            <option value="1h">1 hour</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
          </select>
        </label>
        <label style={{ fontSize: 13 }}>
          Root agent (hex):{" "}
          <input
            value={root}
            onChange={(e) => setRoot(e.target.value)}
            placeholder="optional"
            style={{ width: 200, fontFamily: "monospace", fontSize: 12 }}
          />
        </label>
      </div>

      {loading && <p style={{ color: "#6b7280" }}>Loading…</p>}
      {error && <p style={{ color: "#ef4444" }}>Error: {error}</p>}
      {data && !loading && (
        <>
          <p style={{ fontSize: 12, color: "#6b7280", marginBottom: 8 }}>
            {data.nodes.length} agent{data.nodes.length !== 1 ? "s" : ""} with violations ·
            window {data.window_secs}s · generated {data.generated_at}
          </p>
          {data.nodes.length === 0 ? (
            <p style={{ color: "#6b7280" }}>No violations recorded in this window.</p>
          ) : (
            <ViolationHeatmap nodes={data.nodes} />
          )}
        </>
      )}
    </div>
  );
}
