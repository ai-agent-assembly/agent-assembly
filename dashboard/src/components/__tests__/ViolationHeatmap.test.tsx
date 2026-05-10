import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ViolationHeatmap, ViolationNode } from "../ViolationHeatmap";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNode(partial: Partial<ViolationNode> & { agent_id: string }): ViolationNode {
  return {
    parent_agent_id: null,
    team_id: null,
    depth: 0,
    violation_count: 0,
    top_policies: [],
    ...partial,
  };
}

/** Build 50 audit entries spread across 5 agents.
 *  Agent "hot" gets 30 violations; the other four share the remaining 20. */
function makeFiftyEntryNodes(): ViolationNode[] {
  return [
    makeNode({ agent_id: "aaaa0000000000000000000000000001", parent_agent_id: null, depth: 0, violation_count: 30, top_policies: ["deny-write-fs", "budget-exceeded", "cred-leak"] }),
    makeNode({ agent_id: "aaaa0000000000000000000000000002", parent_agent_id: "aaaa0000000000000000000000000001", depth: 1, violation_count: 8, top_policies: ["deny-write-fs"] }),
    makeNode({ agent_id: "aaaa0000000000000000000000000003", parent_agent_id: "aaaa0000000000000000000000000001", depth: 1, violation_count: 5, top_policies: [] }),
    makeNode({ agent_id: "aaaa0000000000000000000000000004", parent_agent_id: "aaaa0000000000000000000000000002", depth: 2, violation_count: 4, top_policies: [] }),
    makeNode({ agent_id: "aaaa0000000000000000000000000005", parent_agent_id: "aaaa0000000000000000000000000002", depth: 2, violation_count: 3, top_policies: [] }),
  ];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ViolationHeatmap", () => {
  it("renders a node for each agent in the dataset", () => {
    const nodes = makeFiftyEntryNodes();
    render(<ViolationHeatmap nodes={nodes} />);

    for (const node of nodes) {
      expect(
        screen.getByTestId(`heatmap-node-${node.agent_id}`)
      ).toBeInTheDocument();
    }
  });

  it("hot spot node shows correct violation count", () => {
    const nodes = makeFiftyEntryNodes();
    render(<ViolationHeatmap nodes={nodes} />);

    const hotNode = screen.getByTestId("heatmap-node-aaaa0000000000000000000000000001");
    expect(hotNode).toBeInTheDocument();
    // The circle text shows the violation count.
    expect(hotNode.querySelector("text")?.textContent).toBe("30");
  });

  it("hot spot node is colored red (rgb highest ratio)", () => {
    const nodes = makeFiftyEntryNodes();
    render(<ViolationHeatmap nodes={nodes} />);

    const hotCircle = screen
      .getByTestId("heatmap-node-aaaa0000000000000000000000000001")
      .querySelector("circle");

    // Max-violation node should use the red end of the scale.
    const fill = hotCircle?.getAttribute("fill") ?? "";
    // Extract R channel — it should be highest for red.
    const match = fill.match(/rgb\((\d+),(\d+),(\d+)\)/);
    if (match) {
      const [, r, g, b] = match.map(Number);
      expect(r).toBeGreaterThan(g);
      expect(r).toBeGreaterThan(b);
    } else {
      // If fill is a hex color, just assert it's not the green default.
      expect(fill).not.toBe("#22c55e");
    }
  });

  it("low-violation node is colored green or yellow", () => {
    const nodes = makeFiftyEntryNodes();
    render(<ViolationHeatmap nodes={nodes} />);

    const coldCircle = screen
      .getByTestId("heatmap-node-aaaa0000000000000000000000000005")
      .querySelector("circle");

    const fill = coldCircle?.getAttribute("fill") ?? "";
    const match = fill.match(/rgb\((\d+),(\d+),(\d+)\)/);
    if (match) {
      const [, r, , b] = match.map(Number);
      // Green/yellow: red channel low, blue channel low.
      expect(b).toBeLessThan(120);
      expect(r).toBeLessThan(220);
    }
  });

  it("renders legend", () => {
    render(<ViolationHeatmap nodes={makeFiftyEntryNodes()} />);
    expect(screen.getByText(/violations/)).toBeInTheDocument();
  });

  it("shows 'show all' button when nodes exceed maxNodes", () => {
    // Create 6 nodes but set maxNodes=3 so the truncation banner appears.
    const nodes = Array.from({ length: 6 }, (_, i) =>
      makeNode({ agent_id: `${"aa".repeat(7)}0${(i + 1).toString(16).padStart(2, "0")}`, violation_count: i + 1 })
    );
    render(<ViolationHeatmap nodes={nodes} maxNodes={3} />);
    expect(screen.getByText(/Show all/)).toBeInTheDocument();
  });

  it("does not render __root__ synthetic node", () => {
    render(<ViolationHeatmap nodes={makeFiftyEntryNodes()} />);
    expect(screen.queryByTestId("heatmap-node-__root__")).not.toBeInTheDocument();
  });
});
