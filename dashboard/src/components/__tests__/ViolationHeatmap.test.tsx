import { fireEvent, render, screen } from "@testing-library/react";
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

  it("shows tooltip on mouse enter with team, depth, and top policies", () => {
    const nodes = makeFiftyEntryNodes();
    render(<ViolationHeatmap nodes={[...nodes, makeNode({
      agent_id: "bbbb0000000000000000000000000099",
      parent_agent_id: null,
      team_id: "team-alpha",
      depth: 2,
      violation_count: 1,
      top_policies: ["deny-network", "require-approval"],
    })]} />);

    const target = screen.getByTestId("heatmap-node-bbbb0000000000000000000000000099");
    fireEvent.mouseEnter(target);

    expect(screen.getByText(/Violations:/)).toBeInTheDocument();
    expect(screen.getByText(/Team: team-alpha/)).toBeInTheDocument();
    expect(screen.getByText(/Depth: 2/)).toBeInTheDocument();
    expect(screen.getByText("Top policies:")).toBeInTheDocument();
    expect(screen.getByText("deny-network")).toBeInTheDocument();

    // Mouse leave hides tooltip.
    fireEvent.mouseLeave(target);
    expect(screen.queryByText("Top policies:")).not.toBeInTheDocument();
  });

  it("hides team/depth/top-policies tooltip fields when not set", () => {
    const onlyAgent = makeNode({
      agent_id: "cccc0000000000000000000000000001",
      parent_agent_id: null,
      team_id: null,
      depth: null,
      violation_count: 0,
      top_policies: [],
    });
    render(<ViolationHeatmap nodes={[onlyAgent]} />);
    fireEvent.mouseEnter(screen.getByTestId(`heatmap-node-${onlyAgent.agent_id}`));

    expect(screen.queryByText(/Team:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Depth:/)).not.toBeInTheDocument();
    expect(screen.queryByText("Top policies:")).not.toBeInTheDocument();
  });

  it("reveals truncated nodes after clicking 'Show all'", () => {
    const nodes = Array.from({ length: 6 }, (_, i) =>
      makeNode({
        agent_id: `${"aa".repeat(7)}0${(i + 1).toString(16).padStart(2, "0")}`,
        violation_count: i + 1,
      }),
    );
    render(<ViolationHeatmap nodes={nodes} maxNodes={3} />);

    // Hidden node — index 5 — is past maxNodes.
    const hiddenId = nodes[5]!.agent_id;
    expect(screen.queryByTestId(`heatmap-node-${hiddenId}`)).not.toBeInTheDocument();

    fireEvent.click(screen.getByText(/Show all/));

    expect(screen.getByTestId(`heatmap-node-${hiddenId}`)).toBeInTheDocument();
    // Truncation banner gone after expansion.
    expect(screen.queryByText(/Show all/)).not.toBeInTheDocument();
  });

  it("colors every node green when no violations recorded (max=0)", () => {
    const node = makeNode({
      agent_id: "dddd0000000000000000000000000001",
      violation_count: 0,
    });
    render(<ViolationHeatmap nodes={[node]} />);

    const fill = screen
      .getByTestId(`heatmap-node-${node.agent_id}`)
      .querySelector("circle")
      ?.getAttribute("fill");
    expect(fill).toBe("#22c55e");
  });
});
