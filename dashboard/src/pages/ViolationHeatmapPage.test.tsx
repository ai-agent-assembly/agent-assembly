import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ViolationHeatmapPage } from "./ViolationHeatmapPage";

interface ApiResponse {
  nodes: Array<{
    agent_id: string;
    parent_agent_id: string | null;
    team_id: string | null;
    depth: number | null;
    violation_count: number;
    top_policies: string[];
  }>;
  window_secs: number;
  generated_at: string;
}

function jsonResponse(body: ApiResponse, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

function makeNodes(count: number): ApiResponse["nodes"] {
  return Array.from({ length: count }, (_, i) => ({
    agent_id: `aaaa00000000000000000000000000${(i + 1).toString().padStart(2, "0")}`,
    parent_agent_id: null,
    team_id: null,
    depth: 0,
    violation_count: i + 1,
    top_policies: [],
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ViolationHeatmapPage", () => {
  it("shows loading state before fetch resolves", async () => {
    let resolveFetch: (value: Response) => void = () => undefined;
    const pending = new Promise<Response>((res) => {
      resolveFetch = res;
    });
    vi.spyOn(globalThis, "fetch").mockReturnValue(pending);

    render(<ViolationHeatmapPage />);

    expect(screen.getByText(/Loading…/)).toBeInTheDocument();

    resolveFetch(jsonResponse({ nodes: [], window_secs: 86400, generated_at: "2026-05-17T00:00:00Z" }));
    await waitFor(() => expect(screen.queryByText(/Loading…/)).not.toBeInTheDocument());
  });

  it("renders empty-state message when no violations recorded", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ nodes: [], window_secs: 86400, generated_at: "2026-05-17T00:00:00Z" }),
    );

    render(<ViolationHeatmapPage />);

    await waitFor(() =>
      expect(screen.getByText(/No violations recorded in this window\./)).toBeInTheDocument(),
    );
    expect(screen.getByText(/0 agents with violations/)).toBeInTheDocument();
  });

  it("renders the heatmap when the API returns nodes", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        nodes: makeNodes(3),
        window_secs: 86400,
        generated_at: "2026-05-17T00:00:00Z",
      }),
    );

    render(<ViolationHeatmapPage />);

    await waitFor(() => expect(screen.getByText(/3 agents with violations/)).toBeInTheDocument());
    expect(
      screen.getByTestId("heatmap-node-aaaa0000000000000000000000000001"),
    ).toBeInTheDocument();
  });

  it("uses singular 'agent' wording when exactly one node is returned", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        nodes: makeNodes(1),
        window_secs: 86400,
        generated_at: "2026-05-17T00:00:00Z",
      }),
    );

    render(<ViolationHeatmapPage />);

    await waitFor(() => expect(screen.getByText(/1 agent with violations/)).toBeInTheDocument());
    // Should not pluralize.
    expect(screen.queryByText(/1 agents with violations/)).not.toBeInTheDocument();
  });

  it("renders error state when fetch responds non-OK", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("", { status: 500 }));

    render(<ViolationHeatmapPage />);

    await waitFor(() => expect(screen.getByText(/Error: HTTP 500/)).toBeInTheDocument());
  });

  it("renders error state when fetch rejects (network error)", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network unreachable"));

    render(<ViolationHeatmapPage />);

    await waitFor(() => expect(screen.getByText(/Error: network unreachable/)).toBeInTheDocument());
  });

  it("refetches with new ?window= when the window selector changes", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        jsonResponse({ nodes: [], window_secs: 86400, generated_at: "2026-05-17T00:00:00Z" }),
      );

    render(<ViolationHeatmapPage />);
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));

    await userEvent.selectOptions(screen.getByLabelText(/Window/), "7d");

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2));
    const lastCall = fetchSpy.mock.calls.at(-1)?.[0] as string;
    expect(lastCall).toContain("window=7d");
  });

  it("includes ?root=<hex> when a root agent is typed", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        jsonResponse({ nodes: [], window_secs: 86400, generated_at: "2026-05-17T00:00:00Z" }),
      );

    render(<ViolationHeatmapPage />);
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));

    await userEvent.type(screen.getByLabelText(/Root agent/), "deadbeef");

    await waitFor(() => {
      const lastCall = fetchSpy.mock.calls.at(-1)?.[0] as string;
      expect(lastCall).toContain("root=deadbeef");
    });
  });

  it("omits ?root when the root input is empty (default)", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        jsonResponse({ nodes: [], window_secs: 86400, generated_at: "2026-05-17T00:00:00Z" }),
      );

    render(<ViolationHeatmapPage />);
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));

    const firstCall = fetchSpy.mock.calls[0]?.[0] as string;
    expect(firstCall).not.toContain("root=");
    expect(firstCall).toContain("window=24h");
  });
});
