import { render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ViolationHeatmapPage } from "./ViolationHeatmapPage";

// Regression for AAASM-4131: the violation heatmap fetch must go through the
// same base-URL + bearer-auth convention as every other data path, otherwise
// it 401s / hits the SPA origin against a split-origin authenticated backend.

function emptyResponse(): Response {
  return new Response(
    JSON.stringify({ nodes: [], window_secs: 86400, generated_at: "2026-05-17T00:00:00Z" }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  sessionStorage.clear();
});

describe("ViolationHeatmapPage request wiring", () => {
  it("prefixes VITE_API_BASE_URL and sends the Authorization bearer header", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "https://api.example.test");
    sessionStorage.setItem("aa_token", "tok-123");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(emptyResponse());

    render(<ViolationHeatmapPage />);

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/^https:\/\/api\.example\.test\/api\/v1\/audit\/violations-by-lineage\?/);
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  });

  it("omits the Authorization header when no token is stored", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(emptyResponse());

    render(<ViolationHeatmapPage />);

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });
});
