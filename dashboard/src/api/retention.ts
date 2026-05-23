// Retention-policy admin API client (AAASM-1592 S-K).
//
// Thin wrapper around the codegen'd openapi-fetch client. Surfaces the
// three retention-policy operations as named functions so the page
// component never touches `api.GET / api.PUT / api.POST` directly.

import { api } from "./client";
import type { components } from "./generated/schema";

export type RetentionPolicyDocument = components["schemas"]["RetentionPolicyDocument"];
export type UpdateRetentionPolicyRequest = components["schemas"]["UpdateRetentionPolicyRequest"];
export type RetentionRunStatsDto = components["schemas"]["RetentionRunStatsDto"];
export type ColdActionDto = components["schemas"]["ColdActionDto"];

export interface RetentionPolicyClient {
  get(): Promise<RetentionPolicyDocument>;
  update(req: UpdateRetentionPolicyRequest): Promise<RetentionPolicyDocument>;
  run(dryRun: boolean): Promise<RetentionRunStatsDto>;
}

export function createRetentionPolicyClient(): RetentionPolicyClient {
  return {
    async get() {
      const { data, error } = await api.GET("/api/v1/admin/retention-policy");
      if (error || !data) {
        throw new Error(`retention policy GET failed: ${JSON.stringify(error ?? "no data")}`);
      }
      return data;
    },
    async update(req) {
      const { data, error } = await api.PUT("/api/v1/admin/retention-policy", {
        body: req,
      });
      if (error || !data) {
        throw new Error(`retention policy PUT failed: ${JSON.stringify(error ?? "no data")}`);
      }
      return data;
    },
    async run(dryRun) {
      const { data, error } = await api.POST("/api/v1/admin/retention-policy/run", {
        body: { dry_run: dryRun },
      });
      if (error || !data) {
        throw new Error(`retention policy run failed: ${JSON.stringify(error ?? "no data")}`);
      }
      return data;
    },
  };
}

export const retentionPolicyClient: RetentionPolicyClient = createRetentionPolicyClient();
