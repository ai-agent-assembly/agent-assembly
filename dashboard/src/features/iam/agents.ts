import { useQuery } from '@tanstack/react-query'
import { iamQueryKeys } from './queryKeys'
import type { Agent, AgentPermissions, EffectivePermission } from './types'

/**
 * In-memory agent registry.
 *
 * The OpenAPI spec does not yet define `/v1/iam/agents` or
 * `/v1/iam/agents/{id}/permissions`. Mirrors the pattern in api.ts
 * and apiKeys.ts — process-local seed data so the panel is fully
 * exercisable. Swap the function bodies for `api.GET` calls when the
 * gateway lands; hook signatures stay stable.
 */
const SEED_AGENTS: Agent[] = [
  { id: 'agent-001', name: 'support-agent', owner_team: 'cx', status: 'online', last_seen: '2026-05-13T15:31:00Z' },
  { id: 'agent-002', name: 'code-review', owner_team: 'platform', status: 'online', last_seen: '2026-05-13T15:42:00Z' },
  { id: 'agent-003', name: 'data-analyst', owner_team: 'analytics', status: 'offline', last_seen: '2026-05-13T09:11:00Z' },
  { id: 'agent-004', name: 'deploy-agent', owner_team: 'devops', status: 'degraded', last_seen: '2026-05-13T15:38:00Z' },
]

const SEED_PERMISSIONS: Record<string, EffectivePermission[]> = {
  'agent-001': [
    { permission: 'members.read', source: { kind: 'team', name: 'cx', granted_at: '2026-04-10T10:00:00Z' } },
    { permission: 'audit.export', source: { kind: 'team', name: 'cx', granted_at: '2026-04-10T10:00:00Z' } },
    { permission: 'policies.read', source: { kind: 'role', name: 'agent.operator', granted_at: '2026-04-12T08:30:00Z' } },
    { permission: 'tools.invoke', source: { kind: 'policy', name: 'support-agent-policy-v2', granted_at: '2026-05-01T11:00:00Z' } },
  ],
  'agent-002': [
    { permission: 'policies.read', source: { kind: 'role', name: 'agent.readonly', granted_at: '2026-03-30T09:00:00Z' } },
    { permission: 'audit.read', source: { kind: 'team', name: 'platform', granted_at: '2026-03-15T12:00:00Z' } },
  ],
  'agent-003': [],
  'agent-004': [
    { permission: 'tools.invoke', source: { kind: 'policy', name: 'deploy-agent-policy-v1', granted_at: '2026-04-20T14:30:00Z' } },
  ],
}

interface AgentStore {
  agents: Agent[]
  permissions: Record<string, EffectivePermission[]>
}

const store: AgentStore = {
  agents: [...SEED_AGENTS],
  permissions: { ...SEED_PERMISSIONS },
}

function fetchAgents(): Promise<Agent[]> {
  return Promise.resolve([...store.agents])
}

function fetchAgentPermissions(agentId: string): Promise<AgentPermissions> {
  const effective = store.permissions[agentId] ?? []
  return Promise.resolve({ agent_id: agentId, effective: [...effective] })
}

export function useAgentsQuery() {
  return useQuery({
    queryKey: iamQueryKeys.agents(),
    queryFn: fetchAgents,
  })
}

export function useAgentPermissionsQuery(agentId: string | null) {
  return useQuery({
    queryKey: agentId ? iamQueryKeys.agentPermissions(agentId) : ['iam', 'agents', 'noop'],
    queryFn: () => fetchAgentPermissions(agentId as string),
    enabled: agentId !== null,
  })
}

export const _agentsInternal: {
  reset: () => void
  snapshot: () => readonly Agent[]
  setAgents: (agents: Agent[]) => void
  setPermissions: (agentId: string, permissions: EffectivePermission[]) => void
} = {
  reset(): void {
    store.agents = [...SEED_AGENTS]
    store.permissions = { ...SEED_PERMISSIONS }
  },
  snapshot(): readonly Agent[] {
    return store.agents
  },
  setAgents(agents) {
    store.agents = [...agents]
  },
  setPermissions(agentId, permissions) {
    store.permissions = { ...store.permissions, [agentId]: [...permissions] }
  },
}
