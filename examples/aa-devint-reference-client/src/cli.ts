#!/usr/bin/env node
/**
 * The example onboarding / status flow.
 *
 * A terminal, because a terminal is the smallest surface that can show the
 * whole interaction honestly — the same sequence a VS Code webview or a
 * JetBrains tool window would drive, minus the framework. Every screen a real
 * plugin needs appears here once: not-running, not-enrolled, degraded,
 * incompatible, tool list, plan review, apply, status, verify, repair, remove,
 * events, approval relay.
 *
 * It is deliberately not `aasm`. The operator CLI is AAASM-5280's DI-API
 * client; this one exists so an extension author can see a second, independent
 * consumer of the same API and copy its shape rather than reverse-engineering
 * the first.
 */
import { DevIntClient, type ClientIdentity } from './client.js';
import { CapabilityToken } from './credential.js';
import { discover } from './discovery.js';
import { DeniedError, DevIntError, IncompatibleError, actionable } from './errors.js';
import { Verb } from './generated/devint_pb.js';
import {
  HOST_ENFORCED_UNAVAILABLE,
  profileLabel,
  renderEvents,
  renderStatus,
  renderSteps,
  renderTools,
} from './render.js';

const IDENTITY: ClientIdentity = { name: 'devint-reference-client', version: '0.0.1' };

const USAGE = `aa-devint-demo — Developer Integration API reference client

  tools                                 List discovered tools and their capabilities
  status   <tool-id>                    Protection level, evidence and limitations
  plan     <tool-id> [profile] [scope]  Author a dry run (profile: recommended|strict|observe_only)
  install  <tool-id> [profile] [scope]  Plan, show it for review, then apply it
  verify   <tool-id>                    Run the protection test (the runtime adjudicates)
  repair   <tool-id>                    Restore AASM-owned keys that drifted
  remove   <tool-id> [plan-id]          Author and execute the reversal
  events   <tool-id> [limit]            Recent, already-redacted integration events
  approve  <tool-id> <approval-id> <approve|deny|defer>

The capability token comes from AA_DEVINT_TOKEN, or from the file named by
AA_DEVINT_TOKEN_FILE (which must be mode 600). Enrolment is the operator CLI's
job — this client cannot issue itself a credential.
`;

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (command === undefined || command === '--help' || command === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }

  const found = discover();
  if (found.kind === 'runtime-not-running') {
    // Not an error to retry: nothing is listening, and the thin client is the
    // only layer that exists when the runtime does not.
    process.stderr.write(
      `The AASM runtime is not running (no socket at ${found.path}).\n` +
        `Start it, then run this again. Set AA_DEVINT_SOCKET if it listens elsewhere.\n`,
    );
    return 3;
  }

  let token: CapabilityToken | null = null;
  try {
    token = loadToken();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 4;
  }

  let client: DevIntClient;
  try {
    client = await DevIntClient.connect(found.path, IDENTITY, token);
  } catch (error) {
    if (error instanceof IncompatibleError) {
      // Actionable: which side to upgrade, and to what.
      process.stderr.write(
        `Incompatible with this runtime: ${error.message}\n` +
          `  ${error.remediation}\n` +
          `  The runtime serves DI-API ${error.supportedWindow}.\n`,
      );
      return 5;
    }
    process.stderr.write(`${actionable(error)}\n`);
    return 1;
  }

  try {
    process.stdout.write(
      `Connected: DI-API v${client.negotiated.diApiVersion}, core ${client.negotiated.coreVersion}, ` +
        `lifecycle schema v${client.negotiated.lifecycleSchemaVersion}\n`,
    );
    if (client.negotiated.degraded) {
      // Surfaced, never absorbed: proceeding quietly here shows a user a button
      // for a feature the runtime does not have.
      process.stdout.write(
        `\n⚠ Degraded connection: ${client.negotiated.degradedReason}\n` +
          `  Unavailable: ${client.negotiated.unavailableVerbs.join(', ')}\n` +
          `  ${client.negotiated.remediation}\n`,
      );
    }
    if (!client.enrolled) {
      process.stdout.write(
        '\nThis client is not enrolled, so every operation below will be denied.\n' +
          'Enrol it with the operator CLI and set AA_DEVINT_TOKEN.\n',
      );
    }
    process.stdout.write('\n');
    return await run(client, command, args);
  } catch (error) {
    if (error instanceof DeniedError) {
      process.stderr.write(`Denied: ${error.message}\n  ${error.remediation}\n`);
      return 6;
    }
    if (error instanceof DevIntError) {
      process.stderr.write(`${actionable(error)}\n`);
      return 1;
    }
    throw error;
  } finally {
    client.close();
  }
}

async function run(client: DevIntClient, command: string, args: string[]): Promise<number> {
  const tool = args[0] ?? '';
  switch (command) {
    case 'tools': {
      const list = await client.listTools();
      write(renderTools(list.tools));
      return 0;
    }
    case 'status': {
      requireTool(tool);
      write(renderStatus(await client.status(tool)));
      return 0;
    }
    case 'plan': {
      requireTool(tool);
      const plan = await client.plan(tool, planOptions(args));
      writePlan(plan.planId, plan.profile, plan.plannedLevel, plan.steps, plan.warnings, plan.unsupported);
      return 0;
    }
    case 'install': {
      requireTool(tool);
      const plan = await client.plan(tool, planOptions(args));
      writePlan(plan.planId, plan.profile, plan.plannedLevel, plan.steps, plan.warnings, plan.unsupported);
      // A real UI puts a confirmation between these two calls. The point of the
      // split is that the client asks the runtime to apply a plan the runtime
      // authored — it never writes the tool's configuration itself.
      const applied = await client.apply(tool, plan.planId);
      process.stdout.write(
        `\nApplied. Receipt ${applied.receiptId}.\n` +
          `  Planned:  ${applied.plannedLevel}\n` +
          `  Achieved: ${applied.achievedLevel}   (the runtime decided this, not this client)\n`,
      );
      write(applied.steps.map((s) => `  ${s.stepId}: ${s.outcome}${s.fingerprint ? ` (${s.fingerprint})` : ''}`));
      process.stdout.write(`${HOST_ENFORCED_UNAVAILABLE}\n`);
      return 0;
    }
    case 'verify': {
      requireTool(tool);
      const result = await client.verify(tool);
      process.stdout.write(`Verification: ${result.outcome}\n`);
      if (result.reason !== '') process.stdout.write(`  Reason: ${result.reason}\n`);
      if (result.missing.length > 0) process.stdout.write(`  Not established: ${result.missing.join(', ')}\n`);
      write(result.evidence.map((e) => `  ${e.kind}/${e.mechanism}: ${e.outcome}`));
      return 0;
    }
    case 'repair': {
      requireTool(tool);
      const repaired = await client.repair(tool);
      process.stdout.write(`Repaired: ${repaired.repaired.join(', ') || 'nothing'}\n`);
      write(repaired.unrepairable.map((u) => `  Unrepairable ${u.capability}: ${u.reason}`));
      if (repaired.status !== undefined) write(renderStatus(repaired.status));
      return 0;
    }
    case 'remove': {
      requireTool(tool);
      const removal = await client.remove(tool, args[1] ?? '');
      process.stdout.write(`Removal plan ${removal.planId}\n`);
      write(renderSteps(removal.steps));
      if (removal.residual.length > 0) process.stdout.write(`Left behind: ${removal.residual.join(', ')}\n`);
      write(removal.warnings.map((w) => `  ⚠ ${w}`));
      return 0;
    }
    case 'events': {
      requireTool(tool);
      if (!client.supports(Verb.SCOPED_EVENTS)) {
        process.stderr.write(`This runtime does not offer scoped events. ${client.negotiated.remediation}\n`);
        return 5;
      }
      const list = await client.scopedEvents(tool, Number(args[1] ?? 20));
      write(renderEvents(list.events));
      return 0;
    }
    case 'approve': {
      requireTool(tool);
      const approvalId = args[1];
      const input = args[2];
      if (approvalId === undefined || (input !== 'approve' && input !== 'deny' && input !== 'defer')) {
        process.stderr.write('usage: approve <tool-id> <approval-id> <approve|deny|defer>\n');
        return 2;
      }
      const ack = await client.relayApproval(tool, approvalId, input);
      // "Accepted for adjudication", never "granted". The core decides.
      process.stdout.write(
        `Relayed "${ack.relayedInput}" for ${ack.approvalId}. The runtime accepted it for adjudication;\n` +
          'read the outcome from status — this client is not the decision authority.\n',
      );
      return 0;
    }
    default:
      process.stderr.write(USAGE);
      return 2;
  }
}

function planOptions(args: string[]): { profile: string; settingsScope: string; policyProfileId: string } {
  return {
    profile: args[1] ?? 'recommended',
    settingsScope: args[2] ?? 'user',
    // By name. The document is resolved inside the trusted layers and never
    // crosses this boundary.
    policyProfileId: process.env['AA_DEVINT_POLICY_PROFILE'] ?? '',
  };
}

function writePlan(
  planId: string,
  profile: string,
  plannedLevel: string,
  steps: readonly Parameters<typeof renderSteps>[0][number][],
  warnings: readonly string[],
  unsupported: readonly { capability: string; reason: string }[],
): void {
  process.stdout.write(`Plan ${planId}  profile=${profileLabel(profile)}  planned level=${plannedLevel}\n`);
  write(renderSteps(steps));
  write(unsupported.map((u) => `  Unsupported ${u.capability}: ${u.reason}`));
  write(warnings.map((w) => `  ⚠ ${w}`));
}

function requireTool(tool: string): void {
  if (tool === '') throw new Error('a tool id is required; run `tools` to list them');
}

function loadToken(): CapabilityToken | null {
  const file = process.env['AA_DEVINT_TOKEN_FILE'];
  if (file !== undefined && file !== '') return CapabilityToken.fromFile(file);
  return CapabilityToken.fromEnv();
}

function write(lines: readonly string[]): void {
  for (const line of lines) process.stdout.write(`${line}\n`);
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
