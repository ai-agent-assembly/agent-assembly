/**
 * `@agent-assembly/devint-reference-client` — a thin Developer Integration API
 * client, small enough to be read end to end and copied into a VS Code,
 * JetBrains or marketplace package.
 *
 * See `docs/src/devtools/reference-client.md` for what a plugin built on this
 * may and may not do, and `README.md` for the porting checklist.
 *
 * **MCP is optional and independent of this protocol.** Nothing in this package
 * speaks MCP; MCP is one of ten integration *capabilities* the runtime may
 * govern (`docs/src/devtools/product-brief.md` §2), and an integration that
 * uses no MCP at all is fully governed. Building a plugin on MCP instead of on
 * this API would make protection depend on the agent choosing to call a tool.
 */
export {
  DevIntClient,
  DI_API_MAX_SUPPORTED,
  DI_API_MIN_SUPPORTED,
  DI_API_PROJECT_ROOT_SINCE,
  DI_API_USER_CONFIG_HOME_SINCE,
  projectRootRequiresNewerRuntime,
  userConfigHomeRequiresNewerRuntime,
  VERB_NAMES,
} from './client.js';
export type { ClientIdentity, Negotiated, PlanOptions, TargetOptions } from './client.js';
export { CapabilityToken, TOKEN_ENV } from './credential.js';
export { discover, socketPath, SOCKET_PATH_ENV } from './discovery.js';
export type { Discovery } from './discovery.js';
export {
  actionable,
  DeniedError,
  DevIntError,
  IncompatibleError,
  ProjectRootUnsupportedError,
  RuntimeNotRunningError,
  TransportError,
  UnexpectedFrameError,
  UserConfigHomeUnsupportedError,
  VerbUnavailableError,
} from './errors.js';
export { projectRoot, PROJECT_ROOT_ENV } from './project.js';
export { userConfigHome, USER_CONFIG_HOME_ENV } from './userConfigHome.js';
export {
  HOST_ENFORCED_UNAVAILABLE,
  LEVEL_LABELS,
  PROFILE_LABELS,
  STATE_LABELS,
  levelLabel,
  profileLabel,
  renderEvents,
  renderStatus,
  renderSteps,
  renderTools,
  splitEvidence,
} from './render.js';
export type { EvidenceSplit } from './render.js';

// The wire types, re-exported from the generated bindings. A consumer never
// hand-writes a DI-API message shape; it imports the one generated from
// `proto/devint.proto`.
export * from './generated/devint_pb.js';
