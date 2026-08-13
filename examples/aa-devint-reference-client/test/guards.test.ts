/**
 * The excluded responsibilities, proved structurally rather than promised.
 *
 * AAASM-5282 lists six things a thin client must not do. Five of them are not
 * things a *test of behaviour* can establish — you cannot prove by calling a
 * function that no other function writes a config file. So this suite reads the
 * shipped source and asserts the capability is absent from it: a client that
 * never imports `node:child_process` starts no processes, whatever its logic
 * says.
 *
 * The guard is deliberately a test rather than only a lint rule. A lint rule is
 * one `// eslint-disable-next-line` away from silence; a failing test is a red
 * build. Both exist here — the rule for the editor, the test for the gate.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const pkgRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const srcRoot = join(pkgRoot, 'src');

/** Every shipped `.ts` file, generated bindings included. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return full.endsWith('.ts') ? [full] : [];
  });
}

const files = sourceFiles(srcRoot).map((path) => ({
  path,
  relative: relative(pkgRoot, path),
  text: readFileSync(path, 'utf8'),
}));

/** Source, minus comments — so a *mention* in a docstring is not a capability. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('the reference client cannot start a process', () => {
  it.each(files)('$relative imports no process API', ({ text }) => {
    const body = code(text);
    for (const forbidden of ['child_process', 'spawn(', 'execFile', 'execSync', 'node:worker_threads', 'node:vm']) {
      expect(body).not.toContain(forbidden);
    }
  });
});

describe('the reference client cannot modify tool configuration', () => {
  it.each(files)('$relative performs no filesystem write', ({ text }) => {
    const body = code(text);
    // Reading is allowed — the token file and the socket path are reads. There
    // is no write, no rename, no chmod and no mkdir anywhere: mutation happens
    // by asking the runtime to apply a plan the runtime authored.
    for (const forbidden of [
      'writeFile',
      'appendFile',
      'createWriteStream',
      'mkdir',
      'rmSync',
      'unlink',
      'rename(',
      'renameSync',
      'chmod',
      'truncate',
      'copyFile',
    ]) {
      expect(body).not.toContain(forbidden);
    }
  });
});

describe('the reference client reaches nothing but the DI-API socket', () => {
  it.each(files)('$relative opens no network transport', ({ text }) => {
    const body = code(text);
    // Loopback TCP is ADR 0030 forbidden design 7; an HTTP client here would be
    // a second, unreviewed path to the core.
    for (const forbidden of ["'node:http'", "'node:https'", "'node:dgram'", "'node:tls'", 'fetch(', 'XMLHttpRequest']) {
      expect(body).not.toContain(forbidden);
    }
  });

  it('the only transport import in the package is the Unix socket connect', () => {
    const netImporters = files.filter((f) => code(f.text).includes("from 'node:net'"));
    expect(netImporters.map((f) => f.relative).sort()).toEqual(['src/client.ts', 'src/framing.ts']);
  });
});

describe('the reference client evaluates no policy and scans no content', () => {
  it.each(files)('$relative contains no decision or detection logic', ({ text }) => {
    const body = code(text);
    // Naming a redaction *label* the server computed is fine; performing
    // redaction is not. The tokens below are the act, not the vocabulary.
    for (const forbidden of ['redact(', 'scan(', 'scanFor', 'evaluatePolicy', 'checkAction', 'PolicyEngine']) {
      expect(body).not.toContain(forbidden);
    }
    // The only detection vocabulary present is `redactionLabels`, which is a
    // field on a message the server already redacted.
    expect(body.replace(/redactionLabels/g, '')).not.toMatch(/\bredaction\b/i);
  });

  it('the package can only decode DI-API messages', () => {
    // `src/generated/` is generated from `proto/devint.proto` alone
    // (`buf.gen.yaml`). There are no policy, audit or agent types in this
    // package, so a policy frame is not merely unrequested — it is undecodable.
    const generated = readdirSync(join(srcRoot, 'generated')).sort();
    expect(generated).toEqual(['devint_pb.ts']);
    const bindings = readFileSync(join(srcRoot, 'generated', 'devint_pb.ts'), 'utf8');
    expect(bindings).toContain('package assembly.devint.v1');
    expect(bindings).not.toContain('assembly.policy.v1');
    expect(bindings).not.toContain('assembly.audit.v1');
  });
});

describe('the reference client holds no credential but its own capability token', () => {
  it('no source names a core, gateway or organisation credential', () => {
    for (const { relative: rel, text } of files) {
      const body = code(text);
      for (const forbidden of ['gatewayToken', 'apiKey', 'ANTHROPIC_API_KEY', 'orgSecret', 'bearer', 'Authorization']) {
        expect(body, `${rel} names ${forbidden}`).not.toContain(forbidden);
      }
    }
  });

  it('the token wrapper redacts itself everywhere but the wire', async () => {
    const { CapabilityToken } = await import('../src/credential.js');
    const token = CapabilityToken.parse('a'.repeat(64));
    expect(`${token}`).not.toContain('aaaa');
    expect(JSON.stringify({ token })).not.toContain('aaaa');
    expect(token.expose()).toBe('a'.repeat(64));
  });

  it('exactly one call site exposes the secret', () => {
    const exposures = files.flatMap(({ relative: rel, text }) =>
      [...code(text).matchAll(/\.expose\(\)/g)].map(() => rel),
    );
    expect(exposures).toEqual(['src/client.ts']);
  });
});

describe('the reference client cannot decide a protection level', () => {
  it('render.ts maps levels but never orders or compares them', () => {
    const render = code(files.find((f) => f.relative === 'src/render.ts')?.text ?? '');
    expect(render).not.toBe('');
    // Ranking is the capability to withhold: a client that can order the rungs
    // can pick a higher one. There is no `>`, `<`, `Math.max`, `sort` or index
    // arithmetic over levels anywhere in the renderer.
    for (const forbidden of ['Math.max', 'Math.min', '.sort(', 'levelRank', 'indexOf(level', 'LEVEL_ORDER']) {
      expect(render).not.toContain(forbidden);
    }
  });

  it('every level string the client can emit came from the wire or is a display label', async () => {
    const { LEVEL_LABELS, levelLabel } = await import('../src/render.js');
    // An unrecognised level is surfaced as unrecognised, not resolved to a
    // neighbour — resolving it would be the client deciding what the runtime
    // meant.
    expect(levelLabel('some_future_level')).toContain('unrecognised');
    expect(Object.keys(LEVEL_LABELS)).toContain('host_enforced');
  });

  it('uses the canonical vocabulary verbatim, with no synonyms', async () => {
    const { LEVEL_LABELS, PROFILE_LABELS, STATE_LABELS } = await import('../src/render.js');
    // docs/src/devtools/product-brief.md §6 and §7.
    expect(Object.values(PROFILE_LABELS)).toEqual(['Recommended', 'Strict', 'Observe']);
    expect(LEVEL_LABELS['integrated']).toBe('Integrated');
    expect(LEVEL_LABELS['gateway_protected']).toBe('Gateway Protected');
    expect(LEVEL_LABELS['host_enforced']).toBe('Host Enforced');
    expect(STATE_LABELS['drifted']).toBe('Drifted');
    expect(STATE_LABELS['degraded']).toBe('Degraded');
    expect(STATE_LABELS['incompatible']).toBe('Incompatible');
  });
});

describe('the dependency surface is small enough to audit', () => {
  it('the runtime dependency set is exactly the protobuf runtime', () => {
    const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    // A thin client's blast radius is its dependency tree. One runtime
    // dependency, which is the generated bindings' own runtime, is the whole of
    // it — everything else is Node's standard library.
    expect(Object.keys(pkg.dependencies)).toEqual(['@bufbuild/protobuf']);
  });
});
