#!/usr/bin/env node
/**
 * Fail if `src/generated/` no longer matches what `proto/devint.proto` would
 * generate today.
 *
 * The acceptance criterion this guards is "the client uses shared
 * generated/reference bindings rather than duplicating wire schemas manually".
 * Generating once and committing the output satisfies the letter of that and
 * none of its intent: the moment the proto changes, a committed artifact is a
 * hand-maintained mirror again, just one nobody remembers editing. So the check
 * regenerates into a scratch directory and byte-compares — a proto change with
 * no regeneration fails here rather than at the first mis-decoded frame.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const committed = join(pkgRoot, 'src', 'generated');
const scratch = mkdtempSync(join(tmpdir(), 'devint-bindings-'));

/** The generate config, redirected at the scratch directory. */
const genConfig = readFileSync(join(pkgRoot, 'buf.gen.yaml'), 'utf8').replace(
  /^(\s*out:\s*).*$/m,
  `$1${scratch}`,
);
const scratchConfig = join(scratch, 'buf.gen.yaml');
writeFileSync(scratchConfig, genConfig);

try {
  execFileSync(join(pkgRoot, 'node_modules', '.bin', 'buf'), ['generate', '--template', scratchConfig], {
    cwd: pkgRoot,
    stdio: 'inherit',
    env: { ...process.env, PATH: `${join(pkgRoot, 'node_modules', '.bin')}:${process.env.PATH}` },
  });

  const fresh = readdirSync(scratch).filter((f) => f.endsWith('.ts')).sort();
  const onDisk = readdirSync(committed).filter((f) => f.endsWith('.ts')).sort();
  const problems = [];

  if (fresh.join(',') !== onDisk.join(',')) {
    problems.push(`file set differs: proto generates [${fresh}], committed [${onDisk}]`);
  }
  for (const file of fresh) {
    if (!onDisk.includes(file)) continue;
    if (readFileSync(join(scratch, file), 'utf8') !== readFileSync(join(committed, file), 'utf8')) {
      problems.push(`${file} differs from what proto/devint.proto generates`);
    }
  }

  if (problems.length > 0) {
    console.error('DI-API bindings have drifted from proto/devint.proto:');
    for (const p of problems) console.error(`  - ${p}`);
    console.error('\nRun `pnpm generate` and commit src/generated/.');
    process.exit(1);
  }
  console.log('DI-API bindings match proto/devint.proto.');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
