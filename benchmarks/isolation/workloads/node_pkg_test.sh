#!/usr/bin/env sh
# Node package and test activity: pnpm install of a dependency-free package into
# a run-local store, then a node test run.
#
# Dependency-free and offline on purpose: a real dependency graph would make the
# family's cost a function of registry latency rather than of the sandbox. The
# store lives inside the scratch dir so repetitions do not warm each other, and
# so the workload never touches the operator's global pnpm store.
#
# Only stdout is discarded: stderr reaches the harness's per-repetition log, so a
# failure is diagnosable rather than just a non-zero exit code.
set -eu
scratch="$1"

cd "$scratch"
cat > package.json <<'JSONEOF'
{
  "name": "aabench-node-workload",
  "version": "0.0.0",
  "private": true,
  "type": "module"
}
JSONEOF

mkdir -p test
cat > test/basic.test.mjs <<'JSEOF'
import assert from 'node:assert/strict';
import { test } from 'node:test';

test('arithmetic', () => {
  let total = 0;
  for (let i = 0; i < 10000; i += 1) total += i;
  assert.equal(total, 49995000);
});

test('strings', () => {
  assert.equal('aabench'.toUpperCase(), 'AABENCH');
});
JSEOF

pnpm install --ignore-scripts --offline --store-dir "$scratch/.pnpm-store" >/dev/null
# `node --test test/` resolves the trailing-slash directory as a module name on
# Node 23 and dies with MODULE_NOT_FOUND. Name the file explicitly.
node --test test/basic.test.mjs >/dev/null
