import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // The contract suite spawns a real DI-API server per file; sockets in a
    // temporary directory are per-file, so files may still run in parallel.
    testTimeout: 30_000,
    hookTimeout: 40_000,
  },
});
