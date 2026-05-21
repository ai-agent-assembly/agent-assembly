import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // Emit relative asset paths so the embedded `aasm dashboard` server
  // (AAASM-1292) can mount the SPA at any sub-path without breaking
  // resource resolution.
  base: './',
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
  build: {
    outDir: 'dist',
    // Source maps are not served by the embedded `aasm dashboard` server and add
    // ~3.4 MB to the final aasm binary (include_dir! embeds every file in dist/).
    // Disable for production builds; dev (`vite`) generates inline sourcemaps via
    // its own pipeline and is unaffected.
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      reportsDirectory: './coverage',
    },
  },
})
