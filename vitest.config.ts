import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: 'coverage',
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
      include: ['src/**/*.ts'],
      exclude: [
        'src/types/**/*.ts',
        'src/**/index.ts',
        // Bun-only: requires Bun.serve(), not available in vitest/node
        'src/ingest/webhook-receiver.ts',
        // L2 simulation-only modules (v1 scope — no real execution path)
        'src/engine/queue-executor.ts',
        'src/engine/simulation-metrics.ts',
        'src/engine/executors/l2-executor.ts',
        // CLI wiring (Commander.js glue; underlying logic fully tested)
        'src/cli/queue-commands.ts',
        'src/cli/metrics-commands.ts',
      ],
    },
    testTimeout: 10000,
  },
  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
