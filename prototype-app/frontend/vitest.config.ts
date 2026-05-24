import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

export default mergeConfig(viteConfig, defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/**/*.test.{ts,tsx}',
        'src/**/*.spec.{ts,tsx}',
        'src/test/**',
        'src/main.tsx',
        'src/vite-env.d.ts',
        'src/**/*.d.ts',
      ],
      // Global line-coverage floor. Set just below current measured coverage
      // (~14.7% lines as of 2026-05) so this catches regressions without
      // blocking the current state. Ratchet up as page tests are added.
      thresholds: {
        lines: 14,
        statements: 14,
        functions: 11,
        branches: 10
      }
    }
  }
}));
