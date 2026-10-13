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
      // Global line-coverage floor. Ratchet up as page/widget tests are added.
      // Measured 2026-10: lines 42.11%, statements 39.66%, functions 32.52%, branches 31.93%
      thresholds: {
        lines: 42,
        statements: 39,
        functions: 32,
        branches: 31
      }
    }
  }
}));
