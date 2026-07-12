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
      // Measured 2026-07: lines 37.7%, statements 35.4%, functions 27.9%, branches 27.07%
      thresholds: {
        lines: 37,
        statements: 35,
        functions: 27,
        branches: 27
      }
    }
  }
}));
