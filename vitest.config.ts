import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@kitiumai/error': path.resolve(__dirname, '../error/src'),
      '@kitiumai/logger': path.resolve(__dirname, '../logger/src'),
      '@kitiumai/types': path.resolve(__dirname, '../types/src'),
      '@kitiumai/utils-ts': path.resolve(__dirname, '../../../dev-tools/@kitiumai/utils-ts/src'),
    },
  },
  test: {
    globals: false,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    setupFiles: ['./src/__tests__/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['**/node_modules/**', '**/dist/**', '**/*.test.ts'],
    },
  },
});
