import {fileURLToPath} from 'node:url';
import {defineConfig} from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@machina/alloy': fileURLToPath(new URL('../../packages/alloy/src/index.ts', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    restoreMocks: true,
    clearMocks: true,
  },
});
