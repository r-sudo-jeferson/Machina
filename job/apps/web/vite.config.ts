import {fileURLToPath} from 'node:url';
import react from '@vitejs/plugin-react';
import {defineConfig} from 'vite';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@machina/alloy': fileURLToPath(new URL('../../packages/alloy/src/index.ts', import.meta.url)),
    },
  },
  build: {
    sourcemap: true,
  },
});
