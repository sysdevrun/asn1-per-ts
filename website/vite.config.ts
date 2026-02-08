import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  base: './',
  resolve: {
    alias: {
      'per-unaligned-ts': path.resolve(__dirname, '../src'),
      'intercode6-ts': path.resolve(__dirname, '../intercode6-ts/src'),
    },
  },
});
