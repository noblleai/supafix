import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['cjs'],
  target: 'node18',
  clean: true,
  minify: false,
  bundle: true,
  noExternal: [/.*/],
  banner: { js: '#!/usr/bin/env node' },
});
