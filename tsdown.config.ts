import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    cli: 'src/cli.ts',
    relay: 'src/relay/index.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  outDir: 'lib',
  dts: false,
  clean: true,
  sourcemap: false,
  external: [
    '@deepseek-ai/cordis',
    '@deepseek-ai/dsh-host-webserver',
    'ws',
    'qrcode',
    '@deepseek-ai/schemastery',
  ],
})
