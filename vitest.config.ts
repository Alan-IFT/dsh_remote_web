import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    pool: 'threads',
    testTimeout: 20000,
    hookTimeout: 20000,
  },
})
