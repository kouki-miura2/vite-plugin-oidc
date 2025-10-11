import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // テストファイルの場所を指定
    include: [
      'test/**/*.test.ts',
      'test/**/*.integration.test.ts'
    ],
    // srcディレクトリのテストファイルは除外
    exclude: [
      'src/**/*.test.ts',
      'node_modules/**'
    ],
    // テスト環境の設定
    environment: 'node',
    // グローバル設定
    globals: true,
    // カバレッジ設定
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/**/*.integration.test.ts',
        'src/test-helpers/**',
        'src/types/**'
      ]
    }
  },
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
      '@test': new URL('./test', import.meta.url).pathname
    }
  }
})