import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vitest/config';

// 桌面端纯函数单测（tunnel.ts 的接入态解析等）。
// 刻意不用 jsdom：被测对象不碰 DOM，浏览器全局（localStorage / Tauri）在用例里 vi.mock 掉。
// 单独一份配置而不复用 vite.config.ts：那份带 vue 插件与 dev 反代，单测一项都不需要。
export default defineConfig({
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts']
  }
});
