import { fileURLToPath, URL } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

// 白帝桌面客户端：dev 5294 / preview 4294；经 /api 反代到 baidi-control(:8090)。
// Tauri 打包时改用同样的 dist 即可（壳层不变）。
export default defineConfig({
  plugins: [vue()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    host: true,
    port: 5294,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8090', changeOrigin: true },
      // dev：本地敲门代理 baidi-knock-agent（生产为 Tauri sidecar，不经此）
      '/knock': { target: 'http://127.0.0.1:8091', changeOrigin: true }
    }
  },
  preview: { port: 4294 }
});
