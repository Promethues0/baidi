import { fileURLToPath, URL } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

// 白帝移动客户端：dev 5295 / preview 4295；经 /api 反代 baidi-control(:8090)、/knock 反代 dev 敲门代理。
// 打包进 iOS/安卓/鸿蒙 时，webview 加载本 dist，原生壳注入 window.__BAIDI_NATIVE__ 提供 VPN 能力（见 lib/vpn.ts）。
export default defineConfig({
  plugins: [vue()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    host: true,
    port: 5295,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8090', changeOrigin: true },
      '/healthz': { target: 'http://127.0.0.1:8090', changeOrigin: true },
      '/knock': { target: 'http://127.0.0.1:8091', changeOrigin: true }
    }
  },
  preview: { port: 4295 }
});
