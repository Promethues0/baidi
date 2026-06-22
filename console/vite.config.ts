import { fileURLToPath, URL } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

// 白帝控制台：dev 5193 / preview 4193；管理 API 经 /api 反代到自有后端 baidi-control(:8090)。
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  server: {
    host: true,
    port: 5193,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8090', changeOrigin: true }
    }
  },
  preview: { port: 4193 }
});
