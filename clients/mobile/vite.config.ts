import { fileURLToPath, URL } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';
import pkg from './package.json' with { type: 'json' };

// 白帝移动客户端：dev 5295 / preview 4295；经 /api 反代 baidi-control(:8090)、/knock 反代 dev 敲门代理。
// 打包进 iOS/安卓/鸿蒙 时，webview 加载本 dist，原生壳注入 window.__BAIDI_NATIVE__ 提供 VPN 能力（见 lib/vpn.ts）。
export default defineConfig({
  // ★版本号从 package.json 注入，不在页面上手写。手写的那个字符串必然会
  // 与真实打包版本分家，而它正是「客户端更新检查」与终端合规判定的输入——
  // 报错了的版本号会让服务端算出一个错误的升级结论（见 Profile.vue 的 checkUpdate）。
  define: { __APP_VERSION__: JSON.stringify(pkg.version) },
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
