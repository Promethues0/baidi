import { fileURLToPath, URL } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig, type Plugin } from 'vite';

/** 控制面演示端点：控制台 POST 编译后的 netmap，客户端（5174）跨端口轮询 GET。
 *  生产环境此角色由 zhulong-control 的 gRPC 推送承担；这里仅为联动演示。 */
function controlPlane(): Plugin {
  let state: unknown = { version: 0, user: 'zhang.wei', resources: [] };
  return {
    name: 'zl-control-plane',
    configureServer(server) {
      server.middlewares.use('/api/netmap', (req, res) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'content-type');
        if (req.method === 'OPTIONS') { res.statusCode = 204; res.end(); return; }
        if (req.method === 'POST') {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            try { state = JSON.parse(body); } catch { /* ignore */ }
            res.setHeader('Content-Type', 'application/json');
            res.end('{"ok":true}');
          });
          return;
        }
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(state));
      });
    }
  };
}

export default defineConfig({
  plugins: [vue(), controlPlane()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  server: {
    host: true, port: 5193,
    // 真实控制面 zhulong-control（:5273）经 /ctl 反代，三能力页对接真实 API
    proxy: { '/ctl': { target: 'http://127.0.0.1:5273', changeOrigin: true, rewrite: (p) => p.replace(/^\/ctl/, '') } }
  },
  preview: { port: 4193 }
});
