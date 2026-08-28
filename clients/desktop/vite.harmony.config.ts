import { fileURLToPath, URL } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

/**
 * 鸿蒙壳的前端构建：**直接用本目录这套 Vue 源码**（桌面布局），
 * 只把 Tauri 的三个 API 模块 alias 到 ../harmony/webui/shim。
 *
 * ★配置文件放在 desktop 而不是 harmony 下，是因为 vite 以配置文件所在目录解析
 * 插件依赖（@vitejs/plugin-vue 等只装在这里）。shim 仍在 harmony 侧——
 * 那是鸿蒙独有的东西。
 *
 * ★为什么不把 desktop 的源码拷一份过来：拷贝会立刻分叉——桌面端修了缺陷，
 * 鸿蒙端这份不会跟着变，而两者是同一个产品的同一套界面。alias 让它们**共用一份源码**，
 * 差异收敛在 shim/ 里那三个文件。
 *
 * base=./ 是必需的：ArkWeb 从 resource://rawfile/ 加载，绝对路径会 404。
 */
const desktop = fileURLToPath(new URL('.', import.meta.url));
const shim = fileURLToPath(new URL('../harmony/webui/shim', import.meta.url));

export default defineConfig({
  root: desktop,
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@tauri-apps/api/core': `${shim}/core.ts`,
      '@tauri-apps/api/event': `${shim}/event.ts`,
      '@tauri-apps/api/window': `${shim}/window.ts`,
      '@': `${desktop}/src`
    }
  },
  build: {
    outDir: fileURLToPath(new URL('../harmony/webui/dist', import.meta.url)),
    emptyOutDir: true
  }
});
