#!/usr/bin/env node
/**
 * 打包产物里**不许**残留裸说明符的动态 import。
 *
 * ★这不是风格检查，是一个已经真实发生过、把整条主链路打死的缺陷：
 *   变量做模块说明符 + @vite-ignore，等于明确告诉 Vite「别管它」，
 *   于是裸模块名原样进了 bundle。浏览器/WebView2 没有 import map，解析不了裸说明符，
 *   运行期抛 `Failed to resolve module specifier '@tauri-apps/api/core'`。
 *
 *   后果：tunnel_start / tunnel_status / tunnel_stop / open_app_url / force_quit
 *   以及 sidecar 敲门**在打包后的客户端里全是死的**。点「接入」什么都不会发生——
 *   不弹 UAC、不建网卡、服务端一条记录都没有，看起来就像「客户端没反应」。
 *
 *   为什么单测与 dev 都发现不了：dev 走浏览器时 tauriRuntime() 为 false，
 *   这些路径根本不进；而打包后的客户端在 2026-08-18 之前从没在真机上被点过「接入」。
 *   两处（tunnel.ts / knock.ts）从 2026-07-01 起就是坏的。
 *
 * 判据：产物里出现 import("<不以 . 或 / 开头的东西>") 即失败。
 * Vite 正常处理过的动态 import 会被改写成相对路径，不会命中。
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(process.cwd(), 'dist', 'assets');
if (!existsSync(dir)) {
  console.error('X 找不到 dist/assets——先跑 npm run build');
  process.exit(1);
}
const bad = [];
for (const f of readdirSync(dir).filter((n) => n.endsWith('.js'))) {
  const src = readFileSync(join(dir, f), 'utf8');
  for (const m of src.matchAll(/import\(\s*["']([^"'.\/][^"']*)["']\s*\)/g)) {
    bad.push(f + ': import("' + m[1] + '")');
  }
}
if (bad.length) {
  console.error('X 打包产物里残留了裸说明符的动态 import——运行期必然 Failed to resolve module specifier:');
  for (const b of bad) console.error('   ' + b);
  console.error('  改成静态 import（Vite 会打进 bundle）。见本文件头部说明。');
  process.exit(1);
}
console.log('OK 打包产物无裸说明符动态 import');
