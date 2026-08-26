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
 * 判据两条，缺一不可：
 *   ① import("<不以 . 或 / 开头的东西>")  —— 字符串字面量形态；
 *   ② import(<标识符>)                    —— **变量形态**。
 *
 * ★②是 2026-08-25 补上的，而它恰恰是这个检查本来要防的那种写法：
 *   源码里写的是 `const mod = '@tauri-apps/api/window'; await import(mod)`，
 *   Vite 打出来就是 `const v="@tauri-apps/api/window", await import(v)` ——
 *   参数是变量，①的正则**匹配不到**。于是 App.vue 里两处漏网的写法带着这道
 *   "已通过"的检查一路发到真机：无边框窗口的三个窗控键、以及托盘「退出白帝」
 *   的二次确认（隧道运行中会唤起它）在打包后全是死的。
 *   一个写得比它声称的更窄的守卫，比没有守卫更坏——它会让人以为这条已经守住了。
 *
 * Vite 正常处理过的动态 import 会被改写成相对路径字面量（"./chunk-xxx.js"），
 * 两条判据都不会命中；真要按变量分发模块的场景，请显式改成静态 import 或
 * 相对路径字面量——本项目没有需要运行期拼模块名的地方。
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
  // ① 字符串字面量形态
  for (const m of src.matchAll(/import\(\s*["']([^"'.\/][^"']*)["']\s*\)/g)) {
    bad.push(f + ': import("' + m[1] + '")');
  }
  // ② 变量形态：import(<标识符>)。顺带把该变量被赋的值找出来一并报出去，
  //    否则报一句 import(v) 没人知道该去改哪一行源码。
  for (const m of src.matchAll(/import\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    const id = m[1];
    const assign = new RegExp('\\b' + id.replace(/\$/g, '\\$') + '\\s*=\\s*["\']([^"\']+)["\']').exec(src);
    bad.push(f + ': import(' + id + ')' + (assign ? '  ← ' + assign[1] : '  ← 变量值未能静态确定'));
  }
}
if (bad.length) {
  console.error('X 打包产物里残留了裸说明符的动态 import——运行期必然 Failed to resolve module specifier:');
  for (const b of bad) console.error('   ' + b);
  console.error('  改成静态 import（Vite 会打进 bundle）。见本文件头部说明。');
  process.exit(1);
}
console.log('OK 打包产物无裸说明符动态 import');
