// node ESM 的 resolve 钩子：把 `./store` 这类**省略扩展名**的相对导入补成 `./store.ts`。
//
// ★为什么需要：src/ 里的相对导入是按 Vite 的解析规则写的（省扩展名），而 node 的 ESM
//   解析器不做扩展名补全。没有这个钩子，tests/ 就只能 import 那些"零依赖的纯逻辑文件"
//   （tunnelwatch.ts），碰不到 vpn.ts —— 而接线的错正好都在 vpn.ts 里。改造前的接线守卫
//   因此只能对源码做子串匹配，两个破坏语义的变异（无条件启动监视 / 把 stopTunnelWatch
//   挪到 await 之后）都能全绿地混过去。有了它，假桥 + 假计时器就能对 vpn.ts 做**真行为测试**。
//
// 只补相对路径、只补 .ts、补不上就原样回落：不改变任何 node_modules 的解析。
export async function resolve(specifier, context, next) {
  if (/^\.{1,2}\//.test(specifier) && !/\.[cm]?[jt]s$/.test(specifier)) {
    try {
      return await next(specifier + '.ts', context);
    } catch {
      /* 不是 .ts（或压根不存在）：交回默认解析，让它报原本的错 */
    }
  }
  return next(specifier, context);
}
