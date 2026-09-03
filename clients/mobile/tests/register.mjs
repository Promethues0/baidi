// 由 `node --import ./tests/register.mjs` 装上 ts-resolve 钩子（钩子跑在独立线程里，
// 必须经 module.register 注册，不能直接 import）。见 ts-resolve.mjs 的说明。
import { register } from 'node:module';

register('./ts-resolve.mjs', import.meta.url);
