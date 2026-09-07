#!/usr/bin/env node
/**
 * 构建期守卫：装饰性控件与死占位。
 *
 * 这两条都不是风格问题，是本项目反复出现的一个缺陷族——「配置面齐全、零报错、
 * 功能是死的」。它们在页面上与能用的版本**长得一模一样**，管理员会怀疑自己而不是
 * 怀疑页面，type-check 与 build 也都照过。
 *
 * 规则一：`class="bd-searchbox"` 的元素内必须有 <input。
 *   Users / Resources / Apps 三页的搜索框曾长期是 `<div class="bd-searchbox">` +
 *   一个图标 + 一句静态中文，而同一套 UI 在 Objects / Online / Ipsec / System
 *   四页是真的。在那边搜过、有效，到这三页照做发现点不动。
 *
 * 规则二：禁止 `void <标识符>;`。
 *   `void loadCats()` 这类**带括号**的是丢弃 Promise，合法；而 `void _shown;`
 *   ——把一个只声明未使用的 computed 交给 void 堵住编译器——是在承认「这段没接线」
 *   并让守卫闭嘴。Resources.vue 里那句 `const _shown = computed(() => resources.value);
 *   // 预留搜索过滤位` 就这么活了很久。
 *
 * 规则三：失败必须转述后端原话。两条子规则，缺一不可。
 *
 *   3a：catch **没有把异常用起来**，却报了一句编造的失败归因。
 *   全仓曾有二十多处写成
 *       } catch { Message.error('删除失败，请检查权限或后端连接'); }
 *   而后端回的是「分类下仍有 3 个应用，请先改归属」「最后一名超级管理员不可禁用」
 *   「角色「审计管理员」无权执行该操作（需要权限：security）」——**唯一能指导下一步动作**
 *   的那句话，被 catch 那一行整句丢掉，换成一个猜的原因。管理员照着提示去查网络、
 *   去重登，而真正的原因就在被丢掉的字符串里。api.ts 在 errText 上方写下过这条纪律，
 *   然后每一个调用点都没照做——这正是本项目里出现频率最高的「纪律只做了一半」。
 *   收口在 api.ts 的 failReason(e)：接住 e，把后端原话原样转述。
 *
 *   ★判据是「有没有用住 e」，不是「写没写 `catch (e)`」。这道区分是本条规则的全部价值：
 *     改好的写法（`catch (e)` + failReason(e)）与漏掉的写法（`catch (e)` 但正文里
 *     一次都没提 e）在源码里长得几乎一样，只按 `} catch {` 匹配的话，
 *     任何人把参数补上、正文原样不动，守卫立刻失明而缺陷分毫未减。
 *   ★呈报方式也不限于 Message/Modal：登录页那两处是 `err.value = '…'`——
 *     这一族恰恰因为守卫只看 Message/Modal 而**整族逃掉**，而其中被吞掉的
 *     403「登录失败次数过多，已被临时锁定，请约 N 分钟后重试」是防爆破唯一的说明面：
 *     一个人连错 5 次，同一 NAT 出口的所有人在 15 分钟里都看到「网络异常，请稍后重试」。
 *
 *   3b：不得拿异常**文案**去匹配状态码数字（`msg.includes('403')`）。
 *   api() 抛的是 `ApiError(后端中文原文, status)`，而 httpx.Error 只发
 *   `{"error":{"message":…}}`，message 里永远没有状态码数字——这类分支**恒不命中**，
 *   而它长得像已经处理过了。System.vue 的 opError 曾靠两支这样的死分支服务 14 个
 *   写操作调用点，实际每一次失败都落到最后那句「保存失败」。判状态码只有一个东西
 *   能用：api.ts 的 failStatus(e)。
 *
 * 规则四：nav.ts 里每个 `done: true` 的叶子 path 必须在 router.ts 的 BUILT 里。
 *   路由是生成式的：nav.ts 定义 IA，router.ts 按 BUILT[path] 映射到真实组件，
 *   **映射不到就静默落到 ComingSoon**——侧栏照常有这一项、点进去是占位页、
 *   type-check 与 build 都不报。CLAUDE.md 写着「21 页全部真实组件」，这句话此前没有
 *   任何执行方：新加一个 done 叶子却忘了在 BUILT 里登记，或改了 path 只改一边，
 *   页面上看起来就是"这个功能还没做"。这条守卫让那句话有人守。
 *
 * 规则五：styles/tokens.css 必须能被完整解析（:root 块在、--bd-* 声明够数、值非空、
 *   剥掉注释后不残留任何注释定界符、没有哪条注释把声明吞进去）。
 *   上一轮真实踩到：有人在 tokens.css 的注释里写了带通配符的 Arco 变量名（--primary-N /
 *   --color-N 那种写法，把 N 换成星号），「星号+斜杠」把注释提前闭合 → 注释剩下的半截
 *   变成 CSS 正文 → 浏览器按错误恢复规则吃掉紧随其后的 :root 块 → 88 个 --bd-* 一个都
 *   没定义 → 全站 token 归零、页面裸奔。而 type-check（CSS 不进 vue-tsc）、vite build
 *   （对无效 CSS 原样透传）、上面四条规则全绿。这是「配置齐全、零报错、功能是死的」
 *   那个缺陷族在样式层的形态，且发生在**所有页面共用的那一个文件**上。
 *
 * 规则六：每一处 var(--bd-xxx) 引用，src 下必须有对应的 `--bd-xxx:` 声明。
 *   设计系统那一轮查出来：--bd-line（Apps / Nat / Reports / Upgrade 的分隔线）、--bd-fill2
 *   （Overview 口径说明条、Gateway 弱化标签的底色）、--bd-bg-1、--bd-danger-1 在 tokens.css 里
 *   根本不存在，却被引了十余处。引用一个没声明的自定义属性，浏览器**不报错**：var() 在
 *   computed-value time 判为无效，那条属性回落到 initial 或 inherit（按属性自身是否继承）——
 *   border-top 消失、background 变透明、color 随父级，页面上只是"少了一条线 / 没了底色"，
 *   与"设计师就是这么设计的"完全同形。type-check 不看 CSS，vite build 对 var() 原样透传。
 *   那一轮给几个拼写补了别名，但没立守卫——下一个手滑的人照样零报错。规则五守的是
 *   「声明那一侧整段消失」，这条守的是「引用那一侧写错了名」，两边各缺一半。
 *   声明集合 = src 下全部 .css / .vue 里的样式表声明 `--bd-xxx:`（tokens.css 为主，组件内局部声明也算；
 *   先剥注释、剥 <script>——字符串里的 '--bd-x: 1px' 只是一段文本，不是声明），
 *   **加上**运行期声明：`:style="{ '--bd-x': v }"` / script 里样式对象的 `'--bd-x':` 键 /
 *   `el.style.setProperty('--bd-x', v)`——它们由 Vue 或 DOM 在运行期写成真实的自定义属性，
 *   CLAUDE.md「自定义变量一律 --bd-*」正要求把运行期变量也起成这个前缀；此前守卫只认样式表那一种
 *   形状，谁按约定写了个运行期 --bd-* 并在 <style> 里 var() 它，守卫就把它报成"未声明"——
 *   一条会误报的守卫会被人习惯性忽略，或逼人把变量改成不带前缀的名字去躲它。
 *   引用集合 = 同一批文件（含 .ts）里所有 var(--bd-xxx …)，含带回退值的 var(--bd-x, #fff)（回退值挡得住
 *   "没颜色"，挡不住"引的是个不存在的名字"这件事本身），也含 <script> 里给 :style / SVG 属性
 *   准备的 'var(--bd-x)' 字面量——它们最终一样要由浏览器解出来。
 *   只判「有没有声明」，不判「声明在这条引用的祖先链上是否可达」（那要做级联分析，刻意不做）；
 *   方向是漏报不误报。
 *
 * 规则七：模板与图标表里用到的 Arco 图标必须真的在图标集里。
 *   图标是 main.ts 里 app.use(ArcoVueIcon) **全局注册**的：模板里的 <icon-xxx> 对 vue-tsc 只是一个
 *   任意自定义元素，'IconXxx' / 'icon-xxx' 字面量对它只是字符串——两种写法 type-check 都照绿。
 *   浏览器里则是：Vue 解析不到组件 → 把它当原生自定义元素原样输出 <icon-pulse></icon-pulse> → 那个
 *   位置是一块空白，与"设计上就没放图标"完全同形。模板标签形式至少还伴随一条 warn「Failed to resolve
 *   component: icon-pulse」（侧栏「运维诊断」卡就这么空了几个月，六页每次加载 4 条 warn 无人看）；
 *   而 <component :is="'IconAppstore'"> 的字面量形式**连 warn 都没有**——Vue 的 resolveDynamicComponent
 *   对字符串刻意不告警（headless 实测：全局搜索「应用」分组渲染成 <iconappstore> 宽 0、控制台零条），
 *   passkey 登录/管理页那四处 icon-fingerprint 也是同一形态。三种形式里只有 import 的标识符会被 tsc 拦。
 *   图标集 = node_modules/@arco-design/web-vue/es/icon 下的 icon-* 目录名，注册名按 Vue 的
 *   resolveComponent 同一套规则换算：kebab → camelize → capitalize（icon-check-circle-fill ↔
 *   IconCheckCircleFill；287 个目录的 name 字段已逐个核对与此换算一致）。
 *   用法三种形状都收：① 模板里的 <icon-xxx 标签（剥 <script>/<style>，只看模板）；② 引号里的
 *   'icon-xxx'（Auth / PortalApps 经 <component :is> 用 kebab 字符串）；③ 引号里的 'IconXxx'
 *   （nav.ts / Diag / GlobalSearch 的图标表）。②③ 在 .vue 与 .ts 里都扫——nav.ts 的 icon 表最终也是
 *   AppLayout 的 <component :is> 在消费。import { IconX } from '…/icon' 这种标识符形式不用管：写错 tsc 会报。
 *   Arco 没有 icon-ok / icon-pulse / icon-fingerprint / icon-appstore 这类"听起来该有"的名字，
 *   报错时顺带给出拼写相近的候选（同规则六的口径，只提示不猜）。
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');

function walk(dir, ext = /\.(vue|ts)$/) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, ext));
    else if (ext.test(name)) out.push(p);
  }
  return out;
}

/** 从 `class="bd-searchbox"` 起，按同名标签深度找到该元素的内容。 */
function searchboxBody(text, at) {
  const open = text.lastIndexOf('<', at);
  const tagEnd = text.indexOf('>', at);
  if (tagEnd < 0) return '';
  if (text[tagEnd - 1] === '/') return ''; // 自闭合 → 必然无输入
  const tag = text.slice(open + 1, tagEnd).split(/[\s>/]/)[0];
  let depth = 1;
  const re = new RegExp(`<(/?)${tag}\\b`, 'g');
  re.lastIndex = tagEnd + 1;
  let m;
  while ((m = re.exec(text))) {
    depth += m[1] ? -1 : 1;
    if (depth === 0) return text.slice(tagEnd + 1, m.index);
  }
  return text.slice(tagEnd + 1);
}

/**
 * 剥注释（HTML / 块 / 行），保留字节偏移与换行以便行号仍然准确。
 * ★不剥的话，**解释旧缺陷的注释本身**会触发守卫——这次就是：修好之后在注释里写
 * 「原先是 `void _shown;`」，守卫立刻把它报成死占位。那会逼着人删掉解释，
 * 而解释正是这些修复里最该留下的东西。
 * 误剥字符串里的 `//`（如 URL）只会导致漏报，不会误报，方向是安全的。
 */
function stripComments(text) {
  return text
    .replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
}

/**
 * 从 `{` 处按花括号配平取出整块正文。
 * ★规则 3a 必须看**整块**而不是"随后 3 行"：真实的 catch 块经常先复位几个 ref、
 * 再在第 5 行报话（System.vue 的两处 loadXxx 就是），按行数截断会漏掉它们。
 * 输入已剥过注释（注释被换成等长空白），所以注释里的花括号不会把配平算歪。
 */
function braceBody(text, braceAt) {
  let depth = 0;
  for (let i = braceAt; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) return text.slice(braceAt + 1, i);
    }
  }
  return text.slice(braceAt + 1);
}

/**
 * 「向用户报了一句话」的两种形态：
 *   ① Message.error('…') / Modal.warning({ … content: '…' }) 这类调用；
 *   ② `err.value = '…'` / `errMsg.value = '…'` / `pwMsg.value = '…'` 这类赋值。
 * ★形态②必须收进来：登录页那一族全是它，而守卫此前只认①，于是整族逃掉了——
 *   包括后果最坏的那处（防爆破 403 被说成「网络异常或服务不可达，请稍后重试」）。
 */
const SAY_RE =
  /(?:Message\.(?:error|warning|info)|Modal\.(?:warning|error|info))\(\s*['`]([^'`]*)['`]|\b[\w.$]*(?:err|msg|error)[\w.$]*\s*(?:\.value\s*)?=\s*['`]([^'`]*)['`]/gi;

/** 猜测性归因词表：只收那几个真正把人支到错误方向去的说法。 */
const BLAME_RE =
  /(后端连接|后端在线|网络|检查权限|管理员权限|重新登录|需已连|不可达|连接控制中心|未连控制|可能已过期|稍后重试)/;

const errors = [];
for (const file of walk(SRC)) {
  const text = stripComments(readFileSync(file, 'utf8'));
  const rel = relative(ROOT, file);

  // ★类名要精确到词：`bd-searchbox__in` 是输入框自己的类，
  // 用 /bd-searchbox[^"]*/ 会把它一起匹配上，于是每个**已修好**的搜索框
  // 都被报成装饰性的——一道会误报的守卫比没有守卫更坏，它会被人习惯性忽略。
  const boxRe = /class="(?:[^"]*\s)?bd-searchbox(?=[\s"])[^"]*"/g;
  let m;
  while ((m = boxRe.exec(text))) {
    if (!/<input\b/.test(searchboxBody(text, m.index))) {
      const line = text.slice(0, m.index).split('\n').length;
      errors.push(
        `${rel}:${line} 搜索框里没有 <input>：这是一个装饰性控件。` +
          `它与 Objects/Online 那几个能用的搜索框长得一样，管理员点不动会怀疑自己。` +
          `要么接上真过滤（过滤字段与占位文案逐字对应），要么把它删掉。`
      );
    }
  }

  const voidRe = /(^|[\s;{}])void\s+([A-Za-z_$][\w$]*)\s*;/gm;
  while ((m = voidRe.exec(text))) {
    // ★行号要从 `void` 那个字算起，不是从 m.index 算起：前导组 `(^|[\s;{}])` 会把 void
    //   前面的**换行**一起吃进匹配（绝大多数命中都是这一档，因为 `void _x;` 通常独占一行），
    //   于是 m.index 落在上一行的行尾，`slice(0, m.index)` 数出来的行号恒少 1。
    //   报错信息里带的是 `file:line`，编辑器与终端都会照着它跳转——**跳到上一行看不到 void，
    //   人会以为守卫报错了**，而这条规则拦的恰恰是"不该被忽略的死占位"。
    //   加上 m[1].length 把这个换行算回来；m[1] 是行内空白或 `;{}` 时长度不跨行，结果不变。
    const line = text.slice(0, m.index + m[1].length).split('\n').length;
    errors.push(
      `${rel}:${line} 死占位 \`void ${m[2]};\`：` +
        `这是把一个未接线的声明交给 void 堵住编译器。` +
        `接上它，或者连同声明一起删——留着会让人以为功能存在。`
    );
  }

  // ── 规则 3a：catch 没用住异常，却编造了失败归因 ──
  //
  // 只拦**同时满足**两条的写法，避免误伤：
  //   ① catch 正文里一次都没提到被捕获的那个绑定（没写参数，或写了但没用）
  //      ——用住了才有可能转述后端原话；
  //   ② 正文里向用户报了一句带「猜测性归因」的话。
  // 归因词表故意只收那几个真正误导人的说法（连接/网络/权限/登录/不可达/已过期），
  // 「复制失败，请手动复制」这类**与后端无关**的本地失败不在其中。
  const catchRe = /\bcatch\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)\s*)?\{/g;
  while ((m = catchRe.exec(text))) {
    const line = text.slice(0, m.index).split('\n').length;
    const body = braceBody(text, m.index + m[0].length - 1);
    // 用住 = 正文里出现该标识符。这是有意放宽的一侧：宁可漏报也不误报——
    // 一道会误报的守卫会被人习惯性忽略，那时它连真的都守不住了。
    if (m[1] && new RegExp(`\\b${m[1]}\\b`).test(body)) continue;
    let s;
    const said = [];
    SAY_RE.lastIndex = 0;
    while ((s = SAY_RE.exec(body))) {
      const lit = s[1] ?? s[2];
      if (lit && BLAME_RE.test(lit)) said.push(lit);
    }
    if (!said.length) continue;
    errors.push(
      `${rel}:${line} catch 没有用住异常，却编造了失败归因「${said[0]}」：` +
        `后端的拒绝原因（403 防爆破锁还剩几分钟、403 缺哪个权限、409 撞了哪道守卫、` +
        `400 新口令差在哪一条）在这里被整句丢掉了。` +
        `改成 \`catch (e)\` 并用 api.ts 的 failReason(e) 原样转述。`
    );
  }

  // ── 规则 3b：拿异常文案去匹配状态码数字 = 恒不命中的死分支 ──
  const deadRe = /\.(?:includes|startsWith|endsWith|indexOf|search|match)\(\s*['"`]\s*[1-5]\d\d\b/g;
  while ((m = deadRe.exec(text))) {
    const line = text.slice(0, m.index).split('\n').length;
    errors.push(
      `${rel}:${line} 拿文案匹配状态码 \`${m[0].trim()}…\`：这是一条恒不命中的死分支。` +
        `api() 抛的是 ApiError(后端中文原文, status)，而 httpx.Error 只发 ` +
        `{"error":{"message":…}}，message 里永远没有状态码数字。` +
        `判状态码用 api.ts 的 failStatus(e)，措辞用 failReason(e)。`
    );
  }
}

// ── 规则四：done 叶子必须在 BUILT 里 ──
//
// 两边都按源码正则取，不去 import 那两个 TS 模块（脚本跑在 node 里，router.ts 顶层就 createRouter）。
// nav.ts 的叶子形如 `{ title: '…', path: '/monitor/overview', …, done: true }`（单行一项）；
// router.ts 的 BUILT 形如 `'/monitor/overview': () => import('@/views/Overview.vue'),`。
// 正则取不到任何一项也算失败：那是格式变了让守卫失明，不是"没有叶子"。
{
  const navText = stripComments(readFileSync(join(SRC, 'nav.ts'), 'utf8'));
  const routerText = stripComments(readFileSync(join(SRC, 'router.ts'), 'utf8'));
  const doneLeaves = [];
  const leafRe = /\{[^{}\n]*\bpath:\s*'([^']+)'[^{}\n]*\bdone:\s*true[^{}\n]*\}/g;
  let m;
  while ((m = leafRe.exec(navText))) doneLeaves.push(m[1]);
  const builtBlock = /const BUILT\b[^=]*=\s*\{([\s\S]*?)\n\};/.exec(routerText)?.[1] ?? '';
  const built = new Set();
  const builtRe = /^\s*'([^']+)'\s*:/gm;
  while ((m = builtRe.exec(builtBlock))) built.add(m[1]);
  if (!doneLeaves.length || !built.size) {
    errors.push(
      `src/nav.ts / src/router.ts 规则四取数为空（done 叶子 ${doneLeaves.length} 个、BUILT ${built.size} 项）：` +
        `两处写法变了，守卫读不到——改守卫的正则，别让它静默通过。`
    );
  }
  // ★第二道自检：解析出的叶子数必须等于 nav.ts 里 `done: true` 的出现次数。
  //   上面那道只拦「一个都取不到」，而 leafRe 要求 **path 与 done 在同一行、且 path 在 done 之前**——
  //   把某个叶子拆成两行写、或把 path 挪到 done 后面，正则就漏掉它一个，而其余 20 个仍在，
  //   `doneLeaves.length` 非零、循环照跑、脚本照绿：**守卫对那一项彻底失明**，
  //   而它恰恰是新加/刚改过的那一项——最需要被守的那个。计数比对让「部分失明」也说得出话来。
  //   计数用剥过注释的 navText，与 leafRe 同源；否则注释掉的示例会让两边天然对不上。
  const doneMarks = (navText.match(/\bdone:\s*true\b/g) || []).length;
  if (doneMarks !== doneLeaves.length) {
    errors.push(
      `src/nav.ts 有 ${doneMarks} 个 \`done: true\`，但规则四只解析出 ${doneLeaves.length} 个叶子：` +
        `差的 ${doneMarks - doneLeaves.length} 个守卫读不懂（正则要求 path 与 done 写在同一行、且 path 在前），` +
        `它们的 BUILT 映射不会被检查——把那几项写回单行形式，或同时改守卫的正则。`
    );
  }
  for (const p of doneLeaves) {
    if (!built.has(p)) {
      errors.push(
        `src/nav.ts 的 done 叶子 ${p} 不在 src/router.ts 的 BUILT 里：` +
          `侧栏会有这一项，点进去是 ComingSoon 占位页，而 build 与 type-check 都不会报。` +
          `在 BUILT 里登记它对应的真实组件，或把 nav.ts 里的 done 去掉。`
      );
    }
  }
}

// ── 规则五：tokens.css 解析完整性 ──
//
// 三条判据合起来才够，缺一条就有一种形态漏网：
//   (a) :root 块存在且 --bd-* 声明 ≥ MIN_BD_DECLS —— 拦「:root 被吞掉 / 声明整段消失」；
//       阈值刻意远低于当前数量（写 88 这种"当前值"会让每一次正常增删都变红，然后被人调成
//       任意数）——它要拦的是"归零"，不是"少了两条"。
//   (b) 剥掉注释后正文里不许再有 `*/` 或 `/*` —— 前者 = 某条注释被提前闭合、后半截漏成了正文
//       （就是上一轮那次）；后者 = 某条注释没闭合、后面整段声明都在注释里。(a) 单独拦不住 (b)：
//       提前闭合发生在 :root 之前时，:root 本身完好、声明一条不少，破坏的是它前面那段正文，
//       浏览器的错误恢复会从那里一直吃到下一个 `;` 或 `}`——恰好把 `:root {` 吃掉。
//   (c) 每条 --bd-* 的值非空 —— 拦 `--bd-x: ;` 这类被截断到只剩名字的声明。
//   (d) 被剥掉的注释里不许有整行的 `--bd-x: …;` —— 这是变异测试暴露出来的第四种形态：
//       某条注释漏了闭合，CSS 规则（与 stripComments 的非贪婪正则一致）是它一直延伸到**下一条**
//       注释的结尾，于是夹在中间的两三条声明被吞进注释里。(a) 拦不住（88 → 86 仍远高于下限，
//       而下限刻意不能贴着当前值写），(b) 也拦不住（残片一个都没有——那个「下一条注释的结尾」
//       正好把它闭合了）。但被吞掉的声明本身留在注释体里，形状是"行首缩进 + --bd-名: 值;"，
//       而人写的注释里提到变量名从来不带 `: 值;` 且不会顶在行首——按这个形状查注释体即可。
{
  const MIN_BD_DECLS = 60;
  const cssPath = join(SRC, 'styles', 'tokens.css');
  const cssRel = relative(ROOT, cssPath);
  // 复用 stripComments：CSS 只有块注释一种，它剥得对；它顺带把 `//` 到行尾也剥掉，CSS 里没有这种
  // 注释，但 url(https://…) 这类值会丢后半截——值仍非空，只会漏报不会误报，方向安全。
  // 偏移与换行都保留，所以下面报出的行号就是 tokens.css 里的真实行号。
  const raw = readFileSync(cssPath, 'utf8');
  const css = stripComments(raw);
  const lineOf = (idx) => css.slice(0, idx).split('\n').length;
  let m;

  const fragRe = /\*\/|\/\*/g;
  while ((m = fragRe.exec(css))) {
    if (m[0] === '*/') {
      // 残片本身是那条注释**真正的**结尾；把人提前放出来的那个「星号+斜杠」是 raw 里它前面
      // 最近的一个 `*/`（stripComments 就是在那里停的）。两处行号都报：改的是前者所在那行。
      const closeAt = raw.lastIndexOf('*/', m.index - 1);
      const where = closeAt >= 0 ? `第 ${lineOf(closeAt)} 行的注释被提前闭合` : `前面某条注释被提前闭合`;
      errors.push(
        `${cssRel}:${lineOf(m.index)} 剥掉注释后仍残留「*/」：${where}` +
          `（注释里写了「星号+斜杠」的字样，常见的是带通配符的变量名），它后半截已成为 CSS 正文，` +
          `浏览器会从那里一直吃到下一个分号或右花括号——整个 :root 块随之作废、全站 token 归零，` +
          `而 type-check 与 vite build 都不报。把那个字样换成文字描述（如「--primary-N」）。`
      );
    } else {
      errors.push(
        `${cssRel}:${lineOf(m.index)} 剥掉注释后仍残留「/*」：这条注释没有闭合，` +
          `它后面的全部声明都在注释里，浏览器一条都读不到。补上闭合，或检查上一处「星号+斜杠」。`
      );
    }
  }

  // (d) 注释体里出现了整行的声明 = 那条注释把声明吞了。逐条注释查，报注释起始行与被吞的那条。
  const commentRe = /\/\*[\s\S]*?\*\//g;
  const swallowedRe = /^[ \t]*(--bd-[\w-]+)\s*:[^;\n]*;/m;
  while ((m = commentRe.exec(raw))) {
    const hit = swallowedRe.exec(m[0]);
    if (!hit) continue;
    errors.push(
      `${cssRel}:${lineOf(m.index)} 这条注释把声明 \`${hit[1]}\`（第 ${lineOf(m.index + hit.index)} 行）吞进去了：` +
        `它自己没有闭合，按 CSS 规则一直延伸到下一条注释的结尾，中间的声明全部作废——` +
        `页面上对应的 var() 静默回落而两道守卫都不报。给它补上闭合。` +
        `（若那确实是注释里的示例，别把它顶在行首、也别带结尾分号。）`
    );
  }

  const rootAt = /:root\s*\{/.exec(css);
  if (!rootAt) {
    errors.push(
      `${cssRel} 剥掉注释后找不到 \`:root {\` 块：全部 --bd-* 变量都定义在它里面，` +
        `没有它页面上每一处 var(--bd-…) 都会回落到浏览器默认值。`
    );
  } else {
    const body = braceBody(css, rootAt.index + rootAt[0].length - 1);
    const declRe = /(--bd-[\w-]+)\s*:([^;{}]*);/g;
    let n = 0;
    while ((m = declRe.exec(body))) {
      n++;
      if (!m[2].trim()) {
        errors.push(
          `${cssRel}:${lineOf(rootAt.index + rootAt[0].length + m.index)} \`${m[1]}\` 的值是空的：` +
            `一条空值的自定义属性会让每一处 var(${m[1]}) 静默回落到浏览器默认值。`
        );
      }
    }
    if (n < MIN_BD_DECLS) {
      errors.push(
        `${cssRel} 的 :root 里只解析出 ${n} 条 --bd-* 声明（下限 ${MIN_BD_DECLS}）：` +
          `要么大段声明被一条没闭合的注释吞掉了，要么 tokens.css 的写法变了让守卫读不懂——` +
          `两种都不该静默通过。`
      );
    }
  }
}

// ── 规则六：引用的 --bd-* 必须有声明 ──
//
// 声明与引用都按源码正则取，不去解析 CSS（scoped 样式、<style> 里的嵌套写法都不影响"名字在不在"）。
// 剥注释与规则一至五同源（stripComments），行号因此就是文件里的真实行号；
// .vue 的**样式表**声明集合另剥 <script>（字符串里的 '--bd-x: 1px' 只是文本，不是声明），
// **运行期**声明（`'--bd-x':` 对象键 / setProperty('--bd-x', …)）反过来要在全文里找——它们就写在
// <script> 与 :style 里；引用集合不剥（script 里给 :style / SVG 属性准备的 'var(--bd-x)' 一样要能解出来）。
// 取数为空也算失败：那是格式变了让守卫失明，不是"没有引用"。
{
  const stripScript = (t) =>
    t.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, (m) => m.replace(/[^\n]/g, ' '));
  // 声明形如 `--bd-x:`，前面不能紧挨字母/连字符（`--x--bd-y:` 这种拼接名不算声明了 `--bd-y`）。
  // `var(--bd-x)` 后面没有冒号，天然匹配不上——声明与引用两个形状彼此排他。
  const declRe = /(?<![\w-])(--bd-[\w-]+)\s*:/g;
  // 运行期声明两种形状：`'--bd-x':`（:style 对象 / script 样式对象的键，引号紧贴名字两侧、随后是冒号）
  // 与 `setProperty('--bd-x',`。引号里带了冒号的 '--bd-x: 1px' 匹配不上——那是文本不是声明。
  // ★这一侧刻意放宽：一个与样式无关、恰好以 '--bd-x' 为键的对象（比如给文档页列 token 说明）也会被
  //   当成声明——方向是漏报不误报，与本规则其它判据同向。
  const runtimeDeclRe = /(?:(['"`])(--bd-[\w-]+)\1\s*:|setProperty\(\s*(['"`])(--bd-[\w-]+)\3\s*,)/g;
  // 引用形如 `var(--bd-x` / `var( --bd-x`，后面跟 `)` 或 `, 回退值` 都算——名字对不对与有没有回退无关。
  const refRe = /var\(\s*(--bd-[\w-]+)/g;
  const declared = new Set();
  const refs = [];
  // .ts 也进来：它没有样式表声明，但可以有运行期声明（composable 返回的样式对象）与 'var(--bd-x)' 引用。
  for (const file of walk(SRC, /\.(vue|css|ts)$/)) {
    const rel = relative(ROOT, file);
    const raw = readFileSync(file, 'utf8');
    const forRefs = stripComments(raw);
    const forDecls = file.endsWith('.vue') ? stripComments(stripScript(raw)) : file.endsWith('.css') ? forRefs : '';
    let m;
    while ((m = declRe.exec(forDecls))) declared.add(m[1]);
    if (!file.endsWith('.css')) {
      while ((m = runtimeDeclRe.exec(forRefs))) declared.add(m[2] ?? m[4]);
    }
    while ((m = refRe.exec(forRefs))) {
      refs.push({ rel, line: forRefs.slice(0, m.index).split('\n').length, name: m[1] });
    }
  }
  if (!declared.size || !refs.length) {
    errors.push(
      `src/**/*.{css,vue,ts} 规则六取数为空（声明 ${declared.size} 个、引用 ${refs.length} 处）：` +
        `tokens.css 或页面样式的写法变了，守卫读不到——改守卫的正则，别让它静默通过。`
    );
  }
  // 给一个"可能想写的是"：把连字符抹掉后比对——相等（--bd-fill2 ↔ --bd-fill-2），或一方是另一方的
  // 前缀/后缀且短的那边 ≥ 4 个字符（--bd-mono ↔ --bd-font-mono）。只是提示，候选多于 3 个就不给。
  // ★变异检查里 `--bd-nonexistent2` 曾被任意子串规则提示成 `--bd-t2`——猜错的提示比不提示更误导，
  //   所以不做任意子串、且给短侧设下限。
  const squash = (s) => s.replace(/^--bd-/, '').replace(/-/g, '');
  const hint = (name) => {
    const key = squash(name);
    if (!key) return '';
    const c = [...declared].filter((d) => {
      const k = squash(d);
      if (k === key) return true;
      if (Math.min(k.length, key.length) < 4) return false;
      return k.startsWith(key) || k.endsWith(key) || key.startsWith(k) || key.endsWith(k);
    });
    return c.length && c.length <= 3 ? `可能想写的是 ${c.join(' / ')}；` : '';
  };
  for (const { rel, line, name } of refs) {
    if (declared.has(name)) continue;
    errors.push(
      `${rel}:${line}  var(${name})  未在任何地方声明：` +
        `浏览器不报错，这条属性在 computed-value time 判为无效、回落到 initial/inherit——` +
        `分隔线消失、底色透明、字色随父级，而 type-check 与 vite build 都照绿。` +
        hint(name) +
        `改成 tokens.css 里已有的正名（见 console/DESIGN.md 第 1 节），` +
        `或在 tokens.css 里补声明并注明它是什么；别为了过守卫随手起新名。`
    );
  }
}

// ── 规则七：用到的 Arco 图标必须真的在图标集里 ──
//
// 图标集按 node_modules/@arco-design/web-vue/es/icon 的目录名取（icon-*），注册名按 Vue resolveComponent
// 的规则换算（camelize + capitalize）；用法按源码正则取三种形状（模板标签 / kebab 字面量 / Pascal 字面量）。
// 判据与 Vue 的解析完全同构：模板 <icon-a-b> 与字面量 'icon-a-b' 都换算成 IconAB 再查表，
// 'IconAB' 字面量原样查表——所以 icon-faceBook-circle-fill 这种目录名大小写混写的，
// 写成 <icon-facebook-circle-fill> 一样报缺失（Vue 也解析不到它）。
// 取数为空也算失败：node_modules 没装 / Arco 目录挪位 → 图标集空，每个名字都会"缺失"而不是静默全绿；
// 用法一个都取不到同理（这仓里有几百处）。
{
  const ICON_DIR = join(ROOT, 'node_modules', '@arco-design', 'web-vue', 'es', 'icon');
  const MIN_ICONS = 200;
  const camelize = (s) => s.replace(/-(\w)/g, (_, c) => c.toUpperCase());
  const pascal = (kebab) => { const c = camelize(kebab); return c.charAt(0).toUpperCase() + c.slice(1); };
  let iconDirs = [];
  try {
    iconDirs = readdirSync(ICON_DIR).filter((d) => /^icon-/.test(d) && statSync(join(ICON_DIR, d)).isDirectory());
  } catch {
    iconDirs = [];
  }
  const pascalSet = new Set(iconDirs.map(pascal));
  if (iconDirs.length < MIN_ICONS) {
    errors.push(
      `${relative(ROOT, ICON_DIR)} 只读到 ${iconDirs.length} 个 icon-* 目录（下限 ${MIN_ICONS}）：` +
        `node_modules 没装或 Arco 图标目录挪了位置，规则七读不到图标集——别让它静默通过。`
    );
  }
  const stripBlocks = (t, tag) =>
    t.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}>`, 'g'), (m) => m.replace(/[^\n]/g, ' '));
  const lineAt = (t, i) => t.slice(0, i).split('\n').length;
  // ① 模板标签：`<icon-xxx`（名字到空白 / `>` / `/` 为止）。
  const tagRe = /<(icon-[\w-]*)/g;
  // ② kebab 字面量：引号紧贴两侧的 'icon-xxx'——给 <component :is> 用的。
  const kebabLitRe = /(['"`])(icon-[a-z][\w-]*)\1/g;
  // ③ Pascal 字面量：'IconXxx'——nav.ts / Diag.vue / GlobalSearch.vue 的图标表。
  const pascalLitRe = /(['"`])(Icon[A-Z][A-Za-z0-9]*)\1/g;
  const uses = [];
  for (const file of walk(SRC, /\.(vue|ts)$/)) {
    const rel = relative(ROOT, file);
    const text = stripComments(readFileSync(file, 'utf8'));
    let m;
    if (file.endsWith('.vue')) {
      const tpl = stripBlocks(stripBlocks(text, 'script'), 'style');
      while ((m = tagRe.exec(tpl))) uses.push({ rel, line: lineAt(tpl, m.index), name: m[1], pascal: pascal(m[1]), how: `<${m[1]}>` });
    }
    while ((m = kebabLitRe.exec(text))) uses.push({ rel, line: lineAt(text, m.index), name: m[2], pascal: pascal(m[2]), how: `'${m[2]}'` });
    while ((m = pascalLitRe.exec(text))) uses.push({ rel, line: lineAt(text, m.index), name: m[2], pascal: m[2], how: `'${m[2]}'` });
  }
  if (!uses.length) {
    errors.push(
      `src/**/*.{vue,ts} 规则七取数为空（图标用法 0 处）：模板里的 <icon-…> 与图标表的写法变了，` +
        `守卫读不到——改守卫的正则，别让它静默通过。`
    );
  }
  // "可能想写的是"：抹掉 Icon 前缀与连字符后比对，一方是另一方的前缀/后缀且短侧 ≥ 4 字符；候选多于 3 个不给。
  // 与规则六同一口径：icon-ok 太短，不硬凑一个 icon-check 出来——猜错的提示比不提示更误导。
  const squash = (s) => s.replace(/^Icon/, '').replace(/^icon-/, '').replace(/-/g, '').toLowerCase();
  const hint = (name) => {
    const key = squash(name);
    if (key.length < 4) return '';
    const c = [...pascalSet].filter((d) => {
      const k = squash(d);
      if (k === key) return true;
      if (k.length < 4) return false;
      return k.startsWith(key) || k.endsWith(key) || key.startsWith(k) || key.endsWith(k);
    });
    return c.length && c.length <= 3 ? `拼写相近的有 ${c.join(' / ')}；` : '';
  };
  if (iconDirs.length >= MIN_ICONS) {
    for (const u of uses) {
      if (pascalSet.has(u.pascal)) continue;
      errors.push(
        `${u.rel}:${u.line}  ${u.how}  不在 Arco 图标集里（无 ${u.pascal}）：` +
          `图标是全局注册的，type-check 把它当任意自定义元素/字符串放过；浏览器里那个位置是一块空白，` +
          `与"设计上就没放图标"同形（模板标签还伴随一条 Vue warn，<component :is> 的字面量连 warn 都没有）。` +
          hint(u.name) +
          `对着 ${relative(ROOT, ICON_DIR)}/ 的目录名挑一个真有的（勾是 icon-check，没有 icon-ok）。`
      );
    }
  }
}

if (errors.length) {
  console.error('✗ 装饰性控件 / 死占位守卫未通过：\n');
  for (const e of errors) console.error('  • ' + e);
  console.error(`\n共 ${errors.length} 处。`);
  process.exit(1);
}
console.log('✓ 无装饰性搜索框、无死占位、无编造的失败归因、done 叶子全部映射到真实组件、tokens.css 解析完整、每处 var(--bd-…) 都有声明、每个 Arco 图标名都在图标集里');
