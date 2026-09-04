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
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(vue|ts)$/.test(name)) out.push(p);
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
    const line = text.slice(0, m.index).split('\n').length;
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

if (errors.length) {
  console.error('✗ 装饰性控件 / 死占位守卫未通过：\n');
  for (const e of errors) console.error('  • ' + e);
  console.error(`\n共 ${errors.length} 处。`);
  process.exit(1);
}
console.log('✓ 无装饰性搜索框、无死占位、无编造的失败归因、done 叶子全部映射到真实组件');
