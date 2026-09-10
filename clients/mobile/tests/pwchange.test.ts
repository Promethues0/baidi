/**
 * 首登强制改密（FR-DEPLOY-09）的端上出口 —— 移动端这一半。
 *
 * 失败形态是**零报错的死路**：`BAIDI_SEED_MUST_CHANGE` 默认 1、`handleCreateUser` 对每个
 * 新建普通用户置 `MustChangePw`、管理员每次重置口令同理，于是每台按脚本装出来的机器上、
 * 每一个新用户首次登录，服务端回的都是 `{ok:true, mustChangePassword:true, token:<15min
 * 受限令牌>}`——客户端若只看 `ok && token` 就 login()，界面会 replace('/connect')，
 * 然后应用列表与接入逐个 403，而屏幕上一句解释也没有。
 *
 * 钉三件事：① 判定顺序；② 口令登录与 TOTP 第二回合两条路都接上了；
 * ③ 端上写出来的口令要求与控制面判据同数（写错了，人会照着一条错的规则反复试）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { PW_RULE_HINT, checkNewPassword } from '../src/lib/pwchange.ts';

const here = dirname(fileURLToPath(import.meta.url));
const src = (rel: string) => readFileSync(join(here, '..', rel), 'utf8');
/** 仓库根（clients/mobile/tests → ../../..）：跨轨守卫要读控制面的 Go 源码。 */
const repo = (rel: string) => readFileSync(join(here, '..', '..', '..', rel), 'utf8');

/** 去掉注释后的源码——否定式守卫必须用它（理由见 tunnelwatch.test.ts 的同名函数）。 */
function codeOnly(s: string): string {
  return s
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').filter((l) => !/^\s*(\/\/|\*)/.test(l)).join('\n');
}

test('checkNewPassword：只做后端判不了的那几件事', () => {
  assert.equal(checkNewPassword('', '', 'old'), '请输入新口令');
  assert.equal(checkNewPassword('Abcd@12345', 'Abcd@1234', 'old'), '两次输入的新口令不一致');
  assert.match(checkNewPassword('old', 'old', 'old')!, /不得与原口令相同/);
  assert.equal(checkNewPassword('Abcd@12345', 'Abcd@12345', 'baidi@123'), null);
  // 一个后端会判弱的口令（8 位、命中弱口令表），端上**不拦**：它要被送到后端去，由
  // handleChangePassword 回那句带具体原因的 400，再由 failReason 原样转述。端上复刻一份
  // 强度算法必然与后端漂移，"端上放行而后端拒收" 与 "端上拦下而后端本可接受" 都无从解释。
  assert.equal(checkNewPassword('12345678', '12345678', 'baidi@123'), null);
  // 外部认证源认过的那一回合后端不校验旧口令，此时原口令为空，不能拿它比对。
  assert.equal(checkNewPassword('Abcd@12345', 'Abcd@12345', ''), null);
});

/**
 * ★跨轨契约：端上写给用户看的口令要求，数字必须与控制面 auth 包的判据一致。
 * 对不上的症状最费时间：用户照着「至少 8 位」写了个 8 位口令，后端按 10 位判弱回 400，
 * 他换一个 8 位的、再被拒——而这是每套标准部署里每个新用户的第一个动作。
 */
test('跨轨契约：口令要求文案里的位数取自 control/internal/auth/strength.go', () => {
  const strength = repo('control/internal/auth/strength.go');
  const min = strength.match(/minStrongLen\s*=\s*(\d+)/);
  const long = strength.match(/longPassphraseLen\s*=\s*(\d+)/);
  assert.ok(min, 'strength.go 里必须有 minStrongLen（口令长度下限的唯一定义处）');
  assert.ok(long, 'strength.go 里必须有 longPassphraseLen');
  assert.ok(PW_RULE_HINT.includes(min![1]), `端上要求必须写明至少 ${min![1]} 位`);
  assert.ok(PW_RULE_HINT.includes(long![1]), `端上要求必须写明 ${long![1]} 位长口令的例外`);
  assert.match(PW_RULE_HINT, /三类/);
  // 「含账号名」是实践中最常被撞上的那条（zhang.wei → Zhangwei2024），
  // 只说"要复杂"的提示对它完全没有指导作用。
  assert.match(PW_RULE_HINT, /账号名/);
  assert.match(strength, /口令中包含账号名/);
});

/* ── 源码级守卫：.vue 在 node 里跑不起来，只能钉源码（同本目录 tunnelwatch.test.ts）── */

test('源码守卫：mustChangePassword 必须排在 `r.ok && r.token` 之前，且两条登录路径各一处', () => {
  const code = codeOnly(src('src/views/Login.vue'));
  const hits = [...code.matchAll(/r\.mustChangePassword && r\.token/g)];
  assert.equal(hits.length, 2,
    '口令登录与 TOTP 第二回合两条路都要判：服务端 handlePortalLogin / handleTotpLogin 两处都调 mustChangeLogin');
  const oks = [...code.matchAll(/r\.ok && r\.token/g)].map((m) => m.index!);
  assert.equal(oks.length, 2, '两条路各有一处 ok && token 分支');
  hits.forEach((h, i) => {
    assert.ok(h.index! < oks[i],
      '先判 ok && token 的话会拿受限令牌 login() 并 replace(\'/connect\')，随后每个业务端点 403');
  });
});

test('源码守卫：受限令牌不得写进 session，改密请求必须显式带它', () => {
  const code = codeOnly(src('src/views/Login.vue'));
  // 只切 enterPwChange 的**函数体**：在全文里找「enterPwChange 后面若干字符内有没有 login(」
  // 会被它自己的调用点绊住（`{ enterPwChange(r); } else if (…) { login(…) }`），那种守卫恒红。
  const body = code.match(/function enterPwChange\([^)]*\)[^{]*\{([\s\S]*?)\n\}/);
  assert.ok(body, 'Login.vue 里必须有 enterPwChange（改密步骤的唯一入口）');
  assert.ok(!/\blogin\(/.test(body![1]),
    'enterPwChange 里不许调 login()：那会把 15min 受限令牌写进 localStorage，authed() 立刻为真、'
    + '路由守卫放行进主界面，随后每个业务端点 403');
  assert.match(body![1], /pwToken\.value = r\.token/);
  // session.token 此刻是空的（受限令牌刻意没入库），api() 的自动注入拿不到东西。
  assert.match(code, /Authorization: `Bearer \$\{pwToken\.value\}`/);
  assert.match(src('src/views/Login.vue'), /PW_RULE_HINT/, '口令要求必须常驻显示在改密表单上');
});

/**
 * 登录页三处 catch 全部改成转述后端原话。
 *
 * ★这不是"顺手清理"：改密最高频的拒绝是 400「新口令强度不足：<哪一条不达标>」，
 *   而那句话是唯一说得出"改成什么样才行"的话。改造前移动端 api() 连后端 message 都不解
 *   （`throw new Error(\`${res.status} ${res.statusText}\`)`），登录页再把它整句换成
 *   「无法连接控制中心（baidi-control）」——一个方向完全相反的归因：防爆破锁（403）下
 *   用户会去查网络、去重试，而每重试一次都在续锁。
 */
test('源码守卫：登录页不再编造归因，失败一律 failReason 收口', () => {
  const code = codeOnly(src('src/views/Login.vue'));
  assert.ok(!/catch\s*\{\s*err\.value = '无法连接控制中心/.test(code),
    '登录失败不得一律说成"连不上"：后端在口令校验之前就会定性拒绝（防爆破锁 / 账号禁用 / 认证域没选）');
  assert.ok(!/catch\s*\{\s*\n?\s*err\.value = '验证码不正确或已使用/.test(code),
    'TOTP 第二回合同样过 loginGateLocked，把 403 说成"验证码不正确"会让被锁的人一遍遍重输、一遍遍续锁');
  assert.equal([...code.matchAll(/err\.value = failReason\(e\)/g)].length, 3,
    '三处（口令登录 / TOTP / 改密）都要转述后端原话');
  const api = codeOnly(src('src/lib/api.ts'));
  assert.ok(!/throw new Error\(`\$\{res\.status\}/.test(api),
    'api() 必须解出后端 httpx.Error 的中文 message，扔状态行等于把后端那句话丢掉');
  assert.match(api, /class ApiError extends Error/);
  assert.match(api, /export function failReason/);
});

/**
 * api() 的 headers 合并顺序。
 *
 * ★原写法 `{ headers: {…合并…}, ...init }` 里 `...init` 展开在后，而 init 里**也有** headers，
 *   于是合并结果被整个顶掉：任何传了 headers 的调用（改密要带 Authorization + Content-Type）
 *   都会静默丢掉 Accept 与自动注入的 Bearer，症状是一次谁也解释不了的 401。
 *   桌面端 api.ts 早就是"先摘出来再单独合并"的写法，移动端是同一条纪律没做的那一半。
 */
test('源码守卫：api() 的 headers 先摘后合，不被 ...init 顶掉', () => {
  const api = codeOnly(src('src/lib/api.ts'));
  assert.match(api, /const \{ headers: extra, \.\.\.rest \} = init \?\? \{\};/);
  const call = api.match(/await fetch\(apiBase\(\) \+ path, \{([\s\S]*?)\n\s*\}\);/);
  assert.ok(call, 'api() 里必须有那次 fetch');
  const restAt = call![1].indexOf('...rest');
  const headersAt = call![1].indexOf('headers:');
  assert.ok(restAt >= 0 && headersAt > restAt,
    'headers 必须写在 ...rest 之后：反过来 init.headers 会把合并结果整体顶掉（Bearer 静默丢失）');
});
