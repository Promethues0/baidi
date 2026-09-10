/**
 * 首登强制改密（FR-DEPLOY-09）的端上出口。
 *
 * 这条链路的失败形态是**零报错的死路**：`BAIDI_SEED_MUST_CHANGE` 默认 1、
 * `handleCreateUser` 对每个新建普通用户置 `MustChangePw`、管理员每次重置口令同理，
 * 于是每台按脚本装出来的机器上、每一个新用户首次登录，服务端回的都是
 * `{ok:true, mustChangePassword:true, token:<15min 受限令牌>}`——客户端若只看
 * `ok && token` 就 login()，界面会一路跳进接入 hub，然后剖面 / 敲门 / 应用列表逐个 403，
 * 而屏幕上一句解释也没有。所以这里钉的是三件事：
 *   ① 判定顺序（mustChangePassword 必须排在 ok && token 之前）；
 *   ② 两条登录路径（口令 / TOTP 第二回合）都接上了这道分支；
 *   ③ 端上写出来的口令要求与控制面的判据数字一致——写错了，人会照着一条错的规则反复试。
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { PW_RULE_HINT, checkNewPassword } from './pwchange';

/**
 * 去掉注释后的源码——**否定式守卫必须用它**。
 * 本仓的注释习惯是把「改造前是什么形态」原文抄进注释里，于是「源码里不许再出现 X」
 * 这类断言会被自己要保护的那段注释绊倒（与 mobile tests/tunnelwatch.test.ts 同款）。
 */
function codeOnly(s: string): string {
  return s
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').filter((l) => !/^\s*(\/\/|\*)/.test(l)).join('\n');
}

const connect = readFileSync(new URL('../views/Connect.vue', import.meta.url), 'utf8');

describe('checkNewPassword · 只做后端判不了的那几件事', () => {
  it('空口令 / 两次不一致 / 与原口令相同各有一句准确的话', () => {
    expect(checkNewPassword('', '', 'old')).toBe('请输入新口令');
    expect(checkNewPassword('Abcd@12345', 'Abcd@1234', 'old')).toBe('两次输入的新口令不一致');
    expect(checkNewPassword('old', 'old', 'old')).toMatch(/不得与原口令相同/);
  });

  it('合规输入放行——强度判据不在端上，端上多判一条就会出现「客户端拦下而后端本可接受」', () => {
    expect(checkNewPassword('Abcd@12345', 'Abcd@12345', 'baidi@123')).toBeNull();
    // 一个后端会判弱的口令（8 位、命中弱口令表），端上**不拦**：它要被送到后端去，
    // 由 handleChangePassword 回那句带具体原因的 400，再由 failReason 原样转述。
    // 端上复刻一份强度算法必然与后端漂移，两个方向的分歧都无从解释。
    expect(checkNewPassword('12345678', '12345678', 'baidi@123')).toBeNull();
  });

  it('原口令为空时不拿它比对（外部认证源那一回合后端本就不校验旧口令）', () => {
    expect(checkNewPassword('', '', '')).toBe('请输入新口令');
    expect(checkNewPassword('Abcd@12345', 'Abcd@12345', '')).toBeNull();
  });
});

/**
 * ★跨轨契约：端上写给用户看的口令要求，数字必须与控制面 auth 包的判据一致。
 *
 * 对不上的症状是最费时间的那一种：用户照着「至少 8 位」写了一个 8 位口令，后端按 10 位判弱、
 * 回 400，他改成另一个 8 位的、再被拒——而首登改密是每套标准部署里每个新用户的第一个动作。
 * 两边各写各的话，这种漂移在编译期与运行期都不报错，只能靠源码级断言守。
 */
describe('口令要求文案 · 与控制面判据同数', () => {
  const strength = readFileSync(
    new URL('../../../../control/internal/auth/strength.go', import.meta.url), 'utf8'
  );

  it('PW_RULE_HINT 里的位数取自 minStrongLen / longPassphraseLen', () => {
    const min = strength.match(/minStrongLen\s*=\s*(\d+)/);
    const long = strength.match(/longPassphraseLen\s*=\s*(\d+)/);
    expect(min, 'strength.go 里必须有 minStrongLen（口令长度下限的唯一定义处）').toBeTruthy();
    expect(long, 'strength.go 里必须有 longPassphraseLen').toBeTruthy();
    expect(PW_RULE_HINT, `端上要求必须写明至少 ${min![1]} 位`).toContain(min![1]);
    expect(PW_RULE_HINT, `端上要求必须写明 ${long![1]} 位长口令的例外`).toContain(long![1]);
  });

  it('要求里必须点名「三类字符」与「含账号名」两条最常被撞上的判据', () => {
    expect(PW_RULE_HINT).toMatch(/三类/);
    expect(PW_RULE_HINT).toMatch(/账号名/);
    // 后端 PasswordWeakness 的第三条判据：口令里含账号名。它在实践中最常被撞上
    // （zhang.wei → Zhangwei2024），而只说"要复杂"的提示对它完全没有指导作用。
    expect(strength).toMatch(/口令中包含账号名/);
  });
});

/**
 * 源码级守卫：.vue 组件在 node 里跑不起来，只能钉源码（同 mobile 的做法）。
 * 这里钉的是**接线**——判定顺序错、或某条登录路径没接上，功能就等于不存在，
 * 而 checkNewPassword 的那几条用例照样全绿。
 */
describe('源码守卫 · Connect.vue 的首登改密出口', () => {
  it('mustChangePassword 分支必须排在 `r.ok && r.token` 之前（两条登录路径各一处）', () => {
    const code = codeOnly(connect);
    const hits = [...code.matchAll(/r\.mustChangePassword && r\.token/g)];
    expect(hits.length, '口令登录与 TOTP 第二回合两条路都要判：服务端两处都调 mustChangeLogin')
      .toBe(2);
    // 顺序：每一处 mustChangePassword 判定的下标，都必须小于它所在那段里 `r.ok && r.token` 的下标。
    const oks = [...code.matchAll(/r\.ok && r\.token/g)].map((m) => m.index!);
    expect(oks.length, '两条路各有一处 ok && token 分支').toBe(2);
    hits.forEach((h, i) => {
      expect(h.index!, '先判 ok && token 的话会拿受限令牌 login() 并跳进主界面，随后每个业务端点 403')
        .toBeLessThan(oks[i]);
    });
  });

  it('受限令牌不得写进 session（写进去 authed() 立刻为真，等于原缺陷原样复活）', () => {
    const code = codeOnly(connect);
    // 只切 enterPwChange 的**函数体**：直接在全文里找「enterPwChange 后面 N 个字符内有没有
    // login(」会被它自己的调用点绊住（`{ enterPwChange(r); } else if (…) { login(…) }`），
    // 那样写出来的守卫恒红，等于逼着后来的人把它删掉。
    const body = code.match(/function enterPwChange\([^)]*\)[^{]*\{([\s\S]*?)\n\}/);
    expect(body, 'Connect.vue 里必须有 enterPwChange（改密步骤的唯一入口）').toBeTruthy();
    expect(/\blogin\(/.test(body![1]), 'enterPwChange 里不许调 login()：那会把 15min 受限令牌'
      + '写进 localStorage，authed() 立刻为真、界面跳进接入 hub，随后每个业务端点 403')
      .toBe(false);
    expect(body![1]).toMatch(/pwToken\.value = r\.token/);
  });

  it('改密请求必须显式带 Authorization: pwToken（session.token 此刻是空的，不带就是必然 401）', () => {
    expect(codeOnly(connect)).toMatch(/Authorization: `Bearer \$\{pwToken\.value\}`/);
  });

  it('口令要求常驻显示，失败一律转述后端原话', () => {
    expect(connect).toMatch(/PW_RULE_HINT/);
    expect(codeOnly(connect)).toMatch(/doChangePw[\s\S]*?err\.value = failReason\(e\)/);
    // 编造归因是本仓明令禁止的那一族：这里最高频的拒绝是 400「新口令强度不足：<哪一条>」，
    // 换成"请重试"会让人反复撞同一堵墙且从没看到原因。
    expect(/catch[\s\S]{0,120}?err\.value = '口令修改失败/.test(codeOnly(connect)), '不许编造归因')
      .toBe(false);
  });
});
