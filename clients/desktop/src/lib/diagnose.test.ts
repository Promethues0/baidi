/**
 * 诊断页「隧道 / 敲门」两项判定的文案单测。
 *
 * 判据改成数据面健康行之后，这两条 detail 不能再说「尚未打印数据面就绪」「日志里没有敲门保活」——
 * 那两行启动日志早已不是判据，照着它们去翻日志会翻到两行确实存在的字，然后更困惑。
 * 且 !ready 时若健康行带着 err（指纹不匹配 / 取令牌失败 / 拨号超时），诊断页必须把数据面的原话交出去，
 * 而不是给一句中性的猜测。
 */
import { describe, expect, it } from 'vitest';
import { explainControlFailure, hostPlatform, importCertHint, judgeKnock, judgeTunnel } from './diagnose';

describe('judgeTunnel', () => {
  it('运行中未就绪、健康行带 err → detail 转述数据面原话', () => {
    const v = judgeTunnel({ running: true, ready: false, error: '网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def' });
    expect(v.state).toBe('warn');
    expect(v.detail).toBe('数据面报告：网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def');
  });

  it('运行中未就绪、无 err → 中性的「尚未报告隧道拨通」，不提启动日志那行字', () => {
    const v = judgeTunnel({ running: true, ready: false, error: '' });
    expect(v.state).toBe('warn');
    expect(v.detail).toContain('数据面尚未报告隧道拨通');
    expect(v.detail).not.toContain('数据面就绪');
  });

  it('denied 优先于一切：fail + 拒绝原因', () => {
    const v = judgeTunnel({ running: false, ready: false, denied: true, deniedReason: '账号已被禁用' });
    expect(v.state).toBe('fail');
    expect(v.detail).toBe('账号已被禁用');
  });

  it('未运行 → skip；有上次失败原因就带上', () => {
    expect(judgeTunnel({ running: false, ready: false }).state).toBe('skip');
    expect(judgeTunnel({ running: false, ready: false, error: '创建 utun 失败' }).detail).toBe('上次接入失败：创建 utun 失败');
  });

  it('运行中且就绪 → pass', () => {
    expect(judgeTunnel({ running: true, ready: true }).state).toBe('pass');
  });
});

describe('judgeKnock', () => {
  it('运行中无保活 → warn，文案说「尚未报告敲门成功」而不是「日志里没有敲门保活」', () => {
    const v = judgeKnock({ running: true, ready: false, keepalive: false });
    expect(v.state).toBe('warn');
    expect(v.detail).toContain('尚未报告敲门成功');
    expect(v.detail).not.toContain('日志里没有');
  });

  it('未运行 → skip；保活在 → pass', () => {
    expect(judgeKnock({ running: false, ready: false }).state).toBe('skip');
    expect(judgeKnock({ running: true, ready: true, keepalive: true }).state).toBe('pass');
  });
});

/**
 * explainControlFailure 的**归因边界**。
 *
 * 这一组守的是本仓那条「失败必须转述后端原话」纪律在桌面端漏掉的那一半：
 * Connect.vue 的 doLogin 此前是 bare catch，把**任何**登录失败都送进这个传输层
 * 归因器。最坏的一例是防爆破锁定——lockout.go 在口令校验之前回 403，此刻 TCP 当然
 * 连得上、HTTPS 请求也确实"失败"了，于是它会给出一句方向完全相反却写得笃定又可执行的
 * 「地址是对的，问题在证书：请把该站点证书导入本机受信任的根证书颁发机构」。
 * 用户会真的去动系统根证书库，动完仍然登不进去（锁 15 分钟，期间每试一次还在续锁）。
 */
describe('explainControlFailure · 后端答复过就不许自己编', () => {
  const locked = '登录失败次数过多，已被临时锁定，请约 12 分钟后重试';

  it('后端答复过（403 防爆破锁）→ 原样转述，且一个字都不提证书', () => {
    // TCP 通 + HTTPS 失败：这正是会触发"问题在证书"那一支的输入组合。
    const say = explainControlFailure('https://gw.example.com', { kind: 'held-open', ms: 7 }, locked);
    expect(say).toBe(locked);
    expect(say).not.toContain('证书');
    expect(say).not.toContain('地址是对的');
  });

  it('后端答复过 → 连"TCP 都没通"那支也不许抢答（拒绝原因优先于任何探测结论）', () => {
    expect(explainControlFailure('https://gw.example.com', { kind: 'refused', ms: 0 }, locked)).toBe(locked);
  });

  it('全是空白的 serverSaid 不算答复过：回落到传输层归因，不许显示一句空话', () => {
    const say = explainControlFailure('https://gw.example.com', { kind: 'held-open', ms: 7 }, '   ');
    expect(say).toContain('证书');
  });

  it('没有 serverSaid（真·请求没到后端）→ 原有归因一字未改', () => {
    expect(explainControlFailure('https://gw.example.com', { kind: 'held-open', ms: 7 })).toContain('问题在证书');
    expect(explainControlFailure('https://gw.example.com', { kind: 'refused', ms: 0 })).toContain('TCP 都没通');
    expect(explainControlFailure('http://gw.example.com:8090', { kind: 'held-open', ms: 7 })).toContain('它可能不是 baidi-control');
    expect(explainControlFailure('https://gw.example.com')).toContain('运维诊断');
    expect(explainControlFailure('  ')).toBe('未配置控制中心地址');
  });
});

/**
 * 「导证书」这一步必须给到**命令级**，且必须说清它替代不了什么。
 *
 * 改造前那句「把该站点证书导入本机受信任的根证书颁发机构」方向是对的，但三个平台的
 * 入口、要不要管理员、导进哪个存储全不一样，导错了的症状与压根没导一模一样
 * （仍是一句 `Failed to fetch`）——2026-08-18 首次真机验证就卡在这一步整整一轮。
 *
 * 另一半同样要紧：桌面端新接了 `-control-ca` 本地信任锚，但它**只覆盖数据面**。
 * 不把这句限定语钉在文案里，放过锚的人会以为已经配完了，然后对着同一个
 * `Failed to fetch` 反复重试——「配置齐全却零报错不生效」的原版。
 */
describe('importCertHint · 可操作的下一步 + 覆盖范围限定语', () => {
  it('按平台只给该平台那条命令，且带上真实主机与端口', () => {
    const mac = importCertHint('macos', 'https://gw.example.com:9443');
    expect(mac).toContain('gw.example.com:9443');
    expect(mac).toContain('security add-trusted-cert');
    expect(mac).toContain('/Library/Keychains/System.keychain'); // 登录钥匙串不生效
    expect(mac).not.toContain('Import-Certificate');
    expect(mac).not.toContain('update-ca-certificates');

    const win = importCertHint('windows', 'https://gw.example.com');
    expect(win).toContain('Cert:\\LocalMachine\\Root');
    expect(win).toContain('管理员');
    expect(win).not.toContain('security add-trusted-cert');

    const lin = importCertHint('linux', 'https://gw.example.com');
    expect(lin).toContain('update-ca-certificates');
    expect(lin).not.toContain('security add-trusted-cert');
  });

  it('判不出平台 → 三条都给，不许挑一条猜（猜错那条会被真的执行，且失败形态与没执行相同）', () => {
    const all = importCertHint('', 'https://gw.example.com');
    expect(all).toContain('security add-trusted-cert');
    expect(all).toContain('Cert:\\LocalMachine\\Root');
    expect(all).toContain('update-ca-certificates');
  });

  it('★必须写明本地信任锚只覆盖数据面，替代不了导系统信任库这一步', () => {
    for (const p of ['macos', 'windows', 'linux', ''] as const) {
      const s = importCertHint(p, 'https://gw.example.com');
      expect(s).toContain('control-ca.pem');
      expect(s).toContain('只对数据面生效');
      expect(s).toContain('替代不了这一步');
    }
  });

  it('端口缺省按协议补：https→443、http→80', () => {
    expect(importCertHint('macos', 'https://gw.example.com')).toContain('gw.example.com:443');
    expect(importCertHint('macos', 'http://gw.example.com')).toContain('gw.example.com:80');
  });
});

describe('hostPlatform · 三条分支在任何一台开发机上都被断言', () => {
  it('Windows / macOS / Linux 各自认得出来', () => {
    expect(hostPlatform('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')).toBe('windows');
    expect(hostPlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15')).toBe('macos');
    expect(hostPlatform('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')).toBe('linux');
  });

  it('认不出来时回空串（由 importCertHint 三条都给），不猜一条', () => {
    expect(hostPlatform('')).toBe('');
    expect(hostPlatform('SomeEmbeddedShell/1.0')).toBe('');
  });
});

describe('explainControlFailure · 证书那支要带具体命令', () => {
  it('TCP 通 + HTTPS 失败 → 归因不变，但补上该平台的导入命令与限定语', () => {
    const say = explainControlFailure('https://gw.example.com', { kind: 'held-open', ms: 7 }, '', 'macos');
    expect(say).toContain('问题在证书');
    expect(say).toContain('security add-trusted-cert');
    expect(say).toContain('只对数据面生效');
    // WebView 只认系统信任库这件事要说穿，否则用户会去翻客户端设置找"信任"开关。
    expect(say).toContain('系统信任库');
    // ★platform 必须真的透传下去：写死成 '' 的话 mac 用户会同时看到三平台的命令，
    //   而其中两条在他机器上根本跑不了——照着试完仍然登不进去，方向白白多绕两圈。
    expect(say).not.toContain('Cert:\\LocalMachine\\Root');
    expect(say).not.toContain('update-ca-certificates');
  });

  it('后端答复过时一个字都不许自己编——命令也不许冒出来', () => {
    const locked = '登录失败次数过多，已被临时锁定，请约 12 分钟后重试';
    const say = explainControlFailure('https://gw.example.com', { kind: 'held-open', ms: 7 }, locked, 'macos');
    expect(say).toBe(locked);
    expect(say).not.toContain('add-trusted-cert');
  });

  it('TCP 都没通 / 明文 HTTP 两支不该出现证书命令（方向完全不同）', () => {
    expect(explainControlFailure('https://gw.example.com', { kind: 'refused', ms: 0 }, '', 'macos')).not.toContain('add-trusted-cert');
    expect(explainControlFailure('http://gw.example.com:8090', { kind: 'held-open', ms: 7 }, '', 'macos')).not.toContain('add-trusted-cert');
  });
});
