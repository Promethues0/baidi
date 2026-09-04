/**
 * 诊断页「隧道 / 敲门」两项判定的文案单测。
 *
 * 判据改成数据面健康行之后，这两条 detail 不能再说「尚未打印数据面就绪」「日志里没有敲门保活」——
 * 那两行启动日志早已不是判据，照着它们去翻日志会翻到两行确实存在的字，然后更困惑。
 * 且 !ready 时若健康行带着 err（指纹不匹配 / 取令牌失败 / 拨号超时），诊断页必须把数据面的原话交出去，
 * 而不是给一句中性的猜测。
 */
import { describe, expect, it } from 'vitest';
import { explainControlFailure, judgeKnock, judgeTunnel } from './diagnose';

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
