/**
 * 诊断页「隧道 / 敲门」两项判定的文案单测。
 *
 * 判据改成数据面健康行之后，这两条 detail 不能再说「尚未打印数据面就绪」「日志里没有敲门保活」——
 * 那两行启动日志早已不是判据，照着它们去翻日志会翻到两行确实存在的字，然后更困惑。
 * 且 !ready 时若健康行带着 err（指纹不匹配 / 取令牌失败 / 拨号超时），诊断页必须把数据面的原话交出去，
 * 而不是给一句中性的猜测。
 */
import { describe, expect, it } from 'vitest';
import { judgeKnock, judgeTunnel } from './diagnose';

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
