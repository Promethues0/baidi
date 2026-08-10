/**
 * 客户端 SPA 敲门抽象：
 *  - Tauri 运行时（生产）：经 sidecar 调 baidi-knock 直接发真实 UDP 敲门包；
 *  - 浏览器 dev：经本地 baidi-knock-agent（/knock 代理）发起真实敲门 + 隧道可达性验证。
 * 两条路径都执行"真链路"敲门，区别只是谁来发 UDP 包。
 */
import { config, profile, device } from './store';

/**
 * 敲门目标地址：控制面剖面下发的网关落点优先，设置页配置兜底。
 *
 * 此前这里写死 `127.0.0.1:18201`，于是任何非本机部署的网关都敲不开门——
 * 界面上配的网关地址根本没被用上，属于「设置项看着生效、实际被忽略」的假功能。
 */
function spaTarget(): string {
  const gw = profile.data?.gateway;
  const host = gw?.host || config.gateway.trim();
  const port = gw?.spaPort || config.spaPort.trim();
  return `${host}:${port}`;
}

export interface KnockResult { ok: boolean; detail?: string }

function inTauri(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}

export async function knock(token: string): Promise<KnockResult> {
  if (!token) return { ok: false, detail: '未登录，缺少身份令牌' };
  // 网关默认 strict：只认 control 签发的短时效一次性敲门令牌，会话令牌敲不开门。
  // control 地址取设置页的持久化配置（而非硬编码），杜绝「登录用 A、敲门用 B」的错配。
  const control = config.control.trim();
  if (!control) return { ok: false, detail: '未配置控制中心地址（敲门令牌的唯一来源）' };

  if (inTauri()) {
    // 生产：Tauri sidecar 执行 baidi-knock（真实 UDP 敲门，源 IP = 本机）。
    // 变量化模块名 + @vite-ignore，让浏览器 dev 构建不去解析该 Tauri-only 依赖。
    const shellMod = '@tauri-apps/plugin-shell';
    const shell = (await import(/* @vite-ignore */ shellMod)) as { Command: { sidecar: (b: string, a: string[]) => { execute: () => Promise<{ code: number | null; stdout: string; stderr: string }> } } };
    const out = await shell.Command.sidecar('binaries/baidi-knock',
      ['-spa', spaTarget(), '-token', token, '-control', control,
        // 终端指纹：控制面「授信终端」准入闸的判据，与 posture 上报同一个值。
        // 还没采过一轮时是空串，baidi-knock 照常发（观察模式放行并留痕，严格模式明确拒）。
        '-device', device.id]).execute();
    return { ok: out.code === 0, detail: (out.stdout || out.stderr || '').trim() };
  }

  // dev：本地 knock-agent（HTTP→真实 UDP 敲门 + 隧道探测）
  try {
    const res = await fetch('/knock', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, control, device: device.id })
    });
    return (await res.json()) as KnockResult;
  } catch {
    return { ok: false, detail: '本地敲门代理不可达（dev 需运行 baidi-knock-agent）' };
  }
}
