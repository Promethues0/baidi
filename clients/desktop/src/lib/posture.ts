/** 终端环境采集与上报：Tauri 真实采集（Rust collect_posture）/ 浏览器联调模拟采集；
 *  登录期间每 60s 上报控制中心（把接入页那行文案变成真的）。判定权在控制面。 */
import { invoke } from '@tauri-apps/api/core';
import { api } from './api';
import { tauriRuntime } from './tunnel';

export interface PostureCheck { key: string; label: string; ok: boolean; value: string }
export interface PostureInfo { platform: string; os: string; clientVersion: string; device: string; checks: PostureCheck[] }
export interface PostureVerdict { ok: boolean; verdict: 'allow' | 'degrade' | 'gray' | 'block'; score: number; level: string; reasons: string[] }

/** 采集：Tauri 走 Rust 真实探测；浏览器联调回退模拟（标注 DEV-BROWSER，仍走真实上报管道）。 */
export async function collectPosture(): Promise<PostureInfo> {
  if (tauriRuntime()) return await invoke<PostureInfo>('collect_posture');
  return {
    platform: 'macOS', os: '浏览器联调（模拟采集）', clientVersion: '0.1.0', device: 'DEV-BROWSER',
    checks: [
      { key: 'disk_encrypted', label: '磁盘已加密', ok: true, value: '模拟' },
      { key: 'sys_integrity', label: '系统完整性保护开启', ok: true, value: '模拟' },
      { key: 'firewall_on', label: '系统防火墙启用', ok: true, value: '模拟' },
      { key: 'os_version', label: '系统版本合规', ok: true, value: '模拟' },
      { key: 'edr_online', label: 'EDR 终端防护在线', ok: false, value: '浏览器无法检测' },
      { key: 'client_version', label: '客户端为最新版本 v0.1.0', ok: true, value: '0.1.0' }
    ]
  };
}

/** 采集并上报一轮；网络失败返回 null（下轮重试），不打断 UI。 */
export async function reportPosture(): Promise<{ info: PostureInfo; verdict: PostureVerdict } | null> {
  try {
    const info = await collectPosture();
    const verdict = await api<PostureVerdict>('/posture', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(info)
    });
    return { info, verdict };
  } catch { return null; }
}
