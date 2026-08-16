/** 终端环境采集与上报：Tauri 真实采集（Rust collect_posture）/ 浏览器联调模拟采集；
 *  登录期间每 60s 上报控制中心（把接入页那行文案变成真的）。判定权在控制面。
 *  上报循环由 App 级（随登录态）启停，不绑视图——切走接入 Tab 也持续上报，
 *  否则 strict 模式下 10 分钟后报告过期会掐断隧道。共享状态供各视图读取。 */
import { reactive } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { api } from './api';
import { tauriRuntime } from './tunnel';
import { setDeviceID } from './store';

/** unknown = 这项探不到（命令缺失/权限不足）。★不是「不合规」：
 *  Rust 采集器在 unknown 时把 ok 置 false（对旧控制面 fail-closed），
 *  所以渲染必须先看 unknown，否则会把「无法判定」画成「不合规」。 */
export interface PostureCheck { key: string; label: string; ok: boolean; unknown?: boolean; value: string }
export interface PostureInfo { platform: string; os: string; clientVersion: string; device: string; checks: PostureCheck[] }
/** unknowns 控制面回传的不可判定项（observe 下不计入判定，但必须让用户看见）。 */
export interface PostureVerdict { ok: boolean; verdict: 'allow' | 'degrade' | 'gray' | 'block'; score: number; level: string; reasons: string[]; unknowns?: string[] }

/** 最近一次采集结果与控制面判定（全局共享，各视图读取渲染）。 */
export const postureState = reactive<{ info: PostureInfo | null; verdict: PostureVerdict | null }>({ info: null, verdict: null });

/** 采集：Tauri 走 Rust 真实探测；浏览器联调回退模拟（标注 DEV-BROWSER，仍走真实上报管道）。 */
export async function collectPosture(): Promise<PostureInfo> {
  if (tauriRuntime()) {
    const info = await invoke<PostureInfo>('collect_posture');
    setDeviceID(info.device);
    return info;
  }
  setDeviceID('DEV-BROWSER');
  return {
    platform: 'macOS', os: '浏览器联调（模拟采集）', clientVersion: '0.1.0', device: 'DEV-BROWSER',
    checks: [
      { key: 'disk_encrypted', label: '磁盘已加密', ok: true, value: '模拟' },
      { key: 'sys_integrity', label: '系统完整性保护开启', ok: true, value: '模拟' },
      { key: 'firewall_on', label: '系统防火墙启用', ok: true, value: '模拟' },
      { key: 'os_version', label: '系统版本合规', ok: true, value: '模拟' },
      // 浏览器里确实探不到 EDR——按 unknown 报，不是 ok:false。
      // 报 false 会让控制面把联调机判成"不合规"，然后开发自己被 block 基线拦在门外。
      { key: 'edr_online', label: 'EDR 终端防护在线', ok: false, unknown: true, value: '无法判定：浏览器无法枚举进程' },
      // 客户端版本本地判不了「是不是最新」——判据（目标版本）在控制面的灰度发布配置里。
      // 与 Rust 采集器同口径报 unknown，由控制面重算后写回；报 ok:true 就是假绿。
      { key: 'client_version', label: '客户端版本合规', ok: false, unknown: true, value: '0.1.0' }
    ]
  };
}

/** 采集并上报一轮，写入共享状态；网络失败保留上轮值（下轮重试），不打断 UI。 */
export async function reportPosture(): Promise<{ info: PostureInfo; verdict: PostureVerdict } | null> {
  try {
    const info = await collectPosture();
    const verdict = await api<PostureVerdict>('/posture', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(info)
    });
    postureState.info = info;
    postureState.verdict = verdict;
    // 指纹归口到 store：敲门令牌与登录 deviceId 都从这一份取（见 store.device 的说明）。
    setDeviceID(info.device);
    return { info, verdict };
  } catch { return null; }
}

let loopTimer = 0;
/** 启动 60s 上报循环（幂等；随登录态由 App 级调用）。 */
export function startPostureLoop(): void {
  stopPostureLoop();
  reportPosture();
  loopTimer = window.setInterval(reportPosture, 60_000);
}
/** 停止上报循环并清空共享状态（登出时调用）。 */
export function stopPostureLoop(): void {
  clearInterval(loopTimer);
  loopTimer = 0;
  postureState.info = null;
  postureState.verdict = null;
}
