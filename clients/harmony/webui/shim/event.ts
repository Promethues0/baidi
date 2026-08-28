/**
 * `@tauri-apps/api/event` 的鸿蒙 shim。
 *
 * desktop 侧只监听一个 'quit-request'（托盘菜单点退出时 Rust 侧发的）。
 * 鸿蒙没有托盘，这个事件永远不会来——注册一个不会触发的监听器即可，
 * 行为上等价于「用户永远不会从托盘退出」，不影响其余功能。
 */
export type UnlistenFn = () => void;

export async function listen<T>(_event: string, _handler: (e: { payload: T }) => void): Promise<UnlistenFn> {
  return () => { /* 无事件源，无需注销 */ };
}
