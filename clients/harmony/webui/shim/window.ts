/**
 * `@tauri-apps/api/window` 的鸿蒙 shim。
 *
 * desktop 的自定义标题栏（frameless）用它做最小化/最大化/关闭。鸿蒙 PC 上窗口由
 * 系统装饰栏管理，应用侧不自绘标题栏——这三个方法留空即可（按钮点了没反应，
 * 而系统标题栏本身是可用的）。
 *
 * ★没有把 close() 接成「退出应用」：那会让一个看起来是"最小化到托盘"的按钮
 * 真的把进程杀掉。宁可不响应，也不做一个语义不同的动作。
 */
export interface AppWindow {
  minimize(): Promise<void>;
  toggleMaximize(): Promise<void>;
  close(): Promise<void>;
}

export function getCurrentWindow(): AppWindow {
  return {
    async minimize() { /* 由系统装饰栏负责 */ },
    async toggleMaximize() { /* 同上 */ },
    async close() { /* 同上；刻意不接成退出应用 */ }
  };
}
