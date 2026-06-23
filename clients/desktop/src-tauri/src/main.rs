// 白帝安全接入桌面客户端 · Tauri 壳。
// 注入 shell 插件，使前端"一键接入"可经 sidecar 调用 baidi-knock 发起真实 SPA 敲门。
// （baidi-knock 为按需调用，不在启动期常驻；见 src/lib/knock.ts）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .run(tauri::generate_context!())
        .expect("运行白帝桌面客户端失败");
}
