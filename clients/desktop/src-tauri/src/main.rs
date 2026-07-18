// 白帝安全接入桌面客户端 · Tauri 壳。
//   - shell 插件：按需 sidecar 调 baidi-knock 发起真实 SPA 敲门（dev/轻量路径）。
//   - 自定义命令 tunnel_*：以管理员权限拉起 baidi-tun 数据面引擎，真正用 utun 接管
//     受保护网段流量 → 逐流 SPA 敲门 → 加密隧道 → 网关。需 root：经 osascript 授权。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tauri::{Emitter, Manager};

const LOG: &str = "/tmp/baidi-tun.log";
const PID: &str = "/tmp/baidi-tun.pid";
const LAUNCH: &str = "/tmp/baidi-tun-launch.sh";

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TunOpts {
    control: String,    // 控制中心，如 http://127.0.0.1:8090（取短时效敲门令牌 + 保活）
    gateway: String,    // 网关主机，如 127.0.0.1
    spa_port: String,   // SPA 敲门端口，默认 18201
    proxy_port: String, // 隧道代理端口，默认 18443
    route: String,      // 引流进隧道的受保护网段，如 10.99.0.0/24
    ip: String,         // utun 虚拟 IP，如 10.99.0.2
    gm: bool,           // 国密 TLCP 隧道（自签网关证书 → 附带 -insecure 跳过校验）
    token: String,      // 会话 JWT
}

/// 定位随 app 打包的 baidi-tun。确定性顺序：同名 → 当前架构三元组名 → 排序后首个 baidi-tun*。
fn find_tun() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or_else(|| "无法定位程序目录".to_string())?;
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    for name in [String::from("baidi-tun"), format!("baidi-tun-{arch}-apple-darwin")] {
        let p = dir.join(&name);
        if p.exists() {
            return Ok(p);
        }
    }
    // 兜底：排序后取首个（避免 read_dir 顺序不确定）
    if let Ok(rd) = fs::read_dir(dir) {
        let mut hits: Vec<PathBuf> = rd
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("baidi-tun"))
            .map(|e| e.path())
            .collect();
        hits.sort();
        if let Some(p) = hits.into_iter().next() {
            return Ok(p);
        }
    }
    Err(format!("未找到数据面引擎 baidi-tun（{}）", dir.display()))
}

/// POSIX shell 单引号转义。
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn is_cancel(stderr: &str) -> bool {
    stderr.contains("-128") || stderr.contains("User canceled") || stderr.contains("用户已取消")
}

/// 以管理员权限拉起 baidi-tun。要点：
///  - launcher 脚本落纯 ASCII /tmp（0600），osascript 只跑该脚本路径（规避中文 .app 路径 + token 转义）；
///  - `exec </dev/null >/dev/null 2>&1` 先断开脚本自身与 osascript 管道 → do shell script 立即返回，
///    不会因后台 baidi-tun 常驻持有 fd 而卡死（会冻结 UI）；
///  - token 经 BAIDI_TOKEN 环境变量传入，不进 ps 进程参数；脚本用后即删。
#[tauri::command]
fn tunnel_start(opts: TunOpts) -> Result<(), String> {
    let tun = find_tun()?;
    let spa = format!("{}:{}", opts.gateway, opts.spa_port);
    let proxy = format!("{}:{}", opts.gateway, opts.proxy_port);
    let mut args: Vec<String> = vec![
        "-spa".into(), spa,
        "-proxy".into(), proxy,
        "-route".into(), opts.route,
        "-ip".into(), opts.ip,
        "-control".into(), opts.control,
        "-reknock".into(), "15s".into(),
    ];
    if opts.gm {
        args.push("-gm".into());
        args.push("-insecure".into());
    }
    let argline = args.iter().map(|a| sq(a)).collect::<Vec<_>>().join(" ");
    let script = format!(
        "#!/bin/bash\n\
         rm -f {log} {pid}\n\
         export BAIDI_TOKEN={tok}\n\
         exec </dev/null >/dev/null 2>&1\n\
         {tun} {args} >{log} 2>&1 </dev/null &\n\
         echo $! >{pid}\n",
        log = LOG, pid = PID, tok = sq(&opts.token), tun = sq(&tun.to_string_lossy()), args = argline,
    );
    fs::write(LAUNCH, script).map_err(|e| e.to_string())?;
    // 0600：仅所有者可读（token 短暂落盘）
    let _ = fs::set_permissions(LAUNCH, fs::Permissions::from_mode(0o600));

    let apple = format!(
        "do shell script \"/bin/bash {}\" with administrator privileges",
        LAUNCH
    );
    let out = Command::new("osascript").arg("-e").arg(&apple).output();
    let _ = fs::remove_file(LAUNCH); // 用后即删，缩小 token 落盘窗口
    let out = out.map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if is_cancel(&err) {
            return Err("已取消管理员授权".into());
        }
        return Err(format!("启动数据面失败：{}", err.trim()));
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct TunStatus {
    running: bool,
    pid: String,
    log: String,
}

/// 按 pid 判活（ps -p，避免 kill -0 对 root 进程 EPERM 误判）。供状态查询与托盘轮询共用。
fn tun_running() -> bool {
    let pid = fs::read_to_string(PID).unwrap_or_default().trim().to_string();
    if pid.is_empty() {
        return false;
    }
    Command::new("ps")
        .args(["-p", &pid, "-o", "pid="])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// 读 pid + 日志，回最近日志供前端解析真实状态。
#[tauri::command]
fn tunnel_status() -> TunStatus {
    let pid = fs::read_to_string(PID).unwrap_or_default().trim().to_string();
    let running = tun_running();
    let mut log = fs::read_to_string(LOG).unwrap_or_default();
    if log.len() > 4000 {
        log = log[log.len() - 4000..].to_string();
    }
    TunStatus { running, pid, log }
}

/// 断开：以管理员权限 kill 掉 root 数据面进程（utun/路由随进程退出回收），清理临时文件。
#[tauri::command]
fn tunnel_stop() -> Result<(), String> {
    let _ = fs::remove_file(LAUNCH);
    let pid = fs::read_to_string(PID).unwrap_or_default().trim().to_string();
    if pid.is_empty() {
        return Ok(());
    }
    let apple = format!(
        "do shell script \"kill {} 2>/dev/null; rm -f {} 2>/dev/null; true\" with administrator privileges",
        pid, PID
    );
    let out = Command::new("osascript")
        .arg("-e")
        .arg(&apple)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if is_cancel(&err) {
            return Err("已取消管理员授权".into());
        }
        return Err(format!("断开失败：{}", err.trim()));
    }
    Ok(())
}

/// 前端确认后真正退出（隧道运行中退出前的二次确认走此命令）。
#[tauri::command]
fn force_quit(app: tauri::AppHandle) {
    app.exit(0);
}

// ── 终端环境采集（posture）──

#[derive(serde::Serialize, Clone)]
struct PostureCheck {
    key: String,
    label: String,
    ok: bool,
    value: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PostureInfo {
    platform: String,
    os: String,
    client_version: String,
    device: String,
    checks: Vec<PostureCheck>,
}

/// 跑一条只读探测命令，返回 stdout（失败返回空串）。
fn probe(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// 设备指纹：IOPlatformUUID 去连字符取前 16 位，按 4 段冒号分隔（对齐控制台设备指纹形制）。
fn device_fingerprint() -> String {
    let raw = probe(
        "sh",
        &["-c", "ioreg -rd1 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $4}'"],
    );
    let hex: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    if hex.len() < 16 {
        return "UNKNOWN-DEVICE".into();
    }
    format!("{}:{}:{}:{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
}

/// 终端环境真实采集（macOS）：机械布尔化 + 原始值，策略判定在控制面（风险引擎按安全基线评估）。
#[tauri::command]
fn collect_posture() -> PostureInfo {
    let os_ver = probe("sw_vers", &["-productVersion"]);
    let filevault = probe("fdesetup", &["status"]); // "FileVault is On."
    let sip = probe("csrutil", &["status"]); // "... status: enabled."
    let fw = probe(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ); // "... enabled." / "(State = 1)"
    let procs = probe("ps", &["-axco", "comm"]);
    let edr = ["falcond", "CylanceSvc", "wdavdaemon", "SentinelAgent", "ESET"]
        .iter()
        .any(|p| procs.contains(p));
    let os_ok = os_ver
        .split('.')
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|v| v >= 13)
        .unwrap_or(false);
    let ver = env!("CARGO_PKG_VERSION").to_string();
    let checks = vec![
        PostureCheck { key: "disk_encrypted".into(), label: "磁盘已加密".into(), ok: filevault.contains("On"), value: filevault },
        PostureCheck { key: "sys_integrity".into(), label: "系统完整性保护开启".into(), ok: sip.contains("enabled"), value: sip },
        PostureCheck {
            key: "firewall_on".into(),
            label: "系统防火墙启用".into(),
            ok: fw.contains("enabled") || fw.contains("State = 1") || fw.contains("State = 2"),
            value: fw,
        },
        PostureCheck { key: "os_version".into(), label: "系统版本合规".into(), ok: os_ok, value: os_ver.clone() },
        PostureCheck {
            key: "edr_online".into(),
            label: "EDR 终端防护在线".into(),
            ok: edr,
            value: if edr { "检测到 EDR 进程".into() } else { "未检测到".into() },
        },
        PostureCheck { key: "client_version".into(), label: format!("客户端为最新版本 v{ver}"), ok: true, value: ver.clone() },
    ];
    PostureInfo {
        platform: "macOS".into(),
        os: format!("macOS {os_ver}"),
        client_version: ver,
        device: device_fingerprint(),
        checks,
    }
}

/// 显示并聚焦主窗口（从托盘唤起）。
fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::TrayIconBuilder;
    use tauri::WindowEvent;

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![tunnel_start, tunnel_status, tunnel_stop, force_quit, collect_posture])
        .setup(|app| {
            // 托盘菜单：状态（禁用只读）/ 显示主窗口 / 退出
            let status = MenuItem::with_id(app, "status", "○ 未接入", false, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出白帝", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&status, &sep, &show, &quit])?;

            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("白帝安全接入客户端 · 未接入")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main(app),
                    "quit" => {
                        // 隧道运行中直接退出会遗留无管控的 root 数据面 → 唤起窗口 + 请前端二次确认
                        if tun_running() {
                            show_main(app);
                            let _ = app.emit("quit-request", ());
                        } else {
                            app.exit(0);
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            // 后台每 3s 按 pid 判活，刷新托盘状态（窗口隐藏也能看接入态）；
            // UI 更新经 run_on_main_thread 回主线程，符合 macOS AppKit 主线程约束。
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut last: Option<bool> = None;
                loop {
                    let running = tun_running();
                    if last != Some(running) {
                        last = Some(running);
                        let status = status.clone();
                        let h = handle.clone();
                        let _ = handle.run_on_main_thread(move || {
                            let _ = status.set_text(if running { "● 已接入企业内网" } else { "○ 未接入" });
                            if let Some(tray) = h.tray_by_id("main") {
                                let _ = tray.set_tooltip(Some(if running {
                                    "白帝安全接入客户端 · 已接入"
                                } else {
                                    "白帝安全接入客户端 · 未接入"
                                }));
                            }
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关闭 → 隐藏到托盘常驻，不退出（托盘「退出白帝」才真正退出）
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("运行白帝桌面客户端失败");
}
