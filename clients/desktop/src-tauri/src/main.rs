// 白帝安全接入桌面客户端 · Tauri 壳。
//   - shell 插件：按需 sidecar 调 baidi-knock 发起真实 SPA 敲门（dev/轻量路径）。
//   - 自定义命令 tunnel_*：以管理员权限拉起 baidi-tun 数据面引擎，真正用 utun 接管
//     受保护网段流量 → 逐流 SPA 敲门 → 加密隧道 → 网关。需 root：经 osascript 授权。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

/// 定位随 app 打包的 baidi-tun（.app 内与主程序同目录；dev 下带三元组后缀）。
fn find_tun() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or_else(|| "无法定位程序目录".to_string())?;
    let direct = dir.join("baidi-tun");
    if direct.exists() {
        return Ok(direct);
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("baidi-tun") {
                return Ok(e.path());
            }
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

/// 以管理员权限拉起 baidi-tun：launcher 脚本落到纯 ASCII 的 /tmp，osascript 只跑该脚本路径，
/// 规避 .app 中文路径与长 token 在 osascript 里的转义问题。脚本后台启引擎并写 pid。
#[tauri::command]
fn tunnel_start(opts: TunOpts) -> Result<(), String> {
    let tun = find_tun()?;
    let spa = format!("{}:{}", opts.gateway, opts.spa_port);
    let proxy = format!("{}:{}", opts.gateway, opts.proxy_port);
    let mut args: Vec<String> = vec![
        "-spa".into(), spa,
        "-proxy".into(), proxy,
        "-token".into(), opts.token,
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
        "#!/bin/bash\nrm -f {pid}\n{tun} {args} >{log} 2>&1 </dev/null &\necho $! >{pid}\n",
        pid = PID,
        tun = sq(&tun.to_string_lossy()),
        args = argline,
        log = LOG,
    );
    fs::write(LAUNCH, script).map_err(|e| e.to_string())?;

    let apple = format!(
        "do shell script \"/bin/bash {}\" with administrator privileges",
        LAUNCH
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

/// 读 pid + 日志，判活（ps -p，避免 kill -0 对 root 进程 EPERM 误判），回最近日志供前端解析真实状态。
#[tauri::command]
fn tunnel_status() -> TunStatus {
    let pid = fs::read_to_string(PID).unwrap_or_default().trim().to_string();
    let running = if pid.is_empty() {
        false
    } else {
        Command::new("ps")
            .args(["-p", &pid, "-o", "pid="])
            .output()
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false)
    };
    let mut log = fs::read_to_string(LOG).unwrap_or_default();
    if log.len() > 4000 {
        log = log[log.len() - 4000..].to_string();
    }
    TunStatus { running, pid, log }
}

/// 断开：以管理员权限 kill 掉 root 数据面进程（utun/路由随进程退出自动回收）。
#[tauri::command]
fn tunnel_stop() -> Result<(), String> {
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![tunnel_start, tunnel_status, tunnel_stop])
        .run(tauri::generate_context!())
        .expect("运行白帝桌面客户端失败");
}
