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
/// 资源映射表落盘路径。控制面接入剖面里的 resmap（"host:port" → 资源 id）经此文件交给
/// root 权限的 baidi-tun（-resmap）。不含凭据，只是路由提示；仍按 0600 写，避免同机
/// 其他用户顺手读走内网拓扑。root 进程读 0600 的他人文件不受限。
const RESMAP: &str = "/tmp/baidi-resmap.json";
/// 隧道内 DNS 记录表落盘路径（FQDN → VIP）。与 RESMAP 同一套写法：不含凭据，
/// 但仍按 0600 写，避免同机其他用户顺手读走内网域名清单（那是一份现成的内网资产地图）。
const DNSREC: &str = "/tmp/baidi-dns-records.json";

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TunOpts {
    control: String,    // 控制中心，如 http://127.0.0.1:8090（取短时效敲门令牌 + 保活）
    gateway: String,    // 网关主机，如 127.0.0.1
    spa_port: String,   // SPA 敲门端口，默认 18201
    proxy_port: String, // 隧道代理端口，默认 18443
    // route 引流进隧道的受保护网段，逗号分隔可多段。前端把控制面剖面的 routes 数组
    // join(',') 后传入——只接管单一手填网段正是「隧道通了但点开应用不走隧道」的根因。
    route: String,
    ip: String, // utun 虚拟 IP，如 10.99.0.2
    gm: bool,   // 国密 TLCP 隧道（自签网关证书 → 附带 -insecure 跳过校验）
    token: String, // 会话 JWT
    // resmap 控制面剖面下发的 "host:port" → 资源 id 映射（JSON 字符串）。
    // 空串表示没有可路由资源，此时不写文件、不传 -resmap，隧道回退网关默认后端。
    #[serde(default)]
    resmap: String,
    // pin 网关隧道证书 SHA-256 指纹（hex）。非空则 baidi-tun 对通用 TLS 隧道做证书钉扎，
    // 把「加密但不认证」补成「加密 + 认证」。
    #[serde(default)]
    pin: String,
    // ── 分离式 DNS（剖面 dns 段）──
    // 没有这三个字段时，域名后端（oa.corp.internal:8080）完全不被接管，流量直连内网
    // 且没有任何提示——「配了却不生效」里最难归因的一种。三者都为空 = 老行为。
    //
    // dns_listen 隧道内解析器的 VIP。空=不启用（后两个字段随之无意义）。
    #[serde(default)]
    dns_listen: String,
    // dns_domains 交给隧道内解析器的搜索域，逗号分隔。只按域分流，不接管系统全局 DNS。
    #[serde(default)]
    dns_domains: String,
    // dns_records FQDN→VIP 记录表（JSON 字符串），落盘后经 -dns-records 交给 root 数据面。
    #[serde(default)]
    dns_records: String,
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
    } else if !opts.pin.trim().is_empty() {
        // 通用 TLS 隧道：用控制面下发的指纹钉扎网关证书。国密路径走 TLCP 的 CA 校验，
        // 两条路径的信任材料不同，不能混用，故只在非 -gm 时传 -pin。
        args.push("-pin".into());
        args.push(opts.pin.trim().into());
    }
    // 资源映射表：写盘后经 -resmap 交给 root 数据面。控制面是这张表的唯一来源——
    // 客户端不自己推导「哪个地址属于哪个资源」，避免终端与网关对资源归属产生分歧。
    if !opts.resmap.trim().is_empty() {
        fs::write(RESMAP, opts.resmap.trim()).map_err(|e| format!("写资源映射表失败：{e}"))?;
        let _ = fs::set_permissions(RESMAP, fs::Permissions::from_mode(0o600));
        args.push("-resmap".into());
        args.push(RESMAP.into());
    } else {
        // 上一轮遗留的映射表必须清掉：否则换用户/换策略后仍会按旧表路由，
        // 表现为「明明改了权限，客户端还能连到老资源」。
        let _ = fs::remove_file(RESMAP);
    }
    // 分离式 DNS：记录表落盘后经 -dns-records 交给 root 数据面，与 resmap 同一套写法。
    // 只有 -dns-listen 非空才接线；否则连记录表都不写，并把上一轮的残留删掉——
    // 留着会让下一次接入按旧地址作答（「域名改指向了，客户端还连老机器」）。
    if !opts.dns_listen.trim().is_empty() {
        args.push("-dns-listen".into());
        args.push(opts.dns_listen.trim().into());
        if !opts.dns_domains.trim().is_empty() {
            args.push("-dns-domains".into());
            args.push(opts.dns_domains.trim().into());
        }
        if !opts.dns_records.trim().is_empty() {
            fs::write(DNSREC, opts.dns_records.trim()).map_err(|e| format!("写 DNS 记录表失败：{e}"))?;
            let _ = fs::set_permissions(DNSREC, fs::Permissions::from_mode(0o600));
            args.push("-dns-records".into());
            args.push(DNSREC.into());
        } else {
            let _ = fs::remove_file(DNSREC);
        }
    } else {
        let _ = fs::remove_file(DNSREC);
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
///
/// ★这里必须是 `kill`（SIGTERM）而不是 `kill -9`：baidi-tun 收到 SIGTERM 才会去收回
/// 它写进系统的解析器配置（/etc/resolver/<域名>）。被 -9 打掉的话配置会留在系统里，
/// 把该域名指向一个已经不存在的 VIP——症状是「断开客户端后这个域名永久解析失败」，
/// 用户根本不会联想到是客户端留下的。（真被 -9 打掉时，靠 baidi-tun 下次启动时扫描回收。）
#[tauri::command]
fn tunnel_stop() -> Result<(), String> {
    let _ = fs::remove_file(LAUNCH);
    let _ = fs::remove_file(RESMAP); // 断开即清映射表，不给下一轮留下陈旧路由
    let _ = fs::remove_file(DNSREC); // 同理：陈旧的 DNS 记录表会让下轮解析到已下线的地址
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

/// 用系统默认浏览器打开应用地址（应用页「打开」按钮的真实动作）。
///
/// 刻意走自定义命令，而不是给前端放开 `shell:allow-open`：这样「能打开什么」的判定
/// 留在 Rust 侧。URL 虽然来自控制面剖面，但 webview 始终是攻击面，不该具备打开任意
/// URI 的能力——file://、smb:// 以及各类自定义协议处理器都是本地提权的经典跳板。
#[tauri::command]
fn open_app_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_shell::ShellExt;
    let u = url.trim();
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return Err(format!("仅允许打开 http/https 地址：{u}"));
    }
    // shell().open 在 tauri-plugin-shell 2.x 标记为 deprecated（官方推荐 tauri-plugin-opener），
    // 但功能完好。此处不迁移：换插件要同时动 Cargo 依赖、npm 依赖与 capabilities 权限声明，
    // 收益仅是消除一条告警。待有其他理由动 Tauri 依赖时一并迁移。
    #[allow(deprecated)]
    app.shell().open(u, None).map_err(|e| e.to_string())
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
/// 硬件 UUID 不会变——进程生命周期内缓存，免得每轮上报都 spawn ioreg。
fn device_fingerprint() -> String {
    static FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FP.get_or_init(|| {
        let raw = probe(
            "sh",
            &["-c", "ioreg -rd1 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $4}'"],
        );
        let hex: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
        if hex.len() < 16 {
            return "UNKNOWN-DEVICE".into();
        }
        format!("{}:{}:{}:{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
    })
    .clone()
}

/// 终端环境真实采集（macOS）：机械布尔化 + 原始值，策略判定在控制面（风险引擎按安全基线评估）。
/// async：Tauri 2 会把它挪到线程池执行，串行 spawn 的几个探测子进程不再卡主线程（每 60s 一轮）。
/// 采集逻辑抽到同步 gather_posture 以便单元测试；async 壳只负责让 Tauri 挪线程。
#[tauri::command]
async fn collect_posture() -> PostureInfo {
    gather_posture()
}

fn gather_posture() -> PostureInfo {
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
        .invoke_handler(tauri::generate_handler![
            tunnel_start,
            tunnel_status,
            tunnel_stop,
            force_quit,
            collect_posture,
            open_app_url
        ])
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

#[cfg(test)]
mod tests {
    use super::*;

    // 采集器契约：6 个检查项、key 与控制面基线/风险引擎一致、client_version 取包版本、
    // 设备指纹非空。ok 值依真机环境而定，故只断言结构与键，保证稳定不 flaky。
    #[test]
    fn gather_posture_shape() {
        let info = gather_posture();
        assert_eq!(info.platform, "macOS");
        assert!(info.os.starts_with("macOS"));
        assert!(!info.device.is_empty());
        assert_eq!(info.client_version, env!("CARGO_PKG_VERSION"));
        let keys: Vec<&str> = info.checks.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online", "client_version"],
            "采集键须与控制面基线检查键逐一对齐"
        );
    }

    // 设备指纹 OnceLock 缓存：同进程内多次调用返回同一值（避免每轮 spawn ioreg）。
    #[test]
    fn device_fingerprint_is_stable() {
        assert_eq!(device_fingerprint(), device_fingerprint());
    }
}
