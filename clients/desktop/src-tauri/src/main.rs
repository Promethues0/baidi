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

mod posture;

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
/// 网关落点清单落盘路径（多活 + 故障转移，顺序即优先级）。与上面两份同一套写法。
/// 内容是网关地址与隧道证书指纹——不是凭据（指纹是公开信息，钉扎的是对方身份），
/// 但同样按 0600 写：整份清单就是一张"白帝网关都部署在哪"的地图。
const GATEWAYS: &str = "/tmp/baidi-gateways.json";

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
    // 把「加密但不认证」补成「加密 + 认证」。这是**首选落点**那台的指纹（单落点旧入口）。
    #[serde(default)]
    pin: String,
    // gateways 网关落点清单（JSON 数组字符串，顺序即优先级），落盘后经 -gateways
    // 交给 root 数据面。一台网关挂掉时客户端切下一个，不再是"网关一挂全员断"。
    //
    // ★清单里每个落点各带**自己**的 pin：共用一份会让故障转移在钉扎那一步必然失败，
    // 而症状是「切过去就连不上」，极易被误判成第二台网关也坏了。
    // 空串 = 前端没算出任何落点（剖面与本机配置都没有），此时退回 -spa/-proxy/-pin。
    #[serde(default)]
    gateways: String,
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
    // device 终端硬件指纹（与 posture 上报同一个值，来自 collectPosture().device）。
    // 随每次取敲门令牌上报给控制面，是「授信终端」准入闸的判据。
    //
    // ★两处必须是同一个值：设备台账里被管理员批准的那台机器，与敲门时自报的那台，
    // 对不上的症状是严格准入模式下「批了也连不上」，而两边日志都完全正常。
    // 空串 = 不上报（观察模式照常接入并留痕，严格模式会被控制面拒并带回原因）。
    #[serde(default)]
    device: String,
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
    if !opts.device.trim().is_empty() {
        args.push("-device".into());
        args.push(opts.device.trim().into());
    }
    if opts.gm {
        args.push("-gm".into());
        args.push("-insecure".into());
    } else if !opts.pin.trim().is_empty() {
        // 通用 TLS 隧道：用控制面下发的指纹钉扎网关证书。国密路径走 TLCP 的 CA 校验，
        // 两条路径的信任材料不同，不能混用，故只在非 -gm 时传 -pin。
        args.push("-pin".into());
        args.push(opts.pin.trim().into());
    }
    // 网关落点清单：写盘后经 -gateways 交给 root 数据面（顺序即优先级）。
    // 与 resmap 同一套写法，包括「空就把上一轮的残留删掉」——留着会让这次接入
    // 按上一个用户/上一份策略的落点做故障转移，切过去连的是一台不该连的网关。
    if !opts.gateways.trim().is_empty() {
        fs::write(GATEWAYS, opts.gateways.trim()).map_err(|e| format!("写网关落点清单失败：{e}"))?;
        let _ = fs::set_permissions(GATEWAYS, fs::Permissions::from_mode(0o600));
        args.push("-gateways".into());
        args.push(GATEWAYS.into());
    } else {
        let _ = fs::remove_file(GATEWAYS);
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
    /// 最近一条「网关落点」状态行（从**整份日志**里捞，不受 log 尾巴长度限制）。
    ///
    /// ★为什么要单开一个字段：落点切换只在切换发生的那一瞬打**一行**，而之后每条流
    /// 都会打一行引流日志（每行上百字节）。只把日志尾巴交给前端的话，几十条流之后
    /// 那一行就被冲掉了，接入页会静默退回「第 1 个落点」——显示的是一台已经挂掉的
    /// 网关地址，还可能把未钉扎的隧道显示成已钉扎。一次性事件在"最近 N 字节"这种
    /// 通道上不可能可靠送达，必须单独带出来。
    endpoint: String,
}

/// 日志尾巴的字节预算。按**字符边界**回退，绝不按字节硬切。
const LOG_TAIL_BYTES: usize = 4000;

/// 取日志尾巴：至多 LOG_TAIL_BYTES 字节，且从**行首**开始。
///
/// ★`log[log.len() - 4000..]` 会 panic：baidi-tun 每行日志都带中文
/// （`msg="引流 · 经隧道转发"` 等），偏移落在多字节 UTF-8 的续接字节上时
/// Rust 直接 `byte index N is not a char boundary`。那会让 tunnel_status 这个命令
/// 抛出去、invoke 的 Promise 不 resolve，接入页停在上一次的状态上——一个概率性的、
/// 只在日志长起来之后出现的"界面卡住"。
fn log_tail(log: &str, budget: usize) -> &str {
    if log.len() <= budget {
        return log;
    }
    // ★先把切点抬到字符边界上：连 `log[cut..]` 这一步都会 panic，
    // 不是只有最终返回的那个切片才需要对齐。
    let mut cut = log.len() - budget;
    while cut < log.len() && !log.is_char_boundary(cut) {
        cut += 1;
    }
    // 再从切点起找第一个换行，让尾巴从行首开始（半行日志解析出来只会是噪声）。
    match log[cut..].find('\n') {
        Some(off) => &log[cut + off + 1..],
        None => &log[cut..],
    }
}

/// 从整份日志里捞最后一条落点状态行（契约见 gateway 的 picker.logCurrent）。
fn last_endpoint_line(log: &str) -> String {
    log.lines()
        .filter(|l| l.contains("endpoint="))
        .next_back()
        .unwrap_or_default()
        .trim()
        .to_string()
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
    let full = fs::read_to_string(LOG).unwrap_or_default();
    TunStatus {
        running,
        pid,
        log: log_tail(&full, LOG_TAIL_BYTES).to_string(),
        endpoint: last_endpoint_line(&full),
    }
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

/// 终端环境采集（实现见 posture 模块：分平台三态探测）。
/// async：Tauri 2 会把它挪到线程池执行，串行 spawn 的几个探测子进程不再卡主线程（每 60s 一轮）。
#[tauri::command]
async fn collect_posture() -> posture::PostureInfo {
    posture::gather_posture()
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

    /// ★按字节硬切会 panic：baidi-tun 的日志几乎每行都含中文。
    /// 这条用例退回 `log[log.len()-N..]` 的写法立刻 panic（而不是断言失败），
    /// 那正是现网表现——tunnel_status 抛异常、接入页静默停在旧状态上。
    #[test]
    fn 日志尾巴按字符边界回退() {
        let line = "time=2026-08-11 level=INFO msg=\"引流 · 经隧道转发\" resource=oa\n";
        let log: String = line.repeat(200);
        for budget in 1..300 {
            let tail = log_tail(&log, budget); // 不 panic 即为通过（切点会落在续接字节上）
            assert!(log.ends_with(tail), "尾巴必须是原文的后缀");
        }
    }

    #[test]
    fn 日志短于预算时原样返回() {
        let log = "只有一行中文日志\n";
        assert_eq!(log_tail(log, 4000), log);
    }

    #[test]
    fn 日志尾巴从行首开始() {
        let log = "第一行很长很长很长很长\n第二行\n第三行\n";
        let tail = log_tail(log, 20);
        assert!(tail.starts_with("第二行") || tail.starts_with("第三行"), "得 {tail:?}");
    }

    /// ★落点行必须从**整份日志**里捞：它只在切换那一瞬打一行，
    /// 之后每条流的引流日志会很快把它挤出尾巴窗口。
    #[test]
    fn 落点行不受尾巴窗口影响() {
        let mut log = String::from(
            "time=1 level=WARN msg=\"网关落点切换\" endpoint=2/2 id=gw-b addr=10.0.0.2:18443 reason=\"上一落点 gw-a 拨号失败\"\n",
        );
        log.push_str(&"time=2 level=INFO msg=\"引流 · 经隧道转发\" resource=oa\n".repeat(200));
        assert!(
            !log_tail(&log, LOG_TAIL_BYTES).contains("endpoint="),
            "前置条件：落点行确实已被挤出尾巴窗口"
        );
        let ep = last_endpoint_line(&log);
        assert!(ep.contains("endpoint=2/2") && ep.contains("id=gw-b"), "得 {ep:?}");
    }

    #[test]
    fn 没有落点行时回空串() {
        assert_eq!(last_endpoint_line("time=1 msg=\"数据面就绪\"\n"), "");
    }
}
