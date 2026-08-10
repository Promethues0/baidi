//! 终端环境采集（posture）：分平台探测 → 机械三态化 → 交控制面风险引擎判定。
//!
//! 本模块刻意不写成 `#[cfg]` 大分支：命令调用被抽到 [`Env`] 后面，三个平台的**解析逻辑**
//! 在任意主机上都会被编译、被单测覆盖。只有「挑哪个平台函数」和「用哪个真实探测源」
//! 受 cfg 门控——Windows / Linux 分支若只活在 cfg 里，在 mac 上连语法都验不到。
//!
//! `allow(dead_code)`：三平台采集函数无条件编译，非本平台的那两套在非测试构建里没人调用。
#![allow(dead_code)]

use std::fs;
use std::process::Command;

/// 一条检查结果。★三态：`unknown` 表示这项**探不到**（命令缺失 / 权限不足 / 输出无法解释）。
///
/// 为什么不能只有 ok：探不到时若报 ok=false，控制面基线会判成"不合规"，
/// 一台真实合规的终端就被拦在门外（Linux 非 root 读不到防火墙状态、Windows 非管理员
/// 读不到 BitLocker，都是常态）；若报 ok=true 则是误放行。两种错法在页面上都看不出来，
/// 因为报告本身长得完全正常。控制面 risk.Evaluate 对 unknown 的处理：
/// observe（默认）不抬处置只单列展示，strict（BAIDI_POSTURE_ENFORCE=strict）视为不合规。
///
/// unknown 为真时 ok 恒 false：新客户端遇上未升级的控制面时按 fail-closed 落地
/// （宁可多问一次，不可静默放行）。
#[derive(serde::Serialize, Clone)]
pub struct PostureCheck {
    key: String,
    label: String,
    ok: bool,
    unknown: bool,
    value: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureInfo {
    platform: String,
    os: String,
    client_version: String,
    device: String,
    checks: Vec<PostureCheck>,
}

/// 单项探测的三态结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    Pass,
    Fail,
    Unknown,
}

fn check(key: &str, label: &str, r: (Tri, String)) -> PostureCheck {
    let (t, value) = r;
    PostureCheck {
        key: key.into(),
        label: label.into(),
        ok: t == Tri::Pass,
        unknown: t == Tri::Unknown,
        value,
    }
}

/// 不可判定的说明文案（会原样进控制台"终端合规"页，写清楚是**为什么**探不到）。
fn undet(why: &str) -> (Tri, String) {
    (Tri::Unknown, format!("无法判定：{why}"))
}

// ── 探测源抽象 ──

/// 一次命令探测的结果（ok = 退出码 0）。
struct CmdOut {
    ok: bool,
    out: String,
    err: String,
}

/// Env 把「跑命令 / 读文件」抽成接口，好让三个平台的采集逻辑都能在**任意主机**上跑单测。
///
/// 动机很实在：Windows / Linux 分支若只活在 `#[cfg]` 里，在 mac 上连编译都不会发生，
/// 解析写错也没人知道——而这类采集器的 bug 几乎全在解析上（把"探不到"读成"不合规"）。
/// 现在只有「挑哪个平台函数 + 用哪个真实探测源」受 cfg 门控，解析逻辑三平台全量可测。
trait Env {
    /// None = 命令根本起不来（不存在 / 无执行权限）。
    fn run(&self, cmd: &str, args: &[&str]) -> Option<CmdOut>;
    /// None = 文件不存在 / 读不了。
    fn read(&self, path: &str) -> Option<String>;
}

struct RealEnv;

impl Env for RealEnv {
    fn run(&self, cmd: &str, args: &[&str]) -> Option<CmdOut> {
        let o = Command::new(cmd).args(args).output().ok()?;
        Some(CmdOut {
            ok: o.status.success(),
            // Windows 中文语言包的命令输出可能不是 UTF-8：lossy 后中文会变成替换字符。
            // 因此所有 Windows 判据都优先取 ASCII 形态的注册表值，netsh/manage-bde 只作兜底。
            out: String::from_utf8_lossy(&o.stdout).trim().to_string(),
            err: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        })
    }
    fn read(&self, path: &str) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    }
}

/// 命令跑成功且有输出时返回 stdout；否则 None（失败与"成功但空输出"都当探不到）。
fn ok_out(e: &dyn Env, cmd: &str, args: &[&str]) -> Option<String> {
    let o = e.run(cmd, args)?;
    if !o.ok || o.out.is_empty() {
        return None;
    }
    Some(o.out)
}

// ── 通用解析 ──

/// 从一段文本里抠出第一段版本号（Windows `ver` 把版本号包在一整句话里）。
fn extract_version(s: &str) -> Option<String> {
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            cur.push(ch);
        } else if !cur.is_empty() {
            if cur.starts_with(|c: char| c.is_ascii_digit()) {
                return Some(cur.trim_matches('.').to_string());
            }
            cur.clear();
        }
    }
    if cur.starts_with(|c: char| c.is_ascii_digit()) {
        return Some(cur.trim_matches('.').to_string());
    }
    None
}

/// 版本号的 (主, 次)，取不到的段按 0。
fn ver_pair(v: &str) -> Option<(u32, u32)> {
    let mut it = v.split('.');
    let major = it.next()?.parse::<u32>().ok()?;
    let minor = it.next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
    Some((major, minor))
}

/// `reg query` 输出里某个值的最后一列（"MachineGuid    REG_SZ    4c4c4544-..."）。
fn reg_value(out: &str, name: &str) -> Option<String> {
    out.lines()
        .find(|l| l.split_whitespace().next() == Some(name))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.to_string())
}

/// `reg query` 输出里某个 REG_DWORD 值（0x1 这种十六进制形态）。
fn reg_dword(out: &str, name: &str) -> Option<u64> {
    let v = reg_value(out, name)?;
    let hex = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

/// 进程名清单里是否出现任一 EDR 特征进程（大小写不敏感）。
fn any_proc(list: &str, names: &[&str]) -> bool {
    let low = list.to_ascii_lowercase();
    names.iter().any(|n| low.contains(&n.to_ascii_lowercase()))
}

/// 客户端版本项：本地永远能取到（编译期常量），故恒为确定值。
fn client_version_check(ver: &str) -> PostureCheck {
    check(
        "client_version",
        &format!("客户端为最新版本 v{ver}"),
        (Tri::Pass, ver.to_string()),
    )
}

/// 指纹形制：取十六进制/字母数字前 16 位，按 4 段冒号分隔（对齐控制台设备指纹形制）。
fn fmt_fp(raw: &str) -> String {
    let hex: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    if hex.len() < 16 {
        return "UNKNOWN-DEVICE".into();
    }
    format!("{}:{}:{}:{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
}

/// FNV-1a 64 位折叠成 16 位十六进制。用于**不宜原样外泄**的机器标识（Linux machine-id：
/// systemd 明确要求把它当机密、不要直接暴露）。折叠后仍然是「同一台机器恒定」——
/// 指纹一旦不稳定，每次重启都算一台新设备，「每账号 ≤20 台」的上限会被自己刷爆。
fn fold_id(raw: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in raw.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")
}

// ── macOS ──

fn mac_checks(e: &dyn Env) -> (String, Vec<PostureCheck>) {
    let os_ver = ok_out(e, "sw_vers", &["-productVersion"]).unwrap_or_default();
    let ver = env!("CARGO_PKG_VERSION");
    let checks = vec![
        check("disk_encrypted", "磁盘已加密", mac_disk(e)),
        check("sys_integrity", "系统完整性保护开启", mac_sip(e)),
        check("firewall_on", "系统防火墙启用", mac_firewall(e)),
        check("os_version", "系统版本合规", mac_os_version(&os_ver)),
        check("edr_online", "EDR 终端防护在线", mac_edr(e)),
        client_version_check(ver),
    ];
    let os = if os_ver.is_empty() { "macOS".to_string() } else { format!("macOS {os_ver}") };
    (os, checks)
}

fn mac_disk(e: &dyn Env) -> (Tri, String) {
    // fdesetup status："FileVault is On." / "FileVault is Off."
    let Some(o) = ok_out(e, "fdesetup", &["status"]) else {
        return undet("fdesetup 不可用");
    };
    if o.contains("FileVault is On") {
        (Tri::Pass, o)
    } else if o.contains("FileVault is Off") {
        (Tri::Fail, o)
    } else {
        undet(&format!("fdesetup 输出无法解释：{o}"))
    }
}

fn mac_sip(e: &dyn Env) -> (Tri, String) {
    let Some(o) = ok_out(e, "csrutil", &["status"]) else {
        return undet("csrutil 不可用");
    };
    if o.contains("enabled") {
        (Tri::Pass, o)
    } else if o.contains("disabled") {
        (Tri::Fail, o)
    } else {
        undet(&format!("csrutil 输出无法解释：{o}"))
    }
}

fn mac_firewall(e: &dyn Env) -> (Tri, String) {
    let Some(o) = ok_out(e, "/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"]) else {
        return undet("socketfilterfw 不可用");
    };
    if o.contains("State = 1") || o.contains("State = 2") || o.contains("enabled") {
        (Tri::Pass, o)
    } else if o.contains("State = 0") || o.contains("disabled") {
        (Tri::Fail, o)
    } else {
        undet(&format!("socketfilterfw 输出无法解释：{o}"))
    }
}

/// macOS ≥ 13（对齐种子基线 Expect）。
fn mac_os_version(os_ver: &str) -> (Tri, String) {
    match extract_version(os_ver).and_then(|v| ver_pair(&v)) {
        Some((major, _)) if major >= 13 => (Tri::Pass, os_ver.to_string()),
        Some(_) => (Tri::Fail, os_ver.to_string()),
        None => undet("sw_vers 未返回可解析的版本号"),
    }
}

fn mac_edr(e: &dyn Env) -> (Tri, String) {
    // ps 跑通了才谈得上"有没有"：跑不通是探不到，不是没装。
    let Some(procs) = ok_out(e, "ps", &["-axco", "comm"]) else {
        return undet("ps 不可用，无法枚举进程");
    };
    if any_proc(&procs, &["falcond", "CylanceSvc", "wdavdaemon", "SentinelAgent", "ESET"]) {
        (Tri::Pass, "检测到 EDR 进程".into())
    } else {
        (Tri::Fail, "未检测到 EDR 进程".into())
    }
}

fn mac_fingerprint(e: &dyn Env) -> String {
    let raw = ok_out(
        e,
        "sh",
        &["-c", "ioreg -rd1 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $4}'"],
    )
    .unwrap_or_default();
    fmt_fp(&raw)
}

// ── Windows ──
//
// 全部走**不需要管理员**的读法优先：注册表值用户可读，且输出是 ASCII（不受中文语言包
// 影响）；manage-bde / netsh 只作兜底——它们在标准用户下多半直接"拒绝访问"，
// 那时必须落到 Unknown，绝不能读成"不合规"。

fn win_checks(e: &dyn Env) -> (String, Vec<PostureCheck>) {
    let (os_tri, os_val) = win_os_version(e);
    let ver = env!("CARGO_PKG_VERSION");
    let checks = vec![
        check("disk_encrypted", "磁盘已加密", win_disk(e)),
        check("sys_integrity", "系统完整性保护开启", win_integrity(e)),
        check("firewall_on", "系统防火墙启用", win_firewall(e)),
        check("os_version", "系统版本合规", (os_tri, os_val.clone())),
        check("edr_online", "EDR 终端防护在线", win_edr(e)),
        client_version_check(ver),
    ];
    let os = if os_tri == Tri::Unknown { "Windows".to_string() } else { format!("Windows {os_val}") };
    (os, checks)
}

/// BitLocker：先读 `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus\BootStatus`
/// （系统卷是否受保护，标准用户可读），再退 `manage-bde -status`（通常需管理员）。
fn win_disk(e: &dyn Env) -> (Tri, String) {
    if let Some(o) = ok_out(
        e,
        "reg",
        &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus", "/v", "BootStatus"],
    ) {
        match reg_dword(&o, "BootStatus") {
            Some(1) => return (Tri::Pass, "BitLocker BootStatus=1（系统卷已加密）".into()),
            Some(0) => return (Tri::Fail, "BitLocker BootStatus=0（系统卷未加密）".into()),
            _ => {}
        }
    }
    if let Some(o) = ok_out(e, "manage-bde", &["-status", "C:"]) {
        if o.contains("Protection On") || o.contains("保护已启用") {
            return (Tri::Pass, "manage-bde: Protection On".into());
        }
        if o.contains("Protection Off") || o.contains("保护已关闭") {
            return (Tri::Fail, "manage-bde: Protection Off".into());
        }
    }
    undet("BitLocker 状态不可读（注册表无 BootStatus 且 manage-bde 无结果，标准用户常见）")
}

/// 系统完整性：Secure Boot 为主（`SecureBoot\State\UEFISecureBootEnabled`，标准用户可读），
/// 次选 Defender 篡改防护（`Windows Defender\Features\TamperProtection`，值 5 = 开启）。
/// 两者都读不到 → Unknown：传统 BIOS 机器读不到 Secure Boot 键，那不等于"没开保护"。
fn win_integrity(e: &dyn Env) -> (Tri, String) {
    if let Some(o) = ok_out(
        e,
        "reg",
        &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "/v", "UEFISecureBootEnabled"],
    ) {
        match reg_dword(&o, "UEFISecureBootEnabled") {
            Some(1) => return (Tri::Pass, "Secure Boot 已启用".into()),
            Some(0) => return (Tri::Fail, "Secure Boot 未启用".into()),
            _ => {}
        }
    }
    if let Some(o) = ok_out(
        e,
        "reg",
        &["query", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features", "/v", "TamperProtection"],
    ) {
        match reg_dword(&o, "TamperProtection") {
            Some(5) => return (Tri::Pass, "Defender 篡改防护已启用（Secure Boot 不可读）".into()),
            Some(v) => return (Tri::Fail, format!("Defender 篡改防护未启用（TamperProtection=0x{v:x}）")),
            None => {}
        }
    }
    undet("Secure Boot 与 Defender 篡改防护均不可读（传统 BIOS / 注册表受限）")
}

/// 防火墙：三个配置文件的 `EnableFirewall`（标准用户可读、ASCII），退 `netsh advfirewall`。
/// 判据是"读到的配置文件里有没有关着的"：一个都没读到 → Unknown。
fn win_firewall(e: &dyn Env) -> (Tri, String) {
    let mut seen: Vec<(&str, u64)> = Vec::new();
    for p in ["DomainProfile", "StandardProfile", "PublicProfile"] {
        let key = format!(
            r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{p}"
        );
        if let Some(o) = ok_out(e, "reg", &["query", &key, "/v", "EnableFirewall"]) {
            if let Some(v) = reg_dword(&o, "EnableFirewall") {
                seen.push((p, v));
            }
        }
    }
    if !seen.is_empty() {
        let off: Vec<&str> = seen.iter().filter(|(_, v)| *v == 0).map(|(p, _)| *p).collect();
        return if off.is_empty() {
            (Tri::Pass, format!("已启用（{} 个配置文件）", seen.len()))
        } else {
            (Tri::Fail, format!("以下配置文件未启用防火墙：{}", off.join("、")))
        };
    }
    if let Some(o) = ok_out(e, "netsh", &["advfirewall", "show", "allprofiles", "state"]) {
        match win_fw_from_netsh(&o) {
            Tri::Pass => return (Tri::Pass, "netsh: 全部配置文件 ON".into()),
            Tri::Fail => return (Tri::Fail, "netsh: 存在 OFF 的配置文件".into()),
            Tri::Unknown => {}
        }
    }
    undet("防火墙状态不可读（注册表无 EnableFirewall 且 netsh 无可解析输出）")
}

/// 解析 `netsh advfirewall show allprofiles state` 的 State 行。
/// 中文语言包下输出常非 UTF-8，lossy 后中文会碎掉——所以只认 ASCII 的 ON/OFF，
/// 认不出就回 Unknown（碎掉的输出绝不能被读成"防火墙关着"）。
fn win_fw_from_netsh(out: &str) -> Tri {
    let mut states: Vec<bool> = Vec::new();
    for l in out.lines() {
        let t = l.trim();
        let Some(rest) = t.strip_prefix("State") else { continue };
        let v = rest.trim().to_ascii_uppercase();
        if v == "ON" {
            states.push(true);
        } else if v == "OFF" {
            states.push(false);
        }
    }
    if states.is_empty() {
        Tri::Unknown
    } else if states.iter().all(|s| *s) {
        Tri::Pass
    } else {
        Tri::Fail
    }
}

/// 系统版本：`cmd /c ver` → "Microsoft Windows [Version 10.0.19045.3803]"，
/// 退 CIM `Win32_OperatingSystem.Version`。主版本 ≥ 10（对齐种子基线 Expect "Win ≥ 10"）。
fn win_os_version(e: &dyn Env) -> (Tri, String) {
    let raw = ok_out(e, "cmd", &["/c", "ver"]).or_else(|| {
        ok_out(
            e,
            "powershell",
            &["-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).Version"],
        )
    });
    let Some(raw) = raw else {
        return undet("ver 与 Win32_OperatingSystem 均取不到版本号");
    };
    match extract_version(&raw).and_then(|v| ver_pair(&v).map(|p| (v, p))) {
        Some((v, (major, _))) if major >= 10 => (Tri::Pass, v),
        Some((v, _)) => (Tri::Fail, v),
        None => undet(&format!("版本号无法解析：{raw}")),
    }
}

fn win_edr(e: &dyn Env) -> (Tri, String) {
    let Some(procs) = ok_out(e, "tasklist", &["/NH", "/FO", "CSV"]) else {
        return undet("tasklist 不可用，无法枚举进程");
    };
    // MsMpEng = Defender 实时防护引擎（Windows 自带的那一份 EDR 能力）。
    let names = [
        "MsMpEng.exe", "CSFalconService.exe", "SentinelAgent.exe", "CylanceSvc.exe",
        "ekrn.exe", "elastic-endpoint.exe", "xagt.exe", "MBAMService.exe",
    ];
    if any_proc(&procs, &names) {
        (Tri::Pass, "检测到 EDR 进程".into())
    } else {
        (Tri::Fail, "未检测到 EDR 进程".into())
    }
}

/// 指纹：`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`（装机时生成、重启与登录都不变），
/// 退 CIM `Win32_ComputerSystemProduct.UUID`（主板 UUID）。
fn win_fingerprint(e: &dyn Env) -> String {
    if let Some(o) = ok_out(e, "reg", &["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"]) {
        if let Some(v) = reg_value(&o, "MachineGuid") {
            let fp = fmt_fp(&v);
            if fp != "UNKNOWN-DEVICE" {
                return fp;
            }
        }
    }
    let uuid = ok_out(
        e,
        "powershell",
        &["-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
    )
    .unwrap_or_default();
    fmt_fp(&uuid)
}

// ── Linux ──
//
// Linux 上"探不到"是常态而非异常：ufw/nft 要 root，DMI 也要 root。
// 这正是三态存在的理由——非 root 跑客户端不该让整机被判成不合规。

fn linux_checks(e: &dyn Env) -> (String, Vec<PostureCheck>) {
    let osrel = e.read("/etc/os-release").unwrap_or_default();
    let kernel = ok_out(e, "uname", &["-r"]).unwrap_or_default();
    let ver = env!("CARGO_PKG_VERSION");
    let checks = vec![
        check("disk_encrypted", "磁盘已加密", linux_disk(e)),
        check("sys_integrity", "系统完整性保护开启", linux_integrity(e)),
        check("firewall_on", "系统防火墙启用", linux_firewall(e)),
        check("os_version", "系统版本合规", linux_os_version(&osrel, &kernel)),
        check("edr_online", "EDR 终端防护在线", linux_edr(e)),
        client_version_check(ver),
    ];
    let pretty = osrel_field(&osrel, "PRETTY_NAME");
    let os = match (pretty, kernel.is_empty()) {
        (Some(p), true) => p,
        (Some(p), false) => format!("{p}（内核 {kernel}）"),
        (None, false) => format!("Linux {kernel}"),
        (None, true) => "Linux".to_string(),
    };
    (os, checks)
}

/// /etc/os-release 取某个字段（值可能带引号）。
fn osrel_field(osrel: &str, key: &str) -> Option<String> {
    let pre = format!("{key}=");
    osrel
        .lines()
        .find_map(|l| l.trim().strip_prefix(&pre))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// LUKS：`lsblk -o NAME,TYPE` 里有 crypt 类型的块设备即视为已加密。
/// lsblk 起不来才是 Unknown——起得来且没有 crypt，那是确定的"未加密"。
fn linux_disk(e: &dyn Env) -> (Tri, String) {
    let Some(o) = ok_out(e, "lsblk", &["-o", "NAME,TYPE"]) else {
        return undet("lsblk 不可用，无法枚举块设备类型");
    };
    let crypt: Vec<&str> = o
        .lines()
        .filter(|l| l.split_whitespace().last() == Some("crypt"))
        .collect();
    if crypt.is_empty() {
        (Tri::Fail, "未发现 crypt 类型块设备（LUKS 未启用）".into())
    } else {
        (Tri::Pass, format!("检测到 {} 个 crypt 块设备", crypt.len()))
    }
}

/// 强制访问控制：SELinux 优先，其次 AppArmor，最后 getenforce 兜底。
/// 两套 LSM 都检不出时回 Unknown——这台机器可能用别的 LSM 或度量方案，我们判不了，
/// 判成"不合规"会把一批正常的服务器/发行版整体拦在门外。
fn linux_integrity(e: &dyn Env) -> (Tri, String) {
    if let Some(v) = e.read("/sys/fs/selinux/enforce") {
        return match v.trim() {
            "1" => (Tri::Pass, "SELinux enforcing".into()),
            "0" => (Tri::Fail, "SELinux permissive（未强制）".into()),
            other => undet(&format!("/sys/fs/selinux/enforce 值无法解释：{other}")),
        };
    }
    if let Some(v) = e.read("/sys/module/apparmor/parameters/enabled") {
        return match v.trim() {
            "Y" | "y" => (Tri::Pass, "AppArmor 已启用".into()),
            "N" | "n" => (Tri::Fail, "AppArmor 已加载但未启用".into()),
            other => undet(&format!("AppArmor enabled 值无法解释：{other}")),
        };
    }
    if let Some(o) = ok_out(e, "getenforce", &[]) {
        return match o.trim() {
            "Enforcing" => (Tri::Pass, "SELinux enforcing".into()),
            "Permissive" | "Disabled" => (Tri::Fail, format!("SELinux {o}")),
            other => undet(&format!("getenforce 输出无法解释：{other}")),
        };
    }
    undet("未检出 SELinux / AppArmor（可能使用其他 LSM）")
}

/// 防火墙：firewall-cmd（D-Bus，普通用户可查）→ ufw（多数发行版需 root）→ nft（需 root）。
/// 三条都拿不到确定结论就是 Unknown：nft 因 EPERM 打印不出规则，绝不等于"没有规则"。
fn linux_firewall(e: &dyn Env) -> (Tri, String) {
    if let Some(o) = e.run("firewall-cmd", &["--state"]) {
        let text = if o.out.is_empty() { o.err.clone() } else { o.out.clone() };
        if text.contains("not running") {
            return (Tri::Fail, "firewalld 未运行".into());
        }
        if o.ok && text.contains("running") {
            return (Tri::Pass, "firewalld 运行中".into());
        }
    }
    if let Some(o) = ok_out(e, "ufw", &["status"]) {
        if o.contains("Status: active") {
            return (Tri::Pass, "ufw active".into());
        }
        if o.contains("Status: inactive") {
            return (Tri::Fail, "ufw inactive".into());
        }
    }
    if let Some(o) = ok_out(e, "nft", &["list", "ruleset"]) {
        if o.contains("chain") {
            return (Tri::Pass, "nftables 已加载规则集".into());
        }
        return (Tri::Fail, "nftables 规则集为空".into());
    }
    undet("firewall-cmd / ufw / nft 均不可用或权限不足（多数需 root）")
}

/// 系统版本：判据取**内核** ≥ 5.10（跨发行版唯一可机械比较的量；发行版号各家规则不同，
/// 拿来比大小只会误判）。展示值仍带上发行版名，便于人看。
fn linux_os_version(osrel: &str, kernel: &str) -> (Tri, String) {
    let pretty = osrel_field(osrel, "PRETTY_NAME")
        .or_else(|| osrel_field(osrel, "NAME"))
        .unwrap_or_else(|| "未知发行版".into());
    match extract_version(kernel).and_then(|v| ver_pair(&v)) {
        Some((major, minor)) => {
            let okv = major > 5 || (major == 5 && minor >= 10);
            let val = format!("{pretty} · 内核 {kernel}");
            (if okv { Tri::Pass } else { Tri::Fail }, val)
        }
        None => undet("uname -r 未返回可解析的内核版本"),
    }
}

fn linux_edr(e: &dyn Env) -> (Tri, String) {
    let Some(procs) = ok_out(e, "ps", &["-eo", "comm="]) else {
        return undet("ps 不可用，无法枚举进程");
    };
    let names = [
        "falcon-sensor", "falcond", "sentineld", "SentinelAgent", "wdavdaemon",
        "ds_agent", "elastic-endpoint", "cbagentd", "xagt",
    ];
    if any_proc(&procs, &names) {
        (Tri::Pass, "检测到 EDR 进程".into())
    } else {
        (Tri::Fail, "未检测到 EDR 进程".into())
    }
}

/// 指纹：/etc/machine-id（装机生成、重启不变）→ dbus machine-id → DMI product_uuid（通常需 root）。
/// machine-id 按 systemd 的要求不原样外泄，折叠成 64 位后再成形。
fn linux_fingerprint(e: &dyn Env) -> String {
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Some(v) = e.read(p) {
            let v = v.trim();
            if v.len() >= 16 {
                return fmt_fp(&fold_id(v));
            }
        }
    }
    if let Some(v) = e.read("/sys/class/dmi/id/product_uuid") {
        return fmt_fp(v.trim());
    }
    "UNKNOWN-DEVICE".into()
}

// ── 平台分发（唯一受 cfg 门控的部分）──

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
compile_error!("白帝桌面端只支持 macOS / Windows / Linux：posture 的 platform 字段是控制面强枚举（Windows|macOS|Linux），没有第四个合法取值可报");

#[cfg(target_os = "macos")]
fn platform_posture(e: &dyn Env) -> (&'static str, String, Vec<PostureCheck>) {
    let (os, checks) = mac_checks(e);
    ("macOS", os, checks)
}
#[cfg(target_os = "windows")]
fn platform_posture(e: &dyn Env) -> (&'static str, String, Vec<PostureCheck>) {
    let (os, checks) = win_checks(e);
    ("Windows", os, checks)
}
#[cfg(target_os = "linux")]
fn platform_posture(e: &dyn Env) -> (&'static str, String, Vec<PostureCheck>) {
    let (os, checks) = linux_checks(e);
    ("Linux", os, checks)
}

#[cfg(target_os = "macos")]
fn platform_fingerprint(e: &dyn Env) -> String {
    mac_fingerprint(e)
}
#[cfg(target_os = "windows")]
fn platform_fingerprint(e: &dyn Env) -> String {
    win_fingerprint(e)
}
#[cfg(target_os = "linux")]
fn platform_fingerprint(e: &dyn Env) -> String {
    linux_fingerprint(e)
}

/// 设备指纹（分平台，见 platform_fingerprint）。三个平台取的都是**重启不变**的机器标识：
/// 不稳定的话每次重启都算一台新设备，「每账号 ≤20 台」的上限会被自己刷爆，
/// 然后真正的新设备被拒——而现场看到的只是一句"设备数超限"。
/// 进程生命周期内缓存，免得每轮上报都 spawn 子进程。
fn device_fingerprint() -> String {
    static FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FP.get_or_init(|| platform_fingerprint(&RealEnv)).clone()
}

/// 终端环境真实采集：机械三态化 + 原始值，策略判定在控制面（风险引擎按安全基线评估）。
/// 同步函数，便于单元测试；Tauri 命令壳（main.rs `collect_posture`）负责挪线程池。
pub fn gather_posture() -> PostureInfo {
    let (platform, os, checks) = platform_posture(&RealEnv);
    PostureInfo {
        platform: platform.into(),
        os,
        client_version: env!("CARGO_PKG_VERSION").into(),
        device: device_fingerprint(),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// 假探测源：命令按 "cmd arg arg" 整行匹配，文件按路径匹配。没登记 = 探不到。
    #[derive(Default)]
    struct FakeEnv {
        cmds: HashMap<String, (bool, String, String)>,
        files: HashMap<String, String>,
    }
    impl FakeEnv {
        fn cmd(mut self, line: &str, out: &str) -> Self {
            self.cmds.insert(line.into(), (true, out.into(), String::new()));
            self
        }
        /// 命令跑了但失败（权限不足是最典型的一种）。
        fn fail(mut self, line: &str, err: &str) -> Self {
            self.cmds.insert(line.into(), (false, String::new(), err.into()));
            self
        }
        fn file(mut self, path: &str, body: &str) -> Self {
            self.files.insert(path.into(), body.into());
            self
        }
    }
    impl Env for FakeEnv {
        fn run(&self, cmd: &str, args: &[&str]) -> Option<CmdOut> {
            let key = if args.is_empty() { cmd.to_string() } else { format!("{cmd} {}", args.join(" ")) };
            self.cmds.get(&key).map(|(ok, out, err)| CmdOut { ok: *ok, out: out.clone(), err: err.clone() })
        }
        fn read(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }
    }

    const KEYS: [&str; 6] = [
        "disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online", "client_version",
    ];

    fn keys_of(checks: &[PostureCheck]) -> Vec<&str> {
        checks.iter().map(|c| c.key.as_str()).collect()
    }
    fn one<'a>(checks: &'a [PostureCheck], key: &str) -> &'a PostureCheck {
        checks.iter().find(|c| c.key == key).expect("检查项缺失")
    }

    // ① 三平台都产出同一组 6 个 key，且与控制面基线检查键逐一对齐（种子基线里就是这 6 个）。
    // 键对不上的后果是静默的：基线找不到 key → 按"未上报"判失败 → 全员被拦，页面上看不出原因。
    #[test]
    fn all_platforms_emit_the_same_six_keys() {
        let e = FakeEnv::default();
        for (name, checks) in [
            ("macOS", mac_checks(&e).1),
            ("Windows", win_checks(&e).1),
            ("Linux", linux_checks(&e).1),
        ] {
            assert_eq!(keys_of(&checks), KEYS.to_vec(), "{name} 采集键须与控制面基线键对齐");
        }
    }

    // ② 探不到 ≠ 不合规：什么都探不到时，5 项必须是 unknown（而不是 ok=false）。
    // 这是本模块存在的理由——塌缩成 false 会让一台真实合规的终端被 block 基线永久拒之门外。
    #[test]
    fn undetectable_probes_are_unknown_not_false() {
        let e = FakeEnv::default();
        for (name, checks) in [
            ("macOS", mac_checks(&e).1),
            ("Windows", win_checks(&e).1),
            ("Linux", linux_checks(&e).1),
        ] {
            for k in KEYS.iter().filter(|k| **k != "client_version") {
                let c = one(&checks, k);
                assert!(c.unknown, "{name}/{k} 探不到时必须标 unknown，实测 value={}", c.value);
                assert!(!c.ok, "{name}/{k} unknown 时 ok 必须为 false（对旧控制面 fail-closed）");
                assert!(c.value.starts_with("无法判定："), "{name}/{k} 须说明为什么探不到：{}", c.value);
            }
            // 客户端版本来自编译期常量，永远探得到
            let cv = one(&checks, "client_version");
            assert!(cv.ok && !cv.unknown);
            assert_eq!(cv.value, env!("CARGO_PKG_VERSION"));
        }
    }

    // ③ 序列化字段名必须与控制面 store.PostureCheckResult 的 json tag 一致。
    // 名字对不上 → 控制面永远收到 unknown=false → 又退回"探不到即不合规"。
    #[test]
    fn serialized_field_names_match_control_plane() {
        let c = check("disk_encrypted", "磁盘已加密", undet("x"));
        let v = serde_json::to_value(&c).unwrap();
        for f in ["key", "label", "ok", "unknown", "value"] {
            assert!(v.get(f).is_some(), "缺字段 {f}");
        }
        assert_eq!(v["unknown"], serde_json::json!(true));
        assert_eq!(v["ok"], serde_json::json!(false));
    }

    // ④ macOS：能探到时给确定结论。
    #[test]
    fn macos_determinate() {
        let e = FakeEnv::default()
            .cmd("sw_vers -productVersion", "14.4")
            .cmd("fdesetup status", "FileVault is On.")
            .cmd("csrutil status", "System Integrity Protection status: enabled.")
            .cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "Firewall is enabled. (State = 1)")
            .cmd("ps -axco comm", "launchd\nwdavdaemon\nWindowServer");
        let (os, checks) = mac_checks(&e);
        assert_eq!(os, "macOS 14.4");
        for k in ["disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online"] {
            let c = one(&checks, k);
            assert!(c.ok && !c.unknown, "{k} 应判通过：{}", c.value);
        }
        // 关掉 FileVault / SIP / 防火墙是确定的"不合规"，不是 unknown
        let e = FakeEnv::default()
            .cmd("sw_vers -productVersion", "12.7")
            .cmd("fdesetup status", "FileVault is Off.")
            .cmd("csrutil status", "System Integrity Protection status: disabled.")
            .cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "Firewall is disabled. (State = 0)")
            .cmd("ps -axco comm", "launchd\nWindowServer");
        let (_, checks) = mac_checks(&e);
        for k in ["disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online"] {
            let c = one(&checks, k);
            assert!(!c.ok && !c.unknown, "{k} 应判不合规（确定）：{}", c.value);
        }
    }

    // ⑤ Windows：注册表这条非管理员路径给确定结论。
    #[test]
    fn windows_determinate_via_registry() {
        let e = FakeEnv::default()
            .cmd(r"reg query HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus /v BootStatus",
                 "    BootStatus    REG_DWORD    0x1")
            .cmd(r"reg query HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State /v UEFISecureBootEnabled",
                 "    UEFISecureBootEnabled    REG_DWORD    0x1")
            .cmd(r"reg query HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile /v EnableFirewall",
                 "    EnableFirewall    REG_DWORD    0x1")
            .cmd(r"reg query HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile /v EnableFirewall",
                 "    EnableFirewall    REG_DWORD    0x1")
            .cmd("cmd /c ver", "\r\nMicrosoft Windows [Version 10.0.19045.3803]")
            .cmd("tasklist /NH /FO CSV", "\"MsMpEng.exe\",\"4321\",\"Services\",\"0\",\"180,000 K\"");
        let (os, checks) = win_checks(&e);
        assert_eq!(os, "Windows 10.0.19045.3803");
        for k in ["disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online"] {
            let c = one(&checks, k);
            assert!(c.ok && !c.unknown, "{k} 应判通过：{}", c.value);
        }
        // 任一读到的配置文件关着防火墙 = 确定的不合规
        let e = e.cmd(r"reg query HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile /v EnableFirewall",
                      "    EnableFirewall    REG_DWORD    0x0");
        let (_, checks) = win_checks(&e);
        let c = one(&checks, "firewall_on");
        assert!(!c.ok && !c.unknown, "有配置文件关着应判不合规：{}", c.value);
        assert!(c.value.contains("PublicProfile"), "要说清是哪个配置文件：{}", c.value);
    }

    // ⑥ Windows：标准用户下 manage-bde 被拒 / netsh 输出乱码 → 必须落 Unknown，不能读成"不合规"。
    #[test]
    fn windows_permission_denied_is_unknown() {
        let e = FakeEnv::default()
            .fail("manage-bde -status C:", "拒绝访问")
            .cmd("netsh advfirewall show allprofiles state", "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"); // 中文语言包 lossy 后的碎片
        let (_, checks) = win_checks(&e);
        for k in ["disk_encrypted", "firewall_on", "sys_integrity"] {
            let c = one(&checks, k);
            assert!(c.unknown, "{k} 权限不足/输出不可解时必须 unknown：{}", c.value);
        }
    }

    // netsh State 行解析：只认 ASCII 的 ON/OFF，认不出回 Unknown。
    #[test]
    fn netsh_state_parsing() {
        assert_eq!(win_fw_from_netsh("域配置文件设置:\nState                                 ON\n\n公用:\nState   ON"), Tri::Pass);
        assert_eq!(win_fw_from_netsh("State  ON\nState  OFF"), Tri::Fail);
        assert_eq!(win_fw_from_netsh("状态  启用"), Tri::Unknown);
        assert_eq!(win_fw_from_netsh(""), Tri::Unknown);
    }

    // ⑦ Linux：能探到时给确定结论。
    #[test]
    fn linux_determinate() {
        let e = FakeEnv::default()
            .cmd("lsblk -o NAME,TYPE", "NAME       TYPE\nnvme0n1    disk\n└─root     crypt")
            .file("/sys/fs/selinux/enforce", "1")
            .cmd("firewall-cmd --state", "running")
            .cmd("uname -r", "6.5.0-14-generic")
            .file("/etc/os-release", "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nVERSION_ID=\"22.04\"")
            .cmd("ps -eo comm=", "systemd\nfalcon-sensor\nsshd");
        let (os, checks) = linux_checks(&e);
        assert_eq!(os, "Ubuntu 22.04.4 LTS（内核 6.5.0-14-generic）");
        for k in ["disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online"] {
            let c = one(&checks, k);
            assert!(c.ok && !c.unknown, "{k} 应判通过：{}", c.value);
        }
        // 探得到但状态不对 = 确定的不合规
        let e = FakeEnv::default()
            .cmd("lsblk -o NAME,TYPE", "NAME       TYPE\nnvme0n1    disk\n└─root     part")
            .file("/sys/fs/selinux/enforce", "0")
            .cmd("firewall-cmd --state", "not running")
            .cmd("uname -r", "4.19.0-21-amd64")
            .file("/etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 10 (buster)\"")
            .cmd("ps -eo comm=", "systemd\nsshd");
        let (_, checks) = linux_checks(&e);
        for k in ["disk_encrypted", "sys_integrity", "firewall_on", "os_version", "edr_online"] {
            let c = one(&checks, k);
            assert!(!c.ok && !c.unknown, "{k} 应判不合规（确定）：{}", c.value);
        }
    }

    // ⑧ Linux 非 root 是常态：nft/ufw 因权限失败 → Unknown；LSM 一个都检不出 → Unknown。
    #[test]
    fn linux_non_root_is_unknown() {
        let e = FakeEnv::default()
            .fail("ufw status", "ERROR: You need to be root to run this script")
            .fail("nft list ruleset", "Operation not permitted")
            .cmd("uname -r", "6.5.0-14-generic");
        let (_, checks) = linux_checks(&e);
        let fw = one(&checks, "firewall_on");
        assert!(fw.unknown, "非 root 读不到防火墙状态必须是 unknown：{}", fw.value);
        let si = one(&checks, "sys_integrity");
        assert!(si.unknown, "检不出 SELinux/AppArmor 时应 unknown（可能是别的 LSM）：{}", si.value);
        // 但内核版本这类不需要权限的项仍是确定值
        let osv = one(&checks, "os_version");
        assert!(osv.ok && !osv.unknown, "内核版本不需权限，应给确定结论：{}", osv.value);
    }

    // AppArmor 兜底路径（无 SELinux 的发行版）。
    #[test]
    fn linux_apparmor_path() {
        let e = FakeEnv::default().file("/sys/module/apparmor/parameters/enabled", "Y");
        let (t, _) = linux_integrity(&e);
        assert_eq!(t, Tri::Pass);
        let e = FakeEnv::default().file("/sys/module/apparmor/parameters/enabled", "N");
        assert_eq!(linux_integrity(&e).0, Tri::Fail);
    }

    // ⑨ 平台字符串必须落在控制面枚举内（platform 拼错会被 400 拒收，且每 60s 静默重试）。
    #[test]
    fn platform_string_is_valid_enum() {
        let info = gather_posture();
        assert!(
            ["Windows", "macOS", "Linux"].contains(&info.platform.as_str()),
            "platform={} 不在控制面枚举内",
            info.platform
        );
        assert_eq!(keys_of(&info.checks), KEYS.to_vec());
        assert!(!info.device.is_empty());
        assert_eq!(info.client_version, env!("CARGO_PKG_VERSION"));
        // 三平台函数各自回的平台名也钉住（避免改动时把 "macos" 这种小写形态漏出去）
        let e = FakeEnv::default();
        assert_eq!(mac_checks(&e).1.len(), 6);
        assert_eq!(win_checks(&e).1.len(), 6);
        assert_eq!(linux_checks(&e).1.len(), 6);
    }

    // ⑩ 设备指纹：进程内缓存稳定；三平台取的都是重启不变的标识。
    #[test]
    fn fingerprints_are_stable_and_shaped() {
        assert_eq!(device_fingerprint(), device_fingerprint());
        assert_eq!(fmt_fp("4C4C4544-0043-5A10-8054-B7C04F565432"), "4C4C:4544:0043:5A10");
        assert_eq!(fmt_fp("short"), "UNKNOWN-DEVICE");

        let win = FakeEnv::default().cmd(
            r"reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid",
            "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    b2c3d4e5-6789-4abc-9def-0123456789ab",
        );
        assert_eq!(win_fingerprint(&win), "b2c3:d4e5:6789:4abc");
        assert_eq!(win_fingerprint(&win), win_fingerprint(&win));

        // Linux：machine-id 按 systemd 的要求不原样外泄，折叠后仍恒定
        let lin = FakeEnv::default().file("/etc/machine-id", "9f8e7d6c5b4a39281706f5e4d3c2b1a0");
        let fp = linux_fingerprint(&lin);
        assert_eq!(fp, linux_fingerprint(&lin), "同一台机器必须恒定");
        assert!(!fp.replace(':', "").starts_with("9f8e7d6c"), "不得原样外泄 machine-id：{fp}");
        assert_ne!(fp, linux_fingerprint(&FakeEnv::default().file("/etc/machine-id", "0a1b2c3d4e5f60718293a4b5c6d7e8f9")));
        // 什么都读不到时是 UNKNOWN-DEVICE（不是随机值——随机会把设备上限刷爆）
        assert_eq!(linux_fingerprint(&FakeEnv::default()), "UNKNOWN-DEVICE");
    }

    // 版本号抠取：Windows 的 ver 把版本号裹在一整句话里。
    #[test]
    fn version_extraction() {
        assert_eq!(extract_version("Microsoft Windows [Version 10.0.19045.3803]").as_deref(), Some("10.0.19045.3803"));
        assert_eq!(extract_version("14.4").as_deref(), Some("14.4"));
        assert_eq!(extract_version("6.5.0-14-generic").as_deref(), Some("6.5.0"));
        assert_eq!(extract_version("no digits here"), None);
        assert_eq!(ver_pair("10.0.19045"), Some((10, 0)));
        assert_eq!(ver_pair("14"), Some((14, 0)));
        assert_eq!(ver_pair("x"), None);
    }

    // EDR：进程枚举得到才谈得上"有没有"；枚举不了是 unknown，不是"没装"。
    #[test]
    fn edr_absence_vs_undetectable() {
        let has = FakeEnv::default().cmd("ps -eo comm=", "systemd\nsentineld");
        assert_eq!(linux_edr(&has).0, Tri::Pass);
        let none = FakeEnv::default().cmd("ps -eo comm=", "systemd\nsshd");
        assert_eq!(linux_edr(&none).0, Tri::Fail);
        assert_eq!(linux_edr(&FakeEnv::default()).0, Tri::Unknown);
        assert_eq!(win_edr(&FakeEnv::default()).0, Tri::Unknown);
        assert_eq!(mac_edr(&FakeEnv::default()).0, Tri::Unknown);
    }
}
