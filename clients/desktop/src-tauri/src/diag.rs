//! 自助诊断包（FR-INTRO-13）：把排障需要的四份材料**脱敏后**汇成一个纯文本文件落到桌面。
//!
//! 这个包的用途决定了它的全部设计约束：它会被用户**用邮件发给管理员**。也就是说它一旦
//! 生成，就脱离了客户端所有的保护（私有目录 0700、文件 0600 在这一步全部失效）。因此：
//!
//!  1. **只读白名单里的文件，绝不 `read_dir` 运行目录**。同一个目录里还躺着提权用的
//!     `baidi-tun-launch.sh`，里面有一行 `export BAIDI_TOKEN='<会话JWT>'`
//!     （见 elevate::unix_start_script）。它是用后即删的，但"提权被取消 / 客户端崩了"
//!     都会把它留在原地——遍历目录就等于把一张有效会话令牌装进要外发的包裹。
//!  2. **进包的每一个字节都过 [`redact`]**，包括前端传来的 report。前端那份**现在就带着
//!     令牌**：`tunnel.ts` 的 `resolveTunOpts()` 里有 `token: session.token`，而"接入信息"
//!     正是取自那个快照（`startedOpts`）。指望调用方记得摘掉是靠不住的，这里按"传进来的
//!     东西一律有毒"处理。
//!  3. 落纯文本而不是 zip：这个包裹最重要的性质是**用户能在记事本里打开、亲眼看见自己
//!     要发出去什么**。看不见的脱敏等于没有脱敏。
//!
//! 反过来，包里**仍然含有**内网网段、业务地址、资源 id、网关落点地址、隧道内 DNS 记录——
//! 那是一张内网资产地图，但也正是排障所需，抹掉就没有诊断价值了。做法是在包头**如实写明**，
//! 让用户在发之前知道自己在发什么，而不是偷偷塞进去或者一刀切抹掉。

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::Manager;

use crate::elevate::Paths;

/// 单份日志进包的字节上限（取**尾巴**，最近的才有诊断价值）。
/// 无上限的话，一份跑了几周的日志能把这个文件撑到几百 MB——既发不出去也打不开。
const LOG_BUDGET: usize = 2 * 1024 * 1024;

// ══════════════════ 脱敏 ══════════════════

/// base64url 字符集（JWT 三段各自的字符集）。
fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// JWT 单段的最小长度。8 是为了把 `1.2.3`（版本号）、`10.99.0.2`（IP）挡在外面——
/// 真实 JWT 的三段分别是 ~36 / 数十 / 86（Ed25519 签名）字符，离 8 很远。
const SEG_MIN: usize = 8;

/// 脱敏：先按**结构**抹掉 JWT 形状的串，再按**键名**抹掉非 JWT 形状的凭据。
///
/// 两道都要有，缺一不可：
///  - 只按键名 → 日志里裸奔的一串 JWT（没有 `token=` 前缀）漏网；
///  - 只按结构 → 不透明的会话串（`token=abc123`）漏网。
///
/// **幂等**：占位符以 `«` 开头（非 ASCII），既进不了 JWT 字符集，也被键值那道的哨兵挡住。
pub fn redact(input: &str) -> String {
    redact_kv(&redact_jwt(input))
}

/// 脱敏了几处（进包头，让管理员一眼看出脱敏器确实跑过；0 也是有效信息）。
pub fn redacted_count(s: &str) -> usize {
    s.matches("«已脱敏").count()
}

fn mask(len: usize) -> String {
    // 保留长度：管理员最常问的是"令牌是不是空的 / 是不是被截断了"，
    // 抹成一个定长星号串会把这个问题也一起抹掉，那就白脱敏了。
    format!("«已脱敏·长度{len}»")
}

/// UTF-8 首字节 → 该字符的字节数。日志里几乎每行都有中文，**任何切割都必须落在字符边界上**
/// （同 main.rs `log_tail` 那条教训：切在续接字节上是直接 panic，不是断言失败）。
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// 按结构抹掉 `<8+>.<8+>.<8+>`（base64url）的串。
fn redact_jwt(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        // 只在「token 字符集的起始位置」开一个 run，避免从中间切进去。
        let starts_run = is_b64url(b[i]) && (i == 0 || (!is_b64url(b[i - 1]) && b[i - 1] != b'.'));
        if !starts_run {
            let n = utf8_len(b[i]);
            out.push_str(&s[i..i + n]);
            i += n;
            continue;
        }
        let start = i;
        let mut j = i;
        while j < b.len() && (is_b64url(b[j]) || b[j] == b'.') {
            j += 1;
        }
        let run = &s[start..j];
        match find_jwt_span(run) {
            Some((a, z)) => {
                out.push_str(&run[..a]);
                out.push_str(&mask(z - a));
                out.push_str(&run[z..]);
            }
            None => out.push_str(run),
        }
        i = j;
    }
    out
}

/// 在一段「字母数字 `-` `_` `.`」的 run 里找连续三段都 ≥ SEG_MIN 的窗口。
/// 用「连续三段」而不是「整个 run 恰好三段」：句末的 `.`、多余的后缀都不该让令牌逃掉。
fn find_jwt_span(run: &str) -> Option<(usize, usize)> {
    let b = run.as_bytes();
    let mut segs: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    for (k, &c) in b.iter().enumerate() {
        if c == b'.' {
            segs.push((start, k));
            start = k + 1;
        }
    }
    segs.push((start, b.len()));
    segs.windows(3)
        .find(|w| w.iter().all(|&(a, z)| z - a >= SEG_MIN && b[a..z].iter().all(|&c| is_b64url(c))))
        .map(|w| (w[0].0, w[2].1))
}

/// 凭据键名。**刻意不含 `pin` / `device` / `jti` / `resource`**：
/// 那些不是凭据，而且正是排障要看的东西（钉扎指纹对不对、设备指纹跟台账对不对得上）。
/// 往这个表里加东西之前先问一句：抹了它，管理员还能诊断吗。
const SECRET_KEYS: &[&str] = &[
    "baidi_token",
    "authorization",
    "mfaticket",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "bearer",
    "token",
    "pwd",
];

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    i
}

fn redact_kv(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    'outer: while i < b.len() {
        // 键必须整词命中：`tokenTtl` 不该被当成 `token`（后一个字符仍是标识符字符）。
        if is_ident(b[i]) && (i == 0 || !is_ident(b[i - 1])) {
            for key in SECRET_KEYS {
                let kb = key.as_bytes();
                let e = i + kb.len();
                if e <= lb.len() && &lb[i..e] == kb && (e == lb.len() || !is_ident(lb[e])) {
                    if let Some((vs, ve)) = value_span(b, key, e) {
                        out.push_str(&s[i..vs]);
                        out.push_str(&mask(ve - vs));
                        i = ve;
                        continue 'outer;
                    }
                }
            }
        }
        let n = utf8_len(b[i]);
        out.push_str(&s[i..i + n]);
        i += n;
    }
    out
}

/// 定位键后面那个值的 [start, end)。返回 None = 这里没有值可抹（原样保留）。
fn value_span(b: &[u8], key: &str, after_key: usize) -> Option<(usize, usize)> {
    let mut i = skip_ws(b, after_key);
    // 键名自己可能被引号包着（JSON 的 `"token": "v"`）：只有其后确实跟着分隔符才跳过收尾引号，
    // 否则 `token "v"` 里那个引号其实是值的**起始**引号。
    if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
        let n = skip_ws(b, i + 1);
        if n < b.len() && (b[n] == b'=' || b[n] == b':') {
            i = n;
        }
    }
    let mut sep = false;
    if i < b.len() && (b[i] == b'=' || b[i] == b':') {
        i += 1;
        sep = true;
    }
    // 只有 `Bearer <凭据>` 这种键后直接跟值的形态允许没有分隔符。
    if !sep && *key != *"bearer" {
        return None;
    }
    i = skip_ws(b, i);
    let quote = match b.get(i) {
        Some(&q) if q == b'"' || q == b'\'' => {
            i += 1;
            Some(q)
        }
        _ => None,
    };
    let start = i;
    // ★幂等哨兵：值已经是 `«…»` 占位符就别再套一层（« = U+00AB = C2 AB）。
    if b.get(start) == Some(&0xC2) && b.get(start + 1) == Some(&0xAB) {
        return None;
    }
    while i < b.len() {
        let c = b[i];
        let stop = match quote {
            Some(q) => c == q,
            // Authorization 头的值是「Bearer <凭据>」**整体**，遇空格就停会把凭据留在原地。
            None if *key == *"authorization" => c == b'\n' || c == b'\r',
            None => c.is_ascii_whitespace() || c == b',' || c == b'}' || c == b'&' || c == b';',
        };
        if stop {
            break;
        }
        i += 1;
    }
    if i == start {
        return None;
    }
    Some((start, i))
}

// ══════════════════ UTC 时间（无依赖） ══════════════════

/// 格式化 UTC 时间。**刻意只出 UTC 并在文案里标明**：不引 chrono 就拿不到本地时区偏移，
/// 而把 UTC 冒充成本地时间会让管理员按错的时间去比对服务端审计——那比没有时间更糟。
/// 日志正文里每行自带 baidi-tun 打的时间戳，对齐用那个。
pub fn fmt_utc(secs: u64, compact: bool) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let r = secs % 86_400;
    let (hh, mm, ss) = (r / 3600, (r % 3600) / 60, r % 60);
    if compact {
        format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    }
}

/// Howard Hinnant 的 civil_from_days（公有领域算法）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ══════════════════ 取材：白名单 ══════════════════

/// **会被读取正文**的运行期文件白名单。返回 (小节标题, 路径)。
///
/// ★两份日志都要收。`baidi-tun` 的 slog 写的是 **stdout**
/// （gateway/cmd/baidi-tun/main.go:65 `slog.NewTextHandler(os.Stdout, …)`），
/// 而 Windows 的 launcher 把 stdout 重定向到 `paths.out`、stderr 重定向到 `paths.log`
/// （`Start-Process` 不允许两路指向同一个文件）。也就是说 **Windows 上 `baidi-tun.log`
/// 基本是空的，真正的日志全在 `baidi-tun.out.log` 里**（只有 `log.Fatal` 那几条走 stderr）。
/// unix 侧 `>log 2>&1` 合流，`out` 根本不存在——所以"两个都收、缺的如实说缺"是唯一
/// 三平台都正确的取法。只收 `paths.log` 的话，最需要远程排障的那个平台会拿到一个空包。
fn log_sources(p: &Paths) -> Vec<(&'static str, String)> {
    vec![
        ("baidi-tun 日志 · stderr（unix 上与 stdout 合流）", p.log.clone()),
        ("baidi-tun 日志 · stdout（Windows 上 slog 实际写这里）", p.out.clone()),
    ]
}

/// **只列存在性/大小，永不读正文**的运行期文件。
///
/// `launch` / `stop` 两个提权脚本在列表里是**故意的**：残留的 launcher 本身就是一条诊断
/// 线索（说明上一次提权崩在半路）。但它含会话令牌，因此只出现在这份"元数据清单"里，
/// 与 [`log_sources`] 是两个互不相通的表——**正文白名单里永远没有它**。
fn listed_files(p: &Paths) -> Vec<(&'static str, String)> {
    vec![
        ("pid", p.pid.clone()),
        ("资源映射表 resmap", p.resmap.clone()),
        ("网关落点清单 gateways", p.gateways.clone()),
        ("隧道内 DNS 记录表", p.dnsrec.clone()),
        ("提权 launcher（含令牌，仅列存在性，绝不读正文）", p.launch.clone()),
        ("断开脚本（仅列存在性，绝不读正文）", p.stop.clone()),
    ]
}

fn read_capped(path: &str) -> String {
    match fs::read_to_string(path) {
        Ok(s) if s.is_empty() => String::from("（文件存在但内容为空）"),
        Ok(s) if s.len() > LOG_BUDGET => {
            // 复用 main.rs 那个按**字符边界**回退的取尾函数，别再手写一次字节切片。
            format!(
                "（原文 {} 字节，超出 {LOG_BUDGET} 上限，以下只保留最近部分）\n{}",
                s.len(),
                crate::log_tail(&s, LOG_BUDGET)
            )
        }
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::from("（无此文件）"),
        Err(e) => format!("（读取失败：{e}）"),
    }
}

fn file_note(path: &str) -> String {
    match fs::metadata(path) {
        Ok(md) => format!("存在，{} 字节", md.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::from("不存在"),
        Err(e) => format!("无法读取元数据：{e}"),
    }
}

// ══════════════════ 落盘位置 ══════════════════

/// 挑一个「用户找得到、并且能当附件拖走」的目录。
///
/// 桌面 → 下载 → 文档 → 家目录 → 私有运行目录（最后兜底）。
///
/// ★为什么不用 `std::env::home_dir()`：它在 Rust 1.85 已经**解除弃用**（本仓 rustc 1.96 编译
/// 无告警），所以"已弃用"这个理由现在不成立了——但它依然是错的工具：家目录 ≠ 桌面，而
/// Windows 的桌面是 `{FOLDERID_Desktop}`，被 OneDrive 重定向或改到网络盘是常态，
/// 拼 `%USERPROFILE%\Desktop` 会写进一个用户根本看不到（甚至不存在）的目录。
/// `app.path().desktop_dir()` 走的是各平台的已知文件夹 API（Linux 走 XDG_DESKTOP_DIR）。
///
/// ★不用为此加 `dirs` 依赖：`dirs v6` 本来就在依赖树里（tauri 传递依赖），而 Tauri 2 的
/// `PathResolver` 已经把它包出来了，Cargo.toml 一行都不用改。
fn output_dir(app: &tauri::AppHandle) -> PathBuf {
    let r = app.path();
    for d in [r.desktop_dir(), r.download_dir(), r.document_dir(), r.home_dir()] {
        if let Ok(d) = d {
            if d.is_dir() {
                return d;
            }
        }
    }
    PathBuf::from(crate::runtime_dir())
}

// ══════════════════ 命令 ══════════════════

/// 生成诊断包，返回落盘的绝对路径（前端把它显示出来，让用户知道去哪儿找）。
///
/// `report` 是前端已有的诊断结果 JSON（各检查项结论 / 剖面快照 / 接入信息）。
/// 按**不可信**处理——见模块头第 2 条。
///
/// async 的理由与 `collect_posture` 相同：`gather_posture()` 会串行 spawn 好几个探测子进程，
/// 同步跑会卡住 webview 主线程（点一下按钮界面僵住一两秒）。
#[tauri::command]
pub async fn collect_diag(app: tauri::AppHandle, report: String) -> Result<String, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut s = String::with_capacity(64 * 1024);

    s.push_str("==================== 白帝安全接入客户端 · 诊断包 ====================\n");
    s.push_str(&format!("生成时间：{} （UTC，本机时区偏移未计入）\n", fmt_utc(now, false)));
    s.push_str(&format!("客户端版本：{}\n", env!("CARGO_PKG_VERSION")));
    s.push_str(&format!(
        "运行平台：{} / {}（{}）\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    ));
    s.push_str(&format!("私有运行目录：{}\n", crate::runtime_dir()));
    s.push_str(
        "\n【本包已做脱敏】JWT 形状的串、以及 token/authorization/bearer/password/secret 等\n\
         键名下的值，一律被替换成「«已脱敏·长度N»」（只留长度，便于判断是否为空或被截断）。\n\
         【本包仍然包含】内网网段、业务地址与端口、资源 id、网关落点地址、隧道内 DNS 记录、\n\
         网关证书指纹、终端指纹与合规采集结果——它们不是凭据，但合起来是一张内网资产图。\n\
         发送前请确认收件人是你的管理员。\n\
         【本包不包含】提权脚本正文（内含会话令牌，只列存在性）。\n",
    );

    s.push_str("\n-------------------- [1] 前端诊断结果（report） --------------------\n");
    // 能解析就美化一下，解析不了也照单收下——排障包不该因为一段畸形 JSON 就少一节。
    let pretty = serde_json::from_str::<serde_json::Value>(&report)
        .ok()
        .and_then(|v| serde_json::to_string_pretty(&v).ok())
        .unwrap_or_else(|| report.clone());
    s.push_str(if pretty.trim().is_empty() { "（前端未提供）" } else { &pretty });
    s.push('\n');

    s.push_str("\n-------------------- [2] 终端环境采集（posture） --------------------\n");
    match serde_json::to_string_pretty(&crate::posture::gather_posture()) {
        Ok(p) => s.push_str(&p),
        Err(e) => s.push_str(&format!("（采集结果序列化失败：{e}）")),
    }
    s.push('\n');

    s.push_str("\n-------------------- [3] 数据面运行期文件 --------------------\n");
    // ★运行目录复核不通过时**不 `?` 抛出**：那正是最需要一份诊断包的时刻。
    //   但也绝不读里面任何文件（pid/日志都可能是别人塞进来的），把原因如实写进包里。
    match crate::secure_paths() {
        Ok(p) => {
            for (title, path) in log_sources(p) {
                s.push_str(&format!("\n=== {title} ===\n路径：{path}\n"));
                s.push_str(&read_capped(&path));
                s.push('\n');
            }
            s.push_str("\n=== 其余运行期文件（只列存在性，不含正文） ===\n");
            for (title, path) in listed_files(p) {
                s.push_str(&format!("{title}：{}（{path}）\n", file_note(&path)));
            }
        }
        Err(e) => {
            s.push_str(&format!(
                "私有运行目录复核**未通过**：{e}\n\
                 因此本次没有读取任何运行期文件（pid 与日志在这种状态下都不可信）。\n\
                 这本身就是一条关键线索：请把这一节原样交给管理员。\n"
            ));
        }
    }

    // ★脱敏放在最后、对**整份**文本做一次：分节各脱各的，早晚会漏掉后加的那一节。
    let mut body = redact(&s);
    body.push_str(&format!(
        "\n==================== 包尾 ====================\n本包共脱敏 {} 处。\n",
        redacted_count(&body)
    ));

    let name = format!("baidi-diag-{}.txt", fmt_utc(now, true));
    let path = output_dir(&app).join(&name);
    let path_str = path.to_string_lossy().to_string();
    // 复用 write_private：unix 上给 0600。桌面目录本身通常是 0755，这一步挡不住
    // 用户自己转发，但至少不让同机其他账号顺手读走。
    crate::write_private(&path_str, &body)?;
    Ok(path_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elevate::{paths_in, Platform};

    const JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTc1NX0.c2lnbmF0dXJlLWJ5dGVzLWhlcmUtNjQtbG9uZy1wYWRkaW5n";

    /// 日志几乎每行都带中文，脱敏器必须**按字符边界**走。
    /// 退回按字节切片的写法这条用例会 panic 而不是断言失败——与 log_tail 同一条教训。
    #[test]
    fn jwt_在中文日志里被脱敏且不破坏中文() {
        let s = format!("time=1 level=INFO msg=\"引流 · 经隧道转发\" tok={JWT} resource=oa\n");
        let r = redact(&s);
        assert!(!r.contains(JWT), "令牌仍在包里：{r}");
        assert!(r.contains("引流 · 经隧道转发"), "中文被破坏：{r}");
        assert!(r.contains("resource=oa"), "排障信息被误伤：{r}");
    }

    #[test]
    fn 各种凭据形态都被脱敏() {
        for s in [
            // launcher 脚本万一被贴进 report 里
            format!("export BAIDI_TOKEN='{JWT}'"),
            format!("$env:BAIDI_TOKEN = '{JWT}'"),
            format!("Authorization: Bearer {JWT}"),
            // ★前端 startedOpts 快照的真实形状（tunnel.ts 里 token: session.token）
            format!("{{\"gateway\":\"10.0.0.5\",\"token\":\"{JWT}\",\"pin\":\"9f2b\"}}"),
            // 不是 JWT 形状的不透明凭据：只靠结构那道会漏
            "\"token\":\"opaque-session-value\"".into(),
            "Authorization: Bearer opaque-session-abc\n".into(),
            "password=hunter2 next=1".into(),
        ] {
            let r = redact(&s);
            assert!(r.contains("已脱敏"), "未脱敏：{s} -> {r}");
            assert!(
                !r.contains(JWT)
                    && !r.contains("hunter2")
                    && !r.contains("opaque-session-value")
                    && !r.contains("opaque-session-abc"),
                "凭据残留：{r}"
            );
        }
    }

    /// ★这条用例是拦「把脱敏改成核弹」的：诊断包抹掉这些就没有排障价值了，
    /// 而那种改动在功能上看不出问题（包照样生成、照样没有令牌）。
    #[test]
    fn 排障必需的非凭据信息必须原样保留() {
        for k in [
            "captured_dst=10.20.30.40:8080",
            "routes=10.20.0.0/16,10.30.0.0/16",
            "resource=oa-web",
            "endpoint=2/3 id=gw-hangzhou-01 addr=10.0.0.5:18443 reason=首选落点拨号失败",
            "name=oa.corp.internal",
            "pin=9f2b4c8e1a3d5f70b2c4e6a8d0f2b4c6e8a0c2e4f6a8b0d2f4c6e8a0b2d4f6c8",
            "device=MBP-7f3a2b1c",
            "client_version=0.1.0",
            "\"tokenTtl\": 90",
        ] {
            assert_eq!(redact(k), k, "被误伤：{k}");
        }
    }

    #[test]
    fn 脱敏是幂等的() {
        let s = format!("token={JWT} 与 Authorization: Bearer {JWT}");
        let once = redact(&s);
        assert_eq!(redact(&once), once, "二次脱敏改变了内容（占位符被反复套娃）");
    }

    /// ★安全闸：提权脚本含 `export BAIDI_TOKEN='<会话JWT>'`，
    /// 绝不能出现在「会被读正文」的白名单里。把它加进 log_sources 这条用例立刻红。
    #[test]
    fn 提权脚本绝不进正文白名单() {
        for plat in [Platform::MacOS, Platform::Linux, Platform::Windows] {
            let p = paths_in("/tmp/baidi-1000", plat);
            let srcs: Vec<String> = log_sources(&p).into_iter().map(|(_, path)| path).collect();
            assert!(!srcs.contains(&p.launch), "launcher 进了正文白名单（{plat:?}）");
            assert!(!srcs.contains(&p.stop), "停止脚本进了正文白名单（{plat:?}）");
            // 两份日志都必须在：只收 log 的话 Windows 会拿到一个空包（slog 写 stdout）
            assert!(srcs.contains(&p.log) && srcs.contains(&p.out), "两份日志必须都收（{plat:?}）");
        }
    }

    #[test]
    fn utc_格式化() {
        assert_eq!(fmt_utc(0, false), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_utc(1_755_226_245, false), "2025-08-15T02:50:45Z");
        assert_eq!(fmt_utc(1_755_226_245, true), "20250815-025045");
    }
}
