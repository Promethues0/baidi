//! 提权执行分平台：macOS `osascript` / Linux `pkexec`(polkit) / Windows UAC(`runas`)。
//!
//! baidi-tun 必须以管理员权限运行（建 utun/tun/wintun 虚拟网卡、改路由表），而"怎么提权"
//! 三个平台完全不同。本模块与 [`crate::posture`] 同一条纪律：
//!
//!   **只活在 `#[cfg]` 里的分支是验不到的**。
//!
//! 因此这里把「该怎么提权执行」拆成两层：
//!   - **纯函数构造**（[`plan_start`] / [`plan_stop`] / [`preflight_start`] / [`running_probe`] …）：
//!     吃平台枚举 + 路径 + 参数，吐出「跑哪个程序、传哪些参数、先落什么脚本」的**描述**，
//!     不执行任何东西。三个平台的构造逻辑**无 cfg 门控**，在 macOS 上全部被单测逐字断言；
//!   - **薄薄一层执行**（main.rs 的 `run_elevator`）：拿描述去 spawn。它连 cfg 都不需要——
//!     [`Platform::host()`] 用 `cfg!` 宏选平台（是布尔常量，不删代码），
//!     [`plan_start`] 在 Linux 上永远不会吐出 `Osascript`，于是那条分支自然走不到。
//!
//! 本模块**没有任何 `#[cfg]`**。仅有的几处在 main.rs 的落盘层（`ensure_private_dir` /
//! `write_private` / `account_tag`）：属主、权限位、`geteuid` 都是 unix 概念，没有跨平台写法；
//! 而它们的**判据**仍在这里（[`check_runtime_dir`]），无 cfg、在任何主机上都被单测。
//!
//! `allow(dead_code)`：三平台的构造函数无条件编译，非本平台那两套在真实调用链上没人调。
#![allow(dead_code)]

// ── 平台 ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
}

impl Platform {
    /// 当前宿主平台。
    ///
    /// 用 `cfg!` 宏而不是 `#[cfg]` 属性：`cfg!` 展开成布尔字面量，三条分支在**任何**平台上
    /// 都要通过类型检查；`#[cfg]` 则会把另外两条整段删掉，写错了在本机连编译都不报。
    pub const fn host() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            // Tauri 2 桌面端只出这三个平台的包；其余 unix 走 macOS 那套（osascript 不在时
            // preflight 会当场报错，不会静默走成一个假的提权）。
            Platform::MacOS
        }
    }

    pub const fn is_windows(self) -> bool {
        matches!(self, Platform::Windows)
    }

    /// 路径分隔符。构造是纯字符串拼接，不能借 `Path::join`——那会在 macOS 上给
    /// Windows 路径拼出 `C:\Users\x/y.ps1`，测试断言就没法逐字写。
    pub const fn sep(self) -> char {
        if self.is_windows() {
            '\\'
        } else {
            '/'
        }
    }
}

// ── 运行期临时文件清单 ──

/// 数据面运行期落盘的那几份文件。**全部放在 [`runtime_dir`] 排出来的每用户私有目录下**
/// （`<临时目录>/baidi-<uid>`，unix 上 0700），不是直接落临时目录根。
///
/// ★为什么不能直接用临时目录根：Linux 桌面会话通常不设 `TMPDIR`，`std::env::temp_dir()`
/// 返回的就是 **`/tmp`（1777，全局可写）**。而这里的 launcher 脚本会被 **root 执行**、
/// pid 文件会被 root 拿去 `kill`、`gateways.json` 是 root 数据面的落点与钉扎指纹来源——
/// 文件名全是固定可预测的。同机任一普通用户预先建好同名文件（`fs::write` 不带
/// `O_EXCL`/`O_NOFOLLOW`，会直接写进他那个文件），再趁认证框弹着的几秒把内容换掉，
/// 就是一次本地提权到 root。所以落盘位置必须先收敛成一个**只有本人能写**的目录，
/// 且该目录的属主与权限每次都要复核（见 [`check_runtime_dir`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// baidi-tun 日志（进程 stderr：slog 默认写 stderr，接入页解析的就是这一份）。
    pub log: String,
    /// baidi-tun 的 stdout。**只有 Windows 用得到**：PowerShell 的 `Start-Process` 拒绝把
    /// stdout 与 stderr 重定向到同一个文件，unix 那边一句 `>log 2>&1` 就合流了。
    pub out: String,
    pub pid: String,
    /// 提权 launcher 脚本（unix 是 bash，Windows 是 ps1）。含会话令牌，用后即删。
    pub launch: String,
    /// 断开用的提权脚本。
    pub stop: String,
    pub resmap: String,
    pub dnsrec: String,
    pub gateways: String,
}

/// 按平台在 `dir` 下排出上面那份清单。`dir` 通常是 `std::env::temp_dir()`。
pub fn paths_in(dir: &str, platform: Platform) -> Paths {
    let j = |name: &str| join_path(dir, name, platform.sep());
    let (launch, stop) = if platform.is_windows() {
        ("baidi-tun-launch.ps1", "baidi-tun-stop.ps1")
    } else {
        ("baidi-tun-launch.sh", "baidi-tun-stop.sh")
    };
    Paths {
        log: j("baidi-tun.log"),
        out: j("baidi-tun.out.log"),
        pid: j("baidi-tun.pid"),
        launch: j(launch),
        stop: j(stop),
        resmap: j("baidi-resmap.json"),
        dnsrec: j("baidi-dns-records.json"),
        gateways: j("baidi-gateways.json"),
    }
}

fn join_path(dir: &str, name: &str, sep: char) -> String {
    let d = dir.trim_end_matches(['/', '\\']);
    format!("{d}{sep}{name}")
}

// ── 每用户私有运行目录 ──

/// 排出「本次运行该往哪个目录落盘」。纯字符串拼接，不碰文件系统。
///
/// `tag` 是账号标识（unix 传 euid 的十进制，Windows 传空串——`%LOCALAPPDATA%\Temp`
/// 本身就是每用户一份）。**必须进目录名**：`/tmp` 是全机共用的，不带 uid 的话，
/// 同机第一个登录的人建出 `/tmp/baidi`（0700，属主是他），第二个人就再也建不出来、
/// 也写不进去——那时的表现是"接入按钮点了报错"，比静默好，但仍是拒绝服务。
/// 带上 uid 之后，每个账号各自一份，互不干涉。
pub fn runtime_dir(temp: &str, tag: &str, platform: Platform) -> String {
    let t = sanitize_tag(tag);
    let name = if t.is_empty() { String::from("baidi") } else { format!("baidi-{t}") };
    join_path(temp, &name, platform.sep())
}

/// 目录名里的账号标识只留 `[A-Za-z0-9_-]`。uid 本来就是纯数字，这道闸防的是
/// 将来有人把用户名之类的东西接进来（`../` 会把私有目录整个挪出临时目录）。
fn sanitize_tag(tag: &str) -> String {
    tag.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect()
}

/// 私有目录的实况（unix）。抽成纯数据是为了让判定逻辑无 `#[cfg]`、在任何主机上都被单测——
/// 与 `posture::Env`、[`Probe`] 同一个理由：只活在 cfg 里的分支验不到。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirFacts {
    /// `lstat` 看到的是不是符号链接（**必须用 lstat**：`stat` 会跟着链接走，
    /// 攻击者把 `/tmp/baidi-501` 做成指向自己目录的软链，`stat` 看到的属主是他自己
    /// 建的那个目录、模式也可以是 0700，全部检查都能过）。
    pub is_symlink: bool,
    pub is_dir: bool,
    /// 属主 uid。
    pub uid: u32,
    /// 权限位（`mode & 0o7777`）。
    pub mode: u32,
}

/// 判定「这个目录能不能拿来放 root 要执行/读取的文件」。纯函数。
///
/// `facts=None` 表示本平台拿不到 unix 属主/权限（Windows）——**如实放行并在文档里说明**
/// 保护退化成 `%LOCALAPPDATA%\Temp` 的继承 ACL，而不是假装校验过。
///
/// 四条判据缺一不可，错法各有各的静默：
///   - **符号链接**：见 [`DirFacts::is_symlink`]；
///   - **不是目录**：攻击者预先建个同名普通文件，后续 create_dir 失败但我们照写不误；
///   - **属主不是自己**：目录归别人时，他能随意 rename/替换里面的每一个文件条目——
///     launcher 脚本被 root 执行、pid 被 root `kill`，两条都是直通 root 的路；
///   - **组/其他人有任何权限位**：0777 的目录等价于没有目录（`/tmp` 的原样重演）；
///     连读位都不留是因为 launcher 脚本里有会话令牌。
pub fn check_runtime_dir(path: &str, facts: Option<&DirFacts>, my_uid: u32) -> Result<(), String> {
    let Some(f) = facts else { return Ok(()) };
    if f.is_symlink {
        return Err(format!(
            "运行目录 {path} 是一个符号链接，拒绝使用。\n\
             它会被用来把提权脚本重定向到别处（本地提权），请删除它后重试。"
        ));
    }
    if !f.is_dir {
        return Err(format!("运行目录 {path} 不是目录，拒绝使用。请删除它后重试。"));
    }
    if f.uid != my_uid {
        return Err(format!(
            "运行目录 {path} 的属主是 uid={}（当前账号 uid={my_uid}），拒绝使用。\n\
             这里要放的是**将以 root 执行**的提权脚本与 pid 文件，目录归别人\
             等于把 root 权限交出去。请删除该目录后重试。",
            f.uid
        ));
    }
    if f.mode & 0o077 != 0 {
        return Err(format!(
            "运行目录 {path} 的权限是 {:04o}，对同机其他用户开放，拒绝使用。\n\
             请改成 0700（chmod 700）后重试。",
            f.mode
        ));
    }
    Ok(())
}

// ── 提权计划（纯数据） ──

/// 提权前要落盘的脚本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub path: String,
    pub content: String,
}

/// 「怎么把这条命令提权跑起来」。三个变体互不通用，各自对应一套系统认证 UI。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elevator {
    /// macOS：`osascript -e 'do shell script "…" with administrator privileges'`，
    /// 弹的是系统的管理员授权框（支持 Touch ID）。
    Osascript { apple: String },
    /// Linux：`pkexec <program> <args…>`。
    ///
    /// ★刻意**不用 sudo**：图形会话里没有 tty，sudo 无处提示输入口令，表现为
    /// 「点了接入、什么都没发生」——而进程其实卡在读密码上。pkexec 会调起会话里注册的
    /// polkit 认证代理弹系统认证框，这是桌面应用的标准做法。
    Pkexec { program: String, args: Vec<String> },
    /// Windows：以 UAC 提升方式执行 `file`，命令行为 `parameters`
    /// （**单个字符串**，已按 `CommandLineToArgvW` 规则转义，与 `ShellExecuteW` 的
    /// `lpParameters` 同形）。
    ///
    /// ★为什么形态是「一个字符串」而不是 argv 向量：UAC 提升这条路（ShellExecuteEx +
    /// runas 动词）在 Win32 层面收的就是一整条命令行，参数边界由被调用方按
    /// `CommandLineToArgvW` 规则自己切。把转义留给上层"随手拼个空格"正是含空格路径被截断的成因。
    WindowsRunas { file: String, parameters: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// 提权前先落盘的脚本（None = 不需要）。
    pub script: Option<Script>,
    pub elevator: Elevator,
}

/// 一次提权启动的全部输入。
pub struct StartReq<'a> {
    /// sidecar baidi-tun 的绝对路径（**可能含空格与中文**：.app 名字就是「白帝安全接入客户端」）。
    pub tun: &'a str,
    /// baidi-tun 的参数，顺序即命令行顺序。
    pub args: &'a [String],
    /// 要显式带进提权进程的环境变量。
    ///
    /// ★这一项不是可选的礼貌：**pkexec 会把环境清成一份最小安全集**（只留 PATH/USER/HOME/
    /// SHELL/LOGNAME，外加供认证代理用的 DISPLAY/XAUTHORITY），桌面进程里的任何 `BAIDI_*`
    /// 都到不了 root 那一侧。macOS 的 `do shell script` 与 Windows 的 UAC 提升同样是新环境。
    /// 想让 root 数据面看见什么，必须在这里点名——而不是指望它继承。
    pub env: &'a [(String, String)],
    pub paths: &'a Paths,
    /// 已由 [`resolve_elevator`] 解析出的提权程序。
    pub elevator: &'a str,
}

/// 排出「以管理员权限拉起 baidi-tun」的执行计划。纯函数，不碰文件系统也不 spawn。
pub fn plan_start(platform: Platform, req: &StartReq) -> Plan {
    match platform {
        Platform::MacOS => {
            let script = Script {
                path: req.paths.launch.clone(),
                content: unix_start_script(req),
            };
            // 两层引号要分清：外层是 AppleScript 字符串，内层是 POSIX shell。
            // 原先这里是 `format!("do shell script \"/bin/bash {}\"", LAUNCH)` —— 路径没引号，
            // 靠"脚本落在纯 ASCII 的 /tmp 下"兜着。换成 temp_dir() 之后那个前提没了
            // （macOS 的 TMPDIR 是 /var/folders/…，Windows 的 %TEMP% 可能带中文用户名）。
            let shell_cmd = format!("/bin/bash {}", sq(&script.path));
            let apple = format!(
                "do shell script {} with administrator privileges",
                applescript_quote(&shell_cmd)
            );
            Plan {
                script: Some(script),
                elevator: Elevator::Osascript { apple },
            }
        }
        Platform::Linux => {
            let script = Script {
                path: req.paths.launch.clone(),
                content: unix_start_script(req),
            };
            Plan {
                elevator: Elevator::Pkexec {
                    program: req.elevator.to_string(),
                    // 直接 argv 交给 pkexec，**中间没有 shell**：脚本路径含空格/中文也不会被切开，
                    // 也没有任何注入面。
                    args: vec![String::from("/bin/bash"), script.path.clone()],
                },
                script: Some(script),
            }
        }
        Platform::Windows => {
            let script = Script {
                path: req.paths.launch.clone(),
                content: windows_start_script(req),
            };
            Plan {
                elevator: Elevator::WindowsRunas {
                    file: req.elevator.to_string(),
                    parameters: win_cmdline(&[
                        "-NoProfile",
                        "-NonInteractive",
                        // launcher 是 .ps1 文件，会被执行策略拦（默认 Restricted）。
                        // Bypass 只作用于这一次调用，不改机器策略。
                        "-ExecutionPolicy",
                        "Bypass",
                        "-WindowStyle",
                        "Hidden",
                        "-File",
                        &script.path,
                    ]),
                },
                script: Some(script),
            }
        }
    }
}

/// 排出「断开：杀掉 root 数据面进程」的执行计划。`pid` 必须已过 [`sanitize_pid`]。
pub fn plan_stop(platform: Platform, pid: &str, paths: &Paths) -> Plan {
    match platform {
        Platform::MacOS => {
            let script = Script {
                path: paths.stop.clone(),
                content: unix_stop_script(pid, paths),
            };
            let shell_cmd = format!("/bin/bash {}", sq(&script.path));
            Plan {
                elevator: Elevator::Osascript {
                    apple: format!(
                        "do shell script {} with administrator privileges",
                        applescript_quote(&shell_cmd)
                    ),
                },
                script: Some(script),
            }
        }
        Platform::Linux => {
            let script = Script {
                path: paths.stop.clone(),
                content: unix_stop_script(pid, paths),
            };
            Plan {
                elevator: Elevator::Pkexec {
                    program: String::new(), // 由调用方填（resolve_elevator 的结果）
                    args: vec![String::from("/bin/bash"), script.path.clone()],
                },
                script: Some(script),
            }
        }
        Platform::Windows => {
            let script = Script {
                path: paths.stop.clone(),
                content: windows_stop_script(pid, paths),
            };
            Plan {
                elevator: Elevator::WindowsRunas {
                    file: String::new(), // 同上
                    parameters: win_cmdline(&[
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-WindowStyle",
                        "Hidden",
                        "-File",
                        &script.path,
                    ]),
                },
                script: Some(script),
            }
        }
    }
}

/// 把 [`plan_stop`] 留空的提权程序名填上（stop 不需要 StartReq，单独补这一步）。
pub fn with_elevator(mut plan: Plan, elevator: &str) -> Plan {
    match &mut plan.elevator {
        Elevator::Pkexec { program, .. } => *program = elevator.to_string(),
        Elevator::WindowsRunas { file, .. } => *file = elevator.to_string(),
        Elevator::Osascript { .. } => {}
    }
    plan
}

// ── 脚本正文 ──

/// unix（macOS + Linux 共用）launcher 脚本。
///
/// 三个要点一个都不能少：
///  - `exec </dev/null >/dev/null 2>&1` 先断开脚本自身与提权器的管道 → osascript 的
///    `do shell script` / pkexec 立即返回，不会因后台 baidi-tun 常驻持有 fd 而卡死（会冻结 UI）；
///  - 令牌经环境变量传入，**不进 ps 进程参数**；脚本本身用后即删；
///  - PATH 显式写死一份：pkexec 给的最小环境里 PATH 未必含 `/usr/sbin`，而 Linux 侧
///    `ip`/`resolvectl` 就在那儿——少了它，接口配起来了、路由却加不上，症状是"已接入但不通"。
fn unix_start_script(req: &StartReq) -> String {
    let p = req.paths;
    let mut s = String::from("#!/bin/bash\n");
    s.push_str(&format!("rm -f {} {}\n", sq(&p.log), sq(&p.pid)));
    s.push_str("export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n");
    for (k, v) in req.env {
        if !valid_env_key(k) {
            continue; // 变量名是我们自己给的常量；这道闸防的是将来有人把用户输入接进来
        }
        s.push_str(&format!("export {}={}\n", k, sq(v)));
    }
    s.push_str("exec </dev/null >/dev/null 2>&1\n");
    let argline = req.args.iter().map(|a| sq(a)).collect::<Vec<_>>().join(" ");
    s.push_str(&format!(
        "{tun} {args} >{log} 2>&1 </dev/null &\n",
        tun = sq(req.tun),
        args = argline,
        log = sq(&p.log),
    ));
    s.push_str(&format!("echo $! >{}\n", sq(&p.pid)));
    s
}

/// unix 断开脚本。
///
/// ★必须是 `kill`（SIGTERM）而不是 `kill -9`：baidi-tun 收到 SIGTERM 才会去收回它写进系统的
/// 解析器配置（macOS 的 /etc/resolver/<域名>、Linux 的 resolvectl 设置）。被 -9 打掉的话配置
/// 会留在系统里，把该域名指向一个已经不存在的 VIP——症状是「断开客户端后这个域名永久解析失败」。
fn unix_stop_script(pid: &str, paths: &Paths) -> String {
    format!(
        "#!/bin/bash\nkill {pid} 2>/dev/null\nrm -f {pidfile} 2>/dev/null\ntrue\n",
        pid = pid,
        pidfile = sq(&paths.pid),
    )
}

/// Windows launcher 脚本（PowerShell）。
///
/// 与 unix 版对应，但有三处平台差异，都是"照实做"而不是"假装一样"：
///  - **stdout / stderr 分两个文件**：`Start-Process` 拒绝把两路重定向到同一路径。
///    baidi-tun 的 slog 写 stderr，所以接入页解析的那份日志落 `paths.log`（= stderr），
///    stdout 落 `paths.out`（一般是空的）。
///  - **拿 PID 靠 `-PassThru`**：Windows 没有 `$!`。
///  - **不做 `exec </dev/null`**：`Start-Process` 本身就不挂管道。
///
/// ★这里必须是 `-NoNewWindow` 而**不是** `-WindowStyle Hidden`：Windows PowerShell 5.1 的
/// `Start-Process` 有两个**互斥**参数集——`-Verb`/`-WindowStyle` 属 UseShellExecute 那一组，
/// `-RedirectStandard*`/`-NoNewWindow` 属 Default 那一组。两组混用时 PowerShell 连命令都
/// 解析不了（`Parameter set cannot be resolved using the specified named parameters.`），
/// 而脚本首行的 `$ErrorActionPreference='Stop'` 会让它当场终止：baidi-tun 一次都不会被拉起，
/// pid 文件也不会写。也就是说混用等于 **Windows 数据面 100% 起不来**，而这一整段只在
/// Windows 上执行、在 mac 上永远测不到——只能靠对这一行的逐字断言守住（见单测）。
/// `-NoNewWindow` 隐含 `UseShellExecute=false`，与重定向同集，且不弹控制台窗口。
fn windows_start_script(req: &StartReq) -> String {
    let p = req.paths;
    let mut s = String::from("$ErrorActionPreference = 'Stop'\n");
    for f in [&p.log, &p.out, &p.pid] {
        s.push_str(&format!(
            "Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath {}\n",
            ps_quote(f)
        ));
    }
    for (k, v) in req.env {
        if !valid_env_key(k) {
            continue;
        }
        s.push_str(&format!("$env:{} = {}\n", k, ps_quote(v)));
    }
    s.push_str(&format!(
        "$p = Start-Process -FilePath {tun} -ArgumentList {args} -NoNewWindow -PassThru \
         -RedirectStandardOutput {out} -RedirectStandardError {log}\n",
        tun = ps_quote(req.tun),
        // ★整条命令行按 CommandLineToArgvW 规则转义后作为**一个** ArgumentList 元素传入。
        // 传字符串数组是这里最经典的坑：Windows PowerShell 5.1 的 Start-Process 不会给
        // 含空格的数组元素补引号，`-route 10.0.0.0/24` 这种没事，`C:\Program Files\…`
        // 这种会被切成两个参数——而 baidi-tun 只会报一个看不懂的参数错误。
        args = ps_quote(&win_cmdline_owned(req.args)),
        out = ps_quote(&p.out),
        log = ps_quote(&p.log),
    ));
    s.push_str(&format!(
        "Set-Content -LiteralPath {pid} -Value $p.Id -Encoding ascii -NoNewline\n",
        pid = ps_quote(&p.pid)
    ));
    s
}

/// Windows 断开脚本。
///
/// ★与 unix 不同，这里**没有 SIGTERM 可发**：Windows 上 `Stop-Process -Force` 走的是
/// TerminateProcess，等价于 `kill -9`，baidi-tun 的清理 defer 不会跑。后果是它写进注册表的
/// NRPT 分流规则会留下（那玩意儿**跨重启存活**）。这不是这里能修的——真正的兜底在
/// baidi-tun 侧：启动时按 `Comment=baidi-tun` 无条件扫掉残留规则
/// （见 gateway/cmd/baidi-tun/resolver_windows.go 的 `sweepStaleDNSConfig`）。
/// 写在这儿是为了让下一个人知道这条链是靠"下次启动扫一遍"闭合的，不是靠优雅退出。
fn windows_stop_script(pid: &str, paths: &Paths) -> String {
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
         Stop-Process -Id {pid} -Force\n\
         Remove-Item -Force -LiteralPath {pidfile}\n",
        pid = pid,
        pidfile = ps_quote(&paths.pid),
    )
}

// ── 前置检查：提权框弹出**之前**要能说清楚"能不能行" ──

/// 文件存在性探针。抽成 trait 是为了让 Windows / Linux 的前置检查在 macOS 上也能单测——
/// 与 posture 的 `Env` 同一个理由。
pub trait Probe {
    fn exists(&self, path: &str) -> bool;
}

pub struct RealProbe;

impl Probe for RealProbe {
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
}

/// Linux 上 pkexec 的常见落点。找不到就是没装 polkit。
pub const PKEXEC_CANDIDATES: [&str; 3] = ["/usr/bin/pkexec", "/bin/pkexec", "/usr/local/bin/pkexec"];

/// 解析出本平台的提权程序。失败必须是**人能照着做的一句话**，不能静默。
pub fn resolve_elevator(platform: Platform, probe: &dyn Probe) -> Result<String, String> {
    match platform {
        Platform::MacOS => {
            const OSA: &str = "/usr/bin/osascript";
            if probe.exists(OSA) {
                Ok(OSA.to_string())
            } else {
                Err(format!("未找到 {OSA}，无法申请管理员授权（系统组件缺失？）"))
            }
        }
        Platform::Linux => {
            for c in PKEXEC_CANDIDATES {
                if probe.exists(c) {
                    return Ok(c.to_string());
                }
            }
            // ★这条消息就是本任务要的「报清楚而不是静默失败」。刻意不回退 sudo：
            // 图形会话里没有 tty，sudo 会卡在读口令上，界面表现为"点了没反应"。
            Err(String::from(
                "未找到 pkexec：本机没装 polkit，无法弹出系统授权框。\n\
                 请安装后重试：Debian/Ubuntu `apt install policykit-1`；\
                 RHEL/Fedora `dnf install polkit`；Arch `pacman -S polkit`。\n\
                 （刻意不回退 sudo：图形会话里没有终端可输口令，那只会表现成「点了接入没反应」。）",
            ))
        }
        Platform::Windows => Ok(String::from("powershell.exe")),
    }
}

/// wintun.dll 的搜索路径。
///
/// ★不是随便找找：wintun 库用 `LoadLibraryEx(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
/// LOAD_LIBRARY_SEARCH_SYSTEM32)` 加载它，**只**看这两处——不看 PATH、不看当前目录、
/// 不看安装目录的其他子目录。所以这里的判据必须与它一字不差，否则会出现
/// 「DLL 明明在包里、还是报 Unable to load library」。
/// APPLICATION_DIR 指的是**进程自身可执行文件所在目录**，对 sidecar 来说就是 baidi-tun.exe 的目录。
pub fn wintun_search_paths(tun_dir: &str, system_root: &str) -> Vec<String> {
    vec![
        join_path(tun_dir, "wintun.dll", '\\'),
        join_path(&join_path(system_root, "System32", '\\'), "wintun.dll", '\\'),
    ]
}

/// 拉起数据面**之前**的平台前置检查。返回 Err 时调用方必须直接把话说清楚，
/// **不许先弹提权框再失败**——那等于让用户白输一次口令去看一个看不懂的错误。
pub fn preflight_start(
    platform: Platform,
    probe: &dyn Probe,
    tun_dir: &str,
    system_root: &str,
) -> Result<(), String> {
    if platform != Platform::Windows {
        return Ok(());
    }
    let cands = wintun_search_paths(tun_dir, system_root);
    if cands.iter().any(|p| probe.exists(p)) {
        return Ok(());
    }
    Err(format!(
        "Windows 数据面暂不可用：未找到 wintun.dll。\n\
         baidi-tun 在 Windows 上用 Wintun 建虚拟网卡，而 wintun 只在\
         「程序自身目录」与 System32 两处找这个 DLL，当前两处都没有：\n  {}\n\
         请到 https://www.wintun.net/ 取与客户端同架构（amd64 / arm64）的 wintun.dll 放到上述任一位置。\n\
         （刻意没有弹出管理员授权框：弹了也只会在建网卡那一步失败。）",
        cands.join("\n  ")
    ))
}

// ── 进程判活 ──

/// pid 必须是纯数字才拿去用。这一步同时挡掉了「pid 文件被写进奇怪内容 → 拼进脚本」这条注入面。
pub fn sanitize_pid(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(t.to_string())
}

/// 判活探测命令。unix 用 `ps -p`（不用 `kill -0`：对 root 进程会 EPERM 误判成"已退出"）。
pub fn running_probe(platform: Platform, pid: &str) -> (String, Vec<String>) {
    match platform {
        Platform::Windows => (
            String::from("tasklist"),
            vec![
                String::from("/FI"),
                format!("PID eq {pid}"),
                String::from("/NH"),
            ],
        ),
        _ => (
            String::from("ps"),
            vec![
                String::from("-p"),
                pid.to_string(),
                String::from("-o"),
                String::from("pid="),
            ],
        ),
    }
}

/// 解析判活输出。
///
/// ★Windows 这半必须自己解析，不能看退出码：**没有匹配进程时 tasklist 照样返回 0**，
/// 只在 stdout 里打一句本地化的「信息: 没有运行的任务匹配指定标准。」。按退出码判的话，
/// 托盘会永远显示「已接入」——一个只在 Windows 上出现、在 mac 上永远测不到的谎。
pub fn parse_running(platform: Platform, pid: &str, stdout: &str) -> bool {
    match platform {
        Platform::Windows => stdout.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // tasklist /NH 的列序固定：映像名称 PID 会话名 会话# 内存使用。
            // 只认第 2 列——按"任意一列等于 pid"匹配会被内存列（"996 K"）误命中。
            f.len() >= 2 && f[1] == pid
        }),
        _ => stdout.split_whitespace().any(|t| t == pid),
    }
}

// ── 取消判定 ──

/// 用户主动取消授权 vs 真的出错。两者的 UI 措辞完全不同（前者不该报错、不该诱导重试）。
pub fn is_cancel(platform: Platform, code: Option<i32>, stderr: &str) -> bool {
    match platform {
        Platform::MacOS => {
            // osascript 取消：errAEWaitCanceled(-128)
            stderr.contains("-128") || stderr.contains("User canceled") || stderr.contains("用户已取消")
        }
        Platform::Linux => {
            // pkexec(1)：126 = 未取得授权（含用户关掉认证框）；127 = 因错误未取得授权。
            // 只认 126 + 文案，127 留给"真出错"分支去展示原文。
            code == Some(126)
                || stderr.contains("Request dismissed")
                || stderr.contains("Not authorized")
                || stderr.contains("dismissed")
        }
        Platform::Windows => {
            // UAC 拒绝/取消 → ShellExecute 回 ERROR_CANCELLED(1223)，
            // PowerShell 包装成「The operation was canceled by the user.」/「操作已被用户取消。」
            //
            // ★退出码这一路是 ps_runas_command 里 `if ($null -eq $p) { exit 1223 }` 的对侧：
            // 那条分支走到时进程可能一个字的 stderr 都没有，只认文案的话取消会被报成"启动失败"。
            code == Some(1223)
                || stderr.contains("canceled by the user")
                || stderr.contains("cancelled by the user")
                || stderr.contains("操作已被用户取消")
                || stderr.contains("1223")
        }
    }
}

/// 提权器非零退出、但**没有任何 stderr** 时该说什么。纯函数。
///
/// ★为什么单开一个函数：提权那一侧是**另一个进程**（osascript 的 `do shell script` /
/// pkexec / UAC 提升出来的 powershell），它的 stderr 常常到不了我们手里——尤其
/// Windows 现在会把被提升进程的退出码经 `exit $p.ExitCode` 传回来，而错误文本留在了
/// 那一侧。此时直接 `format!("启动数据面失败：{}", stderr.trim())` 会渲染成
/// 「启动数据面失败：」后面一片空白，用户拿不到任何下一步。至少要把退出码与日志路径给出去。
pub fn failure_message(action: &str, code: Option<i32>, stderr: &str, log_path: &str) -> String {
    let e = stderr.trim();
    if !e.is_empty() {
        return format!("{action}失败：{e}");
    }
    let c = code.map(|c| c.to_string()).unwrap_or_else(|| String::from("未知（进程被信号中止）"));
    format!("{action}失败：提权进程以退出码 {c} 结束，且没有可显示的错误输出。数据面日志见 {log_path}")
}

// ── sidecar 定位 ──

/// 随 app 打包的 baidi-tun 候选文件名，**顺序即优先级**（确定性优先于 read_dir 顺序）。
/// Tauri 的 externalBin 按 `<name>-<三元组>` 存放，安装后通常改回不带三元组的名字。
pub fn sidecar_candidates(platform: Platform, arch: &str) -> Vec<String> {
    match platform {
        Platform::MacOS => vec![
            String::from("baidi-tun"),
            format!("baidi-tun-{arch}-apple-darwin"),
            String::from("baidi-tun-universal-apple-darwin"),
        ],
        Platform::Linux => vec![
            String::from("baidi-tun"),
            format!("baidi-tun-{arch}-unknown-linux-gnu"),
            format!("baidi-tun-{arch}-unknown-linux-musl"),
        ],
        // ★`.exe` 不能少：Windows 上不带扩展名的文件不是可执行文件，
        // 少了它 find_tun 会一路走到兜底分支，把 read_dir 里第一个 baidi-tun* 当成引擎。
        Platform::Windows => vec![
            String::from("baidi-tun.exe"),
            format!("baidi-tun-{arch}-pc-windows-msvc.exe"),
            format!("baidi-tun-{arch}-pc-windows-gnu.exe"),
        ],
    }
}

// ── 转义 ──

/// POSIX shell 单引号转义。
pub fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// AppleScript 字符串字面量转义（反斜杠与双引号）。
///
/// ★两层引号必须分别转义：`do shell script "…"` 的引号是 AppleScript 的，里面那条命令的
/// 引号是 shell 的。只做一层的话，一个含 `"` 的路径会让 AppleScript 在解析阶段就崩，
/// 而报错文案（"Expected end of line"）跟路径半点关系都没有。
pub fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// PowerShell 单引号字符串转义（单引号写两遍）。单引号串在 PS 里不做任何插值，
/// `$`、反引号、`\` 全是字面量——正是我们要的。
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Windows 单参数转义，规则同 `CommandLineToArgvW`（也就是 MSVC 运行时切参数的那套）。
pub fn win_quote(s: &str) -> String {
    if !s.is_empty() && !s.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // 引号前的反斜杠要翻倍，引号本身再加一个反斜杠转义
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('\\');
                out.push('"');
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // 结尾的反斜杠同样要翻倍，否则它会把我们补的收尾引号转义掉
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// 把一组参数拼成一条 Windows 命令行。
pub fn win_cmdline(args: &[&str]) -> String {
    args.iter().map(|a| win_quote(a)).collect::<Vec<_>>().join(" ")
}

fn win_cmdline_owned(args: &[String]) -> String {
    args.iter().map(|a| win_quote(a)).collect::<Vec<_>>().join(" ")
}

/// 拼出「以 UAC 提升方式跑 file」的 PowerShell 命令。
///
/// ★为什么不是直接调 `ShellExecuteW`：那要引 `windows-sys` 这类 Windows 专属 crate，而本机
/// （macOS，rustup 只有两个 apple-darwin 目标）**编译不到**那段 FFI——一个连语法都没验过的
/// unsafe 调用比多起一个 powershell 进程危险得多。`Start-Process -Verb RunAs` 是
/// PowerShell 对 `ShellExecuteEx` + runas 动词的官方封装，弹的是同一个 UAC 框。
/// 等到有 Windows 机器能真跑一遍时，把执行层换成 ShellExecuteW 不需要动本模块的任何构造逻辑
/// ——[`Elevator::WindowsRunas`] 的 (file, parameters) 就是照着它的入参形状定的。
///
/// `-Wait`：等 launcher 脚本本身跑完（它只负责 Start-Process 拉起 baidi-tun 再写 pid 就退出），
/// 这样函数返回时 pid 文件已经在了；真正的数据面进程是它的孙子，不受影响。
///
/// ★`-PassThru` + `exit $p.ExitCode` 一个都不能少：少了它们，**外层 powershell 的退出码只
/// 反映 `Start-Process` 自己有没有抛终止性异常**，被提升那一侧发生的一切（用户在 UAC 框上
/// 点「否」、launcher 脚本失败）全被报成成功——`tunnel_start` 返回 Ok、接入页显示"已接入"
/// 并列出网段与钉扎信息，而系统里根本没有 baidi-tun。那与刚在 `parse_running` 上修掉的
/// 「tasklist 无匹配也回 0 → 托盘永远显示已接入」是同一类谎，且 [`is_cancel`] 的 Windows
/// 分支会因此变成永远走不到的死代码。
///
/// ★`$ErrorActionPreference='Stop'` 与 `$null -eq $p` 那道判空是配套的：用户取消 UAC 时
/// `Start-Process` 报的是**非终止性**错误，默认 preference 下脚本会继续往下走，此时 `$p`
/// 是 `$null`，`exit $null` 等于 `exit 0`——又变回"取消也算成功"。置 Stop 让它成为终止性
/// 错误（错误文本进 stderr，[`is_cancel`] 按文案认得出），判空则兜住 preference 万一被
/// 别处改掉的情况，直接以 `1223`（`ERROR_CANCELLED`）退出。
pub fn ps_runas_command(file: &str, parameters: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden -PassThru -Wait; \
         if ($null -eq $p) {{ exit 1223 }}; exit $p.ExitCode",
        ps_quote(file),
        ps_quote(parameters)
    )
}

fn valid_env_key(k: &str) -> bool {
    !k.is_empty()
        && k.bytes().next().map(|b| b.is_ascii_alphabetic() || b == b'_').unwrap_or(false)
        && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

// ══════════════════════════════════════════════════════════════════════════
//  单测：三平台的提权命令构造在 macOS 上被逐字断言
// ══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 本项目真实存在的坑：.app 的名字是中文，路径里还可能有空格。
    const 中文路径: &str =
        "/Applications/白帝 安全接入客户端.app/Contents/MacOS/baidi-tun";

    fn 参数() -> Vec<String> {
        ["-spa", "10.0.0.1:18201", "-route", "10.20.1.0/24,10.30.5.0/24", "-ip", "10.99.0.2"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn 环境() -> Vec<(String, String)> {
        vec![(String::from("BAIDI_TOKEN"), String::from("ey.JhbGciOi.sig"))]
    }

    fn 请求<'a>(
        tun: &'a str,
        args: &'a [String],
        env: &'a [(String, String)],
        paths: &'a Paths,
        elevator: &'a str,
    ) -> StartReq<'a> {
        StartReq { tun, args, env, paths, elevator }
    }

    // ── 路径 ──

    #[test]
    fn 临时文件不再硬编码_tmp_且分隔符跟平台() {
        let u = paths_in("/var/folders/ab/cd/T", Platform::MacOS);
        assert_eq!(u.log, "/var/folders/ab/cd/T/baidi-tun.log");
        assert_eq!(u.launch, "/var/folders/ab/cd/T/baidi-tun-launch.sh");
        let w = paths_in("C:\\Users\\张三\\AppData\\Local\\Temp", Platform::Windows);
        assert_eq!(w.pid, "C:\\Users\\张三\\AppData\\Local\\Temp\\baidi-tun.pid");
        assert_eq!(w.launch, "C:\\Users\\张三\\AppData\\Local\\Temp\\baidi-tun-launch.ps1");
        // 末尾已经带分隔符的目录（macOS 的 TMPDIR 就是这样）不该拼出双斜杠
        assert_eq!(paths_in("/tmp/", Platform::Linux).pid, "/tmp/baidi-tun.pid");
    }

    // ── 每用户私有运行目录 ──

    /// ★回归背景（本地提权）：运行期文件此前直接落 `std::env::temp_dir()` 根。
    /// Linux 桌面会话不设 TMPDIR 时那就是 **`/tmp`（1777，全局可写）**，而落在那里的
    /// launcher 脚本会被 root 执行、pid 会被 root `kill`、gateways.json 是 root 数据面的
    /// 落点与钉扎来源，文件名还全是固定的。私有子目录是这条链的第一道闸。
    #[test]
    fn 运行目录是每用户一份而不是临时目录根() {
        assert_eq!(runtime_dir("/tmp", "501", Platform::Linux), "/tmp/baidi-501");
        assert_eq!(runtime_dir("/tmp/", "0", Platform::MacOS), "/tmp/baidi-0");
        assert_eq!(
            runtime_dir("C:\\Users\\张三\\AppData\\Local\\Temp", "", Platform::Windows),
            "C:\\Users\\张三\\AppData\\Local\\Temp\\baidi"
        );
        // 落盘清单必须整体在私有目录里，不能有哪一份漏在外面
        let p = paths_in(&runtime_dir("/tmp", "501", Platform::Linux), Platform::Linux);
        for f in [&p.log, &p.out, &p.pid, &p.launch, &p.stop, &p.resmap, &p.dnsrec, &p.gateways] {
            assert!(f.starts_with("/tmp/baidi-501/"), "漏在私有目录外：{f}");
        }
        // uid 不同 → 目录不同：同机两个账号互不干涉，也谁都占不住对方的名字
        assert_ne!(runtime_dir("/tmp", "501", Platform::Linux), runtime_dir("/tmp", "502", Platform::Linux));
    }

    #[test]
    fn 运行目录名里的账号标识只留安全字符() {
        // `../` 能把私有目录整个挪出临时目录，一律剔掉
        assert_eq!(runtime_dir("/tmp", "../../etc", Platform::Linux), "/tmp/baidi-etc");
        assert_eq!(runtime_dir("/tmp", "a b;rm -rf /", Platform::Linux), "/tmp/baidi-abrm-rf");
    }

    #[test]
    fn 合规的私有目录放行() {
        let f = DirFacts { is_symlink: false, is_dir: true, uid: 501, mode: 0o700 };
        assert!(check_runtime_dir("/tmp/baidi-501", Some(&f), 501).is_ok());
    }

    /// 四条判据各自对应一种**只在 Linux 上出现、且完全静默**的提权路径。
    #[test]
    fn 私有目录不合规时一律拒绝而不是照用() {
        let 基准 = DirFacts { is_symlink: false, is_dir: true, uid: 501, mode: 0o700 };

        // ① 符号链接：lstat 认得出，stat 认不出（跟着链接走，看到的是攻击者自己的 0700 目录）
        let mut f = 基准;
        f.is_symlink = true;
        let e = check_runtime_dir("/tmp/baidi-501", Some(&f), 501).unwrap_err();
        assert!(e.contains("符号链接") && e.contains("提权"), "{e}");

        // ② 不是目录（预先建个同名普通文件）
        let mut f = 基准;
        f.is_dir = false;
        assert!(check_runtime_dir("/tmp/baidi-501", Some(&f), 501).unwrap_err().contains("不是目录"));

        // ③ 属主是别人：他能替换目录里的每一个条目 → launcher 被 root 执行 = 任意 root 代码执行
        let mut f = 基准;
        f.uid = 1000;
        let e = check_runtime_dir("/tmp/baidi-501", Some(&f), 501).unwrap_err();
        assert!(e.contains("属主") && e.contains("1000") && e.contains("501"), "{e}");

        // ④ 组/其他人有任何权限位：0777 的目录等价于没有目录（/tmp 原样重演）；
        //    连读位都不留——launcher 脚本里有会话令牌。
        for mode in [0o777, 0o755, 0o750, 0o701, 0o704, 0o770] {
            let mut f = 基准;
            f.mode = mode;
            assert!(
                check_runtime_dir("/tmp/baidi-501", Some(&f), 501).is_err(),
                "{mode:04o} 必须被拒"
            );
        }
    }

    /// Windows 拿不到 unix 属主/权限：**如实放行**（保护退化成 %LOCALAPPDATA%\\Temp 的
    /// 继承 ACL），而不是假装校验过——与 write_private 在 Windows 上的诚实说明同一条纪律。
    #[test]
    fn 拿不到_unix_属主权限时如实放行() {
        assert!(check_runtime_dir("C:\\Users\\张三\\AppData\\Local\\Temp\\baidi", None, 0).is_ok());
    }

    // ── macOS ──

    #[test]
    fn macos_提权走_osascript_管理员授权() {
        let p = paths_in("/tmp/T", Platform::MacOS);
        let args = 参数();
        let env = 环境();
        let plan = plan_start(Platform::MacOS, &请求("/opt/baidi-tun", &args, &env, &p, "/usr/bin/osascript"));
        let Elevator::Osascript { apple } = &plan.elevator else {
            panic!("macOS 必须走 osascript，得 {:?}", plan.elevator);
        };
        assert_eq!(
            apple,
            "do shell script \"/bin/bash '/tmp/T/baidi-tun-launch.sh'\" with administrator privileges"
        );
        let sc = plan.script.expect("必须落 launcher 脚本");
        assert_eq!(sc.path, "/tmp/T/baidi-tun-launch.sh");
        assert!(sc.content.starts_with("#!/bin/bash\n"));
        // 令牌只走环境变量，不进命令行（否则同机任何用户 ps 一下就拿到了）
        assert!(sc.content.contains("export BAIDI_TOKEN='ey.JhbGciOi.sig'\n"));
        // 令牌绝不能以 `-token <值>` 的形态进命令行（那样同机任何用户 ps 一下就拿到了）
        assert!(!sc.content.contains("'-token'"), "{}", sc.content);
        // 参数顺序原样保留
        assert!(sc.content.contains("'-spa' '10.0.0.1:18201' '-route' '10.20.1.0/24,10.30.5.0/24' '-ip' '10.99.0.2'"));
        // 断开管道那一句必须在拉起之前，否则 do shell script 会挂住 → UI 冻结
        let i断管 = sc.content.find("exec </dev/null").expect("必须断开管道");
        let i拉起 = sc.content.find("'/opt/baidi-tun'").expect("必须拉起 sidecar");
        assert!(i断管 < i拉起);
    }

    // ── Linux ──

    #[test]
    fn linux_提权走_pkexec_而不是_sudo() {
        let p = paths_in("/tmp/T", Platform::Linux);
        let args = 参数();
        let env = 环境();
        let plan = plan_start(Platform::Linux, &请求("/usr/lib/baidi/baidi-tun", &args, &env, &p, "/usr/bin/pkexec"));
        assert_eq!(
            plan.elevator,
            Elevator::Pkexec {
                program: String::from("/usr/bin/pkexec"),
                args: vec![String::from("/bin/bash"), String::from("/tmp/T/baidi-tun-launch.sh")],
            }
        );
        let sc = plan.script.expect("必须落 launcher 脚本");
        // ★sudo 在图形会话里没有 tty 可输口令，出现在这里就是回归
        assert!(!sc.content.contains("sudo"), "不许回退 sudo：{}", sc.content);
        // pkexec 清环境 → PATH 与令牌都必须显式写进脚本
        assert!(sc.content.contains("export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n"));
        assert!(sc.content.contains("export BAIDI_TOKEN='ey.JhbGciOi.sig'\n"));
    }

    #[test]
    fn linux_没装_pkexec_要报得出照着做的一句话() {
        struct 空;
        impl Probe for 空 {
            fn exists(&self, _p: &str) -> bool {
                false
            }
        }
        let e = resolve_elevator(Platform::Linux, &空).unwrap_err();
        assert!(e.contains("pkexec"), "{e}");
        assert!(e.contains("polkit"), "必须点名要装什么：{e}");
        assert!(e.contains("apt install policykit-1"), "得给出可复制的命令：{e}");
    }

    #[test]
    fn linux_按候选顺序取第一个存在的_pkexec() {
        struct 只有 (&'static str);
        impl Probe for 只有 {
            fn exists(&self, p: &str) -> bool {
                p == self.0
            }
        }
        assert_eq!(resolve_elevator(Platform::Linux, &只有("/bin/pkexec")).unwrap(), "/bin/pkexec");
        assert_eq!(
            resolve_elevator(Platform::Linux, &只有("/usr/local/bin/pkexec")).unwrap(),
            "/usr/local/bin/pkexec"
        );
    }

    // ── Windows ──

    #[test]
    fn windows_提权走_uac_runas_且参数按_win32_规则转义() {
        let p = paths_in("C:\\Temp", Platform::Windows);
        let args = 参数();
        let env = 环境();
        let plan = plan_start(
            Platform::Windows,
            &请求("C:\\Program Files\\白帝\\baidi-tun.exe", &args, &env, &p, "powershell.exe"),
        );
        let Elevator::WindowsRunas { file, parameters } = &plan.elevator else {
            panic!("Windows 必须走 runas，得 {:?}", plan.elevator);
        };
        assert_eq!(file, "powershell.exe");
        assert_eq!(
            parameters,
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Temp\\baidi-tun-launch.ps1"
        );
        let sc = plan.script.expect("必须落 launcher 脚本");
        assert_eq!(sc.path, "C:\\Temp\\baidi-tun-launch.ps1");
        assert!(sc.content.contains("$env:BAIDI_TOKEN = 'ey.JhbGciOi.sig'\n"));
        // 含空格的 sidecar 路径必须整体带引号进 -FilePath
        assert!(sc.content.contains("-FilePath 'C:\\Program Files\\白帝\\baidi-tun.exe'"), "{}", sc.content);
        // stdout / stderr 必须是两个不同文件，否则 Start-Process 直接报错
        assert!(sc.content.contains("-RedirectStandardOutput 'C:\\Temp\\baidi-tun.out.log'"));
        assert!(sc.content.contains("-RedirectStandardError 'C:\\Temp\\baidi-tun.log'"));
        assert_ne!(p.out, p.log);
        // PID 靠 -PassThru 拿（Windows 没有 $!）
        assert!(sc.content.contains("-PassThru"));
        assert!(sc.content.contains("Set-Content -LiteralPath 'C:\\Temp\\baidi-tun.pid' -Value $p.Id"));
    }

    /// ★回归背景：这条 `Start-Process` 曾经同时带 `-WindowStyle Hidden` 与
    /// `-RedirectStandardOutput/-RedirectStandardError`。Windows PowerShell 5.1 里这两组
    /// 分属**互斥**的参数集（UseShellExecute vs Default），混用时命令根本解析不了：
    /// `Start-Process : Parameter set cannot be resolved using the specified named parameters.`
    /// 脚本首行的 `$ErrorActionPreference='Stop'` 让它当场终止 → baidi-tun 一次都不会被拉起、
    /// pid 文件也不会写 = **Windows 数据面 100% 起不来**。这段只在 Windows 上执行，
    /// 在 mac 上永远测不到，只能靠这条逐字断言守住。
    #[test]
    fn windows_launcher_重定向不能与_windowstyle_同时出现() {
        let p = paths_in("C:\\Temp", Platform::Windows);
        let args = 参数();
        let env = 环境();
        let sc = plan_start(Platform::Windows, &请求("C:\\baidi-tun.exe", &args, &env, &p, "powershell.exe"))
            .script
            .unwrap();
        let line = sc
            .content
            .lines()
            .find(|l| l.contains("Start-Process"))
            .expect("必须有拉起 baidi-tun 的 Start-Process");
        assert!(line.contains("-RedirectStandardOutput") && line.contains("-RedirectStandardError"));
        assert!(
            !line.contains("-WindowStyle"),
            "-WindowStyle 与 -RedirectStandard* 参数集互斥，同用则整条命令解析失败：{line}"
        );
        assert!(!line.contains("-Verb"), "-Verb 同属 UseShellExecute 参数集，同样不能与重定向混用：{line}");
        // 与重定向同集、且不弹控制台窗口的那一个
        assert!(line.contains("-NoNewWindow"), "{line}");
    }

    /// ★回归背景：`ps_runas_command` 曾经既没有 `-PassThru` 也不 `exit $p.ExitCode`，
    /// 于是外层 powershell 的退出码只反映 Start-Process 自身有没有抛异常——
    /// 「用户在 UAC 框上点否」与「被提升的 launcher 失败」双双被报成成功，
    /// 接入页显示「已接入」而系统里没有 baidi-tun，`is_cancel(Windows,…)` 成了死代码。
    #[test]
    fn windows_uac_退出码必须回传() {
        let cmd = ps_runas_command("powershell.exe", "-File \"C:\\a b\\x.ps1\"");
        assert!(cmd.contains("-PassThru"), "没有 -PassThru 就拿不到被提升进程：{cmd}");
        assert!(cmd.contains("-Wait"), "{cmd}");
        assert!(cmd.contains("exit $p.ExitCode"), "退出码必须原样回传，否则失败与成功同形：{cmd}");
        // 取消 UAC 时 Start-Process 报的是**非终止性**错误，默认 preference 下会继续往下走、
        // $p 为 $null、`exit $null` 等于 exit 0 —— 又变回"取消也算成功"。两道都要在。
        assert!(cmd.contains("$ErrorActionPreference = 'Stop'"), "{cmd}");
        assert!(cmd.contains("if ($null -eq $p) { exit 1223 }"), "判空兜底不能少：{cmd}");
        // 参数与路径仍按 PS 单引号规则转义
        assert!(cmd.contains("-ArgumentList '-File \"C:\\a b\\x.ps1\"'"), "{cmd}");
    }

    #[test]
    fn windows_缺_wintun_必须当场说清楚而不是弹个_uac_再失败() {
        struct 无;
        impl Probe for 无 {
            fn exists(&self, _p: &str) -> bool {
                false
            }
        }
        let e = preflight_start(Platform::Windows, &无, "C:\\Program Files\\白帝", "C:\\Windows")
            .unwrap_err();
        assert!(e.contains("数据面暂不可用"), "{e}");
        assert!(e.contains("wintun.dll"), "{e}");
        assert!(e.contains("C:\\Program Files\\白帝\\wintun.dll"), "要把找过的位置报出来：{e}");
        assert!(e.contains("C:\\Windows\\System32\\wintun.dll"), "{e}");
        assert!(e.contains("没有弹出"), "必须说明为什么不弹提权框：{e}");
    }

    #[test]
    fn windows_wintun_在_sidecar_目录或_system32_都算数() {
        struct 只有(&'static str);
        impl Probe for 只有 {
            fn exists(&self, p: &str) -> bool {
                p == self.0
            }
        }
        assert!(preflight_start(
            Platform::Windows,
            &只有("C:\\App\\wintun.dll"),
            "C:\\App",
            "C:\\Windows"
        )
        .is_ok());
        assert!(preflight_start(
            Platform::Windows,
            &只有("C:\\Windows\\System32\\wintun.dll"),
            "C:\\App",
            "C:\\Windows"
        )
        .is_ok());
    }

    #[test]
    fn 非_windows_不做_wintun_检查() {
        struct 无;
        impl Probe for 无 {
            fn exists(&self, _p: &str) -> bool {
                false
            }
        }
        assert!(preflight_start(Platform::MacOS, &无, "/x", "").is_ok());
        assert!(preflight_start(Platform::Linux, &无, "/x", "").is_ok());
    }

    // ── 含空格 / 中文的路径不被截断（三平台各一遍） ──

    #[test]
    fn sidecar_路径含空格与中文时三平台都不被截断() {
        let args = 参数();
        let env = 环境();

        let pm = paths_in("/var/folders/白 帝/T", Platform::MacOS);
        let m = plan_start(Platform::MacOS, &请求(中文路径, &args, &env, &pm, "/usr/bin/osascript"));
        let ms = m.script.unwrap();
        // 脚本里 sidecar 路径整体在一对单引号内
        assert!(
            ms.content.contains("'/Applications/白帝 安全接入客户端.app/Contents/MacOS/baidi-tun' "),
            "{}",
            ms.content
        );
        // AppleScript 那一层也要把带空格的脚本路径整体括住
        let Elevator::Osascript { apple } = &m.elevator else { panic!() };
        assert_eq!(
            apple,
            "do shell script \"/bin/bash '/var/folders/白 帝/T/baidi-tun-launch.sh'\" with administrator privileges"
        );

        let pl = paths_in("/tmp/白 帝", Platform::Linux);
        let l = plan_start(Platform::Linux, &请求(中文路径, &args, &env, &pl, "/usr/bin/pkexec"));
        // pkexec 收的是 argv，脚本路径作为**一个**元素原样传（不经 shell，天然不会被切）
        let Elevator::Pkexec { args: a, .. } = &l.elevator else { panic!() };
        assert_eq!(a[1], "/tmp/白 帝/baidi-tun-launch.sh");
        assert!(l.script.unwrap().content.contains(&sq(中文路径)));

        let pw = paths_in("C:\\Users\\张 三\\Temp", Platform::Windows);
        let w = plan_start(
            Platform::Windows,
            &请求("C:\\Program Files\\白 帝\\baidi-tun.exe", &args, &env, &pw, "powershell.exe"),
        );
        let Elevator::WindowsRunas { parameters, .. } = &w.elevator else { panic!() };
        // 含空格的 .ps1 路径必须被双引号整体括住，否则 -File 只吃到 "C:\Users\张"
        assert!(
            parameters.ends_with("-File \"C:\\Users\\张 三\\Temp\\baidi-tun-launch.ps1\""),
            "{parameters}"
        );
    }

    /// 生成的 unix launcher / stop 脚本必须是**合法 bash**。
    ///
    /// 逐字断言只能保证"我以为该长这样"，`bash -n` 才能保证引号真的配平——而引号写错的
    /// 症状是脚本在 root 那侧静默失败（stdout 已经被 `exec >/dev/null` 丢掉了），
    /// 界面上只剩「启动数据面失败：」后面跟一片空白。
    ///
    /// 没有 bash 时跳过（Windows 主机）；不用 `#[cfg(unix)]`，避免这条用例本身变成
    /// 「只活在 cfg 里的分支」。PowerShell 那两份**无法在本机语法校验**（macOS 上没有 pwsh），
    /// 它们的正确性只有逐字断言 + 真机验证，见模块头的诚实说明。
    #[test]
    fn 生成的_bash_脚本语法合法() {
        use std::process::Command;
        if Command::new("bash").arg("-c").arg("true").output().is_err() {
            return;
        }
        let p = paths_in("/var/folders/白 帝/T", Platform::MacOS);
        let args = 参数();
        let env = vec![(String::from("BAIDI_TOKEN"), String::from("a'b\"c$d`e\\f"))];
        let start = plan_start(Platform::MacOS, &请求(中文路径, &args, &env, &p, "/usr/bin/osascript"))
            .script
            .unwrap();
        let stop = plan_stop(Platform::MacOS, "4321", &p).script.unwrap();
        for sc in [start, stop] {
            let f = std::env::temp_dir().join(format!("baidi-elevate-test-{}.sh", std::process::id()));
            std::fs::write(&f, &sc.content).unwrap();
            let o = Command::new("bash").arg("-n").arg(&f).output().unwrap();
            let _ = std::fs::remove_file(&f);
            assert!(
                o.status.success(),
                "脚本语法不合法：{}\n---\n{}",
                String::from_utf8_lossy(&o.stderr),
                sc.content
            );
        }
    }

    #[test]
    fn 令牌里的单引号不会截断脚本() {
        let p = paths_in("/tmp/T", Platform::MacOS);
        let args = 参数();
        let env = vec![(String::from("BAIDI_TOKEN"), String::from("a'b;rm -rf /;'c"))];
        let sc = plan_start(Platform::MacOS, &请求("/opt/baidi-tun", &args, &env, &p, "/usr/bin/osascript"))
            .script
            .unwrap();
        assert!(sc.content.contains(r"export BAIDI_TOKEN='a'\''b;rm -rf /;'\''c'"), "{}", sc.content);
    }

    #[test]
    fn 环境变量名不合法时整条丢弃而不是拼进脚本() {
        let p = paths_in("/tmp/T", Platform::MacOS);
        let args = 参数();
        let env = vec![(String::from("X; rm -rf /"), String::from("v"))];
        let sc = plan_start(Platform::MacOS, &请求("/opt/baidi-tun", &args, &env, &p, "/usr/bin/osascript"))
            .script
            .unwrap();
        assert!(!sc.content.contains("rm -rf"), "{}", sc.content);
    }

    // ── 转义函数本身 ──

    #[test]
    fn win_quote_按_commandlinetoargvw_规则() {
        assert_eq!(win_quote("plain"), "plain");
        assert_eq!(win_quote("has space"), "\"has space\"");
        assert_eq!(win_quote(""), "\"\"");
        // 结尾反斜杠要翻倍，否则会把收尾引号转义掉（→ 参数边界整个乱掉）
        assert_eq!(win_quote("C:\\dir with space\\"), "\"C:\\dir with space\\\\\"");
        // 引号前的反斜杠翻倍 + 引号本身转义
        assert_eq!(win_quote("a\\\"b"), "\"a\\\\\\\"b\"");
        // 不含空格但含引号的也要走引号分支
        assert_eq!(win_quote("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn applescript_两层引号各转各的() {
        assert_eq!(applescript_quote("/bin/bash 'x'"), "\"/bin/bash 'x'\"");
        assert_eq!(applescript_quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(applescript_quote("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn ps_quote_单引号写两遍() {
        assert_eq!(ps_quote("O'Brien"), "'O''Brien'");
        // 单引号串不插值：$ 与反引号都是字面量，不该被额外处理
        assert_eq!(ps_quote("$env:PATH`x"), "'$env:PATH`x'");
    }

    #[test]
    fn ps_runas_命令形态固定() {
        assert_eq!(
            ps_runas_command("powershell.exe", "-File \"C:\\a b\\x.ps1\""),
            "$ErrorActionPreference = 'Stop'; \
             $p = Start-Process -FilePath 'powershell.exe' -ArgumentList '-File \"C:\\a b\\x.ps1\"' \
             -Verb RunAs -WindowStyle Hidden -PassThru -Wait; \
             if ($null -eq $p) { exit 1223 }; exit $p.ExitCode"
        );
    }

    /// 提权那一侧是另一个进程，它的 stderr 常常到不了我们手里（Windows 现在只回传退出码）。
    /// 「启动数据面失败：」后面一片空白等于没说，至少要给出退出码与日志路径。
    #[test]
    fn 没有_stderr_时的失败文案要给得出下一步() {
        let m = failure_message("启动数据面", Some(1), "", "/tmp/baidi-501/baidi-tun.log");
        assert!(m.contains("退出码 1"), "{m}");
        assert!(m.contains("/tmp/baidi-501/baidi-tun.log"), "{m}");
        // 有 stderr 时原样展示，不要被兜底文案盖掉
        assert_eq!(
            failure_message("断开", Some(1), " pkexec: 权限不足\n", "/x.log"),
            "断开失败：pkexec: 权限不足"
        );
        // 被信号打掉时没有退出码，也不能说成 0
        assert!(failure_message("启动数据面", None, "", "/x.log").contains("信号"));
    }

    // ── 断开 ──

    #[test]
    fn 断开三平台各自的杀进程方式() {
        let pm = paths_in("/tmp/T", Platform::MacOS);
        let m = with_elevator(plan_stop(Platform::MacOS, "4321", &pm), "/usr/bin/osascript");
        let ms = m.script.unwrap();
        // ★SIGTERM 而不是 -9：baidi-tun 要靠它回收 /etc/resolver 与 resolvectl 配置
        assert!(ms.content.contains("kill 4321\n") || ms.content.contains("kill 4321 2>/dev/null"));
        assert!(!ms.content.contains("-9"), "不许 kill -9：{}", ms.content);
        assert!(ms.content.contains("rm -f '/tmp/T/baidi-tun.pid'"));

        let pl = paths_in("/tmp/T", Platform::Linux);
        let l = with_elevator(plan_stop(Platform::Linux, "4321", &pl), "/usr/bin/pkexec");
        assert_eq!(
            l.elevator,
            Elevator::Pkexec {
                program: String::from("/usr/bin/pkexec"),
                args: vec![String::from("/bin/bash"), String::from("/tmp/T/baidi-tun-stop.sh")],
            }
        );

        let pw = paths_in("C:\\Temp", Platform::Windows);
        let w = with_elevator(plan_stop(Platform::Windows, "4321", &pw), "powershell.exe");
        let Elevator::WindowsRunas { file, parameters } = &w.elevator else { panic!() };
        assert_eq!(file, "powershell.exe");
        assert!(parameters.ends_with("-File C:\\Temp\\baidi-tun-stop.ps1"));
        assert!(w.script.unwrap().content.contains("Stop-Process -Id 4321 -Force"));
    }

    #[test]
    fn pid_必须是纯数字才拿去用() {
        assert_eq!(sanitize_pid(" 4321\n").as_deref(), Some("4321"));
        assert_eq!(sanitize_pid(""), None);
        assert_eq!(sanitize_pid("4321; rm -rf /"), None);
        assert_eq!(sanitize_pid("-1"), None);
    }

    // ── 判活 ──

    #[test]
    fn 判活命令分平台() {
        let (p, a) = running_probe(Platform::MacOS, "4321");
        assert_eq!(p, "ps");
        assert_eq!(a, vec!["-p", "4321", "-o", "pid="]);
        let (p, a) = running_probe(Platform::Windows, "4321");
        assert_eq!(p, "tasklist");
        assert_eq!(a, vec!["/FI", "PID eq 4321", "/NH"]);
    }

    #[test]
    fn windows_判活必须解析输出而不是看退出码() {
        // 有匹配：映像名 PID 会话名 会话# 内存
        let hit = "baidi-tun.exe                 4321 Console                    1     23,456 K\n";
        assert!(parse_running(Platform::Windows, "4321", hit));
        // ★没有匹配时 tasklist 也回 0，只在 stdout 打一句本地化提示
        let miss = "信息: 没有运行的任务匹配指定标准。\n";
        assert!(!parse_running(Platform::Windows, "4321", miss));
        assert!(!parse_running(Platform::Windows, "4321", "INFO: No tasks are running which match the specified criteria.\n"));
        // 内存列可能恰好等于 pid（"996 K"），只认第 2 列才不会误判成"还活着"
        let 误命中 = "other.exe                     1234 Console                    1        996 K\n";
        assert!(!parse_running(Platform::Windows, "996", 误命中));
    }

    #[test]
    fn unix_判活解析_ps_输出() {
        assert!(parse_running(Platform::MacOS, "4321", " 4321\n"));
        assert!(!parse_running(Platform::MacOS, "4321", "\n"));
        assert!(!parse_running(Platform::Linux, "4321", " 43210\n"));
    }

    // ── 取消 ──

    #[test]
    fn 用户取消授权三平台各自的判据() {
        assert!(is_cancel(Platform::MacOS, Some(1), "execution error: 用户已取消。 (-128)"));
        assert!(!is_cancel(Platform::MacOS, Some(1), "execution error: 权限不足"));
        assert!(is_cancel(Platform::Linux, Some(126), ""));
        assert!(is_cancel(Platform::Linux, Some(1), "Error executing command as another user: Request dismissed"));
        assert!(!is_cancel(Platform::Linux, Some(127), "pkexec must be setuid root"));
        assert!(is_cancel(Platform::Windows, Some(1), "The operation was canceled by the user."));
        assert!(is_cancel(Platform::Windows, Some(1), "操作已被用户取消。"));
        assert!(!is_cancel(Platform::Windows, Some(1), "找不到指定的文件。"));
        // ps_runas_command 的判空分支会 `exit 1223`，那一路可能一个字的 stderr 都没有
        assert!(is_cancel(Platform::Windows, Some(1223), ""));
    }

    // ── sidecar 定位 ──

    #[test]
    fn sidecar_候选名分平台且_windows_带_exe() {
        assert_eq!(
            sidecar_candidates(Platform::MacOS, "aarch64"),
            vec!["baidi-tun", "baidi-tun-aarch64-apple-darwin", "baidi-tun-universal-apple-darwin"]
        );
        assert_eq!(
            sidecar_candidates(Platform::Linux, "x86_64")[1],
            "baidi-tun-x86_64-unknown-linux-gnu"
        );
        let w = sidecar_candidates(Platform::Windows, "x86_64");
        assert!(w.iter().all(|n| n.ends_with(".exe")), "Windows 上不带 .exe 的不是可执行文件：{w:?}");
        assert_eq!(w[0], "baidi-tun.exe");
    }
}

