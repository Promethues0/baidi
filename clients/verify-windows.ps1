<#
.SYNOPSIS
    白帝 Windows 桌面客户端实机验证套件。

.DESCRIPTION
    Windows 这条链路至今**从未在真实 Windows 上跑过**——包能出、组件齐、单测绿，
    但建虚拟网卡、UAC 提权、NRPT 分离式 DNS 一次都没实测。产物因此标 UNVERIFIED
    且刻意不进下载中心。这个脚本就是用来把那些「未验证」逐条变成「已验证」或
    「确认坏了」的，它**不修任何东西**，只观察并如实报告。

    分三个阶段，按依赖递增。前一阶段不过就别跑后一阶段——
    在 DLL 都没落对位置的机器上测隧道，只会得到一个无从归因的失败。

      阶段 A｜打包落位（不需要服务端，装完即可跑）
        A1 安装目录是否在 Program Files（perMachine，非用户可写）
        A2 wintun.dll 是否与 baidi-tun.exe **同目录**
        A3 DLL 的 PE 架构与 baidi-tun.exe 是否一致
        A4 wintun 许可文件是否随包分发（许可义务）
        A5 sidecar 命名是否是运行期真正会去找的那几个名字

      阶段 B｜提权与建卡（需要管理员账号，会弹 UAC，会真的建网卡）
        B1 UAC 提权能否拉起 baidi-tun.exe
        B2 虚拟网卡 baidi0 是否真的建出来
        B3 路由是否按 -route 落进路由表
        B4 停止后网卡与路由是否被清理干净

      阶段 C｜完整链路（需要可达的 baidi-control 与 baidi-gateway）
        C1 SPA 敲门 → 隧道建立
        C2 分离式 DNS（NRPT 规则）是否生效
        C3 断开后 NRPT 规则是否回收

.PARAMETER Stage
    A / B / C / All。默认 A（最安全，不改动系统任何状态）。

.PARAMETER InstallDir
    安装目录。不给则自动探测。

.PARAMETER Control
    阶段 C 用：baidi-control 地址，如 https://10.0.0.5:8090

.PARAMETER ReportPath
    结果写到哪个文件（默认桌面 baidi-windows-verify.txt）。把这份文件回传即可。

.EXAMPLE
    # 最常用：装完先跑阶段 A（普通权限即可）
    powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1

    # 阶段 B 需要管理员：右键「以管理员身份运行 PowerShell」后
    powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1 -Stage B
#>

[CmdletBinding()]
param(
    [ValidateSet('A', 'B', 'C', 'All')][string]$Stage = 'A',
    [string]$InstallDir = '',
    [string]$Control = '',
    [string]$ReportPath = "$env:USERPROFILE\Desktop\baidi-windows-verify.txt"
)

$ErrorActionPreference = 'Continue'   # 单条检查失败不中止整轮：一次跑完拿到全貌比早退更有用
$script:Results = @()

function Add-Result {
    param(
        [string]$Id, [string]$Name,
        [ValidateSet('PASS', 'FAIL', 'SKIP', 'UNKNOWN')][string]$Verdict,
        [string]$Detail
    )
    $script:Results += [pscustomobject]@{ Id = $Id; Name = $Name; Verdict = $Verdict; Detail = $Detail }
    $color = switch ($Verdict) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'DarkGray' } default { 'Yellow' } }
    Write-Host ("[{0}] {1} {2}" -f $Verdict.PadRight(7), $Id, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
}

# ── PE 头解析：判断一个 exe/dll 是 x64 还是 arm64 ──
# 为什么要自己解析而不是信文件名：架构错配的 DLL 装得上、打包也不报错，
# 只在用户点「接入」那一刻炸。文件名是人写的，PE 头是编译器写的。
function Get-PeMachine {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            if ($br.ReadUInt16() -ne 0x5A4D) { return $null }   # 'MZ'
            $fs.Seek(0x3C, 'Begin') | Out-Null
            $peOff = $br.ReadUInt32()
            if ($peOff -le 0 -or $peOff -gt $fs.Length - 6) { return $null }
            $fs.Seek($peOff, 'Begin') | Out-Null
            if ($br.ReadUInt32() -ne 0x00004550) { return $null } # 'PE\0\0'
            return $br.ReadUInt16()
        } finally { $fs.Dispose() }
    } catch { return $null }
}

function Format-Machine {
    param($M)
    switch ($M) { 0x8664 { 'x64' } 0xAA64 { 'arm64' } 0x14C { 'x86' } $null { '读不出' } default { ('未知 0x{0:X}' -f $M) } }
}

function Resolve-InstallDir {
    if ($InstallDir) { return $InstallDir }
    # 装完之后 baidi-tun.exe 与主程序同目录；先按注册表卸载项找，再按常见路径兜底
    $candidates = @()
    foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty $hive -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*白帝*' -or $_.DisplayName -like '*baidi*' } |
            ForEach-Object { if ($_.InstallLocation) { $candidates += $_.InstallLocation } }
    }
    $candidates += "$env:ProgramFiles\白帝安全接入客户端"
    $candidates += "${env:ProgramFiles(x86)}\白帝安全接入客户端"
    $candidates += "$env:LOCALAPPDATA\白帝安全接入客户端"   # 若这条命中，A1 就该判 FAIL
    foreach ($c in $candidates) {
        if ($c -and (Test-Path (Join-Path $c 'baidi-tun.exe'))) { return $c }
    }
    return ''
}

function Invoke-StageA {
    Write-Host "`n═══ 阶段 A：打包落位 ═══" -ForegroundColor Cyan
    $dir = Resolve-InstallDir
    if (-not $dir) {
        Add-Result 'A0' '定位安装目录' 'FAIL' `
            '没找到含 baidi-tun.exe 的安装目录。是否已安装？也可用 -InstallDir 显式指定。'
        return
    }
    Add-Result 'A0' '定位安装目录' 'PASS' $dir

    # A1 安装位置：必须在 Program Files（perMachine）。装进 %LOCALAPPDATA% 意味着
    # 一个普通权限进程可以改写随后被 UAC 提权加载的 exe/dll —— 那是一条提权路径。
    $inProgramFiles = $dir -like "$env:ProgramFiles*" -or $dir -like "${env:ProgramFiles(x86)}*"
    if ($inProgramFiles) {
        Add-Result 'A1' '安装于 Program Files（perMachine）' 'PASS' $dir
    } else {
        Add-Result 'A1' '安装于 Program Files（perMachine）' 'FAIL' `
            "装在了 $dir —— 若该目录普通用户可写，则被 UAC 提权加载的 exe/dll 可被替换（本地提权）。检查 NSIS installMode 是否真为 perMachine。"
    }

    $tun = Join-Path $dir 'baidi-tun.exe'
    $dll = Join-Path $dir 'wintun.dll'

    # A2 这是本轮最想验的一条：DLL 落位此前只由打包器源码推断，从未实测。
    # wintun 用 LoadLibraryEx(APPLICATION_DIR|SYSTEM32)，只看进程自身 exe 目录与 System32。
    if (Test-Path $dll) {
        $sameDir = (Split-Path -Parent $dll) -eq (Split-Path -Parent $tun)
        if ($sameDir) {
            Add-Result 'A2' 'wintun.dll 与 baidi-tun.exe 同目录' 'PASS' `
                ("{0}（{1:N0} 字节）" -f $dll, (Get-Item $dll).Length)
        } else {
            Add-Result 'A2' 'wintun.dll 与 baidi-tun.exe 同目录' 'FAIL' "DLL 在 $dll，exe 在 $tun"
        }
    } elseif (Test-Path "$env:SystemRoot\System32\wintun.dll") {
        Add-Result 'A2' 'wintun.dll 与 baidi-tun.exe 同目录' 'UNKNOWN' `
            '安装目录没有，但 System32 里有一份（可能是别的软件装的）。加载会成功，但不是我们分发的那份——无法据此判断打包落位是否正确。'
    } else {
        Add-Result 'A2' 'wintun.dll 与 baidi-tun.exe 同目录' 'FAIL' `
            "两个位置都没有：$dll 与 $env:SystemRoot\System32\wintun.dll。打包没把 DLL 放进安装根目录（检查 tauri.windows.conf.json 的 resources 是否写成了映射形+空串）。"
    }

    # A3 架构一致性
    if ((Test-Path $dll) -and (Test-Path $tun)) {
        $mDll = Get-PeMachine $dll; $mTun = Get-PeMachine $tun
        if ($null -eq $mDll -or $null -eq $mTun) {
            Add-Result 'A3' 'DLL 与 exe 架构一致' 'UNKNOWN' `
                ("读不出 PE 头（dll={0} exe={1}），不可判定" -f (Format-Machine $mDll), (Format-Machine $mTun))
        } elseif ($mDll -eq $mTun) {
            Add-Result 'A3' 'DLL 与 exe 架构一致' 'PASS' ("均为 " + (Format-Machine $mDll))
        } else {
            Add-Result 'A3' 'DLL 与 exe 架构一致' 'FAIL' `
                ("dll={0} 而 exe={1} —— 加载时会失败，且失败信息不会提架构" -f (Format-Machine $mDll), (Format-Machine $mTun))
        }
    } else {
        Add-Result 'A3' 'DLL 与 exe 架构一致' 'SKIP' '缺 DLL 或 exe'
    }

    # A4 许可义务：wintun 许可第 3(c) 条不得移除版权声明，我们承诺随包附许可原文
    $lic = Join-Path $dir 'wintun-LICENSE.txt'
    if (Test-Path $lic) {
        $head = (Get-Content $lic -TotalCount 1 -ErrorAction SilentlyContinue)
        Add-Result 'A4' 'wintun 许可随包分发' 'PASS' ("首行：" + $head)
    } else {
        Add-Result 'A4' 'wintun 许可随包分发' 'FAIL' "缺 $lic —— 这是分发 wintun.dll 的许可义务，不是可选项"
    }

    # A5 sidecar 命名：运行期按这几个名字找，Tauri 打包时会剥掉三元组后缀
    $names = @('baidi-tun.exe', 'baidi-knock.exe')
    $missing = $names | Where-Object { -not (Test-Path (Join-Path $dir $_)) }
    if ($missing.Count -eq 0) {
        Add-Result 'A5' 'sidecar 命名与运行期查找一致' 'PASS' ($names -join '、')
    } else {
        Add-Result 'A5' 'sidecar 命名与运行期查找一致' 'FAIL' `
            ("缺：" + ($missing -join '、') + "。目录内实际有：" + ((Get-ChildItem $dir -Filter '*.exe' | Select-Object -Expand Name) -join '、'))
    }
}

function Invoke-StageB {
    Write-Host "`n═══ 阶段 B：提权与建卡 ═══" -ForegroundColor Cyan
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Add-Result 'B0' '管理员权限' 'SKIP' '阶段 B 需要管理员：请以管理员身份重开 PowerShell 再跑 -Stage B'
        return
    }
    Add-Result 'B0' '管理员权限' 'PASS' '已是管理员'

    $dir = Resolve-InstallDir
    if (-not $dir) { Add-Result 'B1' '拉起数据面' 'SKIP' '未定位到安装目录'; return }
    $tun = Join-Path $dir 'baidi-tun.exe'

    # B1 只验「能不能加载 wintun 并建卡」，不接服务端：用一个必然连不通的网关地址，
    # 让它走到建卡那一步就够了。建卡失败与连不上网关是两种完全不同的错误。
    Write-Host '  正在拉起 baidi-tun.exe（约 12 秒）…' -ForegroundColor DarkGray
    $out = Join-Path $env:TEMP 'baidi-tun-verify.log'
    $p = Start-Process -FilePath $tun -PassThru -NoNewWindow -RedirectStandardError $out `
        -ArgumentList @('-spa', '127.0.0.1:1', '-proxy', '127.0.0.1:1',
                        '-route', '10.99.99.0/24', '-ip', '10.99.99.2', '-control', 'http://127.0.0.1:1')
    Start-Sleep -Seconds 12
    $log = if (Test-Path $out) { Get-Content $out -Raw } else { '' }

    if ($log -match 'Unable to load library|wintun') {
        Add-Result 'B1' 'wintun.dll 可被加载' 'FAIL' `
            ("日志里出现加载失败：" + (($log -split "`n" | Where-Object { $_ -match 'Unable to load|wintun' }) -join ' / '))
    } else {
        Add-Result 'B1' 'wintun.dll 可被加载' 'PASS' '日志中无加载失败'
    }

    # B2 网卡是否真的建出来了
    $ad = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'baidi0' -or $_.InterfaceDescription -like '*Wintun*' }
    if ($ad) {
        Add-Result 'B2' '虚拟网卡已建出' 'PASS' ("{0}（{1}）状态={2}" -f $ad[0].Name, $ad[0].InterfaceDescription, $ad[0].Status)
        # B3 路由
        $rt = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -eq '10.99.99.0/24' }
        if ($rt) { Add-Result 'B3' '路由已落表' 'PASS' ($rt[0].DestinationPrefix + ' → ifIndex ' + $rt[0].ifIndex) }
        else     { Add-Result 'B3' '路由已落表' 'FAIL' '网卡建出来了但 10.99.99.0/24 没有进路由表' }
    } else {
        Add-Result 'B2' '虚拟网卡已建出' 'FAIL' `
            ("没找到 baidi0 / Wintun 网卡。日志尾部：" + (($log -split "`n" | Select-Object -Last 6) -join ' / '))
        Add-Result 'B3' '路由已落表' 'SKIP' '网卡都没建出来'
    }

    # B4 清理
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 4
    $left = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'baidi0' }
    if ($left) {
        Add-Result 'B4' '退出后网卡已回收' 'FAIL' 'baidi0 仍在（进程被杀后残留，需要重启或手工删卡）'
    } else {
        Add-Result 'B4' '退出后网卡已回收' 'PASS' 'baidi0 已消失'
    }
    Write-Host "  （baidi-tun 原始日志：$out）" -ForegroundColor DarkGray
}

function Invoke-StageC {
    Write-Host "`n═══ 阶段 C：完整链路 ═══" -ForegroundColor Cyan
    if (-not $Control) {
        Add-Result 'C0' '完整链路' 'SKIP' '未给 -Control；阶段 C 需要一个可达的 baidi-control（如 -Control https://10.0.0.5:8090）'
        return
    }
    Add-Result 'C0' '完整链路' 'UNKNOWN' `
        ("阶段 C 目前只能人工走：请用桌面客户端登录 {0} 并点「接入」，然后观察——" -f $Control)
    Add-Result 'C1' 'SPA 敲门 → 隧道建立' 'UNKNOWN' '客户端「接入」页是否显示已接入、网关落点与钉扎指纹是否正确'
    Add-Result 'C2' '分离式 DNS（NRPT）' 'UNKNOWN' "接入后跑 Get-DnsClientNrptRule，看是否出现指向隧道内解析器的规则"
    Add-Result 'C3' '断开后 NRPT 回收' 'UNKNOWN' '断开后再跑一次 Get-DnsClientNrptRule，规则应已消失'
}

# ── 主流程 ──
Write-Host '白帝 Windows 客户端实机验证' -ForegroundColor White
Write-Host ("主机 {0} / {1} / PowerShell {2}" -f $env:COMPUTERNAME,
    (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption, $PSVersionTable.PSVersion)

switch ($Stage) {
    'A'   { Invoke-StageA }
    'B'   { Invoke-StageB }
    'C'   { Invoke-StageC }
    'All' { Invoke-StageA; Invoke-StageB; Invoke-StageC }
}

# ── 报告 ──
$pass = ($script:Results | Where-Object Verdict -eq 'PASS').Count
$fail = ($script:Results | Where-Object Verdict -eq 'FAIL').Count
$unk  = ($script:Results | Where-Object Verdict -eq 'UNKNOWN').Count
$skip = ($script:Results | Where-Object Verdict -eq 'SKIP').Count

Write-Host ("`n结果：通过 {0} · 失败 {1} · 不可判定 {2} · 跳过 {3}" -f $pass, $fail, $unk, $skip) `
    -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'Green' })

$report = @()
$report += "白帝 Windows 客户端实机验证报告"
$report += "时间   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "主机   : $env:COMPUTERNAME"
$report += "系统   : $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)"
$report += "架构   : $env:PROCESSOR_ARCHITECTURE"
$report += "阶段   : $Stage"
$report += "汇总   : 通过 $pass · 失败 $fail · 不可判定 $unk · 跳过 $skip"
$report += ''
foreach ($r in $script:Results) {
    $report += ("[{0}] {1} {2}" -f $r.Verdict.PadRight(7), $r.Id, $r.Name)
    if ($r.Detail) { $report += "         $($r.Detail)" }
}
$report -join "`r`n" | Set-Content -Path $ReportPath -Encoding UTF8
Write-Host "报告已写入：$ReportPath" -ForegroundColor Cyan
Write-Host '把这个文件回传即可（里面没有任何凭据，只有路径、架构与状态）。' -ForegroundColor DarkGray
