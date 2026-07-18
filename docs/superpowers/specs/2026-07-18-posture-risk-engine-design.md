# 终端 posture 真实上报 + 风险引擎（持续验证闭环） · 设计

日期：2026-07-18 ｜ 状态：定稿

## 背景与问题

「完全可用」差距审计排出的 5 大地基缺口中，#1（真实凭据）、#5（JWT 密钥）、#3（态势，部分）已在第一波打掉；本波打 **#4：终端 posture 真实上报 + 风险引擎**——零信任「持续验证」的最深缺口。现状四个断点：

1. **采集是假的**：桌面客户端「终端环境检测」全硬编码 `ok:true`（`clients/desktop/src/views/Connect.vue:229-235`），「每 60s 周期上报控制中心」是静态文案，全仓无任何上报代码。
2. **控制面无接收端**：没有 posture 端点、没有 posture 表。
3. **规则有 schema 无生命**：安全中心的 `BaselinePolicy/BaselineCheck`（平台×期望×严重度×处置）是现成的 posture 规则模型，但纯 Memory 种子、只读、前端编辑器保存不落库、`disposal` 字段无任何消费者。
4. **风险是种子**：`userstate` 风险分桶全硬编码；`riskScore` 只是账号状态两项式，无 posture 驱动的持续评分，更无「风险差→自动收缩」链路。

目标：终端真实采集环境信号 → 周期上报控制面 → 风险引擎按管理员可编辑的安全基线评估 → 不达标者**拒发敲门令牌 + 数据面撤窗断隧道（自动收缩）**，风险状态真实呈现在用户状态/态势/安全中心。

## 方案选择

- **A · 控制面集中评估（选定）**：客户端只负责采集原始信号并做机械布尔化（如 `fdesetup` 输出含 "On" → `ok:true`，附原始值），**策略判定权（选用哪些检查、严重度、处置动作）全在控制面风险引擎**；执行整体复用既有令牌闸 + 轮询捎带撤销管道，网关零改动。
- B · 端侧研判自阻断：把基线下发到客户端由端侧自我阻断——判定发生在被管终端上，可被篡改绕过，违背零信任"永不信任端点自证"。否决为主干；仅保留其 UX 价值（端侧实时展示采集结果）。
- C · posture 随敲门包携带、网关评估：SPA UDP 单包放不下检查集，网关无库无规则，还要为此开状态面——否决。

## 架构与数据流

```
桌面客户端 (Tauri)                     control (:8090)                        gateway
┌──────────────────┐  POST /posture   ┌──────────────────────────┐  policy 轮询  ┌────────────┐
│ Rust collect_posture│ ───60s 周期──▶ │ risk.Evaluate(报告×基线)  │ ──revoked──▶ │ applyRevoked│
│ (fdesetup/csrutil/…)│               │  → verdict 落 posture 表  │  (捎带并入   │ 撤窗+断隧道 │
│ UI 真实检测面板     │ ◀─verdict 响应─ │  → 审计 + 状态转换处置    │  posture 阻断)│ +封禁敲门   │
└──────────────────┘                  │ knock-token 第三道闸      │              └────────────┘
        ▲ 403 原因呈现                 │ userstate/overview 真实化 │
        └─────────────────────────────│ 安全中心基线 CRUD 落库    │
                                      └──────────────────────────┘
```

生效链路（持续验证闭环）：客户端 60s 上报 → 某次报告触发 `block` 判定 → ① 该用户 `/knock-token` 即时 403（掐 reknock 续窗）；② 网关下次轮询（≤15s）的 revoked 名单并入该用户 → 撤销 SPA 放行窗口 + 切断活跃隧道 + 封禁敲门；③ 客户端 `ErrDenied` 链路呈现拒绝原因。恢复 = 客户端下一次合规报告替换判定，闸自动解除。

## 决策点

- **DP-01 判定权在控制面**（方案 A）：客户端上报 `{key, ok, value}` 布尔信号，`ok` 映射是机械转换非策略；引擎在控制面比对基线。
- **DP-02 规则源 = 安全中心基线，落库可编辑**：`baseline_policies` 表持久化（照 authpolicy 范式），前端既有编辑器（分平台 AND 条件、处置、启停）接真实保存。这同时把 `/security` 从纯种子真实化（SPA 隐身块仍种子）。
- **DP-03 判定语义**：某启用基线中任一平台适用检查失败 ⇒ 该基线 violated ⇒ 其 `disposal` 生效；多基线取最严（block > gray > degrade > allow）。严重度只喂评分：high=25 / medium=10 / low=5，cap 100；level：≥60 high、≥30 medium、否则 low。全部可解释（reasons = 失败检查 label 列表）。
- **DP-04 block 判定持久，不看新鲜度**：最新报告判定为 block 就一直拦，直到**被更新的合规报告替换**——防"停止上报以逃逸"。新鲜度（10 分钟 `postureFreshTTL`）只用于 strict 模式的缺报处理。
- **DP-05 缺报策略默认 observe**：无报告/过期报告默认放行（兼容门户、移动端、探针、既有 E2E 与云端 demo），`BAIDI_POSTURE_ENFORCE=strict` 时缺报也 403（fail-closed，生产可开）。有新鲜坏报告则**任何模式都执行**。
- **DP-06 多设备取最差**：同账号任一设备最新判定为 block 即视为 block。
- **DP-07 degrade/gray 不阻断数据面**：只抬升风险呈现（userstate/overview）+ 审计告警。数据面处置只认 block（YAGNI：资源级降权、带宽收缩等留待）。
- **DP-08 8h 会话令牌直连洞同步堵**（上波 blocked-account 教训）：`handleGatewayPolicy` 动态并入 posture-blocked 用户（滚动 until），与 disabled/locked 并入同款——即使持 8h 会话令牌直敲网关也被拒。
- **DP-09 反篡改是明示局限**：客户端自报无 attestation（真产品需 TPM/公证链），与仓库"研究/演示"定位一致，写进 README 声明即可，不做假安全。
- **DP-10 账号键规范化**：posture 表 user 键 = `normUser`（与 revoked/封禁匹配键同族），杜绝大小写变体分裂。

## 契约

### 新表（sqlite.go migrate + seed）

```
baseline_policies(id TEXT PK, name, type, scope, disposal, status, platforms_json, checks_json)
posture_reports(user TEXT, device TEXT, platform, os, client_version,
                checks_json, verdict, score INTEGER, reasons_json, ts INTEGER,
                PRIMARY KEY(user, device))   -- 每 (用户,设备) 只存最新，upsert
```

种子基线（替换现 Memory 种子的消费路径，兼顾真机 demo 不误伤）：
- 「接入准入基线」disposal=**block**：磁盘加密 `disk_encrypted`(high)、系统完整性保护 `sys_integrity`(high) ——典型开发 Mac 默认通过。
- 「终端健康基线」disposal=**degrade**：防火墙 `firewall_on`(medium)、系统版本 `os_version`(medium)、EDR 在线 `edr_online`(low)、客户端最新版 `client_version`(low) ——真机常见部分失败 → 风险抬升可见，demo 叙事自然。

### 新/改端点（control/internal/api）

| 端点 | 鉴权 | 语义 |
|---|---|---|
| `POST /api/v1/posture` | 登录任意角色 | 上报 `{device, platform, os, clientVersion, checks:[{key,label,ok,value}]}`（≤32 检查、body ≤32KB）→ `risk.Evaluate` → upsert 落库 → 判定**转入/转出 block 时**审计（security 类）→ 响应 `{verdict, score, level, reasons}` |
| `GET /api/v1/posture` | admin | 最新报告清单（user/device/os/verdict/score/reasons/ts），喂安全中心「终端合规」 |
| `POST /api/v1/security/baselines` | admin | upsert 整条基线（照 authpolicy 校验范式：name/disposal/checks 必填合法）+ 审计 |
| `DELETE /api/v1/security/baselines/{id}` | admin | 删基线 + 审计 |
| `GET /api/v1/security` | 既有 | 改由 SQLite baselines 供数（`SQLiteStore.Security` 覆盖；Spa 块沿用种子） |
| `POST /api/v1/knock-token` | 既有 | **第三道闸**：latest verdict=block → 403（带失败原因）；strict 且无新鲜报告 → 403「无有效终端环境报告」 |
| `GET /api/v1/gateways/policy` | 既有 | revoked 并入 posture-blocked 用户（滚动 until=now+300s，与禁用账号并入同款） |
| `GET /api/v1/userstate` | 既有 | `SQLiteStore.UserStates` 覆盖：items ← 真实 users 表 × posture 判定（state 优先级 disabled>locked>risk-high>risk-low；idle 无来源诚实为 0），reasons ← 失败检查/账号状态，受关注用户 ← disabled/locked/high |
| `GET /api/v1/overview` | 既有 | 账号防线 TOP/风险分掺入 posture 引擎风险；在线设备数 ← 新鲜 posture 设备数（诚实回退种子） |

### 风险引擎（新包 `control/internal/risk`）

```go
// 纯函数，TDD 首选靶
func Evaluate(platform string, checks []ReportedCheck, baselines []store.BaselinePolicy) Verdict
type Verdict struct { Score int; Level string; Disposal string; Reasons []string }
```
规则：只评 `status=enabled` 且平台匹配（`Platforms` 含该平台或空）基线；基线内检查按 `Platform`（含 All）适用过滤；上报缺失某 key 视为该检查失败（缺失即不合规，防选择性上报）；`Disposal` 取 violated 基线最严；Score/Level 按 DP-03。

### Store 层（照 authpolicy 成对范式）

- `security.go` 扩：`Baselines(ctx)`；`baseline_sqlite.go`：读/`SaveBaseline`/`DeleteBaseline`。
- 新 `posture.go` + `posture_sqlite.go`：`PostureReport` 类型、`SavePostureReport`（upsert）、`PostureReports(ctx)`（全部最新）、`PostureVerdict(ctx, user)`（跨设备取最差 + 最新 ts）、`PostureBlockedUsers(ctx)`。
- `Writer` 接口加 `SaveBaseline / DeleteBaseline / SavePostureReport`。

### 桌面客户端（clients/desktop）

- **Rust 新 command `collect_posture`**（照 `tunnel_status` 范式入 `generate_handler!`）：macOS 真采集——`fdesetup status`（磁盘加密）、`csrutil status`（系统完整性）、`socketfilterfw --getglobalstate`（防火墙）、`sw_vers -productVersion`（版本，≥13 为 ok）、常见 EDR 进程探测（`falcond` 等，多半 false）、客户端版本常量；设备指纹 = `IOPlatformUUID` 的 SHA-256 前 16 hex 按 4 段冒号分隔（对齐种子形制）；非 macOS 返回 per-check `unsupported`（诚实）。
- **TS 侧**：`lib/posture.ts`——`invoke('collect_posture')` + `POST /posture` 上报；登录后启动 60s 循环（把假文案变真），Connect 前先上报一轮。浏览器 dev 回退：模拟采集（标注「浏览器演示环境」），device=`DEV-BROWSER`，仍走真实上报（control 管道在 dev 也可 E2E）。
- **Connect.vue**：posture 面板改渲染真实采集 + 控制面回传的 verdict/score；接入被 posture 拒时红条呈现控制面原因（既有 `ErrDenied`→`denied/deniedReason` 链路自动带出，文案泛化为「接入已被控制面拒绝」）。

### 控制台（console）

- `Security.vue`：基线编辑（增删检查/处置/启停/新建基线）接 `POST /security/baselines` 真保存；新增「终端合规」Tab：`GET /posture` 渲染 user/设备指纹/平台/检查 chips/verdict 着色/分数/最后上报。
- `userstate`/`overview`/大屏前端**零改动**（契约背后换真数据自动变实）。
- `lib/api.ts` 补 `PostureRow` 等类型。

### 网关（gateway）

**零改动**——posture-blocked 经既有 revoked 捎带通道消费（`applyRevoked` 撤窗/断隧道/封禁敲门原语全复用）。

## 边界与已知取舍

- 缺报默认放行（observe）是**文档化的 fail-open**，为兼容既有全部无客户端流程；strict 开关一行环境变量翻转。有坏报告则永远执行。
- 客户端可篡改自报数据（无 attestation）——明示局限（DP-09）。
- degrade 不动数据面（DP-07）；资源级降权留待。
- posture 表只存每 (user,device) 最新；历史轨迹走审计（判定转换时落 audit_log），不建历史表（YAGNI）。
- 每次网关轮询 / knock-token 多 1-2 次小表查询，量级同上波 `store.Users()`，可接受。
- 移动端原生壳接采集不在本波（Go 侧 `Session` 模式待接，无 DevEco/Xcode 工程验证条件）；设备清单页真实化（posture 报告可喂 Devices 页）记 backlog。

## 验证

- 单测（先 RED 后 GREEN）：`risk.Evaluate` 表驱动（平台过滤/缺失键视为失败/最严处置/评分分级/禁用基线跳过）；store 层 baseline/posture 读写（临时 SQLite）；api 层照 `linkage_test.go` 范式——上报→verdict 落库、坏报告→knock-token 403→policy 含该用户→合规报告→解除、strict 缺报 403、observe 缺报放行、非 admin 访 GET /posture 403、基线 CRUD 校验。
- E2E（本机）：control + gateway(-poll 2s) + python 后端；客户端登录→真实采集上报→敲门建长连→curl 伪造 `disk_encrypted=false` 报告→观察网关日志撤窗断隧道 + netstat 无 ESTABLISHED + knock-token 403 带原因→再报合规→令牌恢复 200。
- 前端：vue-tsc + vite build 净；preview 实测安全中心基线保存落库往返、终端合规 Tab、用户状态页真实分桶；桌面端 cargo check + tauri build。
