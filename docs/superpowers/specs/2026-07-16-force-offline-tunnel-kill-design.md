# 强制下线真断隧道 · 设计

日期：2026-07-16 ｜ 状态：定稿

## 背景与问题

监控中心「在线用户」已真实化（`b3cf250`：网关上报活跃敲门会话），但「强制下线」还停在演示层，存在两个缺口：

1. **真实会话踢不动**：`handleKickSession` 的存在性校验只查演示种子（`store.OnlineSessions`），对网关上报的真实会话（id 形如 `gwid:ip`）直接 404。
2. **踢了也不断**：kick 只写控制面内存覆盖层（`s.kicked`），数据面网关的 SPA 放行窗口、活跃隧道连接全都不受影响；客户端的 reknock 保活还会立即续窗。前端 popconfirm 文案「将立即断开隧道并要求重新认证」目前是假的。

目标：让强制下线成为**真实的数据面处置**——撤销 SPA 放行窗口、切断该用户活跃隧道、封禁期内拒绝重新敲门与敲门令牌签发。

## 方案选择

- **A · 轮询捎带（选定）**：撤销名单捎带在网关既有的 `GET /gateways/policy` 轮询响应里。不新增网关监听面（保持"暗"设计）、天然多网关、生效延迟 ≤ 轮询间隔（默认 15s）。
- B · 控制面主动推送：需网关开管理端口，破坏默认不可达的隐身设计——否决。
- C · 长轮询/WS 降延迟：复杂度不成比例，YAGNI——否决。

## 设计

### 控制面（control/internal/api）

- `Server` 增 `revoked map[string]revokeInfo`（key=账号，value={Reason, Until}），与 `kicked` 同锁（`s.mu`）。**封禁时长 5 分钟**（const `kickBanTTL`）：强制下线 + 短时封禁，到期可重新接入；控制面重启即失（与 `kicked` 覆盖层一致的内存语义，可接受）。
- `handleKickSession`：
  - 先在 `s.gwSess` 里解析真实会话（`gwid+":"+ip == id` → 取 `se.User`）；未命中再走演示种子路径（取 `ss.Account`，空则 `ss.User`）；两边都没有才 404。
  - 命中后：`kicked[id]=reason`（显示覆盖层，保留）+ `revoked[user]={reason, now+5m}`；审计文案带上账号；响应回 `user`/`banUntil`。
- `handleGatewayPolicy`：响应增 `revoked: [{user, until, reason}]`（只下发未过期条目，顺手懒清理过期项）。
- `handleKnockToken`：签发前查 `revoked[c.Name]` 未过期 → 403「已被强制下线，暂时无法接入」+ 审计 deny——掐死客户端 reknock 保活的令牌来源。

### 数据面（gateway/）

- `spa.Allowlist` 增：
  - `deny map[string]time.Time`（用户→封禁截止，懒过期）；
  - `DenyUser(user, until) bool`（新封禁或延长时返回 true，供只在首次应用时打日志）；
  - `UserDenied(user) bool`（`Serve` 在令牌校验通过后检查，命中则拒绝敲门并日志「用户已被强制下线」）；
  - `RevokeUser(user) []string`（删除该用户全部放行窗口，返回被撤 IP，供 pf 回收）。
- `proxy` 增连接登记表（包级，同 `active` 风格）：授权通过后 `track(user, conn)`、退出 `untrack`；`KillUser(user) int` 关闭该用户全部活跃隧道连接（`Close` 打断 `io.Copy`）。
- `cplane.Policy()` 返回值扩为 `(resources, revoked, error)`；`Revoked{User, Until, Reason}`；响应缺 `revoked` 字段时向后兼容（空表）。
- `main.go` 轮询回路（含首拉）应用撤销：`DenyUser` 返回 true 时 → `RevokeUser` 撤窗 + `KillUser` 断隧道 + 日志；`-pf` 模式下对被撤 IP 走与 reaper 相同的「确认未重新放行再 DenyIP」防误删。

### 前端（console）

零改动：kick 调用与响应容忍度不变，popconfirm 文案从此为真。

### 生效链路

kick → 控制面记撤销 →（≤poll）网关拉策略 → 撤窗 + 断隧道 + 拒重敲；客户端 reknock 令牌被控制面 403 → 5 分钟封禁期满自然恢复。

## 边界与已知取舍

- 生效延迟 ≤ 轮询间隔（15s 默认）；演示/内网场景可接受，不为此加推送通道。
- 撤销名单在控制面内存态，重启即失——与在线会话本身的生命周期一致。
- 门户 8h 会话 JWT 不吊销（scope 外）；封禁只作用于数据面接入（敲门/令牌/隧道），管理台不受影响。
- kick 演示种子会话同样记撤销（账号进封禁表），语义一致无害。

## 验证

- 单测：`spa`（DenyUser/UserDenied 过期、RevokeUser 撤窗）、`proxy`（track/KillUser）。
- E2E（本机）：control + gateway(-poll 2s) + python 后端；portal 登录 → knock-token → 敲门 → `openssl s_client` 保持长连隧道 → admin kick → 观察网关日志「强制下线执行」+ s_client 断开 + 重敲被拒 + knock-token 403 → 等封禁过期（测试用短 TTL 不必等）。
- go build / go vet 双模块；无前端改动不跑 vite。
