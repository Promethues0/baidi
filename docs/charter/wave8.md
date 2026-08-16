# 白帝 · 第八波行动清单（wave7 全部落地后的 PRD 重扫产物）

> 产出方式：2026-08-16 用 42-agent 工作流对照 PRD 重扫 22 章 471 条 FR/NFR（8 组并行扫章 →
> 34 条候选缺口逐条对抗证伪 → 30 条存活 / 4 条被推翻 → 同根合并收敛）。
> 与 wave7 的扫描相比刻意加了一道门：**每个扫章 agent 必须先读四份「已落地」基线**
> （CLAUDE.md 关键约定 / ARCHITECTURE 第七节 / SCOPE.md / wave7 charter），
> 并被明确允许报「本组没有值得做的缺口」——防止把这三周做完的东西再报一遍。
> 判据：SCOPE.md 已豁免的不算缺口；每条都有 PRD 条目号与代码证据（行号已逐条复核）。
> 另附「实现债」一节：那半 PRD 扫描结构性看不见，由本人当场核实。

---

## 〇、同根合并说明

30 条存活缺口合并为 17 条行动 + 8 条边界建议（含行动 1 复核期间挖出的一条）。合并关系：

- **α 组「假配置面还剩四块」**：认证策略 PC/移动主认证下拉（FR-AUTH-12）+ 认证策略「默认授权应用」（FR-AUTH-23）+ 用户策略继承编辑器 8 项（FR-POLICY-02~44）+ 安全基线 type/scope（FR-SEC-BL-01~08）——同根于 wave7 行动 13：那次摘 `Policy.vue` 六个假开关时**只扫了一个 tab**，同页默认打开的那个 tab 与另两个抽屉一起漏了。
- **β 组「开放能力整章被一个对勾盖住」**：FR-INTRO-14 开放 API 联动 + FR-SEC-3RD-01~03 第三方风险上报 + FR-INT-07/08/12/14/15/16 ch21 空洞——同根于 `SCOPE.md:28` 那个 ✅，它让连续七波审计跳过整章。
- **γ 组「灰度最后一段」**：FR-UPG-19 页面吞掉用户组定向 + 覆盖率完全不可见 + 移动端从未接更新检查——同根于「服务端判定是真的，最后一跳三处各缺一块」。
- **δ 组「外部目录治理」**：FR-AUTH-22 未导入用户准入闸 + FR-USER-10 状态属性映射 + FR-AUTH-09 认证域路由——三条都只在**接了第二个目录之后**才暴露，wave7 把 LDAP/OIDC 接通那一刻就把它们造了出来。
- **ε 组「数据面回执缺口」**：FR-NAT-02/11/17 NAT 零回执 + NFR-SEC-01 隐身真实态不上报 + FR-SCEN-08/17 接入地址无配置面——同一形态：**网关自己完全知道，控制面无从知道**。IPSec 已经把这条路走完（`ipsec_sa_state` + ConfigWarning + 四态），wave7 行动 9 又走了一遍（reachprobe→心跳→资源页），NAT 与隐身是同一模板的第三、四次复用。

---

## 一、行动清单（主线价值 > 静默失效风险 > effort）

### 第一梯队：会当场做出错误的访问决策

**1. 门户磁贴接真授权判定（FR-INTRO-10/12/16）— M ✅ 已落地**
- 落地记（2026-08-16）：判定收敛成 `api.appAccessState`（`subjects.go`，紧邻 `accessibleFor`），剖面与门户共用它；控制面判定点由「三个同构 + 门户一处各行其是」变成**四个同构**，注释与 ARCHITECTURE 同批改对。磁贴新增第三态 `unavailable` + 服务端下发的 `unavailableReason`（**结构性不可用**：未关联受控资源 / 后端不是 host:port——恰好对应剖面的两条丢弃路径，按钮置灰写「请联系管理员」）。三端文案同批脱钩敏感度：门户/桌面/移动的「高敏 · 需申请」改成按**真实原因**分态，移动端此前是独立写死的 `sensitivity === 'high'` 判据（已授权的高敏应用照样挂着「需申请」、未授权的普通应用一个提示都没有），一并改掉。测试 `portal_apps_test.go` 七条：核心同构用例**两个端点都走真实 HTTP**（函数层比对是自欺——两边现在调同一个函数，恒真），遍历两侧 key 的**并集**并断言「磁贴覆盖库里全部 running 应用」，逐条覆盖三种失败形态、两种不可用成因、降权、JIT；对旧代码验证 7 条中 6 条会红。浏览器实测四态渲染 + 走通一次「普通资源未授权 → 提交申请」（旧代码下这条路根本走不到）。
- 收工前跑了一轮 35-agent 对抗式复核（6 视角找 + 逐条证伪），29 条候选存活 6 条，全部已修：① 只覆盖「未关联资源」一种成因，让「剖面缺席 ⟺ 门户标不可用」只单向成立（补上 host:port 那条，双向成立）；②③④ 测试只从门户一侧遍历 + `t.Skip` 依赖种子 a4——变异实测证明「把不可用磁贴藏起来」能让**全包绿灯**通过（改成并集遍历 + 用例自建应用 + 硬断言，三个曾逃逸的变异现在全红）；⑤⑥ 两处文档把改前基线与不变式写强了（死路的消失还依赖前端把 degraded/unavailable 排在「申请权限」之前，这一步原先没写）。
- 顺带修掉三个**先前就存在**的缺陷：那条「七层入口不可用」的 `<div v-if>` 插在按钮 v-if/v-else-if 链中间把链截断了——一个**可访问**的隧道类应用会同时画出「接入地址」和「申请权限」两个按钮；「N 个待申请」把降权与不可用的磁贴也数了进去；桌面端渲染剖面的 `degraded` 却一律画成「需申请」（降权态下申请必然被否）。
- 做什么：`handlePortalApps` 改走 `accessibleFor`（与剖面、Web 票据同构），高敏那条改成「已授权即可访问；未授权**且**资源受限才提示申请」。
- 改哪里：`control/internal/api/api.go:741-753`；`console/src/views/PortalApps.vue:57-60/86`；顺手把 `store/subjects.go:108-122` 那段「控制面侧唯一判定入口」的注释补上门户这第三个消费方。
- 为什么值得：这是控制面**第四个**可访问性判定点，而且它谁都不认——不认 ACL、不认组织/用户组、不认 JIT，只看 `sensitivity`。三种失败形态全部无报错，且已被对抗验证用临时用例实测复现：①普通资源未授权用户 → 磁贴恒亮「访问」，点下去 403；②高敏资源**已授权**用户 → 磁贴恒「需申请」，逼他为自己已有的权限走审批，而同一个人经桌面客户端立刻能进（审批成纸面闸）；③高敏 + 未设 ACL → 磁贴锁着、点「申请权限」回 400「无需申请」死路，而该资源经隧道与 Web 票据对**全体登录用户**开放，方向完全相反。第③种由 `backfillResourceSensitivity` 自动造得出来（`apps.category='finance'` 一律抬 high，不问有没有 ACL）。
- 注意：`api.go:701-702` 现有注释写的是「JIT 闭环的门户侧收口」，读起来像有执行方——改完要把注释同步改对，否则下一个人还会以为它接过。

**2. 安全基线两处会咬人的（FR-SEC-BL-01/02/04/05/14）— S**
- 做什么：①`POST /security/baselines` 校验每个检测项 `key` 必须落在采集器六键之内（`disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version`），并把这六键做成页面上的下拉；②`client_version` 从「客户端自判」改成「控制面按灰度目标版本判」。
- 改哪里：`control/internal/api/security.go:51-56`（紧邻的 40-45 行对 `platforms` **已经做过**这道枚举校验，照抄）；`console/src/views/Security.vue:320-328` `addCheck()`（现在把 key 写成 `'c-' + Date.now()`）；`clients/desktop/src-tauri/src/posture.rs:165-171`（`client_version_check` 直接 `return (Tri::Pass, ver)`）；判据搬到 `control/internal/risk` 或复用 `upgrade.handleClientUpdate` 的比较逻辑。
- 为什么值得：不是「没做」而是「做了且会咬人」——管理员点一次「添加检测项」再保存，该平台**全体终端**下一次 posture 上报即判违规，而种子基线的 disposal 就是 `block`，等于一键全员拒发敲门令牌 + 撤窗断隧道，保存那一刻零报错。反方向同样坏：`client_version` 恒 Pass，终端合规页对跑三个版本前客户端的机器同样亮绿——正是 wave7 行动 10 判过死刑的「假绿替坏链路背书」，只是这次长在合规页上。
- 注意：这两项失败方向相反（key 填错 = 全员 fail-closed，platform 填错 = 永不生效 fail-open），文案与告警要分开写；`client_version` 若判定不接真，就该把它从种子基线里**摘掉**而不是留着恒绿。

**3. NAT 生效回执（FR-NAT-02/11/17）— M**
- 做什么：与 wave7 行动 9（reachprobe→心跳→资源页可达列）**逐字同构**：心跳加 `nat` 字段（能力有无 / 后端 nft|pf / 已灌条数 / lastError / 命中计数）→ 控制面聚合 → `Nat.vue` 把「状态」列拆成「管理意图 / 网关回执」两栏 → `/diag` 加一项。
- 改哪里：`gateway/cmd/baidi-gateway/main.go:372-389`（`applyNAT()` 首行 `if natApp == nil { return }` 静默返回、失败分支只 `slog.Error` 就 return，**只有成功那一支**才 `QueueEvent`）；`gateway/internal/cplane/cplane.go:270-300`；`gateway/internal/natfw/apply.go:134-188` 的 `Applier.Hits()`（**全仓零调用方**，规则里那个 counter 纯属白算）；`control/internal/api`、`console/src/views/Nat.vue:72/95-97`、`api/diag.go`。
- 为什么值得：`store/ipsec.go:22-31` 的注释白纸黑字批判过这个形态——「status 一列同时表达『管理员想让它开』和『它现在真的开着』」，IPSec 为此拆出了 `ipsec_sa_state`；NAT 的 `enabled` 开关**现在承担的正是那个被批判的双重语义**。而 `deploy/install-remote.sh` 生成的 `baidi-gateway.env` 不含任何 `-nat` 相关项，即按参考流程装出来的系统，管理员配好 DNAT 发布、页面绿灯、网关侧一行日志都不打，症状是「发布的业务公网打不开」。FR-NAT-17 更是**做了一半没接线**——最贵的那半（内核 counter + JSON 解析回填 PolicyID）已经写完了。
- 注意：`nat` 字段与 `metrics` 同款三态纪律——没带该字段（旧网关）与带了空值（新网关但没开 -nat）必须可区分。

**4. 网关对外接入地址配置面（FR-SCEN-08/17/18/19）— M**
- 做什么：照搬 `GatewayIface`「网关实测上报 + 控制面登记」那套，给每台网关加**可编辑**的对外访问地址（内网 / 互联网两栏），`profileGateways` 优先取它；兜底分支保留，但落进兜底时必须在剖面 `warnings` 里点名「落点 X 用的是全局兜底 host」。
- 改哪里：`control/internal/api/clientprofile.go:655-666`（兜底 `envOr("BAIDI_CLIENT_GW_HOST","127.0.0.1")` 是**全局单值**，在 for 循环里被每台网关各取一次）、`:692-717` `gatewayWarnings`（只查指纹与在线数，不查落点是不是回环、不查多落点 Host 重复）；网关页；`store` 补两列。
- 为什么值得：两个后果都完全静默。①`gateway/cmd/baidi-gateway/main.go:47-48` 默认监听 `:18201`（不带 host）→ `splitHostPortLoose` 得空 host → **默认配置必然走兜底分支**，于是按 `install-remote.sh` 装一台 `WITH_GATEWAY=1` 的网关，剖面下发给桌面客户端的 host 是 `127.0.0.1`，客户端拨号超时，而控制台显示在线、warnings 一条不报——正是 CLAUDE.md 记的「隧道建起来了、点开应用却不通、无报错」同族。②多数据中心下 N 个落点填**同一个** Host，客户端 `dataplane.picker` 忠实地打出「切到落点 2/3」的日志，实际拨的还是同一台机器——**故障转移在页面上可见、在网络上不存在**。
- 注意：`failover_test.go:44` 所有用例都给显式 host，兜底折叠这条路径**零测试覆盖**——补测试时先构造 `SPA=":18201"` 的网关。这条不属于 SCOPE ch19 已豁免的那半（那里明示不做的是「跨中心统一入口 / 智能 DNS 就近解析」）。

### 第二梯队：监控与留痕正在替坏状态背书

**5. 在线用户页脱壳（FR-MON-10/12/04）— S**
- 做什么：`monitor_objects.go:46-49` 那批硬编码字段改成真取数——`Org` 取 `users.org_id`、`Trust` 取 `trusted_devices` 状态（pending/revoked → untrusted，取不到 → unknown）、`Risk` 取最新 posture 判定档；取不到的一律 `unknown` 而不是好值。
- 改哪里：`control/internal/api/monitor_objects.go`、`console/src/views/Online.vue:174-176`（三个 KPI 与三个筛选 tab 在 live 模式下恒 0 / 恒空）。
- 为什么值得：wave7 删掉的是「无网关时回退 10 条演示会话」那条种子路径，**live 路径本身从未脱壳**。而硬编码 `trusted`/`none` 比补 0 更严重——它是**正向断言**：observe 模式下被放行的未授信终端、被 degrade 降权的账号，在监控中心这一页全部显示为「授信 / 无风险」，与项目自己在网关指标与 posture 上立的「采不到就报不可判定、绝不补 0」纪律方向相反。`org` 恒 `—` 还让 FR-MON-12 的「按组织架构搜索」不可能命中，而 `users.org_id` 就在库里。
- 注意：`store/monitor.go:12-23` 把这几个字段的语义写成真实值（`trusted|untrusted|unknown`、`none|low|high`），没有一处注释说明它们是占位符——脱壳后这些注释才算数。

**6. 审计写入失败必须有信号（FR-AUDIT-01/10、FR-MON-21/22）— M**
- 做什么：`s.audit/auditAs/auditBG` 三处的 `_ = s.writer.RecordAudit(...)` 改成失败即 `slog.Error` + 计数器；给 `alert_rules` 加一条「审计写入失败」规则（信号 = 该计数器）；顺带把 `AuditDiskStat` 已经算好的水位接进 `PurgeExpiredAudit`，兑现 FR-AUDIT-10「最大占用磁盘百分比」那半。
- 改哪里：`control/internal/api/audit_record.go:95/111`（全系统 194 个审计点全部收敛到这两行）；`control/internal/store/alerts.go`（11 条规则里没有一条看**控制面自身**存储，`gateway_load` 看的是数据面的盘）；`store/audit_sqlite.go:322-337` `AuditDiskStat` 现有消费方只有手动体检与页面展示。
- 为什么值得：磁盘写满或库写锁失败时，管理操作照常回 200、审计静默停写、**链校验仍全绿**（`VerifyAuditChain` 只重算已存在行的前缀连续性，尾部整段没写进去不构成断链）、告警一条不响——审计中心「全量留痕、事后可举证」的第一性主张恰在最需要它的时刻失效且无人知晓。项目自己在外送队列上界那里论证过「磁盘写满会让审计本身落不了库」，但那条论证只用来给外送队列加上界，没有反过来保护审计写入本身。
- 注意：**「best-effort 不影响主操作」是对的取舍，别改成回滚**——缺的不是回滚而是信号。同一仓库里外送入队失败尚且 `slog.Error`，主审计写失败连一行日志都没有，这个不对称本身就是判据。

**7. SPA 隐身真实态回执（NFR-SEC-01、NFR-OBS-01、FR-OPS-10）— M**
- 做什么：与 metrics/posture 的三态纪律同款——心跳加一个隐身后端字段（`darkfw.Available()` / `-pf` 实况）→ 网关页与 `/diag` 分「内核态 nftables/pf」与「仅用户态（端口对扫描器可见）」两态呈现 → 对比卡片文案跟随真实态 → deploy 侧要么装 nft ruleset、要么在安装输出里当面写清为什么没装。
- 改哪里：`gateway/cmd/baidi-gateway/main.go:54`（`-pf` **默认关**）、`gateway/internal/cplane/cplane.go:271-303`（payload 无隐身字段）；`console/src/views/Gateway.vue:121/144-146/149`（写死「内核态默认丢弃」「端口扫描全程超时」「攻击面 = 0」）；`control/internal/api/diag.go:363-399` `checkStealth`（只要有网关在线就恒 pass）。
- 为什么值得：隐身是白帝第一卖点，NFR-SEC-01 的验收就是「外部扫描结果端口全闭」。能力在（`darkfw` + 两个 setup 脚本），但**参考部署与在线演示站都没启用**——`deploy/systemd/baidi-gateway.service:3` 明写「默认不开 -pf」，`install-remote.sh` 全程不执行 `baidi-nft.sh`；未开时未敲门的连接走 `proxy.go:129-134` 的 accept-then-close，**TCP 三次握手已经完成，nmap 判 open**。「握手后被断开」与页面断言的「等同于不存在」是两种安全等级。更关键的是形态复发：第七节刚记功删掉过 Security 页那个恒 true 的「已隐身」，理由原文是「在替一台可能压根没配防火墙规则的网关打包票」——`Gateway.vue` 那四条断言与 `checkStealth` 的恒 pass 正在做同一件事，只是换了个页面。
- 注意：控制面确实无法外部实测，但**网关自己完全知道**——不上报等于硬把可判定的事做成不可判定。

**8. C/S 隧道放行留痕（FR-AUDIT-01/02/05、FR-MON-04）— M**
- 做什么：`handleKnockToken` 成功路径落一条 access 审计（照 `webproxy.go:117` 签 Web 票据那条的措辞），网关 `proxy.go:184`「隧道路由命中」由本机 slog 改为经 secevent 通道上报（**扩一个 allow 类**）；两处都按现成的 5min 节流纪律。
- 改哪里：`control/internal/api/api.go:1057-1090`（成功路径零审计，而同函数与 `entryGates` 里五处**拒绝**全部落审计）；`gateway/internal/secevent`（包注释即写明「拒绝」，需要扩语义）；`gateway/internal/proxy/proxy.go:184`、`webproxy/server.go:260`。
- 为什么值得：审计里只有拒绝没有放行——「某账号何时经哪台网关访问了哪个资源」在中心侧查不到，网关一重启本机 slog 即灭失；FR-AUDIT-05 的出向四元组检索连数据源都没有，外送给 SIEM 的证据链只有半边。**对照最刺眼**：过同一道 `entryGates` 的 B/S 路径签票时是落审计的，C/S 这条主路径反而不落。
- 注意：wave7 A 组的措辞是「拒绝比放行更需要留痕」——**那是排序不是排除**。洪泛顾虑有现成解法：敲门是 15s 一次的保活热路径，而 `api/devices.go:229` 的 `auditDeviceObserved` 早已用 (账号,指纹) 5min 节流记录「放行」这一类事实，模式直接复用，不需要新造机制。

**9. 安全概览统计时间窗（FR-MON-04/06/07/08）— S**
- 做什么：`Overview` 接受时间范围参数（`auditAggregates` 两条 SQL 加 WHERE + 页面时间快选），TOP 从硬编码 3 条放到 5 条；终端防线那半如实标注「无历史，只有最新一份」。
- 改哪里：`control/internal/store/overview_sqlite.go:210-217`（`SELECT category, COUNT(*) FROM audit_log GROUP BY category`，**无任何 WHERE**）、`:54/93/199` 的 `len(...) < 3`；`api/api.go:1916`（不读任何查询参数）；`console/src/views/Overview.vue:5/46`、`BigScreen.vue`。
- 为什么值得：口径混排且页面一处不标——同一屏上「威胁事件 N」是建库以来累计、「攻击源」是严格 24 小时，而标题写着「实时判定态势」；`BAIDI_AUDIT_RETENTION_DAYS` 轮转一到期这个数字还会无缘由地往下掉。ARCHITECTURE 当年删掉 `DefenseLine.Trend` 的理由是「白帝一张历史态势表都没有」，**该理由现在对账号防线已部分失效**：`audit_log` 带 ts、`attack_sources` 是小时桶，账号线的趋势与风险类型分布已有真实数据源可算，只有终端防线（`posture_reports` 只存最新一份）确实仍无历史——应当如实分开表态而不是整体缺席。

### 第三梯队：外部目录治理（接了 AD/IdP 才暴露的三条）

**10. 未导入用户准入闸（FR-AUTH-22、FR-USER-13/14）— M**
- 做什么：认证源加一个「未导入用户默认禁止登录」开关（PRD 的 P0 形态），打开时外部账号首登进 `pending` 并生成一条**复用既有 approvals 表**的审批单（与授信终端 `approval` 模式完全同构），批准后才建号；OIDC 侧补允许域 / 允许组过滤。
- 改哪里：`control/internal/api/login_authsrc.go:171-184`（认证通过即直接 `BindExternalUser`，无任何开关或白名单）、`store/authsrc_sqlite.go:219-327`（无条件建 `role=user, status=active` 的 users 行）、`:452-481` `ensureExternalOrgUnit`；`oidcsrc` 配置项（现在只有 Issuer/ClientID/RedirectURI/Scopes）。
- 为什么值得：外部账号落进「外部目录」单元，其父是**第一个顶层组织**（种子里就是根 `root`），而 `OrgAccounts` 是含全部后代的展平——于是把任一资源授权给根组织，即刻覆盖全部自动建号的外部账号。失败场景：接入公司 AD 或 IdP 后，管理员把 OA 授权给根组织「全员可访问」，此后 AD 森林里任意能过 `userFilter` 的条目（服务账号、承包商、刚被 HR 建的号）或 IdP 里任意能完成一次授权码流的账号，首登即自动获得白帝账号 + 门户会话 + OA 访问权，全程无审批、无告警。
- 注意：这与「目录全量同步」（wave7 D 组第二步，L 级延后）**不是一回事**——准入闸不依赖同步。建号本身现在也不单独落审计，一并补上。

**11. 状态回验补全：LDAP 状态属性映射 + OIDC 回验通道（FR-USER-10、FR-AUTH-04/08）— M**
- 做什么：①认证源配置补两个字段（账号状态属性 + 表示停用的值，按服务器类型预填：AD `userAccountControl`、IDTrust `accountEnable`），沿用既有 `usernameAttr/groupAttr` 的模式；②OIDC 侧补回验通道（登录时留存 refresh_token → 周期做一次 refresh grant 或 UserInfo 探活）。
- 改哪里：`control/internal/authsrc/ldapsrc/recheck.go:42-46`（只请求 AD 那两个属性、filter 写死 `(objectClass=*)`，**连配置里的 userFilter 都不用**）、`:72-87`（uac 为空即返回 `StateActive`）；`control/internal/api/login_authsrc.go:50-63` `ldapConfigDTO`；`authsrc.StatusChecker` 的注释即写死「LDAP/AD：subject = entryDN」，`oidcsrc` 无对应实现。
- 为什么值得：这条链路的存在意义就是把「目录侧禁号」传导成「白帝断连」，而它现在**只覆盖了一半的一半**：OpenLDAP/IDTrust 部署下只剩「条目被删除」一种触发条件，OIDC 部署下一种都没有。HR 在目录里停用离职员工后，该账号的会话、敲门令牌、隧道继续有效到自然过期，回验循环每轮都判 active、不留任何痕迹（fail-open 方向的静默失效）。
- 注意：`SCOPE.md:14` 现在的对外口径是「LDAP/AD 按 entryDN 周期直查，禁用/过期/删除即禁号+撤窗断隧道」，不区分 AD 与通用 LDAP，也不提 OIDC——而代码注释（`recheck.go:22-27`）与 `ARCHITECTURE.md:641` 是诚实的，**两处口径不一致**。不打算全做的话，先把 SCOPE 那句改准。

**12. 认证域路由（FR-AUTH-09/24、FR-USER-01/06）— M**
- 做什么：登录请求带 `directory`（或按用户名后缀/域前缀路由）+ 命中即**只问该源**；登录页给目录选择（候选由后端下发，与认证策略的 `directories` 同源）。
- 改哪里：`control/internal/api/login_authsrc.go:156-194` `authenticateExternal`（遍历全部 enabled 外部源逐个 `Authenticate`，第一个成功者胜出）、调用点 `api.go:633-656`；`console/src/views/Login.vue`、`PortalLogin.vue`、移动端登录页。
- 为什么值得：单目录部署无影响，但只要接第二个外部源就同时出现两个问题：①**凭据外溢**——A 目录员工的明文口令会被真实投递到排在前面的每一个 LDAP 服务器去 bind（含本地口令输错的那次），对方日志里就有；②身份归属取决于配置顺序而非用户意图，同名账号谁先配置谁认走，后建的绑定走 `base@sourceID` 后缀分裂成第二个账号，管理员在用户页看到两行、授权配在其中一行上。
- 注意：不必做完整的认证域 UI，「登录带 directory + 命中即只问该源」就能同时消掉两个问题。

### 第四梯队：剩余假配置面与链路收尾

**13. 四块假配置面一次收口（α 组）— M**
- 做什么：逐块二选一（接真 / 摘成如实声明），**不许维持现状**：
  - ①**用户策略 · 继承编辑器**（`Policy.vue:279-299` 的 8 项落 `policy_overrides.settings` 后全仓零消费方，`doSave` 成功 toast 却谎称「已下发至「X」的代理网关」，`:178-195` 的「影响预览」平台分布是 `members×0.62/0.16` 编的，冲突检查引用的还是 wave7 已摘除的那个开关）——建议整批摘成如实声明，**只把 FR-POLICY-29/30 两条 P0 接真**（执行位点现成：在线会话表 + 强制下线撤窗断隧道通道）。
  - ②**认证策略 PC/移动主认证下拉**（`Auth.vue:901-909` 七项无 disabled 无能力声明，后端唯一触碰是非空校验；`loginCtx` 里根本**没有 PC/移动端标识**，三端都走同一个 `/portal/login`，端维度不可能生效）——按同抽屉里二次认证多选那道现成的 `capabilities` 门置灰 + 保存拒收 + 迁移清洗。
  - ③**认证策略「默认授权应用」**（`AuthzApps` 自由文本零执行方，策略卡把空值渲染成「不授权」，种子还预置三条误导值）——建议摘除 + 第七节写明「授权唯一真相是资源侧主体清单」。
  - ④**安全基线 type/scope**（`risk.Evaluate` 只看 `Status/Platforms/Checks/Disposal`，type 与 scope 一眼都不看，页面却按策略属性渲染成蓝标签与「适用范围」）——建议 `scope` 接真（复用 `store.SubjectIndex`，与资源授权/认证策略同一处子树展开），`type` 摘除或按 PRD 让两类的处置集合真的不同。
- 为什么值得：违反本项目自定的「界面上任何一个勾都必须真能生效」。危害不止是装饰：管理员把 PC 端主认证改成「证书 / USB-Key」（意图 = 关掉口令登录），保存 200、卡片明晃晃写着证书认证，实际口令登录一次不落地照常成功；一条标着「应用防护」的基线策略若 disposal=block，实际行为是拒发敲门令牌 + 撤窗断隧道，也就是上线准入，标签与行为方向相反。
- 注意：顺带修 `SCOPE.md ch12` 的表述——那一行写「砍管理模块（安全基线管理…）」，但代码里安全基线页带完整 CRUD 且是风险引擎**唯一规则源**，这半章既没被真砍掉、也没被诚实标注为保留。

**14. 应用可改可删 + WEB 全网资源模式卡处置（FR-APP-01/02/03、FR-NET-01/02/03/05）— M**
- 做什么：①补 `PUT /api/v1/apps/{id}` 与 `DELETE`（`resources` 那四件套是现成模板），`Apps.vue` 的「编辑」真的进编辑态、「详情」给 `@click` 或删掉；②「WEB 全网资源」那张模式卡——建议**摘掉**（泛域名代理 + 证书 + 改写是 L 级工程），若保留则当面标注它只是收藏夹条目、不受访问控制。
- 改哪里：`control/internal/api/api.go:375/532`（apps 只有 GET 与 POST，没有 PUT 也没有 DELETE）；`console/src/views/Apps.vue:59/258-265/294-323`（`openWizard` 把字段全清空、走完三步打 POST，于是「编辑」的净效果是**新增一条同名应用**）、`:229` 第三张模式卡、`:148`；`control/internal/api/clientprofile.go:243-250`（`if a.Mode == "global"` 直接 append 一个 `Accessible: true` 的磁贴，**绕过同函数 :265 的 accessibleFor**）。
- 为什么值得：FR-APP-01 是 P0 且要求「新增/编辑/删除」，而 ARCHITECTURE 第七节与 SCOPE ch8 的不做清单里都没说过「应用不可编辑/删除是刻意的」。后果不只是缺功能：发布时填错内网地址或选错资源后无法修正、无法下架，那条磁贴会永久留在门户与客户端剖面里；而这个「编辑」比 wave7 行动 14 修掉的 Users.vue 死按钮**更坏**——死按钮点了没反应，这个点了会静默产生重复应用。全网资源那张卡则是 ch8 里唯一一处完全未表态的能力，却在向导里与两条真链路平级可选，管理员合理推断是「已发布并受控」，实际零访问控制。
- 注意：顺手删掉 `apps.node`（`store/sqlite.go:1586` 在管理员完全没有这个输入项的情况下默认写死「华东出口」，第七节已认定它无消费方）；三处名字要统一（向导「WEB 全网资源」/ 门户「全局加速」/ 种子「知网文献 (全网资源)」）。

**15. 灰度链收尾（γ 组：FR-UPG-19 AC-12 + FR-OPS-08/09）— S**
- 做什么：①`openGray` 回填 `p.groups` + 弹窗加用户组多选（数据源与资源授权/认证策略共用 `SubjectIndex`）；②接上 `upgrade.Coverage` 显示「预计影响 N 人」+ 一条 `GROUP BY platform, client_version` 的实际版本分布；③移动端接上 `GET /client/update`（后端按 platform 分桶**已经支持**）。
- 改哪里：`console/src/views/Upgrade.vue:238-245/256/271`（`groups: []` 写死在请求体里，`openGray` 根本不读 `p.groups`，而 `SaveGrayPlan` 是整条覆盖式保存）、`:108`；`control/internal/upgrade/gray.go:129-134`（`Coverage` 唯一调用方是三条单测，函数注释写着「供控制台显示『预计影响 N 人』」）；`clients/mobile/src/`（grep `client/update|checkClientUpdate|clientVersion` 零命中，`checkClientUpdate` 的调用方只有桌面端两处）。
- 为什么值得：①是静默失效——管理员只把比例从 10% 调到 20%，用户组定向当场消失，灰度对象从「测试组」变成「全体 20% 随机分桶」，接口回 200、页面看不出差别。与 wave7 行动 15 验收抓到的 `PUT /devices/settings` 缺 `personalPolicy` 即降级为 inherit **完全同族**（同一条「PUT 整体覆盖 + 前端漏字段」的模板），那次的落地记里自己点名了这一条却没顺手修。②管理员配完 10% 之后拿不到任何反馈，AC-12 在真机上无法被验证，灰度「先小范围验证再放开」的决策依据整个缺席。
- 注意：`SCOPE.md:11` 现在把①记成了「已知限制」（「该维度当前只能用 API 配且不可在页面上碰」）——**一个会吞配置的页面不属于边界**，修完把那句改掉。

### 第五梯队：默认部署姿态与入口/实现矛盾

**16. 默认安全开局：种子口令 + 限流（NFR-SEC-05、FR-ADMIN-01、FR-SYSCFG-09、FR-INT-16）— S**
- 做什么：①`BAIDI_SEED_MUST_CHANGE` 默认翻成 `1`，演示机在 `config.env` 里显式置 0；`install-remote.sh` 输出里把「本机初始口令未强制修改」列成醒目告警。②`limit_req_zone` + 对 `/api/v1/auth/`、`/api/v1/portal/login` 加 `limit_req`（burst+nodelay），并给 `/downloads/` 加 `limit_conn`；同时把 `ARCHITECTURE.md:978-980` 那句从「应当」改成指向已生效的配置。
- 改哪里：`deploy/deploy.sh:17-18`、`deploy/config.env.example:23-28`、`control/internal/store/sqlite.go:1113`；`deploy/nginx/baidi.conf`（全文 44 行、`grep limit_ deploy/` 零命中；installer 装的就是这一份，`conf.d` include 在 `http{}` 里，`limit_req_zone` 放得进去）。
- 为什么值得：①NFR-SEC-05 是 P0，验收词就是「默认安全开局：首登强制改密、无默认弱口令」，现在默认姿态恰好相反——按参考流程装出来的生产机开局就带着一个写在 README/CLAUDE.md/演示站说明里的公开口令，且系统不催任何人改。项目自己在「收口默认值与逃生舱」一节确立过判据：三个 HS256 逃生舱都被翻成默认 false，理由是「默认值就是绝大多数部署的真实姿态」——这一项恰恰反着来，而演示便利完全可以由演示机显式置 0 承担。②是**文档已经指名道姓地说了执行方在哪，而那个执行方在产品自己的部署产物里不存在**——`lockout.go:365` 的运行期 warn 日志字面写着「建议：在前置 nginx 对 /api/v1/*/login 按源限速（limit_req）」，代码在运行时把运维指向一份产品自己不发的配置。
- 注意（严重度已被对抗验证下修，别写错）：**登录爆破在默认部署下是防住的**——`lockout` 账号 + 源 IP 两维度默认全开，`loginGateLocked` 在锁命中时直接 403 **且不调用 Fail**，实测单源灌 4096 次只插进 5 个账号键。`limit_req` 对唯一还活着的分布式变种（约 820 个不同 /64、每源 5 个请求）也基本无用。真正剩下的无控制面是三块：**免认证大文件下载**（`/downloads/{file}` 走 `http.ServeFile` 直发几十 MB，nginx 侧 `proxy_buffering off` 且无 `limit_conn`）、**已认证 API 零配额**（FR-INT-16 在白帝形态下的唯一真实读法）、以及**管理员手动关掉 IP 维度**（NAT 后办公网的常见运维动作）的部署。文案要按这三块写，不要写成「登录可被随便爆破」。

**17. 两处入口/实现矛盾 + 静默截断（FR-IPSEC-18/19、NFR-PERF-06）— S**
- 做什么：①`validIpsecPeer` 去掉 FQDN 分支并改掉那句误导文案（或保留放行但在 `ipsecConfigWarning` 里补一条「peer 是域名，本版本网关不做 DNS 解析，该站点会被装载期拒绝」）；②`JitGrants` 与 `PostureReports` 两处 `LIMIT 500` 改为带 total 的分页，或至少回一个「已截断」标记并在页面上显示。
- 改哪里：`control/internal/api/ipsec.go:241-255`（FQDN 分支 + 注释「权威解析在网关侧」，与事实相反）、`:227` 的 400 文案（**主动把 FQDN 列为推荐写法**）、`:137-161` `ipsecConfigWarning`；`control/internal/store/jit_sqlite.go:80`、`store/posture_sqlite.go:76`。
- 为什么值得：①`gateway/cmd/baidi-ipsec/sync.go:459-473` `parsePeer` 是**刻意**不解析的（错误文案自陈理由：DNS 抖动会造成谁也解释不清的间歇性故障），`sync_test.go:388` 正把「拒收 FQDN」当正确行为钉住——入口不但放行，还手把手教管理员填一个必然跑不通的值，而管理员点完保存拿到的是 200 OK，要等到「已指派网关 + 网关在线 + 下一轮同步」之后才从 `SiteState.LastError` 看到。②两处 `LIMIT 500` 返回值不带总数、页面也不提示，与本项目反复强调的「截断必须可见」相反。
- 注意：已核实**执行方没被截断**（告警走 `ActiveGrants/StaleGrants`、准入判定走独立的 `PostureUsersByDisposal` DISTINCT 查询），所以这是展示面问题不是判定面问题——别把它写成安全缺陷。

---

## 二、建议边界收口（写文档 / 表态，不写代码）

1. **ch21 21.3 SSO 与 21.5 开放平台：`SCOPE.md:28` 的 ✅ 必须拆开。** 现状是一处可当场验证的自相矛盾——`:28` 宣称交付 SSO，`:15` 却在 ch8 行写「仍不做：SSO 免认证代填」，`ARCHITECTURE.md:507` 写「没有做 SSO 免登」。一个对勾盖住整章，正是 wave7 立志杜绝的「未表态悬置」的**加强版**：它不只是悬着，它主动关掉了后续审计的检测（这正是 21.5 连续七波没被报出来的原因）。要如实说清缺的是三件：机器身份凭据（无服务账号/AK-SK/长效受限令牌，集成方只能存一个人类管理员的口令、每 8h 重登）、限流、任何形式的接口说明。**SDK 那半要分开说**：`gateway/mobile/baidimobile/` 是货真价实的移动端接入 SDK（FR-INT-15 半真），PC 端 SDK 没有。同时 ✅ 行里的「认证源」还顺带盖住了 FR-INT-03 RADIUS（P0，保存即拒的明拒项）。
2. **开放 API 联动 / 第三方风险摄入（FR-INTRO-14 + FR-SEC-3RD-01~03）：建议定性为「记档延后（M）」而非永久边界。** 承接侧全部就绪却没有入口——白帝已有完整的风险处置管道（`risk.Evaluate` → posture 判定 → `PostureUsersByDisposal` → 网关 `DenyUsers` / revoked 撤窗断隧道），一个 EDR/SIEM 想把「这台机已失陷」推进来，今天没有任何合法路径（`POST /posture` 第一行就 `requireUser`，mTLS 那几个口按 CN 前缀分权只给自家进程）。但它不是纯接线活：**需要先造一套第三方调用方的身份**，且本环境没有真第三方设备可对接实测，硬做会重蹈「配置齐全但没人验过」。可接受的最小形态是照 notify webhook 的先例做反向摄入端点（出口能测入口就能测）。**若判定不做，就必须同步改掉 `SCOPE.md:20` ch13 行那句「保留开放 API/标准化第三方联动（见 ch21）」**——那个引用闭环让 FR-INT-12 既不在 ch13 也不在 ch21 的账上。
3. **URL 级发布（FR-WEB-03，P0）：建议记档延后到 wave9。** 资源只有 `host:port` 一个维度，L7 剥掉 `/app/<id>` 前缀后把后端全部路径原样透传，因此「发布一个 Web 应用 = 把该 host:port 的**整个**后端暴露给被授权者」，管理后台 `/admin` 与业务 `/travel` 无法分授。这是能力缺口不是 UI 欺骗，但有实打实的安全语义，且实现位点收敛（资源补路径前缀列 + 逐请求鉴权处加前缀比对 + 向导收路径 + 前缀归一化），与「判定权全在控制面、网关只机械比对」的纪律相容。**ARCHITECTURE 第七节的 webproxy 边界逐条声明了四条却唯独没提路径粒度**——即便本波不做，也要先把这条写进第七节。
4. **`handleSaveResource` 不校验 `backend` 的 host:port 形态：单独立项（S）。** 行动 1 的对抗式复核实测出来的——`POST /api/v1/resources {backend:"10.91.0.1"}` 回 200，控制台 `Resources.vue` 在「选了地址对象、没选服务对象」时也会写出裸地址。落库之后网关必然拨不通，而这条资源在剖面里被丢弃、在门户磁贴上（行动 1 之后）显示成不可用——读侧兜底已经有了，缺的是入口不该收。同族纪律现成：`sensitivity`/`webScheme` 拼错即 400。**改动要注意存量库里可能已有裸地址的行**，校验只能挡新写入，不能让旧行读不出来。另：`app_unlinked` 告警的判据是 `resource_id == ""`，既漏掉悬空引用（资源被删 → 剖面报 warning 而告警不响，而它的注释自称「与客户端剖面 warnings 同一条信号」），又把 `mode=global` 的应用误报成配置缺口（演示库里「知网文献」就永久挂着一条无法处置的待办）——同批一起改，判据统一到一处。
5. **服务端分页（NFR-PERF-06 的 M 半）：延后。** wave7 行动 14 把 CSV 批量导入做出来后，这条从「理论问题」变成「导一次就撞上」，但分页缺失的失败形态是**变慢（可见）**，不属静默失效族，优先级低于本波全部 17 条。顺带记一处放大器：`upgrade.go:276-289` 的 `groupsOf` 为取一个账号的组 id，每次客户端查更新都全量拉起整张用户目录（含 org JOIN 与成员关系）——应改成按 account 直查 `user_group_members`。
6. **ch15 的四小节 + FR-ADMIN-06~09：建议一次性边界收口。** 15.3 终端个性配置、15.4 网络部署（设备形态需求，白帝是软件进程）、15.6 特性中心、15.9 区域与虚拟 IP 池（业务侧看到的源 IP 恒为网关，用户维度溯源在业务侧不可得）、以及管理员的内容分权（管理范围 / 17 级树）——都既没实现也没在 SCOPE 或第七节写明不做。按本项目「完成度的另一半是把不做说清楚」的口径，一次表态即可，不必逐条立项。
7. **Windows / Linux 桌面端真机验证债（不是代码债）。** `clients/BUILD.md:533` 已如实写明「Windows 这条链路至今从未在真实 Windows 上跑过」，包能出、wintun 随包、哈希钉扎、NSIS perMachine、三道守卫都做了，**缺的只是一台真机**。列在这里是为了别让它继续隐形——不建议在 wave8 里当代码行动做，没有真机时任何「修复」都不可证。
8. **复述 wave7 的两条 L 级延后**：外部目录**全量同步**（FR-USER-07/20 完整形态：导入 / 立即与周期同步 / 同步日志 / 属性映射配置面）——**注意本波行动 11 会把「属性映射」那一小块先做掉**；终端日志远程收集（FR-EP-17/18/19，需新造服务端→客户端指令下发通道，桌面端一键诊断落地后价值进一步降低）。

---

## 三、本次扫描的诚实说明

**4 条候选被对抗验证推翻**，逐条记下来，免得下一波再报一遍：

| 候选 | 判定 | 为什么不成立 |
|---|---|---|
| 客户端流量未打「访问进程信息」标签（FR-INTRO-06） | out-of-scope | 「从未表态」这个前提是错的——表态在 `SCOPE.md` ch12，不在提交者查的 ch1 / 第七节。 |
| 防爆破缺 nginx `limit_req` 兜底 | wrong-evidence | 载荷性结论读错代码语义：该攻击的前提是**管理员关掉 IP 维度**，而那既不是默认也不是 deploy 形态。默认双维度全开，实测单源灌 4096 次只插进 5 个账号键。剩余的窄边界（关掉 IP 维度后可稀释账号锁）已写进第七节并由 `TestKnownLimit_` 钉住。**限流仍以另一条形态进了行动 16**，但严重度按上面那张表述写。 |
| 开放平台「一行都没有」 | wrong-evidence | `gateway/mobile/baidimobile/` 是真的移动端 SDK（FR-INT-15 半真）；且「唯一出路是长期存超管口令」被代码推翻（自定义管理员角色 + `scope_json` 确实能被脚本程序化调用）。**该缺口以修正后的形态进了边界建议 1**。 |
| SNAT 排除清单漏 `WebPorts` | low-value | 补上也打不到 L7 流量，且是结构性的而非巧合（SNAT 规则恒带 iifname/oifname）。 |

**这次扫描结构性看不见的那一半**（已由本人当场核实，均已并入上面的行动或边界）：
- 移动端从未接客户端灰度更新 → 行动 15
- `upgrade.Coverage` 无生产消费方 → 行动 15
- OIDC 无状态回验通道 → 行动 11
- nginx 无 `limit_req` → 行动 16（严重度已下修）
- 代码里 **零** TODO/FIXME 标记（`grep` 全仓确认）——这不是好消息也不是坏消息，只说明欠账不在注释里，得靠扫描找

**判据没变**：SCOPE.md 已豁免的不算缺口；每条行动都要能指出 PRD 条目号与代码行；「不做」也是一种完成，但必须写在 SCOPE 或 ARCHITECTURE 第七节里，不能靠一个对勾盖住。
