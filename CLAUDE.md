# 白帝 · 零信任访问控制系统（ZTNA/SDP）

独立于烛龙的全栈自研 ZTNA（从烛龙 PRD 分叉做减法，取舍见 docs/SCOPE.md：UEM 整章不做）：SPA 单包授权服务隐身 + 国密 TLCP/TLS 隧道 + utun 真流量接管 + 身份/策略/审计闭环。控制台 15 页脱 mock、数据面真链路实测、桌面 Tauri 客户端带 utun 数据面。在线演示 https://101.43.125.131/（admin/baidi@123）。研究/演示用途，未经安全审计。

## 交流与协作约定

- 全程中文（对话/注释/文档/commit）。独立 git 仓库。
- **主题是 Arco 原生 ArcoBlue #165DFF**，自定义变量一律 `--bd-*` 前缀（console/src/styles/tokens.css），明确不覆盖 Arco --primary——与烛龙黏土橙的做法完全相反，**不要把烛龙配色规范带进来**。

## 常用命令

```bash
cd console && npm run dev            # :5193（或 preview_start baidi-console），/api→127.0.0.1:8090
cd control && go run ./cmd/baidi-control   # :8090，SQLite 首启自动建表+播种
cd gateway && ./demo.sh              # 数据面最小闭环：暗→敲门→隧道→后端→TTL重暗（前置 control 已跑）
cd gateway && ./e2e.sh               # 全链路自检（自带起栈）：登录→剖面→敲门→钉扎→多资源路由→越权拒绝
cd gateway && ./ipsec-e2e.sh         # IPSec 全链路自检（无 root）：真 IKEv2 协商→真 ESP 加密→跨隧道业务流量→反例
cd gateway && go run ./cmd/baidi-ipsec -h  # 站点组网守护进程（IKEv2+ESP，需 CAP_NET_ADMIN）
cd gateway && go run ./cmd/baidi-gateway -gm   # 国密 TLCP 隧道网关
cd clients/desktop && npm run dev    # :5294
cd clients/desktop && ./src-tauri/build-sidecars.sh && npm run tauri:build   # 打包前必先 build sidecar
cd clients/mobile && npm run dev     # :5295
cd deploy && cp config.env.example config.env && ./deploy.sh   # 一键部署
```

## 端口表

| 服务 | 端口 |
|---|---|
| baidi-control 管理 API | 8090（BAIDI_ADDR） |
| console dev / desktop dev / mobile dev | 5193 / 5294 / 5295 |
| baidi-gateway SPA 敲门 / TLS·TLCP 隧道 | 18201/udp / 18443/tcp |
| baidi-ipsec IKE / NAT-T（ESP 走 UDP 封装） | 500/udp / 4500/udp（可 `-ike-port` 改） |
| baidi-knock-agent（dev 敲门代理，/knock 反代目标） | 8091 |
| 部署 nginx HTTPS | 443 独占机；与烛龙共存默认 **9443** |

## 架构地图

- `console/` — 单 SPA：管理台（监控中心/业务管理/安全防护/系统，15 真实页余 ComingSoon）+ 门户 /portal/* + 大屏 /screen + 诊断 /diag；路由生成式：nav.ts 定义 IA → router.ts BUILT 映射
- `console/src/lib/api.ts` — 唯一 HTTP 封装：BASE=/api/v1，token 存 localStorage(baidi_token)
- `control/` — Go 控制面（**stdlib mux + Go 1.22 方法路由，无 gin**；modernc SQLite 免 CGO；自实现 JWT）；store 层 = 领域文件 + 同名 _sqlite.go 成对
- `docs/ARCHITECTURE.md` — **架构与技术方案解析**（含接入时序图、信任模型、五道门、代码地图、真伪清单）。改动数据面/信任链前先读它
- `gateway/` — Go 数据面：9 个二进制（baidi-gateway / baidi-knock sidecar / baidi-knock-agent / baidi-tun utun 数据面(需root) / baidi-gmca SM2 签发 / baidi-tlcp-probe / baidi-e2e 全链路自检 / **baidi-ipsec 站点组网守护进程** / baidi-ipsec-e2e）；`internal/ipsec/` 自研 IKEv2+ESP（ike/ 控制面 · esp/ 数据面 · site/ 编排，依赖单向：ipsec←ike←esp←site）；firewall/ 内核态隐身脚本（pf/nft）
- `gateway/mobile/baidimobile/` — gomobile 绑定（iOS .xcframework / 安卓 .aar）
- `clients/desktop/` — Tauri 2 + Vue3，4 视图，osascript 提权拉起 root baidi-tun，托盘常驻
- `docs/` — SCOPE.md（对烛龙 PRD 逐章取舍）、design/00-ia-and-interaction.md（P1-P10 交互范式）

## 关键约定

- 鉴权：JWT Role ∈ admin|user|gateway；写操作 handler 内 requireAdmin()，数据面拉策略 requireGateway()。
- **管理员分级分权 / 三权分立（真执行方）**：角色落 `admin_roles("key",name,power,builtin,scope_json)`，归属落 `users.admin_role`（补列 + **一次性**回填既有 admin→root，`admin.role.backfill.v1`）。判定点是 `api.requirePerm(w,r,perm)`——读的是 `scope_json` 里的权限键（`system`/`security`/`audit`/`admins`/`*`），**不是 power 也不是页面文案**。审计管理员只读审计（`/api/v1/audit*`）、安全管理员管认证源/策略/资源/用户组织/审批但读不到审计、系统管理员管网关证书/组网/对象库/`/diag`。**角色现算不进令牌**（降权要立刻算数），读不到角色一律 fail-closed 403 且落审计——**读端点同样现算**：`requireAdmin` 与 `requirePerm` 共用 `currentAdminRole`，撤销/禁用后旧令牌立刻读不到目录与在线会话（此前读面停在 8h 令牌快照上）。**改管理员的口令与状态需 `admins` 权**（`api.guardAdminTarget`，判据是目标 `users.role='admin'`）：只查 `security` 的话，安全管理员重置一次超管口令就能登进去拿全权，或把审计/系统管理员禁用掉——防自锁只管「最后一名超管」，管不到另外两权。**防自锁**：最后一名可登录超管不可降权/撤销/禁用（事务内计数，409；已禁用的 root 不计入）；自定义角色拒收 `*` 与 `admins`（否则等于自造一个不叫 root 的超管，防自锁计数绕过去）。`POST /api/v1/users` 已收口成只建普通用户，建管理员唯一入口 `POST /api/v1/admins`。**集群没实现**：System 页与 `/diag checkCluster` 同口径回「未部署」，不再显示三个假节点。
- 配置全走 `BAIDI_*` 环境变量（BAIDI_ADDR/BAIDI_DB/BAIDI_JWT_SECRET/BAIDI_GW_SPA…）。
- **终端 posture / 风险引擎**：`POST /api/v1/posture` 上报（登录用户，platform 枚举 Windows|macOS|Linux，每账号 ≤20 台设备）→ `internal/risk.Evaluate` 按安全中心基线（`baseline_policies` 表，安全中心页可编辑）评估 → 最新判定 block 则 knock-token 403 + 经 `gateways/policy` revoked 捎带撤窗断隧道；判定权全在控制面。缺报默认放行（observe），`BAIDI_POSTURE_ENFORCE=strict` 缺报/过期（10min）也拒。基线检查 key 与桌面采集器对齐：disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version。
- **风险四档都有执行方（PRD 1.5「降权优先于全断」）**：严厉度 `allow < gray < degrade < block`，排序表只在 `store.DisposalRank` 定义一份。**gray** = 访问权不变 + 每轮策略下发记一条 observing 审计（`api.auditGrayObserved`，按 5min 节流，否则 30s 轮询会把审计冲成噪声）；**degrade** = **降权不断连**，只把高敏资源摘掉——判据是 `resources.sensitivity`(low|normal|high，补列 + 两步回填，`finance` 类应用关联的资源抬成 high，第二步带一次性标记防"改了重启就变回去")，网关侧经新增的 `resource.Resource.DenyUsers` 否决、剖面侧经 `accessibleFor` 剔除，**两处同构有测试同时断言**；**block** 行为完全未改。**`DenyUsers` 必须先于一切允许来源判定**——JIT 授予是并进 `AllowUsers` 的，先判允许等于一张审批单就能绕过降权。网关仍不做推导（不知道"高敏"是什么），只执行控制面算好的名单。降权必须让用户知道：剖面 `warnings` 第一条写明原因与影响面，磁贴带 `degraded` 区分"没授权"与"被降权"（两者下一步动作不同）。用户状态页分桶已与四档统一（`block/degrade/gray` + `locked/disabled`，原 `risk-high/risk-low/idle` 已删）。
- **采集三态（`ok` / `unknown`）**：采集器（`clients/desktop/src-tauri/src/posture.rs`，Windows/macOS/Linux 三平台）对**探不到**的项报 `unknown=true` 而非 `ok=false`——Linux 非 root 读不到防火墙、Windows 非管理员读不到 BitLocker 都是常态，塌缩成 false 会把**真实合规的终端误拒**，塌缩成 true 是误放行，两种错法在页面上都看不出来。`risk.Evaluate` 按 `Options.StrictUnknown` 处理：observe（默认）不计分不抬处置、只单列进 `Verdict.Unknowns` 展示，strict 与「缺报即拒」同口径视为不合规。**判 unknown 必须先于判 ok**（unknown 时 ok 恒 false，是给旧控制面的 fail-closed 兜底），三处渲染同此顺序。采集逻辑抽在 `Env` trait 后面，三平台解析在任意主机上都编译+单测——只活在 `#[cfg]` 里的分支在 mac 上连语法都验不到。
- **身份密钥（CA 迁移已收口）**：control 持**两把 Ed25519 私钥**按用途分签——`BAIDI_JWT_KEY` 签会话令牌与 MFA 票据，`BAIDI_JWT_KNOCK_KEY` 只签敲门令牌（首启自动生成 0600，公钥写同名 `.pub`）。**网关只装 knock 公钥**（`-jwt-pubkey`，逗号分隔可多把供轮换）：会话令牌的 kid 在网关侧查不到，**从密码学上就敲不开门**，`spa.checkKnock` 的 use 语义闸退化为纵深而非唯一防线。**公钥用部署期文件分发，刻意不做 JWKS 端点**——在线端点若自身即信任根会构成循环论证。
- **网关机器身份 = mTLS 客户端证书（唯一路径）**：control 内部 CA（标准 X.509/P-256，`BAIDI_PKI_DIR`）签发，`POST /api/v1/pki/gateway-certs` 取证、`…/{fingerprint}/revoke` 吊销（指纹白名单是即刻吊销的执行点）。网关配 `-mtls-cert/-mtls-key/-mtls-ca` 经 `BAIDI_MTLS_ADDR` 独立端口调控制面；**配了 `-control` 却没配证书直接拒绝启动**。`/api/v1/gateways/*` 只挂 mTLS 监听。SM2 国密 CA 继续只管 TLCP 隧道，两套 PKI 互不污染。
- **`gateway/internal/auth` 刻意没有 Sign 函数**：数据面在代码层不具备签发能力（阶段 4 删除）。要加签发就是在给被保护方发钥匙，别加。
- **收口默认值与逃生舱**：`BAIDI_ACCEPT_HS256`、`BAIDI_GW_ACCEPT_HS256`、`BAIDI_GW_PLAINTEXT_COMPAT` **均已默认 false**。三者置 1 是过渡逃生舱（升级瞬间尚有未过期的 8h 会话时临时用），存量过期后必须关回。`BAIDI_JWT_SECRET` 收口后已不承担跨进程职责，仅逃生舱路径用得到。
- **严格敲门（strict knock，默认开）**：网关只接受 control `/knock-token` 签发的短时效一次性令牌（`use=knock` + jti + ≤`-knock-max-ttl`，见 `spa.checkKnock`）。长效会话令牌**不能**再直接敲门——那会绕过强制下线/账号禁用/终端合规三道闸。因此**所有敲门客户端必须能访问 control**（`baidi-knock`/`baidi-tun`/`tlcp-probe` 的 `-control` 已必填，knock-agent 有默认值）。逃生舱 `BAIDI_GW_KNOCK_STRICT=0` 仅限过渡。副作用：control 不可达超过网关 `-ttl`(30s) 时窗口自然关闭（fail-closed，零信任下是正确姿态，不再回退长效令牌硬撑）。
- **客户端接入剖面（终端能连通的前提）**：`GET /api/v1/client/profile`（登录用户）一次下发**网关落点 + 该接管哪些网段 + "host:port→资源id"映射 + 隧道证书指纹**。终端**不推导策略、也不自己猜网段**——只有控制面同时知道网关在哪、业务在哪、当前用户有权访问什么。剖面里同时登记 VIP 与业务真实地址（两种访问姿态收敛到同一 `CONNECT <id>`），VIP 按资源 id 字典序**确定性分配**（不稳定会让用户书签/SSH 配置失效）。**剖面不是授权凭据**，只是路由提示：权威授权闸始终在网关侧 `resource.Authorize`，泄露剖面拿不到任何访问权。可访问性判定必须与 `handleGatewayPolicy` 同构（静态 ACL ∪ 组织/用户组展开 ∪ 有效 JIT 授予），否则会出现「审批批了却连不上」。
- **隧道服务端认证 = 证书指纹钉扎**：网关隧道证书是启动期自签的，没有公共 CA 可依赖。网关算出自己证书的 SHA-256 指纹随 mTLS 注册心跳上报 → control 经剖面转发 → 客户端 `VerifyPeerCertificate` 比对（`dataplane.tlsClientConfig`）。代码里的 `InsecureSkipVerify: true` 关掉的是**链**校验，安全性由钉扎承担——钉扎比链校验**更严**，只认那一张证书。指纹口径两侧必须一致：都对**叶子证书 DER 原文**取 SHA-256。国密 TLCP 走 CA 校验，两条路径信任材料不同，不可混用。
- **分离式 DNS（split-DNS）**：剖面 `dns` 段下发解析器 VIP + 分流域 + `FQDN→VIP`；客户端在 netstack 里跑隧道内解析器（`dataplane/dns.go`），并按域配系统解析器（macOS `/etc/resolver` / Linux `resolvectl` / Windows NRPT）。**不做递归转发**（未知域名 REFUSED，避免泄露内网查询 + 变成开放解析器）；**AAAA 命中名字回 NOERROR+0 而非 NXDOMAIN**（回 NXDOMAIN 会让客户端连 A 都不再查，且只在双栈机器上出现）；**UDP 只服务 DNS**，其余 UDP 回 ICMP 端口不可达而非黑洞（黑洞会让 QUIC 卡到超时才降级）。解析器 VIP 用网段基址 +53 并从资源分配区间**挖除**。系统解析器配置那一段**未实机验证**，退出清理覆盖 defer/信号/异常退出三路。
- **`baidi-tun -route` 支持逗号分隔多网段**：业务地址散落在多个内网段，只接管单一网段就会出现「隧道建起来了、点开应用却直连不走隧道」——这是本项目历史上最迷惑人的失败形态（无报错、UI 显示已接入）。网段清单由剖面下发，不该由用户手填。
- **认证源接入（LDAP/AD + OIDC 已真实现）**：配置落库 `auth_sources`，凭据走 `auth_source_secrets` 独立表加密（AAD 绑源 id，**只写不读**）。登录链路「先本地、后外部」——反过来等于把本地 admin 的认证权外包出去。**账号绑定以 `Subject`（OIDC `sub` / LDAP `entryDN`）为键而非用户名**：按用户名绑的话，AD 里新建一个 admin 就能冒充本地管理员且审计看起来完全正常；撞名加来源后缀、外部账号 `role` 恒 user、`pass_hash` 恒空（否则停用认证源后账号退回成"某个本地口令也能登录"）。外部账号建号时**必须落 `org_id`**（`ensureExternalOrgUnit`，缺失即当场建回外部目录组织）+ 一次性回填 `org.extuser.orgid.v1`：只写 `org_key` 的话 `SubjectIndex` 按 `org_id` JOIN 会把这批人整体排除，组织授权（fail-closed）与策略适用范围（**fail-open**）都覆盖不到他们。**认证源故障不能回「密码错误」**也不计入锁定。LDAP 客户端用 go-ldap（**刻意不自研**：与 IKEv2 相反，LDAP 的价值就是连别人的 AD，自研只增互通风险）；OIDC 用标准库。RADIUS/短信/证书三类未实现，保存时明确拒绝。**均未与真实 AD/IdP 实机互通验证**，边界见 docs/ARCHITECTURE.md 第七节。
- **组织与用户组（目录维度，非授权维度）**：`org_units`（邻接表 + 冗余物化路径 `path`，形如 `/root/dev/`）、`user_groups`（`kind=static` 显式成员 / `kind=role` 按 `users.roles` 派生只读）、`user_group_members`（**按 account 存**，account 是令牌主体，将来接授权才对得上）、`users.org_id`。REST 在 `/api/v1/orgs`、`/api/v1/groups`、`PUT /users/{id}/membership`，全 admin + 落审计；控制台在「业务管理→用户与角色」页内维护，不另开导航。冗余 `path` 的用途是**环检测**（把父设成后代时，该父的 path 必含 `/<自己 id>/`）与子树查询——改父必须级联重写子树 path。删除守卫：有子部门或有成员一律拒删（**不做级联置空**：静默失去归属 = 静默丢策略分组）。种子那 4 个部门由 `backfillOrgUnits` 建成真实行并回填既有用户，**调用点在 seed() 之后**（全新库跑 migrate 时 users 还是空表，放 migrate 里会静默空转），一次性标记落 `settings`（否则管理员删掉的部门会被下次启动复活）。
- **按组织/用户组授权（主体维度已接进判定）**：`resources.allow_groups / allow_orgs` 两列（补列 + 回填 `[]`，见 `backfillResourceSubjects`），组织**含子树**——授权给某组织即涵盖其全部后代组织的用户。**子树展开只有一处实现**：`store.SubjectIndex`（`store/subjects.go` 纯逻辑 + `subjects_sqlite.go` 取数，靠冗余 `path` 一次展平祖先链）。控制面两个判定点都从它取答案且必须同真同假——`handleGatewayPolicy → expandForGateway`（把组织/组展开成账号并进 `AllowUsers` 下发）与 `buildProfile → authorizeRes`（剖面可达性）。**网关侧 `resource.Resource` 与 `registry.Authorize` 一字未改**：数据面不知道组织树，也不做子树推导，判定权全在控制面。展开**每次现算不缓存**——把人移出组织下一轮轮询即失效。**空展开必须下发哨兵 `store.DenyAllSubject`**：成员为零的组织授权若原样下发，网关会因「两维皆空 = 不限」退化成对所有人开放，与控制面判定方向完全相反且两侧都不报错。
- **消息通道（`internal/notify`，PRD ch15.2）**：`smtp`（net/smtp + TLS，STARTTLS/implicit，匿名/PLAIN/LOGIN）与 `webhook`（POST JSON，非 2xx 即失败）是真实现；**`sms` 就是一次 webhook 调用**（载荷 `{mobiles,text}`），白帝不实现任何短信网关协议，UI 与 `smsNote` 都必须照实说，别写成"已支持某某云短信"。**StartTLS 失败绝不降级明文**（与 ldapsrc 同款纪律，对照测试断言服务端一条 AUTH/MAIL 都没收到）；明文传输 + 配置认证在构造期就拒。配置落 `notify_channels`，凭据走 `notify_channel_secrets` 独立表 AES-256-GCM、**AAD 绑 channel id、只写不读**。REST 在 `/api/v1/notify/channels*`，**归 `PermSystem` 一权**（给 security 的话，安全管理员能把告警改投到自己邮箱）。**真实消费方**：爆破锁定（`noteLoginFailure`）与终端判定**转入** block（`handlePostureReport`）各发一条——按"当前是 block"发会随上报频率刷爆邮箱，判据必须与审计那条转换判据同源。派发走 `notify.Dispatcher` **有界异步队列**（满则丢新保旧并计数，计数经 `droppedNotices` 下发）：消费方在主流程上，一台连不上的 SMTP 会变成比爆破更省事的拒绝服务面。发送成败**都落审计**（行为人 `system`，见 `auditBG`——异步动作记到某个管理员头上是最难自证的错记）。**`last_status/last_detail/last_event/last_at` 只由真正发出那一次写入**，`SaveNotifyChannel` 的 upsert 分支刻意不碰这四列，否则通道页会在邮件根本发不出去时长期显示绿色。无重试、无 App Push、webhook URL 不做出网限制（SSRF 面，接受的边界，见 docs/ARCHITECTURE.md 第七节）。
- **审计外送 Syslog/SIEM（`internal/forward`，PRD ch16 + ch21.6）**：`syslog` = RFC 5424 报文 + RFC 6587 帧（octet-counting / LF），**只走 TCP**，可选 TLS；`http` = 通用 JSON 批量出口。**刻意不做 UDP**（审计用 UDP 会静默丢包，两端都看不见），TLS **不给跳过证书校验的开关**（证书对不上填 `serverName`/`caCert`；有反例用例守着）。**外送必须带链的 `seq`/`mac`**——那是 SIEM 侧独立验真的唯一依据，也是本功能区别于"日志复制"的地方；三个出口（`/audit` 列表、CSV 导出、外送）共用**同一个 `store.AuditEntry`**（`forward.Record` 是它的类型别名），加字段改一处三处跟上。**可靠性**：审计落库的同一事务里给每个启用中的出口入队（`audit_forward_queue`），后台 pump 批量投递、**成功才出队**、失败整批留队退避（5s→15min 封顶，`forward.Backoff`）；入队失败只 `slog.Error` 不回滚（少一条外送远好过少一条审计）。**选独立队列表而不是在 `audit_log` 加 `forwarded` 列**：加列要配一次性回填把既有行标成已处理，漏了就会在开启外送那一刻把 180 天历史整段重发；队列表让"不重发历史"结构性成立。队列**有上界**（`BAIDI_AUDIT_FORWARD_QUEUE_MAX`，默认 20000/出口，无上界=把库写满进而让审计本身落不了库），溢出**丢新保旧**（留连续的最早一段，SIEM 侧 seq 仍连续）+ 丢弃计数落库 + 控制台红条 + 节流转一条 security 审计。配置落 `audit_forward_targets`，凭据走 `audit_forward_secrets`（AAD 绑 target id、只写不读；**syslog 出口没有凭据可设，设了直接 400**）。REST 在 `/api/v1/audit/forward*`，**归 `PermSystem`**（`PermAudit` 按设计只读，不持写端点）。投递循环 `StartAuditForwardLoop`（`BAIDI_AUDIT_FORWARD_INTERVAL`，默认 5s）是唯一执行方。**未与商用 SIEM 实机对接验证**，边界见 docs/ARCHITECTURE.md 第七节。
- 演示口令：管理台 admin/baidi@123；门户任意用户+baidi@123。
- **二次认证 = WebAuthn/passkey**（`BAIDI_WEBAUTHN_RPID` + `BAIDI_WEBAUTHN_ORIGIN` 驱动，门户与管理台都覆盖）：已注册 passkey 的账号登录强制断言；被认证策略判定需要二次认证、却尚未注册 passkey 的账号拒绝登录并引导录入。**RP ID 必须是可注册域名或 localhost——浏览器规范不允许裸 IP**，故 IP 演示站（101.43.125.131）无法启用，未配置时回落 legacy 演示验证码 123456（仅此路径可达）。passkey 管理页 /portal/security。
- **认证策略真接进登录链路**（`internal/authpolicy` 纯函数判定 + `api/authpolicy.go` 取数）：策略按**用户目录**分组（目录由登录链路当场得知：本地哈希命中=local，外部源命中=该源 kind），适用范围用 `scopeOrgs/scopeGroups` 匹配（复用 `store.SubjectIndex`，与资源授权同一处子树展开）。真接线的规则只有五条——增强 `always`（取代此前写死的「账号名 ext*/含外包」启发式，改为按组织/用户组配置）、`weakPwd`（判据是 `users.pw_strength`，**只能在改密/建号那一刻判**，存量行回填 `unknown` 且不命中）、`offHours`（服务器时间 + 策略里的工作日/时段）；豁免 `trustedDevice`（登录带的设备指纹以本账号上报过 posture 且最新判定 allow；指纹客户端自报、**只降低认证要求绝不放宽授权**）、`trustedNetwork`（`clientIP` 比对策略网段，开启必配 CIDR）。**`geoAnomaly` / `winDomain` 判不了（无 IP 地理库、无域校验），已冻结**：保存接口拒绝开启、控制台按后端下发的 `capabilities` 置灰并说明原因、迁移回填清掉存量 true 值；`oneClick` 从模型与 UI 删除（`one_click` 列冻结）。**求值顺序即安全语义：已注册 passkey 的强制断言排在策略之前——策略只能加强不能削弱**，任何豁免都碰不到它（有测试钉住）。判定材料读不到时 fail-closed 拒登录；决策（含"因 X 豁免"）一律写审计 category=auth。**目录候选由后端下发**（`GET /authpolicy` 的 `directories` = 本地 ∪ 已配置认证源的 kind ∪ 存量策略已用的目录）：登录链路把 `Directory` 置成真实源的 kind，前端写死一份的话 LDAP/OIDC 源永远绑不出一条能命中的策略（Match 按目录先筛一刀，静默）。保存时校验 `directory` 与 `scopeOrgs/scopeGroups` 引用存在（与资源授权共用 `validateSubjectRefs`）；**被策略引用的组织/用户组拒删 409**——删掉即静默停掉一条二次认证策略（fail-open 方向；资源授权的引用是 fail-closed，刻意不拦）。
- **网关设备状态（FR-MON-01/02）**：采集器 `gateway/internal/sysstat`（**纯标准库**：Linux 读 /proc、darwin 走 sysctl+路由套接字；解析函数无 build tag，好让 Linux 的 /proc 格式在 mac 上也能编译+单测）→ 随 mTLS 心跳的 `metrics` 字段上报 → `gateway_metrics` 表 → 监控中心「设备状态」页。**采不到的指标一律「不可判定」（报文缺席 / 落库 NULL / 页面「—」），绝不补 0**——补 0 会让「CPU 0%」伪装成一台空闲机器，并让「CPU>80%」告警对一台失明的网关永久沉默（与 posture 的 unknown 同一条纪律；macOS 上 CPU 恒不可判定，取时间片要 cgo）。**双向兼容有测试**：旧网关不带 metrics → 不落点、单列成「在线但未上报指标」；新网关带 `{}` → 落一条全 NULL 的点，两者可区分。**留存上限 `BAIDI_METRICS_RETENTION_HOURS`（默认 72，没有"关闭清理"这一档）**——它是全系统唯一的高频写入口（每网关 15s 一条），主键 `(gateway_id, ts)` + `INSERT OR REPLACE` 顺带把写入速率钉在每网关每秒一行。趋势按 `range=hour|day|week` **在 SQL 里降采样**（桶宽 60/900/3600s），**空桶不返回**（掉线段断线而非零线），**当前值取最新一条原始采样而不是桶均值**。列名是 `gateway_id` 不是 `gw_id`：与 `ipsec_sa_state` 同名，也是告警 `gateway_load` 规则里 `GatewayMetricsProbe` 读的那个名字，对不上它就永远不触发。
- **业务告警（真实体，非流水）**：`alert_rules` + `alerts` 两表，状态机 `pending|ignored|handled`，控制台「监控中心 → 业务告警」。**八类触发源全部读真实存在的信号**（网关心跳超时 / `gateway_metrics` 水位 / JIT 授予将到期 / JIT 授予过期未回收 / 应用未关联资源 / 爆破锁定 / posture 判 block / **审计链周期自检**），出处逐条写在 `store.alertKindSpecs.Signal` 并原样展示在页面上——**不许为不存在的信号建规则**。判定是纯函数 `alerting.Evaluate`（吃信号快照吐候选：条件写反在集成环境里与"一切正常"无法区分，只有纯函数测得住），取数在 `api.alertSnapshot`，落库去重在 `store.RaiseAlert`。**冷却按 (规则, 对象) 且只看时间不看状态**：少了对象键，三台网关同时离线只剩一条；按状态放宽则一点「已处理」就立刻再冒一条。数据源未就绪（如 `gateway_metrics` 无数据）**如实回「等待数据面上报」+ 原因**，不做永不触发的死规则。通知复用消息通道（规则 `channels` 留空=全部启用通道，点名不存在的通道保存即拒；发失败 / 通道停用 / 通道已删三种情况都落审计）。读=任意管理员（角色现算），写=`PermSecurity`。侧栏角标同批接成真实计数（此前写死 '10'/'2'），取不到就不显示，在线用户角标只在 `source=live` 时给数字。
- 未起后端时 console 各页降级为内置演示数据，UI 完整可点（**「设备状态」与「业务告警」两页刻意例外**：连不上就说连不上，不画假曲线、不编假告警——编造的曲线/待办与真实采集在那两页上无法区分，而它们的存在意义正是"有没有异常"）。

## 坑

- gateway/ 根目录 tracked 了两个 13MB 预编译二进制 baidi-tun(.exe)——是历史提交的产物非源码（源码在 gateway/cmd/baidi-tun/），别当文本处理也别轻易删。
- `design-system/` 是烛龙黏土橙**遗留目录**（fork 残留），白帝不消费它——改主题只动 console/src/styles/tokens.css。
- **烛龙共存契约**：nginx 站点绝不允许 default_server（build.sh/install-remote.sh 有自检，检出即中止）；deploy/wipe-remote.sh + WIPE=1 会铲目标机原有业务，慎开。
- certs/（SM2 双证 pem，含私钥）已进 .gitignore——是本地 gmca 产物，任何情况下不入库。
- Go 版本不一致：control 要 go 1.25，gateway 要 go 1.26.3；交叉编译全程 CGO_ENABLED=0。
- curl 不支持国密 TLCP，验证 -gm 隧道用 gateway/cmd/baidi-tlcp-probe。
- 重置数据：删 control/baidi.db 重启即重灌种子。
- **补列迁移必须配回填**：`addColumnIfMissing` 只加列不填值，既有库的新列永久为 NULL。`apps.resource_id` 就这么静默断过——应用↔资源桥接为空 → JIT 解析不出资源、客户端剖面排不出路由，两处都**无报错**。加业务语义列时同步写回填（见 `backfillAppResourceID`）。
- **IPSec 已真实实现，但边界很硬**：纯 Go IKEv2+ESP（`gateway/internal/ipsec/`，独立进程 `baidi-ipsec`）。**只支持 PSK 认证、ESP 只走 UDP-4500 封装、未与 strongSwan 实机互通验证过**；`suite=gm` 用 IANA 私有码点，只白帝↔白帝，**不是国密 IPSec，别这么说**。toggle 改的是 `enabled`（管理意图），`state` 由网关实测回报——`ipsec_sites` 的 `status/rx_bytes/tx_bytes/last_up` 四列已废弃，读运行态一律走 `ipsec_sa_state`。站点 `gatewayId` **必须以 `ipsec-` 开头**（它就是组网网关 mTLS 证书的 CN，控制面按 CN 精确过滤下发；前缀不对时网关拉到空列表而非错误，站点安静地永远 down）。其余真伪边界见 docs/ARCHITECTURE.md 第七节。
- **IKE_AUTH 之外的交换必须先过已认证闸**（`ike.onRequest`）：SK_e/SK_a 只由 DH + nonce + SPI 派生，PSK 只进 AUTH 载荷——任何能完成一次 IKE_SA_INIT 的对端都持有可用的 SK 密钥。少了这道闸，不知道 PSK 的对端跳过 IKE_AUTH 直发 CREATE_CHILD_SA 就能装进一条真通的 ESP 隧道，而 `States()` 因 `primary()` 要求 SAEstablished 仍不显示 up（数据面已通、控制台无痕）。判据必须用 `State.authenticated()` 而非 `Keys != nil`——**密钥就绪不等于身份已验**。
- **展示值必须来自「数据面真正在用的那份」**：桌面客户端接入信息取 `tunnel.ts` 的 `startedOpts` 快照而非当前剖面。全局剖面随时会被刷新（切「应用」页即重拉），而 baidi-tun 的参数在拉起那一刻定死——现算当前剖面会把**未钉扎的运行中隧道显示成已钉扎**。同理 `profile.error` 与剖面 `warnings` 必须在「接入」页渲染：剖面拉不到会退回本机默认配置（单网段、无 resmap、无 pin）却仍显示「已接入」。
