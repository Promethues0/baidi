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
- 配置全走 `BAIDI_*` 环境变量（BAIDI_ADDR/BAIDI_DB/BAIDI_JWT_SECRET/BAIDI_GW_SPA…）。
- **终端 posture / 风险引擎**：`POST /api/v1/posture` 上报（登录用户，platform 枚举 Windows|macOS|Linux，每账号 ≤20 台设备）→ `internal/risk.Evaluate` 按安全中心基线（`baseline_policies` 表，安全中心页可编辑）评估 → 最新判定 block 则 knock-token 403 + 经 `gateways/policy` revoked 捎带撤窗断隧道；判定权全在控制面，网关零改动。缺报默认放行（observe），`BAIDI_POSTURE_ENFORCE=strict` 缺报/过期（10min）也拒。基线检查 key 与桌面采集器对齐：disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version。
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
- **认证源接入（LDAP/AD + OIDC 已真实现）**：配置落库 `auth_sources`，凭据走 `auth_source_secrets` 独立表加密（AAD 绑源 id，**只写不读**）。登录链路「先本地、后外部」——反过来等于把本地 admin 的认证权外包出去。**账号绑定以 `Subject`（OIDC `sub` / LDAP `entryDN`）为键而非用户名**：按用户名绑的话，AD 里新建一个 admin 就能冒充本地管理员且审计看起来完全正常；撞名加来源后缀、外部账号 `role` 恒 user、`pass_hash` 恒空（否则停用认证源后账号退回成"某个本地口令也能登录"）。**认证源故障不能回「密码错误」**也不计入锁定。LDAP 客户端用 go-ldap（**刻意不自研**：与 IKEv2 相反，LDAP 的价值就是连别人的 AD，自研只增互通风险）；OIDC 用标准库。RADIUS/短信/证书三类未实现，保存时明确拒绝。**均未与真实 AD/IdP 实机互通验证**，边界见 docs/ARCHITECTURE.md 第七节。
- **组织与用户组（目录维度，非授权维度）**：`org_units`（邻接表 + 冗余物化路径 `path`，形如 `/root/dev/`）、`user_groups`（`kind=static` 显式成员 / `kind=role` 按 `users.roles` 派生只读）、`user_group_members`（**按 account 存**，account 是令牌主体，将来接授权才对得上）、`users.org_id`。REST 在 `/api/v1/orgs`、`/api/v1/groups`、`PUT /users/{id}/membership`，全 admin + 落审计；控制台在「业务管理→用户与角色」页内维护，不另开导航。冗余 `path` 的用途是**环检测**（把父设成后代时，该父的 path 必含 `/<自己 id>/`）与子树查询——改父必须级联重写子树 path。删除守卫：有子部门或有成员一律拒删（**不做级联置空**：静默失去归属 = 静默丢策略分组）。种子那 4 个部门由 `backfillOrgUnits` 建成真实行并回填既有用户，**调用点在 seed() 之后**（全新库跑 migrate 时 users 还是空表，放 migrate 里会静默空转），一次性标记落 `settings`（否则管理员删掉的部门会被下次启动复活）。
- **按组织/用户组授权（主体维度已接进判定）**：`resources.allow_groups / allow_orgs` 两列（补列 + 回填 `[]`，见 `backfillResourceSubjects`），组织**含子树**——授权给某组织即涵盖其全部后代组织的用户。**子树展开只有一处实现**：`store.SubjectIndex`（`store/subjects.go` 纯逻辑 + `subjects_sqlite.go` 取数，靠冗余 `path` 一次展平祖先链）。控制面两个判定点都从它取答案且必须同真同假——`handleGatewayPolicy → expandForGateway`（把组织/组展开成账号并进 `AllowUsers` 下发）与 `buildProfile → authorizeRes`（剖面可达性）。**网关侧 `resource.Resource` 与 `registry.Authorize` 一字未改**：数据面不知道组织树，也不做子树推导，判定权全在控制面。展开**每次现算不缓存**——把人移出组织下一轮轮询即失效。**空展开必须下发哨兵 `store.DenyAllSubject`**：成员为零的组织授权若原样下发，网关会因「两维皆空 = 不限」退化成对所有人开放，与控制面判定方向完全相反且两侧都不报错。
- 演示口令：管理台 admin/baidi@123；门户任意用户+baidi@123。
- **二次认证 = WebAuthn/passkey**（`BAIDI_WEBAUTHN_RPID` + `BAIDI_WEBAUTHN_ORIGIN` 驱动，门户与管理台都覆盖）：已注册 passkey 的账号登录强制断言；被认证策略判定需要二次认证、却尚未注册 passkey 的账号拒绝登录并引导录入。**RP ID 必须是可注册域名或 localhost——浏览器规范不允许裸 IP**，故 IP 演示站（101.43.125.131）无法启用，未配置时回落 legacy 演示验证码 123456（仅此路径可达）。passkey 管理页 /portal/security。
- **认证策略真接进登录链路**（`internal/authpolicy` 纯函数判定 + `api/authpolicy.go` 取数）：策略按**用户目录**分组（目录由登录链路当场得知：本地哈希命中=local，外部源命中=该源 kind），适用范围用 `scopeOrgs/scopeGroups` 匹配（复用 `store.SubjectIndex`，与资源授权同一处子树展开）。真接线的规则只有五条——增强 `always`（取代此前写死的「账号名 ext*/含外包」启发式，改为按组织/用户组配置）、`weakPwd`（判据是 `users.pw_strength`，**只能在改密/建号那一刻判**，存量行回填 `unknown` 且不命中）、`offHours`（服务器时间 + 策略里的工作日/时段）；豁免 `trustedDevice`（登录带的设备指纹以本账号上报过 posture 且最新判定 allow；指纹客户端自报、**只降低认证要求绝不放宽授权**）、`trustedNetwork`（`clientIP` 比对策略网段，开启必配 CIDR）。**`geoAnomaly` / `winDomain` 判不了（无 IP 地理库、无域校验），已冻结**：保存接口拒绝开启、控制台按后端下发的 `capabilities` 置灰并说明原因、迁移回填清掉存量 true 值；`oneClick` 从模型与 UI 删除（`one_click` 列冻结）。**求值顺序即安全语义：已注册 passkey 的强制断言排在策略之前——策略只能加强不能削弱**，任何豁免都碰不到它（有测试钉住）。判定材料读不到时 fail-closed 拒登录；决策（含"因 X 豁免"）一律写审计 category=auth。
- 未起后端时 console 各页降级为内置演示数据，UI 完整可点。

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
