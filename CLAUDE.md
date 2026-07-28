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
| baidi-knock-agent（dev 敲门代理，/knock 反代目标） | 8091 |
| 部署 nginx HTTPS | 443 独占机；与烛龙共存默认 **9443** |

## 架构地图

- `console/` — 单 SPA：管理台（监控中心/业务管理/安全防护/系统，15 真实页余 ComingSoon）+ 门户 /portal/* + 大屏 /screen + 诊断 /diag；路由生成式：nav.ts 定义 IA → router.ts BUILT 映射
- `console/src/lib/api.ts` — 唯一 HTTP 封装：BASE=/api/v1，token 存 localStorage(baidi_token)
- `control/` — Go 控制面（**stdlib mux + Go 1.22 方法路由，无 gin**；modernc SQLite 免 CGO；自实现 JWT）；store 层 = 领域文件 + 同名 _sqlite.go 成对
- `gateway/` — Go 数据面：6 个二进制（baidi-gateway / baidi-knock sidecar / baidi-knock-agent / baidi-tun utun 数据面(需root) / baidi-gmca SM2 签发 / baidi-tlcp-probe）；firewall/ 内核态隐身脚本（pf/nft）
- `gateway/mobile/baidimobile/` — gomobile 绑定（iOS .xcframework / 安卓 .aar）
- `clients/desktop/` — Tauri 2 + Vue3，4 视图，osascript 提权拉起 root baidi-tun，托盘常驻
- `docs/` — SCOPE.md（对烛龙 PRD 逐章取舍）、design/00-ia-and-interaction.md（P1-P10 交互范式）

## 关键约定

- 鉴权：JWT Role ∈ admin|user|gateway；写操作 handler 内 requireAdmin()，数据面拉策略 requireGateway()。
- 配置全走 `BAIDI_*` 环境变量（BAIDI_ADDR/BAIDI_DB/BAIDI_JWT_SECRET/BAIDI_GW_SPA…）。
- **终端 posture / 风险引擎**：`POST /api/v1/posture` 上报（登录用户，platform 枚举 Windows|macOS|Linux，每账号 ≤20 台设备）→ `internal/risk.Evaluate` 按安全中心基线（`baseline_policies` 表，安全中心页可编辑）评估 → 最新判定 block 则 knock-token 403 + 经 `gateways/policy` revoked 捎带撤窗断隧道；判定权全在控制面，网关零改动。缺报默认放行（observe），`BAIDI_POSTURE_ENFORCE=strict` 缺报/过期（10min）也拒。基线检查 key 与桌面采集器对齐：disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version。
- **身份密钥（CA 迁移已收口）**：control 持**两把 Ed25519 私钥**按用途分签——`BAIDI_JWT_KEY` 签会话令牌与 MFA 票据，`BAIDI_JWT_KNOCK_KEY` 只签敲门令牌（首启自动生成 0600，公钥写同名 `.pub`）。**网关只装 knock 公钥**（`-jwt-pubkey`，逗号分隔可多把供轮换）：会话令牌的 kid 在网关侧查不到，**从密码学上就敲不开门**，`spa.checkKnock` 的 use 语义闸退化为纵深而非唯一防线。**公钥用部署期文件分发，刻意不做 JWKS 端点**——在线端点若自身即信任根会构成循环论证。
- **网关机器身份 = mTLS 客户端证书（唯一路径）**：control 内部 CA（标准 X.509/P-256，`BAIDI_PKI_DIR`）签发，`POST /api/v1/pki/gateway-certs` 取证、`…/{fingerprint}/revoke` 吊销（指纹白名单是即刻吊销的执行点）。网关配 `-mtls-cert/-mtls-key/-mtls-ca` 经 `BAIDI_MTLS_ADDR` 独立端口调控制面；**配了 `-control` 却没配证书直接拒绝启动**。`/api/v1/gateways/*` 只挂 mTLS 监听。SM2 国密 CA 继续只管 TLCP 隧道，两套 PKI 互不污染。
- **`gateway/internal/auth` 刻意没有 Sign 函数**：数据面在代码层不具备签发能力（阶段 4 删除）。要加签发就是在给被保护方发钥匙，别加。
- **收口默认值与逃生舱**：`BAIDI_ACCEPT_HS256`、`BAIDI_GW_ACCEPT_HS256`、`BAIDI_GW_PLAINTEXT_COMPAT` **均已默认 false**。三者置 1 是过渡逃生舱（升级瞬间尚有未过期的 8h 会话时临时用），存量过期后必须关回。`BAIDI_JWT_SECRET` 收口后已不承担跨进程职责，仅逃生舱路径用得到。
- **严格敲门（strict knock，默认开）**：网关只接受 control `/knock-token` 签发的短时效一次性令牌（`use=knock` + jti + ≤`-knock-max-ttl`，见 `spa.checkKnock`）。长效会话令牌**不能**再直接敲门——那会绕过强制下线/账号禁用/终端合规三道闸。因此**所有敲门客户端必须能访问 control**（`baidi-knock`/`baidi-tun`/`tlcp-probe` 的 `-control` 已必填，knock-agent 有默认值）。逃生舱 `BAIDI_GW_KNOCK_STRICT=0` 仅限过渡。副作用：control 不可达超过网关 `-ttl`(30s) 时窗口自然关闭（fail-closed，零信任下是正确姿态，不再回退长效令牌硬撑）。
- 演示口令：管理台 admin/baidi@123；门户任意用户+baidi@123。
- **二次认证 = WebAuthn/passkey**（`BAIDI_WEBAUTHN_RPID` + `BAIDI_WEBAUTHN_ORIGIN` 驱动，门户与管理台都覆盖）：已注册 passkey 的账号登录强制断言；风险账号（ext.*/含「外包」）未注册则拒绝登录并引导录入。**RP ID 必须是可注册域名或 localhost——浏览器规范不允许裸 IP**，故 IP 演示站（101.43.125.131）无法启用，未配置时回落 legacy 演示验证码 123456（仅此路径可达）。passkey 管理页 /portal/security。
- 未起后端时 console 各页降级为内置演示数据，UI 完整可点。

## 坑

- gateway/ 根目录 tracked 了两个 13MB 预编译二进制 baidi-tun(.exe)——是历史提交的产物非源码（源码在 gateway/cmd/baidi-tun/），别当文本处理也别轻易删。
- `design-system/` 是烛龙黏土橙**遗留目录**（fork 残留），白帝不消费它——改主题只动 console/src/styles/tokens.css。
- **烛龙共存契约**：nginx 站点绝不允许 default_server（build.sh/install-remote.sh 有自检，检出即中止）；deploy/wipe-remote.sh + WIPE=1 会铲目标机原有业务，慎开。
- certs/（SM2 双证 pem，含私钥）已进 .gitignore——是本地 gmca 产物，任何情况下不入库。
- Go 版本不一致：control 要 go 1.25，gateway 要 go 1.26.3；交叉编译全程 CGO_ENABLED=0。
- curl 不支持国密 TLCP，验证 -gm 隧道用 gateway/cmd/baidi-tlcp-probe。
- 重置数据：删 control/baidi.db 重启即重灌种子。
