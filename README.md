# 白帝 · 零信任访问控制系统

> **以身份重塑边界，默认不信任、持续验证、最小授权、动态收缩。**
> 白帝是基于深信服 aTrust 逆向分析、从「烛龙·统一安全接入平台」**分叉立项的独立产品**，聚焦零信任**访问控制**主线（ZTNA / SDP），
> 对标深信服 aTrust / Zscaler / Cloudflare ZTNA，定位为 SSL VPN（EasyConnect 一代）的下一代演进。

## 1. 白帝 ≠ 烛龙：范围边界

白帝**有意做减法**——相比烛龙主体，砍掉两类"非接入控制主线"的重模块，换取更聚焦、更易交付的产品形态：

| 模块 | 烛龙 | 白帝 | 说明 |
|---|---|---|---|
| UEM 统一终端数据安全（PRD ch11） | ✅ | ❌ **不做** | 移动/PC 数据安全、沙箱工作空间、外发审批等 DLP 能力整体移出范围 |
| 安全中心 · 管理模块（PRD ch12） | ✅ | ❌ **不做** | 安全基线管理、虚拟网络域、可信应用等**管理页面**移出范围 |
| **SPA 服务隐身** | ✅ | ✅ **保留** | 隐身是 ZTNA「网络隐身」价值主张的底座，作为**安全代理网关内建能力**保留，仅不暴露独立管理模块 |
| 身份 / 认证 / 资源 / 策略 / 网关 / 审计 / 系统 | ✅ | ✅ **保留** | 零信任访问控制完整闭环，**白帝自有实现** |

> 边界是**刻意记录**的设计决策，详见 [`docs/SCOPE.md`](docs/SCOPE.md)（22 章 PRD → 白帝逐章取舍）。
> 源 PRD = 飞书《白帝零信任访问控制系统—PRD V1.0》（aTrust v2.5.16 逆向，22 章；本地副本 [`docs/source-prd-zhulong.md`](docs/source-prd-zhulong.md)）。

## 2. 与烛龙的关系：分叉立项，自有全栈

白帝是**独立仓库 + 独立 git 历史**。立项之初曾设想"fork 烛龙 console + 运行时复用 zhulong 引擎"，但已**整体退场**——白帝交互细节与烛龙不同、视觉走 **Arco Design 原生**、前后端与数据面**全部自有实现**：

| 层 | 白帝现状 | 备注 |
|---|---|---|
| **Console 前端** | 自有 `console/`（Vue3 + Arco Design Vue），从 PRD 重做交互（范式 P1–P10） | 视觉 = **Arco 原生 ArcoBlue #165DFF**（非烛龙暖色系） |
| **控制面** | 自有 `control/`（Go · `baidi-control` · :8090 · SQLite · JWT） | 不再依赖 `zhulong-control` |
| **数据面网关** | 自有 `gateway/`（Go · `baidi-gateway`：SPA 敲门 + TLS/国密 TLCP 隧道 + 防火墙 DROP 隐身 + 动态拉策略） | 不再依赖 `zhulong-ssl-gw` |
| **终端客户端** | 自有 `clients/`（桌面 Tauri 壳 + 移动端三端壳 + gomobile 数据面） | — |

烛龙留给白帝的是**需求与设计养分**（aTrust 逆向 PRD、IA 取舍、零信任范式），不是运行时进程。

## 3. 目录结构

```
baidi/
├── console/         # 控制台（Vue3 + Arco，dev :5193）— 管理台 + 态势大屏 + 终端用户门户
│   └── src/{layout,views,lib,styles,nav.ts,router.ts}
├── control/         # 控制面 baidi-control（Go，:8090，SQLite + JWT）
│   ├── cmd/baidi-control/
│   └── internal/{api,store,auth,...}
├── gateway/         # 数据面 baidi-gateway（Go：SPA 敲门 / 隧道 / 防火墙隐身 / utun 引流）
│   ├── cmd/{baidi-gateway,baidi-knock,baidi-tun,...}
│   └── internal/{spa,proxy,gmcert,darkfw,dataplane,...}  +  mobile/  firewall/
├── clients/         # 终端客户端
│   ├── desktop/     #   桌面客户端（Vue + Arco，Tauri-ready，dev :5294）
│   └── mobile/      #   移动端（iOS/安卓/鸿蒙，移动优先 UI + 原生 VPN 壳，dev :5295）
├── deploy/          # systemd + nginx + build/install/wipe 脚本
├── design-system/   # 设计 token
├── docs/            # SCOPE.md 范围边界 · design/ 交互规范 · source-prd 副本
└── README.md
```

## 4. 本地运行

### 控制台 + 控制面

```bash
# 控制面（Go，:8090）
cd control
go run ./cmd/baidi-control          # SQLite 落 baidi.db（已 gitignore）；首启建表 + 播种

# 控制台（Vue，:5193）
cd console
npm install                         # 首次
npm run dev                         # → http://localhost:5193
```

- 管理 API 经 vite 反代 **`/api → http://127.0.0.1:8090`**（自有后端 `baidi-control`）。未起后端时各页降级为内置演示数据（mock），UI 完整可点。
- **登录**：管理台 `admin / baidi@123`（admin 角色）；终端用户门户 `/portal/login` 接受任意用户名 + 口令 `baidi@123`（如 `li.fang`），其中 `ext.*` 或含「外包」的账号（如 `ext.zhou`）触发自适应 MFA，验证码 `123456`。
- **鉴权**：HS256 JWT（`BAIDI_JWT_SECRET`）。写操作强制 admin（否则 403）；非公开读无 token 401。前端 `lib/api` 自动带 Bearer，401 跳登录。
- **视觉**：Hanken Grotesk + Arco 原生 **ArcoBlue #165DFF**（头像紫 #722ED1，侧栏底深色状态卡）。

### 控制台三模式（顶栏切换）

| 模式 | 路由 | 说明 |
|---|---|---|
| **控制台** | `/`（监控中心 / 业务管理 / 安全防护 / 系统 四组侧栏 IA） | 管理主台 |
| **态势大屏** | `/screen` | 全屏暗色 NOC：实时威胁雷达 + 三道防线仪表 + 实时安全事件 + 接入来源 TOP 地域（连真实接口，15s 轮询） |
| **运维诊断** | `/diag` | 运维自检：控制面/数据面/隐身/集群/存储/身份多维一键体检 |

### 数据面网关（可选）

```bash
cd gateway
./demo.sh                           # 暗→敲门(SPA)→隧道→后端→TTL 自动重暗 的最小演示
go run ./cmd/baidi-gateway -gm      # 国密 TLCP 隧道（SM2 双证书 + ECC_SM4_GCM_SM3）
```

数据面默认对外不可达（隐身），收到 `baidi-control` 签发的短时效一次性 SPA 敲门令牌后，为源 IP 开 TTL 放行窗口，窗口内才接受 TLS 隧道；并向 `baidi-control` 注册心跳 + 动态拉取资源策略。详见 [`gateway/README.md`](gateway/README.md)。

## 5. 部署

`deploy/` 提供 systemd（`baidi-control@:8090`）+ nginx（80→443 + SPA 回退 + `/api` 反代透传 Bearer）+ `build.sh`（交叉编译 linux/amd64 静态 ELF + vite dist）+ `install-remote.sh` / `wipe-remote.sh` / `deploy.sh`。`WITH_GATEWAY=1` 一并装启 `baidi-gateway`（国密）。

**线上**：已独占部署到 `https://101.43.125.131/`（控制台 `admin/baidi@123`、门户 `/portal/login`），控制面 + 数据面公网全栈跑通（含国密 TLCP 真实接入实测）。注：当前为自签证书，生产需换正式证书。
