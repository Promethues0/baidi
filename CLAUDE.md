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
- **control 与 gateway 必须共用同一 BAIDI_JWT_SECRET**，不一致则 SPA 敲门校验全挂。
- 演示口令：管理台 admin/baidi@123；门户任意用户+baidi@123；ext.*/含「外包」账号触发自适应 MFA，验证码 123456。
- 未起后端时 console 各页降级为内置演示数据，UI 完整可点。

## 坑

- gateway/ 根目录 tracked 了两个 13MB 预编译二进制 baidi-tun(.exe)——是历史提交的产物非源码（源码在 gateway/cmd/baidi-tun/），别当文本处理也别轻易删。
- `design-system/` 是烛龙黏土橙**遗留目录**（fork 残留），白帝不消费它——改主题只动 console/src/styles/tokens.css。
- **烛龙共存契约**：nginx 站点绝不允许 default_server（build.sh/install-remote.sh 有自检，检出即中止）；deploy/wipe-remote.sh + WIPE=1 会铲目标机原有业务，慎开。
- certs/（SM2 双证 pem）未跟踪也未 ignore，git status 常年 ?? ——别顺手 add。
- Go 版本不一致：control 要 go 1.25，gateway 要 go 1.26.3；交叉编译全程 CGO_ENABLED=0。
- curl 不支持国密 TLCP，验证 -gm 隧道用 gateway/cmd/baidi-tlcp-probe。
- 重置数据：删 control/baidi.db 重启即重灌种子。
