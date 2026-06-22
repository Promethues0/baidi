# 白帝 · 零信任访问控制系统

> **以身份重塑边界，默认不信任、持续验证、最小授权、动态收缩。**
> 白帝是从「烛龙·统一安全接入平台」中裁剪出的**独立产品**，聚焦零信任**访问控制**主线（ZTNA / SDP），
> 对标深信服 aTrust / Zscaler / Cloudflare ZTNA，定位为 SSL VPN（EasyConnect 一代）的下一代演进。

## 1. 白帝 ≠ 烛龙：范围边界

白帝**有意做减法**——相比烛龙主体，砍掉两类"非接入控制主线"的重模块，换取更聚焦、更易交付的产品形态：

| 模块 | 烛龙 | 白帝 | 说明 |
|---|---|---|---|
| UEM 统一终端数据安全（PRD ch11） | ✅ | ❌ **不做** | 移动/PC 数据安全、沙箱工作空间、外发审批等 DLP 能力整体移出范围 |
| 安全中心 · 管理模块（PRD ch12） | ✅ | ❌ **不做** | 安全基线管理、虚拟网络域、可信应用等**管理页面**移出范围 |
| **SPA 服务隐身** | ✅ | ✅ **保留** | 隐身是 ZTNA「网络隐身」价值主张的底座，作为**安全代理网关内建能力**保留，仅不暴露独立管理模块 |
| 身份 / 认证 / 资源 / 策略 / 网关 / 审计 / 系统 | ✅ | ✅ **保留** | 零信任访问控制完整闭环，全部复用烛龙能力 |

> 边界是**刻意记录**的设计决策，详见 [`docs/SCOPE.md`](docs/SCOPE.md)（22 章 PRD → 白帝逐章取舍）。

## 2. 与烛龙的复用关系

白帝是**独立仓库**（独立 git 历史），但在能力上**最大化复用烛龙**：

| 层 | 复用方式 | 来源 |
|---|---|---|
| **Console 前端** | fork 裁剪 + rebrand（本仓 `console/`，40 页 6 中心 IA） | `zhulong/console` |
| **设计系统** | 继承 Claude 黏土橙暖色系 token（本仓 `design-system/`，视觉与烛龙同源） | `zhulong/design-system` |
| **控制面 / 数据面引擎** | **直接复用**烛龙引擎进程（`zhulong-control` :5273 经 `/ctl` 反代；`zhulong-ssl-gw` 数据面 + SPA 隐身） | `zhulong/gateway/ssl-gw` |

产品壳层（品牌、定位、范围）是白帝自己的；引擎层仍是烛龙——这正是"复用烛龙能力"的落地形态。

## 3. 目录结构

```
baidi/
├── console/         # 白帝控制台（Vue3 + Arco Design Vue）— fork 自烛龙 console
│   └── src/{layout,views,services,styles,components,lib}
├── design-system/   # 设计 token（继承烛龙暖色系）
├── docs/            # SCOPE.md 范围边界；后续补立项/PRD
└── README.md
```

## 4. 本地运行

```bash
cd console
npm install          # 首次（已随仓复制 node_modules 则可跳过）
npm run dev          # → http://localhost:5193
```

- 管理 API 走 vite 反代 `/ctl → http://127.0.0.1:5273`（复用烛龙 `zhulong-control`）。未起后端时各页降级为内置演示数据（mock），UI 完整可点。
- 设计：Hanken Grotesk + Claude 黏土橙暖色系；`:root` / `body` 已铺 Arco brand token，组件随主色。
