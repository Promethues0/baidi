# 下载中心 backlog 硬化轮 · 设计（2026-07-20）

## 背景与目标

客户端下载中心（2026-07-19，`0e23ecb..0795b4f`）整支终审判定 Ready，留下九条非阻塞 backlog（`.superpowers/sdd/progress.md`）。本轮一次性钉死其中八条；「APK apiBase 连自签证书服务器」一条依赖正式证书/域名决策，明确保留。

## 改动清单

### 后端（control）

1. **slog 统一**：`internal/api/downloads.go` 两处 `log.Printf` 改 `log/slog`（与 `main.go`/`httpx` 一致）；同时把「manifest 损坏或为空」的日志拆开措辞——解析失败记 `manifest.json 损坏`（带 err），合法 JSON 但 `clients` 空记 `manifest.json 为空`（不带 err）。
2. **Content-Disposition 加固**：`handleDownloadFile` 写头前对文件名剔除 `"`（`strings.ReplaceAll(name, `"`, "")`）。白名单+字符过滤已把可达性关死，这是关最后一道头畸形面。
3. **穿越测试强化**：`TestDownloadFileTraversal` 每个载荷显式断言 `rec.Code` ∈ {404, 301, 400} 且 body 不含 manifest 内容特征字节（如 `baidi-desktop_0.1.0`），替代仅 `!=200`。

### 前端（console）

4. **PortalBar 抽组件**：新建 `src/components/PortalBar.vue`（logo mark SVG + 标题 + spacer + 右侧插槽），`PortalLogin` 不动（它是双栏品牌区非顶栏），`PortalApps` 与 `PortalDownloads` 两页改用组件；视觉零变化（类名/样式随组件走，两页删除重复 CSS）。
5. **type-check 基线清零**：修掉既有 5 个错误（分布在 `router.ts`/`ComingSoon.vue`/`Policy.vue`，具体错误以现场 `npm run type-check` 输出为准，逐个消除而非 @ts-ignore 压制；确因 Arco 类型缺陷不可修者允许最窄范围的显式类型断言并注释原因）。此后 `vue-tsc --noEmit` 退出码 0 成为可靠门禁。

### Android（clients/mobile/native/android）

6. **minSdk 24→26**：`app/build.gradle.kts` 一行；消除 API 24-25 自适应图标无兜底问题，不再维护 legacy mipmap。

### 管线（deploy / clients）

7. **build-artifacts note 条件化**：android 条目的「调试签名版…」note 仅在 `AND_FILE` 非空时传入（与 macos 分支对齐）；缺 APK 时占位 note 用「构建中，敬请期待」。
8. **downloads 原子切换**：`install-remote.sh` 改为拷到 `$BD_PREFIX/downloads.new` 后 `rm -rf downloads && mv downloads.new downloads`，把不一致窗口从「整个拷贝期」缩到 mv 瞬间。

### 收尾（构建与上线一致性）

- minSdk 变更 → 重建 APK（`JAVA_HOME` 用 Android Studio JBR）→ `clients/build-artifacts.sh` 重出 manifest（sha256 变）→ `deploy.sh`（WIPE=0）→ 公网抽验：manifest sha256 与下载文件一致、下载页正常。dmg 不变不重建。

## 不做

- APK apiBase 正式证书/域名（用户侧决策后另开）。
- PortalLogin 品牌区改造、其它页面重构。

## 验收

- `cd control && go test ./...` 全绿（含强化后的穿越断言）。
- `cd console && npm run type-check && npm run build` **双零错误**（基线清零后）。
- `./gradlew assembleDebug` 出新 APK，badging minSdkVersion=26。
- 云端重部署后公网 curl：manifest 中 APK sha256 与实拉文件一致；`/portal/downloads` 页面可达。
