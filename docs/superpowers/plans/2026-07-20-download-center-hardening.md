# 下载中心 backlog 硬化轮 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 一次性钉死下载中心终审留下的八条 backlog（后端三条、前端两条、Android 一条、管线两条），并重建 APK 重部署保持线上一致。

**Architecture:** 全部是既有代码的定点硬化，无新子系统。顺序：先清 console type-check 基线（恢复门禁）→ PortalBar 去重（用干净门禁验证）→ 后端/Android/管线各自独立 → 收尾重建重部署。

**Tech Stack:** Go 1.25（slog/httptest）、Vue3 + vue-tsc、Android Gradle（AGP 8.5.2）、bash。

**Spec:** `docs/superpowers/specs/2026-07-20-download-center-hardening-design.md`

## Global Constraints

- 不改任何对外契约：路由、manifest 字段、文件名、`--bd-*` token、门户视觉全部保持不变。
- console 验证标准从本轮 Task 1 之后起是**双零**：`npm run type-check` 与 `npm run build` 退出码均 0。
- type-check 清零禁止 `@ts-ignore`/`@ts-expect-error` 压制；确因第三方类型缺陷不可修者允许最窄显式断言并注释原因。
- Go 测试跑法 `cd control && go test ./...`；Android 重建须 `export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`（DevEco JBR 缺 jlink 会挂）。
- 不动 `deploy/config.env`；部署必须确认 `WIPE` 未设或 =0。
- 每任务独立提交，commit message 中文动词开头。

---

### Task 1: console type-check 基线清零（5 错误 → 0）

**Files:**
- Modify: `console/src/router.ts:7-30`（BUILT 类型 + leafRoutes 映射）
- Modify: `console/src/views/ComingSoon.vue:24`
- Modify: `console/src/views/Policy.vue:191-196`（Row 接口）

**Interfaces:**
- Consumes: 既有 `NAV`/`NavGroup { label, children }`（src/nav.ts:13-16）。
- Produces: `vue-tsc --noEmit` 退出码 0——后续任务的门禁基线。

- [ ] **Step 1: 复现基线**

Run: `cd ~/Projects/baidi/console && npm run type-check`
Expected: 5 个错误（router.ts:25 / ComingSoon.vue:24 / Policy.vue:83,84,85）。

- [ ] **Step 2: 三处修复**

`router.ts`——错误根因：`BUILT` 值类型 `() => Promise<unknown>` + 对 `RouteRecordRaw['component']`（含 `null|undefined` 的跨联合索引类型）的强转，使映射对象无法匹配联合任何一臂。改为：

```ts
const BUILT: Record<string, RouteRecordRaw['component']> = {
  '/monitor/overview': () => import('@/views/Overview.vue'),
  // …其余条目不变，仅声明类型变化…
};

const leafRoutes: RouteRecordRaw[] = NAV.flatMap((g) =>
  g.children.map((c): RouteRecordRaw => ({
    path: c.path.slice(1),
    component: BUILT[c.path] ?? (() => import('@/views/ComingSoon.vue'))
  }))
);
```

（`??` 同时消掉索引类型里的 `null|undefined`，显式返回注解让 TS 选中 SingleView 臂；原 `as` 强转删除。若仍有残留报错，按同思路调注解，不得用 @ts-ignore。）

`ComingSoon.vue:24`——`NavGroup` 只有 `label` 没有 `title`：

```ts
const groupTitle = computed(() => loc.value.group?.label ?? '');
```

`Policy.vue:191-196`——`Row.value/inherited` 从 `unknown` 收窄（MOCK 数据实际只有三种标量，模板 v-model 直接合法）：

```ts
type Val = string | number | boolean;
interface Row {
  key: string; label: string; desc: string;
  type: 'toggle' | 'number' | 'select';
  source: Src; value: Val; inherited: Val;
  unit?: string; options?: string[]; risk?: boolean;
}
```

（若收窄后 `mk()` 或恢复继承逻辑出现新报错，按 `Val` 顺势收窄其签名，不引入断言。）

- [ ] **Step 3: 验证双零**

Run: `cd ~/Projects/baidi/console && npm run type-check && npm run build`
Expected: 两命令退出码均 0，无任何错误输出。

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/baidi
git add console/src/router.ts console/src/views/ComingSoon.vue console/src/views/Policy.vue
git commit -m "console type-check 基线清零：router 组件映射去宽转换 + NavGroup.label + Policy Row 值类型收窄"
```

---

### Task 2: PortalBar 顶栏组件抽取

**Files:**
- Create: `console/src/components/PortalBar.vue`
- Modify: `console/src/views/PortalApps.vue`（顶栏换组件，删重复 CSS）
- Modify: `console/src/views/PortalDownloads.vue`（同上）

**Interfaces:**
- Consumes: Task 1 后的双零门禁。
- Produces: `PortalBar` 组件，props `{ title: string }`，默认插槽承载右侧按钮/账号区。**PortalLogin 不动**（它是双栏品牌区，无此顶栏）。

- [ ] **Step 1: 写组件**

`console/src/components/PortalBar.vue`：

```vue
<template>
  <header class="bd-pbar">
    <div class="bd-plogo">
      <span class="bd-plogo__mark">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
          <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
          <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </span>
      <span class="bd-plogo__txt">{{ title }}</span>
    </div>
    <div class="bd-pbar__spacer" />
    <slot />
  </header>
</template>

<script setup lang="ts">
defineProps<{ title: string }>();
</script>

<style scoped>
.bd-pbar {
  height: 56px; background: #fff; border-bottom: 1px solid var(--bd-border);
  display: flex; align-items: center; padding: 0 24px; gap: 14px; position: sticky; top: 0; z-index: 10;
}
.bd-plogo { display: inline-flex; align-items: center; gap: 10px; }
.bd-plogo__mark {
  width: 30px; height: 30px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
}
.bd-plogo__txt { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); }
.bd-pbar__spacer { flex: 1; }
</style>
```

- [ ] **Step 2: 两页替换**

两页各自：`import PortalBar from '@/components/PortalBar.vue';`，把 `<header class="bd-pbar">…logo+spacer…</header>` 换成组件，右侧内容进默认插槽；从各自 `<style scoped>` 删除 `.bd-pbar/.bd-plogo*/.bd-pbar__spacer` 规则（**保留** `.bd-pquit/.bd-pacct` 等插槽内容样式——插槽节点编译在父作用域，页内 scoped 样式继续生效）。

`PortalApps.vue` 顶栏变为：

```html
    <PortalBar title="白帝 · 应用门户">
      <button class="bd-pquit" @click="$router.push('/portal/downloads')">
        <icon-download /><span>下载客户端</span>
      </button>
      <div class="bd-pacct">
        <span class="bd-pacct__av">{{ avatarText }}</span>
        <span class="bd-pacct__name">{{ displayName }}</span>
      </div>
      <button class="bd-pquit" @click="logout"><icon-export /><span>退出</span></button>
    </PortalBar>
```

（router 取用方式与该页现状一致，若页内用的是 `router.push` 就沿用。）

`PortalDownloads.vue` 顶栏变为：

```html
    <PortalBar title="白帝 · 客户端下载">
      <button class="bd-pquit" @click="goBack"><icon-left /><span>返回</span></button>
    </PortalBar>
```

- [ ] **Step 3: 验证 + 视觉走查**

Run: `cd ~/Projects/baidi/console && npm run type-check && npm run build`
Expected: 双零。

再起 preview（`baidi-console`）分别打开 `/portal/apps`（登录 li.fang/baidi@123）与 `/portal/downloads`，截图对照：顶栏高度 56px、logo/标题/按钮位置与改前一致（视觉零变化）。

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/baidi
git add console/src/components/PortalBar.vue console/src/views/PortalApps.vue console/src/views/PortalDownloads.vue
git commit -m "门户顶栏抽 PortalBar 组件：Apps/Downloads 两页去重，视觉零变化"
```

---

### Task 3: 后端硬化三条（slog + Content-Disposition + 穿越断言）

**Files:**
- Modify: `control/internal/api/downloads.go:1-15`（import）、`:52-57`（loadManifest 日志拆分）、`:84`（缺盘日志）、`:88`（CD 头）
- Modify: `control/internal/api/downloads_test.go`（穿越断言强化 + CD 剔引号新测试）

**Interfaces:**
- Consumes: 既有 `downloadsFixture(t)`、`getFile(t, h, path)` 测试 helper（downloads_test.go）。
- Produces: 无契约变化（日志与头部字符集是内部行为）。

- [ ] **Step 1: 写失败测试（TDD 覆盖 CD 剔引号）**

追加到 `downloads_test.go`：

```go
// 文件名含引号（只可能来自被污染的 manifest）时，Content-Disposition 中剔除引号防头畸形
func TestDownloadFileQuoteStripped(t *testing.T) {
	h, dir := newDownloadsServer(t)
	weird := `evil"name.apk`
	os.WriteFile(filepath.Join(dir, weird), []byte("X"), 0o644)
	m := `{"clients":[{"platform":"android","label":"a","version":"0.1.0","file":"evil\"name.apk","size":1,"sha256":"x","available":true}]}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644)
	rec := getFile(t, h, "/downloads/evil%22name.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="evilname.apk"` {
		t.Fatalf("Content-Disposition = %q, 引号未剔除", cd)
	}
}
```

同时把 `TestDownloadFileTraversal` 的断言体替换为强化版：

```go
	for _, p := range []string{
		"/downloads/../manifest.json",
		"/downloads/..%2Fmanifest.json",
		"/downloads/%2e%2e%2fmanifest.json",
		"/downloads/..%5Cmanifest.json",
	} {
		rec := getFile(t, h, p)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s code = %d, want 404/301/400", p, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, "baidi-desktop_0.1.0") || strings.Contains(body, "baidi-mobile_0.1.0") || strings.Contains(body, "APKBYTES") {
			t.Fatalf("%s 响应泄露 manifest/文件内容: %q", p, body)
		}
	}
```

（`strings` 若未 import 则补。）

- [ ] **Step 2: 跑测试确认新测试失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ -run 'TestDownloadFile' -v`
Expected: `TestDownloadFileQuoteStripped` FAIL（现头含原样引号）；强化后的 Traversal 应仍 PASS（行为本就正确，只是断言变严）。

- [ ] **Step 3: 实现**

`downloads.go`：

1. import `"log"` → `"log/slog"`（`strings` 已有）。
2. `loadManifest` 解析段拆开：

```go
	var m downloadsManifest
	if err := json.Unmarshal(b, &m); err != nil {
		slog.Warn("downloads: manifest.json 损坏，回占位清单", "err", err)
		return placeholderManifest()
	}
	if len(m.Clients) == 0 {
		slog.Warn("downloads: manifest.json 为空，回占位清单")
		return placeholderManifest()
	}
	return m
```

3. 缺盘日志：`slog.Warn("downloads: manifest 列出但盘上缺失", "file", name)`。
4. CD 头：

```go
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
```

- [ ] **Step 4: 全绿**

Run: `cd ~/Projects/baidi/control && go test ./... && go vet ./...`
Expected: 全绿、vet 净。

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/baidi
git add control/internal/api/downloads.go control/internal/api/downloads_test.go
git commit -m "下载中心后端硬化：slog 统一+损坏/为空日志拆分、Content-Disposition 剔引号、穿越测试断言强化"
```

---

### Task 4: Android minSdk 26 + 重建 APK

**Files:**
- Modify: `clients/mobile/native/android/app/build.gradle.kts:12`
- 产物: `app/build/outputs/apk/debug/app-debug.apk`（重建，不进仓）

**Interfaces:**
- Consumes: Task 5 之前完成（新 APK 是 manifest 重生成的输入）。
- Produces: badging `minSdkVersion:'26'` 的新 APK。

- [ ] **Step 1: 改 minSdk**

`app/build.gradle.kts:12`：`minSdk = 24` → `minSdk = 26`（一行）。

- [ ] **Step 2: 重建**

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
cd ~/Projects/baidi/clients/mobile/native/android && ./gradlew assembleDebug
```
Expected: BUILD SUCCESSFUL（timeout 给足 600000ms）。

- [ ] **Step 3: 校验**

```bash
BT=~/Library/Android/sdk/build-tools/$(ls ~/Library/Android/sdk/build-tools | sort -V | tail -1)
"$BT/aapt" dump badging app/build/outputs/apk/debug/app-debug.apk | grep -E "sdkVersion|^package"
```
Expected: `sdkVersion:'26'`、`package: name='dev.baidi.mobile' versionName='0.1.0'`。

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/baidi
git add clients/mobile/native/android/app/build.gradle.kts
git commit -m "Android 客户端：minSdk 24→26（自适应图标原生覆盖，去除低版本图标兜底缺口）"
```

---

### Task 5: 管线两条 + manifest 重生成

**Files:**
- Modify: `clients/build-artifacts.sh:54-55`（android note 条件化）
- Modify: `deploy/install-remote.sh:26-29`（downloads 原子切换）
- 产物: `deploy/artifacts/downloads/`（重生成，gitignored）

**Interfaces:**
- Consumes: Task 4 的新 APK。
- Produces: 新 manifest.json（APK sha256 已变）；install-remote 原子切换段。

- [ ] **Step 1: note 条件化**

`clients/build-artifacts.sh` python 段 android 条目改为：

```python
    entry("android", "Android 客户端", os.environ["AND_FILE"],
          "armeabi-v7a / arm64-v8a / x86 / x86_64",
          "调试签名版，安装时需允许「未知来源应用」" if os.environ["AND_FILE"] else "构建中，敬请期待"),
```

- [ ] **Step 2: 原子切换**

`deploy/install-remote.sh:26-29` 替换为：

```bash
# 客户端安装包（先落新目录再瞬时切换，重部署期间进行中的下载不中断于拷贝窗口）
if [ -d "$HERE/downloads" ]; then
  rm -rf "$BD_PREFIX/downloads.new"
  mkdir -p "$BD_PREFIX/downloads.new"
  cp -R "$HERE/downloads/." "$BD_PREFIX/downloads.new/"
  chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX/downloads.new"
  rm -rf "$BD_PREFIX/downloads"
  mv "$BD_PREFIX/downloads.new" "$BD_PREFIX/downloads"
fi
```

- [ ] **Step 3: 重生成 + 本地冒烟**

```bash
cd ~/Projects/baidi && ./clients/build-artifacts.sh
python3 -c "import json;m=json.load(open('deploy/artifacts/downloads/manifest.json'));a=[c for c in m['clients'] if c['platform']=='android'][0];print(a['sha256'],a['size'],a['note'])"
shasum -a 256 deploy/artifacts/downloads/baidi-mobile_0.1.0_debug.apk
```
Expected: manifest 的 android sha256 == shasum 实测；note 为调试签名提示（APK 在位）；dmg 条目不变。

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/baidi
git add clients/build-artifacts.sh deploy/install-remote.sh
git commit -m "产物管线硬化：android 占位 note 修正 + 服务器 downloads 目录原子切换"
```

---

### Task 6: 云端重部署 + 公网抽验

**Files:** 无代码改动（部署 + 验收记录）。

**Interfaces:**
- Consumes: 全部前序任务。
- Produces: 线上与仓库一致（新前端 hash、新 APK、新 manifest）。

- [ ] **Step 1: WIPE 红线**

Run: `cd ~/Projects/baidi/deploy && grep -E "SERVER_SSH|WIPE" config.env`
Expected: `WIPE` 未设或 =0；若 =1 改 0。

- [ ] **Step 2: 部署**

Run: `cd ~/Projects/baidi/deploy && ./deploy.sh`
Expected: exit 0；远端 nginx reload 净、baidi-control active。

- [ ] **Step 3: 公网抽验**

```bash
curl -sk https://101.43.125.131/api/v1/portal/downloads | python3 -c "import json,sys;a=[c for c in json.load(sys.stdin)['clients'] if c['platform']=='android'][0];print(a['sha256'])"
curl -sk -o /tmp/hardening-e2e.apk https://101.43.125.131/downloads/baidi-mobile_0.1.0_debug.apk && shasum -a 256 /tmp/hardening-e2e.apk
curl -sk -o /dev/null -w "%{http_code}\n" https://101.43.125.131/portal/downloads
curl -sk -o /dev/null -w "%{http_code}\n" https://101.43.125.131/downloads/evil.bin
```
Expected: 两 sha256 一致（且为新值≠上轮 APK）；页面 200；evil.bin 404。既有功能抽验：`/portal/login` 200。

- [ ] **Step 4: 收尾**

台账记录 + `git push origin main`。

---

## Self-Review 结论

- **Spec 覆盖**：spec 八条 ↔ Task 3（1/2/3 条）、Task 2（4）、Task 1（5）、Task 4（6）、Task 5（7/8）、收尾 ↔ Task 4/5/6 链路；「不做」未混入。
- **顺序依赖**：Task 1 先行恢复双零门禁 → Task 2 用其验证；Task 4 新 APK → Task 5 重生成 manifest → Task 6 部署。
- **类型一致**：`Val`/`Row` 只在 Policy.vue 局部；PortalBar props `{ title: string }` 两页用法一致；后端无签名变化。
