# 白帝客户端下载中心 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 门户提供「客户端下载中心」（macOS dmg + Android APK 真实可下，其余平台占位），产物经 deploy 管线上云 101.43.125.131 公网分发。

**Architecture:** baidi-control 新增两个公开路由（manifest JSON + 白名单静态分发，白名单即防穿越）；console 新增 `/portal/downloads` 公开页（平台识别 + Android 二维码）；本机构建 macOS dmg（尽量 universal）与 Android debug APK（新建完整 Gradle 壳工程）；`clients/build-artifacts.sh` 汇集产物并生成 manifest，deploy 管线 rsync 到服务器 `/opt/baidi/downloads/`。

**Tech Stack:** Go 1.25 标准库 ServeMux（`baidi.dev/control`）、Vue3 + Arco Design Vue + `qrcode` npm 包、Tauri 2、Android Gradle + gomobile aar、bash + python3 产物脚本。

**Spec:** `docs/superpowers/specs/2026-07-19-client-download-center-design.md`

## Global Constraints

- 客户端版本统一 `0.1.0`（与 `clients/desktop/src-tauri/tauri.conf.json` 对齐）。
- 分发文件名 ASCII 化：`baidi-desktop_0.1.0_universal.dmg`（或 `_aarch64`）、`baidi-mobile_0.1.0_debug.apk`。
- 路由固定：`GET /api/v1/portal/downloads`（manifest）、`GET /downloads/{file}`（分发），两者均免认证（加入 `IsOpen`）。
- 新环境变量：`BAIDI_DOWNLOADS`（下载目录，默认 `downloads`，服务器 `/opt/baidi/downloads`）。
- manifest 六平台 key 固定：`macos` / `windows` / `linux` / `ios` / `android` / `harmony`。
- 前端遵循既有约定：类名 `bd-` 前缀 BEM、配色 `--bd-*` token（ArcoBlue `#165DFF`）、Arco 图标 kebab-case 免 import、请求走 `@/lib/api` 的 `api<T>()`（base `/api/v1`）。
- 后端遵循既有约定：handler 收在 `internal/api/`，测试用 `newTestServer` 模式（httptest + 真 SQLite 临时库 + 真 auth 中间件）。
- Go 测试跑法：`cd control && go test ./...`；前端验证：`cd console && npm run build && npm run type-check`。
- 每任务独立提交；commit message 中文、动词开头，与仓库风格一致（如「客户端下载中心：…」）。

---

### Task 1: 后端 manifest 类型 + 加载 + `GET /api/v1/portal/downloads`

**Files:**
- Create: `control/internal/api/downloads.go`
- Create: `control/internal/api/downloads_test.go`
- Modify: `control/internal/config/config.go`（加 `DownloadsDir`）
- Modify: `control/internal/api/api.go`（`Server` 加字段、`New` 加参、`Routes` 注册、`IsOpen` 豁免）
- Modify: `control/cmd/baidi-control/main.go`（传 `cfg.DownloadsDir`）
- Modify: `control/internal/api/linkage_test.go`（`newTestServer` 适配新签名）

**Interfaces:**
- Consumes: 既有 `httpx.JSON`、`store.OpenSQLite`、`auth.Middleware`、`testSecret`（linkage_test.go）。
- Produces（后续任务依赖）：
  - `type ClientDownload struct { Platform, Label, Version, File string; Size int64; SHA256 string; Available bool; Arch, Note string }`（JSON tag 小写，见下）
  - `type downloadsManifest struct { Clients []ClientDownload }`
  - `func (s *Server) loadManifest() downloadsManifest`（Task 2 复用做白名单）
  - `Server.downloadsDir string` 字段；`New(..., downloadsDir string)` 第 5 参
  - 测试 helper `newDownloadsServer(t) (http.Handler, string)`（返回 handler 与下载目录路径，Task 2 复用）

- [ ] **Step 1: 写失败测试**

`control/internal/api/downloads_test.go`：

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// newDownloadsServer 建测试 server 并返回可写的下载目录（manifest/安装包放这里）。
func newDownloadsServer(t *testing.T) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testSecret, "test", dir)
	return auth.Middleware(testSecret, s.IsOpen)(s.Routes()), dir
}

func getManifest(t *testing.T, h http.Handler) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/portal/downloads", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("解析响应: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

// manifest 缺失 → 200 + 六平台全占位（available 全 false），不 500
func TestDownloadsManifestMissing(t *testing.T) {
	h, _ := newDownloadsServer(t)
	code, body := getManifest(t, h)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	clients := body["clients"].([]any)
	if len(clients) != 6 {
		t.Fatalf("占位清单应含 6 平台, got %d", len(clients))
	}
	for _, c := range clients {
		if c.(map[string]any)["available"].(bool) {
			t.Fatalf("manifest 缺失时不应有 available=true 条目: %v", c)
		}
	}
}

// manifest 损坏（非法 JSON）→ 同样回占位，不 500
func TestDownloadsManifestCorrupt(t *testing.T) {
	h, dir := newDownloadsServer(t)
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{not json"), 0o644)
	code, body := getManifest(t, h)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if n := len(body["clients"].([]any)); n != 6 {
		t.Fatalf("损坏 manifest 应回 6 平台占位, got %d", n)
	}
}

// manifest 正常 → 原样返回；且免认证（无 Authorization 头）
func TestDownloadsManifestOK(t *testing.T) {
	h, dir := newDownloadsServer(t)
	m := `{"clients":[{"platform":"macos","label":"macOS 桌面客户端","version":"0.1.0","file":"baidi-desktop_0.1.0_universal.dmg","size":123,"sha256":"ab","available":true}]}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644)
	code, body := getManifest(t, h)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	clients := body["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("应原样返回 1 条, got %d", len(clients))
	}
	c := clients[0].(map[string]any)
	if c["file"] != "baidi-desktop_0.1.0_universal.dmg" || c["available"] != true {
		t.Fatalf("条目内容不符: %v", c)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ -run TestDownloadsManifest -v`
Expected: 编译失败（`New` 参数不符 / `newDownloadsServer` 依赖的第 5 参不存在）。

- [ ] **Step 3: 最小实现**

`control/internal/config/config.go` 的 `Load()` 增加一行（与 `DBPath` 相邻）：

```go
DownloadsDir: env("BAIDI_DOWNLOADS", "downloads"), // 客户端安装包目录（manifest.json + 安装包）
```

并在 `Config` struct 加字段 `DownloadsDir string`。

`control/internal/api/api.go`：
1. `Server` struct 加字段 `downloadsDir string`。
2. `New(...)` 尾部加第 5 参 `downloadsDir string`，赋给 `s.downloadsDir`。
3. `Routes()` 的门户段（`POST /api/v1/portal/login` 附近）加：

```go
mux.HandleFunc("GET /api/v1/portal/downloads", s.handleDownloadsManifest)
```

4. `IsOpen` 的 switch 加 case：

```go
case "/healthz", "/api/v1/auth/login", "/api/v1/portal/login", "/api/v1/portal/downloads":
	return true
```

`control/cmd/baidi-control/main.go`：`api.New(st, st, secret, cfg.Env)` → `api.New(st, st, secret, cfg.Env, cfg.DownloadsDir)`。

`control/internal/api/linkage_test.go` 的 `newTestServer`：`New(st, st, testSecret, "test")` → `New(st, st, testSecret, "test", t.TempDir())`。

`control/internal/api/downloads.go`（新文件）：

```go
// 客户端下载中心：manifest 清单 + 安装包白名单分发。
// manifest.json 是服务器数据文件（deploy 时随安装包 rsync），不进代码仓；
// 缺失/损坏时回六平台全占位，页面仍可渲染。
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"baidi.dev/control/internal/httpx"
)

// ClientDownload 客户端下载清单条目（manifest.json 与 API 同构）。
type ClientDownload struct {
	Platform  string `json:"platform"`
	Label     string `json:"label"`
	Version   string `json:"version,omitempty"`
	File      string `json:"file,omitempty"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Available bool   `json:"available"`
	Arch      string `json:"arch,omitempty"`
	Note      string `json:"note,omitempty"`
}

type downloadsManifest struct {
	Clients []ClientDownload `json:"clients"`
}

// placeholderManifest 六平台全占位：manifest 缺失/损坏时的兜底。
func placeholderManifest() downloadsManifest {
	return downloadsManifest{Clients: []ClientDownload{
		{Platform: "macos", Label: "macOS 桌面客户端", Note: "构建中，敬请期待"},
		{Platform: "windows", Label: "Windows 桌面客户端", Note: "构建中，敬请期待"},
		{Platform: "linux", Label: "Linux 桌面客户端", Note: "构建中，敬请期待"},
		{Platform: "ios", Label: "iOS 客户端", Note: "需企业签名 / TestFlight 分发，请联系管理员"},
		{Platform: "android", Label: "Android 客户端", Note: "构建中，敬请期待"},
		{Platform: "harmony", Label: "鸿蒙客户端", Note: "构建中，敬请期待"},
	}}
}

// loadManifest 读 <downloadsDir>/manifest.json；缺失或损坏回占位清单，绝不失败。
func (s *Server) loadManifest() downloadsManifest {
	b, err := os.ReadFile(filepath.Join(s.downloadsDir, "manifest.json"))
	if err != nil {
		return placeholderManifest()
	}
	var m downloadsManifest
	if err := json.Unmarshal(b, &m); err != nil || len(m.Clients) == 0 {
		log.Printf("downloads: manifest.json 损坏或为空，回占位清单: %v", err)
		return placeholderManifest()
	}
	return m
}

func (s *Server) handleDownloadsManifest(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, s.loadManifest())
}
```

注意：错误响应风格、`httpx.JSON` 签名以仓库现状为准（若 `httpx.JSON` 参数顺序不同，对齐现有 handler 的用法）。

- [ ] **Step 4: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./... `
Expected: 全绿（含既有 linkage/posture 套件——`New` 签名变更已同步）。

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/baidi
git add control/internal/api/downloads.go control/internal/api/downloads_test.go \
  control/internal/config/config.go control/internal/api/api.go \
  control/cmd/baidi-control/main.go control/internal/api/linkage_test.go
git commit -m "客户端下载中心：manifest 公开端点（缺失/损坏回六平台占位，BAIDI_DOWNLOADS 目录）"
```

---

### Task 2: 后端 `GET /downloads/{file}` 白名单分发

**Files:**
- Modify: `control/internal/api/downloads.go`（加 `handleDownloadFile`）
- Modify: `control/internal/api/downloads_test.go`（加分发/穿越测试）
- Modify: `control/internal/api/api.go`（`Routes` 注册 + `IsOpen` 前缀豁免）

**Interfaces:**
- Consumes: Task 1 的 `loadManifest()`、`newDownloadsServer`。
- Produces: `GET /downloads/{file}` 免认证分发端点；`Content-Disposition: attachment` + 正确 `Content-Length`（`http.ServeFile` 自带 Range 支持）。

- [ ] **Step 1: 写失败测试**

追加到 `control/internal/api/downloads_test.go`：

```go
func getFile(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// 写一份 manifest + 真实文件，返回 handler
func downloadsFixture(t *testing.T) (http.Handler, string) {
	t.Helper()
	h, dir := newDownloadsServer(t)
	os.WriteFile(filepath.Join(dir, "baidi-mobile_0.1.0_debug.apk"), []byte("APKBYTES"), 0o644)
	m := `{"clients":[
	  {"platform":"android","label":"Android 客户端","version":"0.1.0","file":"baidi-mobile_0.1.0_debug.apk","size":8,"sha256":"x","available":true},
	  {"platform":"macos","label":"macOS 桌面客户端","version":"0.1.0","file":"baidi-desktop_0.1.0_universal.dmg","size":9,"sha256":"y","available":true},
	  {"platform":"windows","label":"Windows 桌面客户端","file":"ghost.exe","available":false}
	]}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644)
	return h, dir
}

// 白名单内且在盘 → 200 + attachment + 字节一致
func TestDownloadFileOK(t *testing.T) {
	h, _ := downloadsFixture(t)
	rec := getFile(t, h, "/downloads/baidi-mobile_0.1.0_debug.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "APKBYTES" {
		t.Fatalf("body = %q", got)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="baidi-mobile_0.1.0_debug.apk"` {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if cl := rec.Header().Get("Content-Length"); cl != "8" {
		t.Fatalf("Content-Length = %q, want 8", cl)
	}
}

// 不在 manifest → 404（manifest.json 自身也不可下）
func TestDownloadFileNotListed(t *testing.T) {
	h, _ := downloadsFixture(t)
	for _, p := range []string{"/downloads/evil.bin", "/downloads/manifest.json"} {
		if rec := getFile(t, h, p); rec.Code != http.StatusNotFound {
			t.Fatalf("%s code = %d, want 404", p, rec.Code)
		}
	}
}

// available:false 的条目即使列了 file 也不可下
func TestDownloadFileUnavailable(t *testing.T) {
	h, _ := downloadsFixture(t)
	if rec := getFile(t, h, "/downloads/ghost.exe"); rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

// 穿越攻击：..、编码 ..、绝对路径式 → 全部 404，绝不读出 manifest 外内容
func TestDownloadFileTraversal(t *testing.T) {
	h, _ := downloadsFixture(t)
	for _, p := range []string{
		"/downloads/../manifest.json",
		"/downloads/..%2Fmanifest.json",
		"/downloads/%2e%2e%2fmanifest.json",
		"/downloads/..%5Cmanifest.json",
	} {
		rec := getFile(t, h, p)
		// 标准库 mux 对 .. 会 301 清洗或本 handler 404，二者都不得 200
		if rec.Code == http.StatusOK {
			t.Fatalf("%s 不应成功 (code=%d body=%q)", p, rec.Code, rec.Body.String())
		}
	}
}

// 白名单内但盘上缺文件 → 404
func TestDownloadFileMissingOnDisk(t *testing.T) {
	h, _ := downloadsFixture(t)
	if rec := getFile(t, h, "/downloads/baidi-desktop_0.1.0_universal.dmg"); rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ -run TestDownloadFile -v`
Expected: FAIL（404，路由未注册）。

- [ ] **Step 3: 实现**

`downloads.go` 追加（import 增加 `"strings"`）：

```go
// handleDownloadFile 只分发 manifest 中 available 条目列出的文件——白名单即防穿越。
func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		httpx.JSON(w, http.StatusNotFound, map[string]string{"error": "文件不存在"})
		return
	}
	listed := false
	for _, c := range s.loadManifest().Clients {
		if c.Available && c.File == name {
			listed = true
			break
		}
	}
	if !listed {
		httpx.JSON(w, http.StatusNotFound, map[string]string{"error": "文件不存在"})
		return
	}
	full := filepath.Join(s.downloadsDir, name)
	if fi, err := os.Stat(full); err != nil || fi.IsDir() {
		log.Printf("downloads: manifest 列出但盘上缺失 %s", name)
		httpx.JSON(w, http.StatusNotFound, map[string]string{"error": "文件不存在"})
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, full)
}
```

（错误 JSON 结构对齐仓库既有 404 风格；若既有风格是 `httpx.Error(w, code, msg)` 之类 helper，用它。）

`api.go` `Routes()` 加：

```go
// 客户端安装包分发（公开；白名单校验在 handler 内）
mux.HandleFunc("GET /downloads/{file}", s.handleDownloadFile)
```

`IsOpen` 在 switch 之后加前缀豁免（import `"strings"`）：

```go
if strings.HasPrefix(path, "/downloads/") {
	return true
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./...`
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/baidi
git add control/internal/api/downloads.go control/internal/api/downloads_test.go control/internal/api/api.go
git commit -m "客户端下载中心：/downloads/{file} 白名单分发（manifest 即白名单，穿越/未列出/缺盘全 404）"
```

---

### Task 3: 前端下载中心页 + 路由 + 双入口 + Android 二维码

**Files:**
- Create: `console/src/views/PortalDownloads.vue`
- Modify: `console/src/router.ts`（加 `/portal/downloads` 公开路由）
- Modify: `console/src/lib/api.ts`（加 `ClientDownload` / `DownloadsResp` 类型）
- Modify: `console/src/views/PortalLogin.vue`（卡脚加「下载客户端」链接）
- Modify: `console/src/views/PortalApps.vue`（顶栏加「下载客户端」按钮）
- Modify: `console/vite.config.ts`（dev 代理 `/downloads` → :8090）
- Modify: `console/package.json`（新增 `qrcode` + devDep `@types/qrcode`）

**Interfaces:**
- Consumes: Task 1/2 的 `GET /api/v1/portal/downloads` 与 `GET /downloads/{file}`；既有 `api<T>()`（无 token 时不带 Authorization，天然公开调用）。
- Produces: 路由 `/portal/downloads`；类型 `ClientDownload { platform, label, version?, file?, size?, sha256?, available, arch?, note? }`、`DownloadsResp { clients: ClientDownload[] }`。

- [ ] **Step 1: 装依赖**

```bash
cd ~/Projects/baidi/console && npm install qrcode && npm install -D @types/qrcode
```

- [ ] **Step 2: 类型 + 路由 + 代理**

`console/src/lib/api.ts` 在门户类型（`PortalAppsResp` 附近）追加：

```ts
/** 客户端下载中心（公开端点 GET /portal/downloads；文件走 /downloads/<file>） */
export interface ClientDownload {
  platform: string;
  label: string;
  version?: string;
  file?: string;
  size?: number;
  sha256?: string;
  available: boolean;
  arch?: string;
  note?: string;
}
export interface DownloadsResp { clients: ClientDownload[] }
```

`console/src/router.ts` 门户段加一行（`/portal/apps` 之后）：

```ts
{ path: '/portal/downloads', component: () => import('@/views/PortalDownloads.vue') },
```

（登录守卫 `to.path.startsWith('/portal')` 已豁免，无需改守卫。）

`console/vite.config.ts` 的 `server.proxy` 加：

```ts
'/downloads': { target: 'http://127.0.0.1:8090', changeOrigin: true },
```

- [ ] **Step 3: 下载中心页**

`console/src/views/PortalDownloads.vue`（完整新文件）：

```vue
<template>
  <div class="bd-portal">
    <!-- 顶部细 bar（与应用门户同构） -->
    <header class="bd-pbar">
      <div class="bd-plogo">
        <span class="bd-plogo__mark">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="bd-plogo__txt">白帝 · 客户端下载</span>
      </div>
      <div class="bd-pbar__spacer" />
      <button class="bd-pquit" @click="goBack"><icon-left /><span>返回</span></button>
    </header>

    <main class="bd-pmain">
      <div class="bd-pwrap">
        <!-- 推荐下载（按访问端识别） -->
        <section v-if="recommended" class="bd-hero">
          <div class="bd-hero__txt">
            <p class="bd-hero__kicker">为你推荐 · 已识别当前设备</p>
            <h1 class="bd-hero__title">{{ recommended.label }}</h1>
            <p class="bd-hero__meta">
              <template v-if="recommended.available">
                版本 {{ recommended.version }}
                <template v-if="recommended.arch"> · {{ recommended.arch }}</template>
                · {{ fmtSize(recommended.size) }}
              </template>
              <template v-else>{{ recommended.note || '构建中，敬请期待' }}</template>
            </p>
            <button v-if="recommended.available" class="bd-hero__btn" @click="download(recommended)">
              <icon-download /> 立即下载
            </button>
          </div>
        </section>

        <!-- 全平台栅格 -->
        <h2 class="bd-sect">全部平台</h2>
        <div class="bd-grid">
          <article v-for="c in clients" :key="c.platform" class="bd-dtile" :class="{ 'bd-dtile--off': !c.available }">
            <header class="bd-dtile__head">
              <span class="bd-dtile__icon"><component :is="platformIcon(c.platform)" /></span>
              <div>
                <h3 class="bd-dtile__name">{{ c.label }}</h3>
                <p class="bd-dtile__arch">{{ c.available ? (c.arch || '') : (c.note || '构建中，敬请期待') }}</p>
              </div>
            </header>
            <template v-if="c.available">
              <dl class="bd-dtile__meta">
                <div><dt>版本</dt><dd>{{ c.version }}</dd></div>
                <div><dt>大小</dt><dd>{{ fmtSize(c.size) }}</dd></div>
                <div class="bd-dtile__sha">
                  <dt>SHA256</dt>
                  <dd class="bd-mono" :title="c.sha256">{{ shortSha(c.sha256) }}
                    <button class="bd-copybtn" title="复制完整校验值" @click="copySha(c.sha256)"><icon-copy /></button>
                  </dd>
                </div>
              </dl>
              <p v-if="c.note" class="bd-dtile__note">{{ c.note }}</p>
              <div class="bd-dtile__act">
                <button class="bd-dtile__btn" @click="download(c)"><icon-download /> 下载</button>
                <div v-if="c.platform === 'android'" class="bd-qr">
                  <img v-if="qr" :src="qr" alt="扫码下载 Android 客户端" width="84" height="84" />
                  <span v-else class="bd-mono bd-qr__fallback">{{ fileUrl(c) }}</span>
                  <span class="bd-qr__cap">手机扫码直接下载</span>
                </div>
              </div>
            </template>
            <template v-else>
              <div class="bd-dtile__act">
                <button class="bd-dtile__btn bd-dtile__btn--ghost" disabled>暂未提供</button>
              </div>
            </template>
          </article>
        </div>

        <p class="bd-foot">
          安装包由控制中心统一分发，下载后请核对 SHA256 校验值。iOS / 鸿蒙分发请联系管理员。
        </p>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import QRCode from 'qrcode';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type ClientDownload, type DownloadsResp } from '@/lib/api';
import { IconDesktop, IconMobile } from '@arco-design/web-vue/es/icon';

const router = useRouter();
const clients = ref<ClientDownload[]>([]);
const qr = ref('');

function detectPlatform(): string {
  const ua = navigator.userAgent;
  if (/HarmonyOS|OpenHarmony/i.test(ua)) return 'harmony';
  if (/Android/i.test(ua)) return 'android';
  if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
  if (/Windows/i.test(ua)) return 'windows';
  if (/Macintosh|Mac OS X/.test(ua)) return 'macos';
  if (/Linux/i.test(ua)) return 'linux';
  return 'macos';
}

const recommended = computed(() => clients.value.find((c) => c.platform === detectPlatform()));

function platformIcon(p: string) {
  return p === 'android' || p === 'ios' || p === 'harmony' ? IconMobile : IconDesktop;
}

function fileUrl(c: ClientDownload): string {
  return `${location.origin}/downloads/${encodeURIComponent(c.file || '')}`;
}

function download(c: ClientDownload) {
  if (!c.file) return;
  window.location.href = `/downloads/${encodeURIComponent(c.file)}`;
}

function fmtSize(n?: number): string {
  if (!n) return '—';
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(n / 1024))} KB`;
}

function shortSha(s?: string): string {
  return s ? `${s.slice(0, 8)}…${s.slice(-8)}` : '—';
}

async function copySha(s?: string) {
  if (!s) return;
  await navigator.clipboard.writeText(s);
  Message.success('SHA256 已复制');
}

function goBack() {
  router.push(getToken() ? '/portal/apps' : '/portal/login');
}

onMounted(async () => {
  try {
    const resp = await api<DownloadsResp>('/portal/downloads');
    clients.value = resp.clients;
    const android = resp.clients.find((c) => c.platform === 'android' && c.available && c.file);
    if (android) {
      try {
        qr.value = await QRCode.toDataURL(fileUrl(android), { width: 168, margin: 1 });
      } catch {
        qr.value = ''; // 降级显示纯 URL 文本
      }
    }
  } catch {
    Message.error('下载清单获取失败，请稍后重试');
  }
});
</script>

<style scoped>
.bd-portal { min-height: 100vh; display: flex; flex-direction: column; background: var(--bd-fill-1); }
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
.bd-pquit {
  display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 12px;
  border: 1px solid var(--bd-border); background: #fff; border-radius: 7px; cursor: pointer;
  font-size: 13px; color: var(--bd-t2); transition: all .15s;
}
.bd-pquit:hover { border-color: var(--bd-primary); color: var(--bd-primary); }
.bd-pmain { flex: 1; padding: 28px 24px 48px; }
.bd-pwrap { max-width: 1080px; margin: 0 auto; }
.bd-hero {
  background: linear-gradient(135deg, var(--bd-dark-1), var(--bd-dark-2));
  border-radius: var(--bd-radius); padding: 30px 34px; color: #fff; margin-bottom: 30px;
}
.bd-hero__kicker { font-size: 12px; color: var(--bd-dark-txt); margin-bottom: 8px; }
.bd-hero__title { font-size: 24px; font-weight: 700; margin: 0 0 8px; }
.bd-hero__meta { font-size: 13px; color: var(--bd-dark-txt); margin-bottom: 18px; }
.bd-hero__btn {
  display: inline-flex; align-items: center; gap: 8px; height: 38px; padding: 0 22px;
  background: var(--bd-primary); color: #fff; border: none; border-radius: 8px; font-size: 14px;
  cursor: pointer; box-shadow: 0 4px 14px rgba(22, 93, 255, .35); transition: background .15s;
}
.bd-hero__btn:hover { background: var(--bd-primary-h); }
.bd-sect { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin: 0 0 14px; }
.bd-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
.bd-dtile {
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 18px 20px; display: flex; flex-direction: column; gap: 14px;
}
.bd-dtile--off { opacity: .62; }
.bd-dtile__head { display: flex; align-items: center; gap: 12px; }
.bd-dtile__icon {
  width: 40px; height: 40px; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center;
  background: var(--bd-primary-1); color: var(--bd-primary); font-size: 20px; flex: none;
}
.bd-dtile__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); margin: 0; }
.bd-dtile__arch { font-size: 12px; color: var(--bd-t3); margin: 2px 0 0; }
.bd-dtile__meta { display: flex; flex-wrap: wrap; gap: 6px 22px; margin: 0; font-size: 12.5px; }
.bd-dtile__meta div { display: flex; gap: 8px; }
.bd-dtile__meta dt { color: var(--bd-t3); }
.bd-dtile__meta dd { color: var(--bd-t2); margin: 0; display: inline-flex; align-items: center; gap: 4px; }
.bd-dtile__sha { flex-basis: 100%; }
.bd-copybtn {
  border: none; background: none; color: var(--bd-t3); cursor: pointer; padding: 0 2px; font-size: 12px;
}
.bd-copybtn:hover { color: var(--bd-primary); }
.bd-dtile__note { font-size: 12px; color: var(--bd-warning); margin: 0; }
.bd-dtile__act { margin-top: auto; display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; }
.bd-dtile__btn {
  display: inline-flex; align-items: center; gap: 6px; height: 34px; padding: 0 18px;
  background: var(--bd-primary); color: #fff; border: none; border-radius: 7px; font-size: 13px;
  cursor: pointer; box-shadow: 0 2px 8px rgba(22, 93, 255, .25); transition: background .15s;
}
.bd-dtile__btn:hover { background: var(--bd-primary-h); }
.bd-dtile__btn--ghost {
  background: #fff; color: var(--bd-t3); border: 1px solid var(--bd-border); box-shadow: none; cursor: not-allowed;
}
.bd-qr { display: flex; flex-direction: column; align-items: center; gap: 4px; }
.bd-qr img { border: 1px solid var(--bd-border); border-radius: 6px; }
.bd-qr__cap { font-size: 11px; color: var(--bd-t3); }
.bd-qr__fallback { font-size: 10px; color: var(--bd-t3); max-width: 160px; word-break: break-all; }
.bd-foot { margin-top: 28px; font-size: 12px; color: var(--bd-t4); }
</style>
```

注意：Arco 图标此页用了显式 import（`IconDesktop`/`IconMobile` 作动态组件），模板内 `<icon-download/>`、`<icon-left/>`、`<icon-copy/>` 走全局注册——与仓库现状一致即可，若全局未注册该图标名则换用已注册的等价图标。

- [ ] **Step 4: 双入口**

`PortalLogin.vue`：在 `.bd-demo` 段落之后、`.bd-card` 闭合前加：

```html
        <p class="bd-getcli">
          <router-link class="bd-getcli__link" to="/portal/downloads">
            <icon-download /> 下载桌面 / 移动客户端
          </router-link>
        </p>
```

scoped 样式追加（对齐 `.bd-demo` 的分隔约定）：

```css
.bd-getcli { margin: 14px 0 0; text-align: center; }
.bd-getcli__link {
  display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px;
  color: var(--bd-t3); text-decoration: none; transition: color .15s;
}
.bd-getcli__link:hover { color: var(--bd-primary); }
```

`PortalApps.vue`：顶栏 `.bd-pbar__spacer` 之后、`.bd-pacct` 之前加：

```html
      <button class="bd-pquit" @click="$router.push('/portal/downloads')">
        <icon-download /><span>下载客户端</span>
      </button>
```

（该组件若未用 `$router`，改成 script 里已有的 `router` 实例调用，与文件现状对齐。）

- [ ] **Step 5: 验证构建**

```bash
cd ~/Projects/baidi/console && npm run type-check && npm run build
```
Expected: 两者零错误退出。

再起 dev 冒烟（control 在本地 8090 跑着的话）：浏览器访问 `http://localhost:5193/portal/downloads` 应渲染六平台占位（本地无 manifest）。此步为可选冒烟，构建通过即可提交。

- [ ] **Step 6: Commit**

```bash
cd ~/Projects/baidi
git add console/src/views/PortalDownloads.vue console/src/router.ts console/src/lib/api.ts \
  console/src/views/PortalLogin.vue console/src/views/PortalApps.vue console/vite.config.ts \
  console/package.json console/package-lock.json
git commit -m "客户端下载中心：门户下载页（平台识别+推荐大卡+Android 扫码）+ 登录页/应用门户双入口"
```

---

### Task 4: macOS dmg 重构建（尽量 universal）

**Files:**
- Modify: `clients/desktop/src-tauri/build-sidecars.sh`（支持追加 x86_64 交叉编译）
- 产物: `clients/desktop/src-tauri/target/universal-apple-darwin/release/bundle/dmg/白帝安全接入客户端_0.1.0_universal.dmg`（fallback: `target/release/bundle/dmg/…_aarch64.dmg`）

**Interfaces:**
- Consumes: `gateway/cmd/baidi-knock`、`gateway/cmd/baidi-tun`（纯 Go，`CGO_ENABLED=0` 可跨架构）。
- Produces: dmg 产物路径（Task 6 的 build-artifacts.sh 按「universal 优先、aarch64 兜底」查找）。

- [ ] **Step 1: 补 Rust x86_64 target**

```bash
rustup target add x86_64-apple-darwin
```
Expected: `installed` 或已存在。

- [ ] **Step 2: 扩展 sidecar 脚本双架构**

`build-sidecars.sh` 在 host 编译段之后追加（macOS host 时同时产出另一架构）：

```bash
# macOS 上顺带产出另一 darwin 架构，供 universal 打包（Tauri 按 <name>-<triple> 查找）
if [[ "$TRIPLE" == *apple-darwin ]]; then
  for OTHER in aarch64-apple-darwin x86_64-apple-darwin; do
    [ "$OTHER" = "$TRIPLE" ] && continue
    case "$OTHER" in
      aarch64-apple-darwin) OGOARCH=arm64 ;;
      x86_64-apple-darwin)  OGOARCH=amd64 ;;
    esac
    echo "==> 交叉编译 sidecar（darwin/$OGOARCH → $OTHER）"
    ( cd "$GW" && CGO_ENABLED=0 GOOS=darwin GOARCH=$OGOARCH go build -trimpath -ldflags='-s -w' \
        -o "$HERE/binaries/baidi-knock-$OTHER" ./cmd/baidi-knock )
    ( cd "$GW" && CGO_ENABLED=0 GOOS=darwin GOARCH=$OGOARCH go build -trimpath -ldflags='-s -w' \
        -o "$HERE/binaries/baidi-tun-$OTHER" ./cmd/baidi-tun )
  done
fi
```

- [ ] **Step 3: 构建**

```bash
cd ~/Projects/baidi/clients/desktop
./src-tauri/build-sidecars.sh
ls src-tauri/binaries/   # 应见 baidi-{knock,tun}-{aarch64,x86_64}-apple-darwin 共 4 个
npm run tauri:build -- --target universal-apple-darwin
```
Expected: `src-tauri/target/universal-apple-darwin/release/bundle/dmg/白帝安全接入客户端_0.1.0_universal.dmg` 生成。

**Fallback**（universal 构建失败且 20 分钟内无法排除时）：`npm run tauri:build` 重出 aarch64 dmg，卡片 arch 标「Apple Silicon」，并在任务小结里记录失败原因。

- [ ] **Step 4: 验证产物**

```bash
DMG=src-tauri/target/universal-apple-darwin/release/bundle/dmg/白帝安全接入客户端_0.1.0_universal.dmg
ls -la "$DMG"
# 校验 app 主二进制确为双架构：
lipo -info src-tauri/target/universal-apple-darwin/release/bundle/macos/白帝安全接入客户端.app/Contents/MacOS/baidi-desktop
```
Expected: `Architectures in the fat file: … x86_64 arm64`。

- [ ] **Step 5: Commit（仅脚本；产物不进仓）**

```bash
cd ~/Projects/baidi
git add clients/desktop/src-tauri/build-sidecars.sh
git commit -m "桌面客户端：sidecar 脚本双 darwin 架构，支持 universal dmg 打包"
```

---

### Task 5: Android 完整 Gradle 工程 + debug APK

**Files:**
- Create: `clients/mobile/native/android/settings.gradle.kts`、`build.gradle.kts`、`gradle.properties`、`gradlew`（wrapper 全套）、`.gitignore`、`local.properties`（gitignored）
- Create: `clients/mobile/native/android/app/build.gradle.kts`
- Create: `clients/mobile/native/android/app/src/main/AndroidManifest.xml`
- Create: `clients/mobile/native/android/app/src/main/res/values/strings.xml` + 最简 launcher 图标
- Move: `clients/mobile/native/android/MainActivity.kt` → `clients/mobile/native/android/app/src/main/java/dev/baidi/mobile/MainActivity.kt`（git mv，并补 WebViewAssetLoader 接线）
- Move: `clients/mobile/native/android/BaidiVpnService.kt` → `clients/mobile/native/android/app/src/main/java/dev/baidi/mobile/BaidiVpnService.kt`（git mv，逻辑不动）
- 产物: `app/build/outputs/apk/debug/app-debug.apk`

**Interfaces:**
- Consumes: `clients/mobile/native/out/baidimobile.aar`（已编好，minSdk 21，4 ABI）；`clients/mobile` 的 `npm run build` dist（vite base `/`，故 dist 内容平铺进 assets 根，`https://appassets.local/index.html` 直接命中）。
- Produces: debug 签名 APK，applicationId `dev.baidi.mobile`，versionName `0.1.0`；Bridge `apiBase` 改由 `BuildConfig.BAIDI_API_BASE` 提供（默认 `https://101.43.125.131`，可 `-PbaidiApiBase=…` 覆盖）。

- [ ] **Step 1: 环境确认**

```bash
java -version 2>&1 | head -1 || true
which gradle || true
ls "/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java" 2>/dev/null || true
ls ~/Library/Android/sdk/build-tools ~/Library/Android/sdk/platforms
```
决策规则：JDK 优先系统 `java`（须 ≥17）；没有则 `export JAVA_HOME="/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home"`（DevEco 自带 JBR 17+）。gradle 没有则 `brew install gradle`（仅用来生成 wrapper，一次性）。compileSdk 取 `platforms/` 下已装的最高版本（如 `android-35` → 35；若只有更低版本用之，AGP 版本随之降级适配）。

- [ ] **Step 2: 工程骨架**

`clients/mobile/native/android/settings.gradle.kts`：

```kotlin
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "baidi-mobile"
include(":app")
```

`clients/mobile/native/android/build.gradle.kts`：

```kotlin
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.20" apply false
}
```

`clients/mobile/native/android/gradle.properties`：

```properties
org.gradle.jvmargs=-Xmx2g
android.useAndroidX=true
```

`clients/mobile/native/android/local.properties`（**gitignore**）：

```properties
sdk.dir=/Users/prometheus/Library/Android/sdk
```

`clients/mobile/native/android/.gitignore`：

```
.gradle/
build/
app/build/
local.properties
app/src/main/assets/
app/libs/*.aar
```

（dist 与 aar 均为构建期拷入的产物，不进仓。）

`clients/mobile/native/android/app/build.gradle.kts`：

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.baidi.mobile"
    compileSdk = 35 // 以本机 platforms/ 最高版为准

    defaultConfig {
        applicationId = "dev.baidi.mobile"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        // 控制中心地址：./gradlew -PbaidiApiBase=https://x.x.x.x 覆盖
        val apiBase = (project.findProperty("baidiApiBase") as String?) ?: "https://101.43.125.131"
        buildConfigField("String", "BAIDI_API_BASE", "\"$apiBase\"")
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(files("libs/baidimobile.aar"))
    implementation("androidx.webkit:webkit:1.11.0")
}
```

`clients/mobile/native/android/app/src/main/AndroidManifest.xml`：

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:usesCleartextTraffic="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <!-- VPN 数据面：系统以 BIND_VPN_SERVICE 权限绑定 -->
        <service
            android:name=".BaidiVpnService"
            android:exported="false"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

`app/src/main/res/values/strings.xml`：

```xml
<resources><string name="app_name">白帝安全接入</string></resources>
```

图标：最简做法用 `mipmap-anydpi-v26` adaptive icon XML + 单色前景 vector（自绘白帝盾形，参照 PortalApps 顶栏那枚 SVG path），或临时用 AGP 默认。给出 vector：

`app/src/main/res/drawable/ic_launcher_fg.xml`：

```xml
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp" android:height="108dp"
    android:viewportWidth="108" android:viewportHeight="108">
  <group android:scaleX="2.6" android:scaleY="2.6" android:translateX="22.8" android:translateY="22.8">
    <path android:fillColor="#FFFFFF"
        android:pathData="M12,2l8,3v6c0,5 -3.5,8.5 -8,11c-4.5,-2.5 -8,-6 -8,-11V5l8,-3z"/>
    <path android:strokeColor="#165DFF" android:strokeWidth="2"
        android:strokeLineCap="round" android:pathData="M9,12l2,2l4,-4"/>
  </group>
</vector>
```

`app/src/main/res/values/ic_launcher_background.xml`：

```xml
<resources><color name="ic_launcher_background">#165DFF</color></resources>
```

`app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`：

```xml
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background"/>
    <foreground android:drawable="@drawable/ic_launcher_fg"/>
</adaptive-icon>
```

（minSdk 24 < 26 时，另拷一份 vector 为 `mipmap-hdpi` 等的兜底可省——直接在 manifest 用 `@drawable/ic_launcher_fg` 亦可接受；实施者取能让 `assembleDebug` 通过的最简方案，但不得删掉 adaptive icon。）

- [ ] **Step 3: 迁移 + 修补 Kotlin 源**

```bash
cd ~/Projects/baidi/clients/mobile/native/android
mkdir -p app/src/main/java/dev/baidi/mobile
git mv MainActivity.kt app/src/main/java/dev/baidi/mobile/MainActivity.kt
git mv BaidiVpnService.kt app/src/main/java/dev/baidi/mobile/BaidiVpnService.kt
```

`MainActivity.kt` 两处修补（其余不动）：

1. **接上 WebViewAssetLoader**（现状 loadUrl `https://appassets.local/index.html` 但无拦截器，白屏）。`onCreate` 中 webViewClient 段替换为：

```kotlin
        val assets = WebViewAssetLoader.Builder()
            .setDomain("appassets.local")
            .addPathHandler("/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
        web.webViewClient = object : WebViewClientCompat() {
            override fun shouldInterceptRequest(v: WebView, req: WebResourceRequest): WebResourceResponse? =
                assets.shouldInterceptRequest(req.url)
            override fun onPageFinished(v: WebView?, url: String?) {
                v?.evaluateJavascript(BRIDGE_JS, null)
            }
        }
```

import 增加：

```kotlin
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
```

2. **apiBase 脱硬编码**：

```kotlin
        @JavascriptInterface fun apiBase(): String = BuildConfig.BAIDI_API_BASE // 控制中心入口
```

- [ ] **Step 4: 拷产物 + wrapper + 构建**

```bash
cd ~/Projects/baidi/clients/mobile
npm run build                       # 出最新 dist
cd native/android
mkdir -p app/libs app/src/main/assets
cp ../out/baidimobile.aar app/libs/
cp -R ../../dist/. app/src/main/assets/   # base '/' → dist 平铺 assets 根
gradle wrapper --gradle-version 8.9       # 生成 gradlew（此后全用 ./gradlew）
./gradlew assembleDebug
```
Expected: `BUILD SUCCESSFUL`，产物 `app/build/outputs/apk/debug/app-debug.apk`（约 30+ MB，含 4 ABI 的 libgojni.so）。

- [ ] **Step 5: 校验 APK**

```bash
BT=~/Library/Android/sdk/build-tools/$(ls ~/Library/Android/sdk/build-tools | sort -V | tail -1)
"$BT/aapt" dump badging app/build/outputs/apk/debug/app-debug.apk | grep -E "^package|native-code|application-label"
unzip -l app/build/outputs/apk/debug/app-debug.apk | grep -E "libgojni|index.html"
```
Expected: `package: name='dev.baidi.mobile' versionName='0.1.0'`；native-code 含 `arm64-v8a` 等；zip 内有 `assets/index.html` 与 4 个 `libgojni.so`。

再确认 manifest 里 VpnService 权限声明（编译期 merge 后）：

```bash
"$BT/aapt" dump xmltree app/build/outputs/apk/debug/app-debug.apk AndroidManifest.xml | grep -A3 -i "BaidiVpnService\|BIND_VPN"
```
Expected: service 节点带 `android.permission.BIND_VPN_SERVICE`。

（可选冒烟：`~/Library/Android/sdk/emulator/emulator -list-avds` 有 AVD 则装机开屏看到登录页；无 AVD 不强求，不新建镜像。）

- [ ] **Step 6: Commit**

```bash
cd ~/Projects/baidi
git add clients/mobile/native/android
git commit -m "Android 客户端：完整 Gradle 壳工程（WebViewAssetLoader 接线+apiBase 走 BuildConfig+VpnService 声明），出 debug APK"
```

---

### Task 6: 产物管线：build-artifacts.sh + manifest 生成 + deploy 接线

**Files:**
- Create: `clients/build-artifacts.sh`
- Modify: `deploy/build.sh`（携带 `deploy/artifacts/downloads` → `_out/downloads`）
- Modify: `deploy/install-remote.sh`（装 `downloads/` 到 `$BD_PREFIX/downloads`）
- Modify: `deploy/systemd/baidi-control.service`（`Environment=BAIDI_DOWNLOADS=@BD_PREFIX@/downloads`）
- Modify: `deploy/nginx/baidi.conf`（`location /downloads/` 反代 control）
- Modify: `deploy/.gitignore`（加 `artifacts/`）
- Modify: `deploy/README.md`（管线说明一段）

**Interfaces:**
- Consumes: Task 4 dmg（universal 优先 aarch64 兜底）、Task 5 APK 的产物路径。
- Produces: `deploy/artifacts/downloads/{baidi-desktop_0.1.0_*.dmg, baidi-mobile_0.1.0_debug.apk, manifest.json}`；服务器 `/opt/baidi/downloads/`。manifest 结构与 Task 1 的 `ClientDownload` 同构。

- [ ] **Step 1: 写 build-artifacts.sh**

`clients/build-artifacts.sh`（可执行）：

```bash
#!/usr/bin/env bash
# 汇集客户端安装包 → deploy/artifacts/downloads/ 并生成 manifest.json（size/sha256 自动计算）。
# 前置：桌面 dmg 已构建（Task 4）、安卓 APK 已构建（Task 5）；缺哪个就在 manifest 里占位。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/deploy/artifacts/downloads"
VER="0.1.0"
rm -rf "$OUT"; mkdir -p "$OUT"

# ── 桌面 dmg：universal 优先，aarch64 兜底 ──
DMG_UNI="$HERE/desktop/src-tauri/target/universal-apple-darwin/release/bundle/dmg/白帝安全接入客户端_${VER}_universal.dmg"
DMG_ARM="$HERE/desktop/src-tauri/target/release/bundle/dmg/白帝安全接入客户端_${VER}_aarch64.dmg"
MAC_FILE="" MAC_ARCH=""
if [ -f "$DMG_UNI" ]; then
  MAC_FILE="baidi-desktop_${VER}_universal.dmg"; MAC_ARCH="Universal（Intel + Apple Silicon）"
  cp "$DMG_UNI" "$OUT/$MAC_FILE"
elif [ -f "$DMG_ARM" ]; then
  MAC_FILE="baidi-desktop_${VER}_aarch64.dmg"; MAC_ARCH="Apple Silicon"
  cp "$DMG_ARM" "$OUT/$MAC_FILE"
else
  echo "⚠ 未找到桌面 dmg，macOS 将占位"
fi

# ── Android APK ──
APK="$HERE/mobile/native/android/app/build/outputs/apk/debug/app-debug.apk"
AND_FILE=""
if [ -f "$APK" ]; then
  AND_FILE="baidi-mobile_${VER}_debug.apk"
  cp "$APK" "$OUT/$AND_FILE"
else
  echo "⚠ 未找到 Android APK，android 将占位"
fi

# ── 生成 manifest.json ──
MAC_FILE="$MAC_FILE" MAC_ARCH="$MAC_ARCH" AND_FILE="$AND_FILE" VER="$VER" OUT="$OUT" python3 - <<'PY'
import hashlib, json, os

out = os.environ["OUT"]; ver = os.environ["VER"]

def entry(platform, label, file, arch="", note=""):
    e = {"platform": platform, "label": label, "available": bool(file), "note": note}
    if file:
        p = os.path.join(out, file)
        e.update(version=ver, file=file, size=os.path.getsize(p),
                 sha256=hashlib.sha256(open(p, "rb").read()).hexdigest(), arch=arch)
    return e

clients = [
    entry("macos", "macOS 桌面客户端", os.environ["MAC_FILE"], os.environ["MAC_ARCH"]),
    entry("windows", "Windows 桌面客户端", "", note="构建中，敬请期待"),
    entry("linux", "Linux 桌面客户端", "", note="构建中，敬请期待"),
    entry("ios", "iOS 客户端", "", note="需企业签名 / TestFlight 分发，请联系管理员"),
    entry("android", "Android 客户端", os.environ["AND_FILE"],
          "armeabi-v7a / arm64-v8a / x86 / x86_64", "调试签名版，安装时需允许「未知来源应用」"),
    entry("harmony", "鸿蒙客户端", "", note="构建中，敬请期待"),
]
with open(os.path.join(out, "manifest.json"), "w") as f:
    json.dump({"clients": clients}, f, ensure_ascii=False, indent=2)
print("✓ manifest.json 已生成")
PY

echo "✓ 产物就绪 → $OUT"; ls -la "$OUT"
```

```bash
chmod +x ~/Projects/baidi/clients/build-artifacts.sh
```

- [ ] **Step 2: deploy 三件接线**

`deploy/build.sh` 在「携带部署脚本/模板」段之后加：

```bash
if [ -d "$HERE/artifacts/downloads" ]; then
  echo "==> 携带客户端安装包（deploy/artifacts/downloads）"
  cp -R "$HERE/artifacts/downloads" "$OUT/downloads"
fi
```

`deploy/install-remote.sh` 在「二进制 + 前端」段之后加：

```bash
# 客户端安装包（有则整目录替换；manifest 白名单由 control 校验）
if [ -d "$HERE/downloads" ]; then
  rm -rf "$BD_PREFIX/downloads"; mkdir -p "$BD_PREFIX/downloads"
  cp -R "$HERE/downloads/." "$BD_PREFIX/downloads/"
fi
```

（此段须位于既有 `chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX"` 之前，让属主统一处理。）

`deploy/systemd/baidi-control.service` 的 Environment 组加：

```ini
Environment=BAIDI_DOWNLOADS=@BD_PREFIX@/downloads
```

`deploy/nginx/baidi.conf` 在 `location /api/` 之后加：

```nginx
    # 客户端安装包分发（manifest 白名单校验在 baidi-control 内；大文件直通不缓冲）
    location /downloads/ {
        proxy_pass http://127.0.0.1:@CONTROL_PORT@;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Connection "";
        proxy_read_timeout 3600s;
        proxy_buffering off;
    }
```

`deploy/.gitignore` 加一行 `artifacts/`。

`deploy/README.md` 架构图/说明补一行：`/downloads → control 白名单分发客户端安装包（产物先跑 clients/build-artifacts.sh 汇集）`。

- [ ] **Step 3: 本地验证管线**

```bash
cd ~/Projects/baidi && ./clients/build-artifacts.sh
python3 -c "import json;m=json.load(open('deploy/artifacts/downloads/manifest.json'));print([ (c['platform'],c['available']) for c in m['clients'] ])"
```
Expected: 六平台，macos/android 为 True（Task 4/5 产物在位），文件与 manifest 的 size/sha256 一致。

本地端到端冒烟：

```bash
cd ~/Projects/baidi/control && BAIDI_DOWNLOADS=../deploy/artifacts/downloads go run ./cmd/baidi-control &
sleep 2
curl -s http://127.0.0.1:8090/api/v1/portal/downloads | python3 -m json.tool | head -20
curl -sI http://127.0.0.1:8090/downloads/baidi-mobile_0.1.0_debug.apk | grep -Ei "200|content-disposition|content-length"
kill %1
```
Expected: manifest JSON 正常；HEAD/GET 200 + attachment 头。

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/baidi
git add clients/build-artifacts.sh deploy/build.sh deploy/install-remote.sh \
  deploy/systemd/baidi-control.service deploy/nginx/baidi.conf deploy/.gitignore deploy/README.md
git commit -m "客户端下载中心：产物汇集脚本（自动 size/sha256 出 manifest）+ deploy 管线接线（downloads 目录/nginx/systemd）"
```

---

### Task 7: 云端部署 + 公网 E2E 验收

**Files:**
- 无代码改动（部署执行 + 验收记录）；如验收暴露缺陷，修复归入对应文件并单独提交。

**Interfaces:**
- Consumes: 全部前序任务；`deploy/config.env`（已存在，gitignored，场景 A：`root@101.43.125.131`，`BD_HTTPS_PORT=443`）。
- Produces: 公网可用的 `https://101.43.125.131/portal/downloads`。

- [ ] **Step 1: 部署前检查**

```bash
cd ~/Projects/baidi/deploy && grep -E "SERVER_SSH|WIPE|BD_HTTPS_PORT" config.env
```
**必须确认 `WIPE` 未设或 `=0`**（服务器已跑白帝，重部署绝不能再铲）。若 `WIPE=1`，改为 `WIPE=0` 再继续。

- [ ] **Step 2: 部署**

```bash
cd ~/Projects/baidi/deploy && ./deploy.sh
```
Expected: 构建（web+bin+downloads 携带）→ rsync → install-remote 完成，末尾打印控制台地址；nginx reload 无报错。

- [ ] **Step 3: 公网 E2E 验收**

```bash
# manifest
curl -sk https://101.43.125.131/api/v1/portal/downloads | python3 -m json.tool
# 下载头
curl -skI "https://101.43.125.131/downloads/baidi-mobile_0.1.0_debug.apk" | grep -Ei "HTTP|content-disposition|content-length"
# 真实拉取 + sha256 与 manifest 比对
curl -sk -o /tmp/e2e.apk "https://101.43.125.131/downloads/baidi-mobile_0.1.0_debug.apk"
shasum -a 256 /tmp/e2e.apk
curl -sk https://101.43.125.131/api/v1/portal/downloads | python3 -c "import json,sys;print([c['sha256'] for c in json.load(sys.stdin)['clients'] if c['platform']=='android'])"
# dmg 同法验一遍；穿越攻击公网复验应 404：
curl -sk -o /dev/null -w "%{http_code}\n" "https://101.43.125.131/downloads/..%2Fdata%2Fbaidi.db"
```
Expected: manifest 六平台、macos/android available；两文件 sha256 与 manifest 一致；穿越 404（或 nginx 层 400/301，非 200）。

- [ ] **Step 4: 浏览器走查**

用 Browser 打开 `https://101.43.125.131/portal/downloads`：推荐大卡命中 macOS、六卡渲染、Android 二维码显示、SHA256 复制、占位卡灰化；`/portal/login` 卡脚链接与 `/portal/apps` 顶栏按钮可达。截图留证。

- [ ] **Step 5: 收尾提交（如有修复）+ 推送**

```bash
cd ~/Projects/baidi && git push origin main
```

---

## Self-Review 结论

- **Spec 覆盖**：manifest 端点（Task 1）、白名单分发（Task 2）、下载页+双入口+二维码+平台识别（Task 3）、macOS 构建（Task 4）、Android 构建（Task 5）、产物管线+部署接线（Task 6）、云端 E2E（Task 7）——spec 全节有任务落点；「不做」清单未混入。
- **类型一致**：Go `ClientDownload` JSON tag 与前端 `ClientDownload` 接口、`build-artifacts.sh` 生成的 manifest 字段三方同构（platform/label/version/file/size/sha256/available/arch/note）。
- **签名一致**：`New(..., downloadsDir string)` 第 5 参在 Task 1 定义，main.go/linkage_test/downloads_test 同步；`newDownloadsServer` 在 Task 1 定义、Task 2 复用。
- **已知适配点**（实施者按仓库现状对齐，不视为占位）：`httpx.JSON` 的实参形态、错误 JSON 风格、Arco 图标全局注册名、compileSdk 取本机最高版。
