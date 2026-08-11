// 客户端下载中心：manifest 清单 + 安装包白名单分发。
// manifest.json 是服务器数据文件（deploy 时随安装包 rsync），不进代码仓；
// 缺失/损坏时回六平台全占位，页面仍可渲染。
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

	// ── 构建溯源（BuiltAt/SourceCommit 由 clients/build-artifacts.sh 写入）──
	//
	// ★为什么必须有：此前 manifest 只有 version+size+sha256，看起来很权威，
	// 却完全不说「这包是从哪份源码构建的」。实际发生过的形态是——安装包停在 7 月 20 日，
	// 而客户端源码此后被改了 11 次（真实接入剖面、证书钉扎、三平台 posture、
	// 落点故障转移…），页面上 available=true、有版本号有校验和，一切正常，
	// 用户装下去却是个三周前的客户端，中间那些能力一个都不在里面。
	// 版本号帮不上忙：源码改了但 package.json 的 0.1.0 没动，两边看起来还是"一致"的。
	BuiltAt      string `json:"builtAt,omitempty"`      // 构建时刻（RFC3339）
	SourceCommit string `json:"sourceCommit,omitempty"` // 构建时 clients/ 子树的 git commit（短哈希）

	// ── 以下由服务端现算，不落 manifest（算出来的结论不该被文件里的陈值顶替）──

	// Stale 该包所依据的源码之后又被改过。判据是 SourceCommit 与当前 clients/ 子树
	// HEAD 不一致；SourceCommit 缺失（老 manifest）时**报不可判定而非 false**——
	// 报 false 等于替一个我们无从验证的包背书。
	Stale bool `json:"stale,omitempty"`
	// StaleReason 人话说清为什么，直接展示给用户。
	StaleReason string `json:"staleReason,omitempty"`
	// ProvenanceUnknown 无溯源信息，无法判断新旧。
	ProvenanceUnknown bool `json:"provenanceUnknown,omitempty"`
}

type downloadsManifest struct {
	Clients []ClientDownload `json:"clients"`
}

// placeholderManifest 六平台全占位：manifest 缺失/损坏时的兜底。
//
// ★占位文案要与 clients/build-artifacts.sh 里那份**逐字一致**（两处都得改），
// downloads_script_test.go 真的跑一遍那个脚本来比对。
// ★「构建中，敬请期待」只能用在**真的会被构建出来、且装了能用**的平台上。
// iOS 与鸿蒙不是——它们缺的不是一次构建，而是公共 CI 上根本不存在的东西（Apple 付费账号
// 签名 + Network Extension 授权 / DevEco Studio 工具链）。
// **Windows 也不是**：包在 CI 上出得来，但 baidi-tun 建虚拟网卡要 wintun.dll，那是我们
// 不分发的第三方二进制，加上 UAC 提权路径未实机验证，产物因此标 UNVERIFIED 且刻意不进
// 下载中心。用户看到的不是「包能不能出」，是「能不能用」——对他写「敬请期待」等于让他
// 一直等一个按现有决策不会下发的包，而正确的下一步（自备 DLL / 找管理员要 UNVERIFIED 包）
// 明明存在，却被那句话挡住了。照实说，他才知道该找谁。理由见 clients/BUILD.md 第九节。
func placeholderManifest() downloadsManifest {
	return downloadsManifest{Clients: []ClientDownload{
		{Platform: "macos", Label: "macOS 桌面客户端", Note: "构建中，敬请期待"},
		{Platform: "windows", Label: "Windows 桌面客户端", Note: "需自备 wintun.dll（第三方组件，本仓库不分发）才能建虚拟网卡，且 UAC 提权路径未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员"},
		{Platform: "linux", Label: "Linux 桌面客户端", Note: "pkexec 提权与数据面均未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员"},
		{Platform: "ios", Label: "iOS 客户端", Note: "需 Xcode + 付费账号签名与 Network Extension 授权，公共 CI 无法构建；请联系管理员"},
		{Platform: "android", Label: "Android 客户端", Note: "构建中，敬请期待"},
		{Platform: "harmony", Label: "鸿蒙客户端", Note: "需 DevEco Studio 人工构建（工具链不在 CI 上）；请联系管理员"},
	}}
}

// loadManifest 读 <downloadsDir>/manifest.json；缺失或损坏回占位清单，绝不失败。
func (s *Server) loadManifest() downloadsManifest {
	b, err := os.ReadFile(filepath.Join(s.downloadsDir, "manifest.json"))
	if err != nil {
		return placeholderManifest()
	}
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
}

// clientSourceRev 当前 clients/ 子树的 git 版本（短哈希）。
//
// 取的是**子树**而非仓库 HEAD：只改了控制面就把所有安装包标成过期，会让这条提示
// 迅速变成噪音，管理员两天后就不看了。BAIDI_CLIENT_SRC_REV 可覆盖（部署机上
// 通常没有 .git，由构建流水线注入）。取不到返回空串 = 不可判定。
func clientSourceRev() string {
	if v := strings.TrimSpace(os.Getenv("BAIDI_CLIENT_SRC_REV")); v != "" {
		return v
	}
	// ★路径规格用 `:/clients/`（git 的**仓库根相对**语法）而不是 `clients/`：
	// 后者相对进程 cwd 解析，而 control 通常跑在 control/ 目录下，那里没有 clients/，
	// 于是恒返回空 → 每个包都被标成「无法判断新旧」。这个错法很隐蔽：
	// 降级方向是安全的（不可判定而非假称最新），没人会报障，但整套溯源就此永久失效。
	// 实测起真栈时正是这么发现的——单测里 annotateProvenance 是纯函数，测不到取数这一步。
	out, err := exec.Command("git", "log", "-1", "--format=%h", "--", ":/clients/").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// annotateProvenance 给每个可下载条目标注它相对当前源码是否已过期。
//
// 三态，缺一不可：
//   - 有溯源且一致        → 什么都不显示（正常情况不该打扰人）
//   - 有溯源但对不上      → Stale + 说清差在哪
//   - 无溯源（老 manifest）→ ProvenanceUnknown，**不报 Stale=false**：
//     报 false 等于替一个我们无从验证的包背书，与 posture/设备指标的
//     「采不到就说不可判定，绝不补 0」是同一条纪律。
func annotateProvenance(m downloadsManifest, cur string) downloadsManifest {
	for i := range m.Clients {
		c := &m.Clients[i]
		if !c.Available {
			continue // 占位条目本来就没有包，谈不上新旧
		}
		switch {
		case c.SourceCommit == "":
			c.ProvenanceUnknown = true
			c.StaleReason = "该安装包没有记录构建来源，无法判断它是否包含最新改动。" +
				"请用 clients/build-artifacts.sh 重新构建以补上溯源信息。"
		case cur == "":
			c.ProvenanceUnknown = true
			c.StaleReason = "服务端读不到客户端源码版本（部署机通常无 .git），无法比对新旧。" +
				"可由构建流水线注入 BAIDI_CLIENT_SRC_REV。"
		case c.SourceCommit != cur:
			c.Stale = true
			c.StaleReason = "此包构建自源码 " + c.SourceCommit + "，而客户端源码当前已是 " + cur +
				"——包里不含此后的改动。请重新构建后再分发。"
		}
	}
	return m
}

func (s *Server) handleDownloadsManifest(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, annotateProvenance(s.loadManifest(), clientSourceRev()))
}

// handleDownloadFile 只分发 manifest 中 available 条目列出的文件——白名单即防穿越。
func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		httpx.Error(w, http.StatusNotFound, "文件不存在")
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
		httpx.Error(w, http.StatusNotFound, "文件不存在")
		return
	}
	full := filepath.Join(s.downloadsDir, name)
	if fi, err := os.Stat(full); err != nil || fi.IsDir() {
		slog.Warn("downloads: manifest 列出但盘上缺失", "file", name)
		httpx.Error(w, http.StatusNotFound, "文件不存在")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
	http.ServeFile(w, r, full)
}
