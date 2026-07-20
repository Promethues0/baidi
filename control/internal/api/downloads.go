// 客户端下载中心：manifest 清单 + 安装包白名单分发。
// manifest.json 是服务器数据文件（deploy 时随安装包 rsync），不进代码仓；
// 缺失/损坏时回六平台全占位，页面仍可渲染。
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
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

func (s *Server) handleDownloadsManifest(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, s.loadManifest())
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
