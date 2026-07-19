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
