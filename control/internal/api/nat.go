package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// 地址转换（PRD 第 18 章）REST。
//
//	GET    /api/v1/nat                      策略 + 网卡 + 互斥告警（读=任意管理员，角色现算）
//	POST   /api/v1/nat/policies             新增/修改（id 为空即新增）
//	DELETE /api/v1/nat/policies/{id}        删除
//	PUT    /api/v1/nat/ifaces/{gw}/{name}   给网卡定 LAN/WAN 类型
//
// ★权限归 PermSystem 而不是 PermSecurity：NAT 是网络部署能力（PRD 把它放在
// 系统管理/网络部署下），与网关证书、组网同属系统管理员职责。给 security 的话，
// 安全管理员能用一条 DNAT 把内网业务发布到公网——那是绕过整个零信任接入面的捷径。

// natReady 后端是否支持地址转换。不支持时如实回 503 并说明原因——
// 回空列表会让「还没配策略」与「这个后端根本存不了策略」在页面上无法区分。
func (s *Server) natReady(w http.ResponseWriter) bool {
	if s.nat == nil {
		httpx.Error(w, http.StatusServiceUnavailable,
			"当前后端不支持地址转换（需要 SQLite 存储；纯内存演示栈无此能力）")
		return false
	}
	return true
}

func (s *Server) handleNAT(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) || !s.natReady(w) {
		return
	}
	b, err := s.natBundle(r)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load nat policies")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) natBundle(r *http.Request) (store.NATBundle, error) {
	ps, err := s.nat.NATPolicies(r.Context())
	if err != nil {
		return store.NATBundle{}, err
	}
	ifs, err := s.nat.GatewayIfaces(r.Context())
	if err != nil {
		return store.NATBundle{}, err
	}
	return store.NATBundle{Policies: ps, Ifaces: ifs, Warnings: store.NATWarnings(ps)}, nil
}

func (s *Server) handleSaveNATPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) || !s.natReady(w) {
		return
	}
	var p store.NATPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid nat policy payload")
		return
	}
	created := strings.TrimSpace(p.ID) == ""
	saved, err := s.nat.SaveNATPolicy(r.Context(), p)
	if err != nil {
		s.writeNATErr(w, r, err, p)
		return
	}
	verb := "修改"
	if created {
		verb = "新增"
	}
	s.audit(r, "system", verb+"地址转换策略「"+saved.Name+"」（"+natDesc(saved)+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "policy": saved,
		// 每次保存都把告警一并回给前端：管理员最需要看到「这条 DNAT 让 SPA 对该端口失效」
		// 的时刻，就是他刚刚点下保存的时刻，而不是下次打开页面时。
		"warnings": store.NATWarnings([]store.NATPolicy{saved})})
}

func (s *Server) handleDeleteNATPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) || !s.natReady(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.nat.DeleteNATPolicy(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNATNotFound) {
			httpx.Error(w, http.StatusNotFound, "策略不存在")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to delete nat policy")
		return
	}
	s.audit(r, "system", "删除地址转换策略 "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetIfaceType(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) || !s.natReady(w) {
		return
	}
	var body struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	gw, name := r.PathValue("gw"), r.PathValue("name")
	if err := s.nat.SetGatewayIfaceType(r.Context(), gw, name, strings.ToLower(strings.TrimSpace(body.Type))); err != nil {
		switch {
		case errors.Is(err, store.ErrNATIfaceUnknown):
			httpx.Error(w, http.StatusNotFound, "网关 "+gw+" 没有上报过网卡「"+name+"」")
		case errors.Is(err, store.ErrNATIfaceUntyped):
			httpx.Error(w, http.StatusBadRequest, "网卡类型只能是 lan / wan，或留空取消定性")
		default:
			httpx.Error(w, http.StatusInternalServerError, "failed to set interface type")
		}
		return
	}
	s.audit(r, "system", "设置网关 "+gw+" 网卡「"+name+"」类型为 "+body.Type, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// writeNATErr 把领域校验错误映射成能指导下一步动作的 4xx。
//
// 这些错误的文案本身就是产品的一部分：「方向选反」是 NAT 最常见的配置错误，
// 而它的症状是规则灌进内核后一条流量都不匹配——没有任何报错可查。
func (s *Server) writeNATErr(w http.ResponseWriter, r *http.Request, err error, p store.NATPolicy) {
	switch {
	case errors.Is(err, store.ErrNATNotFound):
		httpx.Error(w, http.StatusNotFound, "策略不存在")
	case errors.Is(err, store.ErrNATIfaceUnknown),
		errors.Is(err, store.ErrNATIfaceUntyped),
		errors.Is(err, store.ErrNATIfaceWrongDir):
		s.audit(r, "system", "保存地址转换策略「"+p.Name+"」被拒："+err.Error(), "fail")
		httpx.Error(w, http.StatusBadRequest, err.Error())
	default:
		// normNATPolicy 的其余校验（网段/端口/协议）都是普通 error，一律 400 并原样回文案。
		httpx.Error(w, http.StatusBadRequest, err.Error())
	}
}

func natDesc(p store.NATPolicy) string {
	if p.Type == store.NATSnat {
		return "SNAT " + p.SrcIface + " " + p.SrcAddr + " → " + p.DstIface + " " + p.DstAddr
	}
	return "DNAT " + p.SrcIface + " " + p.DstAddr + " → " + p.TranslatedAddr
}

// gwIface 网关心跳里上报的一张网卡。
type gwIface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	Up    bool     `json:"up"`
}

// recordGatewayIfaces 把网关实测的网卡清单落库（供地址转换选接口）。
//
// ifaces==nil 表示这台网关根本不上报该字段（旧版本）——**保持库里现状不动**。
// 若按空清单整体替换，旧网关每 15s 就会把自己的网卡记录连同管理员定好的
// LAN/WAN 定性一起清掉，而症状是「NAT 策略突然全部校验失败」，
// 看起来像策略坏了，其实是网卡定性没了。
//
// 落库失败只记日志不让心跳失败：网卡台账是配置辅助数据，
// 它写不进去不该连累网关注册（那会让整台网关掉线）。
func (s *Server) recordGatewayIfaces(r *http.Request, gwID string, ifaces *[]gwIface) {
	if s.nat == nil || ifaces == nil || gwID == "" {
		return
	}
	out := make([]store.GatewayIface, 0, len(*ifaces))
	for _, f := range *ifaces {
		name := strings.TrimSpace(f.Name)
		if name == "" {
			continue
		}
		addrs := f.Addrs
		if addrs == nil {
			addrs = []string{}
		}
		out = append(out, store.GatewayIface{GatewayID: gwID, Name: name, Addrs: addrs, Up: f.Up})
	}
	if err := s.nat.ReplaceGatewayIfaces(r.Context(), gwID, out); err != nil {
		slog.Error("网关网卡清单落库失败（不影响注册）", "gateway", gwID, "err", err.Error())
	}
}
