package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/pki"
	"baidi.dev/control/internal/standby"
	"baidi.dev/control/internal/store"
)

// ── 网关机器身份：mTLS（CA 身份迁移 阶段 2）──
//
// 此前网关用共享密钥自签 role=gateway 令牌调控制面（cplane.token()）——
// 那把密钥同时能签 role=admin，等于把控制面的签发能力放在被保护方手里。
// 改为 mTLS 客户端证书后，机器身份在传输层完成，且与用户身份彻底分家。
//
// ★路由分离而非只改角色判断：/api/v1/gateways/* 只挂在 mTLS 监听上，
// 明文侧对该前缀直接拒绝。若只改 requireGateway 的判定、旧路仍留在明文 :8090，
// 那 admin 令牌照样能调网关接口，「机器身份走 mTLS」就只是多了一条路而没关掉旧路。

// certCNKey 把 mTLS 客户端证书的 CN 注入请求上下文。
type certCNKey struct{}

// GatewayCN 取本次请求的 mTLS 客户端证书 CN（即网关 id）；非 mTLS 请求返回 ""。
func GatewayCN(ctx context.Context) string {
	cn, _ := ctx.Value(certCNKey{}).(string)
	return cn
}

// ipsecCNPrefix 站点组网网关（baidi-ipsec）的证书 CN 前缀约定。
const ipsecCNPrefix = "ipsec-"

// standbyCNPrefix 温备节点（baidi-standby）的证书 CN 前缀约定（定义在 standby 包，这里只取用）。
const standbyCNPrefix = standby.CNPrefix

// MTLSHandler 返回只服务机器身份接口的 handler，身份取自客户端证书。
//
// ★三类进程共用同一套 CA 与同一个 mTLS 端口，但**能调的接口不同**：
//
//	CN 非 ipsec-/standby- （接入网关 baidi-gateway）→ register / policy
//	CN =  ipsec-*         （组网网关 baidi-ipsec）  → 只有 /api/v1/gateways/ipsec*
//	CN =  standby-*       （温备节点 baidi-standby）→ 只有 /api/v1/standby/*
//
// 分权的目标是收窄各自的出口：一张只负责站点组网的证书**不该能读走全量资源授权策略**
// （policy 里是「谁能访问哪个后端」的完整清单，等于一张授权地图）；一张备机证书
// **更不该能调网关接口**——它能拉走的已经是整套信任材料了，再让它注册成一台网关、
// 或读一份策略，只会让"这张证书到底能做什么"变得没人说得清。反过来，
// 网关证书也绝不能拉备份：那等于把 CA 私钥发给被保护方。
//
// ★为什么两个新角色用白名单（必须 ipsec-/standby-）、接入侧用黑名单（只要不是这两个前缀）：
// 接入网关的 CN 就是部署时填的 GW_ID（deploy/config.env.example 里默认 gw-1，
// 但它是**用户可改的**，现网可能是 beijing-idc-1 之类）。把接入侧也收成
// `gw-` 白名单，会在升级的那一瞬间把所有 CN 不以 gw- 开头的现网网关全部踢下线，
// 而安全收益为零——真正要挡的是「组网/备机证书读授权策略」这一个方向，
// 黑名单已经完整覆盖它。两个新前缀是后引入的，可以从一开始就要求。
func (s *Server) MTLSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/gateways/register", accessCNet(s.handleGatewayRegister))
	mux.HandleFunc("GET /api/v1/gateways/policy", accessCNet(s.handleGatewayPolicy))
	// 站点组网：只有 ipsec-* 证书能调
	mux.HandleFunc("GET /api/v1/gateways/ipsec", ipsecCNOnly(s.handleGatewayIpsecSites))
	mux.HandleFunc("GET /api/v1/gateways/ipsec/{id}/psk", ipsecCNOnly(s.handleGatewayIpsecPSK))
	mux.HandleFunc("POST /api/v1/gateways/ipsec/status", ipsecCNOnly(s.handleGatewayIpsecStatus))
	// 控制面温备：只有 standby-* 证书能调（PRD 15.5，见 api/standby.go）
	mux.HandleFunc("GET "+standby.PathBackup, standbyCNOnly(s.handleStandbyBackup))
	mux.HandleFunc("POST "+standby.PathStatus, standbyCNOnly(s.handleStandbyStatus))
	// 与明文口的 httpx.BodyLimit(1<<20) 同口径：mTLS 监听在 main.go 里不走那条
	// 中间件链，缺了这层则各 handler 的 MaxBytesReader 成为唯一防线（register 就漏过）。
	return withCertCN(httpx.BodyLimit(1 << 20)(mux))
}

// ipsecCNOnly 只放行 CN 以 ipsec- 开头的客户端证书。
func ipsecCNOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := GatewayCN(r.Context())
		if !strings.HasPrefix(cn, ipsecCNPrefix) {
			// 错误信息带上实际 CN 与期望前缀：部署时把 IPSEC_GW_ID 写成了 gw-1-ipsec
			// 而不是 ipsec-gw-1，是这条闸最常见的误报来源，报文里说清楚能省一小时。
			httpx.Error(w, http.StatusForbidden,
				"该接口只接受站点组网网关（证书 CN 需以 "+ipsecCNPrefix+" 开头，本次为 "+orElse(cn, "空")+"）")
			return
		}
		next(w, r)
	}
}

// standbyCNOnly 只放行 CN 以 standby- 开头的客户端证书。
func standbyCNOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := GatewayCN(r.Context())
		if !strings.HasPrefix(cn, standbyCNPrefix) {
			httpx.Error(w, http.StatusForbidden,
				"该接口只接受温备节点（证书 CN 需以 "+standbyCNPrefix+" 开头，本次为 "+orElse(cn, "空")+
					"）：配置备份含 CA 私钥与全部凭据，网关证书不得拉取")
			return
		}
		next(w, r)
	}
}

// accessCNet 拒绝 CN 以 ipsec- / standby- 开头的客户端证书调用接入网关接口。
func accessCNet(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := GatewayCN(r.Context())
		if strings.HasPrefix(cn, ipsecCNPrefix) {
			httpx.Error(w, http.StatusForbidden,
				"站点组网网关证书（CN "+cn+"）不能调用接入网关接口：一张只负责 IPSec 的证书不应能读全量资源授权策略")
			return
		}
		if strings.HasPrefix(cn, standbyCNPrefix) {
			// 备机不是数据面：让它注册成一台网关的话，网关页会多出一台永远不转发流量的
			// "在线网关"，剖面还会把它当落点下发给客户端——终端会拨向一台什么都不听的机器。
			httpx.Error(w, http.StatusForbidden,
				"温备节点证书（CN "+cn+"）不能调用接入网关接口：备机不承载数据面，注册成网关会被剖面当作可用落点下发给终端")
			return
		}
		next(w, r)
	}
}

// withCertCN 把已完成 mTLS 握手的客户端证书 CN 放进上下文，供 requireGateway 使用。
func withCertCN(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			httpx.Error(w, http.StatusForbidden, "需要客户端证书")
			return
		}
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), certCNKey{}, cn)))
	})
}

// MTLSConfig 构造 control 的 mTLS 服务端配置：要求并校验客户端证书，
// 且证书指纹必须在白名单内且未吊销——这是「即刻吊销某台网关」的执行点
// （mTLS 只证明证书由我们 CA 签过，不代表此刻仍被信任）。
func (s *Server) MTLSConfig(ca *pki.CA, serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("缺少客户端证书")
			}
			fp := pki.Fingerprint(rawCerts[0])
			rec, ok, err := s.store.GatewayCertTrusted(context.Background(), fp)
			if err != nil {
				return errors.New("证书白名单查询失败")
			}
			if !ok {
				if rec.Revoked {
					slog.Warn("拒绝已吊销的网关证书", "gwid", rec.GatewayID, "fp", fp[:16])
					return errors.New("证书已吊销")
				}
				slog.Warn("拒绝未登记的网关证书", "fp", fp[:16])
				return errors.New("证书未登记")
			}
			return nil
		},
	}
}

// handleIssueGatewayCert 给一台网关签发 mTLS 客户端证书（admin）。
// 私钥只在响应里返回一次，服务端不留存——控制面只记指纹用于白名单/吊销。
func (s *Server) handleIssueGatewayCert(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	if s.ca == nil {
		httpx.Error(w, http.StatusServiceUnavailable, "控制面未启用内部 CA（需配置 BAIDI_PKI_DIR）")
		return
	}
	var b struct {
		GatewayID string `json:"gatewayId"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b); err != nil || b.GatewayID == "" {
		httpx.Error(w, http.StatusBadRequest, "gatewayId 必填")
		return
	}
	// ★`standby-` 是保留命名空间，本端点拒收。
	//
	// CN 前缀是温备同步端点的**唯一分权判据**（standbyCNOnly 就是 HasPrefix），
	// 而这里对 gatewayId 原样当 CN 签。不拦的话，持 PermSystem 的系统管理员可以
	// 签一张 CN=standby-任意 的证书，凭它 GET /api/v1/standby/backup 拉走整套信任材料
	// （CA 私钥 + 三把签名私钥 + 审计链密钥 + 整个库）——那是备机专属的出口。
	// 备机证书的正路是**离线 CLI**（baidi-control -issue-gateway-cert standby-1 -out …，
	// 见 deploy/README.md）：要有这台机器的文件系统访问权，不是一次 HTTP 调用。
	// `ipsec-` 不拦：组网网关的证书本来就走这条 HTTP 路（gateway/ipsec-e2e.sh），
	// 且它那条分权只是收窄出口，不是拉走信任材料。
	if strings.HasPrefix(b.GatewayID, standbyCNPrefix) {
		httpx.Error(w, http.StatusBadRequest,
			"gatewayId 不得以 "+standbyCNPrefix+" 开头："+
				"该前缀是温备节点的分权判据，凭它能拉走整套信任材料。"+
				"备机证书请在主机上离线签发：baidi-control -issue-gateway-cert standby-1 -out <目录>")
		return
	}
	// License 网关席位闸：只对**新 gatewayId** 计席位——同 id 换证不占新席位
	// （计数口径是未吊销证书的去重 gatewayId，见 licenseUsage）。
	if !s.gatewayHasCert(r, b.GatewayID) {
		if reason, ok := s.licenseAdmit(r, "gateway"); !ok {
			s.audit(r, "admin", "签发网关证书「"+b.GatewayID+"」被 License 拒绝："+reason, "fail")
			httpx.Error(w, http.StatusConflict, reason)
			return
		}
	}
	iss, err := s.ca.IssueClient(b.GatewayID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "签发失败")
		return
	}
	if err := s.writer.SaveGatewayCert(r.Context(), store.GatewayCert{
		Fingerprint: iss.Fingerprint, GatewayID: b.GatewayID,
		NotAfter: iss.NotAfter.Format("2006-01-02 15:04:05"),
	}); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "登记证书失败")
		return
	}
	s.audit(r, "admin", "签发网关客户端证书："+b.GatewayID+"（指纹 "+iss.Fingerprint[:16]+"…）", "ok")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"gatewayId": b.GatewayID, "fingerprint": iss.Fingerprint,
		"notAfter": iss.NotAfter.Format(time.RFC3339),
		"certPem":  iss.CertPEM, "keyPem": iss.KeyPEM, "caPem": string(s.ca.CertPEM()),
	})
}

// handleGatewayCerts 已签发的网关证书清单（admin）。
func (s *Server) handleGatewayCerts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	cs, err := s.store.GatewayCerts(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load certs")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"certs": cs, "caEnabled": s.ca != nil})
}

// handleRevokeGatewayCert 吊销一张网关证书（admin）：下次握手即被拒。
func (s *Server) handleRevokeGatewayCert(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fp := r.PathValue("fingerprint")
	var b struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	// 先查出这张证书属于哪台网关：吊销之后 GatewayCertTrusted 就查不到"可信记录"了，
	// 而下面要按 CN 把它从内存台账里摘掉。
	rec, _, _ := s.store.GatewayCertTrusted(r.Context(), fp)
	err := s.writer.RevokeGatewayCert(r.Context(), fp, b.Reason)
	if errors.Is(err, store.ErrCertNotFound) {
		httpx.Error(w, http.StatusNotFound, "证书不存在或已吊销")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "吊销失败")
		return
	}
	// ★吊销必须同时把这台网关从**下发给终端的落点清单**里摘掉。
	//
	// 此前吊销只切断了「网关→控制面」这一半：进程还在跑（机器可能已被攻击者控制），
	// 剖面照旧把它当落点下发、`tunnelPin` 也照发，客户端钉扎照样校验通过、界面显示
	// 「已建立 · 证书钉扎」，每轮还主动给它发一次有效敲门令牌（等于持续替一台已吊销的
	// 网关开着 SPA 窗口）；首选落点一抖就切过去，业务流量流进失陷网关。
	// 内存台账没有别的清除路径（除了控制面重启），所以摘除点只能在这里。
	// 它若还持有另一张未吊销的证书，下一次心跳（15s）会自己重新注册回来——
	// 那正是我们要的语义：吊销的是**证书**，不是"这台机器从此不存在"。
	dropped := s.dropGatewayRegistration(rec.GatewayID)
	note := ""
	if dropped {
		note = "；已同时从客户端落点清单中摘除网关 " + rec.GatewayID
	}
	s.audit(r, "security", "吊销网关客户端证书 "+fp[:min(16, len(fp))]+"…："+
		orElse(b.Reason, "管理员主动吊销")+note, "deny")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "fingerprint": fp,
		"gatewayId": rec.GatewayID, "endpointDropped": dropped,
	})
}

// dropGatewayRegistration 把一台网关从内存台账里摘除（落点清单 / 隧道指纹 / 会话）。
// 返回是否真的摘掉了一条注册记录。
func (s *Server) dropGatewayRegistration(id string) bool {
	if strings.TrimSpace(id) == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.gateways[id]
	delete(s.gateways, id)
	delete(s.gwTunnelFP, id)
	delete(s.gwSess, id)
	return existed
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// gatewayHasCert 该 gatewayId 是否已有未吊销证书（有则本次签发是换证，不占新席位）。
// 读失败按"没有"处理：方向是多过一次容量闸（更严），而不是放行。
func (s *Server) gatewayHasCert(r *http.Request, gwID string) bool {
	certs, err := s.store.GatewayCerts(r.Context())
	if err != nil {
		return false
	}
	for _, c := range certs {
		if !c.Revoked && c.GatewayID == gwID {
			return true
		}
	}
	return false
}
