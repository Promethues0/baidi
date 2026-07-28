package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/pki"
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

// MTLSHandler 返回只服务网关接口的 handler（注册/拉策略），身份取自客户端证书。
func (s *Server) MTLSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/gateways/register", s.handleGatewayRegister)
	mux.HandleFunc("GET /api/v1/gateways/policy", s.handleGatewayPolicy)
	return withCertCN(mux)
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
	if !s.requireAdmin(w, r) {
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
	if !s.requireAdmin(w, r) {
		return
	}
	fp := r.PathValue("fingerprint")
	var b struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	err := s.writer.RevokeGatewayCert(r.Context(), fp, b.Reason)
	if errors.Is(err, store.ErrCertNotFound) {
		httpx.Error(w, http.StatusNotFound, "证书不存在或已吊销")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "吊销失败")
		return
	}
	s.audit(r, "security", "吊销网关客户端证书 "+fp[:min(16, len(fp))]+"…："+orElse(b.Reason, "管理员主动吊销"), "deny")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "fingerprint": fp})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
