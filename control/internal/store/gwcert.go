package store

import (
	"context"
	"errors"
)

// ── 网关客户端证书白名单（CA 身份迁移 阶段 2）──
//
// mTLS 只证明「这张证书由我们的 CA 签过」，不代表它此刻仍被信任。
// 白名单表让控制面能即刻剔除某台网关（撤销比 CRL 轻、且无需分发）：
// VerifyPeerCertificate 回调里查表，不在表内或已吊销一律拒。

// GatewayCert 一张已签发的网关客户端证书记录。
type GatewayCert struct {
	Fingerprint  string `json:"fingerprint"` // 证书 DER 的 SHA-256（主键）
	GatewayID    string `json:"gatewayId"`   // 证书 CN
	IssuedAt     string `json:"issuedAt"`
	NotAfter     string `json:"notAfter"`
	Revoked      bool   `json:"revoked"`
	RevokedAt    string `json:"revokedAt"`
	RevokeReason string `json:"revokeReason"`
}

// ErrCertNotFound 指纹不在白名单内（未签发过或已被清理）。
var ErrCertNotFound = errors.New("网关证书不存在")

// Memory 空实现（真实数据域，无种子）。
func (m *Memory) GatewayCerts(context.Context) ([]GatewayCert, error) { return []GatewayCert{}, nil }
func (m *Memory) GatewayCertTrusted(context.Context, string) (GatewayCert, bool, error) {
	return GatewayCert{}, false, nil
}
