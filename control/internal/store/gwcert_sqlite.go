package store

import (
	"context"
	"database/sql"
)

const gwCertCols = `fingerprint,gateway_id,issued_at,not_after,revoked,revoked_at,revoke_reason`

func scanGatewayCerts(rows *sql.Rows) ([]GatewayCert, error) {
	defer rows.Close()
	out := []GatewayCert{}
	for rows.Next() {
		var c GatewayCert
		var rev int
		if err := rows.Scan(&c.Fingerprint, &c.GatewayID, &c.IssuedAt, &c.NotAfter, &rev, &c.RevokedAt, &c.RevokeReason); err != nil {
			return nil, err
		}
		c.Revoked = rev == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// GatewayCerts 全部已签发的网关证书（管理台展示/审查）。
func (s *SQLiteStore) GatewayCerts(ctx context.Context) ([]GatewayCert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+gwCertCols+` FROM gateway_certs ORDER BY issued_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanGatewayCerts(rows)
}

// GatewayCertTrusted 按指纹点查，并报告是否仍可信（存在且未吊销）。
// mTLS 握手的 VerifyPeerCertificate 回调用它——这是「即刻吊销」的执行点。
func (s *SQLiteStore) GatewayCertTrusted(ctx context.Context, fp string) (GatewayCert, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+gwCertCols+` FROM gateway_certs WHERE fingerprint=? LIMIT 1`, fp)
	if err != nil {
		return GatewayCert{}, false, err
	}
	cs, err := scanGatewayCerts(rows)
	if err != nil || len(cs) == 0 {
		return GatewayCert{}, false, err
	}
	return cs[0], !cs[0].Revoked, nil
}

// SaveGatewayCert 记录一张新签发的证书（同指纹幂等覆盖）。
func (s *SQLiteStore) SaveGatewayCert(ctx context.Context, c GatewayCert) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO gateway_certs(`+gwCertCols+`)
VALUES(?,?,?,?,0,'','')
ON CONFLICT(fingerprint) DO UPDATE SET gateway_id=excluded.gateway_id,
  issued_at=excluded.issued_at, not_after=excluded.not_after, revoked=0, revoked_at='', revoke_reason=''`,
		c.Fingerprint, c.GatewayID, nowStr(), c.NotAfter)
	return err
}

// RevokeGatewayCert 吊销一张证书（下次握手即被拒）。指纹不存在 → ErrCertNotFound。
func (s *SQLiteStore) RevokeGatewayCert(ctx context.Context, fp, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE gateway_certs SET revoked=1, revoked_at=?, revoke_reason=? WHERE fingerprint=? AND revoked=0`,
		nowStr(), reason, fp)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCertNotFound
	}
	return nil
}
