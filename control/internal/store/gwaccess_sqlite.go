package store

import (
	"context"
	"strings"
)

// GatewayAccessList 读全部网关的对外接入地址登记。
func (s *SQLiteStore) GatewayAccessList(ctx context.Context) ([]GatewayAccess, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT gateway_id, COALESCE(lan_host,''), COALESCE(wan_host,''), COALESCE(updated_at,'')
		 FROM gateway_access ORDER BY gateway_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GatewayAccess
	for rows.Next() {
		var a GatewayAccess
		if err := rows.Scan(&a.GatewayID, &a.LANHost, &a.WANHost, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetGatewayAccess 登记/更新一台网关的对外接入地址。两栏都空即删除该行——
// 留一行两个空串与「从未登记过」在读侧完全等价，留着只会让页面上多一条什么都不说的记录。
func (s *SQLiteStore) SetGatewayAccess(ctx context.Context, a GatewayAccess) (GatewayAccess, error) {
	a.GatewayID = strings.TrimSpace(a.GatewayID)
	lan, err := NormalizeAccessHost(a.LANHost)
	if err != nil {
		return GatewayAccess{}, err
	}
	wan, err := NormalizeAccessHost(a.WANHost)
	if err != nil {
		return GatewayAccess{}, err
	}
	a.LANHost, a.WANHost = lan, wan
	if !a.Configured() {
		_, derr := s.db.ExecContext(ctx, `DELETE FROM gateway_access WHERE gateway_id=?`, a.GatewayID)
		return a, derr
	}
	a.UpdatedAt = nowStr()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO gateway_access(gateway_id,lan_host,wan_host,updated_at) VALUES(?,?,?,?)
		 ON CONFLICT(gateway_id) DO UPDATE SET lan_host=excluded.lan_host, wan_host=excluded.wan_host,
		 updated_at=excluded.updated_at`,
		a.GatewayID, a.LANHost, a.WANHost, a.UpdatedAt)
	return a, err
}
