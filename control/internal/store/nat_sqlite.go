package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// ── 地址转换的 SQLite 实现（表 nat_policies / gateway_ifaces，见 migrate）──

const natCols = `id,name,type,gateway_id,src_iface,src_addr,dst_iface,dst_addr,protocol,
dst_port,translated_addr,translated_port,enabled,created_at,updated_at`

func (s *SQLiteStore) NATPolicies(ctx context.Context) ([]NATPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+natCols+` FROM nat_policies ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []NATPolicy{}
	for rows.Next() {
		var p NATPolicy
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.GatewayID, &p.SrcIface, &p.SrcAddr,
			&p.DstIface, &p.DstAddr, &p.Protocol, &p.DstPort, &p.TranslatedAddr,
			&p.TranslatedPort, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveNATPolicy 新增或更新一条策略（id 为空即新增）。
//
// 校验用的网卡清单在事务内现读：管理员改网卡类型与建策略是两个并发操作，
// 用事务外读到的旧清单校验，会放过一条方向已经不成立的规则。
func (s *SQLiteStore) SaveNATPolicy(ctx context.Context, p NATPolicy) (NATPolicy, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NATPolicy{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	ifaces, err := scanIfacesTx(ctx, tx)
	if err != nil {
		return NATPolicy{}, err
	}
	p, err = normNATPolicy(p, ifaces)
	if err != nil {
		return NATPolicy{}, err
	}

	now := nowStr()
	if strings.TrimSpace(p.ID) == "" {
		p.ID = "nat-" + uuid.NewString()[:8]
		p.CreatedAt, p.UpdatedAt = now, now
		if _, err := tx.ExecContext(ctx, `INSERT INTO nat_policies(`+natCols+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.ID, p.Name, p.Type, p.GatewayID, p.SrcIface, p.SrcAddr, p.DstIface, p.DstAddr,
			p.Protocol, p.DstPort, p.TranslatedAddr, p.TranslatedPort, boolInt(p.Enabled),
			p.CreatedAt, p.UpdatedAt); err != nil {
			return NATPolicy{}, err
		}
		return p, tx.Commit()
	}

	var createdAt string
	switch err := tx.QueryRowContext(ctx, `SELECT created_at FROM nat_policies WHERE id=?`, p.ID).
		Scan(&createdAt); err {
	case nil:
	case sql.ErrNoRows:
		return NATPolicy{}, ErrNATNotFound
	default:
		return NATPolicy{}, err
	}
	p.CreatedAt, p.UpdatedAt = createdAt, now
	if _, err := tx.ExecContext(ctx, `UPDATE nat_policies SET name=?,type=?,gateway_id=?,
src_iface=?,src_addr=?,dst_iface=?,dst_addr=?,protocol=?,dst_port=?,translated_addr=?,
translated_port=?,enabled=?,updated_at=? WHERE id=?`,
		p.Name, p.Type, p.GatewayID, p.SrcIface, p.SrcAddr, p.DstIface, p.DstAddr, p.Protocol,
		p.DstPort, p.TranslatedAddr, p.TranslatedPort, boolInt(p.Enabled), p.UpdatedAt, p.ID); err != nil {
		return NATPolicy{}, err
	}
	return p, tx.Commit()
}

func (s *SQLiteStore) DeleteNATPolicy(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nat_policies WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNATNotFound
	}
	return nil
}

func (s *SQLiteStore) GatewayIfaces(ctx context.Context) ([]GatewayIface, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT gateway_id,name,COALESCE(if_type,''),COALESCE(addrs_json,'[]'),up,updated_at
FROM gateway_ifaces ORDER BY gateway_id,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanIfaceRows(rows)
}

func scanIfacesTx(ctx context.Context, tx *sql.Tx) ([]GatewayIface, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT gateway_id,name,COALESCE(if_type,''),COALESCE(addrs_json,'[]'),up,updated_at
FROM gateway_ifaces ORDER BY gateway_id,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanIfaceRows(rows)
}

func scanIfaceRows(rows *sql.Rows) ([]GatewayIface, error) {
	out := []GatewayIface{}
	for rows.Next() {
		var f GatewayIface
		var addrs string
		var up int
		if err := rows.Scan(&f.GatewayID, &f.Name, &f.Type, &addrs, &up, &f.UpdatedAt); err != nil {
			return nil, err
		}
		f.Up = up != 0
		_ = json.Unmarshal([]byte(addrs), &f.Addrs)
		if f.Addrs == nil {
			f.Addrs = []string{}
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ReplaceGatewayIfaces 用网关本次心跳实测到的网卡清单整体替换该网关的记录。
//
// ★管理员定的 if_type **必须保留**：它不在网关上报的内容里（网关没法知道哪张卡对公网），
// 整体替换时若不回填，管理员每 15 秒就会被心跳把 LAN/WAN 定性清空一次——
// 而症状是「NAT 策略突然全部校验失败」，看起来像策略坏了，其实是网卡定性没了。
// 网卡消失（拔线/改名）时定性一并消失，这是对的：它已经不是同一张卡了。
func (s *SQLiteStore) ReplaceGatewayIfaces(ctx context.Context, gwID string, ifaces []GatewayIface) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	prev := map[string]string{}
	rows, err := tx.QueryContext(ctx, `SELECT name,COALESCE(if_type,'') FROM gateway_ifaces WHERE gateway_id=?`, gwID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n, t string
		if err := rows.Scan(&n, &t); err != nil {
			rows.Close() //nolint:errcheck
			return err
		}
		prev[n] = t
	}
	rows.Close() //nolint:errcheck
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM gateway_ifaces WHERE gateway_id=?`, gwID); err != nil {
		return err
	}
	now := nowStr()
	for _, f := range ifaces {
		addrs, _ := json.Marshal(f.Addrs)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO gateway_ifaces(gateway_id,name,if_type,addrs_json,up,updated_at) VALUES(?,?,?,?,?,?)`,
			gwID, f.Name, prev[f.Name], string(addrs), boolInt(f.Up), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) SetGatewayIfaceType(ctx context.Context, gwID, name, ifType string) error {
	switch ifType {
	case IfaceLAN, IfaceWAN, IfaceNone:
	default:
		return ErrNATIfaceUntyped
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE gateway_ifaces SET if_type=?, updated_at=? WHERE gateway_id=? AND name=?`,
		ifType, nowStr(), gwID, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNATIfaceUnknown
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
