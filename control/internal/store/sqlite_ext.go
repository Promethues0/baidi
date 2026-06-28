package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// ── IPSec 站点（落库覆盖 Memory 种子）──

// Ipsec 从库读取 IPSec 站点清单。
func (s *SQLiteStore) Ipsec(ctx context.Context) ([]IpsecSite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,peer,local_subnet,remote_subnet,ike_version,auth,suite,phase1,phase2,pfs,pq_hybrid,status,rx_bytes,tx_bytes,last_up,COALESCE(local_ref,''),COALESCE(remote_ref,'') FROM ipsec_sites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IpsecSite{}
	for rows.Next() {
		var it IpsecSite
		var p1, p2 string
		var pfs, pq int
		if err := rows.Scan(&it.ID, &it.Name, &it.Peer, &it.LocalSubnet, &it.RemoteSubnet, &it.IkeVersion, &it.Auth, &it.Suite, &p1, &p2, &pfs, &pq, &it.Status, &it.RxBytes, &it.TxBytes, &it.LastUp, &it.LocalRef, &it.RemoteRef); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(p1), &it.Phase1)
		_ = json.Unmarshal([]byte(p2), &it.Phase2)
		it.Pfs = pfs == 1
		it.PqHybrid = pq == 1
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) upsertIpsecSite(ctx context.Context, it IpsecSite) error {
	p1, _ := json.Marshal(it.Phase1)
	p2, _ := json.Marshal(it.Phase2)
	// 配置型 upsert：编辑站点只改配置字段，绝不回写运行态（status / last_up / rx_bytes / tx_bytes）。
	// 运行态由 ToggleIpsecSite（启停）与数据面统计独占，避免编辑时用陈旧表单快照把在线隧道改成 down。
	_, err := s.db.ExecContext(ctx, `INSERT INTO ipsec_sites(id,name,peer,local_subnet,remote_subnet,ike_version,auth,suite,phase1,phase2,pfs,pq_hybrid,status,rx_bytes,tx_bytes,last_up,local_ref,remote_ref,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, peer=excluded.peer, local_subnet=excluded.local_subnet,
  remote_subnet=excluded.remote_subnet, ike_version=excluded.ike_version, auth=excluded.auth, suite=excluded.suite,
  phase1=excluded.phase1, phase2=excluded.phase2, pfs=excluded.pfs, pq_hybrid=excluded.pq_hybrid,
  local_ref=excluded.local_ref, remote_ref=excluded.remote_ref, updated_at=excluded.updated_at`,
		it.ID, it.Name, it.Peer, it.LocalSubnet, it.RemoteSubnet, it.IkeVersion, it.Auth, it.Suite,
		string(p1), string(p2), b2i(it.Pfs), b2i(it.PqHybrid), it.Status, it.RxBytes, it.TxBytes, it.LastUp,
		it.LocalRef, it.RemoteRef, nowStr())
	return err
}

// SaveIpsecSite 新增 / 修改一条 IPSec 站点（upsert）。
func (s *SQLiteStore) SaveIpsecSite(ctx context.Context, it IpsecSite) (IpsecSite, error) {
	if it.ID == "" {
		it.ID = "site-" + uuid.NewString()[:8]
	}
	if it.IkeVersion == "" {
		it.IkeVersion = "IKEv2"
	}
	if it.Status == "" {
		it.Status = "down"
	}
	if it.LastUp == "" {
		it.LastUp = "—"
	}
	if err := s.upsertIpsecSite(ctx, it); err != nil {
		return IpsecSite{}, err
	}
	return it, nil
}

// DeleteIpsecSite 删除一条站点。
func (s *SQLiteStore) DeleteIpsecSite(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ipsec_sites WHERE id=?`, id)
	return err
}

// ToggleIpsecSite 翻转隧道连接状态（up <-> down），返回新状态。
func (s *SQLiteStore) ToggleIpsecSite(ctx context.Context, id string) (string, error) {
	var cur string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM ipsec_sites WHERE id=?`, id).Scan(&cur); err != nil {
		return "", err
	}
	// 断开：仅改 status，保留 last_up（最近一次建立时间）；建立：刷新 last_up=now。
	if cur == "up" {
		_, err := s.db.ExecContext(ctx, `UPDATE ipsec_sites SET status='down' WHERE id=?`, id)
		return "down", err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE ipsec_sites SET status='up', last_up=? WHERE id=?`, nowStr(), id)
	return "up", err
}

// ── 对象库（落库覆盖 Memory 种子）──

// Objects 从库读取三类对象。
func (s *SQLiteStore) Objects(ctx context.Context) (ObjectBundle, error) {
	out := ObjectBundle{Addrs: []AddrObject{}, Services: []ServiceObject{}, Times: []TimeObject{}}
	ar, err := s.db.QueryContext(ctx, `SELECT id,name,kind,value,descr FROM addr_objects ORDER BY id`)
	if err != nil {
		return out, err
	}
	for ar.Next() {
		var o AddrObject
		if err := ar.Scan(&o.ID, &o.Name, &o.Kind, &o.Value, &o.Desc); err != nil {
			ar.Close()
			return out, err
		}
		out.Addrs = append(out.Addrs, o)
	}
	ar.Close()

	sr, err := s.db.QueryContext(ctx, `SELECT id,name,proto,ports,descr FROM service_objects ORDER BY id`)
	if err != nil {
		return out, err
	}
	for sr.Next() {
		var o ServiceObject
		if err := sr.Scan(&o.ID, &o.Name, &o.Proto, &o.Ports, &o.Desc); err != nil {
			sr.Close()
			return out, err
		}
		out.Services = append(out.Services, o)
	}
	sr.Close()

	tr, err := s.db.QueryContext(ctx, `SELECT id,name,kind,spec,descr FROM time_objects ORDER BY id`)
	if err != nil {
		return out, err
	}
	for tr.Next() {
		var o TimeObject
		if err := tr.Scan(&o.ID, &o.Name, &o.Kind, &o.Spec, &o.Desc); err != nil {
			tr.Close()
			return out, err
		}
		out.Times = append(out.Times, o)
	}
	tr.Close()
	return out, nil
}

// SaveAddrObject upsert 地址对象。
func (s *SQLiteStore) SaveAddrObject(ctx context.Context, o AddrObject) (AddrObject, error) {
	if o.ID == "" {
		o.ID = "addr-" + uuid.NewString()[:8]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO addr_objects(id,name,kind,value,descr,updated_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, value=excluded.value, descr=excluded.descr, updated_at=excluded.updated_at`,
		o.ID, o.Name, o.Kind, o.Value, o.Desc, nowStr())
	return o, err
}

// SaveServiceObject upsert 服务对象。
func (s *SQLiteStore) SaveServiceObject(ctx context.Context, o ServiceObject) (ServiceObject, error) {
	if o.ID == "" {
		o.ID = "svc-" + uuid.NewString()[:8]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_objects(id,name,proto,ports,descr,updated_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, proto=excluded.proto, ports=excluded.ports, descr=excluded.descr, updated_at=excluded.updated_at`,
		o.ID, o.Name, o.Proto, o.Ports, o.Desc, nowStr())
	return o, err
}

// SaveTimeObject upsert 时间对象。
func (s *SQLiteStore) SaveTimeObject(ctx context.Context, o TimeObject) (TimeObject, error) {
	if o.ID == "" {
		o.ID = "time-" + uuid.NewString()[:8]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO time_objects(id,name,kind,spec,descr,updated_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, spec=excluded.spec, descr=excluded.descr, updated_at=excluded.updated_at`,
		o.ID, o.Name, o.Kind, o.Spec, o.Desc, nowStr())
	return o, err
}

// DeleteObject 按类别（addr | service | time）删除一个对象。
func (s *SQLiteStore) DeleteObject(ctx context.Context, kind, id string) error {
	tbl := map[string]string{"addr": "addr_objects", "service": "service_objects", "time": "time_objects"}[kind]
	if tbl == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM `+tbl+` WHERE id=?`, id)
	return err
}
