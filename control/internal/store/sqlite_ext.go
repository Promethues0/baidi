package store

import (
	"context"

	"github.com/google/uuid"
)

// ★IPSec 站点的落库实现已整体搬到 ipsec_sqlite.go（连同新增的 ipsec_secrets /
// ipsec_sa_state 两张表）。搬走的不只是位置：原先这里的 ToggleIpsecSite 全部实现
// 就是 `UPDATE ipsec_sites SET status='up'`——「建立隧道」等于改一个字符串列，
// 没有任何进程被通知。现在 toggle 只改 enabled（管理意图），运行态由网关回报。

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
