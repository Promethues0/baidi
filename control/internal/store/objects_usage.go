package store

import (
	"context"
	"database/sql"
)

// objTable 把对象 kind 映射到表名（addr|service|time）；未知 kind 返回空串。
func objTable(kind string) string {
	return map[string]string{"addr": "addr_objects", "service": "service_objects", "time": "time_objects"}[kind]
}

// ObjectExists 点查某 kind 的对象 id 是否存在（SELECT 1，避免整库 bundle 扫描）。
// Memory 走种子 bundle 线性扫描即可。
func (m *Memory) ObjectExists(ctx context.Context, kind, id string) (bool, error) {
	b, err := m.Objects(ctx)
	if err != nil {
		return false, err
	}
	switch kind {
	case "addr":
		for _, o := range b.Addrs {
			if o.ID == id {
				return true, nil
			}
		}
	case "service":
		for _, o := range b.Services {
			if o.ID == id {
				return true, nil
			}
		}
	case "time":
		for _, o := range b.Times {
			if o.ID == id {
				return true, nil
			}
		}
	}
	return false, nil
}

// ObjectExists 点查落库版：SELECT 1 FROM <table> WHERE id=?。
func (s *SQLiteStore) ObjectExists(ctx context.Context, kind, id string) (bool, error) {
	tbl := objTable(kind)
	if tbl == "" {
		return false, nil
	}
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM `+tbl+` WHERE id=? LIMIT 1`, id).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// DeleteObjectIfUnreferenced 在单事务内复核引用并删除：被引用则不删、返回 (false,nil)，
// 由调用方回 409。借助 _txlock=immediate 起手取写锁，与并发的资源/IPSec 保存原子互斥（根治 TOCTOU）。
// 引用复核按 kind 收敛到真正可能指向它的列：addr → resources.addr_ref + ipsec local/remote_ref；
// service → resources.svc_ref；time → 暂无消费者（恒可删）。
func (s *SQLiteStore) DeleteObjectIfUnreferenced(ctx context.Context, kind, id string) (bool, error) {
	tbl := objTable(kind)
	if tbl == "" {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var n int
	switch kind {
	case "addr":
		if err := tx.QueryRowContext(ctx,
			`SELECT (SELECT COUNT(*) FROM resources WHERE addr_ref=?)
			       +(SELECT COUNT(*) FROM ipsec_sites WHERE local_ref=? OR remote_ref=?)`,
			id, id, id).Scan(&n); err != nil {
			return false, err
		}
	case "service":
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM resources WHERE svc_ref=?`, id).Scan(&n); err != nil {
			return false, err
		}
	case "time":
		n = 0 // 时间对象暂无落库消费者
	}
	if n > 0 {
		return false, nil // 被引用：交由调用方回 409（带 consumers 清单）
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+tbl+` WHERE id=?`, id); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ── 对象库「被引用」反查（复用闭环）──
// 把地址 / 服务对象被哪些消费者（资源策略 / IPSec 站点）引用聚合成
// objectID → []ObjectRef，供对象库展示「被引用 N」与删除守卫（被引用者拒删 409）。

// ObjectRef 一个引用了某对象的消费者。
type ObjectRef struct {
	Kind string `json:"kind"` // resource | ipsec
	ID   string `json:"id"`   // 消费者 id（资源 id / 站点 id）
	Name string `json:"name"` // 消费者显示名
}

// ObjectUsage 返回 objectID → 引用它的消费者清单。
// Memory 种子无落库引用关系，返回空表；SQLiteStore 覆盖为真实聚合。
func (m *Memory) ObjectUsage(_ context.Context) (map[string][]ObjectRef, error) {
	return map[string][]ObjectRef{}, nil
}

// ObjectUsage 从库聚合资源策略（addr_ref/svc_ref）与 IPSec 站点（local_ref/remote_ref）的引用。
func (s *SQLiteStore) ObjectUsage(ctx context.Context) (map[string][]ObjectRef, error) {
	usage := map[string][]ObjectRef{}
	add := func(objID, kind, id, name string) {
		if objID == "" {
			return
		}
		usage[objID] = append(usage[objID], ObjectRef{Kind: kind, ID: id, Name: name})
	}

	rrows, err := s.db.QueryContext(ctx, `SELECT id,name,COALESCE(addr_ref,''),COALESCE(svc_ref,'') FROM resources`)
	if err != nil {
		return nil, err
	}
	for rrows.Next() {
		var id, name, addrRef, svcRef string
		if err := rrows.Scan(&id, &name, &addrRef, &svcRef); err != nil {
			rrows.Close()
			return nil, err
		}
		add(addrRef, "resource", id, name)
		add(svcRef, "resource", id, name)
	}
	rrows.Close()
	if err := rrows.Err(); err != nil {
		return nil, err
	}

	irows, err := s.db.QueryContext(ctx, `SELECT id,name,COALESCE(local_ref,''),COALESCE(remote_ref,'') FROM ipsec_sites`)
	if err != nil {
		return nil, err
	}
	for irows.Next() {
		var id, name, localRef, remoteRef string
		if err := irows.Scan(&id, &name, &localRef, &remoteRef); err != nil {
			irows.Close()
			return nil, err
		}
		add(localRef, "ipsec", id, name)
		add(remoteRef, "ipsec", id, name)
	}
	irows.Close()
	return usage, irows.Err()
}
