package store

import (
	"context"
	"database/sql"
	"strings"

	"baidi.dev/control/internal/standby"
)

// 温备节点台账的持久化（表 standby_nodes，见 migrate）。
//
// ★为什么落库而不是像网关在线登记那样放内存：网关的在线态**本来就该随主机重启归零**
// （心跳 15s 一轮，重启后几秒就重建了）；备机的「上次成功同步在什么时候」不是这种东西——
// 主机重启一次就把它清空的话，页面会在重启后显示「从未成功同步」，而那正是最容易
// 被误读成"备机坏了"的时刻，运维会去动一台其实好好的备机。
//
// ★新表无需回填（区别于补列迁移）：既有库此前根本没有温备这回事，空表就是正确初态，
// 而且空表的语义（"没配备机"）恰好也是既有部署的真实形态。

// StandbyStore 温备台账（可选能力：纯内存演示栈没有它，端点如实回 503）。
type StandbyStore interface {
	StandbyNodes(ctx context.Context) ([]standby.Node, error)
	// NoteStandbyPull 记一次「备机来拉过备份」（主机直接观测到的事实）。
	// 它**不动 last_sync_at**：发出去字节 ≠ 对面校验通过并落盘了。
	NoteStandbyPull(ctx context.Context, nodeID, addr string, at int64) error
	// SaveStandbyStatus 记一次备机回报。ok=true 时把 syncedAt 写进 last_sync_at；
	// ok=false 时**只记失败详情、绝不推进 last_sync_at**——推进了就等于把
	// 「拉失败」显示成「刚同步过」，方向完全反了。
	SaveStandbyStatus(ctx context.Context, n standby.Node, ok bool, syncedAt int64) error
}

const standbyCols = `node_id,addr,interval_sec,last_pull_at,last_sync_at,
backup_version,backup_created_at,backup_sha256,last_status,last_detail,updated_at`

// StandbyNodes 全部已登记备机，按 node_id 排序（顺序稳定，页面不跳）。
func (s *SQLiteStore) StandbyNodes(ctx context.Context) ([]standby.Node, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+standbyCols+` FROM standby_nodes ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []standby.Node{}
	for rows.Next() {
		var n standby.Node
		// 四个时间/间隔列可为 NULL：NULL = 「这件事一次都没发生过」。
		// 用 sql.NullInt64 接而不是让 driver 塞 0——虽然本层随后把 NULL 折成 0，
		// 但 0 在 standby.Node 的契约里就是"从未"，两者语义一致，不存在补 0 掩盖事实的问题。
		var iv, pull, sync, upd sql.NullInt64
		var addr, ver, created, sha, st, detail sql.NullString
		if err := rows.Scan(&n.NodeID, &addr, &iv, &pull, &sync,
			&ver, &created, &sha, &st, &detail, &upd); err != nil {
			return nil, err
		}
		n.Addr, n.BackupVersion, n.BackupCreatedAt = addr.String, ver.String, created.String
		n.BackupSHA256, n.LastStatus, n.LastDetail = sha.String, st.String, detail.String
		n.IntervalSec = int(iv.Int64)
		n.LastPullAt, n.LastSyncAt, n.UpdatedAt = pull.Int64, sync.Int64, upd.Int64
		out = append(out, n)
	}
	return out, rows.Err()
}

// NoteStandbyPull 登记一次拉取（首次出现的节点在这里建行）。
func (s *SQLiteStore) NoteStandbyPull(ctx context.Context, nodeID, addr string, at int64) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return sql.ErrNoRows
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO standby_nodes(node_id,addr,last_pull_at,updated_at) VALUES(?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET
  last_pull_at=excluded.last_pull_at,
  updated_at=excluded.updated_at,
  -- addr 只在备机真报过时才更新：拉取请求里没有它，用空串覆盖会把已知落点抹掉
  addr=CASE WHEN excluded.addr='' THEN standby_nodes.addr ELSE excluded.addr END`,
		nodeID, addr, at, at)
	return err
}

// SaveStandbyStatus 落一次备机回报。
func (s *SQLiteStore) SaveStandbyStatus(ctx context.Context, n standby.Node, ok bool, syncedAt int64) error {
	nodeID := strings.TrimSpace(n.NodeID)
	if nodeID == "" {
		return sql.ErrNoRows
	}
	status := "fail"
	var sync any // NULL = 保持原值（见下方 COALESCE）
	if ok {
		status = "ok"
		sync = syncedAt
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO standby_nodes(node_id,addr,interval_sec,last_sync_at,
  backup_version,backup_created_at,backup_sha256,last_status,last_detail,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET
  addr=excluded.addr,
  interval_sec=excluded.interval_sec,
  -- 失败回报传 NULL：保留上一次成功的时间戳，页面才能如实显示「上次成功是 X，之后一直在失败」
  last_sync_at=COALESCE(excluded.last_sync_at, standby_nodes.last_sync_at),
  -- 备份头信息同理：失败那次没有新的头可报，不能用空串把上一次的抹成"未知版本"
  backup_version=CASE WHEN excluded.backup_version='' THEN standby_nodes.backup_version ELSE excluded.backup_version END,
  backup_created_at=CASE WHEN excluded.backup_created_at='' THEN standby_nodes.backup_created_at ELSE excluded.backup_created_at END,
  backup_sha256=CASE WHEN excluded.backup_sha256='' THEN standby_nodes.backup_sha256 ELSE excluded.backup_sha256 END,
  last_status=excluded.last_status,
  last_detail=excluded.last_detail,
  updated_at=excluded.updated_at`,
		nodeID, n.Addr, n.IntervalSec, sync,
		n.BackupVersion, n.BackupCreatedAt, n.BackupSHA256, status, n.LastDetail, syncedAt)
	return err
}
