package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
)

// ── IPSec 三张表的落库实现 ──
//
// 读路径的一条硬约定：**永远显式列出列名，绝不 SELECT ***。
// ipsec_secrets 与 ipsec_sites 之间有 LEFT JOIN，一个 `SELECT *` 就会把密文
// 顺手带进站点清单的 DTO；密文本身没有密钥解不开，但让它出现在一个 admin
// 接口的响应体里，等于把「分表隔离」这层设计在第一次重构时就还回去了。

// ipsecSiteCols 站点配置列（顺序与 scanIpsecSites 严格对应）。
//
// 新列一律 COALESCE：旧库经 ALTER 补列后这些格子是 NULL，
// 直接 Scan 进 string/int 会返回 "converting NULL to string is unsupported"——
// 症状是整个站点清单接口 500，而不是某一行缺字段，排查方向很容易跑偏。
const ipsecSiteCols = `s.id, s.name, COALESCE(s.gateway_id,''), COALESCE(s.enabled,0),
 s.peer, s.local_subnet, s.remote_subnet, COALESCE(s.local_id,''), COALESCE(s.remote_id,''),
 s.ike_version, s.auth, s.suite, s.phase1, s.phase2, s.pfs, s.pq_hybrid,
 COALESCE(s.psk_version,0), COALESCE(s.peer_nat_port,0), COALESCE(s.local_ref,''), COALESCE(s.remote_ref,''),
 COALESCE(k.fingerprint,'')`

// ipsecSiteFrom 站点 + 密钥指纹的联表。只取 fingerprint，密文列一个字都不带出来。
const ipsecSiteFrom = ` FROM ipsec_sites s LEFT JOIN ipsec_secrets k ON k.site_id = s.id`

func scanIpsecSites(rows *sql.Rows) ([]IpsecSite, error) {
	defer rows.Close()
	out := []IpsecSite{}
	for rows.Next() {
		var it IpsecSite
		var p1, p2, fp string
		var enabled, pfs, pq int
		if err := rows.Scan(&it.ID, &it.Name, &it.GatewayID, &enabled,
			&it.Peer, &it.LocalSubnet, &it.RemoteSubnet, &it.LocalID, &it.RemoteID,
			&it.IkeVersion, &it.Auth, &it.Suite, &p1, &p2, &pfs, &pq,
			&it.PSKVersion, &it.PeerNATPort, &it.LocalRef, &it.RemoteRef, &fp); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(p1), &it.Phase1)
		_ = json.Unmarshal([]byte(p2), &it.Phase2)
		it.Enabled = enabled == 1
		it.Pfs = pfs == 1
		it.PqHybrid = pq == 1
		// 指纹只回前 8 位十六进制：够运维核对两端是不是同一把，又不给出完整的
		// 比对口令。HasPSK 由指纹是否为空推出——密文列压根没进这个查询。
		it.HasPSK = fp != ""
		if len(fp) > 8 {
			fp = fp[:8]
		}
		it.PSKFingerprint = fp
		out = append(out, it)
	}
	return out, rows.Err()
}

// Ipsec 从库读取全部 IPSec 站点配置（admin 清单用）。
//
// ★不再读 status / rx_bytes / tx_bytes / last_up 四列：它们已冻结为兼容残留，
// 值分别是「toggle 直接写的 up」与「播种时灌进去就没变过的常量」。
// 运行态一律去 IpsecSAStates 读，两者在 API 层合并。
func (s *SQLiteStore) Ipsec(ctx context.Context) ([]IpsecSite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ipsecSiteCols+ipsecSiteFrom+` ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	return scanIpsecSites(rows)
}

// IpsecSitesForGateway 只返回归属该网关的站点（最小披露）。
//
// ★精确相等匹配，不做「gateway_id 为空就发给所有人」的兜底。兜底会让两台网关
// 同时去建同一条 SA：双方各建一条、互相 rekey 与 Delete，表现为隧道反复抖动，
// 而日志两边都只说「对端删了我的 SA」。宁可未指派的站点一条都不发（fail-closed），
// 由 API 层对「已启用但未指派网关」显式回一条 configWarning 把静默失效摊开。
func (s *SQLiteStore) IpsecSitesForGateway(ctx context.Context, gatewayID string) ([]IpsecSite, error) {
	if gatewayID == "" {
		return []IpsecSite{}, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+ipsecSiteCols+ipsecSiteFrom+` WHERE s.gateway_id = ? ORDER BY s.id`, gatewayID)
	if err != nil {
		return nil, err
	}
	return scanIpsecSites(rows)
}

// upsertIpsecSite 配置型 upsert：只写配置列。
//
// ★ON CONFLICT 分支里**没有** psk_version：它由 SaveIpsecSecret 独占自增。
// 若在这里跟着表单快照一起回写，管理员在「改个站点名」时就会把版本号退回旧值，
// 网关据此认为密钥没变而继续用本地缓存——改了 PSK 却不生效，且两端都不报错。
//
// 同理没有 status/rx_bytes/tx_bytes/last_up：那四列已冻结，INSERT 时写中性值
// 只是为了让直接翻库的人看到「这里是空的」，而不是一串会被误读为统计值的数字。
func (s *SQLiteStore) upsertIpsecSite(ctx context.Context, it IpsecSite) error {
	p1, _ := json.Marshal(it.Phase1)
	p2, _ := json.Marshal(it.Phase2)
	_, err := s.db.ExecContext(ctx, `INSERT INTO ipsec_sites(
  id,name,gateway_id,enabled,peer,local_subnet,remote_subnet,local_id,remote_id,
  ike_version,auth,suite,phase1,phase2,pfs,pq_hybrid,psk_version,peer_nat_port,
  status,rx_bytes,tx_bytes,last_up,local_ref,remote_ref,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,'',0,0,'—',?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, gateway_id=excluded.gateway_id,
  enabled=excluded.enabled, peer=excluded.peer, local_subnet=excluded.local_subnet,
  remote_subnet=excluded.remote_subnet, local_id=excluded.local_id, remote_id=excluded.remote_id,
  ike_version=excluded.ike_version, auth=excluded.auth, suite=excluded.suite,
  phase1=excluded.phase1, phase2=excluded.phase2, pfs=excluded.pfs, pq_hybrid=excluded.pq_hybrid,
  peer_nat_port=excluded.peer_nat_port,
  local_ref=excluded.local_ref, remote_ref=excluded.remote_ref, updated_at=excluded.updated_at`,
		it.ID, it.Name, it.GatewayID, b2i(it.Enabled), it.Peer, it.LocalSubnet, it.RemoteSubnet,
		it.LocalID, it.RemoteID, it.IkeVersion, it.Auth, it.Suite,
		string(p1), string(p2), b2i(it.Pfs), b2i(it.PqHybrid), it.PeerNATPort,
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
	if err := s.upsertIpsecSite(ctx, it); err != nil {
		return IpsecSite{}, err
	}
	// 回读而不是回显入参：psk_version / hasPsk 是库里的权威值，
	// 入参里那两个字段来自表单，返回它们会让控制台误以为密钥被这次保存改过。
	sites, err := s.ipsecSiteByID(ctx, it.ID)
	if err != nil || len(sites) == 0 {
		return it, err
	}
	return sites[0], nil
}

func (s *SQLiteStore) ipsecSiteByID(ctx context.Context, id string) ([]IpsecSite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ipsecSiteCols+ipsecSiteFrom+` WHERE s.id = ?`, id)
	if err != nil {
		return nil, err
	}
	return scanIpsecSites(rows)
}

// DeleteIpsecSite 删除一条站点，连带清掉它的密钥行与运行态行（单事务）。
//
// ★三张表必须同生共死。只删配置行的症状很隐蔽：ipsec_sa_state 里那条最后一次
// up 的残影会一直留着，等有人重新建一条**同 id** 的站点（uuid 前 8 位有概率复用，
// 或干脆手填同名 id），界面上就会出现「刚建好的站点已经连上了」，
// 连带流量数字也是上一条站点的。密钥行不删则更糟：新站点直接继承了旧密钥。
func (s *SQLiteStore) DeleteIpsecSite(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM ipsec_secrets WHERE site_id=?`,
		`DELETE FROM ipsec_sa_state WHERE site_id=?`,
		`DELETE FROM ipsec_sites WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetIpsecEnabled 只改管理意图（toggle 的全部语义）。
//
// ★旧实现在这里写的是 `UPDATE ipsec_sites SET status='up', last_up=now`——
// 即「建立隧道」等于把一个字符串列改成 'up'。没有任何进程被通知、没有任何网络动作。
// 现在这里只表达意图，真正的 up/down 由网关经 ReplaceIpsecSAStates 回报。
func (s *SQLiteStore) SetIpsecEnabled(ctx context.Context, id string, enabled bool) (IpsecSite, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE ipsec_sites SET enabled=?, updated_at=? WHERE id=?`, b2i(enabled), nowStr(), id)
	if err != nil {
		return IpsecSite{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return IpsecSite{}, ErrIpsecSiteNotFound
	}
	sites, err := s.ipsecSiteByID(ctx, id)
	if err != nil {
		return IpsecSite{}, err
	}
	if len(sites) == 0 {
		return IpsecSite{}, ErrIpsecSiteNotFound
	}
	return sites[0], nil
}

// ── PSK 密文行 ──

// SaveIpsecSecret 写密文 + 自增版本号（单事务）。返回新版本号。
//
// ★版本号与密文必须原子同进同退。分成两条语句执行时的失败形态是：
// 版本涨了、密文没换 → 网关看到新版本去取密钥，取回来的还是旧的，
// 但它已经把本地版本记成新的，于是永远不会再取一次。AUTH 失败，
// 而两端日志都只说「认证失败」，没有任何线索指向控制面写了一半。
func (s *SQLiteStore) SaveIpsecSecret(ctx context.Context, sec IpsecSecret) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE ipsec_sites SET psk_version = COALESCE(psk_version,0) + 1, updated_at=? WHERE id=?`,
		nowStr(), sec.SiteID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrIpsecSiteNotFound
	}
	var version int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(psk_version,0) FROM ipsec_sites WHERE id=?`, sec.SiteID).Scan(&version); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ipsec_secrets(site_id,alg,nonce,cipher,fingerprint,version,updated_at)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(site_id) DO UPDATE SET alg=excluded.alg, nonce=excluded.nonce, cipher=excluded.cipher,
  fingerprint=excluded.fingerprint, version=excluded.version, updated_at=excluded.updated_at`,
		sec.SiteID, sec.Alg, sec.Nonce, sec.Cipher, sec.Fingerprint, version, nowStr()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}

// IpsecSecret 取一条站点的 PSK 密文行。解密在 api 层用 secret.Box 完成——
// store 层刻意不持有密钥，这样「读库」与「解密」是两件必须分别拿到的东西。
func (s *SQLiteStore) IpsecSecret(ctx context.Context, siteID string) (IpsecSecret, bool, error) {
	var sec IpsecSecret
	err := s.db.QueryRowContext(ctx,
		`SELECT site_id,alg,nonce,cipher,fingerprint,version,updated_at FROM ipsec_secrets WHERE site_id=?`,
		siteID).Scan(&sec.SiteID, &sec.Alg, &sec.Nonce, &sec.Cipher, &sec.Fingerprint, &sec.Version, &sec.UpdatedAt)
	if err == sql.ErrNoRows {
		return IpsecSecret{}, false, nil
	}
	if err != nil {
		return IpsecSecret{}, false, err
	}
	return sec, true, nil
}

// ── 运行态（网关权威）──

const ipsecSAStateCols = `site_id,gateway_id,state,ike_spi_i,ike_spi_r,child_spi_in,child_spi_out,
 rx_bytes,tx_bytes,packets_in,packets_out,negotiated,established_at,rekey_at,expires_at,
 last_error,last_error_at,reported_at`

// IpsecSAStates 全部网关回报的运行态行。
func (s *SQLiteStore) IpsecSAStates(ctx context.Context) ([]IpsecSAState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+ipsecSAStateCols+` FROM ipsec_sa_state ORDER BY site_id, gateway_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IpsecSAState{}
	for rows.Next() {
		var st IpsecSAState
		var spiIn, spiOut int64 // SPI 是 uint32；SQLite 只有有符号整数，中转一次再收窄
		if err := rows.Scan(&st.SiteID, &st.GatewayID, &st.State, &st.IKESPIi, &st.IKESPIr,
			&spiIn, &spiOut, &st.RxBytes, &st.TxBytes, &st.PacketsIn, &st.PacketsOut,
			&st.NegotiatedProposal, &st.EstablishedAt, &st.RekeyAt, &st.ExpiresAt,
			&st.LastError, &st.LastErrorAt, &st.ReportedAt); err != nil {
			return nil, err
		}
		st.ChildSPIIn = uint32(spiIn)
		st.ChildSPIOut = uint32(spiOut)
		out = append(out, st)
	}
	return out, rows.Err()
}

// ReplaceIpsecSAStates 全量覆写某网关名下的运行态（单事务：先删后插）。
//
// ★gateway_id 一律用参数里的值覆盖每一行，**不信任 states 里自带的 GatewayID**。
// 不覆盖的话，一台被攻陷（或只是配错 id）的 IPSec 网关就能把别的网关的站点
// 全部写成 failed，界面上看起来像对端集体故障——一个纯粹的伪造运行态通道。
//
// 先删后插也是刻意的：网关不再回报的站点行必须消失。增量 upsert 会让一条
// 已被删除的站点永远停在最后一次 up，而那正是「界面显示在线、实际早就没了」。
func (s *SQLiteStore) ReplaceIpsecSAStates(ctx context.Context, gatewayID string, states []IpsecSAState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM ipsec_sa_state WHERE gateway_id=?`, gatewayID); err != nil {
		return err
	}
	for _, st := range states {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ipsec_sa_state(`+ipsecSAStateCols+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			st.SiteID, gatewayID, st.State, st.IKESPIi, st.IKESPIr,
			int64(st.ChildSPIIn), int64(st.ChildSPIOut),
			st.RxBytes, st.TxBytes, st.PacketsIn, st.PacketsOut,
			st.NegotiatedProposal, st.EstablishedAt, st.RekeyAt, st.ExpiresAt,
			st.LastError, st.LastErrorAt, st.ReportedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// backfillIpsecEnabled 回填 ipsec_sites.enabled（与 backfillAppResourceID 并列，
// 原因见 sqlite.go 里那条注释——补列迁移只加列、不填值）。
//
// ★不回填的后果与 apps.resource_id 那次静默断裂一模一样：既有库的 enabled 永久为
// NULL，网关侧 `WHERE enabled=1` 拉到**空站点列表**，于是每一条已配好的隧道都不再
// 被建立，而控制台、网关日志、审计三处**全程零报错**——只是「什么都没发生」。
//
// 映射用旧的 status 列：旧实现里 status='up' 的唯一来源就是管理员点过「启用」，
// 所以它恰好就是当时的管理意图，是最忠实的还原。其余（down/connecting/空）一律 0。
func (s *SQLiteStore) backfillIpsecEnabled() error {
	if _, err := s.db.Exec(
		`UPDATE ipsec_sites SET enabled = CASE WHEN status='up' THEN 1 ELSE 0 END WHERE enabled IS NULL`); err != nil {
		return err
	}
	return s.backfillIpsecIdentity()
}

// backfillIpsecIdentity 回填种子站点的 gateway_id / local_id / remote_id。
//
// ★这三列与 enabled 同批补进来，只回填 enabled 是漏的：既有库升级上来后
// gateway_id 永久为 NULL，而控制面按 gateway_id == 证书 CN 精确过滤下发——
// 网关拉到的是**空列表而不是错误**，站点安静地永远 down。
// （local_id/remote_id 为空至少是 fail loud 的：网关装载期拒绝并回报 LastError。）
//
// ★只回填**种子站点**：它们的"正确值"是已知的（就是 Memory.Ipsec 里那份）。
// 管理员自建的老站点无从推断 gateway_id，猜一个填进去比留空更糟——留空时
// ipsecConfigWarning 会明确报「未指派承载网关」，管理员在控制台上就能补。
func (s *SQLiteStore) backfillIpsecIdentity() error {
	for _, seed := range []struct{ id, gw, local, remote string }{
		{"site-sh", "ipsec-1", "hq.baidi", "sh.baidi"},
		{"site-gz", "ipsec-1", "hq.baidi", "gz.baidi"},
		{"site-cd", "ipsec-1", "hq.baidi", "cd.baidi"},
	} {
		// 逐列 COALESCE：只填空值，绝不覆盖管理员已经改过的字段。
		if _, err := s.db.Exec(`UPDATE ipsec_sites SET
  gateway_id = COALESCE(NULLIF(gateway_id,''), ?),
  local_id   = COALESCE(NULLIF(local_id,''),   ?),
  remote_id  = COALESCE(NULLIF(remote_id,''),  ?)
WHERE id = ?`, seed.gw, seed.local, seed.remote, seed.id); err != nil {
			return err
		}
	}
	return nil
}
