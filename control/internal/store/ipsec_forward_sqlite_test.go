package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// ── 内核转发两列的补列迁移（wave11 行动 10-①）──
//
// 本项目 CLAUDE.md 里那条「补列迁移必须配回填」在这里的答案是**刻意不回填**，
// 而不回填这件事本身需要一条用例守着：
//
//   - `ipsec_sa_state` 每 15s 被 ReplaceIpsecSAStates 全量覆写一次，
//     既有行在一次心跳内就换掉了；
//   - 在那之前读到的空串，语义恰好正确——「这台网关还没报过这一项」。
//     回填任何值都是替一台还没说话的网关编一个答案，而这一格的全部意义就是不编。
//
// 于是真正的风险只剩一个：**读侧 Scan 到 NULL 会直接报错**。
// 少了 COALESCE，升级后第一次打开 IPSec 页面就是 500，而本地全新库测不出来。

// TestIpsecSAStateForwardColumnsMigrateFromOldDB 模拟一次真实升级。
//
// 造一个**没有那两列**的旧库（照升级前的 DDL 建表），再用现在的 OpenSQLite 打开：
// 补列跑完后既有行的新列是 NULL，读侧必须能把它读成空串而不是报错。
func TestIpsecSAStateForwardColumnsMigrateFromOldDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// ① 用升级前的 DDL 造表并塞一行（绕开现在的写入侧，存量库就是这个形状）。
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE ipsec_sa_state (
  site_id TEXT, gateway_id TEXT, state TEXT,
  ike_spi_i TEXT, ike_spi_r TEXT, child_spi_in INTEGER, child_spi_out INTEGER,
  rx_bytes INTEGER, tx_bytes INTEGER, packets_in INTEGER, packets_out INTEGER,
  negotiated TEXT, established_at INTEGER, rekey_at INTEGER, expires_at INTEGER,
  last_error TEXT, last_error_at INTEGER, reported_at INTEGER,
  PRIMARY KEY(site_id, gateway_id)
)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO ipsec_sa_state(site_id,gateway_id,state,
  ike_spi_i,ike_spi_r,child_spi_in,child_spi_out,rx_bytes,tx_bytes,packets_in,packets_out,
  negotiated,established_at,rekey_at,expires_at,last_error,last_error_at,reported_at)
VALUES('old-site','ipsec-1','up','aa','bb',1,2,3,4,5,6,'AES256-GCM',7,8,9,'',0,10)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// ② 现在的代码打开同一个文件：CREATE TABLE IF NOT EXISTS 不会重建，
	//    走的正是 addColumnIfMissing 那条升级路径。
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("打开存量库失败（补列迁移炸了）：%v", err)
	}
	defer st.Close()

	states, err := st.IpsecSAStates(context.Background())
	if err != nil {
		t.Fatalf("读存量行失败——新列是 NULL，读侧少了 COALESCE 就会在这里炸，"+
			"而症状是升级后第一次打开 IPSec 页面直接 500：%v", err)
	}
	if len(states) != 1 {
		t.Fatalf("存量行应还在，得到 %d 行", len(states))
	}
	// ★空串而不是任何"好值"：它的语义就是「这台网关还没报过这一项」。
	if states[0].KernelForward != "" || states[0].KernelForwardDetail != "" {
		t.Fatalf("存量行的新列应读成空串（=未上报），得到 %q / %q",
			states[0].KernelForward, states[0].KernelForwardDetail)
	}
	// 别的列不能被这次迁移动到。
	if states[0].State != "up" || states[0].NegotiatedProposal != "AES256-GCM" {
		t.Fatalf("存量行的其它列被改动了：%+v", states[0])
	}
}

// TestIpsecSAStateForwardRoundTrip 两列的写入-读回。
//
// ★覆盖的是「加了列、加了字段，却忘了往 INSERT 的列清单/占位符里加」这一类：
// 那种漏法编译得过、单元测试也全绿，只是控制台上那一格永远是空的。
func TestIpsecSAStateForwardRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	in := []IpsecSAState{{
		SiteID: "s1", GatewayID: "ipsec-1", State: "up",
		KernelForward:       IpsecForwardOff,
		KernelForwardDetail: "实测本机 IPv4 转发处于关闭状态",
	}}
	if err := st.ReplaceIpsecSAStates(ctx, "ipsec-1", in); err != nil {
		t.Fatal(err)
	}
	got, err := st.IpsecSAStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("应有 1 行，得到 %d", len(got))
	}
	if got[0].KernelForward != IpsecForwardOff {
		t.Fatalf("kernel_forward 没回来：%q", got[0].KernelForward)
	}
	if got[0].KernelForwardDetail != in[0].KernelForwardDetail {
		t.Fatalf("kernel_forward_detail 没回来：%q", got[0].KernelForwardDetail)
	}
}
