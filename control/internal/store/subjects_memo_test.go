package store

import (
	"context"
	"path/filepath"
	"testing"
)

func memoStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "memo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// 挂了备忘的 ctx 上，SubjectIndex 只真算一次——且第二次拿到的必须是同一份，
// 否则同一次请求内的两处判定可能基于不同的展开。
func TestSubjectIndex备忘一次请求内只算一次(t *testing.T) {
	st := memoStore(t)
	ctx := context.Background()

	org, err := st.SaveOrgUnit(ctx, Org{Name: "研发"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, DirUser{Name: "甲", Account: "jia", OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}

	mctx := WithSubjectIndexMemo(ctx)
	a, err := st.SubjectIndex(mctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.OrgAccounts[org.ID]) != 1 {
		t.Fatalf("第一次应展开出 1 个账号，实得 %v", a.OrgAccounts[org.ID])
	}

	// 中途新增一个人：备忘生效的话第二次仍是旧快照（同一请求内一致）。
	if _, err := st.CreateUser(ctx, DirUser{Name: "乙", Account: "yi", OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	b, err := st.SubjectIndex(mctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.OrgAccounts[org.ID]) != 1 {
		t.Fatalf("同一请求内两次展开必须一致，实得 %v——"+
			"不一致时「应用可不可达」与「有没有这条路由」会在同一份剖面里自相矛盾",
			b.OrgAccounts[org.ID])
	}
}

// ★跨请求绝不缓存：这是 SubjectIndex 的安全属性（撤权必须立即生效）。
// 不挂备忘的 ctx 每次都要现算。
func TestSubjectIndex跨请求不缓存(t *testing.T) {
	st := memoStore(t)
	ctx := context.Background()

	org, err := st.SaveOrgUnit(ctx, Org{Name: "研发"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, DirUser{Name: "甲", Account: "jia", OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	if a, _ := st.SubjectIndex(ctx); len(a.OrgAccounts[org.ID]) != 1 {
		t.Fatalf("实得 %v", a.OrgAccounts[org.ID])
	}

	// 把人移出组织 —— 下一次（另一个"请求"）必须立刻看不到他。
	if _, err := st.CreateUser(ctx, DirUser{Name: "乙", Account: "yi", OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	b, _ := st.SubjectIndex(ctx)
	if len(b.OrgAccounts[org.ID]) != 2 {
		t.Fatalf("未挂备忘的 ctx 必须每次现算，实得 %v——"+
			"一旦跨请求缓存，撤权与生效之间就出现一段谁都说不清多长的窗口",
			b.OrgAccounts[org.ID])
	}

	// 每个"请求"各挂各的备忘，互不串味。
	c, _ := st.SubjectIndex(WithSubjectIndexMemo(ctx))
	if len(c.OrgAccounts[org.ID]) != 2 {
		t.Fatalf("新请求的备忘不该看到上一个请求的快照，实得 %v", c.OrgAccounts[org.ID])
	}
}

// 重复挂载不套第二层（否则内层那次仍会各算各的，备忘等于没加）。
func TestSubjectIndex备忘重复挂载幂等(t *testing.T) {
	ctx := WithSubjectIndexMemo(context.Background())
	if WithSubjectIndexMemo(ctx) != ctx {
		t.Fatal("重复挂载应原样返回，否则内层调用会绕开外层备忘")
	}
}
