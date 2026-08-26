package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// 删除受控资源此前没有存在性检查、没有影响面回执：
//   · SQLite 对匹配不到行的 DELETE **不报错** → 删一个早就没了的资源照样回 200，
//     审计里因此出现一件没发生过的事；
//   · 引用它的应用变成悬空引用，管理台把那些应用折叠成「未关联资源」——
//     **与从未关联过完全同形**，没人能看出这是删资源造成的；
//   · 该资源上的 JIT 授予留在库里，授权清单显示的是失真状态。
// 与应用下架（handleDeleteApp）同一条纪律：不级联删，但必须把连带影响当面说清。
func TestDeleteResourceReportsBlastRadius(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()

	if code, out := f.saveResource(map[string]any{
		"id": "res-doomed", "name": "待删资源", "backend": "10.20.1.10:8080",
	}); code != http.StatusOK {
		t.Fatalf("建资源 %d: %v", code, out)
	}
	// 两个应用引用它
	for _, name := range []string{"应用甲", "应用乙"} {
		if code, out := doJSON(t, f.h, "POST", "/api/v1/apps", adminToken(), map[string]any{
			"name": name, "addr": "10.20.1.10:8080", "mode": "tunnel",
			"category": "dev", "resourceId": "res-doomed",
		}); code != http.StatusCreated {
			t.Fatalf("发布应用 %s: %d %v", name, code, out)
		}
	}

	code, out := doJSON(t, f.h, "DELETE", "/api/v1/resources/res-doomed", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("删除应成功，实得 %d: %v", code, out)
	}
	apps, _ := out["apps"].([]any)
	if len(apps) != 2 {
		t.Errorf("回执必须列出仍引用它的 2 个应用（删后它们会显示为「未关联资源」，"+
			"与从未关联过同形），实得 %v", out["apps"])
	}
	note, _ := out["note"].(string)
	for _, want := range []string{"未关联资源", "应用甲"} {
		if !strings.Contains(note, want) {
			t.Errorf("回执要说清连带影响，缺 %q：%s", want, note)
		}
	}

	// ★不级联删：应用还在（删了它们才是替管理员做他没要求的事）。
	ab, err := f.st.Apps(ctx)
	if err != nil {
		t.Fatalf("读应用: %v", err)
	}
	n := 0
	for _, a := range ab.Apps {
		if a.Name == "应用甲" || a.Name == "应用乙" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("删资源不该级联删应用（同应用下架不删资源的纪律），实得还剩 %d 个", n)
	}

	// 审计要写出影响面，否则事后无从知道当初删掉了什么
	b, _ := f.st.Audit(ctx)
	var hit bool
	for _, e := range b.Logs {
		if strings.Contains(e.Event, "删除受控资源 res-doomed") && strings.Contains(e.Event, "应用") {
			hit = true
		}
	}
	if !hit {
		t.Error("审计要记下连带影响（几个应用受影响、有无未回收的 JIT 授予）")
	}
}

// 删一个不存在的资源必须回 404：回 200 会落一条「删除受控资源 xxx」的审计，
// 而库里根本没有这一行——审计里出现一件没发生过的事。
func TestDeleteMissingResourceIs404(t *testing.T) {
	f := newIsoFixture(t)
	code, _ := doJSON(t, f.h, "DELETE", "/api/v1/resources/res-从来没有过", adminToken(), nil)
	if code != http.StatusNotFound {
		t.Fatalf("删不存在的资源应 404，实得 %d", code)
	}
	// 重复删除同样要 404（第一次成功、第二次就不该再"成功"一遍）
	if code, _ := f.saveResource(map[string]any{
		"id": "res-once", "name": "一次性", "backend": "10.20.1.10:8080",
	}); code != http.StatusOK {
		t.Fatal("建资源失败")
	}
	if code, _ := doJSON(t, f.h, "DELETE", "/api/v1/resources/res-once", adminToken(), nil); code != http.StatusOK {
		t.Fatalf("首次删除应 200，实得 %d", code)
	}
	if code, _ := doJSON(t, f.h, "DELETE", "/api/v1/resources/res-once", adminToken(), nil); code != http.StatusNotFound {
		t.Errorf("重复删除应 404，实得 %d", code)
	}
}
