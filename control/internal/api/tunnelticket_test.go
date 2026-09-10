package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
)

// ── wave11 行动 3：L4 隧道身份票据的控制面这一半 ──
//
// 被修的坏形态：隧道连接**没有身份**。网关只能按源 IP 反查（spa.Allowlist 以源 IP 为
// 唯一键、后敲门者整条覆盖 user），于是同一出口下任意主机在放行窗内直连隧道口，
// 就继承了最后那个敲门者的全部资源授权。控制面这一半是"跑完五道闸之后，
// 把结论签成一张可携带的票"。

// knockGrant 调一次 /knock-token，返回响应体。
func knockGrant(t *testing.T, h http.Handler, account string) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/knock-token", userToken(account), nil)
	if code != http.StatusOK {
		t.Fatalf("knock-token http %d，want 200：%v", code, out)
	}
	return out
}

// claimsOf 不验签地解出 payload（只用来读 use/name 这类字段做断言）。
func claimsOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("不是一个 JWT：%q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("解 payload：%v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解 claims：%v", err)
	}
	return out
}

// headerOf 解出 JWT 头（读 kid，用来断言两张票是**不同密钥**签的）。
func headerOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatalf("解 header：%v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解 header：%v", err)
	}
	return out
}

// TestKnockTokenAlsoIssuesTunnelTicket 敲门令牌与隧道票据必须同一次调用签出，且是两把密钥。
func TestKnockTokenAlsoIssuesTunnelTicket(t *testing.T) {
	h := newTestServer(t)
	out := knockGrant(t, h, "li.fang")

	ticket, _ := out["tunnelTicket"].(string)
	if ticket == "" {
		t.Fatal("★/knock-token 必须同时下发隧道身份票据：少了它，严格网关会拒掉每一条隧道连接；" +
			"而在网关**没开**严格模式的部署上，症状是身份悄悄退回按源 IP 反查")
	}
	if ttl, _ := out["tunnelTicketExpiresIn"].(float64); ttl <= 0 {
		t.Errorf("要下发票据寿命供客户端安排刷新，得 %v", out["tunnelTicketExpiresIn"])
	}

	c := claimsOf(t, ticket)
	if c["use"] != auth.UseTunnel {
		t.Errorf("票据用途应是 %q，得 %v", auth.UseTunnel, c["use"])
	}
	if c["name"] != "li.fang" {
		t.Errorf("票据必须自证账号（网关据此鉴权），得 %v", c["name"])
	}
	// ★不带 jti：这张票刻意不做一次性（理由在 gateway/internal/proxy 的 checkTunnelTicket）。
	// 签一个没人去重的 jti 只会让下一个人以为一次性已经做了。
	if _, has := c["jti"]; has {
		t.Error("隧道票据不该带 jti——它不做一次性去重，带上等于给出一个假的一次性承诺")
	}
	// ★不绑 gw：控制面不知道客户端会拨哪台落点（剖面给的是有序清单，客户端逐个试）。
	// 绑一个猜的值会让故障转移在切换那一刻被票据自己挡住。
	if _, has := c["gw"]; has {
		t.Error("隧道票据不该绑网关：多活故障转移下客户端随时可能切落点")
	}

	// 两张票必须由**不同密钥**签出（kid 不同）。合用一把的话，一张沿链路广播的
	// UDP 敲门令牌就能直接当隧道身份用——而那种令牌的截获门槛低得多。
	knockTok, _ := out["token"].(string)
	if kidT, kidK := headerOf(t, ticket)["kid"], headerOf(t, knockTok)["kid"]; kidT == kidK {
		t.Errorf("★隧道票据与敲门令牌是同一把密钥签的（kid=%v）：密钥分离没有生效", kidT)
	}
}

// TestTunnelTicketRejectedAsBearer 用途闸的**控制面入站**这一向：隧道票据不能调 API。
//
// 少了这道，一张 5 分钟的隧道票就是该账号 5 分钟的全量 API 会话（admin 的票就是全权管理台），
// 而且能拿它再调一次 /knock-token 给自己续签，"短时效"被结构性抵消。
func TestTunnelTicketRejectedAsBearer(t *testing.T) {
	h := newTestServer(t)
	ticket, _ := knockGrant(t, h, "li.fang")["tunnelTicket"].(string)
	if ticket == "" {
		t.Fatal("先要能拿到票据")
	}
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/knock-token", "/api/v1/client/profile"} {
		method := "GET"
		if path == "/api/v1/knock-token" {
			method = "POST"
		}
		code, out := doJSON(t, h, method, path, ticket, nil)
		if code != http.StatusForbidden {
			t.Errorf("★隧道票据当 Bearer 调 %s 应 403，得 %d：%v", path, code, out)
		}
	}
}

// TestTunnelTicketNotIssuedWhenGatesReject 闸拒掉的账号拿不到票据（票和令牌同生同死）。
//
// ★这条钉的是"票据是那五道闸的结论"这件事本身：若哪天有人把签票挪到闸之前，
// 被强制下线 / 账号禁用 / 终端不合规的人仍会拿到一张能进隧道的票，而敲门被拒
// 只是让他多等一个放行窗口——同出口有别人在线时，那个窗口本来就是开着的。
func TestTunnelTicketNotIssuedWhenGatesReject(t *testing.T) {
	h := newTestServer(t)
	// zhao.min 是种子里 locked 的账号，ext.zhou 是 disabled。
	for _, account := range []string{"zhao.min", "ext.zhou"} {
		code, out := doJSON(t, h, "POST", "/api/v1/knock-token", userToken(account), nil)
		if code != http.StatusForbidden {
			t.Fatalf("%s 应被账号状态闸拒，得 %d", account, code)
		}
		if _, has := out["tunnelTicket"]; has {
			t.Errorf("★被闸拒掉的账号绝不能拿到隧道票据：%v", out)
		}
	}
}
