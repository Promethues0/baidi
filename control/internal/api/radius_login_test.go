package api

// RADIUS 认证源端到端（FR-INT-03）：真 SQLite 店 + 真 radiussrc 客户端 + 进程内真 RADIUS 服务端，
// 走完「保存源 → 设共享密钥 → 门户登录 → 建号/绑定 → 提权被拒」整条链。
//
// ★这组用例回答的是 SCOPE 里那条「明拒」理由：RADIUS 没有权威 Subject，于是按用户名绑定
// → 冒充本地管理员。下面逐条钉住那条推理为何不成立：撞名加后缀、role 恒 user、
// pass_hash 恒空、提权入口拒绝、Subject 按源隔离。

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// radiusSrvOpts 进程内 RADIUS 服务端的行为开关。
type radiusSrvOpts struct {
	secret       string
	users        map[string]string
	statusServer bool     // 是否应答 Status-Server（false 模拟老服务器）
	blackhole    bool     // 收到什么都不回（模拟丢包 / 未登记的 NAS）
	classes      []string // Access-Accept 里写进 Class 的值（默认只有 vpn-users）
	// noReplyMA 应答**不带** Message-Authenticator：既是"老设备"，也是 Blast-RADIUS
	// （CVE-2024-3596）里中间人把该属性剥离掉之后那份报文的形状。
	// ★默认是**带**——现代服务器对带了 MA 的请求会在应答里回它（RFC 5080 §2.2.2），
	// 而 radiussrc 默认要求它；夹具默认值必须与"能正常工作的部署"一致。
	noReplyMA bool
}

// signRadiusMA 给一份应答附 Message-Authenticator（RFC 2869 §5.14）：
// HMAC-MD5(secret, 整个报文，该属性先置 16 个零)。应答的 Authenticator 字段此刻仍是
// **请求的** Authenticator（radius.Request.Response 复制过来的），与客户端的校验口径一致。
func signRadiusMA(pkt *radius.Packet) error {
	if err := rfc2869.MessageAuthenticator_Set(pkt, make([]byte, 16)); err != nil {
		return err
	}
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(md5.New, pkt.Secret)
	mac.Write(wire)
	return rfc2869.MessageAuthenticator_Set(pkt, mac.Sum(nil))
}

// radiusSrvHandle 进程内服务端句柄：地址 + 收到的 Access-Request 计数。
type radiusSrvHandle struct {
	host string
	port int
	mu   sync.Mutex
	n    int
}

func (h *radiusSrvHandle) accessRequests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

// startRadiusSrvOpts 进程内 RADIUS 服务端（PAP）。
func startRadiusSrvOpts(t *testing.T, o radiusSrvOpts) *radiusSrvHandle {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	h := &radiusSrvHandle{}
	classes := o.classes
	if classes == nil {
		classes = []string{"vpn-users"}
	}
	srv := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource([]byte(o.secret)),
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			reply := func(resp *radius.Packet) {
				if !o.noReplyMA {
					if err := signRadiusMA(resp); err != nil {
						t.Errorf("服务端签 Message-Authenticator 失败：%v", err)
					}
				}
				_ = w.Write(resp)
			}
			switch r.Code {
			case radius.CodeStatusServer:
				if o.statusServer && !o.blackhole {
					reply(r.Response(radius.CodeAccessAccept))
				}
			case radius.CodeAccessRequest:
				h.mu.Lock()
				h.n++
				h.mu.Unlock()
				if o.blackhole {
					return
				}
				u := rfc2865.UserName_GetString(r.Packet)
				if pw, ok := o.users[u]; ok && rfc2865.UserPassword_GetString(r.Packet) == pw {
					resp := r.Response(radius.CodeAccessAccept)
					for _, c := range classes {
						_ = rfc2865.Class_AddString(resp, c)
					}
					reply(resp)
					return
				}
				reply(r.Response(radius.CodeAccessReject))
			}
		}),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()); _ = pc.Close() })
	hs, ps, _ := net.SplitHostPort(pc.LocalAddr().String())
	h.host = hs
	for _, ch := range ps {
		h.port = h.port*10 + int(ch-'0')
	}
	return h
}

// startRadiusSrv 旧签名的薄封装：statusServer=false 模拟不认 Status-Server 的老服务器。
func startRadiusSrv(t *testing.T, secretKey string, users map[string]string, statusServer bool) (host string, port int) {
	t.Helper()
	h := startRadiusSrvOpts(t, radiusSrvOpts{secret: secretKey, users: users, statusServer: statusServer})
	return h.host, h.port
}

// newRadiusAPI 一台带 secret 盒的测试控制面（凭据主密钥路径必须在第一次触碰前指走）。
func newRadiusAPI(t *testing.T) (*Server, http.Handler, *store.SQLiteStore) {
	t.Helper()
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "radius.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return s, auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st
}

// saveRadiusSource 经 REST 保存一条 RADIUS 源并设共享密钥，返回源 id。
func saveRadiusSource(t *testing.T, h http.Handler, host string, port int, secretKey string, extra map[string]any) string {
	t.Helper()
	cfg := map[string]any{"host": host, "port": port, "timeoutMs": 300, "retries": 1}
	for k, v := range extra {
		cfg[k] = v
	}
	code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
		"name": "测试 RADIUS", "kind": "radius", "enabled": true, "priority": 10, "config": cfg,
	})
	if code != http.StatusOK {
		t.Fatalf("保存 RADIUS 源 http %d：%v", code, out)
	}
	// 保存那一刻还没有共享密钥：warning 必须点名它，而不是静默通过。
	if w, _ := out["warning"].(string); !strings.Contains(w, "共享密钥") {
		t.Fatalf("未设密钥时的保存回执应提示共享密钥，得到 %q", w)
	}
	id := mapOf(t, out["source"])["id"].(string)
	if code, out := doJSON(t, h, "PUT", "/api/v1/authsrc/sources/"+id+"/secret", adminToken(),
		map[string]string{"secret": secretKey}); code != http.StatusOK {
		t.Fatalf("设共享密钥 http %d：%v", code, out)
	}
	return id
}

func portalLoginRaw(t *testing.T, h http.Handler, user, pw string) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{"username": user, "password": pw})
	if code != http.StatusOK {
		t.Fatalf("portal login http %d：%v", code, out)
	}
	return out
}

// TestRadiusLoginBindsSafely 撞名后缀 / role=user / pass_hash 空 / Subject 稳定 / 本地账号不受影响。
func TestRadiusLoginBindsSafely(t *testing.T) {
	s, h, st := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"li.fang": "radius-pw", "admin": "radius-admin-pw"}, true)
	// groupAttr=class：服务端把组写在 Class 里；不配这一项时组不映射（④ 会失败，这是预期——组映射是显式选择）。
	srcID := saveRadiusSource(t, h, host, port, "s3cret", map[string]any{"groupAttr": "class"})
	ctx := context.Background()

	// ① RADIUS 里有个叫 li.fang 的人（与本地种子用户撞名）。他登进来的是 li.fang@<源 id>，不是本地 li.fang。
	out := portalLoginRaw(t, h, "li.fang", "radius-pw")
	if out["ok"] != true || out["token"] == nil {
		t.Fatalf("RADIUS 放行的用户应登录成功：%v", out)
	}
	extAccount := "li.fang@" + srcID
	cred, found, err := st.Credential(ctx, extAccount)
	if err != nil || !found {
		t.Fatalf("撞名的外部用户应以来源后缀建号 %q：found=%v err=%v", extAccount, found, err)
	}
	if cred.Role != "user" {
		t.Errorf("外部账号 role 应恒为 user，得到 %q", cred.Role)
	}
	if cred.PassHash != "" {
		t.Errorf("外部账号 pass_hash 应恒为空（不能有任何本地口令能登录它），得到非空")
	}
	// 本地 li.fang 原样未动：口令仍是本地那份，且没被外部登录改写。
	local, _, _ := st.Credential(ctx, "li.fang")
	if !auth.VerifyPassword(local.PassHash, "baidi@123") {
		t.Error("本地 li.fang 的口令哈希被外部登录改写了")
	}
	if lo := portalLoginRaw(t, h, "li.fang", "baidi@123"); lo["ok"] != true {
		t.Errorf("本地 li.fang 用本地口令仍应登录成功：%v", lo)
	}

	// ② Subject 稳定：同一写法第二次登录绑到同一个账号，不建新号（换大小写是另一个 Subject，见 radiussrc 包注释）。
	before := countUsers(t, s)
	portalLoginRaw(t, h, "li.fang", "radius-pw")
	if after := countUsers(t, s); after != before {
		t.Errorf("第二次登录不该再建号：%d → %d", before, after)
	}
	if c2, ok, _ := st.UserBySubject(ctx, srcID, "radius:"+srcID+":li.fang"); !ok || c2.Account != extAccount {
		t.Errorf("Subject 应为 radius:<源 id>:<用户名> 且指向 %s，得到 ok=%v acct=%q", extAccount, ok, c2.Account)
	}

	// ③ RADIUS 里造一个 admin：登进来的是 admin@<源 id>，本地 admin 毫发无损。
	if ao := portalLoginRaw(t, h, "admin", "radius-admin-pw"); ao["ok"] != true {
		t.Fatalf("RADIUS 的 admin 应作为外部普通用户登录成功：%v", ao)
	}
	ac, found, _ := st.Credential(ctx, "admin@"+srcID)
	if !found || ac.Role != "user" {
		t.Fatalf("RADIUS 侧的 admin 应落成 admin@<源 id> 的普通用户，得到 found=%v role=%q", found, ac.Role)
	}
	rootCred, _, _ := st.Credential(ctx, "admin")
	if rootCred.Role != "admin" || !auth.VerifyPassword(rootCred.PassHash, "baidi@123") {
		t.Error("本地 admin 被 RADIUS 侧同名账号影响了")
	}
	// 管理台登录只验本地口令：拿 RADIUS 的 admin 口令登管理台必须失败。
	if code, lo := doJSON(t, h, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "radius-admin-pw"}); code == http.StatusOK && lo["ok"] == true {
		t.Error("RADIUS 侧的 admin 口令竟能登进管理台")
	}

	// ④ Class=vpn-users **不再**自动建成用户组：Class 值只用于准入闸与「已存在的组」成员同步
	// （Cisco ISE 等把 Class 用作逐会话标识，原样建组会把 user_groups 写爆）。正面用例见
	// TestRadiusClassNeverCreatesGroups。
	if grps, err := st.UserGroups(ctx); err == nil {
		for _, g := range grps {
			if strings.EqualFold(strings.TrimSpace(g.Name), "vpn-users") {
				t.Errorf("RADIUS Class 值不该自动建成用户组，却建了：%+v", g)
			}
		}
	}
}

// TestRadiusClassNeverCreatesGroups Class 值绝不自动新建用户组；只往**已存在**的本源外部组里同步成员。
//
// 「已存在」的行只可能来自升级前的自动建组（本改动后 RADIUS 不再建），这里用 BindExternalUser
// 直接造一行来模拟那批存量组。
func TestRadiusClassNeverCreatesGroups(t *testing.T) {
	_, h, st := newRadiusAPI(t)
	ctx := context.Background()
	// 服务端每次 Accept 回三个 Class：一个存量组、一个从没见过的"组"、一个像会话标识的值。
	srv := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", statusServer: true,
		users:   map[string]string{"zhou": "pw"},
		classes: []string{"VPN-Users", "brand-new-group", "CACS:0a0a0a0a000000010000abcd:ise/12345"}})
	srcID := saveRadiusSource(t, h, srv.host, srv.port, "s3cret", map[string]any{"groupAttr": "class"})

	// 模拟升级前留下的存量外部组：直接经 store 绑一个别的身份并带上该组名。
	if _, err := st.BindExternalUser(ctx, srcID, store.ExternalIdentity{
		Subject: "radius:" + srcID + ":legacy", Username: "legacy-user", Groups: []string{"vpn-users"},
	}); err != nil {
		t.Fatalf("造存量组失败：%v", err)
	}
	before, err := st.UserGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var legacyGID string
	for _, g := range before {
		if g.Kind == store.GroupKindExternal && strings.EqualFold(g.Name, "vpn-users") {
			legacyGID = g.ID
		}
	}
	if legacyGID == "" {
		t.Fatalf("夹具没造出存量外部组：%+v", before)
	}

	out := portalLoginRaw(t, h, "zhou", "pw")
	if out["ok"] != true {
		t.Fatalf("登录应成功：%v", out)
	}
	after, err := st.UserGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// ① 组行数一行不多：brand-new-group 与 CACS:… 都没被建成组。
	if len(after) != len(before) {
		t.Errorf("RADIUS 登录不该新建任何用户组：%d → %d（%+v）", len(before), len(after), after)
	}
	for _, g := range after {
		if strings.Contains(g.Name, "brand-new-group") || strings.HasPrefix(g.Name, "CACS:") {
			t.Errorf("Class 值被自动建成了用户组：%+v", g)
		}
	}
	// ② 存量组的成员同步照常：zhou 进了 vpn-users（名字大小写不敏感：服务端回的是 VPN-Users）。
	members, err := st.GroupMembers(ctx, legacyGID)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(members, "zhou") {
		t.Errorf("已存在的外部组应同步成员，zhou 不在 vpn-users 里：%v", members)
	}
}

// TestRadiusRetriesZeroSendsOnce 管理员显式选「重发 0 次」= 只发一次；配置里缺席才取默认 1。
//
// 此前 radiusRetries 把 `n <= 0` 一律当"取默认"：控制台显示 0、执行 1，总预算翻倍且页面看不出。
func TestRadiusRetriesZeroSendsOnce(t *testing.T) {
	zero, one := 0, 1
	if got := radiusRetries(nil); got != -1 {
		t.Errorf("缺席应交给 radiussrc 取默认（-1），得到 %d", got)
	}
	if got := radiusRetries(&zero); got != 0 {
		t.Errorf("显式 0 必须原样是 0，得到 %d", got)
	}
	if got := radiusRetries(&one); got != 1 {
		t.Errorf("显式 1 应为 1，得到 %d", got)
	}

	_, h, _ := newRadiusAPI(t)
	// 黑洞服务端：只数收到几份 Access-Request。timeoutMs=200 让用例不拖。
	bh := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", blackhole: true})
	saveRadiusSource(t, h, bh.host, bh.port, "s3cret", map[string]any{"timeoutMs": 200, "retries": 0})
	if o := portalLoginRaw(t, h, "zhou", "pw"); o["ok"] == true {
		t.Fatalf("黑洞服务端不该登录成功：%v", o)
	}
	if n := bh.accessRequests(); n != 1 {
		t.Errorf("retries=0 应只发一份 Access-Request，服务端收到 %d", n)
	}
	// 对照：retries=1 至少两份。
	_, h1, _ := newRadiusAPI(t)
	bh1 := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", blackhole: true})
	saveRadiusSource(t, h1, bh1.host, bh1.port, "s3cret", map[string]any{"timeoutMs": 200, "retries": 1})
	portalLoginRaw(t, h1, "zhou", "pw")
	if n := bh1.accessRequests(); n < 2 {
		t.Errorf("retries=1 应至少发两份，服务端收到 %d", n)
	}

	// 落库形态：不带 retries 保存 → 库里是显式 1（不留空缺）；带 0 保存 → 库里是 0。
	_, h2, _ := newRadiusAPI(t)
	post := func(cfg map[string]any) map[string]any {
		code, out := doJSON(t, h2, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"name": "r", "kind": "radius", "enabled": true, "config": cfg,
		})
		if code != http.StatusOK {
			t.Fatalf("保存 %d：%v", code, out)
		}
		// rec.Config 是落库的 JSON **字符串**：这里看的正是库里那份的形态。
		raw, _ := mapOf(t, out["source"])["config"].(string)
		var c map[string]any
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("落库 config 不是合法 JSON：%q（%v）", raw, err)
		}
		return c
	}
	if c := post(map[string]any{"host": "10.0.0.1"}); c["retries"] != float64(1) {
		t.Errorf("缺席的 retries 落库应归一成显式 1，得到 %v", c["retries"])
	}
	if c := post(map[string]any{"host": "10.0.0.2", "retries": 0}); c["retries"] != float64(0) {
		t.Errorf("显式 0 落库应保留 0，得到 %v", c["retries"])
	}
}

// TestRadiusAdmitHintNeverMentionsEmailWithoutDomainConfig RADIUS 的 Email 恒空，准入提示不能拿
// 「邮箱为空」当"域白名单没过"的判据——组白名单不过时应给组属性的提示，只有真配了域才提邮箱域。
func TestRadiusAdmitHintNeverMentionsEmailWithoutDomainConfig(t *testing.T) {
	recGroups := store.AuthSourceRec{ID: "as-r", Kind: string(authsrc.KindRADIUS), Config: `{"allowedGroups":["vpn-users"],"groupAttr":"class"}`}
	// ① 组白名单配了、应答没映射出组：提示组属性，绝不提邮箱域。
	hint := admitAttrHint(recGroups, authsrc.Identity{Subject: "radius:as-r:zhou"})
	if !strings.Contains(hint, "组属性") || strings.Contains(hint, "邮箱域") {
		t.Errorf("RADIUS 组白名单不过（无组）的提示应指向组属性、不提邮箱域，得到 %q", hint)
	}
	// ② 组拿到了、只是不在白名单里：不加提示（管理员该改白名单）。
	if hint := admitAttrHint(recGroups, authsrc.Identity{Groups: []string{"other"}}); hint != "" {
		t.Errorf("组已拿到时不该加属性提示，得到 %q", hint)
	}
	// ③ 存量配置真配了域白名单（保存接口现已拒收）：这时才提邮箱域。
	recDomains := store.AuthSourceRec{ID: "as-r", Kind: string(authsrc.KindRADIUS), Config: `{"allowedDomains":["corp.example"]}`}
	if hint := admitAttrHint(recDomains, authsrc.Identity{}); !strings.Contains(hint, "邮箱域") {
		t.Errorf("真配了域白名单的 RADIUS 源才该提邮箱域，得到 %q", hint)
	}
}

// TestRadiusExternalCannotBecomeAdmin 外部 RADIUS 账号提升为管理员必须被拒（guardLocalCredentialForAdmin）。
func TestRadiusExternalCannotBecomeAdmin(t *testing.T) {
	_, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	srcID := saveRadiusSource(t, h, host, port, "s3cret", nil)
	portalLoginRaw(t, h, "zhou", "pw")

	code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(),
		map[string]string{"account": "zhou", "name": "周", "roleKey": "security", "password": testStrongPw})
	if code != http.StatusBadRequest {
		t.Fatalf("外部账号提权应 400，得到 %d：%v", code, out)
	}
	msg, _ := mapOf(t, out["error"])["message"].(string)
	if !strings.Contains(msg, "外部认证源") || !strings.Contains(msg, "本地口令") {
		t.Errorf("拒绝文案应说清原因与下一步（先重置本地口令），得到 %q", msg)
	}
	_ = srcID
}

// TestRadiusUnavailableIsNotWrongPassword 共享密钥不匹配 → 「认证服务暂时不可用」，**不计锁定**。
//
// ★断言必须有区分度：此前只登一次就断 len(Active())==0，而阈值是 5——计不计都是 0。
// 现在同一账号对不可用源连登 N（=阈值）次仍未锁定，而同一夹具下 N 次真实口令错误会锁定，两条并排。
func TestRadiusUnavailableIsNotWrongPassword(t *testing.T) {
	s, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "server-secret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "client-secret-mismatch", nil)
	n := s.lockout.Config().Threshold
	if n < 1 {
		t.Fatalf("锁定阈值应 ≥1，得到 %d", n)
	}

	for i := 0; i < n; i++ {
		out := portalLoginRaw(t, h, "zhou", "pw")
		reason, _ := out["reason"].(string)
		if out["ok"] == true || !strings.Contains(reason, "不可用") {
			t.Fatalf("第 %d 次：密钥不匹配应回「认证服务暂时不可用」，得到 %v", i+1, out)
		}
		if strings.Contains(reason, "密码错误") {
			t.Errorf("绝不能把源故障说成密码错误：%q", reason)
		}
	}
	if act := s.lockout.Active(); len(act) != 0 {
		t.Errorf("对不可用源连登 %d 次（=阈值）仍不该计入爆破锁定，却有 %d 条：%+v", n, len(act), act)
	}
	if _, hit := s.lockout.Check("zhou", ""); hit {
		t.Errorf("zhou 不该被锁定（源故障不是口令错误）")
	}

	// 对照：密钥对了但口令错 → 「用户名或密码错误」，且 N 次之后**真的锁定**——
	// 证明夹具里的阈值、计数、锁定都活着，上面那个 0 不是因为计数器根本没接。
	s2, h2, _ := newRadiusAPI(t)
	host2, port2 := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h2, host2, port2, "s3cret", nil)
	for i := 0; i < n; i++ {
		o2 := portalLoginRaw(t, h2, "zhou", "wrong")
		if o2["ok"] == true || !strings.Contains(o2["reason"].(string), "密码错误") {
			t.Fatalf("第 %d 次：Access-Reject 应回用户名或密码错误：%v", i+1, o2)
		}
	}
	lk, hit := s2.lockout.Check("zhou", "")
	if !hit || lk.Kind != store.LockKindAccount || lk.Key != "zhou" {
		t.Fatalf("同一夹具下 %d 次真实口令错误应触发账号锁定，得到 hit=%v %+v（Active=%+v）", n, hit, lk, s2.lockout.Active())
	}
	// 锁定是真的：此刻拿**正确**口令登也被 403 挡在门外。
	if code, o := doJSON(t, h2, "POST", "/api/v1/portal/login", "", map[string]string{"username": "zhou", "password": "pw"}); code != http.StatusForbidden {
		t.Errorf("锁定期内正确口令也应 403，得到 %d：%v", code, o)
	}
}

// TestRadiusSaveValidation 入口校验：端口范围 / 协议枚举 / 域白名单拒收 / 未实现类型的拒绝文案带上 radius。
func TestRadiusSaveValidation(t *testing.T) {
	_, h, _ := newRadiusAPI(t)
	post := func(cfg map[string]any, kind string) (int, string) {
		code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"name": "x", "kind": kind, "enabled": true, "config": cfg,
		})
		msg := ""
		if e, ok := out["error"].(map[string]any); ok {
			msg, _ = e["message"].(string)
		}
		return code, msg
	}
	if code, msg := post(map[string]any{"host": "10.0.0.1", "port": 70000}, "radius"); code != 400 || !strings.Contains(msg, "端口") {
		t.Errorf("端口越界应 400 并点名端口：%d %q", code, msg)
	}
	if code, msg := post(map[string]any{"port": 1812}, "radius"); code != 400 || !strings.Contains(msg, "host") {
		t.Errorf("缺 host 应 400：%d %q", code, msg)
	}
	if code, msg := post(map[string]any{"host": "10.0.0.1", "protocol": "eap"}, "radius"); code != 400 || !strings.Contains(msg, "pap") {
		t.Errorf("协议非 pap/chap 应 400：%d %q", code, msg)
	}
	if code, msg := post(map[string]any{"host": "10.0.0.1", "groupAttr": "vendor"}, "radius"); code != 400 || !strings.Contains(msg, "class") {
		t.Errorf("组属性非枚举应 400：%d %q", code, msg)
	}
	// ★域白名单对 RADIUS 恒 fail-closed（应答里没有邮箱）：配上去 = 该源全员进不来且零报错，保存即拒。
	if code, msg := post(map[string]any{"host": "10.0.0.1", "allowedDomains": []string{"corp.example"}}, "radius"); code != 400 || !strings.Contains(msg, "邮箱域") {
		t.Errorf("RADIUS 源配域白名单应 400 并说明原因：%d %q", code, msg)
	}
	// ★同一条理由：allowedGroups 非空 + groupAttr 为空 = 不映射组 = 组白名单对谁都不过，保存即拒，
	// 文案要说清两条出路（配组属性 / 清空允许的组）。
	if code, msg := post(map[string]any{"host": "10.0.0.1", "allowedGroups": []string{"vpn-users"}}, "radius"); code != 400 ||
		!strings.Contains(msg, "组属性") || !strings.Contains(msg, "允许的组") {
		t.Errorf("allowedGroups 非空而 groupAttr 为空应 400 并点名两条出路：%d %q", code, msg)
	}
	if code, msg := post(map[string]any{"host": "10.0.0.1", "allowedGroups": []string{"vpn-users"}, "groupAttr": "class"}, "radius"); code != 200 {
		t.Errorf("allowedGroups + groupAttr=class 应保存成功：%d %q", code, msg)
	}
	// retries 越界仍 400。
	if code, msg := post(map[string]any{"host": "10.0.0.1", "retries": 9}, "radius"); code != 400 || !strings.Contains(msg, "retries") {
		t.Errorf("retries 越界应 400：%d %q", code, msg)
	}
	// 未实现类型的拒绝文案里，支持清单要跟着 SupportedKinds 走（radius 现在在里面）。
	if code, msg := post(map[string]any{}, "sms"); code != 400 || !strings.Contains(msg, "radius") || !strings.Contains(msg, "未实现") {
		t.Errorf("sms 应仍被拒且清单含 radius：%d %q", code, msg)
	}
	// supportedKinds 响应同源。
	code, out := doJSON(t, h, "GET", "/api/v1/authsrc/sources", adminToken(), nil)
	if code != 200 {
		t.Fatalf("list %d", code)
	}
	joined := ""
	for _, k := range out["supportedKinds"].([]any) {
		joined += k.(string) + ","
	}
	if !strings.Contains(joined, "radius,") || strings.Contains(joined, "sms") {
		t.Errorf("supportedKinds 应含 radius、不含 sms：%s", joined)
	}
}

// TestRadiusProbeSaysWhichMethod 「测试连接」必须说清是 Status-Server 还是回退的 Access-Request。
func TestRadiusProbeSaysWhichMethod(t *testing.T) {
	_, h, _ := newRadiusAPI(t)
	hostA, portA := startRadiusSrv(t, "s3cret", nil, true)
	idA := saveRadiusSource(t, h, hostA, portA, "s3cret", nil)
	code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources/"+idA+"/probe", adminToken(), nil)
	if code != 200 || out["ok"] != true || out["method"] != "status-server" {
		t.Errorf("支持 Status-Server 的服务器应 ok 且 method=status-server：%d %v", code, out)
	}

	hostB, portB := startRadiusSrv(t, "s3cret", nil, false)
	idB := saveRadiusSource(t, h, hostB, portB, "s3cret", nil)
	code, out = doJSON(t, h, "POST", "/api/v1/authsrc/sources/"+idB+"/probe", adminToken(), nil)
	detail, _ := out["detail"].(string)
	if code != 200 || out["ok"] != true || out["method"] != "access-request" || !strings.Contains(detail, "失败登录") {
		t.Errorf("老服务器应 ok 且 method=access-request、并说明会在对面留一条失败登录：%d %v", code, out)
	}
}

// TestRadiusResponseWithoutMessageAuthenticatorRejected 应答不带 Message-Authenticator = 源不可用，
// 走的是完整生产链路（REST 保存 → buildProvider → radiussrc → 门户登录）。
//
// ★这是 Blast-RADIUS（CVE-2024-3596）那道闸的**执行方**证据：请求侧一直无条件附 MA，应答侧
// 若停在「带了才校验」，链路上的攻击者只要把该属性删掉就能整个跳过 HMAC 校验，只剩他已经
// 攻破的 MD5 Response Authenticator。夹具里的服务端知道共享密钥（进程内没法复现 MD5 选择前缀
// 碰撞），等价于**攻击成功之后那一刻**的报文：MD5 那层已经过了，只剩本包这道闸。
func TestRadiusResponseWithoutMessageAuthenticatorRejected(t *testing.T) {
	s, h, _ := newRadiusAPI(t)
	srv := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", statusServer: true,
		users: map[string]string{"zhou": "pw"}, noReplyMA: true})
	id := saveRadiusSource(t, h, srv.host, srv.port, "s3cret", nil)

	// ① 口令**完全正确**，但应答没带 MA：必须登不进来，且理由是「不可用」不是「密码错误」。
	out := portalLoginRaw(t, h, "zhou", "pw")
	if out["ok"] == true || out["token"] != nil {
		t.Fatalf("不带 Message-Authenticator 的 Access-Accept 竟放行了：%v", out)
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, "不可用") {
		t.Errorf("应回「认证服务暂时不可用」，得到 %q", reason)
	}
	if strings.Contains(reason, "密码错误") {
		t.Errorf("链路/服务端问题绝不能说成密码错误（会计入锁定并把人支去改密码）：%q", reason)
	}
	// 一行用户都不该建：认证根本没通过。
	if n := countUsers(t, s); n == 0 {
		t.Fatalf("夹具异常：种子用户数为 0")
	}
	if _, found, _ := s.store.Credential(context.Background(), "zhou@"+id); found {
		t.Error("认证未通过却建了外部账号")
	}
	// ② 不计入爆破锁定：口令是对的。
	if act := s.lockout.Active(); len(act) != 0 {
		t.Errorf("源不可用不该计入爆破锁定，得到 %+v", act)
	}

	// ③ 「测试连接」也必须红，且说清是哪一层缺了、以及两种可能的成因与出路——
	// 一句「连接失败」会让管理员去查网络，而这里既可能是中间人也可能是老设备。
	code, pout := doJSON(t, h, "POST", "/api/v1/authsrc/sources/"+id+"/probe", adminToken(), nil)
	detail, _ := pout["detail"].(string)
	if code != 200 || pout["ok"] != false {
		t.Fatalf("探测应判失败：%d %v", code, pout)
	}
	for _, want := range []string{"Message-Authenticator", "CVE-2024-3596", "老设备", radiusAllowMissingRespMAKey} {
		if !strings.Contains(detail, want) {
			t.Errorf("探测结论应提到「%s」，得到：%s", want, detail)
		}
	}

	// ④ 对照：同一台服务器改回**带** MA（现代姿态），同样的配置就登得进来——
	// 证明上面那条红不是"这条链路根本没通"。
	_, h2, _ := newRadiusAPI(t)
	ok := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", statusServer: true,
		users: map[string]string{"zhou": "pw"}})
	saveRadiusSource(t, h2, ok.host, ok.port, "s3cret", nil)
	if o := portalLoginRaw(t, h2, "zhou", "pw"); o["ok"] != true {
		t.Fatalf("应答带 MA 时应登录成功：%v", o)
	}
}

// TestRadiusSaveKeepsUnknownConfigKeys 归一必须**只回写本函数改过的键**，其余原样带过去。
//
// ★此前 validateRadiusConfig 是「解成 DTO 再重新 Marshal」：DTO 里没声明的键会被那一次保存
// 整个抹掉——「改了 A 设置，B 设置莫名其妙没了」，接口回 200、页面看不出。同仓 mergeAdmitCfg
// 的注释早把这条写死了。今天字段恰好对齐所以无实害，但 DTO 与库里那份 config 的字段集只要
// 有一次没同步就炸（新增的 allowMissingResponseMessageAuthenticator 正是这样一个 DTO 外的键）。
func TestRadiusSaveKeepsUnknownConfigKeys(t *testing.T) {
	_, h, st := newRadiusAPI(t)
	ctx := context.Background()
	// 库里先有一条带"DTO 未声明的键"的 RADIUS 源（模拟别的入口/更高版本写进来的配置）。
	rec, err := st.SaveAuthSource(ctx, store.AuthSourceRec{
		Name: "存量 RADIUS", Kind: string(authsrc.KindRADIUS), Enabled: true,
		Config: `{"host":"10.0.0.9","port":1812,"nasIdentifier":"nas-a","vendorNote":"运维备注：这台是 ISE","futureFlag":true}`,
	})
	if err != nil {
		t.Fatalf("造存量源失败：%v", err)
	}
	// 控制台把读到的整份 config 原样带回来再保存一次（只改了端口）。
	var cfg map[string]any
	if err := json.Unmarshal([]byte(rec.Config), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["port"] = 1645
	code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
		"id": rec.ID, "name": rec.Name, "kind": "radius", "enabled": true, "config": cfg,
	})
	if code != http.StatusOK {
		t.Fatalf("保存 %d：%v", code, out)
	}
	raw, _ := mapOf(t, out["source"])["config"].(string)
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("落库 config 不是合法 JSON：%q", raw)
	}
	if got["vendorNote"] != "运维备注：这台是 ISE" {
		t.Errorf("DTO 未声明的键 vendorNote 被这次保存抹掉了：%v", got)
	}
	if got["futureFlag"] != true {
		t.Errorf("DTO 未声明的键 futureFlag 被这次保存抹掉了：%v", got)
	}
	// 本函数改过的键照常归一。
	if got["port"] != float64(1645) || got["protocol"] != "pap" || got["retries"] != float64(1) {
		t.Errorf("归一后的键不对：%v", got)
	}
	if got["nasIdentifier"] != "nas-a" {
		t.Errorf("nasIdentifier 应原样保留：%v", got)
	}
}

// TestRadiusMessageAuthenticatorWaiverConfig 逃生舱的入口语义：默认关、只认布尔、打开时当面告警。
func TestRadiusMessageAuthenticatorWaiverConfig(t *testing.T) {
	_, h, _ := newRadiusAPI(t)
	post := func(cfg map[string]any) (int, map[string]any) {
		return doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"name": "r", "kind": "radius", "enabled": true, "config": cfg,
		})
	}
	storedFlag := func(out map[string]any) any {
		raw, _ := mapOf(t, out["source"])["config"].(string)
		var c map[string]any
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("落库 config 不是合法 JSON：%q", raw)
		}
		return c[radiusAllowMissingRespMAKey]
	}

	// ① 缺席 = 归一成显式 false 落库（要求应答带 MA），保存回执里没有逃生舱告警。
	code, out := post(map[string]any{"host": "10.0.0.1"})
	if code != 200 {
		t.Fatalf("保存 %d：%v", code, out)
	}
	if storedFlag(out) != false {
		t.Errorf("缺席应归一成显式 false（安全那一侧就是零值），得到 %v", storedFlag(out))
	}
	if w, _ := out["warning"].(string); strings.Contains(w, "Message-Authenticator") {
		t.Errorf("没打开逃生舱不该有这条告警（常驻警告会被当背景噪声）：%q", w)
	}

	// ② 显式 true：落库为 true，且保存回执**当面**说清放弃了哪一层保护。
	code, out = post(map[string]any{"host": "10.0.0.2", radiusAllowMissingRespMAKey: true})
	if code != 200 {
		t.Fatalf("保存 %d：%v", code, out)
	}
	if storedFlag(out) != true {
		t.Errorf("显式 true 应原样落库，得到 %v", storedFlag(out))
	}
	w, _ := out["warning"].(string)
	for _, want := range []string{"Message-Authenticator", "CVE-2024-3596", "MD5"} {
		if !strings.Contains(w, want) {
			t.Errorf("打开逃生舱的保存回执应提到「%s」，得到：%q", want, w)
		}
	}
	// 「还没填共享密钥」那条也要在——两条是独立的事，后者不该把前者覆盖掉。
	if !strings.Contains(w, "共享密钥") {
		t.Errorf("可用性告警被逃生舱告警覆盖了：%q", w)
	}

	// ③ 非布尔一律 400 并点名这个键：安全开关不能靠"填错了于是当 false"蒙混过去——
	// 方向虽然是收紧的，但管理员会以为自己配上了。
	code, out = post(map[string]any{"host": "10.0.0.3", radiusAllowMissingRespMAKey: "yes"})
	msg := ""
	if e, ok := out["error"].(map[string]any); ok {
		msg, _ = e["message"].(string)
	}
	if code != 400 || !strings.Contains(msg, radiusAllowMissingRespMAKey) {
		t.Errorf("非布尔应 400 并点名键名：%d %q", code, msg)
	}
}

// TestRadiusMessageAuthenticatorWaiverTakesEffect 逃生舱**有执行方**：同一台不回
// Message-Authenticator 的服务器，开关关（默认）认证失败判「源不可用」，开关开则认证通过。
//
// ★必须走**从库里那份 config 出发**的完整链路（REST 保存 → buildProvider → radiussrc →
// 门户登录）。直接构造 radiussrc.Config 正好绕过这次的缺陷：那个字段在 radiussrc 里一直是
// 真判据（该包自己的用例已钉住），断的是「控制面读不读它」这一跳——
// radiusConfigDTO 没声明这个键、buildProvider 也没传，于是入口校验/归一落库/保存告警/
// 登录拒绝文案/探测结论五处齐全，而 Provider 那边恒 false。
//
// 变异：删掉 buildProvider 里那行 AllowMissingResponseMessageAuthenticator，本用例
// 第 ② 段当场红（开关打开了却仍判"源不可用"）。
func TestRadiusMessageAuthenticatorWaiverTakesEffect(t *testing.T) {
	// ① 开关关（默认）：不带 MA 的 Access-Accept 一律拒，且理由是「不可用」不是「密码错误」。
	s1, h1, _ := newRadiusAPI(t)
	srv1 := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", statusServer: true,
		users: map[string]string{"zhou": "pw"}, noReplyMA: true})
	id1 := saveRadiusSource(t, h1, srv1.host, srv1.port, "s3cret", nil)
	out := portalLoginRaw(t, h1, "zhou", "pw")
	if out["ok"] == true || out["token"] != nil {
		t.Fatalf("默认（开关关）不该接受不带 Message-Authenticator 的应答：%v", out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "不可用") {
		t.Errorf("应回「认证服务暂时不可用」，得到 %q", reason)
	}
	if _, found, _ := s1.store.Credential(context.Background(), "zhou"); found {
		t.Error("认证未通过却建了账号")
	}

	// ② 开关开：**同一份**伪造应答（同一个 radiusSrvOpts.noReplyMA）现在认证通过。
	s2, h2, _ := newRadiusAPI(t)
	srv2 := startRadiusSrvOpts(t, radiusSrvOpts{secret: "s3cret", statusServer: true,
		users: map[string]string{"zhou": "pw"}, noReplyMA: true})
	id2 := saveRadiusSource(t, h2, srv2.host, srv2.port, "s3cret",
		map[string]any{radiusAllowMissingRespMAKey: true})
	out = portalLoginRaw(t, h2, "zhou", "pw")
	if out["ok"] != true || out["token"] == nil {
		t.Fatalf("打开逃生舱后同一台服务器应认证通过（否则这个开关没有执行方）：%v", out)
	}
	if _, found, err := s2.store.Credential(context.Background(), "zhou"); err != nil || !found {
		t.Errorf("认证通过应建号：found=%v err=%v", found, err)
	}
	// 落库那份确实是 true（排除"其实没存进去、只是别处放行了"这种解释）。
	if rec, ok, err := s2.store.(store.AuthSourceStore).AuthSourceByID(context.Background(), id2); err != nil || !ok {
		t.Fatalf("读回源失败：ok=%v err=%v", ok, err)
	} else if !radiusWaiverFromConfig(rec.Config) {
		t.Errorf("库里那份 config 的逃生舱不是 true：%s", rec.Config)
	}
	_ = id1
}
