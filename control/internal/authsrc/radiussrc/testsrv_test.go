package radiussrc

// 进程内的真实 RADIUS 服务端（layeh.com/radius 的 PacketServer）。
// 客户端是生产代码本身；这里只模拟服务端**行为**（放行/拒绝/黑洞/挑战/密钥不对），
// 不模拟报文——报文编解码两侧都是库，用例断的是本包的安全语义。

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

type srvOpts struct {
	secret string
	users  map[string]string   // 用户 → 明文口令（PAP 与 CHAP 都用它验）
	groups map[string][]string // 用户 → 组，写进 groupAttr 指定的属性
	// groupAttr 组写进哪个属性："class" / "filter-id" / "reply-message"。
	groupAttr string
	// binaryClass 额外塞一个非 UTF-8 的 Class 值（模拟服务器自己的会话 Class）。
	binaryClass bool
	// statusServer 是否应答 Status-Server（不应答 = 模拟老服务器）。
	statusServer bool
	// blackhole 收到什么都不回（模拟端口被丢包 / 未登记的 NAS）。
	blackhole bool
	// acceptAll 任何账号任何口令都放行（模拟配错的服务器）。
	acceptAll bool
	// challengeUsers 对这些用户回 Access-Challenge。
	challengeUsers map[string]bool
	// noReplyMA 应答**不带** Message-Authenticator（模拟老服务器，也模拟中间人把该属性剥离掉的
	// Blast-RADIUS 姿态）。★默认是「带」——现代 RADIUS 服务器对带了 MA 的请求会在应答里回它
	// （RFC 5080 §2.2.2），而本包默认要求它，夹具的默认值必须与"能正常工作的部署"一致，
	// 否则每条用例都在测逃生舱那条路。
	noReplyMA bool
	// badReplyMA 用错密钥算 Message-Authenticator（模拟篡改 / 密钥不匹配）。
	badReplyMA bool
	// requireReqMA 请求没带（或带错）Message-Authenticator 就丢弃（FreeRADIUS 3.2.5+ 的严格姿态）。默认 true。
	noRequireReqMA bool
}

type testSrv struct {
	addr string
	mu   sync.Mutex
	// 收到的请求类型计数。
	codes map[radius.Code]int
	// 最后一份 Access-Request 是否带了合法的 Message-Authenticator。
	lastReqMAValid bool
}

func (s *testSrv) count(c radius.Code) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.codes[c]
}

func (s *testSrv) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range s.codes {
		n += v
	}
	return n
}

// requestMAValid 校验请求里的 Message-Authenticator（RFC 2869 §5.14；请求侧 Authenticator 原样参与）。
func requestMAValid(p *radius.Packet) bool {
	got := rfc2869.MessageAuthenticator_Get(p)
	if len(got) != 16 {
		return false
	}
	clone := *p
	clone.Attributes = make(radius.Attributes, len(p.Attributes))
	copy(clone.Attributes, p.Attributes)
	_ = rfc2869.MessageAuthenticator_Set(&clone, make([]byte, 16))
	wire, err := clone.MarshalBinary()
	if err != nil {
		return false
	}
	mac := hmac.New(md5.New, p.Secret)
	mac.Write(wire)
	return hmac.Equal(mac.Sum(nil), got)
}

// chapValid 按 RFC 2865 §5.3 验 CHAP-Password。
func chapValid(p *radius.Packet, password string) bool {
	cp := rfc2865.CHAPPassword_Get(p)
	if len(cp) != 17 {
		return false
	}
	chal := rfc2865.CHAPChallenge_Get(p)
	if len(chal) == 0 {
		chal = p.Authenticator[:]
	}
	h := md5.New()
	h.Write(cp[:1])
	h.Write([]byte(password))
	h.Write(chal)
	return hmac.Equal(h.Sum(nil), cp[1:])
}

func startSrv(t *testing.T, o srvOpts) *testSrv {
	t.Helper()
	if o.secret == "" {
		o.secret = "s3cret"
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ts := &testSrv{addr: pc.LocalAddr().String(), codes: map[radius.Code]int{}}

	handler := radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		ts.mu.Lock()
		ts.codes[r.Code]++
		ts.mu.Unlock()
		if o.blackhole {
			return
		}
		reply := func(resp *radius.Packet) {
			if !o.noReplyMA {
				if o.badReplyMA {
					resp.Secret = []byte("not-the-secret")
				}
				if err := signMessageAuthenticator(resp); err != nil {
					t.Errorf("server sign MA: %v", err)
				}
				resp.Secret = []byte(o.secret) // Response Authenticator 仍用真密钥算，让 MD5 那层过、只 MA 不过
			}
			_ = w.Write(resp)
		}
		switch r.Code {
		case radius.CodeStatusServer:
			if !o.statusServer {
				return // 老服务器：不认识 Status-Server，静默
			}
			if !o.noRequireReqMA && !requestMAValid(r.Packet) {
				return // RFC 5997 §2：没有（或算错）MA 的 Status-Server 必须丢
			}
			reply(r.Response(radius.CodeAccessAccept))
		case radius.CodeAccessRequest:
			valid := requestMAValid(r.Packet)
			ts.mu.Lock()
			ts.lastReqMAValid = valid
			ts.mu.Unlock()
			if !o.noRequireReqMA && !valid {
				return // 严格姿态：静默丢弃（与 FreeRADIUS 行为一致）
			}
			// 用户名大小写不敏感：模拟 AD 后端的 FreeRADIUS。客户端**不改**它发出去的用户名，
			// Subject 也照 User-Name 原样（只 trim）——所以 "Alice" 与 "alice" 在这台服务器上
			// 是同一个人，在白帝这边却是两个 Subject；TestSubjectStableAndSourceIsolated 正是断这一点。
			user := strings.ToLower(strings.TrimSpace(rfc2865.UserName_GetString(r.Packet)))
			if o.challengeUsers[user] {
				reply(r.Response(radius.CodeAccessChallenge))
				return
			}
			ok := o.acceptAll
			if !ok {
				pw, known := o.users[user]
				if known {
					if cp := rfc2865.CHAPPassword_Get(r.Packet); cp != nil {
						ok = chapValid(r.Packet, pw)
					} else {
						ok = rfc2865.UserPassword_GetString(r.Packet) == pw
					}
				}
			}
			if !ok {
				resp := r.Response(radius.CodeAccessReject)
				_ = rfc2865.ReplyMessage_SetString(resp, "bad credentials")
				reply(resp)
				return
			}
			resp := r.Response(radius.CodeAccessAccept)
			for _, g := range o.groups[user] {
				switch o.groupAttr {
				case "class":
					_ = rfc2865.Class_AddString(resp, g)
				case "filter-id":
					_ = rfc2865.FilterID_AddString(resp, g)
				case "reply-message":
					_ = rfc2865.ReplyMessage_AddString(resp, g)
				}
			}
			if o.binaryClass {
				_ = rfc2865.Class_Add(resp, []byte{0xff, 0xfe, 0x00, 0x01})
			}
			reply(resp)
		}
	})

	srv := &radius.PacketServer{
		Handler:      handler,
		SecretSource: radius.StaticSecretSource([]byte(o.secret)),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = pc.Close()
	})
	return ts
}
