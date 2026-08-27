package proxy

import (
	"net"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
	"baidi.dev/gateway/internal/spa"
)

// 并发到顶时，新连接必须被**拒绝并留痕**，而不是静默挂住。
//
// ★原实现是 `sem <- struct{}{}` 直接阻塞在 accept 循环里：到顶后新连接停在内核
// backlog，客户端拨号后一直挂到超时，网关既不拒绝也不记日志、不上报、不落审计。
// 那是本项目最不愿意有的形态——控制台上与「一切正常」完全同形，而实际是整台网关
// 对所有新用户不可用。容量到顶是运维信号（该扩容），挂住不会告诉任何人这件事。
//
// 用例把上限设成 1：先占住唯一的 slot（一条不结束的会话），再拨第二条。
func Test并发到顶拒绝新连接并留痕(t *testing.T) {
	// 后端：接了就不回也不关，用来把第一条连接的 slot 长期占住。
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起后端失败：%v", err)
	}
	defer backend.Close()
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			held <- c // 持有不关：会话不结束 → slot 不释放
		}
	}()

	reg := resource.New(backend.Addr().String())
	reg.Replace([]resource.Resource{{
		ID: "res-git", Backend: backend.Addr().String(), AllowUsers: []string{"zhang.wei"},
	}})
	al := spa.NewAllowlist()
	al.Allow("127.0.0.1", "zhang.wei", "user", time.Minute)

	cap := &capture{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败：%v", err)
	}
	defer ln.Close()
	go func() { _ = serve(ln, reg, al, secevent.New(cap.sink), 1) }()

	// 第一条：占住唯一 slot。
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("第一条连接失败：%v", err)
	}
	defer c1.Close()
	if _, err := c1.Write([]byte("CONNECT res-git\n")); err != nil {
		t.Fatalf("写前导失败：%v", err)
	}
	select {
	case <-held: // 后端已被拨通 = handle 正在 io.Copy，slot 占住了
	case <-time.After(5 * time.Second):
		t.Fatal("第一条连接没有拨通后端")
	}

	// 第二条：必须被立刻拒（读到 EOF），而不是挂住。
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("第二条连接失败：%v", err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	n, rerr := c2.Read(buf)
	if rerr == nil && n > 0 {
		t.Fatalf("并发到顶却仍在转发数据：%q", string(buf[:n]))
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatal("并发到顶时连接被静默挂住（读超时）——必须立刻拒绝，否则整台网关的不可用在控制台上不可见")
	}

	// 留痕：类别与正文都要说得出「是我方容量到顶」，别让人去查攻击。
	deadline := time.Now().Add(3 * time.Second)
	var recs []string
	for time.Now().Before(deadline) {
		recs = cap.denyRecs()
		if len(recs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(recs) == 0 {
		t.Fatal("并发到顶的拒绝没有上报——网关一重启这件事就查不到了")
	}
	if !strings.HasPrefix(recs[0], "proxy-capacity|") {
		t.Fatalf("拒绝类别不对：%s", recs[0])
	}
	if !strings.Contains(recs[0], "上限") {
		t.Fatalf("拒绝正文没说明原因：%s", recs[0])
	}
}
