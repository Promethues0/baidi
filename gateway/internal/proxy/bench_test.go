package proxy

// 数据面首批基准（wave9）：每流 TLS/TLCP 握手成本 · 单流吞吐 · 并发建流（含到顶行为）。
//
// ★定位：**防回归 + 给传输模型的代价一个量级**，不是容量承诺、不是规格。
// 口径（缺一条就会被读成规格）：
//   ① 全部进程内回环：客户端、网关 proxy、后端三方跑在同一进程、同一台机器的同一批核上，
//      ns/op 里**客户端侧与网关侧的握手 CPU 是加在一起的**，allocs/op 是整个进程的
//      （testing 用 runtime.MemStats 差值，服务端 goroutine 的分配也算进来）。
//      没有网络 RTT、没有丢包、没有 NAT；真实部署里每流握手还要多付 1~2 个 RTT。
//   ② 为什么量「每流一条握手」：白帝的隧道形态是**每条 TCP 流各拨一条完整 TLS/TLCP 连接**
//      + 首行 `CONNECT <资源id>\n`（dataplane.go 的 tunneler.tunnel→dialEndpoint / proxy.go 的 handle），
//      客户端 tlsClientConfig 没配 ClientSessionCache → 每流都是**完整**握手（无会话复用）。
//      一个网页几十条并发流就是几十次握手，这是传输模型的固有代价，此前从未量过。
//   ③ 证书形态照生产：网关启动期自签 **RSA-2048**（cmd/baidi-gateway mustSelfSigned），
//      握手成本里服务端 RSA 签名占大头；ECDSA P-256 那组只是对照，**生产没有这个选项**。
//   ④ slog 输出丢弃（handle 每流打两行 Info）：生产上这两行走 journald，是这里没算的成本。
//      secevent 上报器接的是空 sink（节流表照常走，网络上报不在口径内）。
//   ⑤ 钉扎回调（dataplane.PinVerifier）不在口径内——它只是一次 SHA-256 与常量比较。
//   ⑥ 并发那组的 limit 是**注入的小值**（serve 的 limit 形参，生产恒为 maxConcurrent=1024），
//      为的是在单测规模上观察「到顶时拒绝而非挂住」，不代表 1024 附近的真实行为。
//
// 本机样本与解读写在 docs/ARCHITECTURE.md 第七节「不能声称」的 PERF 段；
// 数字随机器变化，比较**同一台机器上改动前后的差**才有意义。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"

	"baidi.dev/gateway/internal/gmcert"
	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
	"baidi.dev/gateway/internal/spa"
)

const benchRID = "res-bench"

// ── 证书材料（各只生成一次：RSA-2048 keygen 要几百毫秒，别让它进任何一组的计时）──

var (
	benchRSAOnce   sync.Once
	benchRSACert   tls.Certificate
	benchECOnce    sync.Once
	benchECCert    tls.Certificate
	benchTLCPOnce  sync.Once
	benchTLCPCerts []tlcp.Certificate
	benchTLCPPool  *smx509.CertPool
	benchTLCPErr   error
)

// selfSignedTLS 与 cmd/baidi-gateway 的 mustSelfSigned 同形态（RSA-2048，SAN 含 127.0.0.1）；
// ecdsa=true 换成 P-256 作对照。
func selfSignedTLS(tb testing.TB, ecdsaKey bool) tls.Certificate {
	tb.Helper()
	var (
		pub     any
		priv    any
		keyPEM  []byte
		keyType string
	)
	if ecdsaKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		der, _ := x509.MarshalECPrivateKey(k)
		pub, priv, keyPEM, keyType = &k.PublicKey, k, der, "EC PRIVATE KEY"
	} else {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tb.Fatal(err)
		}
		pub, priv, keyPEM, keyType = &k.PublicKey, k, x509.MarshalPKCS1PrivateKey(k), "RSA PRIVATE KEY"
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "baidi-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"baidi-gateway", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyPEM}))
	if err != nil {
		tb.Fatal(err)
	}
	return cert
}

func rsaCert(tb testing.TB) tls.Certificate {
	benchRSAOnce.Do(func() { benchRSACert = selfSignedTLS(tb, false) })
	return benchRSACert
}

func ecCert(tb testing.TB) tls.Certificate {
	benchECOnce.Do(func() { benchECCert = selfSignedTLS(tb, true) })
	return benchECCert
}

// tlcpMaterial 用 gmcert 在临时目录里签一套 SM2 双证书 + CA 池（与 -gm 网关同一条签发路径）。
// 临时目录签完即删，之后用的都是内存里的对象。
func tlcpMaterial(tb testing.TB) ([]tlcp.Certificate, *smx509.CertPool) {
	benchTLCPOnce.Do(func() {
		dir, err := os.MkdirTemp("", "baidi-bench-gm-")
		if err != nil {
			benchTLCPErr = err
			return
		}
		defer os.RemoveAll(dir)
		benchTLCPCerts, benchTLCPErr = gmcert.EnsureGateway(dir)
		if benchTLCPErr != nil {
			return
		}
		benchTLCPPool, benchTLCPErr = gmcert.LoadCAPool(dir)
	})
	if benchTLCPErr != nil {
		tb.Fatalf("准备 TLCP 证书失败：%v", benchTLCPErr)
	}
	return benchTLCPCerts, benchTLCPPool
}

// ── 脚手架：后端 / 网关 / 拨号 ──

// quietLog 把默认 slog 换成丢弃（handle 每流两行 Info，成千上万次迭代会淹掉基准输出）；结束恢复。
func quietLog(b *testing.B) {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(old) })
}

// startBenchBackend 起一个真 TCP 后端，每条连接交给 handler（handler 负责关连接）。结束时关监听。
// （nopreamble_test.go 里已有一个 startBackend，故换名。）
func startBenchBackend(tb testing.TB, handler func(net.Conn)) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("起后端失败：%v", err)
	}
	tb.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	return ln.Addr().String()
}

// firstByteBackend 接到即回 1 字节，然后吸干对端直到 EOF —— 给「握手 + 首字节」用。
func firstByteBackend(c net.Conn) {
	defer c.Close()
	_, _ = c.Write([]byte{'k'})
	_, _ = io.Copy(io.Discard, c)
}

// chunkAckBackend 每收满 n 字节回 1 字节 ack，直到对端断开 —— 给吞吐用。
// 用 ack 而不是回显：回显会让每个字节过网关两次，量到的就不是单向吞吐。
func chunkAckBackend(n int64) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		for {
			if _, err := io.CopyN(io.Discard, c, n); err != nil {
				return
			}
			if _, err := c.Write([]byte{'a'}); err != nil {
				return
			}
		}
	}
}

// oneShotAckBackend 收满 n 字节、回 1 字节 ack、关连接 —— 给并发建流用（关连接 = 释放 slot）。
func oneShotAckBackend(n int64) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		if _, err := io.CopyN(io.Discard, c, n); err != nil {
			return
		}
		_, _ = c.Write([]byte{'a'})
	}
}

// startProxy 在 ln 上跑真实的 serve 循环：放行表预先放行 127.0.0.1、注册表只有 benchRID。
//
// ★刻意**不关**这个监听：serve 对 Accept 错误是 `continue`，监听一关它就空转烧 CPU，
// 会污染同一进程里后续每一组基准（这是 serve 的既有形态，不在本批改动范围内）。
// 监听留到进程结束，代价是一个阻塞在 Accept 上的 goroutine。
func startProxy(tb testing.TB, ln net.Listener, backend string, limit int) {
	tb.Helper()
	reg := resource.New("")
	reg.Replace([]resource.Resource{{ID: benchRID, Backend: backend, AllowUsers: []string{"bench.user"}}})
	al := spa.NewAllowlist()
	al.Allow("127.0.0.1", "bench.user", "user", time.Hour)
	rep := secevent.New(func(string, string, string, int, bool) {})
	go func() { _ = serve(ln, reg, al, rep, limit) }()
}

// dialer 是一种加密形态的客户端拨号（返回已完成握手的连接）。
type dialer func() (net.Conn, error)

func tlsDialer(addr string) dialer {
	// 与 dataplane.tlsClientConfig 同款：InsecureSkipVerify（链校验必然失败），无 ClientSessionCache。
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	return func() (net.Conn, error) { return tls.Dial("tcp", addr, cfg) }
}

func tlcpDialer(addr string, pool *smx509.CertPool) dialer {
	cfg := &tlcp.Config{RootCAs: pool, ServerName: "localhost"}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return func() (net.Conn, error) {
		c, err := tlcp.DialWithDialer(d, "tcp", addr, cfg) // 与 crypto/tls 一样，Dial 返回即已握手
		if err != nil {
			return nil, err // 不能直接 return 多值：出错时会把 typed-nil 的 *tlcp.Conn 装进非 nil 接口
		}
		return c, nil
	}
}

func tcpDialer(addr string) dialer {
	return func() (net.Conn, error) { return net.DialTimeout("tcp", addr, 5*time.Second) }
}

// openFlow = 拨号（含握手）+ 写 CONNECT 前导。这就是客户端每条 TCP 流要付的固定动作。
func openFlow(d dialer) (net.Conn, error) {
	c, err := d()
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte(preamblePrefix + benchRID + "\n")); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// listenTLS / listenTLCP 起网关侧监听（与 Serve / ServeTLCP 里的配置一致）。
func listenTLS(tb testing.TB, cert tls.Certificate) net.Listener {
	tb.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		tb.Fatal(err)
	}
	return ln
}

func listenTLCP(tb testing.TB, certs []tlcp.Certificate) net.Listener {
	tb.Helper()
	ln, err := tlcp.Listen("tcp", "127.0.0.1:0", &tlcp.Config{Certificates: certs})
	if err != nil {
		tb.Fatal(err)
	}
	return ln
}

// negotiatedSuite 用一条探测连接读出实际协商的版本/套件，写进子基准名——
// 名字里带套件，看输出的人才知道量的是哪种加密，不必去翻默认值。
func negotiatedSuite(tb testing.TB, d dialer) string {
	tb.Helper()
	c, err := openFlow(d)
	if err != nil {
		tb.Fatalf("探测握手失败：%v", err)
	}
	defer c.Close()
	switch cc := c.(type) {
	case *tls.Conn:
		st := cc.ConnectionState()
		return tls.VersionName(st.Version) + "_" + tls.CipherSuiteName(st.CipherSuite)
	case *tlcp.Conn:
		st := cc.ConnectionState()
		return "TLCP_" + tlcp.CipherSuiteName(st.CipherSuite)
	}
	return "TCP"
}

// ── a. 每流握手成本 ──

// BenchmarkPerFlowHandshake：每次迭代 = 新建一条加密连接（完整握手）+ 写 CONNECT 前导
// + 收到后端首字节 + 关闭。这是「每条 TCP 流各拨一条 TLS」这个传输模型的直接成本。
//
// 量的是什么：一条流从拨号到首字节的**进程内**端到端耗时（客户端握手 + 网关握手 + 前导解析
// + 查表授权 + 拨后端 + 一字节转发），以及整个过程在进程里的堆分配次数。
// 不代表什么：不是网关单机能扛的 conn/s（客户端在同一批核上抢 CPU，且无网络 RTT）；
// 不是任何时延规格。RSA-2048 是生产形态，ECDSA 是对照——看两者的差就知道
// 服务端签名在握手成本里占多大。
func BenchmarkPerFlowHandshake(b *testing.B) {
	quietLog(b)
	backend := startBenchBackend(b, firstByteBackend)

	run := func(b *testing.B, d dialer) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, err := openFlow(d)
			if err != nil {
				b.Fatalf("建流失败：%v", err)
			}
			if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
				b.Fatalf("没收到后端首字节：%v", err)
			}
			_ = c.Close()
		}
		b.StopTimer()
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "flows/s")
	}

	rsaLn := listenTLS(b, rsaCert(b))
	startProxy(b, rsaLn, backend, maxConcurrent)
	rsaD := tlsDialer(rsaLn.Addr().String())
	b.Run("RSA2048自签(生产形态)/"+negotiatedSuite(b, rsaD), func(b *testing.B) { run(b, rsaD) })

	ecLn := listenTLS(b, ecCert(b))
	startProxy(b, ecLn, backend, maxConcurrent)
	ecD := tlsDialer(ecLn.Addr().String())
	b.Run("ECDSA-P256(对照,生产无此选项)/"+negotiatedSuite(b, ecD), func(b *testing.B) { run(b, ecD) })

	certs, pool := tlcpMaterial(b)
	gmLn := listenTLCP(b, certs)
	startProxy(b, gmLn, backend, maxConcurrent)
	gmD := tlcpDialer(gmLn.Addr().String(), pool)
	b.Run("国密SM2双证书(-gm形态)/"+negotiatedSuite(b, gmD), func(b *testing.B) { run(b, gmD) })
}

// ── b. 单流吞吐 ──

const throughputChunk = 1 << 20 // 每次迭代推 1 MiB，后端收满回 1 字节 ack

// BenchmarkFlowThroughput：一条**已建立**的流上，客户端每次迭代写 1 MiB、等后端 1 字节 ack。
// b.SetBytes 让 go test 报 MB/s。
//
// 量的是什么：单条流的单向数据面吞吐（客户端加密 → 网关解密 → io.Copy → 明文到后端），
// 含每 MiB 一次 ack 往返的进程内开销。「直连 TCP 对照」是不经网关、客户端直连后端的同一动作，
// 两者之差就是网关（TLS 终止 + 用户态转发）在这条路上加的成本。
// 不代表什么：不是多流聚合吞吐，不是 utun/netstack 那一段（那段在 dataplane 包，本批不量），
// 不是任何带宽规格——真实链路上限通常在网络而不在这里。
func BenchmarkFlowThroughput(b *testing.B) {
	quietLog(b)
	backend := startBenchBackend(b, chunkAckBackend(throughputChunk))
	payload := make([]byte, throughputChunk)
	_, _ = rand.Read(payload)

	run := func(b *testing.B, c net.Conn) {
		ack := make([]byte, 1)
		b.SetBytes(throughputChunk)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := c.Write(payload); err != nil {
				b.Fatalf("写入失败：%v", err)
			}
			if _, err := io.ReadFull(c, ack); err != nil {
				b.Fatalf("没收到 ack：%v", err)
			}
		}
	}

	tlsLn := listenTLS(b, rsaCert(b))
	startProxy(b, tlsLn, backend, maxConcurrent)
	tlsD := tlsDialer(tlsLn.Addr().String())
	b.Run("经网关TLS/"+negotiatedSuite(b, tlsD), func(b *testing.B) {
		c, err := openFlow(tlsD)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		run(b, c)
	})

	certs, pool := tlcpMaterial(b)
	gmLn := listenTLCP(b, certs)
	startProxy(b, gmLn, backend, maxConcurrent)
	gmD := tlcpDialer(gmLn.Addr().String(), pool)
	b.Run("经网关国密/"+negotiatedSuite(b, gmD), func(b *testing.B) {
		c, err := openFlow(gmD)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		run(b, c)
	})

	b.Run("直连TCP对照(不经网关)", func(b *testing.B) {
		// 直连时**不发** CONNECT 前导：经网关的两组里前导被网关消费掉、后端看不到；
		// 直连若也发，chunkAckBackend 按字节计数会把那 18 字节算进第一块，两条曲线就不同口径了。
		c, err := tcpDialer(backend)()
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		run(b, c)
	})
}

// ── c. 并发建流与到顶行为 ──

const concurrentPayload = 4 << 10 // 每条流推 4 KiB，后端 ack 后关连接（= 释放 slot）

// BenchmarkConcurrentFlows：b.RunParallel 下并发建流（完整握手 + 前导 + 4 KiB + ack + 关闭）。
//
// 量的是什么：多核并发下每流的平均耗时与成功建流速率（"ok_flows/s"），以及 serve 的并发
// 信号量**到顶时的行为**——"rejected/op" 是被网关以 proxy-capacity 拒掉的比例。
// 「上限充足」组 limit 远大于并发度，应当 rejected≈0；「上限紧张」组把 limit 注入成一个
// 比并发 goroutine 数还小的值，拒绝必然发生：这组要看的不是数字大小，而是**拒绝是立刻的**
// （ns/op 不因到顶而飙到秒级——改造前的形态是挂在内核 backlog 里直到超时）。
// 不代表什么：limit 是注入的小值，不是 1024；并发度 = GOMAXPROCS×SetParallelism，
// 客户端与网关同抢一批核，拒绝比例随调度抖动，**不是**任何并发规格。
func BenchmarkConcurrentFlows(b *testing.B) {
	quietLog(b)
	backend := startBenchBackend(b, oneShotAckBackend(concurrentPayload))
	payload := make([]byte, concurrentPayload)

	run := func(b *testing.B, d dialer, limit int) {
		var okN, rejN atomic.Int64
		b.SetParallelism(2) // 并发 goroutine = 2×GOMAXPROCS
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			ack := make([]byte, 1)
			for pb.Next() {
				c, err := openFlow(d)
				if err != nil {
					// 到顶时网关在握手前就把 TCP 关了：客户端表现为握手读到 EOF / 连接重置。
					rejN.Add(1)
					continue
				}
				_, werr := c.Write(payload)
				_, rerr := io.ReadFull(c, ack)
				_ = c.Close()
				if werr != nil || rerr != nil {
					rejN.Add(1) // 握手后被拒（如 slot 在握手期间被抢）也算一次未建成
					continue
				}
				okN.Add(1)
			}
		})
		b.StopTimer()
		total := okN.Load() + rejN.Load()
		if total == 0 {
			b.Fatal("一次迭代都没跑")
		}
		b.ReportMetric(float64(rejN.Load())/float64(total), "rejected/op")
		b.ReportMetric(float64(okN.Load())/b.Elapsed().Seconds(), "ok_flows/s")
		if limit > 64 && rejN.Load() > 0 {
			b.Errorf("上限充足（limit=%d）却有 %d 次被拒：要么 slot 泄漏，要么脚手架有误", limit, rejN.Load())
		}
	}

	// 监听与 serve 循环在 b.Run 之外起：子基准的函数体会随 b.N 递增被执行多次，
	// 放在里面每次都会多起一个（永不关闭的）监听。
	for _, tc := range []struct {
		name  string
		limit int
	}{{"上限充足_limit256", 256}, {"上限紧张_limit4", 4}} {
		ln := listenTLS(b, rsaCert(b))
		startProxy(b, ln, backend, tc.limit)
		d := tlsDialer(ln.Addr().String())
		b.Run(tc.name, func(b *testing.B) { run(b, d, tc.limit) })
	}
}

// ── 脚手架自检（常规 go test 下运行，几十毫秒）──
//
// 基准只在 -bench 时执行，脚手架若悄悄坏了（放行表没放行、前导拼错、后端不回字节）
// 要等到下次有人跑基准才发现。这两条用普通用例把「一条流走得通」钉住，ECDSA 是为了
// 不让 RSA keygen 的几百毫秒进 CI。

func smokeFlow(t *testing.T, d dialer) {
	t.Helper()
	c, err := openFlow(d)
	if err != nil {
		t.Fatalf("基准脚手架建流失败：%v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 1)
	if _, err := io.ReadFull(c, got); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("基准脚手架：3s 内没收到后端首字节（放行表 / 注册表 / 前导三者之一没接对）")
		}
		t.Fatalf("基准脚手架：读后端首字节失败：%v", err)
	}
	if got[0] != 'k' {
		t.Fatalf("后端首字节应为 'k'，得到 %q", got)
	}
}

func Test基准脚手架_一条TLS流走通(t *testing.T) {
	backend := startBenchBackend(t, firstByteBackend)
	ln := listenTLS(t, selfSignedTLS(t, true))
	startProxy(t, ln, backend, maxConcurrent)
	smokeFlow(t, tlsDialer(ln.Addr().String()))
}

func Test基准脚手架_一条TLCP流走通(t *testing.T) {
	backend := startBenchBackend(t, firstByteBackend)
	certs, pool := tlcpMaterial(t)
	ln := listenTLCP(t, certs)
	startProxy(t, ln, backend, maxConcurrent)
	smokeFlow(t, tlcpDialer(ln.Addr().String(), pool))
}
