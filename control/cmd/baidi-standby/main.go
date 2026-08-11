// Command baidi-standby 是白帝控制面的**温备（warm standby）**守护进程。
//
// 它做且只做三件事：周期性从主机拉一份加密配置备份、校验、落盘；顺带把
// 「我这份是什么时候的」回报给主机。它**不开任何对外监听、不服务任何请求**——
// 备机不是第二个控制面，这一点由"进程里根本没有 http.Server"来保证，
// 而不是靠一句注释或一个默认关闭的开关。
//
// 切换是人工/脚本触发的：deploy/promote-standby.sh（校验 → 解开覆盖 → 起服务 → 自检）。
// 刻意不做自动选主：两节点没有仲裁第三方，自动选主必然脑裂，而脑裂在这套系统里
// 意味着两个控制面同时签发令牌、下发相反的策略。
//
// 用法：
//
//	baidi-standby -primary https://主机:8092 -cert standby.crt.pem -key standby.key.pem \
//	              -ca ca.crt.pem -dir /var/lib/baidi-standby -interval 10m
//	baidi-standby -status  -dir DIR                 # 打印本地同步状态（提升脚本的前置检查）
//	baidi-standby -verify  -file X.bak              # 校验一份备份（解密 + 必须含 baidi.db）
//	baidi-standby -extract -file X.bak -out DIR     # 校验并解开（提升流程用）
//
// 备份口令走环境变量 BAIDI_STANDBY_PASSPHRASE，与主机侧同一把。
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"baidi.dev/control/internal/standby"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	var (
		primary  = flag.String("primary", "", "主机的 mTLS 地址，如 https://10.0.0.1:8092")
		certPath = flag.String("cert", "", "备机 mTLS 客户端证书（CN 须以 "+standby.CNPrefix+" 开头）")
		keyPath  = flag.String("key", "", "备机 mTLS 客户端私钥")
		caPath   = flag.String("ca", "", "控制面内部 CA 证书（校验主机身份）")
		dir      = flag.String("dir", "standby", "本地存放目录（latest.bak / latest.json）")
		interval = flag.Duration("interval", standby.DefaultInterval,
			"同步间隔，即本套温备的 RPO（下限 "+standby.MinInterval.String()+"）")
		addr    = flag.String("addr", "", "备机自报落点（仅在主机页面上展示；默认取主机名）")
		once    = flag.Bool("once", false, "只同步一轮后退出（装机自检 / cron 用）")
		status  = flag.Bool("status", false, "打印本地同步状态后退出")
		verify  = flag.Bool("verify", false, "校验 -file 指定的备份后退出")
		extract = flag.Bool("extract", false, "校验并把 -file 解开到 -out 后退出")
		file    = flag.String("file", "", "-verify / -extract 的输入备份文件")
		out     = flag.String("out", "", "-extract 的输出目录")
	)
	flag.Parse()

	switch {
	case *status:
		os.Exit(runStatus(*dir))
	case *verify:
		os.Exit(runVerify(*file))
	case *extract:
		os.Exit(runExtract(*file, *out))
	}

	pass := os.Getenv("BAIDI_STANDBY_PASSPHRASE")
	if pass == "" {
		fatal("缺少 BAIDI_STANDBY_PASSPHRASE：备份是加密的，没有口令连校验都做不了（也就无从知道拉到的是不是一份能用的备份）")
	}
	if *primary == "" || *certPath == "" || *keyPath == "" || *caPath == "" {
		fatal("-primary / -cert / -key / -ca 均为必填：备机身份是 mTLS 客户端证书，没有它主机不会给出任何备份")
	}
	node, err := commonName(*certPath)
	if err != nil {
		fatal("读客户端证书失败：" + err.Error())
	}
	// ★装机期就拦住前缀写错——照 ipsec- 那条坑的处置：前缀不对时主机只会回 403，
	// 而 403 在日志里很容易被读成"证书没登记/被吊销了"，指向完全错误的排查方向。
	if !strings.HasPrefix(node, standby.CNPrefix) {
		fatal(fmt.Sprintf("证书 CN 是 %q，必须以 %s 开头：主机按 CN 前缀分权，"+
			"写成 gw-1-standby（后缀形态）会被一路 403", node, standby.CNPrefix))
	}
	iv := *interval
	if iv < standby.MinInterval {
		slog.Warn("同步间隔低于下限，已抬回",
			"要求", iv.String(), "实际", standby.MinInterval.String(),
			"原因", "每轮都要主机现做一份全量加密备份（PBKDF2 600k 轮 + 全库打包）")
		iv = standby.MinInterval
	}
	self := *addr
	if self == "" {
		self, _ = os.Hostname()
	}

	cli, err := mtlsClient(*certPath, *keyPath, *caPath)
	if err != nil {
		fatal("装配 mTLS 客户端失败：" + err.Error())
	}
	a := &agent{
		cli: cli, primary: strings.TrimRight(*primary, "/"), node: node,
		dir: *dir, pass: pass, addr: self, interval: iv,
	}

	slog.Info("baidi-standby 启动（温备：只拉备份，不提供任何服务）",
		"node", node, "primary", a.primary, "dir", a.dir, "interval", iv.String(),
		"RPO", "= 同步间隔 "+iv.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if a.syncOnce(ctx) != nil && *once {
		os.Exit(1)
	}
	if *once {
		return
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("收到退出信号，停止同步")
			return
		case <-t.C:
			_ = a.syncOnce(ctx)
		}
	}
}

// agent 一台备机的同步器。
type agent struct {
	cli      *http.Client
	primary  string
	node     string
	dir      string
	pass     string
	addr     string
	interval time.Duration
}

// syncOnce 拉一轮：取 → 校验 → 落盘 → 回报。
//
// ★任何一步失败都**保留本地已有的那份**，并把失败原样回报给主机。
// 静默失败是这套机制最危险的形态：页面显示"温备正常"，而备机手上其实是三周前的库。
func (a *agent) syncOnce(ctx context.Context) error {
	blob, err := a.fetch(ctx)
	if err != nil {
		slog.Error("拉取配置备份失败（本地已有的那份保持不变）", "err", err)
		a.report(ctx, standby.LocalState{}, false, err.Error())
		return err
	}
	st, err := standby.Adopt(a.dir, blob, a.pass, a.node, a.primary, int(a.interval/time.Second), time.Now())
	if err != nil {
		slog.Error("备份校验失败，拒绝覆盖本地", "bytes", len(blob), "err", err)
		a.report(ctx, standby.LocalState{}, false, "校验失败："+err.Error())
		return err
	}
	slog.Info("同步完成", "bytes", st.Bytes, "sha256", short(st.SHA256),
		"备份版本", st.BackupVersion, "生成于", st.BackupCreatedAt, "材料", len(st.Files))
	a.report(ctx, st, true, "")
	return nil
}

func (a *agent) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.primary+standby.PathBackup, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	// 上限 512 MiB：没有上界的话，一个坏掉（或被顶替）的对端能让备机把内存吃光。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("主机回 %d：%s", resp.StatusCode, snippet(body))
	}
	return body, nil
}

// report 把本轮结果回报给主机。失败只记日志——回报不上不影响盘上那份的价值，
// 而主机侧会因为「久未回报」自己把这台备机判成落后（那正是正确的表现）。
func (a *agent) report(ctx context.Context, st standby.LocalState, ok bool, detail string) {
	payload := map[string]any{
		"addr": a.addr, "intervalSec": int(a.interval / time.Second),
		"status": statusWord(ok), "detail": detail,
		"backupVersion": st.BackupVersion, "backupCreatedAt": st.BackupCreatedAt, "sha256": st.SHA256,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		slog.Error("序列化同步回报失败", "err", err)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, a.primary+standby.PathStatus, bytes.NewReader(b))
	if err != nil {
		slog.Error("构造同步回报失败", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.cli.Do(req)
	if err != nil {
		slog.Warn("回报同步状态失败（不影响本地备份）", "err", err)
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		slog.Warn("主机拒绝了同步回报", "status", resp.StatusCode, "body", snippet(body))
	}
}

// ── 一次性子命令（提升流程与装机自检用）──

// statusOut 备机自报的同步状态。落后时长是**现算**的，不落盘——
// 盘上存一个"落后 3 分钟"，读的时候永远是 3 分钟。
type statusOut struct {
	standby.LocalState
	// LagSeconds 盘上那份距今多久。-1 = 不可判定（时间戳解析不出来），不是 0。
	LagSeconds int64  `json:"lagSeconds"`
	LagText    string `json:"lagText"`
	RPO        string `json:"rpo"`
}

func runStatus(dir string) int {
	st, ok, err := standby.LoadLocal(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读本地同步状态失败："+err.Error())
		return 1
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "%s 下没有已校验通过的备份：这台备机从未成功同步过，现在提升它只会得到一套空系统\n", dir)
		return 1
	}
	out := statusOut{LocalState: st, LagSeconds: -1, LagText: "不可判定"}
	if ts, perr := time.ParseInLocation("2006-01-02 15:04:05", st.SyncedAt, time.Local); perr == nil {
		lag := time.Since(ts)
		if lag < 0 {
			lag = 0
		}
		out.LagSeconds, out.LagText = int64(lag/time.Second), standby.HumanDuration(lag)
	}
	out.RPO = "RPO = 同步间隔 " + standby.HumanDuration(time.Duration(st.IntervalSec)*time.Second) +
		"：这个时间点之后的配置改动，提升后不存在"
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return 0
}

func runVerify(file string) int {
	blob, pass, code := readBackup(file)
	if code != 0 {
		return code
	}
	meta, files, err := standby.VerifyBackup(blob, pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "校验不通过："+err.Error())
		return 1
	}
	fmt.Printf("✓ 备份校验通过：版本 %s，生成于 %s，%d 项材料\n", meta.Version, meta.CreatedAt, len(files))
	fmt.Println("  " + strings.Join(meta.Files, "  "))
	if meta.Note != "" {
		fmt.Println("  备注：" + meta.Note)
	}
	return 0
}

func runExtract(file, out string) int {
	if strings.TrimSpace(out) == "" {
		fmt.Fprintln(os.Stderr, "-extract 需同时指定 -out <目录>")
		return 2
	}
	blob, pass, code := readBackup(file)
	if code != 0 {
		return code
	}
	names, err := standby.ExtractTo(out, blob, pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解开失败（未写出任何内容前即中止）："+err.Error())
		return 1
	}
	fmt.Printf("✓ 已解开 %d 项材料到 %s\n", len(names), out)
	for _, n := range names {
		fmt.Println("  " + n)
	}
	return 0
}

func readBackup(file string) ([]byte, string, int) {
	if strings.TrimSpace(file) == "" {
		fmt.Fprintln(os.Stderr, "需指定 -file <备份文件>")
		return nil, "", 2
	}
	pass := os.Getenv("BAIDI_STANDBY_PASSPHRASE")
	if pass == "" {
		fmt.Fprintln(os.Stderr, "缺少 BAIDI_STANDBY_PASSPHRASE")
		return nil, "", 2
	}
	blob, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读备份文件失败："+err.Error())
		return nil, "", 1
	}
	return blob, pass, 0
}

// ── 小工具 ──

// mtlsClient 装配双向 TLS 客户端：认主机用内部 CA（**不跳过校验**），
// 认自己用备机客户端证书。这里没有任何 InsecureSkipVerify 逃生舱——
// 这条链上传的是整套信任材料，接受一个未验证的对端等于把 CA 私钥交给任何人。
func mtlsClient(certPath, keyPath, caPath string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA 证书解析失败：" + caPath)
	}
	return &http.Client{
		Timeout: 10 * time.Minute, // 全量备份可能不小，慢也得让它传完
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		}},
	}, nil
}

// commonName 取客户端证书的 CN（备机 id 的权威来源）。
func commonName(certPath string) (string, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", err
		}
		return c.Subject.CommonName, nil
	}
	return "", errors.New("证书文件里没有 CERTIFICATE 块")
}

func statusWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "baidi-standby: "+msg)
	os.Exit(2)
}
