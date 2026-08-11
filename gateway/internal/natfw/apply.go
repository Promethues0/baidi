package natfw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// backend 内核后端。与 darkfw 同款探测方式，但两者的表互不相干。
type backend int

const (
	none backend = iota
	nft          // Linux
	pf           // macOS
)

func detect() backend {
	if _, err := exec.LookPath("nft"); err == nil {
		return nft
	}
	if _, err := exec.LookPath("pfctl"); err == nil {
		return pf
	}
	return none
}

// Applier 把规则集灌进内核，并记住上一次灌的内容以避免无谓重灌。
type Applier struct {
	mu      sync.Mutex
	be      backend
	last    string
	Exempt  Exempt
	DryRun  bool // 只生成不执行（无 root 时的自检模式）
	applied int
}

func New(ex Exempt) *Applier { return &Applier{be: detect(), Exempt: ex} }

// Available 报告本机是否具备内核 NAT 后端。
func (a *Applier) Available() bool { return a.be != none }

// Backend 后端名（供 /diag 与日志如实呈现，不可判定时说不可判定）。
func (a *Applier) Backend() string {
	switch a.be {
	case nft:
		return "nftables(Linux)"
	case pf:
		return "pf(macOS)"
	default:
		return "无（未找到 nft / pfctl）"
	}
}

// Ruleset 按当前后端生成规则集文本（不灌内核）。DryRun 与自检用。
func (a *Applier) Ruleset(policies []Policy) string {
	if a.be == pf {
		return BuildPf(policies, a.Exempt)
	}
	return BuildNft(policies, a.Exempt)
}

// Apply 生成规则集并在**内容有变化时**原子灌入内核。返回 (是否重灌, 错误)。
//
// 无变化不重灌：策略每 15s 全量重拉，每轮都 flush 一次内核 nat 表会在重灌的瞬间
// 出现规则真空——正在建立的连接会漏过转换，表现为偶发的连接失败，极难复现。
func (a *Applier) Apply(policies []Policy) (bool, error) {
	rs := a.Ruleset(policies)
	a.mu.Lock()
	defer a.mu.Unlock()
	if rs == a.last {
		return false, nil
	}
	if a.DryRun || a.be == none {
		a.last = rs
		return true, nil
	}
	if err := a.load(rs, len(policies)); err != nil {
		// 失败不更新 last：下一轮还会重试，而不是记成「已经灌进去了」。
		return false, err
	}
	a.last = rs
	a.applied = len(policies)
	return true, nil
}

func (a *Applier) load(rs string, n int) error {
	switch a.be {
	case nft:
		if n == 0 {
			// 没有策略就整表删掉，而不是灌一张空表——留着空表会让 nft list 上
			// 出现一个 baidi_nat 表，看起来像 NAT 还开着。
			_ = run("nft", "delete", "table", "ip", NftTable)
			return nil
		}
		return runStdin(rs, "nft", "-f", "-")
	case pf:
		f, err := os.CreateTemp("", "baidi-nat-*.conf")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name()) //nolint:errcheck
		if _, err := f.WriteString(rs); err != nil {
			f.Close() //nolint:errcheck
			return err
		}
		f.Close() //nolint:errcheck
		return run("pfctl", "-a", PfAnchor, "-f", f.Name())
	}
	return nil
}

// Flush 清空本机的地址转换规则（进程退出与「策略全删」时调用）。
func (a *Applier) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = ""
	switch a.be {
	case nft:
		return run("nft", "delete", "table", "ip", NftTable)
	case pf:
		return run("pfctl", "-a", PfAnchor, "-F", "nat")
	}
	return nil
}

// Hit 一条规则的命中计数（FR-NAT-17）。
type Hit struct {
	PolicyID string `json:"policyId"`
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
}

// Hits 读回内核计数器。
//
// ★读不到时返回 nil 而不是零值切片：报「0 包命中」会让「规则确实没被匹配」与
// 「我们根本读不到计数」在页面上长得一模一样，而这两者的排障方向完全相反
// （与 posture / 设备指标的不可判定同一条纪律）。
func (a *Applier) Hits() ([]Hit, bool) {
	if a.be != nft {
		return nil, false // pf 的计数按锚点聚合，拆不到规则粒度——如实说不可判定
	}
	out, err := exec.Command("nft", "-j", "list", "table", "ip", NftTable).Output()
	if err != nil {
		return nil, false
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, false
	}
	var hits []Hit
	for _, node := range doc.Nftables {
		raw, ok := node["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil || !strings.HasPrefix(rule.Comment, "baidi:") {
			continue
		}
		h := Hit{PolicyID: strings.TrimPrefix(rule.Comment, "baidi:")}
		for _, e := range rule.Expr {
			var c struct {
				Counter *struct {
					Packets int64 `json:"packets"`
					Bytes   int64 `json:"bytes"`
				} `json:"counter"`
			}
			if err := json.Unmarshal(e, &c); err == nil && c.Counter != nil {
				h.Packets, h.Bytes = c.Counter.Packets, c.Counter.Bytes
			}
		}
		hits = append(hits, h)
	}
	return hits, true
}

// EnableForwarding 打开内核 IP 转发。NAT 要求网关以路由设备形态工作（FR-NAT-11），
// 转发关着的话规则全部正确但一个包都过不去，且没有任何报错。
func EnableForwarding() error {
	switch runtime.GOOS {
	case "linux":
		return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	case "darwin":
		return run("sysctl", "-w", "net.inet.ip.forwarding=1")
	}
	return fmt.Errorf("不支持的平台：%s", runtime.GOOS)
}

// ForwardingEnabled 读取当前转发状态；读不到回 (false,false)。
func ForwardingEnabled() (on bool, known bool) {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			return false, false
		}
		return strings.TrimSpace(string(b)) == "1", true
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").Output()
		if err != nil {
			return false, false
		}
		v, err := strconv.Atoi(strings.TrimSpace(string(out)))
		return v == 1, err == nil
	}
	return false, false
}

func run(bin string, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		slog.Warn("NAT 规则命令失败", "bin", bin, "err", err.Error(), "stderr", strings.TrimSpace(stderr.String()))
		return fmt.Errorf("%s: %w (%s)", bin, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func runStdin(stdin, bin string, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		slog.Warn("NAT 规则灌入失败", "bin", bin, "err", err.Error(), "stderr", strings.TrimSpace(stderr.String()))
		return fmt.Errorf("%s: %w (%s)", bin, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
