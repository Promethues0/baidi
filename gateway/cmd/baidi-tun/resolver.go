// 隧道内 DNS 的「系统侧接线」：把哪些域名交给隧道内解析器、怎么写进系统解析器、
// 以及断开时怎么把它们**干净地**收回来。
//
// 本文件只放平台无关的纯函数（域名规范化、文件名/规则名映射、记录表解析、清理清单推导），
// 真正动系统配置的部分在 resolver_{darwin,linux,windows}.go。这样切分有两个理由：
//
//	① 纯函数能在任意平台跑单测——写 /etc/resolver 需要 root，单测里绝不能真写；
//	② 三平台「怎么写」差异极大（resolver 文件 / systemd-resolved / NRPT），
//	   但「写什么名字」的口径必须完全一致，否则清理时会漏掉一部分。
//
// ★清理是这一整块最容易被忽略、后果又最难归因的一环：隧道断开后若
// /etc/resolver/corp.internal（或 NRPT 规则、或 resolv.conf 里那行 nameserver）还在，
// 该域名会被指向一个已经不存在的 VIP——症状是「断开客户端后这个域名永久解析失败」，
// 用户完全不会联想到是接入客户端留下的，只会觉得「公司系统坏了」。故三平台都实现清理，
// 且都覆盖 defer 与信号两条路径，并在启动时顺带扫掉上一轮异常退出的残留
// （SIGKILL/断电杀不掉的那种残留只能靠这次扫描收拾）。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	// dnsMarker 写进系统解析器配置里的所有权标记。清理时**只删带此标记的内容**——
	// 管理员手工放在 /etc/resolver 下的同名文件绝不能被我们顺手删掉
	// （那是把「VPN 断开后域名不通」升级成「装过一次 VPN 后域名永久不通」）。
	dnsMarker = "baidi-tun"
	// resolverDir macOS 按域分流的配置目录（见 resolver(5)）。放公共文件里是为了让
	// 文件名映射能在任意平台跑单测；真正写它的只有 resolver_darwin.go。
	resolverDir = "/etc/resolver"
	// backupSuffix 接管既有配置时的备份后缀。备份只在「原文件不是我们写的」时产生，
	// 清理时原样还回去。
	backupSuffix = ".baidi-bak"
)

// normalizeDomain 把一个搜索域规范化为「小写、无尾点、无前导点」的形式，并做合法性校验。
//
// ★大小写与尾点必须在此统一：DNS 名字大小写不敏感、线上形制带尾点，而 macOS 的
// /etc/resolver/<domain> 与 Windows NRPT 的 Namespace 都是按字面量匹配的。不规范化的
// 症状是「配了 OA.corp.internal，查 oa.corp.internal. 却不走隧道」——而且只在某些
// 大小写写法下复现，极难归因。
//
// 校验同时兜住一个更硬的问题：域名会被直接拼进 /etc/resolver/<domain> 的路径里，
// 含 `/` 或 `..` 的输入等于让控制面（或篡改了剖面响应的中间人）指定任意写入路径。
// 这里把字符集收死到 [a-z0-9-.]，空标签一律拒——`..` 会产生空标签，因而被挡住。
// 返回空串表示「该项为空，调用方跳过」，返回 error 表示配置有误、应当早失败。
func normalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	// "*.corp.internal" 与 ".corp.internal" 都是常见写法，语义上都是「按后缀分流」，
	// 与 "corp.internal" 等价，统一收敛成后者。
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	if d == "" {
		return "", nil
	}
	// 根域/通配：会把**全部** DNS 查询导进隧道，隧道一断全网解析全挂。
	// 本项目明确只做按域分流，这类输入是配置错误而不是「更强的接管」。
	if d == "*" {
		return "", fmt.Errorf("搜索域 %q 等价于接管全部域名：只支持按域分流（全局接管会让隧道一断全网解析全挂）", raw)
	}
	if len(d) > 253 {
		return "", fmt.Errorf("搜索域 %q 超长（>253）", raw)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "", fmt.Errorf("搜索域 %q 含空标签（连续的点或首尾点）", raw)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("搜索域 %q 的标签 %q 超长（>63）", raw, label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("搜索域 %q 的标签 %q 以连字符起止", raw, label)
		}
		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return "", fmt.Errorf("搜索域 %q 含非法字符 %q（只允许字母/数字/连字符/点）", raw, string(c))
		}
	}
	return d, nil
}

// splitDomains 解析 -dns-domains 的逗号分隔清单：规范化 + 去空 + 去重（保持原序）。
// 去重是必须的：同一个域重复写两遍会让 macOS 侧重复写同一文件（无害）、
// 但 Windows 侧重复添加 NRPT 规则（清理时只删掉一条，另一条永久残留）。
func splitDomains(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(s, ",") {
		d, err := normalizeDomain(raw)
		if err != nil {
			return nil, err
		}
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// normalizeFQDN 规范化记录表里的名字：小写、去首尾空白、去尾点。
// 与数据面 dataplane 装表/查表两侧的规范化口径必须一致（同为「小写 + 去尾点」）。
func normalizeFQDN(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
}

// parseDNSRecords 解析 -dns-records 指向的 JSON（FQDN → IP 字面量）。
//
// 严格校验而非「跳过坏项」：这张表由控制面剖面生成，出现非 IP 的值只可能是控制面
// 或落盘环节的 bug。静默跳过的症状是「某一个应用死活解析不出来，其余都正常」，
// 而日志里什么都没有——正是本项目反复吃亏的那类失效。宁可起不来。
// 空文件按空表处理（合法：纯 IP 场景不需要记录）。
func parseDNSRecords(b []byte) (map[string]string, error) {
	out := map[string]string{}
	if len(bytes.TrimSpace(b)) == 0 {
		return out, nil
	}
	raw := map[string]string{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("记录表不是 {\"域名\":\"IP\"} 形式的 JSON: %w", err)
	}
	for k, v := range raw {
		name := normalizeFQDN(k)
		if name == "" {
			return nil, fmt.Errorf("记录表含空域名（键 %q）", k)
		}
		ip := net.ParseIP(strings.TrimSpace(v))
		if ip == nil {
			return nil, fmt.Errorf("记录 %q 的地址 %q 不是 IP 字面量", k, v)
		}
		val := ip.String()
		// 规范化后撞名且地址不一致：说明控制面同时下发了 OA.corp.internal 与
		// oa.corp.internal 两条不同答案。谁生效取决于 map 迭代序（不稳定），
		// 必须报错而不是随便挑一条。
		if prev, dup := out[name]; dup && prev != val {
			return nil, fmt.Errorf("记录表中 %q 规范化后重复且地址不一致（%s vs %s）", name, prev, val)
		}
		out[name] = val
	}
	return out, nil
}

// resolverFilePath macOS 的按域分流配置文件路径。域名已由 normalizeDomain 校验过字符集，
// 这里不会拼出 resolverDir 之外的路径。
func resolverFilePath(domain string) string {
	return resolverDir + "/" + domain
}

// resolverFiles 由搜索域清单推导出「我们会写、也必须清理」的文件清单。
// 清理路径复用它，保证写与删的口径同源——两处各写一遍是漏删的经典来源。
func resolverFiles(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		out = append(out, resolverFilePath(d))
	}
	return out
}

// resolverFileContent macOS /etc/resolver/<domain> 的内容。首行标记用于所有权判定，
// 第二行的说明是写给「隧道已断却发现这个文件还在」的人看的——那正是清理失败的现场。
func resolverFileContent(server string) string {
	return "# " + dnsMarker + " 自动生成（白帝安全接入客户端）：该域名的解析交给隧道内解析器。\n" +
		"# 断开接入时本文件会被自动删除；若隧道已断而它还在，说明客户端异常退出，可直接删除。\n" +
		"nameserver " + server + "\n"
}

// isBaidiManaged 判定一份系统解析器配置是否由我们写入（据此决定能不能删）。
func isBaidiManaged(content string) bool {
	return strings.Contains(content, dnsMarker)
}

// nrptNamespace Windows NRPT 规则的 Namespace 形制：域名后缀必须以点开头，
// ".corp.internal" 才表示「corp.internal 及其子域」；写成 "corp.internal" 会被当作
// 单个精确名字，症状是「oa.corp.internal 不走隧道解析器而 corp.internal 走」。
func nrptNamespace(domain string) string {
	return "." + domain
}

// resolvectlDomainArgs systemd-resolved 的 `resolvectl domain <iface> …` 参数形制：
// "~domain" 是**仅路由**（routing-only）域，只把该域的查询导向本接口的解析器，
// 不把它加进搜索域。少了这个 "~" 前缀就变成搜索域语义，会让裸主机名被拼上该域去查，
// 属于额外的、没人要的行为改变。
func resolvectlDomainArgs(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		out = append(out, "~"+d)
	}
	return out
}

// fileExists 存在性判定（只用于备份/还原这类 best-effort 分支，故吞掉具体错误）。
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ── 清理钩子 ──
//
// 清理函数由平台实现返回，注册到这里，由 main 在三条路径上触发：正常返回的 defer、
// 数据面报错退出前的显式调用、以及信号处理协程。runDNSCleanup 幂等（取出即置空），
// 平台实现自身再用 sync.Once 兜一层——重复清理不能把「管理员在此期间新建的同名配置」删掉。
var (
	dnsCleanupMu sync.Mutex
	dnsCleanupFn func()
)

func setDNSCleanup(f func()) {
	dnsCleanupMu.Lock()
	dnsCleanupFn = f
	dnsCleanupMu.Unlock()
}

func runDNSCleanup() {
	dnsCleanupMu.Lock()
	f := dnsCleanupFn
	dnsCleanupFn = nil
	dnsCleanupMu.Unlock()
	if f != nil {
		f()
	}
}
