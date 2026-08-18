package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── IPSec VPN 组网 · 管理侧（明文 :8090 + admin 令牌）──
//
// 本文件的四个端点合起来只做一件事：**表达管理意图**。
// 隧道到底建没建起来、走了哪个套件、传了多少字节，全部由承载它的网关经 mTLS
// 回报（见 ipsec_gateway.go），控制面在这里只负责把两者并排展示。
//
// 这个分工是本轮改造的核心。旧实现里 toggle 直接把 status 写成 'up' 并记一条
// 「建立 IPSec 隧道 · ok」的审计——没有任何进程被通知、没有任何网络动作，
// 而审计日志与控制台都声称隧道已建立。修掉它比把 IKE 写出来更重要：
// 一个会说谎的状态面板比一个没有的功能危险得多。

// ipsecSiteDTO 站点配置 + 实测运行态的合并视图。
//
// 内嵌 store.IpsecSite（JSON 平铺），另挂三样东西：
//   - SA：网关回报的运行态，nil = 还没有任何网关报过这条站点；
//   - ConfigWarning：装载期一定会失败、但控制台上看不出来的配置问题；
//   - 兼容层三字段由 fillLegacy 现算（见下）。
type ipsecSiteDTO struct {
	store.IpsecSite
	SA *store.IpsecSAState `json:"sa,omitempty"`
	// ConfigWarning 配置本身注定跑不通时的中文提示（如「未指派网关」）。
	// ★这一格是专门用来对付静默失效的：未指派网关的站点在协议上完全正常、
	// 只是没有任何网关会去承载它，界面上永远停在 connecting 且零报错。
	ConfigWarning string `json:"configWarning,omitempty"`
}

// fillLegacy 由实测运行态**现算** status/rxBytes/txBytes/lastUp 四个兼容字段。
//
// ★这四个字段在库里已冻结（值分别是 toggle 写死的 'up' 与播种时灌进去的
// 184 MB 常量）。这里现算而不是回读，是为了让尚未升级的控制台显示**真数字**
// 而不是假数字——过渡期里"字段还在但值是真的"比"字段还在且值是假的"好得多。
// 新控制台请改用 enabled + sa.*，这四个字段会随控制台升级一起删掉。
func (d *ipsecSiteDTO) fillLegacy() {
	switch {
	case !d.Enabled:
		d.Status = "down" // 管理员未启用——这是意图，不是故障
	case d.SA == nil:
		// 已下发启用意图，但还没有任何网关回报过。可能是网关刚起、
		// 也可能是根本没有网关认领这条站点（此时 ConfigWarning 会说明）。
		d.Status = "connecting"
	default:
		d.Status = d.SA.State
	}
	d.LastUp = "—"
	if d.SA != nil {
		d.RxBytes, d.TxBytes = d.SA.RxBytes, d.SA.TxBytes
		if d.SA.EstablishedAt > 0 {
			d.LastUp = time.Unix(d.SA.EstablishedAt, 0).Format("2006-01-02 15:04:05")
		}
	}
}

// ipsecStore 取出 IPSec 专用的读写契约。
//
// 类型断言而非 Server 字段：store.Store / store.Writer 是全模块共享接口，
// 而这组方法里有「读 PSK 密文」这种只该被本文件与 ipsec_gateway.go 调用的能力。
// 断言失败只可能发生在把 Server 挂到纯内存 store 上的场景（Memory 不实现它），
// 此时诚实回 503 而不是把 IPSec 页面降级成演示数据——组网配置写不进去却显示
// 保存成功，是比报错更糟的结果。
func (s *Server) ipsecStore(w http.ResponseWriter) (store.IpsecStore, bool) {
	is, ok := s.store.(store.IpsecStore)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储后端不支持 IPSec 组网（需 SQLite）")
		return nil, false
	}
	return is, true
}

// handleIpsec 返回站点组网清单：配置 + 实测运行态并排。
//
// ★仅 admin：站点清单里是**对端公网地址 + 两端内网网段**，等于一张完整的企业内网
// 拓扑图，对攻击者是最有价值的侦察材料之一。此前这里漏了 requireAdmin，任何登录用户
// （含门户里的普通员工）都能整表读走。往这个模型里加任何密钥材料之前，这道闸是硬前置。
func (s *Server) handleIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	sites, err := s.store.Ipsec(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sites")
		return
	}
	states, err := is.IpsecSAStates(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sa states")
		return
	}
	// 运行态按 site_id 索引。★同一 site 可能有多台网关回报（两台抢同一条站点），
	// 这里取 reported_at 最新的一条展示，但清单里保留全量供界面提示冲突——
	// 悄悄丢掉另一条正是「隧道莫名抖动、界面看不出原因」的成因。
	latest := map[string]*store.IpsecSAState{}
	for i := range states {
		st := &states[i]
		if cur, ok := latest[st.SiteID]; !ok || st.ReportedAt > cur.ReportedAt {
			latest[st.SiteID] = st
		}
	}
	out := make([]ipsecSiteDTO, 0, len(sites))
	for _, site := range sites {
		d := ipsecSiteDTO{IpsecSite: site, SA: latest[site.ID]}
		d.ConfigWarning = ipsecConfigWarning(site)
		d.fillLegacy()
		out = append(out, d)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sites": out, "states": states})
}

// ipsecConfigWarning 报出「配置本身注定跑不通、但界面上看不出来」的问题。
//
// ★这是本项目反复吃亏的失败形态的对症药：配置合法、协议正常、就是没有任何东西
// 会发生，且全程零报错（apps.resource_id 空、baidi-tun 只接管一个网段，都是这一类）。
// 返回空串表示没发现问题——它不是权威校验，权威校验在网关装载期，那里会把
// 「group24 本实现不支持」这类原因经 SA 回报打到 LastError。
func ipsecConfigWarning(site store.IpsecSite) string {
	if !site.Enabled {
		return "" // 没启用就不该报警，那是管理意图不是故障
	}
	var warns []string
	if site.GatewayID == "" {
		warns = append(warns, "未指派承载网关（gatewayId 为空），不会有任何网关去建立这条隧道")
	} else if !strings.HasPrefix(site.GatewayID, ipsecCNPrefix) {
		// 组网网关只能用 CN 以 ipsec- 开头的证书调 /api/v1/gateways/ipsec*（见 MTLSHandler
		// 的分权注释），而站点清单按 gateway_id == CN 精确过滤。前缀不对 = 协议上不可能
		// 有任何网关来承载它，且症状是「站点安静地永远 down、日志里一条协商记录都没有」。
		warns = append(warns, "承载网关 "+site.GatewayID+" 不以 "+ipsecCNPrefix+
			" 开头，任何组网网关都取不到这条站点（控制面按证书 CN 精确过滤），请改成 "+ipsecCNPrefix+site.GatewayID)
	}
	if !site.HasPSK {
		warns = append(warns, "尚未设置 PSK，网关装载期会直接拒绝这条站点")
	}
	if site.Auth != "" && site.Auth != "psk" {
		warns = append(warns, "认证方式 "+site.Auth+" 本版本未实现（只支持 psk），网关会拒绝装载")
	}
	if site.PqHybrid {
		warns = append(warns, "后量子混合（pqHybrid）字段保留但网关未实现，会被装载期拒绝")
	}
	return strings.Join(warns, "；")
}

// handleSaveIpsec 新增 / 修改一条站点（admin）。
func (s *Server) handleSaveIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	var it store.IpsecSite
	if err := json.NewDecoder(r.Body).Decode(&it); err != nil || it.Name == "" || it.Peer == "" {
		httpx.Error(w, http.StatusBadRequest, "name/peer 必填")
		return
	}
	if msg := validateIpsecSite(it); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	// 网段引用必须指向真实存在的地址对象，挡住悬空引用。
	for _, ref := range []string{it.LocalRef, it.RemoteRef} {
		if ref == "" {
			continue
		}
		if ok, err := s.objectExists(r.Context(), "addr", ref); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to validate addr ref")
			return
		} else if !ok {
			httpx.Error(w, http.StatusBadRequest, "引用的地址对象不存在")
			return
		}
	}
	saved, err := is.SaveIpsecSite(r.Context(), it)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save ipsec site")
		return
	}
	s.audit(r, "admin", "保存 IPSec 站点「"+saved.Name+"」（承载网关 "+orElse(saved.GatewayID, "未指派")+"）", "ok")
	d := ipsecSiteDTO{IpsecSite: saved}
	d.ConfigWarning = ipsecConfigWarning(saved)
	d.fillLegacy()
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "site": d})
}

// validateIpsecSite 装载前的结构校验。返回空串表示通过。
//
// ★错误信息一律带上**实际值**。「网段格式错误」这种提示对着一个 10.20.0.0/16
// 与 10.20.0.1/16 的差别毫无帮助，而后者是真会被 netip 拒绝的常见手误
// （CIDR 主机位非零）。
func validateIpsecSite(it store.IpsecSite) string {
	for _, f := range []struct{ name, val string }{
		{"localSubnet", it.LocalSubnet}, {"remoteSubnet", it.RemoteSubnet},
	} {
		if f.val == "" {
			return f.name + " 必填（IKEv2 的流量选择器 TSi/TSr 由它推导）"
		}
		p, err := netip.ParsePrefix(f.val)
		if err != nil {
			return f.name + " 不是合法网段：" + f.val + "（应形如 10.20.0.0/16）"
		}
		if p.Masked() != p {
			return f.name + " 的主机位不为零：" + f.val + "，应写作 " + p.Masked().String()
		}
	}
	if msg := ipsecPeerError(it.Peer); msg != "" {
		return msg
	}
	// gatewayId 必须与组网网关的证书 CN 同形。留空是合法的（尚未指派，由 ConfigWarning 提示），
	// 但填了个取不到站点的值就是**静默失效**：控制面按 gateway_id == CN 精确过滤下发，
	// 前缀不对时网关拉到的是空列表而不是错误——站点永远 down 且零日志。入口挡住。
	if it.GatewayID != "" && !strings.HasPrefix(it.GatewayID, ipsecCNPrefix) {
		return "gatewayId 须以 " + ipsecCNPrefix + " 开头（它就是组网网关 mTLS 证书的 CN）：" +
			it.GatewayID + " 改成 " + ipsecCNPrefix + it.GatewayID
	}
	return ""
}

// ipsecPeerError 校验对端 IKE 落点；返回空串表示合法。
//
// 只接受**裸 IP** 与 **IP:端口**（含 IPv6），端口可省（网关按 IKE 默认 500 补）。
//
// ★**FQDN 一律拒收**（wave8 行动 17）。此前这里放行域名、注释还写着「权威解析在网关侧」，
// 而事实完全相反：`gateway/cmd/baidi-ipsec/sync.go` 的 `parsePeer` 是**刻意**不解析域名的，
// 它的错误文案自陈理由——「隧道对端在 DNS 抖动时切换落点，会得到一条谁也解释不清的
// 间歇性故障」，`sync_test.go` 还把「拒收 FQDN」当正确行为钉住。
//
// 于是改造前的形态是：入口不但放行，400 文案还**主动把 `sh.example.com` 列为推荐写法**，
// 管理员照着填、点保存拿到 200 OK，站点安静地永远 down——要等到「已指派网关 + 网关在线
// + 下一轮同步」之后，才能从站点详情的 LastError 里看到那句拒绝。
// 入口与实现必须同口径：数据面不解析，控制面就不能收。
func ipsecPeerError(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "peer 不能为空（对端 IKE 落点，写 IP 或 IP:端口，如 203.0.113.21 或 203.0.113.21:500）"
	}
	if _, err := netip.ParseAddrPort(v); err == nil {
		return ""
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return ""
	}
	// 到这里说明它不是 IP。若长得像域名，给一条**说得出原因**的拒绝，
	// 而不是笼统的"格式不对"——后者会让管理员反复换写法去试。
	host := v
	if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	if host != "" && strings.Contains(host, ".") && !strings.ContainsAny(host, " /\\") {
		return "peer 不能填域名（" + v + "）：本版本的组网网关**不做 DNS 解析**——" +
			"隧道对端在 DNS 抖动时切换落点，会造成一条谁也解释不清的间歇性故障。" +
			"请填对端的固定 IP（可带端口），如 203.0.113.21 或 203.0.113.21:500。"
	}
	return "peer 不是合法的对端地址：" + v + "（只接受 IP 或 IP:端口，如 203.0.113.21、203.0.113.21:500）"
}

// handleDeleteIpsec 删除一条站点（admin）。密钥行与运行态行同事务连带清除。
func (s *Server) handleDeleteIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := is.DeleteIpsecSite(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete ipsec site")
		return
	}
	s.audit(r, "admin", "删除 IPSec 站点 "+id+"（连同 PSK 与运行态记录）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleToggleIpsec 翻转站点的**启用意图**（admin）。
//
// ★审计文案是这次改造的重点之一。原文是「建立 IPSec 隧道 site-sh · ok」，
// 而这个 handler 从来没有建立过任何隧道——审计日志断言了一个从未发生的事实，
// 这在一个以审计闭环为卖点的系统里是最不能接受的一类缺陷。
// 现在只记「下发启用意图」，真正的 up/down 由网关回报后另记（见 ipsec_gateway.go）。
func (s *Server) handleToggleIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	// ★取目标值而非盲翻转。前端提交的是 {enabled: 目标值}（它知道自己想要什么），
	// 服务端按当前值取反的话，两次并发点击、或基于陈旧列表的一次点击，都会把
	// 「我要启用」执行成「停用」——而返回体看起来完全正常。
	// 请求体缺省（旧控制台/curl）时才回退到翻转，保持既有调用方可用。
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body)

	sites, err := s.store.Ipsec(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sites")
		return
	}
	var cur store.IpsecSite
	found := false
	for _, st := range sites {
		if st.ID == id {
			cur, found = st, true
			break
		}
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "站点不存在："+id)
		return
	}
	want := !cur.Enabled
	if body.Enabled != nil {
		want = *body.Enabled
	}
	saved, err := is.SetIpsecEnabled(r.Context(), id, want)
	if errors.Is(err, store.ErrIpsecSiteNotFound) {
		httpx.Error(w, http.StatusNotFound, "站点不存在："+id)
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to toggle ipsec site")
		return
	}
	act := "停用"
	if saved.Enabled {
		act = "启用"
	}
	// 措辞刻意是「下发…意图」而不是「建立/断开」：这一刻只有一个布尔值落了库，
	// 网关最快也要到下一轮同步（15s）才知道，协商成功与否还要更久。
	s.audit(r, "admin", "下发 IPSec 站点 "+id+" 的"+act+"意图（实际状态以网关回报为准）", "ok")
	d := ipsecSiteDTO{IpsecSite: saved}
	d.ConfigWarning = ipsecConfigWarning(saved)
	d.fillLegacy()
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "enabled": saved.Enabled, "site": d,
		// status 保留是为了兼容旧控制台的按钮文案；它现在是 down/connecting 而不是 up。
		"status": d.Status,
	})
}

// minPSKLen PSK 原文最小长度（字节）。
//
// ★20 不是拍脑袋：IKEv2 的 PSK 认证里 AUTH 载荷是 PSK 的 PRF 输出，
// 抓到一次完整握手就能对 PSK 做**离线**字典攻击——没有任何速率限制能帮上忙。
// 弱 PSK 在这里等于没有认证。够不到长度就让管理员用「生成随机 PSK」。
const minPSKLen = 20

// handleSetIpsecPSK 设置一条站点的预共享密钥（admin，只写不读）。
//
// 两种用法：
//
//	{"psk": "……"}      直接写入（长度 ≥ minPSKLen）
//	{"generate": true} 控制面生成 32 字节随机密钥，**只在本次响应里返回一次**
//
// 后者照抄 handleIssueGatewayCert 的姿态：服务端不提供任何回读路径，
// 管理员没抄下来就只能重新生成。回显没有操作价值（配错了重设即可），只有泄露面。
func (s *Server) handleSetIpsecPSK(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	var b struct {
		PSK      string `json:"psk"`
		Generate bool   `json:"generate"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}

	var psk []byte
	var generated string
	switch {
	case b.Generate:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "生成随机 PSK 失败")
			return
		}
		// base64 而不是 hex：同样 32 字节熵，字符串短 1/3，管理员抄到对端设备上少错一位。
		generated = base64.RawURLEncoding.EncodeToString(raw)
		psk = []byte(generated)
	case len(b.PSK) >= minPSKLen:
		psk = []byte(b.PSK)
	default:
		// 错误信息带上实际长度与期望长度——「PSK 太短」不告诉管理员还差多少。
		httpx.Error(w, http.StatusBadRequest,
			"PSK 至少 "+strconv.Itoa(minPSKLen)+" 字节（实得 "+strconv.Itoa(len(b.PSK))+"）；"+
				"IKEv2 的 PSK 可被离线字典攻击，弱口令等于没有认证。可改用 {\"generate\":true} 让控制面生成")
		return
	}

	box, err := secret.Default()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "PSK 主密钥不可用（"+secret.DefaultKeyPathEnv+"）："+err.Error())
		return
	}
	// AAD 绑 site_id：把这一行密文剪贴到别的站点上会解不开，而不是悄悄生效。
	nonce, ct, err := box.Seal(id, psk)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "加密 PSK 失败")
		return
	}
	version, err := is.SaveIpsecSecret(r.Context(), store.IpsecSecret{
		SiteID: id, Alg: "AES-256-GCM", Nonce: nonce, Cipher: ct,
		Fingerprint: box.Fingerprint(psk),
	})
	if errors.Is(err, store.ErrIpsecSiteNotFound) {
		httpx.Error(w, http.StatusNotFound, "站点不存在："+id)
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "保存 PSK 失败")
		return
	}
	// ★审计里只出现站点与版本号，绝不出现 PSK 的任何形态（含长度以外的特征）。
	// 一次 debug 打印就是永久泄漏，而审计日志恰恰是最常被导出的东西。
	s.audit(r, "security", "更新 IPSec 站点 "+id+" 的 PSK（v"+strconv.Itoa(version)+"）", "ok")

	resp := map[string]any{
		"ok": true, "id": id, "pskVersion": version,
		"pskFingerprint": box.Fingerprint(psk)[:8],
	}
	if generated != "" {
		// 只此一次。说明写进响应里，让前端能把这句原样显示给管理员。
		resp["psk"] = generated
		resp["notice"] = "该 PSK 只在本次响应中出现一次，控制面不提供回读；请立即配置到对端设备"
	}
	httpx.JSON(w, http.StatusOK, resp)
}
