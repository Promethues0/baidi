package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/authsrc/ldapsrc"
	"baidi.dev/control/internal/authsrc/oidcsrc"
	"baidi.dev/control/internal/authsrc/radiussrc"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// 登录链路的认证源编排：本地目录优先，未命中再问**认证域路由挑中的那一个**外部源。
//
// ★「按优先级依次询问」这个说法已经不成立（wave8 行动 12 起）：routeDirectory 的返回值
// 长度恒 ≤1，一次登录只把口令交给一台服务器。auth_sources.priority 现在只决定
// 列表/下拉的排列顺序，不是询问顺序——见 store.AuthSourceRec.Priority 的注释。
//
// # 这一层的全部安全语义都在注释里，改之前请读完
//
// 认证源接入最容易做出来的两个洞，都不在协议实现里，而在这一层的账号映射上：
//
//	① 按用户名而不是 subject 绑定 → 外部目录里新建一个叫 admin 的账号即可冒充本地管理员，
//	   而审计日志里是一次完全正常的「admin 登录成功」；
//	② 外部用户留着本地口令哈希 → 认证源被停用/删除后，那个账号退回成"某个本地口令也能登录"，
//	   而那个口令是谁设的、什么时候设的，没有人说得清。
//
// 两者的共同点是：**出问题时看起来一切正常**。所以下面每一处都写了症状。

// authSourceStore 是本文件需要的 store 能力。抽成小接口而不是直接用 *SQLiteStore，
// 是为了让登录编排能被单测覆盖（测试里塞一个假实现即可）。
type authSourceStore interface {
	AuthSources(ctx context.Context) ([]store.AuthSourceRec, error)
	AuthSourceSecret(ctx context.Context, id string) (store.AuthSourceSecret, bool, error)
	UserBySubject(ctx context.Context, sourceID, subject string) (store.Credential, bool, error)
	BindExternalUser(ctx context.Context, sourceID string, ext store.ExternalIdentity) (store.Credential, error)
	// SetExternalPwStrength 落一次外部口令认证判出的强度标记（只写 pw_strength 一列）。
	// 放进这个接口而不是通用 store 接口，是为了让它**只能**从外部认证这条链路上被调到：
	// 它接受的入参里有一个是外部目录的明文口令判定结果，别的地方没有理由碰它。
	SetExternalPwStrength(ctx context.Context, account, strength string) error
}

// authSrcStore 取 store 的认证源能力；未实现（如纯 Memory）时返回 nil。
func (s *Server) authSrcStore() authSourceStore {
	if as, ok := s.store.(authSourceStore); ok {
		return as
	}
	return nil
}

// admitConfigDTO 外部身份准入配置（wave8 行动 10）。**两种源共用**——
// 准入是白帝这一侧的策略，与目录协议无关，各写一份迟早只改一处。
type admitConfigDTO struct {
	// AdmitPolicy auto（认证通过即建号，改造前的行为）| approval（首登只登记待批单）。
	// 空 = auto（存量配置向后兼容，见 store.NormalizeAdmitPolicy）。
	AdmitPolicy string `json:"admitPolicy"`
	// AllowedDomains / AllowedGroups 每次登录都判的白名单（空=不限）。
	// ★与 AdmitPolicy 的判定时机不同：过滤每次都判（目录侧移出组后下次登录就该被拒），
	// 审批只判首次（已批过的账号不必天天再批）。详见 store/extadmit.go 头部。
	AllowedDomains []string `json:"allowedDomains"`
	AllowedGroups  []string `json:"allowedGroups"`
}

// filter 折算成判定用的过滤条件。
func (a admitConfigDTO) filter() store.AdmitFilter {
	return store.AdmitFilter{Domains: a.AllowedDomains, Groups: a.AllowedGroups}
}

// ldapConfigDTO / oidcConfigDTO 是落库 config JSON 的形状。
// 敏感项（bind 口令 / client_secret）**不在这里**——它们在 auth_source_secrets 表。
type ldapConfigDTO struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	TLSMode            string `json:"tlsMode"` // ldaps | starttls | plaintext
	CACert             string `json:"caCert"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	BindDN             string `json:"bindDn"`
	BaseDN             string `json:"baseDn"`
	UserFilter         string `json:"userFilter"`
	UsernameAttr       string `json:"usernameAttr"`
	DisplayNameAttr    string `json:"displayNameAttr"`
	EmailAttr          string `json:"emailAttr"`
	GroupAttr          string `json:"groupAttr"`
	// StatusAttr / StatusDisabledValues 账号状态回验的属性映射（wave8 行动 11）。
	// AD 的禁用是 userAccountControl 的位（内置）；通用 LDAP 协议里没有"禁用"语义，
	// 各家用各家的属性——不给这两项的话，非 AD 部署下回验只剩「条目被删除」一种触发条件。
	StatusAttr           string   `json:"statusAttr"`
	StatusDisabledValues []string `json:"statusDisabledValues"`
	admitConfigDTO
}

type oidcConfigDTO struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"clientId"`
	RedirectURI string   `json:"redirectUri"`
	Scopes      []string `json:"scopes"`
	// UseUserInfo 是否调 UserInfo 端点补全属性。
	//
	// ★这一项此前不存在，于是 oidcsrc 的 UseUserInfo 恒 false、整套 userInfo()
	// 代码在生产路径上不可达——而它正是为「有些 IdP（精简配置的 Keycloak 等）
	// 不把 groups/email 放进 ID Token，只在 UserInfo 里给」写的。后果不是少几个
	// 展示字段：外部身份准入闸的域白名单判 Email、组白名单判 Groups，两者拿不到
	// 就 fail-closed（store.AdmitFilter.Allow 的「认证源未返回邮箱」分支），
	// **该源的所有用户永远进不来**，而管理员那边配置齐全、白名单看着完全正确。
	// 默认 false：多打一次 UserInfo 是真出网，不该对所有存量部署无声生效。
	UseUserInfo bool `json:"useUserInfo"`
	admitConfigDTO
}

// radiusConfigDTO RADIUS 源落库 config JSON 的形状。共享密钥**不在这里**——
// 它走 auth_source_secrets（AAD 绑源 id、只写不读），与 LDAP bind 口令同一条路。
type radiusConfigDTO struct {
	Host string `json:"host"`
	Port int    `json:"port"` // 0 = 1812
	// NASIdentifier 报文里的 NAS-Identifier；服务端常按它挑策略/找客户端条目。
	NASIdentifier string `json:"nasIdentifier"`
	// Protocol pap | chap（默认 pap）。CHAP 要求服务端持有明文口令，接 AD 的 FreeRADIUS 通常只放行 PAP。
	Protocol string `json:"protocol"`
	// GroupAttr class | filter-id | reply-message | 空（不映射组）。
	GroupAttr string `json:"groupAttr"`
	// TimeoutMs 单次等待应答；Retries 重发次数。总预算仍受外部认证 8s 预算（BAIDI_EXTAUTH_TIMEOUT）钳制。
	TimeoutMs int `json:"timeoutMs"`
	// Retries 用指针是为了把「配置里缺席」与「管理员显式选了 0」分开：控制台让人选
	// 「重发 0 次」并按「总预算 = 单次等待 × (重发+1)」算，此前 int 零值被当成"取默认 1"，
	// 显示 0、执行 1，预算翻倍且页面上看不出来。nil = 取 radiussrc 默认（1）；&0 = 只发一次。
	// validateRadiusConfig 保存时把 nil 归一成显式 1 落库，存量行 UI 一直都带这个键、不需回填。
	Retries *int `json:"retries,omitempty"`
	admitConfigDTO
	// ★安全逃生舱 allowMissingResponseMessageAuthenticator **刻意不在这个 DTO 里**，
	// 取值走 radiusWaiverFromConfig（按常量读 map）。两条理由都在那个函数的注释里。
}

// radiusWaiverFromConfig 从落库 config 里取那个安全逃生舱
// （allowMissingResponseMessageAuthenticator，见 authsrc.go 的 radiusAllowMissingRespMAKey）。
//
// ★为什么不做成 radiusConfigDTO 的一个字段——两条理由，各对应一种"零报错的不生效"：
//
//	① 键名的唯一真相源是 radiusAllowMissingRespMAKey 那个常量，而结构体 tag 只能写字面量。
//	   两处各写一份，改名时就会分家成「入口按新名字校验、构造按旧名字读」——症状与本次修的
//	   缺陷逐字相同：管理员在页面上打开它、保存回执当面说「已打开」，而 Provider 那边恒 false。
//	② DTO 上多一个 bool 字段会让 validateRadiusConfig 的第 ② 步（把整份 config 解进 DTO）
//	   对 `"yes"` 这类非布尔值先炸在 json 解码器手里，authsrc.go 里那句点名键名的中文 400
//	   （「须为布尔值 true / false，得到：yes」）就永远走不到——安全开关填错时给出的解释
//	   会退化成一行英文 unmarshal 报错。
//
// 只认真正的布尔：缺席 / null / 类型不对一律 false = 要求应答带 Message-Authenticator。
// 安全那一侧就是零值（与入口校验同向；类型不对的那份在保存那一刻就被 400 挡住了，
// 走到这里只可能是别的入口写进去的脏数据，此时回落方向必须是收紧）。
func radiusWaiverFromConfig(cfg string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		return false
	}
	b, _ := m[radiusAllowMissingRespMAKey].(bool)
	return b
}

// buildProvider 由一条落库配置构造出可用的认证源实现。
//
// ★凭据在这里、且只在这里被解密。整个控制面里能读到 bind 口令/client_secret 明文的
// 就这一个函数——与 IPSec PSK 同款收敛（见 ipsec_gateway.go 的推理）。
func (s *Server) buildProvider(ctx context.Context, rec store.AuthSourceRec) (any, error) {
	as := s.authSrcStore()
	if as == nil {
		return nil, fmt.Errorf("当前存储实现不支持认证源")
	}
	kind := authsrc.Kind(rec.Kind)
	if !kind.Supported() {
		// ★明确拒绝而不是静默跳过：控制台上那些 RADIUS/短信/证书磁贴是历史种子，
		// 后端从来没有实现过。静默跳过的症状是「配了一个 RADIUS 源，用户登录一直失败，
		// 日志里什么都没有」。
		return nil, fmt.Errorf("认证源类型 %q 本版本未实现", rec.Kind)
	}

	// 取凭据（可能没有：OIDC 的公共客户端、匿名 bind 的 LDAP）。
	var credential string
	if sec, ok, err := as.AuthSourceSecret(ctx, rec.ID); err != nil {
		return nil, err
	} else if ok {
		box, err := secret.Default()
		if err != nil {
			return nil, fmt.Errorf("凭据主密钥不可用：%w", err)
		}
		// AAD 绑认证源 id：把某一行密文剪贴到另一条源上会直接解不开，
		// 而不是安静地下发一把错凭据。
		plain, err := box.Open(rec.ID, sec.Nonce, sec.Cipher)
		if err != nil {
			return nil, fmt.Errorf("凭据解密失败（密文行损坏或主密钥被替换）：%w", err)
		}
		credential = string(plain)
	}

	switch kind {
	case authsrc.KindLDAP, authsrc.KindAD:
		var c ldapConfigDTO
		if err := json.Unmarshal([]byte(rec.Config), &c); err != nil {
			return nil, fmt.Errorf("LDAP 配置不是合法 JSON：%w", err)
		}
		return ldapsrc.New(ldapsrc.Config{
			Kind: kind, Host: c.Host, Port: c.Port,
			TLS:                ldapTLSMode(c.TLSMode),
			CACert:             c.CACert,
			InsecureSkipVerify: c.InsecureSkipVerify,
			BindDN:             c.BindDN, BindPassword: credential,
			BaseDN: c.BaseDN, UserFilter: c.UserFilter,
			UsernameAttr: c.UsernameAttr, DisplayNameAttr: c.DisplayNameAttr,
			EmailAttr: c.EmailAttr, GroupAttr: c.GroupAttr,
			StatusAttr: c.StatusAttr, StatusDisabledValues: c.StatusDisabledValues,
			// ★改造前这两个字段**一个都不传**，恒取 ldapsrc 缺省（5s / 10s），
			// 而 RequestTimeout 是逐请求的：两次拨号 + StartTLS + 服务账号 bind
			// + search + 用户 bind，最坏能叠到约 60s。零值仍回落缺省。
			ConnectTimeout: s.ldapConnectTimeout,
			RequestTimeout: s.ldapRequestTimeout,
		})
	case authsrc.KindOIDC:
		var c oidcConfigDTO
		if err := json.Unmarshal([]byte(rec.Config), &c); err != nil {
			return nil, fmt.Errorf("OIDC 配置不是合法 JSON：%w", err)
		}
		return oidcsrc.New(oidcsrc.Config{
			Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: credential,
			RedirectURI: c.RedirectURI, Scopes: c.Scopes,
			UseUserInfo: c.UseUserInfo,
		})
	case authsrc.KindRADIUS:
		var c radiusConfigDTO
		if err := json.Unmarshal([]byte(rec.Config), &c); err != nil {
			return nil, fmt.Errorf("RADIUS 配置不是合法 JSON：%w", err)
		}
		// ★SourceID 必须是 rec.ID：Subject = radius:<源 id>:<用户名>，源 id 就是把两条
		// RADIUS 源里的同名用户隔成两个身份的那道墙。传别的值等于拆墙。
		return radiussrc.New(radiussrc.Config{
			SourceID: rec.ID, Host: c.Host, Port: c.Port, Secret: credential,
			NASIdentifier: c.NASIdentifier,
			Protocol:      radiussrc.Protocol(c.Protocol),
			GroupAttr:     radiussrc.GroupAttr(c.GroupAttr),
			Timeout:       time.Duration(c.TimeoutMs) * time.Millisecond,
			Retries:       radiusRetries(c.Retries),
			// ★这一行此前是缺的：入口校验、归一落库、保存告警、登录拒绝文案、探测结论
			// 五处都在，唯独没有人把它传给 Provider——于是那个字段恒 false（恒「要求 MA」），
			// 管理员打开开关、回执说「已打开」，而它一点作用都没有。
			// 它是**放宽**方向的开关，没有执行方时的后果不是不安全而是"配了不生效"，
			// 但同样属于本仓反复消灭的那一族（配置面与执行方分家，两边都不报错）。
			AllowMissingResponseMessageAuthenticator: radiusWaiverFromConfig(rec.Config),
		})
	}
	return nil, fmt.Errorf("认证源类型 %q 无法构造", rec.Kind)
}

// extAuthResult 一次外部认证编排的结果。
//
// ★收成结构体而不是继续加返回值：这里原本是 5 个匿名返回值，再加一个「耗时」
// 就没人读得懂调用点的 `_, _, _, hit, err :=` 了。
type extAuthResult struct {
	Cred    store.Credential
	SrcName string        // 命中的源显示名
	SrcKind string        // 命中的源 kind（认证策略按目录分组要用）
	Hit     bool          // 是否有源认出这个人
	Elapsed time.Duration // ★外部认证调用的墙上耗时（NFR-PERF-03 埋点）。
	// 未命中任何外部源时为 0；有多个源时是实际问过的那些之和。
}

// authenticateExternal 依次问外部认证源，返回第一个认证成功的本地凭据。
//
// 错误只在「所有源都不可用」这类运维故障时非 nil——调用方据此区分
// 「密码错」与「目录挂了」。
func (s *Server) authenticateExternal(r *http.Request, username, password, directory string) (extAuthResult, error) {
	ctx := r.Context()
	as := s.authSrcStore()
	if as == nil {
		return extAuthResult{}, nil
	}
	all, err := as.AuthSources(ctx)
	if err != nil {
		return extAuthResult{}, err
	}
	// ★认证域路由（wave8 行动 12）：命中即**只问该源**。
	// 这不是性能优化——遍历全部源意味着把用户的明文口令逐台投递给每一个排在
	// 前面的 LDAP 服务器去 bind，而它们中的大多数不该看到这份口令。
	// 返回的切片长度恒 ≤1，见 routeDirectory 的注释。
	srcs, rerr := routeDirectory(all, directory)
	if rerr != nil {
		return extAuthResult{}, rerr
	}

	// unavailable 记录「源本身出故障」的次数。★它与「凭据错」必须分开统计：
	// 只有当**没有任何源认出这个人、且至少有一个源是坏的**时，才该告诉调用方
	// "这是运维故障"。否则 AD 挂了会让所有本来就不存在的用户名也报"目录不可用"，
	// 反过来变成一个探测接口。
	var unavailable []string
	// spent 累计**实际问过的**外部源耗时。多源部署下这是它们之和——
	// 用户等的就是这个总数，只报最后一个源的耗时会低估他的真实体验。
	var spent time.Duration

	for _, rec := range srcs {
		if !rec.Enabled || authsrc.Kind(rec.Kind) == authsrc.KindLocal {
			continue
		}
		pa, perr := s.passwordAuthOf(ctx, rec)
		if perr != nil {
			slog.Warn("认证源不可用（配置构造失败）", "源", rec.Name, "id", rec.ID, "err", perr.Error())
			unavailable = append(unavailable, rec.Name)
			continue
		}
		if pa == nil {
			// OIDC 这类重定向式的源不参与口令登录——它有自己的入口。
			continue
		}
		cred, hit, el, ferr := s.finishExternalAuth(r, rec, as, pa, username, password)
		spent += el
		switch {
		case hit:
			// 第三个返回值是源的 kind（ldap/ad/oidc）：认证策略按用户目录分组，
			// 登录链路是唯一知道"这个人是被哪个目录认出来的"的地方。
			return extAuthResult{Cred: cred, SrcName: rec.Name, SrcKind: rec.Kind, Hit: true, Elapsed: spent}, nil
		case asAdmitDenied(ferr) != nil:
			// ★准入闸拒绝：**不再问下一个源**。口令已经对了，这个人的归属已经确定，
			// 继续问别的源等于把同一份明文口令再投递给一台不该看到它的服务器
			// （与 wave8 行动 12 要修的凭据外溢同一条道理）。
			return extAuthResult{SrcName: rec.Name, SrcKind: rec.Kind, Elapsed: spent}, ferr
		case asAdminExtDenied(ferr) != nil:
			// ★管理员闸拒绝：与准入闸同款，**不再问下一个源**——口令已经对了、这个人的
			// 归属也已确定，继续问别的源就是把同一份明文口令再投递给一台不该看到它的
			// 服务器。少了这一条，它会掉进下面的 default 被当成"运维故障"，
			// 用户看到的是「认证服务暂时不可用」而不是那句「管理员只接受本地口令」——
			// 一句把人支去查网络的假归因，正是本项目反复消灭的形态。
			return extAuthResult{SrcName: rec.Name, SrcKind: rec.Kind, Elapsed: spent}, ferr
		case errors.Is(ferr, authsrc.ErrInvalidCredentials):
			// 这个源不认识他/口令不对：继续问下一个源。不记 unavailable。
			continue
		case errors.Is(ferr, errBindFailed):
			// 认证过了但绑定/建号失败：这是本机故障，直接上抛（换个源也救不了）。
			return extAuthResult{SrcName: rec.Name, SrcKind: rec.Kind, Elapsed: spent}, ferr
		default:
			// ErrSourceUnavailable / ErrNotConfigured：运维故障。
			// ★不能当成"密码错误"回给用户——那会让运维去查用户而不是查目录。
			slog.Warn("认证源故障", "源", rec.Name, "id", rec.ID, "err", ferr.Error())
			unavailable = append(unavailable, rec.Name)
		}
	}

	if len(unavailable) > 0 {
		return extAuthResult{Elapsed: spent},
			fmt.Errorf("%w：%s", authsrc.ErrSourceUnavailable, strings.Join(unavailable, "、"))
	}
	return extAuthResult{Elapsed: spent}, nil
}

// radiusRetries 把 DTO 里的 *int 翻成 radiussrc.Config.Retries：
// nil（配置里缺席）→ -1 让 radiussrc 取自己的默认值 1；显式值（含 0）原样——管理员在
// 控制台选「重发 0 次」要的就是只发一次，此前 `n <= 0 → -1` 把它悄悄改成了 1。
// 负数不可能从 validateRadiusConfig 过来（那里 400），防御性地也当"取默认"。
func radiusRetries(n *int) int {
	if n == nil || *n < 0 {
		return -1
	}
	return *n
}

// radiusSyncableGroups 把 RADIUS 应答里的组值筛成**可以同步成员的那部分**：
// 只保留白帝里**已存在**的、属于本源的外部用户组（kind=external，名字大小写不敏感），
// 其余一律丢掉——BindExternalUser 对传进去的每个组名都会 INSERT OR IGNORE 一行永久的
// user_groups，而 RADIUS 的 Class 常被服务器用作逐会话标识（Cisco ISE 的 CACS:<session>…），
// 原样传等于每次登录都往 user_groups 表里加一行、直到写爆。
//
// ★这只影响**成员同步**：准入闸（allowedGroups 比对）仍看 radiussrc 交出来的全部组值
// （已在那边限到 32 个 / 128 字节），调用方要在过闸**之后**才用本函数的结果去绑定。
// 「已存在」的组只可能来自升级前的自动建组行（本改动后 RADIUS 不再建）——LDAP/OIDC 的
// memberOf / groups 同步是 DN 维度的另一条路，不在这里动它。
//
// ★外部组的 id 形态（`gext-<源 id>-<hash>`）是 store.extGroupID 的私有约定，这里刻意
// **不复刻它**，改按 (kind=external, 描述里带本源 id, 名字) 三元匹配——描述文本
// 「外部目录组（来源 <源 id>）」是 refreshExternalProfile 建行时写死的，两处若分家，
// 症状是"存量组停止同步"，TestRadiusClassNeverCreatesGroups 钉着它。
// 读组失败时 fail-closed：一个组都不同步（少同步一个成员远好过多建一行）。
func (s *Server) radiusSyncableGroups(ctx context.Context, sourceID string, groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	all, err := s.store.UserGroups(ctx)
	if err != nil {
		slog.Warn("读取用户组失败，本次 RADIUS 登录不同步任何组成员", "源", sourceID, "err", err.Error())
		return nil
	}
	marker := "（来源 " + sourceID + "）"
	existing := map[string]bool{}
	for _, g := range all {
		if g.Kind == store.GroupKindExternal && strings.Contains(g.Description, marker) {
			existing[strings.ToLower(strings.TrimSpace(g.Name))] = true
		}
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if existing[strings.ToLower(strings.TrimSpace(g))] {
			out = append(out, g)
		}
	}
	return out
}

func ldapTLSMode(s string) ldapsrc.TLSMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "starttls":
		return ldapsrc.TLSModeStartTLS
	case "plaintext", "none":
		return ldapsrc.TLSModePlaintext
	}
	return ldapsrc.TLSModeLDAPS // 零值即最安全的那一档
}

// admitDenied 准入闸拒绝。**独立错误类型**而不是复用 ErrInvalidCredentials：
// 「口令错」与「口令对但不准你进」对用户、对运维、对防爆破计数都是三件不同的事。
// 混成一个的话，一个被准入闸挡住的人会被计进爆破锁定，最后连申诉都申诉不了。
type admitDenied struct{ verdict admitVerdict }

func (e *admitDenied) Error() string { return e.verdict.Reason }

// Pending 报告是不是"等管理员批"（区别于确定性拒绝）。
func (e *admitDenied) Pending() bool { return e.verdict.Pending }

// asAdmitDenied 从错误链里取准入拒绝（不是则回 nil）。
func asAdmitDenied(err error) *admitDenied {
	var d *admitDenied
	if errors.As(err, &d) {
		return d
	}
	return nil
}

// errBindFailed 认证过了但绑定/建号失败（本机故障，换个源也救不了）。
var errBindFailed = errors.New("外部身份绑定失败")

// adminExtDenied 管理员账号经外部认证源认证通过、但按纪律不得换取任何凭证。
//
// 与 admitDenied 同族、刻意分开：两者都是「口令是对的、人不准进」，但下一步动作
// 完全不同——准入拒绝要么等审批要么去找管理员开白名单，而这条的出路只有一个：
// 改用本地口令登录。合成一种错误的话，handlePortalLogin 只能给出一句折中的话。
// 审计与文案已在 denyAdminExternal 里落好，调用方不再重复记账、不计爆破锁定。
type adminExtDenied struct{ reason string }

func (e *adminExtDenied) Error() string { return e.reason }

// asAdminExtDenied 从错误链里取管理员闸拒绝（不是则回 nil）。
func asAdminExtDenied(err error) *adminExtDenied {
	var d *adminExtDenied
	if errors.As(err, &d) {
		return d
	}
	return nil
}

// passwordAuthOf 取该源的口令认证实现；nil,nil = 这个源不参与口令登录（如 OIDC）。
func (s *Server) passwordAuthOf(ctx context.Context, rec store.AuthSourceRec) (authsrc.PasswordAuthenticator, error) {
	if s.testPasswordAuth != nil {
		// 测试注入缝：绕开真实 LDAP 拨号，其余编排（准入闸、绑定、审计）原样走。
		return s.testPasswordAuth(rec)
	}
	prov, err := s.buildProvider(ctx, rec)
	if err != nil {
		return nil, err
	}
	pa, ok := prov.(authsrc.PasswordAuthenticator)
	if !ok {
		return nil, nil
	}
	return pa, nil
}

// finishExternalAuth 对一个源走完「认证 → 准入闸 → 绑定/建号」。
//
// 返回 (凭据, 是否认证并放行, 错误)。抽成独立函数是为了让**准入闸的位置**能被
// 端到端钉住：闸判得对（纯函数用例覆盖了）但接在 BindExternalUser 之后的话，
// 账号照建不误——而那正是本行动要防的。
func (s *Server) finishExternalAuth(r *http.Request, rec store.AuthSourceRec, as authSourceStore,
	pa authsrc.PasswordAuthenticator, username, password string) (store.Credential, bool, time.Duration, error) {

	ctx := r.Context()
	// ★预算只包住这一次外部调用。后面的准入闸、绑定、审计一律用**原 ctx**——
	// 它们是本机库操作，被外部目录的慢拖累而失败是最难自证的一类故障
	// （拒绝发生了、审计里没有；锁定计了、没落库）。见 SetAuthTimeouts 的推理。
	actx, cancel := s.authCtx(ctx)
	start := time.Now()
	id, err := pa.Authenticate(actx, username, password)
	cancel()
	elapsed := time.Since(start)
	// 时延如实记一行：NFR-PERF-03 的验收是「认证响应时延」，而这条链路改造前
	// 零埋点——没有测量点的话，超时改对没改对在生产上无从判断。
	// 成败都记：慢到超时的那次恰恰是最该看见的一次。
	slog.Info("外部认证源应答", "源", rec.Name, "kind", rec.Kind,
		"耗时ms", elapsed.Milliseconds(), "预算ms", s.extAuthTimeout.Milliseconds(),
		"ok", err == nil)
	if err != nil {
		return store.Credential{}, false, elapsed, err
	}
	// ★准入闸必须在 BindExternalUser **之前**（wave8 行动 10）。
	// 放在建号之后就晚了：账号已经存在、已经落进组织树、已经被组织授权覆盖到了。
	cur, bound, berr := as.UserBySubject(ctx, rec.ID, id.Subject)
	if berr != nil {
		return store.Credential{}, false, elapsed, fmt.Errorf("%w：%v", errBindFailed, berr)
	}
	if v := s.admitExternal(ctx, rec, id, bound); !v.Allowed {
		// 落审计：待批只在**新建单子**那一次记（登录可无限重试，每次都记会把审计冲成噪声）；
		// 确定性拒绝（白名单不过 / 已被驳回）每次都记——那是有人正在反复尝试进来，恰恰该看得见。
		if !v.Pending || v.NewTicket {
			s.auditAdmitDenied(r, rec, id, v)
		}
		return store.Credential{}, false, elapsed, &admitDenied{verdict: v}
	}
	// ★管理员账号绝不交给外部目录改写——这道闸必须在 BindExternalUser **之前**。
	//
	//   调用方那道闸（externalSessionCredential）拒的是**会话**，而它排在绑定之后：
	//   会话确实拒掉了，可 BindExternalUser → refreshExternalProfile 已经按外部应答把这个
	//   白帝管理员的显示名与邮箱写成了目录说的那份，并**增删**了他的外部组归属。
	//   于是控制 AD/IdP 的人虽然登不进来，却能把某个管理员移出一个「一律二次认证」的
	//   用户组——等于替他的**本地**登录降了一档认证策略要求（authpolicy 的适用范围
	//   正是按用户组/组织算的）；改邮箱那半则能把找回/通知引到别处。
	//   「认证被拒了」不等于"这次外部登录什么都没改动"，这正是那条 minor 的实质。
	//
	//   判据与另一处逐字同源：users.role='admin'（窄 SELECT 里就有 role，此前被丢成 _），
	//   文案与审计同经 denyAdminExternal 产出，两处同真同假。
	//   只在 bound 时判：未绑定就还没有这个外部身份对应的白帝账号，建号一律 role=user。
	if bound && cur.Role == "admin" {
		return store.Credential{}, false, elapsed,
			&adminExtDenied{reason: s.denyAdminExternal(r, cur.Account, "外部认证源「"+rec.Name+"」")}
	}
	// ★RADIUS 的组值不自动建组：过了准入闸（那里看的是全部组值）之后，只把**已存在**的
	// 本源外部组交给绑定去同步成员。传全部的话 BindExternalUser 会把每个 Class 值
	// INSERT OR IGNORE 成一行永久的 user_groups（见 radiusSyncableGroups）。
	syncGroups := id.Groups
	if authsrc.Kind(rec.Kind) == authsrc.KindRADIUS {
		syncGroups = s.radiusSyncableGroups(ctx, rec.ID, id.Groups)
	}
	cred, berr := as.BindExternalUser(ctx, rec.ID, store.ExternalIdentity{
		Subject: id.Subject, Username: id.Username,
		DisplayName: id.DisplayName, Email: id.Email, Groups: syncGroups,
	})
	if berr != nil {
		slog.Error("外部身份绑定失败", "源", rec.Name, "subject", id.Subject, "err", berr.Error())
		return store.Credential{}, false, elapsed, fmt.Errorf("%w：%v", errBindFailed, berr)
	}
	if !bound {
		// 真的建了号才记（已存在的绑定不记，否则每次登录都是一条）。
		s.auditExtUserCreated(r, rec, id, cred.Account)
	}
	// FR-AUTH-21：外部目录账号的口令强度**只有这一刻**判得出来（明文由客户端提交、
	// 白帝拿它去 bind / 发 Access-Request；下一秒它就只剩对方目录里的一个哈希）。
	// 落在这里而不是 handlePortalLogin，是因为本函数是「口令认证源」这条链的唯一出口
	// （OIDC 的 passwordAuthOf 返回 nil，结构上进不来），拿不到口令的源不会误落一个假判定。
	//
	// **每次登录都判**，不是只在建号那次：外部目录里改口令白帝完全不知情，只判首次
	// 等于把一个可能早就变了的结论一直用下去。
	//
	// 顺序上它排在 externalSessionCredential 的重读之前（调用方 handlePortalLogin），
	// 所以本次登录的 secondFactor 用的就是刚落下的这个值——弱口令在**当次**就要求二次认证，
	// 而不是"下次登录才开始生效"。
	s.noteExternalPwStrength(ctx, as, cred.Account, password)
	return cred, true, elapsed, nil
}

// noteExternalPwStrength 把一次外部口令认证的强度判定落库。
//
// ★写失败只记日志、不打断登录：口令是对的、准入闸也过了，用一次库写抖动把人挡在门外
// 是明显更坏的方向。代价是那次登录的「弱密码」规则不会命中（标记停在上一次的值），
// 这是 fail-open，但它与「登录整个失败」的量级不在一个数量级上，且日志里说得出来。
//
// ★account 传的是**白帝账号**（撞名时带源后缀）而不是用户输入的用户名：
// `auth.PasswordWeakness` 的「口令中包含账号名」那条判据要与本地路径同口径
// （`accountCore` 会在 `@` 处截断，所以 `alice@as-ldap` 比对的仍是 alice）。
func (s *Server) noteExternalPwStrength(ctx context.Context, as authSourceStore, account, password string) {
	strength := auth.PasswordStrength(account, password)
	if err := as.SetExternalPwStrength(ctx, account, strength); err != nil {
		slog.Error("外部账号口令强度标记落库失败（本次登录的「弱密码」规则将按上一次的标记判定）",
			"账号", account, "err", err.Error())
	}
}

// SetAuthTimeouts 注入外部认证的超时预算（NFR-PERF-03）。由 main 从 config 传入；
// 不调用即全零 = 与改造前行为一致（ldapsrc 取自己的缺省，且不设整体预算）。
//
// ★这里刻意**只**给外部认证那一次调用设预算，而不是给登录 handler 加 deadline。
// 后者看起来更彻底，实际是个比实现更宽的闸，装上去只会制造「已经有超时了」的假象：
//
//   - 它压不住真正慢的那段。go-ldap 的拨号与请求都不吃 ctx，只能靠 ldapsrc 把 ctx
//     折算进自己的超时字段（dialTimeout / requestTimeout）。handler 上挂 3s，
//     LDAP 那边照样能跑几十秒。
//   - 它会把「目录慢」升级成「全员登录不了」。deadline 一过期，后面所有吃 ctx 的
//     动作一起失败：审计写不进库（`/diag` 的 audit-write 翻红，且把运维指向磁盘
//     可写性——错误方向）、锁定落不了库、`stepUpDecision` 的 AuthPolicies 与
//     SubjectIndex 两次库读失败即 **fail-closed 拒登录**，而用户看到的文案是
//     「认证策略暂不可用」。SubjectIndex 还是每次登录现算的全表 JOIN，
//     正好排在外部认证之后——预算被目录吃完后最先饿死的就是它。
//   - 它打不断 bcrypt（不吃 ctx），只能在口令验完之后把后续步骤判死。
func (s *Server) SetAuthTimeouts(external, ldapConnect, ldapRequest time.Duration) {
	s.extAuthTimeout, s.ldapConnectTimeout, s.ldapRequestTimeout = external, ldapConnect, ldapRequest
}

// authCtx 给外部认证调用套上预算。预算 <=0 时原样返回（逃生舱 / 测试栈）。
// 返回的 cancel 必须调用，否则计时器要等到 deadline 才释放。
func (s *Server) authCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.extAuthTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.extAuthTimeout)
}

// extAuthTookZh 把外部认证耗时写成审计正文里的一小段中文。
//
// ★为什么进审计正文而不是加一列：store.AuditEntry 没有任何数值列，而加列的连带面
// 很宽——防篡改 MAC 只覆盖既有七格（新列可被无痕改动），把它加进 MAC 又会让**全部
// 存量行**校验立刻断链（backfillAuditChain 只补 mac IS NULL 的行）；此外 CSV 导出
// 表头写死、forward.Record 是 AuditEntry 的类型别名会自动出现在外送给 SIEM 的 JSON 里。
// 拼进正文是本项目既有做法（对照「自助修改登录口令（强度判定：X）」），且**被 MAC 覆盖**。
//
// 0 表示没问过任何外部源（本地就认出来了 / 一个源都没配），此时不编造一个耗时。
func extAuthTookZh(d time.Duration) string {
	if d <= 0 {
		return "外部认证未参与"
	}
	return "外部认证耗时 " + strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}
