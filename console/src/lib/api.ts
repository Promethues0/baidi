/** 白帝控制台 · HTTP 客户端。管理 API 经 vite /api 反代到自有后端 baidi-control(:8090)。 */
const BASE = '/api/v1';
const TOKEN_KEY = 'baidi_token';

export function getToken(): string { return localStorage.getItem(TOKEN_KEY) || ''; }
export function setToken(t: string): void { localStorage.setItem(TOKEN_KEY, t); }
export function clearToken(): void { localStorage.removeItem(TOKEN_KEY); }

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const t = getToken();
  // headers 必须在 ...rest 之后合并：否则调用方传入 headers 会把 Authorization 整体顶掉（静默 401）
  const { headers: extra, ...rest } = init ?? {};
  const res = await fetch(BASE + path, {
    ...rest,
    headers: {
      Accept: 'application/json',
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
      ...(extra ?? {})
    }
  });
  if (res.status === 401) {
    clearToken();
    // 门户与管理台分别回各自登录页
    location.href = location.pathname.startsWith('/portal') ? '/portal/login' : '/login';
    throw new Error('401 未认证');
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

/* ── 与 baidi-control internal/store.Overview 同构 ── */
export interface KV { name: string; value: number }
export interface DefenseLine { key: string; name: string; risk: number; trend: 'up' | 'down' | 'flat'; top: string[] }
export interface Overview {
  generatedAt: string;
  devices: { online: number; total: number; rate: number };
  users: { total: number; disabled: number; locked: number };
  threats: { rejected: number; failed: number; secondary: number };
  sessions: number;
  auditByKind: KV[];
  verdicts: KV[];
  defense: DefenseLine[];
}

/* ── 与 store.PolicyBundle 同构（策略继承树 + 用户策略清单） ── */
export interface OrgNode {
  key: string;
  title: string;
  hasCustom: boolean;
  members: number;
  children?: OrgNode[];
}
export interface UserPolicy {
  id: string;
  name: string;
  scope: string;
  status: 'custom' | 'inherited';
  inheritedFrom: string;
  members: number;
  updated: string;
}
export interface PolicyBundle {
  tree: OrgNode[];
  list: UserPolicy[];
}

/* ── 应用管理（store.AppBundle）── */
export interface AppCategory { key: string; label: string; count: number }
export interface App {
  id: string; name: string; addr: string;
  mode: 'tunnel' | 'web' | 'global';
  category: string; node: string; authedUsers: number;
  status: 'running' | 'stopped';
}
export interface AppBundle { categories: AppCategory[]; apps: App[] }

/* ── 访问者目录（store.UserDirBundle）── */
export interface Directory { key: string; name: string; type: 'local' | 'ad' | 'ldap'; users: number; online: number; lastSync: string }
export interface OrgUnit { key: string; title: string; members: number; children?: OrgUnit[] }
export interface DirUser {
  id: string; name: string; account: string; org: string; orgKey: string;
  device: string; ip: string; auth: string; lastLogin: string;
  online: boolean; status: 'active' | 'locked' | 'disabled' | 'idle'; risk: 'none' | 'low' | 'high';
  roles: string[];
}
export interface UserDirBundle { directories: Directory[]; orgTree: OrgUnit[]; users: DirUser[] }

/* ── 终端管理（store.DeviceBundle）── */
export interface DeviceTrustSetting { enabled: boolean; bindMethod: 'auto' | 'approval'; perUserQuota: number }
export interface Device {
  id: string; name: string; fingerprint: string; user: string;
  assetClass: 'enterprise' | 'personal' | 'managed'; os: string; clientVersion: string;
  online: boolean; tags: string[];
}
export interface ApprovalEvent { time: string; kind: 'submit' | 'login' | 'review' | 'notify' | 'risk'; title: string; detail: string }
export interface TrustApproval {
  id: string; user: string; device: string; fingerprint: string; submittedAt: string;
  reason: string; status: 'pending' | 'approved' | 'rejected'; timeline: ApprovalEvent[];
}
export interface DeviceBundle { settings: DeviceTrustSetting; devices: Device[]; approvals: TrustApproval[] }

/* ── 审计中心（store.AuditBundle）── */
export interface DiskStat { usedPct: number; totalGB: number; retainDays: number }
export interface AuditEntry { time: string; category: 'access' | 'auth' | 'admin' | 'security'; user: string; srcIp: string; event: string; verdict: 'allow' | 'deny' | 'mfa' | 'ok' | 'fail' }
export interface AuditBundle { categories: KV[]; todayTotal: number; disk: DiskStat; logs: AuditEntry[] }

/* ── 网关与隐身（store.GatewayBundle）── */
export interface GwNode { name: string; ip: string; role: 'primary' | 'backup'; status: string; loadPct: number }
export interface GwZone { key: string; name: string; status: 'healthy' | 'degraded' | 'down'; apps: number; clients: number; nodes: GwNode[] }
export interface SpaStatus { generation: string; authMode: string; protectedPorts: string[]; hidden: boolean; knockOk: boolean }
export interface GatewayBundle { zones: GwZone[]; spa: SpaStatus }

/* ── 系统管理（store.SystemBundle）── */
export interface AdminGroup { key: string; name: string; power: 'root' | 'system' | 'security' | 'audit' | 'custom'; builtin: boolean; members: number; scope: string }
export interface AdminAccount { name: string; account: string; group: string; auth: string; twoFa: boolean; lastLogin: string }
export interface ClusterNode { name: string; ip: string; role: 'master' | 'backup' | 'center' | 'branch'; status: string }
export interface ClusterInfo { localNodes: ClusterNode[]; distNodes: ClusterNode[] }
export interface SystemBundle { adminGroups: AdminGroup[]; admins: AdminAccount[]; cluster: ClusterInfo }

/* ── 认证源接入（store.AuthSrcBundle）── */
export interface AuthSource { key: string; name: string; type: 'local' | 'ad' | 'ldap' | 'radius' | 'oauth' | 'sms' | 'cert'; status: string; users: number; primary: boolean }
export interface RuleCond { field: 'weakPwd' | 'geoAnomaly' | 'offHours' | 'riskScore' | 'untrustedDevice' | 'newDevice'; op: 'is' | 'gt' | 'in'; value: string }
export interface AdaptiveRule { id: string; name: string; enabled: boolean; logic: 'AND' | 'OR'; conditions: RuleCond[]; action: 'allow' | 'mfa' | 'stepup' | 'block'; priority: number }
export interface AuthSrcBundle { sources: AuthSource[]; rules: AdaptiveRule[] }

/* ── 认证源接入 · 真实落库的那一套（GET /api/v1/authsrc/sources）──
 *
 * ★与上面的 AuthSource 是**两回事**：那个是历史内存种子的形状（带编造的 users 数），
 * 这个是真落库的配置。用户数这类拿不到的字段刻意不在这里——
 * 显示一个 0 会让人以为是真的统计出来的。
 */
export type AuthSrcKind = 'local' | 'ldap' | 'ad' | 'oidc';

export interface AuthSourceRec {
  id: string;
  name: string;
  kind: AuthSrcKind | string;
  enabled: boolean;
  priority: number;
  /** 该类型的非敏感配置 JSON 字符串（敏感项在独立加密表，不在这里）。 */
  config: string;
  /** 凭据是否已配置。原文永不回显——只写不读。 */
  hasSecret: boolean;
  /** 凭据指纹前 8 位，供两端核对"是不是同一把"。 */
  secretFingerprint?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthSourcesResp {
  sources: AuthSourceRec[];
  /** 后端真实实现了的类型。控制台据此把未实现的选项置灰，而不是让它们看起来可选。 */
  supportedKinds: string[];
}

/** LDAP/AD 的配置形状（与 control 的 ldapConfigDTO 对齐）。 */
export interface LdapConfig {
  host: string;
  port?: number;
  tlsMode: 'ldaps' | 'starttls' | 'plaintext';
  caCert?: string;
  insecureSkipVerify?: boolean;
  bindDn?: string;
  baseDn: string;
  userFilter?: string;
  usernameAttr?: string;
  displayNameAttr?: string;
  emailAttr?: string;
  groupAttr?: string;
}

/** OIDC 的配置形状（与 control 的 oidcConfigDTO 对齐）。 */
export interface OidcConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes?: string[];
}

export interface ProbeResp { ok: boolean; detail: string; elapsedMs?: number }
export interface SaveSourceResp { ok: boolean; source: AuthSourceRec; warning?: string }

/* ── 认证策略 · PC/移动端分栏（store.AuthPolicy，FR-AUTH-12）── */
export type PrimaryMethod = 'local' | 'ad' | 'ldap' | 'radius' | 'oauth' | 'sms' | 'cert';
export type SecondaryMethod = 'sms' | 'totp' | 'radius' | 'cert' | 'http';
export interface AuthMethodSet { primary: PrimaryMethod | ''; secondary: SecondaryMethod[] }
export interface ExemptRule { trustedDevice: boolean; trustedNetwork: boolean; winDomain: boolean }
export interface EnhanceRule { weakPwd: boolean; offHours: boolean; geoAnomaly: boolean }
export interface AuthPolicy {
  id: string; name: string; directory: PrimaryMethod | string; isDefault: boolean;
  scope: string; priority: number; enabled: boolean;
  pc: AuthMethodSet; mobile: AuthMethodSet;
  exempt: ExemptRule; oneClick: boolean; enhance: EnhanceRule; authzApps: string;
}
export interface AuthPolicyResp { policies: AuthPolicy[] }

/* ── 安全中心（store.SecurityBundle）── */
export interface BaselineCheck { key: string; label: string; platform: 'Windows' | 'macOS' | 'Linux' | 'All'; expect: string; severity: 'high' | 'medium' | 'low' }
export interface BaselinePolicy { id: string; name: string; type: 'app-protect' | 'onboarding'; scope: string; disposal: 'allow' | 'degrade' | 'block' | 'gray'; status: 'enabled' | 'disabled'; platforms: string[]; checks: BaselineCheck[] }
export interface SecurityBundle { baselines: BaselinePolicy[]; spa: SpaStatus }

/* ── 终端 posture（安全中心 · 终端合规） ── */
export interface PostureCheckRow { key: string; label: string; ok: boolean; value: string }
export interface PostureRow {
  user: string; device: string; platform: string; os: string; clientVersion: string;
  checks: PostureCheckRow[]; verdict: 'allow' | 'degrade' | 'gray' | 'block';
  score: number; level: 'low' | 'medium' | 'high'; reasons: string[]; ts: number;
}
export interface PostureResp { reports: PostureRow[] }

/* ── 资源策略 + 在线网关（数据面，control 托管、网关动态拉取） ── */
export interface Resource { id: string; name: string; backend: string; allowRoles: string[]; allowUsers: string[]; addrRef?: string; svcRef?: string }
export interface ResourcesResp { resources: Resource[] }
export interface GwSess { ip: string; user: string; role: string; since: number }
export interface GatewayReg { id: string; proxy: string; spa: string; lastSeen: number; clients: number; tunnels: number; uptime: number; sessions?: GwSess[] }
export interface GatewaysResp { gateways: GatewayReg[] }

/* ── 监控中心 · 在线用户（store.OnlineSession）── */
export interface OnlineSession {
  id: string; user: string; account: string; org: string;
  ip: string; location: string; device: string; os: string;
  auth: string; app: string; gateway: string;
  loginAt: string; duration: string;
  trust: 'trusted' | 'untrusted' | 'unknown';
  risk: 'none' | 'low' | 'high';
  status: 'online' | 'offline';
  kickReason?: string;
}
export interface OnlineResp { sessions: OnlineSession[]; generatedAt: string; source?: 'live' | 'demo' }

/* ── 监控中心 · 用户状态（store.UserStateBundle）── */
export interface UserStateBucket { key: string; label: string; count: number; tone: 'danger' | 'warning' | 'info' | 'normal' }
export interface UserStateItem {
  id: string; user: string; account: string; org: string;
  state: 'risk-high' | 'risk-low' | 'locked' | 'disabled' | 'idle';
  risk: 'none' | 'low' | 'high'; online: boolean;
  reasons: string[]; lastEvent: string; lastSeen: string;
  /** 该账号当前有生效的登录防爆破锁定（login_lockouts）。与目录 status=locked 是两种锁：
   *  爆破锁到期自动解除、解锁走 /security/lockouts/unlock；目录锁走 /users/{id}/status。
   *  「就地解锁」按此字段选路（可能两种都要解）。 */
  bruteLocked?: boolean;
}
export interface UserStateBundle { buckets: UserStateBucket[]; items: UserStateItem[] }

/* ── 登录防爆破（login_lockouts + internal/lockout.Guard）── */
export interface LoginLockout {
  kind: 'account' | 'ip';
  key: string;       // 规范化账号 / 源 IP
  until: number;     // 锁定截止 Unix 秒
  reason: string;    // 触发事实（如「10 分钟内连续 5 次登录失败」）
  createdAt: string;
}
export interface LockoutsResp { lockouts: LoginLockout[] }
/** BAIDI_LOCKOUT_* 的运行时覆盖（settings 落库、登录链路 Guard 即时消费）。 */
export interface LockoutConfig {
  threshold: number;      // 窗口内失败次数阈值
  windowSec: number;      // 滑动窗口（秒）
  durationSec: number;    // 锁定时长（秒）
  ipEnabled: boolean;     // 源 IP 维度开关
  accountEnabled: boolean; // 账号维度开关
}

/* ── IPSec VPN 组网（配置 store.IpsecSite ＋ 运行态 ipsec_sa_state）──
 *
 * ★这两半必须分开看，混在一个结构里就是旧实现出事的根源：
 *   · 配置 / 管理意图 —— 管理员写，控制面权威（peer、subnet、phase1/phase2、auth、suite、enabled…）
 *   · 实测运行态     —— 网关经 mTLS 心跳回报，网关权威（全在 sa 子对象里）
 * 旧版把 status/rxBytes 与配置列平级摆在同一张表，于是「toggle 一下把 status 改成 up」
 * 成了合法写法：界面上那条「已建立 · 已传 184 MB」其实是播种时灌进库的常量，永不变化。
 * 现在配置侧不再暴露任何可读的运行态字段——想显示状态就只能去读 sa，读不到就老实说未回报。
 */
export interface IpsecPhase { enc: string; hash: string; dh: string }

/** IPSec 隧道实测五态，与 gateway/internal/ipsec.State 一一对应。
 *
 * ★为什么是五态而不是三态：down 表示「管理员没启用」，failed 表示「启用了但协商失败」。
 * 两者挤进同一个值，界面上就分不出「本来就没开」和「开了连不上」——后者必须刺眼，
 * 前者不该报警。rekeying 也不能并进 connecting：重协商期间旧 SA 仍在承载流量，不是故障。 */
export type IpsecState = 'down' | 'connecting' | 'up' | 'rekeying' | 'failed';

/** 一条站点隧道的实测运行态（gateway/internal/ipsec.SiteState 的 JSON 形态）。
 *  每个字段都来自 IKE 状态机或 ESP 计数器，没有任何一项是配置回显。 */
export interface IpsecSA {
  siteId: string;
  /** 回报这条状态的网关。与 IpsecSite.gatewayId 不一致 = 有第二台网关在抢同一条站点，
   *  表现为隧道反复抖动，靠这两个字段对比才看得出来。 */
  gatewayId: string;
  state: IpsecState;
  /** IKE SA 的一对 SPI（各 16 hex）。★这是「真的协商过」最硬的证据：单端伪造不出
   *  与对端交叉相等的一对 SPI，纯配置回显的假数据这里只会是空串。 */
  ikeSpiI: string;
  ikeSpiR: string;
  /** ESP 双向 SPI，本端入向 = 对端出向。 */
  childSpiIn: number;
  childSpiOut: number;
  /** ESP 实测字节/包计数。UI 上的流量数字只允许来自这四个字段。 */
  rxBytes: number;
  txBytes: number;
  packetsIn: number;
  packetsOut: number;
  /** 实际协商定型的套件，如 "AES256-GCM16/PRF-HMAC-SHA256/ECP256"。必须与配置分列展示，
   *  不一致时高亮——「以为走了国密其实降级了」只有这一格看得出来。 */
  negotiatedProposal: string;
  establishedAt: number; // Unix 秒，0 = 未建立
  rekeyAt: number;       // 软生存期到点（UI 的剩余寿命倒计时按它算）
  expiresAt: number;     // 硬生存期到点
  /** 本条回报的生成时刻（Unix 秒）。心跳 15s 一跳，UI 必须据此算新鲜度：
   *  把 3 分钟前的快照当实时数字展示，和展示种子常量是同一种欺骗。 */
  reportedAt: number;
  /** 中文可读的失败原因（如「对端 203.0.113.88:500 无响应（7 次重传超时）」）。 */
  lastError: string;
  lastErrorAt: number;
  /** IKEv2 NOTIFY 码点名（NO_PROPOSAL_CHOSEN / AUTHENTICATION_FAILED / TS_UNACCEPTABLE…）。
   *  可选：控制面若只回中文原因，UI 就只显示中文，不假装有码点。 */
  lastErrorCode?: string;
}

export interface IpsecSite {
  id: string; name: string; peer: string; localSubnet: string; remoteSubnet: string;
  ikeVersion: string; auth: 'psk' | 'cert' | 'sm2cert'; suite: 'standard' | 'gm';
  phase1: IpsecPhase; phase2: IpsecPhase; pfs: boolean; pqHybrid: boolean;
  /** 管理意图：管理员想不想让它开。toggle 只改这一个字段，
   *  它**不代表隧道真的建起来了**——那个只有 sa.state 能回答。 */
  enabled: boolean;
  /** 由哪台网关承载这条站点（最小披露：控制面只把站点下发给对应 CN 的网关）。 */
  gatewayId?: string;
  /** PSK 只写不读：控制面永不回原文，只回「配没配 / 指纹 / 版本」。指纹供运维核对两端
   *  是不是同一把；回显原文没有任何操作价值，只有泄露面。 */
  hasPsk?: boolean;
  pskFingerprint?: string;
  pskVersion?: number;
  /** 网关实测运行态。缺省 = 这条站点从未被任何网关回报过（≠ 未建立，UI 要分开说）。 */
  sa?: IpsecSA;
  localRef?: string; remoteRef?: string; // 本端/对端网段引用的地址对象 id（对象库复用）

  /** @deprecated ipsec_sites 的 status/rx_bytes/tx_bytes/last_up 四列已冻结为只读兼容：
   *  控制面不再写、UI 一律不得渲染——它们正是那份「永远不变的 184 MB」。
   *  仍留在类型里只是为了让旧后端的响应能通过类型检查，不是给人用的。 */
  status?: 'up' | 'down' | 'connecting';
  /** @deprecated 见 status；流量一律读 sa.rxBytes。 */
  rxBytes?: number;
  /** @deprecated 见 status；流量一律读 sa.txBytes。 */
  txBytes?: number;
  /** @deprecated 见 status；建立时间读 sa.establishedAt（Unix 秒，不是中文相对时间串）。 */
  lastUp?: string;
}
export interface IpsecResp { sites: IpsecSite[] }
/** PUT /api/v1/ipsec/{id}/psk 的响应：只回指纹与版本，永远不回原文。 */
export interface IpsecPskResp { fingerprint?: string; version?: number }

/* ── 对象库（store.ObjectBundle）── */
export interface AddrObject { id: string; name: string; kind: 'ip' | 'cidr' | 'range' | 'domain'; value: string; desc: string }
export interface ServiceObject { id: string; name: string; proto: 'tcp' | 'udp' | 'icmp' | 'any'; ports: string; desc: string }
export interface TimeObject { id: string; name: string; kind: 'periodic' | 'absolute'; spec: string; desc: string }
export interface ObjectBundle { addrs: AddrObject[]; services: ServiceObject[]; times: TimeObject[] }

/* ── 对象库「被引用」反查（复用闭环，store.ObjectRef）── */
export interface ObjectRef { kind: 'resource' | 'ipsec'; id: string; name: string }
export interface ObjectUsageResp { usage: Record<string, ObjectRef[]> }

/* ── 终端用户门户 ── */
export interface PortalLoginResp {
  ok: boolean;
  needMfa?: boolean;        // legacy 演示验证码路径（未配置 WebAuthn RP 时回落）
  needWebauthn?: boolean;   // 需 passkey 断言；配合 ticket 走 /webauthn/login/*
  needEnroll?: boolean;     // 风险账号尚未注册 passkey，须先录入
  mustChangePassword?: boolean; // 首登强制改密：token 是 15min 受限令牌，只够调 /auth/password
  ticket?: string;          // 「口令已验」一次性票据（3min），断言两回合凭它绑定账号
  reason?: string;
  token?: string;
  displayName?: string;
  role?: string;
}

/* ── WebAuthn / passkey（store.WebauthnCredential）── */
export interface WebauthnCredential {
  id: string; userId: string; account: string; credentialId: string;
  signCount: number; transports: string; aaguid: string;
  name: string; createdAt: string; lastUsedAt: string;
}
export interface WebauthnCredentialsResp { credentials: WebauthnCredential[]; enabled: boolean }
export interface PortalTile { id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string; sensitivity: 'normal' | 'high'; accessible: boolean; resourceId: string }
export interface PortalAppsResp { apps: PortalTile[] }

/* ── JIT 即时访问申请 / 时限授予（store.AccessRequest / store.JitGrant）── */
export interface AccessRequest {
  id: string; user: string; resourceId: string; resourceName: string;
  reason: string; ttlMinutes: number;
  status: 'pending' | 'approved' | 'rejected';
  timeline: ApprovalEvent[];
  submittedAt: string; decidedAt: string; decideReason: string; decidedBy: string; grantId: string;
}
export interface JitGrant {
  id: string; user: string; resourceId: string; resourceName: string; requestId: string;
  reason: string; grantedBy: string; grantedAt: number; expiresAt: number;
  status: 'active' | 'revoked' | 'expired'; revokedAt: number; revokeReason: string;
}
export interface AccessRequestsResp { requests: AccessRequest[] }
export interface MyRequestsResp { requests: AccessRequest[]; grants: JitGrant[] }
export interface JitGrantsResp { grants: JitGrant[] }

/** 客户端下载中心（公开端点 GET /portal/downloads；文件走 /downloads/<file>） */
export interface ClientDownload {
  platform: string;
  label: string;
  version?: string;
  file?: string;
  size?: number;
  sha256?: string;
  available: boolean;
  arch?: string;
  note?: string;
}
export interface DownloadsResp { clients: ClientDownload[] }

/* ── 运维诊断（store/api.DiagBundle，控制面真实自检）── */
export type DiagStatus = 'pass' | 'warn' | 'fail';
export type DiagCategory = 'control' | 'storage' | 'dataplane' | 'stealth' | 'cluster' | 'identity' | 'posture' | 'security';
export interface DiagItem { label: string; value: string; status?: DiagStatus }
export interface DiagCheck {
  key: string; category: DiagCategory; name: string;
  status: DiagStatus; summary: string; metric: string; hint: string;
  items?: DiagItem[];
}
export interface DiagBundle {
  generatedAt: string; component: string; version: string; env: string; uptime: string;
  score: number; pass: number; warn: number; fail: number;
  checks: DiagCheck[];
}
