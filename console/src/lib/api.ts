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
  if (!res.ok) throw new Error(await errText(res));
  return (await res.json()) as T;
}

/**
 * errText 取后端的错误文案（httpx.Error 的 {"error":{"message":…}}），拿不到才退回状态行。
 * ★后端的守卫消息常常是**唯一能指导下一步动作**的信息（"分类下仍有 3 个应用，请先改归属"、
 * "该组织仍有子部门"），只把 "409 Conflict" 抛给调用方，等于把这些话全丢掉，
 * 管理员看到的就只是一次没有原因的失败。
 */
async function errText(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: { message?: string } };
    const msg = body?.error?.message;
    if (msg) return msg;
  } catch { /* 非 JSON 应答（网关 502 之类）：退回状态行 */ }
  return `${res.status} ${res.statusText}`;
}

/* ── 与 baidi-control internal/store.Overview 同构 ── */
export interface KV { name: string; value: number }
/** 三道防线之一。刻意没有 trend：趋势要有历史快照才算得出来，后端一张历史态势表都没有。 */
export interface DefenseLine { key: string; name: string; risk: number; top: string[] }
export interface Overview {
  generatedAt: string;
  /** 授信终端台账统计（trusted_devices 真实计数）。"设备此刻是否在线"控制面无从得知，
   *  故口径是台账：登记总数 / 已授信 / 待审批 / 已吊销，rate = 已授信占比（纳管率）。 */
  devices: { total: number; trusted: number; pending: number; revoked: number; rate: number };
  users: { total: number; disabled: number; locked: number };
  threats: { rejected: number; failed: number; secondary: number };
  sessions: number;
  auditByKind: KV[];
  verdicts: KV[];
  defense: DefenseLine[];
}

/* ── 与 store.PolicyBundle 同构（策略继承树） ── */
export interface OrgNode {
  key: string;
  title: string;
  hasCustom: boolean;
  members: number;
  children?: OrgNode[];
}
/** 只有 tree。后端原来还下发一份 list（5 条编造的策略清单），控制台从来没渲染过它，
 *  已随 store.PolicyBundle 一并删除——"哪个节点自己定了策略"由 OrgNode.hasCustom 表达。 */
export interface PolicyBundle {
  tree: OrgNode[];
}

/* ── 应用管理（store.AppBundle）── */
/** 应用页分类筛选条的一项。首项 key='all' 是后端现拼的**合成项**，不在分类字典里。 */
export interface AppCategory { key: string; label: string; count: number }
/**
 * 分类字典行（store.AppCategoryDef，表 app_categories）。
 * builtin=内置分类：可改名、可排序，不可删（key 被种子应用引用）。
 * count=该分类下的应用数，删除守卫判的就是它。
 */
export interface AppCategoryDef { key: string; label: string; sort: number; builtin: boolean; count: number }
export interface AppCategoriesResp { categories: AppCategoryDef[] }
export interface App {
  id: string; name: string; addr: string;
  mode: 'tunnel' | 'web' | 'global';
  category: string; node: string; authedUsers: number;
  /** 授权面性质：unlinked 未关联资源 / unlimited 未设 ACL 对全员开放 / limited 按 ACL 限定 */
  authScope?: 'unlinked' | 'unlimited' | 'limited';
  status: 'running' | 'stopped';
}
export interface AppBundle { categories: AppCategory[]; apps: App[] }

/* ── 访问者目录（store.UserDirBundle）── */
/** 身份源分栏。**与认证源页同一份 auth_sources 数据**：本地目录的 users = 没有任何外部
 *  绑定的账号数，外部目录的 users = 该源的绑定条数（登录过一次才有）。
 *  刻意没有 online / lastSync：users.online 只在建号那一刻写过、登录登出都不更新；
 *  白帝也不做目录周期同步（外部账号是首次登录时按 subject 绑定建号的）。 */
export interface Directory { key: string; name: string; type: 'local' | 'ldap' | 'ad' | 'oidc'; users: number }
/** 组织树节点（展示用）：members 是**子树**合计人数，不是直属数。 */
export interface OrgUnit { key: string; title: string; members: number; children?: OrgUnit[] }
/** 组织单元（持久化实体，store.Org）。members 为直属成员数。 */
export interface Org {
  id: string; name: string; parentId: string; path: string;
  sort: number; createdAt: string; members: number;
}
/** 用户组（store.UserGroup）。kind=static 显式成员；kind=role 按用户展示角色派生（成员只读）。 */
export interface UserGroup {
  id: string; name: string; kind: 'static' | 'role';
  description: string; createdAt: string; members: number;
}
/** GET /groups 的一行：用户组 + 它当前的成员账号。 */
export interface GroupWithMembers extends UserGroup { memberAccounts: string[] }
export interface DirUser {
  id: string; name: string; account: string; org: string; orgKey: string;
  /** 组织归属（org_units.id）。org/orgKey 是展示遗物，有 orgId 时由后端对齐到组织表。 */
  orgId: string;
  /** 所属用户组 id（含角色组的派生归属）。 */
  groups: string[];
  device: string; ip: string; auth: string; lastLogin: string;
  online: boolean; status: 'active' | 'locked' | 'disabled' | 'idle'; risk: 'none' | 'low' | 'high';
  roles: string[];
}
export interface UserDirBundle { directories: Directory[]; orgTree: OrgUnit[]; groups: UserGroup[]; users: DirUser[] }

/* ── 终端管理 · 授信终端（store.DeviceBundle）── */

/** 准入模式：observe = 非授信终端照常放行但留痕；strict = 拒发敲门令牌（连不进数据面）。 */
export type DeviceTrustMode = 'observe' | 'strict';
export type DeviceStatus = 'pending' | 'trusted' | 'revoked';
export interface DeviceTrustSetting {
  mode: DeviceTrustMode;
  bindMethod: 'auto' | 'approval';
  staleDays: number;
  /** 单账号设备上限。**只读**：判定写死在原子 SQL 里，前端按它置灰并注明「内置上限」。 */
  perUserQuota: number;
}
/** 一台已登记终端。verdict/os/clientVersion/stale 是后端读时派生，不落库。 */
export interface Device {
  id: string; account: string; fingerprint: string; name: string; platform: string;
  status: DeviceStatus;
  firstSeen: number; lastSeen: number;
  approvedBy: string; approvedAt: number; approvalId: string; revokeReason: string;
  stale: boolean;
  os: string; clientVersion: string;
  /** 最近一次 posture 判定；**空串 = 从未上报**（不是 allow）。 */
  verdict: '' | 'allow' | 'degrade' | 'gray' | 'block';
  level: string; postureTs: number;
}
export interface ApprovalEvent { time: string; kind: 'submit' | 'login' | 'review' | 'notify' | 'risk'; title: string; detail: string }
export interface TrustApproval {
  id: string; user: string; device: string; fingerprint: string; submittedAt: string;
  reason: string; status: 'pending' | 'approved' | 'rejected'; timeline: ApprovalEvent[];
}
export interface DeviceBundle { settings: DeviceTrustSetting; devices: Device[]; approvals: TrustApproval[] }

/* ── 审计中心（store.AuditBundle）── */
export interface DiskStat { usedPct: number; totalGB: number; retainDays: number }
/** 一条审计记录。★seq/mac 是防篡改链的序号与链式 MAC：列表、CSV 导出、
 *  syslog/SIEM 外送三个出口同源（后端就是同一个 store.AuditEntry）。 */
export interface AuditEntry { time: string; category: 'access' | 'auth' | 'admin' | 'security' | 'dataplane'; user: string; srcIp: string; event: string; verdict: 'allow' | 'deny' | 'mfa' | 'ok' | 'fail'; seq?: number; mac?: string }
export interface AuditBundle { categories: KV[]; todayTotal: number; disk: DiskStat; logs: AuditEntry[] }

/* ── 网关与隐身（GET /api/v1/gateway → api.GatewayPageBundle）──
 *
 * ★数据源是 mTLS 注册心跳的在线登记（与 GET /api/v1/gateways、诊断页同一份），
 * 不再是「华东/华南出口」那张编造的区域拓扑。区域、主备角色、负载百分比三个维度
 * 已整体去掉：白帝没有区域概念、没有选主、也不采集负载，画出来就是假的。
 */
export interface GwNode {
  id: string; proxy: string; spa: string;
  online: boolean; lastSeen: number; uptime: number;
  clients: number; tunnels: number; sessions: number;
  /** 网关二进制版本；旧网关不上报则为空串。 */
  version: string;
  /**
   * 网关时钟相对控制面的偏差（秒，正=网关快）；null = 旧网关未上报（不可判定）。
   * ★渲染纪律与 posture/设备指标一致：null 显示「未上报」，绝不显示 0——
   * 敲门令牌由控制面签、网关验，时钟这一列失真的代价是「敲门全灭且无处报错」。
   */
  skewSec: number | null;
}
export interface GatewayBundle {
  nodes: GwNode[];
  total: number; online: number; sessions: number;
  /** 判定"在线"的心跳窗口秒数（页面据此说清判据，而不是让人猜阈值）。 */
  onlineWindowSec: number;
  /** 控制面签发的敲门令牌有效期（秒）。 */
  knockTokenTtlSec: number;
}

/* ── 系统管理 · 三权分立（store.SystemBundle）──
 *
 * perms 是**执行方真正读的那份**（后端 admin_roles.scope_json，api.requirePerm 逐端点比对）；
 * scope 只是它的中文摘要。别把摘要当判据渲染成"能做什么"，两者不同源就会出现
 * 「页面说能做、点下去 403」。
 */
export type AdminPerm = 'system' | 'security' | 'audit' | 'admins' | '*';
export interface AdminRole {
  key: string; name: string;
  power: 'root' | 'system' | 'security' | 'audit' | 'custom';
  builtin: boolean; perms: AdminPerm[]; members: number; scope: string;
}
export interface AdminAccount {
  id: string; name: string; account: string;
  roleKey: string; roleName: string; power: string;
  auth: string; twoFa: boolean; lastLogin: string; status: string;
}
/* ── 控制面温备（standby.ClusterView，PRD 15.5 / FR-ARCH-03）──
 *
 * ★白帝的控制面是**温备不是双活**：SQLite 单写者，做不了多活。备机周期拉加密备份、
 * 校验后落盘，不对外提供服务；切换由人工/脚本触发（promoteCmd 给的是真能跑的那条命令）。
 * RPO = 同步间隔，必须原样显示——让人以为是零丢失比没有温备更危险。
 * 三态：未配置备机（skip）/ 同步新鲜（pass）/ 落后或失败（warn），与 /diag checkCluster 同源。
 */
export type StandbyState = 'fresh' | 'stale' | 'never';
export interface StandbyNodeView {
  nodeId: string; addr: string; state: StandbyState;
  /** 盘上那份落后多久；**-1 = 不可判定**（从未成功同步过），不是 0。 */
  lagSeconds: number; lagText: string;
  intervalSec: number; thresholdSec: number;
  lastSyncAt: string; lastPullAt: string;
  backupVersion: string; backupCreatedAt: string; backupSha256: string;
  lastStatus: string; lastDetail: string;
}
export interface ClusterInfo {
  mode: 'single' | 'warm-standby';
  deployed: boolean;
  status: 'pass' | 'warn' | 'skip';
  summary: string; note: string; rpo: string;
  staleAfterSec: number;
  nodes: StandbyNodeView[];
  boundaries: string[];
  promoteCmd: string;
}
export interface SystemBundle { roles: AdminRole[]; admins: AdminAccount[]; cluster: ClusterInfo }

/* ── 消息通道（store.NotifyChannel，PRD ch15.2）──
 *
 * ★三种类型的边界要照实说：smtp / webhook 是真实现；sms **就是一次 webhook 调用**
 * （载荷 mobiles + text），白帝不实现任何短信网关协议——后端会把这句话随
 * smsNote 一起下发，界面照抄，不许自己写成"已支持某某云短信"。
 */
export type NotifyKind = 'smtp' | 'webhook' | 'sms';

export interface NotifyChannel {
  id: string;
  name: string;
  kind: NotifyKind | string;
  enabled: boolean;
  /** 非敏感配置 JSON 字符串（敏感项在独立加密表，不在这里）。 */
  config: string;
  /** 凭据是否已配置。原文永不回显——只写不读。 */
  hasSecret: boolean;
  /** 凭据指纹前 8 位，供核对"是不是同一把"。 */
  secretFingerprint?: string;
  /** 上次发送结果。★只由**真正发出那一次**写入，保存配置不会碰它。 */
  lastStatus?: 'ok' | 'fail' | '';
  lastDetail?: string;
  lastEvent?: string;
  lastAt?: number;
  createdAt: string;
  updatedAt: string;
}

export interface NotifyChannelsResp {
  channels: NotifyChannel[];
  /** 后端真实实现了的类型；控制台据此置灰未实现项。 */
  supportedKinds: string[];
  /** 通知队列溢出被丢弃的**真实**累计条数：区分"压根没触发"与"触发了但没发出去"。 */
  droppedNotices: number;
  /** 短信通道的诚实标注，由后端下发、界面原样展示。 */
  smsNote: string;
}

/** SMTP 通道配置（与 control 的 smtpChannelDTO 对齐）。 */
export interface SmtpChannelConfig {
  host: string;
  port?: number;
  tlsMode: 'starttls' | 'implicit' | 'plaintext';
  serverName?: string;
  caCert?: string;
  insecureSkipVerify?: boolean;
  authMode: 'none' | 'plain' | 'login';
  username?: string;
  from: string;
  fromName?: string;
  recipients: string[];
  timeoutSec?: number;
}

/** Webhook / 短信通道配置（与 control 的 webhookChannelDTO 对齐）。 */
export interface WebhookChannelConfig {
  url: string;
  headers?: Record<string, string>;
  /** 凭据要注入的头名；头值在加密表里，只写不读。 */
  secretHeader?: string;
  /** webhook: 载荷里的 to；sms: 手机号。 */
  recipients?: string[];
  timeoutSec?: number;
}

export interface NotifyTestResp { ok: boolean; detail: string; elapsedMs?: number }
export interface SaveNotifyChannelResp { ok: boolean; channel: NotifyChannel; warning?: string }

/* ── 审计日志外送（store.AuditForwardTarget，PRD ch16 + ch21.6）──
 *
 * 两种出口都是真实现：syslog 走 **RFC 5424 over TCP**（可选 TLS，没有"跳过证书校验"
 * 这一项，见后端注释）；http 是通用 JSON 出口。**刻意没有 UDP**——审计日志用 UDP
 * 会静默丢包，而"丢了"这件事两端都看不见。
 *
 * 每条外送记录都带链的 seq/mac，SIEM 侧可据此独立验真——这是本功能的价值所在，
 * 不是"日志复制"。
 */
export type AuditForwardKind = 'syslog' | 'http';

export interface AuditForwardTarget {
  id: string;
  name: string;
  kind: AuditForwardKind | string;
  enabled: boolean;
  /** 非敏感配置 JSON 字符串（凭据在独立加密表，不在这里）。 */
  config: string;
  hasSecret: boolean;
  secretFingerprint?: string;
  /** 建立该出口时的审计水位：此前的历史**不会补发**，页面要如实说出来。 */
  startAuditId: number;
  /** 上次发送结果。★只由真正发出那一次写入，保存配置不会碰它。 */
  lastStatus?: 'ok' | 'fail' | '';
  lastDetail?: string;
  /** 上次尝试（无论成败）/ 上次**成功**。运维靠后者判断外送是不是已经断了。 */
  lastAt?: number;
  lastOkAt?: number;
  /** 队列满时被丢弃的累计条数（落库、可见）：这些审计已落库但不会送达 SIEM。 */
  dropped: number;
  /** 当前积压条数（读时现算）。 */
  queued: number;
  createdAt: string;
  updatedAt: string;
}

export interface AuditForwardResp {
  targets: AuditForwardTarget[];
  supportedKinds: string[];
  /** 每个出口的队列上界；没有它，页面上的积压数看不出离丢弃还有多远。 */
  queueMax: number;
  /** 后端下发的诚实标注（历史不补发 / seq+mac 可验真），界面原样展示。 */
  note: string;
}

/** syslog 出口配置（与 control 的 syslogTargetDTO 对齐）。 */
export interface SyslogTargetConfig {
  host: string;
  port?: number;
  tls: boolean;
  serverName?: string;
  caCert?: string;
  facility?: number;
  appName?: string;
  hostname?: string;
  framing?: 'octet' | 'lf';
  enterpriseId?: string;
  timeoutSec?: number;
}

/** HTTP JSON 出口配置（与 control 的 httpTargetDTO 对齐）。 */
export interface HttpTargetConfig {
  url: string;
  headers?: Record<string, string>;
  /** 凭据要注入的头名；头值在加密表里，只写不读。 */
  secretHeader?: string;
  caCert?: string;
  timeoutSec?: number;
}

export interface SaveAuditForwardResp { ok: boolean; target: AuditForwardTarget; warning?: string }
export interface AuditForwardTestResp { ok: boolean; detail: string; elapsedMs?: number }
export interface AuditForwardFlushResp { ok: boolean; reset: number; target: AuditForwardTarget }

/* ── 认证源接入 · 聚合视图（GET /api/v1/authsrc → store.AuthSrcBundle）──
 *
 * 与下面的 AuthSourceRec 同源（都读 auth_sources），差别只在这份多带一个
 * **账号计数**、不带凭据元信息。原来的 status / users / primary 三个字段已删除：
 * status 恒 online 是替一台可能早已宕掉的目录打包票；users（「AD 域 1160 用户」）
 * 纯属编造——目录规模要遍历整个 LDAP 才数得出来，白帝没有那个能力。
 */
export interface AuthSource {
  key: string;
  name: string;
  type: AuthSrcKind | string;
  enabled: boolean;
  priority: number;
  /** 本系统内归属该源的账号数：外部源 = 已绑定条数，本地目录 = 无外部绑定的账号数。
   *  **不是目录纳管用户数**。 */
  boundAccounts: number;
}
export interface AuthSrcBundle { sources: AuthSource[] }

/** 自适应规则沙盘（Auth.vue 的「自适应认证规则」页签本地推演用）。
 *  ★后端**没有**这套规则：真实生效的自适应认证是认证策略（AuthPolicy 的
 *  enhance/exempt，登录链路真求值）。这两个接口只描述前端沙盘的形状。 */
export interface RuleCond { field: 'weakPwd' | 'geoAnomaly' | 'offHours' | 'riskScore' | 'untrustedDevice' | 'newDevice'; op: 'is' | 'gt' | 'in'; value: string }
export interface AdaptiveRule { id: string; name: string; enabled: boolean; logic: 'AND' | 'OR'; conditions: RuleCond[]; action: 'allow' | 'mfa' | 'stepup' | 'block'; priority: number }

/* ── 认证源接入 · 单条配置（GET /api/v1/authsrc/sources）──
 *
 * 与上面的 AuthSource 同一批库行的两个投影：这一份带凭据元信息（只写不读的
 * 存在性 + 指纹），编辑抽屉用；上一份带账号计数，卡片汇总用。
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

/* ── 认证策略 · PC/移动端分栏 + 自适应规则（store.AuthPolicy，FR-INTRO-07/08、FR-AUTH-12）──
 *
 * ★这些开关是**登录链路真读的**（control/internal/authpolicy.Evaluate），不再是纯展示：
 * 命中增强条件且未被豁免 → 登录被要求二次认证。因此界面上任何一个勾都必须是真能生效的，
 * 判不了的规则由后端 capabilities 声明为不可用并在此置灰（不是静默无效）。
 */
export type PrimaryMethod = 'local' | 'ad' | 'ldap' | 'radius' | 'oauth' | 'sms' | 'cert';
export type SecondaryMethod = 'sms' | 'totp' | 'radius' | 'cert' | 'http';
export interface AuthMethodSet { primary: PrimaryMethod | ''; secondary: SecondaryMethod[] }
export interface ExemptRule {
  trustedDevice: boolean;
  trustedNetwork: boolean;
  /** 可信网段 CIDR 列表。trustedNetwork 开启时必须非空，否则后端拒绝保存（空 = 永不命中）。 */
  networks: string[];
  /** 已冻结：无域校验能力，后端拒绝开启。 */
  winDomain: boolean;
}
export interface EnhanceRule {
  /** 范围内一律二次认证（取代此前写死的「账号名以 ext 开头或含外包」启发式）。 */
  always: boolean;
  weakPwd: boolean;
  offHours: boolean;
  /** 工作时段 HH:MM（空 = 09:00 / 18:00）与工作日 1-7（空 = 周一至周五）。 */
  workStart: string; workEnd: string; workDays: number[];
  /** 已冻结：未接入 IP 地理库，后端拒绝开启。 */
  geoAnomaly: boolean;
}
export interface AuthPolicy {
  id: string; name: string; directory: PrimaryMethod | string; isDefault: boolean;
  /** scope 只是文字说明；真正参与匹配的是 scopeOrgs / scopeGroups。 */
  scope: string; priority: number; enabled: boolean;
  pc: AuthMethodSet; mobile: AuthMethodSet;
  /** 适用范围：组织（含子树）与用户组。非默认策略两者皆空则匹配不到任何账号，后端拒绝保存。 */
  scopeOrgs: string[]; scopeGroups: string[];
  exempt: ExemptRule; enhance: EnhanceRule; authzApps: string;
}
/** 一条规则的能力声明：能不能判、判据是什么、判不了是为什么（后端 authpolicy.Capabilities）。 */
export interface AuthRuleCapability {
  key: string; kind: 'enhance' | 'exempt'; label: string;
  available: boolean; effect: string; reason: string;
}
/** 可被策略绑定的「用户目录」。key 与登录链路给判定的 directory 同一取值域：
 *  本地哈希命中 = local，外部源命中 = 该认证源的 kind（ldap|ad|oidc）。
 *  ★这份清单必须由后端下发：前端写死的话，管理员真配的 LDAP/OIDC 源永远进不了下拉，
 *  而登录链路只按 kind 匹配——策略一条都命中不了，且页面上无从修。 */
export interface AuthDirectory {
  key: string; name: string;
  /** 该目录下是否有已配置的认证源。false = 当前不会有人从这个目录登录（如已删源的存量策略）。 */
  configured: boolean;
  sources: string[];
}
export interface AuthPolicyResp {
  policies: AuthPolicy[];
  capabilities?: AuthRuleCapability[];
  directories?: AuthDirectory[];
  orgs?: SubjectOption[];
  groups?: SubjectOption[];
}

/* ── 安全中心（store.SecurityBundle）── */
export interface BaselineCheck { key: string; label: string; platform: 'Windows' | 'macOS' | 'Linux' | 'All'; expect: string; severity: 'high' | 'medium' | 'low' }
export interface BaselinePolicy { id: string; name: string; type: 'app-protect' | 'onboarding'; scope: string; disposal: 'allow' | 'degrade' | 'block' | 'gray'; status: 'enabled' | 'disabled'; platforms: string[]; checks: BaselineCheck[] }
/** 只有 baselines。原来还有一段 spa（G3 / 已隐身 / 敲门正常）是纯种子——控制面既不实测
 *  端口可见性、也不代数据面宣布敲门是否正常，整段连同安全中心页那张卡片已删除。
 *  真实出处是「网关与隐身」页：那里每一项都来自网关 mTLS 注册心跳。 */
export interface SecurityBundle { baselines: BaselinePolicy[] }

/* ── 终端 posture（安全中心 · 终端合规） ── */
/** unknown = 终端探不到该项（权限不足/命令缺失），既非合规也非不合规。
 *  上报时 ok 恒 false（对旧控制面 fail-closed），故渲染必须**先看 unknown**。 */
export interface PostureCheckRow { key: string; label: string; ok: boolean; unknown?: boolean; value: string }
export interface PostureRow {
  user: string; device: string; platform: string; os: string; clientVersion: string;
  checks: PostureCheckRow[]; verdict: 'allow' | 'degrade' | 'gray' | 'block';
  score: number; level: 'low' | 'medium' | 'high'; reasons: string[]; ts: number;
}
export interface PostureResp { reports: PostureRow[] }

/* ── 资源策略 + 在线网关（数据面，control 托管、网关动态拉取） ── */
export interface Resource {
  id: string; name: string; backend: string; allowRoles: string[]; allowUsers: string[];
  /** 授权用户组 id（store.Resource.AllowGroups）。控制面下发网关前展开成账号，数据面看不到组。 */
  allowGroups?: string[];
  /** 授权组织 id（store.Resource.AllowOrgs）。★含子树：授权某组织即涵盖其全部后代组织的用户。 */
  allowOrgs?: string[];
  /**
   * 资源敏感度（store.Resource.Sensitivity）。**风险降权的唯一判据**：
   * 终端被判 degrade 的用户，high 资源会从网关允许集合与客户端剖面里同时摘除，
   * low/normal 照常可访问（降权而非全断）。空 = 未标注，后端按 normal 处理。
   */
  sensitivity?: 'low' | 'normal' | 'high';
  /**
   * 七层 Web 代理拨内网后端用的协议（store.Resource.WebScheme）。空 = 后端按端口推默认
   * （443/8443 → https，其余 http）。★它是拨号参数不是策略：猜错的症状是浏览器上一个
   * 空白页，而两侧日志都正常，所以 Web 应用发布时应显式选。
   */
  webScheme?: 'http' | 'https';
  /**
   * 对外访问入口基址覆盖（store.Resource.WebEntry），如 https://oa.corp.example。
   * 空 = 用网关自报的七层落点。只影响控制面发给浏览器的跳转地址，不影响网关路由。
   */
  webEntry?: string;
  addrRef?: string; svcRef?: string;
}
/**
 * 可选授权主体（组织或用户组）+ 它当前覆盖的账号。
 *
 * ★accounts 是**服务端展开好**的（组织那份已含全部后代组织的成员），与下发给网关时
 * 并进 allowUsers 的是同一次展开。前端只做集合并，绝不自己走组织树——
 * 子树语义实现两遍，迟早会让管理员看到的人数与网关实际放行的人对不上。
 */
export interface SubjectOption { id: string; name: string; kind?: 'static' | 'role'; path?: string; accounts: string[] }
export interface ResourcesResp { resources: Resource[]; orgs?: SubjectOption[]; groups?: SubjectOption[] }
export interface GwSess { ip: string; user: string; role: string; since: number }
export interface GatewayReg { id: string; proxy: string; spa: string; lastSeen: number; clients: number; tunnels: number; uptime: number; version?: string; sessions?: GwSess[] }
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
  /**
   * 档位。★与风险引擎的处置四档**同一套名字**：block/degrade/gray 就是控制面此刻
   * 正在执行的那一档（degrade 已摘掉高敏资源、gray 每轮下发都在记 observing 审计），
   * locked/disabled 是与风险正交的目录账号状态。
   * 旧的 risk-high/risk-low/idle 已删除——同一个概念在两处两套名字，管理员无从对照。
   */
  state: 'block' | 'degrade' | 'gray' | 'locked' | 'disabled';
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
export interface PortalTile {
  id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string;
  sensitivity: 'low' | 'normal' | 'high';
  accessible: boolean; resourceId: string;
  /** 因终端风险降权而不可访问（而非缺授权）。降权否决压过 JIT 授予，此时提交申请必然无效，
   *  用户该做的是修复终端环境——两种"不可访问"的下一步动作完全不同，必须分开提示。 */
  degraded?: boolean;
}
/** 七层 Web 代理入口此刻能不能用。ready=false 时 note 说明原因（网关没开 -web / 没有网关在线）。
 *  ★门户据此把 Web 磁贴的「访问」按钮置灰并显示原因，而不是让人点了才拿到一个一闪而过的 503。 */
export interface WebProxyStatus { ready: boolean; note: string }
export interface PortalAppsResp { apps: PortalTile[]; webProxy?: WebProxyStatus }
/** POST /portal/web-ticket 的响应：短时效一次性入口 URL（浏览器直接跳过去换会话 Cookie）。 */
export interface WebTicketResp { url: string; expiresIn: number; resourceId: string }

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
  /** 构建溯源：这包出自哪份客户端源码、什么时候构建的（由 build-artifacts.sh 写入）。 */
  builtAt?: string;
  sourceCommit?: string;
  /** 服务端现算：该包所依据的源码之后又被改过（包里不含此后的能力）。 */
  stale?: boolean;
  /** 服务端现算：没有溯源信息，**无法判断**新旧——不等于「不过期」。 */
  provenanceUnknown?: boolean;
  /** stale / provenanceUnknown 的人话解释，直接展示给用户。 */
  staleReason?: string;
}
export interface DownloadsResp { clients: ClientDownload[] }

/* ── 运维诊断（store/api.DiagBundle，控制面真实自检）── */
/* skip = 该能力未部署（如集群），不参与健康分；渲染时对未知枚举兜底为中性样式，别让页面崩 */
export type DiagStatus = 'pass' | 'warn' | 'fail' | 'skip';
export type DiagCategory = 'control' | 'storage' | 'dataplane' | 'stealth' | 'cluster' | 'identity' | 'posture' | 'security';
export interface DiagItem { label: string; value: string; status?: DiagStatus }
export interface DiagCheck {
  key: string; category: DiagCategory; name: string;
  status: DiagStatus; summary: string; metric: string; hint: string;
  items?: DiagItem[];
}
export interface DiagBundle {
  generatedAt: string; component: string; version: string; env: string; uptime: string;
  score: number; pass: number; warn: number; fail: number; skip?: number;
  checks: DiagCheck[];
}

/* ── 监控中心 · 设备状态（GET /monitor/device-stat，PRD ch5 FR-MON-01/02）── */

/**
 * 一个指标值：number = 网关真采到的实测值；**null = 不可判定**（这台机器采不到）。
 *
 * ★不要在任何地方写 `v ?? 0` 把它折平——「CPU 0%」看起来像一台空闲的机器，
 * 而实际是根本没采到，两者的下一步动作完全不同。渲染成「—」，并说明原因。
 */
export type MetricValue = number | null;

/** 一条原始采样点（当前值取的就是这个，不是桶均值）。 */
export interface DeviceMetricPoint {
  gatewayId: string;
  ts: number;
  cpu: MetricValue; mem: MetricValue; disk: MetricValue;
  load: MetricValue; rxBps: MetricValue; txBps: MetricValue;
}

/** 一个降采样时间桶。★空桶不会出现在数组里——掉线段靠相邻 ts 的跨度识别并断线。 */
export interface DeviceMetricBucket {
  ts: number;   // 桶起点
  n: number;    // 桶内原始采样点数
  cpu: MetricValue; mem: MetricValue; disk: MetricValue;
  load: MetricValue; rxBps: MetricValue; txBps: MetricValue;
}

export interface DeviceMetricSeries {
  gatewayId: string;
  latest: DeviceMetricPoint | null;
  points: DeviceMetricBucket[];
}

export type DeviceStatRange = 'hour' | 'day' | 'week';

export interface DeviceStatResp {
  range: DeviceStatRange;
  rangeLabel: string;
  since: number;
  until: number;
  bucketSec: number;
  retentionHours: number;
  truncated: boolean;      // 时间窗被留存期截断（周档常见）
  onlineGateways: number;
  silentGateways: string[]; // 在线、但一条指标都没上报过（多半是旧版本网关）
  gateways: DeviceMetricSeries[];
  generatedAt: string;
}

/* ── 业务告警（store.Alert / AlertRule，PRD ch5 FR-MON-21~25）──
   与审计中心的区别：审计是只追加的流水，这里是**待办实体**——有状态机、有处置人。 */
export type AlertStatus = 'pending' | 'ignored' | 'handled';
export type AlertCategory = 'device' | 'authz' | 'security';
export type AlertSeverity = 'info' | 'warning' | 'critical';
export interface Alert {
  id: string; ruleId: string; kind: string;
  category: AlertCategory; severity: AlertSeverity;
  title: string; detail: string;
  /** 告警对象的稳定标识（gw:xxx / grant:xxx / posture:account…），去重键的一半 */
  objectKey: string;
  status: AlertStatus; triggeredAt: number; handledAt?: number; handledBy?: string;
}
export interface AlertCounts { pending: number; ignored: number; handled: number }
export interface AlertsResp {
  alerts: Alert[];
  /** 全局计数，**不受列表过滤影响**（角标与页头统计吃它） */
  counts: AlertCounts;
  categories: Record<string, string>;
}
export interface AlertRule {
  id: string; name: string; kind: string;
  threshold: Record<string, number>;
  enabled: boolean;
  /** 点名的通知通道（留空 = 发给全部启用中的通道） */
  channels: string[];
  cooldownSec: number;
  createdAt?: string; updatedAt?: string;
}
/** 规则种类元信息：阈值表单按它渲染，前端不写第二份阈值清单 */
export interface AlertKindSpec {
  kind: string; name: string; category: AlertCategory; severity: AlertSeverity;
  /** 该规则读的是哪份真实信号（原样展示给排障的人看） */
  signal: string;
  thresholds: Record<string, number>;
  thresholdZh: Record<string, string>;
}
/** 数据源就绪状态：未就绪时要如实说明「等待数据面上报」，而不是让规则看起来在工作 */
export interface AlertDataSource { kind: string; ready: boolean; reason?: string }
export interface AlertNotifyOption { id: string; name: string; kind: string; enabled: boolean }
export interface AlertRulesResp {
  rules: AlertRule[];
  kinds: AlertKindSpec[];
  sources: AlertDataSource[];
  notify: { wired: boolean; channels: AlertNotifyOption[]; note?: string; reason?: string };
  cooldown: { default: number; min: number; max: number };
}

/* ── 地址转换 NAT（PRD 第 18 章，store.NATPolicy / GatewayIface）────────────── */

/** 转换类型：snat=内网出站统一出口（代理上网）；dnat=公网 IP:端口 → 内网真实地址（资源发布）。 */
export type NATType = 'snat' | 'dnat';
export type NATProto = 'tcp' | 'udp' | 'icmp' | 'all';
/** 网卡类型。空串=尚未定性，不能出现在任何 NAT 策略里。 */
export type IfaceType = 'lan' | 'wan' | '';

export interface NATPolicy {
  id: string; name: string; type: NATType;
  /** NAT 是网关设备本地能力，每条策略必须绑定到具体网关。 */
  gatewayId: string;
  srcIface: string; srcAddr: string;
  dstIface: string; dstAddr: string;
  protocol: NATProto;
  /** 以下三项仅 DNAT 有效，SNAT 保存时会被后端清零。 */
  dstPort: number; translatedAddr: string; translatedPort: number;
  enabled: boolean; createdAt?: string; updatedAt?: string;
}

/** 网关实测枚举上报的网卡；type 由管理员定（网关无可靠依据自动判断）。 */
export interface GatewayIface {
  gatewayId: string; name: string; type: IfaceType; addrs: string[]; up: boolean; updatedAt?: string;
}

export interface NATBundle {
  policies: NATPolicy[];
  ifaces: GatewayIface[];
  /** 后端下发的风险提示（SPA 互斥 / 回程路由 / 带宽）。PRD 把它列为强需求，前端不得自行编写。 */
  warnings: string[];
}

/* ── 产品升级管理（PRD 第 4 章，internal/upgrade）──────────────────────── */

/** 强制跳跃链路的一跳：低于 below 的版本必须先升到 next。版本号由管理员配，代码里不写死。 */
export interface UpgradeHop { below: string; next: string }
export interface UpgradeRules {
  allowDowngrade: boolean;
  requireComponentMatch: boolean;
  hops: UpgradeHop[];
}
/** 一个平台的客户端灰度计划。version 为空=该平台无灰度，所有人拿 stable。 */
export interface GrayPlan {
  platform: string; version: string; percent: number;
  accounts: string[]; groups: string[]; stable: string; note?: string;
}
export interface UpgradeBundle {
  control: string;
  /** 网关 id → 上报版本；空串=旧网关不上报（判定层会标「无法校验」，不是「一致」）。 */
  gateways: Record<string, string>;
  rules: UpgradeRules;
  gray: GrayPlan[];
  /** 后端下发的边界声明：哪些做了、哪些刻意不做。前端不得自行编写或省略。 */
  boundaries: string[];
}
/** 升级包校验结论（POST /upgrade/check）。blocked 时 UI 必须禁用升级并显示 reasons。 */
export interface UpgradeCheckResult {
  blocked: boolean; reasons?: string[]; warnings?: string[];
  nextHop?: string; manifest?: { version: string; component: string; notes?: string };
}
