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
export interface DefenseLine {
  key: string; name: string; risk: number; top: string[];
  /** scope 这条防线的数是**窗口内累计**（window）还是**当前状态**（current）。
   *  ★三条线里只有隐身防线真按时间窗算：账号防线读 users 表的当前状态，
   *  终端防线读 posture_reports 的最新一份（压根没有历史）。时间选择器对后两条
   *  不生效——不标出来的话，切到「近 7 天」看到的是当前状态却以为是七天内的情况。
   *  一个悄悄不生效的筛选比没有筛选更坏。 */
  scope?: 'window' | 'current';
  note?: string;
}
/** 近 24h 攻击源统计（数据面拒绝事件的聚合，attack_sources 表）。
 *  trend 的 0 是真实的「这一小时没有拒绝」——与设备指标的 NULL 语义不同。 */
export interface AttackStat {
  sources: number; denies: number;
  top: { ip: string; count: number; cat: string }[];
  trend: KV[];
}
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
  /** 缺席 = 后端没有攻击表（内存种子模式），整块面板不画。 */
  attack?: AttackStat;
  /** 审计派生统计（访问决策/判定分布/威胁事件/攻击源）的时间窗（小时）。
   *  ★改造前它们是**建库以来累计**，而攻击源是严格 24h，两个口径并排显示在
   *  标着「实时判定态势」的同一屏上，页面一处不标。 */
  windowHours?: number;
  /** 口径说明（含"实际能覆盖多久"）。 */
  windowNote?: string;
  /** 所选窗口被审计留存期截断了（页面据此加提示）。 */
  truncated?: boolean;
}

/* ── 接入策略（FR-POLICY-29 同时在线设备上限 / FR-POLICY-30 接入超时注销）──
 *
 * ★这里原来是 PolicyBundle / OrgNode（策略继承树）+ 8 项继承编辑器。那 8 项落进
 * policy_overrides.settings 之后**全仓零消费方**，而保存 toast 写着「已下发至代理网关」。
 * 整批摘除（wave8 行动 13-①），换成下面这两条真有执行方的规则：执行点是敲门令牌
 * （api.accessSessionGate → handleKnockToken），撤销在一个 15s 保活周期内必然生效。 */
export interface AccessPolicy {
  /** 是否启用「同时在线设备上限」。★与 maxDevices=0 不是一回事：0 = 禁止接入（PRD 原文）。 */
  deviceLimitEnabled: boolean;
  maxDevices: number;
  splitPlatform: boolean;
  maxDevicesMobile: number;
  idleEnabled: boolean;
  idleMinutes: number;
}
/** 一台终端的接入会话（页面上「谁在线、哪台机器、多久没业务流量」）。 */
export interface DeviceSessionRow {
  account: string;
  fingerprint: string;
  platform: string;
  ip: string;
  firstSeen: number;
  lastKnock: number;
  lastActive: number;
  /** false = 没有任何网关报过这条会话的活跃时刻 → 超时规则对它**不生效**（页面必须显示"不可判定"）。 */
  activityKnown: boolean;
  state: 'active' | 'timeout';
  endedReason?: string;
}
export interface AccessPolicyResp {
  policy: AccessPolicy;
  onlineWindowSec: number;
  storeReady: boolean;
  sessions?: DeviceSessionRow[];
  activityKnown?: number;
  /** false = 目前没有任何活跃回执，开了「接入超时注销」也不会触发。页面必须当面说清。 */
  idleReady?: boolean;
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
  /** tunnel/web 是受控发布；**global 是直连书签**——不经网关、不受访问控制，
   *  对全体登录用户可见（剖面与门户都直接给 accessible: true）。 */
  mode: 'tunnel' | 'web' | 'global';
  /** 关联的受控资源 id。空 = 未关联，隧道与七层两条路都不通。 */
  resourceId?: string;
  category: string; authedUsers: number;
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
  id: string; name: string; kind: 'static' | 'role' | 'external';
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

/* ── 用户批量导入导出（GET /users/export → CSV 附件；POST /users/import ← CSV 原文）──
 *
 * ★导出**不含口令哈希、也不含口令强度**：前者是能拿去离线爆破的材料，后者是一张
 * "先打哪个账号"的排序表。两者都由后端的 store.UserExportRow 从类型层面排除。
 * ★导入**只建普通用户**：CSV 里出现「角色 / role / 管理员角色」一类列，后端整份拒收
 * （建管理员的唯一入口是 /api/v1/admins）。界面必须照实说，别让人以为能用表格发管理员。
 */
export interface UserImportRow {
  /** 文件里的**物理行号**（含表头行，故首个数据行通常是 2）——管理员拿它回 Excel 定位。 */
  row: number;
  account?: string;
  name?: string;
  /** 成功时给新账号 id。 */
  id?: string;
  /** 失败时给原因（后端原话，直接展示）。 */
  reason?: string;
}
export interface UserImportResp {
  ok: boolean;
  /** 文件里的数据行总数（= created + failed）。 */
  total: number;
  created: UserImportRow[];
  failed: UserImportRow[];
  /** 表头里没被识别的列。必须展示：填了却什么都没发生，是最难自查的一种"导入成功"。 */
  ignoredColumns?: string[];
}

/* ── 终端管理 · 授信终端（store.DeviceBundle）── */

/** 准入模式：observe = 非授信终端照常放行但留痕；strict = 拒发敲门令牌（连不进数据面）。 */
export type DeviceTrustMode = 'observe' | 'strict';
export type DeviceStatus = 'pending' | 'trusted' | 'revoked';

/** 资产分类（PRD ch9 FR-EP-06~09）。**是准入判据**：personal 受 personalPolicy 约束，
 *  managed（企业纳管个人）按企业资产处理——它的语义就是"个人设备但已纳管"。 */
export type AssetClass = 'enterprise' | 'personal' | 'managed';

/** 个人资产准入策略。执行方是控制面的敲门令牌闸（api.deviceAdmissionGate），
 *  粒度是 (账号,指纹)：同一个人的企业机不受影响。
 *  - inherit：与企业资产一视同仁，走全局 mode（**默认，行为与本功能上线前一致**）
 *  - strict：个人资产恒按严格准入判（即使全局是 observe）
 *  - deny：个人资产一律拒（即使已批准为已授信） */
export type PersonalAssetPolicy = 'inherit' | 'strict' | 'deny';

export interface DeviceTrustSetting {
  mode: DeviceTrustMode;
  bindMethod: 'auto' | 'approval';
  staleDays: number;
  /** 单账号设备上限。**只读**：判定写死在原子 SQL 里，前端按它置灰并注明「内置上限」。 */
  perUserQuota: number;
  personalPolicy: PersonalAssetPolicy;
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
  /** 资产分类。管理员标注，白帝不自动识别设备归属（没有 MDM / 资产系统对接）。 */
  assetClass: AssetClass;
  /** 自由标签。**纯台账属性，没有任何执行方**：不参与准入、授权、风险评分。
   *  UI 上必须照实说明——不生效的东西要标明它只是标签。 */
  tags: string[];
}
export interface ApprovalEvent { time: string; kind: 'submit' | 'login' | 'review' | 'notify' | 'risk'; title: string; detail: string }
export interface TrustApproval {
  id: string; user: string; device: string; fingerprint: string; submittedAt: string;
  reason: string; status: 'pending' | 'approved' | 'rejected'; timeline: ApprovalEvent[];
}
export interface DeviceBundle { settings: DeviceTrustSetting; devices: Device[]; approvals: TrustApproval[] }

/* ── 审计中心（store.AuditBundle）── */
/* DiskStat 审计存储水位。★两个百分比是两件事：
   usedPct = 整个文件系统的占用率（谁占的都算）；
   selfPct = **审计库自己**占文件系统的比例（按水位回收的判据）。
   审计页上只画 usedPct 会被读成「审计日志吃了这么多盘」，而它可能只有几 MB。 */
export interface DiskStat { usedPct: number; totalGB: number; retainDays: number; dbBytes: number; selfPct: number }
/** 一条审计记录。★seq/mac 是防篡改链的序号与链式 MAC：列表、CSV 导出、
 *  syslog/SIEM 外送三个出口同源（后端就是同一个 store.AuditEntry）。 */
export interface AuditEntry { time: string; category: 'access' | 'auth' | 'admin' | 'security' | 'dataplane'; user: string; srcIp: string; event: string; verdict: 'allow' | 'deny' | 'mfa' | 'ok' | 'fail'; seq?: number; mac?: string }
/* AuditWriteHealth 控制面**自己**没能把审计写进库的读数（api.auditWriteHealth）。
   ★零失败时后端整段不下发（omitempty），所以 undefined = 一切正常，不是"取不到"。
   它挂在**读**响应上是有意的：审计写不进去的时候读路径通常还活着，
   这一格就是那种状态下唯一还能自曝家丑的地方。 */
export interface AuditWriteHealth {
  failures: number; firstAt?: number; lastAt?: number; lastErr?: string; lastEvent?: string;
}
export interface AuditBundle {
  categories: KV[]; todayTotal: number; disk: DiskStat; logs: AuditEntry[];
  writeHealth?: AuditWriteHealth;
}

/* ── License（GET/POST /api/v1/license）──
 * mode: demo=未导入（容量不限，如实标注）| licensed | expired | invalid。
 * usage 里 -1 = 读不出（不可判定，渲染成 —，绝不当 0）。 */
export interface LicenseInfo {
  mode: 'demo' | 'licensed' | 'expired' | 'invalid';
  reason: string;
  keysConfigured: boolean;
  canImport: boolean;
  boundaries: string[];
  manifest?: { product: string; licensee: string; issuedAt: string; expiresAt: string; maxUsers: number; maxGateways: number };
  usage: { users: number; gateways: number; maxUsers: number; maxGateways: number; overUsers: boolean; overGateways: boolean };
}

/* ── 运营报表（GET /api/v1/audit/report → store.OpsReport）──
 * 全部字段是对 audit_log / alerts 的 SQL 聚合；权限归 audit（聚合并不脱敏）。 */
export interface OpsDay { date: string; authOk: number; authFail: number; accessAllow: number; accessDeny: number; adminOps: number; security: number; total: number }
export interface OpsReport {
  days: number; since: string; truncated: boolean; retainDays: number;
  daily: OpsDay[];
  totals: { entries: number; activeAccounts: number; authOk: number; authFail: number; accessAllow: number; accessDeny: number; adminOps: number; security: number };
  topLogin: KV[]; topDenied: KV[];
  alerts: { total: number; pending: number; bySeverity: KV[] };
}

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
  /** 管理员登记的对外接入地址（PRD FR-SCEN-08/17）。
   *  ★与上面 spa/proxy 那两个**监听地址**是两回事：网关默认监听 ':18201'（不带 host），
   *  无从知道自己在 NAT / 负载均衡后面对外是什么地址。这两栏才是客户端真正会去拨的地址。 */
  lanHost?: string;
  wanHost?: string;
  /** 是否登记过至少一栏。false 时剖面只能拿自报地址或全局兜底去猜，
   *  而猜错的症状是「控制台显示在线、客户端拨号超时」——页面必须显著提示。 */
  accessConfigured?: boolean;
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
  /** 逐台在线网关的**隐身实测回执**（wave8 行动 7）。
   *  ★页面上那四条「端口扫描全程超时 / 攻击面 = 0」此前是写死的，而参考部署根本
   *  不开 -pf——未敲门的 TCP 会先完成三次握手再被用户态断开，nmap 判 open。
   *  现在改成跟随这里的真实态渲染。 */
  stealth: StealthReceipt[];
  /** 内核态隐身**实测生效**的台数（只有 armed 计入；不可判定与未上报都不算）。 */
  stealthArmed: number;
  /** 要顶到页面上的隐身告警。文案由后端下发——这是安全结论，前端自己编就会与
   *  后端实际判定脱节（与 Nat.vue 的 warnings 同一条纪律）。 */
  stealthWarnings: string[];
}

/** StealthReceipt 一台网关的隐身回执。status 六态见后端 api/stealth.go。 */
export interface StealthReceipt {
  gatewayId: string;
  /** unreported | off | orphan-ruleset | no-ruleset | no-drop-rule | port-mismatch | unknown | armed */
  status: string;
  /** wanted = -pf 管理意图，与 status（实测态）分开——一列同时表达"想开"和
   *  "真的开着"正是 ipsec 那段注释批判过的形态。 */
  /** ★可选 = 该网关根本没上报（旧版本）。用 boolean 的话零值会在页面上渲染成
   *  确定结论「-pf 未开启 · 非 root」，与「控制面无从判断」的措辞直接打架。 */
  wanted?: boolean;
  backend: string; root?: boolean;
  proxyAddr: string; guardedPort?: number;
  summary: string; detail?: string;
  /** scannerView **未敲门的攻击者从外部看到什么**——把配置状态翻译成安全后果，
   *  而后者才是 NFR-SEC-01 验收的东西。 */
  scannerView: string;
  at: number;
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
  /** 哪些安全事件真的会发通知（wired=false 的当面说清为什么不发）。
   *  ★不列清单的话，「没收到」与「这类事件根本没接线」在页面上完全同形。 */
  events?: NotifyEventSpec[];
}

/** 一类安全事件通知的元信息（后端 notifyEventSpecs）。 */
export interface NotifyEventSpec {
  event: string; name: string; wired: boolean; signal: string; reason?: string;
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
  /** 账号状态回验的属性映射（wave8 行动 11）。AD 的禁用是 userAccountControl 的位
   *  （内置）；通用 LDAP 协议里没有"禁用"语义，各家用各家的属性——不配这两项的话，
   *  非 AD 部署下回验只剩「条目被删除」一种触发条件。 */
  statusAttr?: string;
  statusDisabledValues?: string[];
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
  /** 是否调 UserInfo 端点补全属性。★关系到准入闸能不能判：域白名单看 email、
   *  组白名单看 groups，而有些 IdP 不把它们放进 ID Token，只在 UserInfo 里给。 */
  useUserInfo?: boolean;
}

/** AdmitConfig 外部身份准入设置（LDAP/AD/OIDC 共用；wave8 行动 10）。
 *  ★两项的判定时机不同：白名单**每次登录都判**（目录侧移出组后下次登录就该被拒），
 *  审批**只判首次建号**（已批过的账号不必天天再批）。 */
export interface AdmitConfig {
  /** auto = 认证通过即建号（改造前的行为）；approval = 首登只登记待批单。 */
  admitPolicy?: 'auto' | 'approval';
  allowedDomains?: string[];
  allowedGroups?: string[];
}

/** ExtAdmission 一条待批的外部身份准入登记。 */
export interface ExtAdmission {
  sourceId: string; sourceName: string; subject: string;
  username: string; displayName: string; email: string; groups: string[];
  status: 'pending' | 'approved' | 'rejected';
  approvalId: string; createdAt: string;
  decidedAt?: string; decidedBy?: string; reason?: string;
}

export interface ProbeResp { ok: boolean; detail: string; elapsedMs?: number }
export interface SaveSourceResp { ok: boolean; source: AuthSourceRec; warning?: string }

/* ── 认证策略 · PC/移动端分栏 + 自适应规则（store.AuthPolicy，FR-INTRO-07/08、FR-AUTH-12）──
 *
 * ★这些开关是**登录链路真读的**（control/internal/authpolicy.Evaluate），不再是纯展示：
 * 命中增强条件且未被豁免 → 登录被要求二次认证。因此界面上任何一个勾都必须是真能生效的，
 * 判不了的规则由后端 capabilities 声明为不可用并在此置灰（不是静默无效）。
 */
/** 可作为「用户目录」出现的取值。★这个类型此前叫 PrimaryMethod、兼作"主认证方式"，
 *  而主认证那一维已摘除（wave8 行动 13-②）；radius/oauth/sms/cert 四个从来没有实现，
 *  留在这里只是因为存量策略的 directory 字段里可能还有它们。 */
export type DirectoryKind = 'local' | 'ad' | 'ldap' | 'oidc' | 'radius' | 'oauth' | 'sms' | 'cert';
export type SecondaryMethod = 'sms' | 'totp' | 'radius' | 'cert' | 'http';
/** 可接受的二次认证方式（AuthPolicy.secondary）。
 *
 *  ★PC / 移动端两栏已合并（wave8 行动 13-②）：三端走**同一个** /portal/login，
 *  请求里没有任何端标识，两栏并排会让人以为「移动端可以配得更严」。
 *  同批摘掉了每栏里的 primary（主认证方式）——策略匹配第一步就按目录筛，
 *  一条策略只作用于已经被该目录认出来的人，对他说"主认证用证书"不可能生效。
 *
 *  **唯一执行语义**：非空时，本策略要求二次认证而账号又没绑任何认证器的情况下，
 *  不接受 legacy 演示验证码回落（回「请先注册」）。它不决定用哪个因子——
 *  那由账号已注册的认证器决定（passkey > TOTP）。 */
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
  id: string; name: string; directory: DirectoryKind | string; isDefault: boolean;
  /** scope 只是文字说明；真正参与匹配的是 scopeOrgs / scopeGroups。 */
  scope: string; priority: number; enabled: boolean;
  secondary: SecondaryMethod[];
  /** 适用范围：组织（含子树）与用户组。非默认策略两者皆空则匹配不到任何账号，后端拒绝保存。 */
  scopeOrgs: string[]; scopeGroups: string[];
  exempt: ExemptRule; enhance: EnhanceRule;
  /** ★这里曾经有 authzApps（"默认授权应用"，自由文本）。已摘除（wave8 行动 13-③）：
   *  它零执行方，而策略卡把空值渲染成「不授权」、种子还预置「默认授权全部应用」——
   *  两者都在暗示这条策略决定了能访问哪些应用。授权的唯一真相是**资源侧的主体清单**
   *  （allowUsers/allowGroups/allowOrgs + JIT 授予），与认证策略无关。 */
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
  /** 该目录当前有几条认证策略。★0 是危险值不是中性值：登录链路按目录筛，
   *  零策略 = 不要求任何二次认证，且那条分支上一条审计都不写。 */
  policies?: number;
  /** 该目录的配置问题（后端下发的原话），空 = 无异常。 */
  warning?: string;
}
/** 二次认证方式的能力声明（后端 authpolicy.SecondaryMethods）：
 *  真实现的（totp）可选；未实现的置灰并给出原因，保存端同源拒绝。 */
export interface AuthMethodCapability {
  key: string; label: string; available: boolean; effect?: string; reason?: string;
}
export interface AuthPolicyResp {
  policies: AuthPolicy[];
  capabilities?: AuthRuleCapability[];
  methods?: AuthMethodCapability[];
  directories?: AuthDirectory[];
  orgs?: SubjectOption[];
  groups?: SubjectOption[];
}

/* ── 安全中心（store.SecurityBundle）── */
export interface BaselineCheck { key: string; label: string; platform: 'Windows' | 'macOS' | 'Linux' | 'All'; expect: string; severity: 'high' | 'medium' | 'low' }
/** 安全基线。
 *
 *  ★`type`（上线准入 / 应用防护）已删：风险引擎 risk.Evaluate 从不读它——两类基线的
 *  检测项、处置、判定路径完全一样，它只是列表上的一个色块。留着就是"看起来有分类、
 *  实际上没有任何行为差异"。
 *
 *  ★`scope` 自由文本已换成 scopeOrgs/scopeGroups **结构化范围**（组织含子树）。
 *  自由文本那栏写着「个人 BYOD 设备」而判定对全体终端生效，是本项目最典型的
 *  「界面上写了、代码里没人读」。两者皆空 = 对全体生效。 */
export interface BaselinePolicy { id: string; name: string; scopeOrgs: string[]; scopeGroups: string[]; disposal: 'allow' | 'degrade' | 'block' | 'gray'; status: 'enabled' | 'disabled'; platforms: string[]; checks: BaselineCheck[] }
/** 只有 baselines。原来还有一段 spa（G3 / 已隐身 / 敲门正常）是纯种子——控制面既不实测
 *  端口可见性、也不代数据面宣布敲门是否正常，整段连同安全中心页那张卡片已删除。
 *  真实出处是「网关与隐身」页：那里每一项都来自网关 mTLS 注册心跳。 */
/** 采集器**真的会上报**的一个检查项。基线检测项的 key 只能取自这份目录——
 *  采集器不报的 key 会让该基线对全平台终端永远判违规（接入准入基线默认处置是 block，
 *  等于一键给所有人拒发敲门令牌）。后端 handleSaveBaseline 与本页下拉读同一份。 */
export interface CheckSpec { key: string; label: string; expect: string; platform: 'Windows' | 'macOS' | 'Linux' | 'All'; note?: string }
export interface SecurityBundle { baselines: BaselinePolicy[]; checkCatalog?: CheckSpec[]; orgs?: SubjectOption[]; groups?: SubjectOption[] }

/* ── 终端 posture（安全中心 · 终端合规） ── */
/** unknown = 终端探不到该项（权限不足/命令缺失），既非合规也非不合规。
 *  上报时 ok 恒 false（对旧控制面 fail-closed），故渲染必须**先看 unknown**。 */
export interface PostureCheckRow { key: string; label: string; ok: boolean; unknown?: boolean; value: string }
export interface PostureRow {
  user: string; device: string; platform: string; os: string; clientVersion: string;
  checks: PostureCheckRow[]; verdict: 'allow' | 'degrade' | 'gray' | 'block';
  score: number; level: 'low' | 'medium' | 'high'; reasons: string[]; ts: number;
}
/** ★带截断标记：清单只读前 limit 条。truncated 时页面**必须**显示「共 N 条，
 *  这里只显示前 M 条」——一份被截断的合规清单被当成全量，管理员会据此判断
 *  「没有不合规终端」。判定面不受这道上限影响（准入闸走独立的 DISTINCT 查询）。 */
export interface PostureResp { reports: PostureRow[]; total?: number; limit?: number; truncated?: boolean }

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
/** 一条真实接入会话。**唯一来源**是网关注册心跳里的 sessions。
 *
 *  ★网关按会话上报的只有 {IP, 账号, 角色, 建立时刻}。此前这里还有
 *  location / device / os / app 四个字段，由后端逐条填 "—"，页面上并排渲染成四列
 *  永远空着的表头；而「异地·公网接入」KPI 与筛选页签因此**结构性恒为 0**。
 *  四个字段连同那个 KPI 已整体删除——白帝没有 GeoIP 库，网关也不按会话上报
 *  设备与当前应用。org / trust / risk 三格改由控制面按账号从库里现取真值。 */
export interface OnlineSession {
  id: string; user: string; account: string; org: string;
  ip: string;
  /** 接入方式（恒为「SPA 敲门 + 隧道」）。**不是**登录因子：那发生在控制面登录时，
   *  与这条隧道会话不同源，网关也无从得知。 */
  auth: string; gateway: string;
  loginAt: string; duration: string;
  /** 该**账号**名下终端的授信态（会话上报里没有设备指纹，定位不到具体哪一台）。
   *  一台都没登记 = unknown，不是 trusted。 */
  trust: 'trusted' | 'untrusted' | 'unknown';
  /** 该账号的终端合规风险档，判据是 posture 跨设备最差判定（与降权/阻断同一份）。
   *  从未上报 = unknown。 */
  risk: 'none' | 'low' | 'high' | 'unknown';
  /** 上面两个结论的依据，页面挂 title。只给结论不给依据，管理员没法判断该不该处置。 */
  trustNote?: string;
  riskNote?: string;
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
/** AuthDomainOption 登录页的认证域下拉项（GET /api/v1/auth/domains，免认证）。
 *  只有 id/name/kind 三样——那个端点是匿名可访问的，多一个字段就是多一分暴露。 */
export interface AuthDomainOption { id: string; name: string; kind: string }

export interface PortalLoginResp {
  ok: boolean;
  needMfa?: boolean;        // legacy 演示验证码路径（未配置 WebAuthn RP 且未注册 TOTP 时回落）
  needWebauthn?: boolean;   // 需 passkey 断言；配合 ticket 走 /webauthn/login/*
  needTotp?: boolean;       // 需 TOTP 动态验证码；配合 ticket 走 /auth/totp
  needEnroll?: boolean;     // 风险账号尚未注册 passkey/TOTP，须先录入
  mustChangePassword?: boolean; // 首登强制改密：token 是 15min 受限令牌，只够调 /auth/password
  ticket?: string;          // 「口令已验」一次性票据（3min），断言两回合凭它绑定账号
  reason?: string;
  token?: string;
  displayName?: string;
  /** needDirectory 配了多个认证域又没指定：前端据此渲染下拉并重试（wave8 行动 12）。
   *  ★不指定时后端**拒绝**而不是挨个去问——挨个问等于把明文口令逐台投递给
   *  每一个排在前面的目录服务器。 */
  needDirectory?: boolean;
  domains?: AuthDomainOption[];
  role?: string;
}

/* ── WebAuthn / passkey（store.WebauthnCredential）── */
export interface WebauthnCredential {
  id: string; userId: string; account: string; credentialId: string;
  signCount: number; transports: string; aaguid: string;
  name: string; createdAt: string; lastUsedAt: string;
}
export interface WebauthnCredentialsResp { credentials: WebauthnCredential[]; enabled: boolean }
/** TOTP 状态（GET /totp）。永不携带密钥材料——密钥只在 enroll 响应里回显一次。 */
export interface TotpStatus { enrolled: boolean; confirmed: boolean; createdAt?: string }
export interface TotpEnrollResp { secret: string; uri: string }
export interface PortalTile {
  id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string;
  sensitivity: 'low' | 'normal' | 'high';
  /** 服务端算出的授权结论：静态 ACL ∪ 组织/用户组展开 ∪ 有效 JIT 授予，减去终端降权否决。
   *  ★与客户端剖面、七层票据同一个判定函数（control 侧 appAccessState）——前端不得再按
   *  sensitivity 之类的字段自己推一遍，那正是这块曾经的缺陷：门户说「需申请」而客户端直接能进。 */
  accessible: boolean; resourceId: string;
  /** 因终端风险降权而不可访问（而非缺授权）。降权否决压过 JIT 授予，此时提交申请必然无效，
   *  用户该做的是修复终端环境——两种"不可访问"的下一步动作完全不同，必须分开提示。 */
  degraded?: boolean;
  /** 该应用**结构上不可用**（未关联受控资源 / 后端不是 host:port）——配置缺口，不是授权结论：
   *  隧道与七层两条路都必然不通，自助申请也会被 JIT 闸以「该应用不支持自助申请」拒掉。
   *  既不能画成「访问」（点了打不开），也不能画成「需申请」（申请是死路），
   *  只能如实告诉用户去找管理员。判据与客户端剖面的丢弃分支同源。 */
  unavailable?: boolean;
  /** 不可用的具体原因，直接渲染给用户看——他要拿这句话去找管理员。 */
  unavailableReason?: string;
  /** 有效 JIT 授予的到期时刻（Unix 秒）；0/缺省 = 不是靠 JIT 拿到的访问权
   *  （静态 ACL / 组织 / 用户组授权没有有效期维度）。 */
  grantExpiresAt?: number;
  /** 此刻能不能提交续期（PRD FR-AUTH-03/04）。★判据由服务端下发，与
   *  store.CreateAccessRequest 的放行条件同源——早于窗口提交必然 409，
   *  前端自己算一遍就会给出一个点了必然失败的按钮。 */
  renewable?: boolean;
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
/** ★同 PostureResp：第 limit+1 条之后的授予在管理台上根本不存在，
 *  而访问审查恰恰是要看「有没有我不知道的授予」。 */
export interface JitGrantsResp { grants: JitGrant[]; total?: number; limit?: number; truncated?: boolean }

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

/** 一台网关的地址转换回执：它现在**真的**在执行这些规则吗。
 *
 *  ★与 policy.enabled（管理意图）是两件事，页面必须分栏呈现。合成一格的话，
 *  「网关没带 -nat 启动」和「规则灌入内核失败」与正常完全同形——而这两种失效
 *  网关侧一行日志都不打，症状只是「发布的业务公网打不开 / 内网上不了网」。
 *  同一条纪律已在 IPSec 上执行过（ipsec_sites.status 废弃、运行态改读 ipsec_sa_state）。 */
export interface NATReceipt {
  gatewayId: string;
  /** unreported=旧网关没报过 · disabled=网关没开 -nat · failed=灌内核失败
   *  · dryrun=只生成不灌 · applied=已生效 */
  status: 'unreported' | 'disabled' | 'failed' | 'dryrun' | 'applied';
  /** 一句话结论，直接渲染（后端保证它给得出下一步动作，前端不自行编写）。 */
  say: string;
  online: boolean;
  backend?: string;
  applied: number;
  /** 内核 IP 转发。★三态：缺席=读不到（不是「关着」）。转发关着时规则全部正确
   *  但一个包都过不去，且没有任何报错。 */
  forwarding?: boolean;
  lastError?: string;
  lastAt?: number;
  at?: number;
}
/** 一条规则的命中计数（FR-NAT-17）。 */
export interface NATHit { policyId: string; packets: number; bytes: number }

export interface NATBundle {
  policies: NATPolicy[];
  ifaces: GatewayIface[];
  /** 后端下发的风险提示（SPA 互斥 / 回程路由 / 带宽 + 回执侧「配了却不会生效」）。
   *  PRD 把它列为强需求，前端不得自行编写。 */
  warnings: string[];
  /** 逐网关回执，key=gatewayId。只含本页策略真的落在其上的网关。 */
  receipts?: Record<string, NATReceipt>;
  /** 逐策略命中计数，key=policyId。 */
  hits?: Record<string, NATHit>;
  /** 有没有任何一台网关报得出计数。★false 时必须显示「不可判定」而不是 0——
   *  「规则没灌进去」与「灌进去了但没流量命中」排障方向完全相反。 */
  hitsKnown?: boolean;
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
  /** 每条灰度计划**精确**命中的账号数（key = platform）。缺席 = 读取失败，
   *  与 0 是两回事：把读失败画成「0 人」会让管理员以为这条灰度谁也没命中，进而调高比例。 */
  coverage?: Record<string, number>;
  /** 参与分桶的账号总数（覆盖数的分母）。 */
  total?: number;
  /** 现场终端的**实际**版本分布（posture 上报）。灰度只决定"告诉谁有新版"，
   *  不决定任何人实际装了什么——放开比例前要看的是这一份。 */
  versions?: { platform: string; version: string; count: number }[];
  /** 用户组候选（灰度定向用，与资源授权/认证策略共用同一处展开）。 */
  groups?: SubjectOption[];
  /** 后端下发的边界声明：哪些做了、哪些刻意不做。前端不得自行编写或省略。 */
  boundaries: string[];
}
/** 升级包校验结论（POST /upgrade/check）。blocked 时 UI 必须禁用升级并显示 reasons。 */
export interface UpgradeCheckResult {
  blocked: boolean; reasons?: string[]; warnings?: string[];
  nextHop?: string; manifest?: { version: string; component: string; notes?: string };
}

/* ── 终端设备台账批量出入口（wave7 行动 14）──────────────────────────────
 *
 * GET  /api/v1/devices/export  → CSV 附件（流式，全列过公式注入中和）
 * POST /api/v1/devices/import  → 正文是 CSV 文本，回执逐行可见
 *
 * ★导入是**预登记**，不是"把设备弄成能连"：它只写设备台账（trusted_devices），
 * 不产生终端环境报告（posture_reports）。设备准入闸与终端合规闸各判各的，
 * 所以在 BAIDI_POSTURE_ENFORCE=strict 下，预登记为已授信的终端**仍然连不进来**，
 * 直到它用客户端真的上报过一次环境。这句话由后端随回执下发（note/postureEnforce），
 * 前端必须原样展示——不说的话，这就是又一个「配置齐全却连不上」。
 */

/** 一行成功预登记的设备。line 是 CSV 文件里的行号（含表头那一行）。 */
export interface DeviceImportOK {
  line: number; account: string; fingerprint: string; name: string; status: DeviceStatus;
  /** 落库后的**实际值**（分类留空按企业资产、标签已去重截断）——不是 CSV 里的原文。 */
  assetClass: AssetClass; tags: string[];
}
/** 一行被跳过的记录。reason 是后端原话——它常常是唯一能指导下一步动作的信息，不要改写。 */
export interface DeviceImportSkip {
  line: number; account?: string; fingerprint?: string; reason: string;
}
export interface DeviceImportResult {
  ok: boolean;
  imported: DeviceImportOK[];
  skipped: DeviceImportSkip[];
  /** 其中直接置为「已授信」的台数（= 本次真正发出的准入授予数）。 */
  trusted: number;
  /** 控制面当前的 BAIDI_POSTURE_ENFORCE 取值。strict 时预登记不足以让终端连上。 */
  postureEnforce: 'observe' | 'strict';
  /** 本批标为个人资产的台数，与当前生效的个人资产策略。★与 postureEnforce 同一条理由：
   *  在 deny 下，一行「个人资产 + 已授信」导进去照样连不上——不说的话又是一个
   *  「台账是绿的、就是连不上」。策略读不到时后端回空串，前端不渲染这一段。 */
  personal: number;
  personalPolicy: PersonalAssetPolicy | '';
  /** 预登记与终端合规闸的交互说明（后端 api.deviceImportPostureNote，同一份文本）。 */
  note: string;
}
