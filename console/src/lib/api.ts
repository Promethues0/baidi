/** 白帝控制台 · HTTP 客户端。管理 API 经 vite /api 反代到自有后端 baidi-control(:8090)。 */
const BASE = '/api/v1';
const TOKEN_KEY = 'baidi_token';

export function getToken(): string { return localStorage.getItem(TOKEN_KEY) || ''; }
export function setToken(t: string): void { localStorage.setItem(TOKEN_KEY, t); }
export function clearToken(): void { localStorage.removeItem(TOKEN_KEY); }

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const t = getToken();
  const res = await fetch(BASE + path, {
    headers: {
      Accept: 'application/json',
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
      ...(init?.headers ?? {})
    },
    ...init
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

/* ── 资源策略 + 在线网关（数据面，control 托管、网关动态拉取） ── */
export interface Resource { id: string; name: string; backend: string; allowRoles: string[]; allowUsers: string[]; addrRef?: string; svcRef?: string }
export interface ResourcesResp { resources: Resource[] }
export interface GatewayReg { id: string; proxy: string; spa: string; lastSeen: number }
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
export interface OnlineResp { sessions: OnlineSession[]; generatedAt: string }

/* ── 监控中心 · 用户状态（store.UserStateBundle）── */
export interface UserStateBucket { key: string; label: string; count: number; tone: 'danger' | 'warning' | 'info' | 'normal' }
export interface UserStateItem {
  id: string; user: string; account: string; org: string;
  state: 'risk-high' | 'risk-low' | 'locked' | 'disabled' | 'idle';
  risk: 'none' | 'low' | 'high'; online: boolean;
  reasons: string[]; lastEvent: string; lastSeen: string;
}
export interface UserStateBundle { buckets: UserStateBucket[]; items: UserStateItem[] }

/* ── IPSec VPN 组网（store.IpsecSite）── */
export interface IpsecPhase { enc: string; hash: string; dh: string }
export interface IpsecSite {
  id: string; name: string; peer: string; localSubnet: string; remoteSubnet: string;
  ikeVersion: string; auth: 'psk' | 'cert' | 'sm2cert'; suite: 'standard' | 'gm';
  phase1: IpsecPhase; phase2: IpsecPhase; pfs: boolean; pqHybrid: boolean;
  status: 'up' | 'down' | 'connecting'; rxBytes: number; txBytes: number; lastUp: string;
  localRef?: string; remoteRef?: string; // 本端/对端网段引用的地址对象 id（对象库复用）
}
export interface IpsecResp { sites: IpsecSite[] }

/* ── 对象库（store.ObjectBundle）── */
export interface AddrObject { id: string; name: string; kind: 'ip' | 'cidr' | 'range' | 'domain'; value: string; desc: string }
export interface ServiceObject { id: string; name: string; proto: 'tcp' | 'udp' | 'icmp' | 'any'; ports: string; desc: string }
export interface TimeObject { id: string; name: string; kind: 'periodic' | 'absolute'; spec: string; desc: string }
export interface ObjectBundle { addrs: AddrObject[]; services: ServiceObject[]; times: TimeObject[] }

/* ── 对象库「被引用」反查（复用闭环，store.ObjectRef）── */
export interface ObjectRef { kind: 'resource' | 'ipsec'; id: string; name: string }
export interface ObjectUsageResp { usage: Record<string, ObjectRef[]> }

/* ── 终端用户门户 ── */
export interface PortalLoginResp { ok: boolean; needMfa?: boolean; reason?: string; token?: string; displayName?: string }
export interface PortalTile { id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string; sensitivity: 'normal' | 'high'; accessible: boolean }
export interface PortalAppsResp { apps: PortalTile[] }

/* ── 运维诊断（store/api.DiagBundle，控制面真实自检）── */
export type DiagStatus = 'pass' | 'warn' | 'fail';
export type DiagCategory = 'control' | 'storage' | 'dataplane' | 'stealth' | 'cluster' | 'identity' | 'posture' | 'security';
export interface DiagCheck {
  key: string; category: DiagCategory; name: string;
  status: DiagStatus; summary: string; metric: string; hint: string;
}
export interface DiagBundle {
  generatedAt: string; component: string; version: string; env: string; uptime: string;
  score: number; pass: number; warn: number; fail: number;
  checks: DiagCheck[];
}
