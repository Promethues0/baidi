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

/* ── 安全中心（store.SecurityBundle）── */
export interface BaselineCheck { key: string; label: string; platform: 'Windows' | 'macOS' | 'Linux' | 'All'; expect: string; severity: 'high' | 'medium' | 'low' }
export interface BaselinePolicy { id: string; name: string; type: 'app-protect' | 'onboarding'; scope: string; disposal: 'allow' | 'degrade' | 'block' | 'gray'; status: 'enabled' | 'disabled'; platforms: string[]; checks: BaselineCheck[] }
export interface SecurityBundle { baselines: BaselinePolicy[]; spa: SpaStatus }

/* ── 终端用户门户 ── */
export interface PortalLoginResp { ok: boolean; needMfa?: boolean; reason?: string; token?: string; displayName?: string }
export interface PortalTile { id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string; sensitivity: 'normal' | 'high'; accessible: boolean }
export interface PortalAppsResp { apps: PortalTile[] }
