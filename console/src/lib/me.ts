/**
 * 白帝控制台 · **当前管理员身份**（唯一来源 GET /api/v1/auth/me）。
 *
 * ★背景：这里此前**没有任何东西**——顶栏那块 `<b>安全管理员</b><i>security-admin</i>`
 * 是两句写死的中文。种子 admin 的显示名恰好就叫"安全管理员"，于是它在演示环境里
 * 看起来完全正确；而那个账号的**角色是超管**，换成审计管理员登录顶栏也一字不改。
 * 与写死角标 '10' / '2' 是同一族假数据，只是它伪装成的是**身份**——
 * 一个天天挂在每一页右上角、没人会去怀疑的身份。
 *
 * 三条纪律（与 badges.ts 同源）：
 *  1. 值只来自真实接口；
 *  2. **取不到就说不知道，不回落到任何编造值**；
 *  3. 「不可判定」与「确定无权」必须分得开——见 permKnown。
 */
import { computed, reactive, readonly } from 'vue';
import { api, getToken } from '@/lib/api';
import type { AdminPerm } from '@/lib/api';

/** /auth/me 的应答。adminRole **缺席 = 不可判定**（不是"无权限"）。 */
export interface MeResp {
  sub: string;
  role: 'admin' | 'user' | string;
  name: string;
  exp: number;
  /** 库里的显示名（令牌里的 name 是账号）。取不到时缺席，页面回落显示账号。 */
  displayName?: string;
  /** 现算的管理员角色。只有完整会话令牌才会下发（受限改密令牌拿不到）。 */
  adminRole?: {
    key: string; name: string; power: string;
    perms: AdminPerm[]; scope: string; builtin: boolean;
  };
}

interface MeState {
  /** 已成功拉到过身份。false 时页面一律按"不可判定"渲染。 */
  loaded: boolean;
  sub: string;
  displayName: string;
  roleKey: string;
  roleName: string;
  power: string;
  scope: string;
  /** 权限键集合。**只有 permKnown 为真时它才有判定意义**。 */
  perms: AdminPerm[];
  /**
   * 角色与权限是否**判得出来**。
   *
   * ★这是本文件里最要紧的一个布尔量。adminRole 缺席有两种成因：受限改密令牌、
   * 或者后端根本没升级（旧控制面的 /auth/me 只回 sub/role/name/exp）。两种情况下
   * 「这个人有哪些权限」都是**不知道**，而不是"没有权限"。
   * 把不知道当成没有权限，会让接旧后端的控制台把所有写操作一起灰掉——
   * 一个能用的系统看起来像是全员被降权了，且页面上找不出原因。
   * 所以：permKnown=false 时**不收敛任何东西**，真闸本来就在后端（requirePerm）。
   */
  permKnown: boolean;
}

const state = reactive<MeState>({
  loaded: false, sub: '', displayName: '', roleKey: '', roleName: '',
  power: '', scope: '', perms: [], permKnown: false
});

export const me = readonly(state);

/** 顶栏头像里的那个字：显示名/账号的首个字符，取不到用「管」。 */
export const avatarChar = computed(() => (state.displayName || state.sub || '管').trim().charAt(0) || '管');

/** 顶栏主行：显示名（没有就回落账号）。 */
export const meTitle = computed(() => state.displayName || state.sub || '未登录');

/**
 * 顶栏副行：**账号 · 角色名**。
 * ★这里刻意同时显示账号与角色：只显示角色的话，两个不同的超管在页面上无从区分
 * （而审计要查的正是"是谁做的"）；只显示账号的话，三权分立在界面上完全不可见。
 * 角色判不出来时写「角色未知」——不写死成任何一个角色名。
 */
export const meSubtitle = computed(() => {
  if (!state.loaded) return '身份加载中…';
  const role = state.permKnown ? state.roleName : '角色未知';
  return `${state.sub} · ${role}`;
});

/**
 * 是否持有某权限键。
 *
 * ★**判不出来时一律回 true**（fail-open），方向与后端相反且是有意的：
 * 这里的判定只用来决定"要不要把按钮灰掉"，权威闸始终是后端 requirePerm。
 * 两个方向的错法后果完全不对称——
 *   多显示一个按钮：点下去拿到一句「角色「审计管理员」无权执行该操作（需要权限：security）」，
 *   少显示一个按钮：管理员明明有权，却在界面上找不到入口，且**没有任何报错可查**。
 * 后者正是本项目反复在修的那类静默失效。
 */
export function can(perm?: AdminPerm | null): boolean {
  if (!perm) return true;
  if (!state.permKnown) return true;
  return state.perms.includes('*') || state.perms.includes(perm);
}

/** 权限键的中文名（与 System 页「三权分立」卡片同一套叫法）。 */
export const PERM_ZH: Record<string, string> = {
  '*': '全部权限', system: '系统配置', security: '安全策略', audit: '审计日志', admins: '管理员管理'
};

/** 拉一次身份。失败时**清空**已有身份——宁可显示"不可判定"，也不让上一次的旧角色继续冒充现值。 */
export async function refreshMe(): Promise<void> {
  if (!getToken()) { resetMe(); return; }
  try {
    const r = await api<MeResp>('/auth/me');
    state.sub = r.sub || '';
    state.displayName = r.displayName || '';
    state.loaded = true;
    if (r.adminRole) {
      state.roleKey = r.adminRole.key;
      state.roleName = r.adminRole.name;
      state.power = r.adminRole.power;
      state.scope = r.adminRole.scope || '';
      state.perms = r.adminRole.perms || [];
      state.permKnown = true;
    } else {
      state.roleKey = ''; state.roleName = ''; state.power = ''; state.scope = '';
      state.perms = []; state.permKnown = false;
    }
  } catch {
    resetMe();
  }
}

export function resetMe(): void {
  state.loaded = false; state.sub = ''; state.displayName = '';
  state.roleKey = ''; state.roleName = ''; state.power = ''; state.scope = '';
  state.perms = []; state.permKnown = false;
}
