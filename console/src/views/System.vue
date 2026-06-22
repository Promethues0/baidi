<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">系统管理</div>
        <div class="bd-page__sub">三权分立 · 分级分权 · 集群高可用</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'admin' }" @click="tab = 'admin'">管理员与三权分立</span>
      <span class="bd-tab" :class="{ on: tab === 'cluster' }" @click="tab = 'cluster'">集群拓扑</span>
    </div>

    <!-- ============ 管理员与三权分立 ============ -->
    <div v-show="tab === 'admin'">
      <!-- ① 管理组卡片行 -->
      <div class="bd-section-title">管理组 · 三权分立</div>
      <div class="bd-sep__note">
        <icon-safe />
        <span><b>系统 / 安全 / 审计</b> 三组互不越权：系统管理员管配置不碰策略与日志，安全管理员定策略不留审计，审计管理员只读全量日志且不可被其余角色清除；上级角色对下级仅作收缩授权，不能反向提权。</span>
      </div>
      <div class="bd-groups">
        <div
          v-for="g in adminGroups"
          :key="g.key"
          class="bd-card bd-gcard"
          :style="{ '--pc': powerColor(g.power) }"
        >
          <span class="bd-gcard__bar" />
          <div class="bd-gcard__top">
            <span class="bd-gcard__dot" />
            <span class="bd-gcard__name">{{ g.name }}</span>
            <a-tag v-if="g.builtin" size="small" :style="tagStyle(powerColor(g.power))">内置</a-tag>
            <a-tag v-else size="small" :style="tagStyle('#86909C')">自定义</a-tag>
          </div>
          <div class="bd-gcard__meta">
            <span class="bd-gcard__power" :style="{ color: powerColor(g.power) }">{{ powerText(g.power) }}</span>
            <span class="bd-gcard__members"><b>{{ g.members }}</b> 人</span>
          </div>
          <div class="bd-gcard__scope">{{ g.scope }}</div>
        </div>
      </div>

      <!-- ② 管理员账号表 -->
      <div class="bd-section-title" style="margin-top: 26px">管理员账号</div>
      <div class="bd-tablecard">
        <div class="bd-toolbar">
          <div class="bd-searchbox" style="flex: 1; max-width: 280px">
            <icon-search />
            <input v-model="kw" placeholder="搜索账号 / 姓名" />
          </div>
          <div style="margin-left: auto; display: flex; gap: 10px">
            <button class="bd-btn bd-btn--ghost" @click="reload"><icon-refresh />刷新</button>
            <button class="bd-btn" @click="addAdmin"><icon-plus />新建管理员</button>
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>账号</th>
              <th>所属组</th>
              <th>认证方式</th>
              <th>二次认证</th>
              <th>最后登录</th>
              <th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in filteredAdmins" :key="a.account">
              <td>
                <div class="bd-cellname">
                  <span class="bd-avatar" :style="{ background: avatarBg(a.name) }">{{ a.name.slice(0, 1) }}</span>
                  <span>
                    <b>{{ a.name }}</b>
                    <i class="bd-mono">{{ a.account }}</i>
                  </span>
                </div>
              </td>
              <td>
                <span class="bd-st">
                  <span class="d" :style="{ background: powerColor(groupPower(a.group)) }" />{{ a.group }}
                </span>
              </td>
              <td>{{ a.auth }}</td>
              <td>
                <span v-if="a.twoFa" class="bd-tg" :style="tagStyle('#00B42A')">已开启</span>
                <span v-else class="bd-tg" :style="tagStyle('#86909C')">未开启</span>
              </td>
              <td class="bd-mono">{{ a.lastLogin }}</td>
              <td class="r">
                <span class="bd-link" @click="editAdmin(a)">编辑</span>
                <span class="bd-link bd-link--danger" style="margin-left: 14px" @click="disableAdmin(a)">禁用</span>
              </td>
            </tr>
          </tbody>
        </table>
        <div class="bd-pager">共 {{ filteredAdmins.length }} 名管理员 · 三权分立强制启用，单组不可独大</div>
      </div>
    </div>

    <!-- ============ 集群拓扑（P8 SVG）============ -->
    <div v-show="tab === 'cluster'" class="bd-clusters">
      <!-- ① 本地集群 HA -->
      <div class="bd-card bd-topo">
        <div class="bd-topo__h">
          <span class="bd-topo__t">本地集群 · 双机热备（HA）</span>
          <span class="bd-topo__sub">主备实时心跳同步，VIP 漂移，主节点故障秒级切换</span>
        </div>
        <svg viewBox="0 0 720 280" width="100%" preserveAspectRatio="xMidYMid meet" font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
          <!-- VIP -->
          <g>
            <rect x="296" y="18" width="128" height="44" rx="10" fill="#F2F7FF" stroke="#BEDAFF" />
            <text x="360" y="38" font-size="13" font-weight="600" fill="#1D2129" text-anchor="middle">虚拟 IP（VIP）</text>
            <text x="360" y="55" font-size="11" fill="#86909C" text-anchor="middle" font-family="ui-monospace, monospace">{{ vip }}</text>
          </g>
          <!-- VIP 漂移连线（指向主） -->
          <path d="M340 62 C 300 92, 240 96, 196 132" fill="none" stroke="#165DFF" stroke-width="2" />
          <path d="M380 62 C 420 92, 480 96, 524 132" fill="none" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4" />
          <text x="218" y="104" font-size="11" fill="#165DFF">VIP 当前指向</text>
          <text x="470" y="104" font-size="11" fill="#86909C" text-anchor="end">备用待命</text>

          <!-- 主备节点 -->
          <template v-for="(n, i) in cluster.localNodes" :key="n.name">
            <g>
              <rect :x="localX(i)" y="132" width="172" height="106" rx="12" fill="#FFFFFF" :stroke="strokeColor(n.status)" stroke-width="1.5" />
              <text :x="localX(i) + 16" y="160" font-size="14" font-weight="600" fill="#1D2129">{{ n.name }}</text>
              <rect :x="localX(i) + 116" y="146" width="44" height="20" rx="10" :fill="powerColor(n.role) + '1A'" />
              <text :x="localX(i) + 138" y="160" font-size="11" font-weight="600" :fill="powerColor(n.role)" text-anchor="middle">{{ roleText(n.role) }}</text>
              <text :x="localX(i) + 16" y="184" font-size="12" fill="#86909C" font-family="ui-monospace, monospace">{{ n.ip }}</text>
              <line :x1="localX(i) + 16" y1="200" :x2="localX(i) + 156" y2="200" stroke="#F2F3F5" stroke-width="1" />
              <circle :cx="localX(i) + 22" cy="220" r="4.5" :fill="strokeColor(n.status)" />
              <text :x="localX(i) + 34" y="224" font-size="12" :fill="strokeColor(n.status)" font-weight="600">{{ statusText(n.status) }}</text>
            </g>
          </template>

          <!-- 心跳同步双向连线 -->
          <g>
            <path d="M212 175 L 508 175" fill="none" stroke="#00B42A" stroke-width="2" stroke-dasharray="6 5" marker-start="url(#arrowL)" marker-end="url(#arrowR)" />
            <rect x="312" y="162" width="96" height="26" rx="13" fill="#E8FFEA" />
            <text x="360" y="179" font-size="11" font-weight="600" fill="#0B8235" text-anchor="middle">心跳同步</text>
          </g>

          <defs>
            <marker id="arrowR" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="#00B42A" />
            </marker>
            <marker id="arrowL" markerWidth="8" markerHeight="8" refX="2" refY="4" orient="auto">
              <path d="M8,0 L0,4 L8,8 Z" fill="#00B42A" />
            </marker>
          </defs>

          <!-- 图例 -->
          <g transform="translate(16, 262)">
            <text x="0" y="0" font-size="11" font-weight="600" fill="#4E5969">图例</text>
            <line x1="42" y1="-4" x2="70" y2="-4" stroke="#165DFF" stroke-width="2" />
            <text x="78" y="0" font-size="11" fill="#86909C">VIP 指向</text>
            <line x1="148" y1="-4" x2="176" y2="-4" stroke="#00B42A" stroke-width="2" stroke-dasharray="6 5" />
            <text x="184" y="0" font-size="11" fill="#86909C">心跳同步</text>
            <circle cx="262" cy="-4" r="4.5" fill="#00B42A" /><text x="272" y="0" font-size="11" fill="#86909C">主用</text>
            <circle cx="316" cy="-4" r="4.5" fill="#86909C" /><text x="326" y="0" font-size="11" fill="#86909C">备用待命</text>
          </g>
        </svg>
      </div>

      <!-- ② 分布式集群 -->
      <div class="bd-card bd-topo">
        <div class="bd-topo__h">
          <span class="bd-topo__t">分布式集群 · 中心—分支</span>
          <span class="bd-topo__sub">中心单元统一控制下发，分支单元就近接入并回传数据同步</span>
        </div>
        <svg viewBox="0 0 720 300" width="100%" preserveAspectRatio="xMidYMid meet" font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
          <!-- 中心单元 -->
          <template v-for="c in centerNodes" :key="c.name">
            <g>
              <rect x="276" y="20" width="168" height="100" rx="12" fill="#F2F7FF" :stroke="strokeColor(c.status)" stroke-width="1.5" />
              <text x="360" y="48" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">{{ c.name }}</text>
              <rect x="316" y="58" width="88" height="20" rx="10" :fill="powerColor(c.role) + '1A'" />
              <text x="360" y="72" font-size="11" font-weight="600" :fill="powerColor(c.role)" text-anchor="middle">{{ roleText(c.role) }}</text>
              <text x="360" y="96" font-size="12" fill="#86909C" text-anchor="middle" font-family="ui-monospace, monospace">{{ c.ip }}</text>
              <circle cx="312" cy="110" r="4.5" :fill="strokeColor(c.status)" />
              <text x="324" y="114" font-size="12" :fill="strokeColor(c.status)" font-weight="600">{{ statusText(c.status) }}</text>
            </g>
          </template>

          <!-- 中心 → 分支 虚线（控制下发 / 数据同步） -->
          <template v-for="(b, i) in branchNodes" :key="'l-' + b.name">
            <path
              :d="`M360 120 C 360 160, ${branchX(i) + 86} 150, ${branchX(i) + 86} 200`"
              fill="none" :stroke="strokeColor(b.status)" stroke-width="1.5" stroke-dasharray="5 4"
            />
          </template>
          <text x="360" y="170" font-size="11" fill="#86909C" text-anchor="middle">控制下发 / 数据同步（虚线）</text>

          <!-- 分支单元 -->
          <template v-for="(b, i) in branchNodes" :key="b.name">
            <g>
              <rect :x="branchX(i)" y="200" width="172" height="88" rx="12" fill="#FFFFFF" :stroke="strokeColor(b.status)" stroke-width="1.5" />
              <text :x="branchX(i) + 16" y="226" font-size="13" font-weight="600" fill="#1D2129">{{ b.name }}</text>
              <rect :x="branchX(i) + 120" y="212" width="40" height="20" rx="10" :fill="powerColor(b.role) + '1A'" />
              <text :x="branchX(i) + 140" y="226" font-size="11" font-weight="600" :fill="powerColor(b.role)" text-anchor="middle">{{ roleText(b.role) }}</text>
              <text :x="branchX(i) + 16" y="248" font-size="11" fill="#86909C" font-family="ui-monospace, monospace">{{ b.ip }}</text>
              <circle :cx="branchX(i) + 22" cy="268" r="4.5" :fill="strokeColor(b.status)" />
              <text :x="branchX(i) + 34" y="272" font-size="12" :fill="strokeColor(b.status)" font-weight="600">{{ statusText(b.status) }}</text>
            </g>
          </template>

          <!-- 图例 -->
          <g transform="translate(16, 294)">
            <text x="0" y="0" font-size="11" font-weight="600" fill="#4E5969">图例</text>
            <circle cx="46" cy="-4" r="4.5" fill="#00B42A" /><text x="56" y="0" font-size="11" fill="#86909C">正常</text>
            <circle cx="100" cy="-4" r="4.5" fill="#FF7D00" /><text x="110" y="0" font-size="11" fill="#86909C">降级</text>
            <circle cx="154" cy="-4" r="4.5" fill="#F53F3F" /><text x="164" y="0" font-size="11" fill="#86909C">故障</text>
            <line x1="208" y1="-4" x2="236" y2="-4" stroke="#86909C" stroke-width="1.5" stroke-dasharray="5 4" />
            <text x="244" y="0" font-size="11" fill="#86909C">控制 / 同步链路</text>
          </g>
        </svg>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type SystemBundle, type AdminGroup, type AdminAccount, type ClusterInfo, type ClusterNode } from '@/lib/api';

const tab = ref<'admin' | 'cluster'>('admin');
const live = ref(false);
const kw = ref('');
const vip = ref('10.0.0.250');

/* ── 内置 mock（结构同后端 SystemBundle）── */
const MOCK_GROUPS: AdminGroup[] = [
  { key: 'root', name: '根管理员', power: 'root', builtin: true, members: 1, scope: '系统初始化与超级权限，仅用于创建三权角色，日常禁用' },
  { key: 'system', name: '系统管理员', power: 'system', builtin: true, members: 3, scope: '网关 / 节点 / 集群 / 系统配置，不触策略与日志' },
  { key: 'security', name: '安全管理员', power: 'security', builtin: true, members: 2, scope: '认证 / 访问 / 基线策略制定下发，不留审计、不改配置' },
  { key: 'audit', name: '审计管理员', power: 'audit', builtin: true, members: 2, scope: '全量日志只读与导出，监督其余角色，不可被清除' },
  { key: 'ops-east', name: '华东运维组', power: 'custom', builtin: false, members: 5, scope: '自定义：仅华东大区节点只读 + 告警处置，授权由系统组收缩' }
];
const MOCK_ADMINS: AdminAccount[] = [
  { name: '张承宇', account: 'root', group: '根管理员', auth: '本地口令 + UKey', twoFa: true, lastLogin: '2024-05-30 02:11' },
  { name: '李恒', account: 'sys.lihen', group: '系统管理员', auth: '本地口令 + TOTP', twoFa: true, lastLogin: '2024-06-22 09:04' },
  { name: '王沐', account: 'sys.wangmu', group: '系统管理员', auth: 'AD 域账号', twoFa: false, lastLogin: '2024-06-21 18:32' },
  { name: '陈砚', account: 'sec.chenyan', group: '安全管理员', auth: '本地口令 + TOTP', twoFa: true, lastLogin: '2024-06-22 08:47' },
  { name: '赵岚', account: 'sec.zhaolan', group: '安全管理员', auth: '本地口令 + UKey', twoFa: true, lastLogin: '2024-06-20 15:09' },
  { name: '周霁', account: 'aud.zhouji', group: '审计管理员', auth: '本地口令 + TOTP', twoFa: true, lastLogin: '2024-06-22 07:55' },
  { name: '吴桐', account: 'aud.wutong', group: '审计管理员', auth: '本地口令', twoFa: false, lastLogin: '2024-06-19 11:20' },
  { name: '孙岐', account: 'ops.sunqi', group: '华东运维组', auth: 'LDAP 账号', twoFa: false, lastLogin: '2024-06-21 22:48' }
];
const MOCK_CLUSTER: ClusterInfo = {
  localNodes: [
    { name: 'ctl-master', ip: '10.0.0.11', role: 'master', status: 'healthy' },
    { name: 'ctl-backup', ip: '10.0.0.12', role: 'backup', status: 'standby' }
  ],
  distNodes: [
    { name: '总部中心单元', ip: '10.0.0.1', role: 'center', status: 'healthy' },
    { name: '华东分支单元', ip: '10.20.0.1', role: 'branch', status: 'healthy' },
    { name: '华南分支单元', ip: '10.30.0.1', role: 'branch', status: 'degraded' }
  ]
};

const adminGroups = ref<AdminGroup[]>(MOCK_GROUPS);
const admins = ref<AdminAccount[]>(MOCK_ADMINS);
const cluster = ref<ClusterInfo>(MOCK_CLUSTER);

const filteredAdmins = computed(() => {
  const q = kw.value.trim().toLowerCase();
  if (!q) return admins.value;
  return admins.value.filter((a) => a.name.toLowerCase().includes(q) || a.account.toLowerCase().includes(q));
});

const centerNodes = computed(() => cluster.value.distNodes.filter((n) => n.role === 'center'));
const branchNodes = computed(() => cluster.value.distNodes.filter((n) => n.role === 'branch'));

/* ── SVG 布局辅助 ── */
function localX(i: number) { return i === 0 ? 40 : 508; }
function branchX(i: number) {
  const n = branchNodes.value.length;
  const total = n * 172 + (n - 1) * 28;
  const start = (720 - total) / 2;
  return start + i * (172 + 28);
}

/* ── 颜色 / 文案 ── */
function powerColor(power: string) {
  switch (power) {
    case 'system': case 'master': case 'center': return '#165DFF';
    case 'security': return '#F53F3F';
    case 'audit': return '#00B42A';
    case 'custom': return '#722ED1';
    case 'branch': return '#722ED1';
    default: return '#86909C'; // root / backup
  }
}
function powerText(power: string) {
  switch (power) {
    case 'root': return '超级权限 · 日常禁用';
    case 'system': return '系统配置权';
    case 'security': return '策略制定权';
    case 'audit': return '审计监督权';
    default: return '自定义收缩权';
  }
}
function roleText(role: string) {
  switch (role) {
    case 'master': return '主';
    case 'backup': return '备';
    case 'center': return '中心单元';
    case 'branch': return '分支';
    default: return role;
  }
}
function groupPower(group: string): string {
  return adminGroups.value.find((g) => g.name === group)?.power ?? 'custom';
}
function strokeColor(status: string) {
  return status === 'healthy'
    ? '#00B42A'
    : status === 'degraded'
      ? '#FF7D00'
      : status === 'down'
        ? '#F53F3F'
        : '#86909C'; // standby / 其它
}
function statusText(status: string) {
  switch (status) {
    case 'healthy': return '健康';
    case 'standby': return '备用待命';
    case 'degraded': return '降级';
    case 'down': return '故障';
    default: return status;
  }
}
function tagStyle(color: string) { return { color, background: color + '14', border: 'none' }; }
function avatarBg(name: string) {
  const palette = ['#165DFF', '#722ED1', '#00B42A', '#FF7D00', '#F53F3F'];
  let h = 0;
  for (const ch of name) h = (h + ch.charCodeAt(0)) % palette.length;
  return palette[h];
}

/* ── 操作（演示）── */
function addAdmin() { Message.info('新建管理员：需指定三权角色之一，超级权限不可直接分配'); }
function editAdmin(a: AdminAccount) { Message.info(`编辑管理员「${a.name}」`); }
function disableAdmin(a: AdminAccount) {
  if (a.group === '审计管理员') { Message.warning('审计管理员受保护，禁用需双人复核'); return; }
  Message.success(`已禁用「${a.name}」`);
}
async function reload() {
  try {
    const b = await api<SystemBundle>('/system');
    adminGroups.value = b.adminGroups; admins.value = b.admins; cluster.value = b.cluster; live.value = true;
    Message.success('已刷新');
  } catch { live.value = false; Message.error('刷新失败，仍为降级演示数据'); }
}

onMounted(async () => {
  try {
    const b = await api<SystemBundle>('/system');
    adminGroups.value = b.adminGroups; admins.value = b.admins; cluster.value = b.cluster; live.value = true;
  } catch { live.value = false; }
});
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }

/* 三权分立说明条 */
.bd-sep__note {
  display: flex; align-items: flex-start; gap: 9px; margin-bottom: 16px;
  background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: var(--bd-radius);
  padding: 12px 14px; font-size: 12.5px; line-height: 1.7; color: var(--bd-t2);
}
.bd-sep__note :deep(svg) { color: var(--bd-primary); font-size: 16px; flex: none; margin-top: 2px; }
.bd-sep__note b { color: var(--bd-t1); font-weight: 600; }

/* 管理组卡片行 */
.bd-groups { display: grid; grid-template-columns: repeat(auto-fill, minmax(218px, 1fr)); gap: 14px; }
.bd-gcard { position: relative; padding: 16px 16px 16px 20px; overflow: hidden; }
.bd-gcard__bar { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--pc); }
.bd-gcard__top { display: flex; align-items: center; gap: 8px; }
.bd-gcard__dot { width: 9px; height: 9px; border-radius: 50%; background: var(--pc); flex: none; }
.bd-gcard__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-gcard__meta { display: flex; align-items: center; gap: 10px; margin: 12px 0 8px; }
.bd-gcard__power { font-size: 12px; font-weight: 600; }
.bd-gcard__members { margin-left: auto; font-size: 12px; color: var(--bd-t3); }
.bd-gcard__members b { font-size: 16px; font-weight: 700; color: var(--bd-t1); margin-right: 2px; }
.bd-gcard__scope { font-size: 12px; color: var(--bd-t3); line-height: 1.6; }

/* 搜索框内 input 复位 */
.bd-searchbox input { border: none; background: transparent; outline: none; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-btn--ghost :deep(svg), .bd-btn :deep(svg) { font-size: 14px; }

/* 集群拓扑 */
.bd-clusters { display: flex; flex-direction: column; gap: 16px; }
.bd-topo { padding: 16px 18px 14px; }
.bd-topo svg { display: block; }
.bd-topo__h { margin-bottom: 6px; }
.bd-topo__t { font-size: 15px; font-weight: 600; color: var(--bd-t1); }
.bd-topo__sub { font-size: 12.5px; color: var(--bd-t3); margin-left: 10px; }
</style>
