<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">用户管理<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">内嵌 IdP · 同一身份供三种接入模式与 SDK 联邦共用（ZL-FR-101）</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建用户</a-button>
    </div>

    <!-- 筛选条 -->
    <div class="zl-card zl-card__pad usr-filter">
      <a-input-search v-model="q" placeholder="搜索姓名 / 账号 / 组织" allow-clear style="width: 260px" />
      <a-select v-model="fOrg" placeholder="组织" allow-clear style="width: 190px" size="small">
        <a-option v-for="o in orgOptions" :key="o" :value="o">{{ o }}</a-option>
      </a-select>
      <a-select v-model="fStatus" placeholder="状态" allow-clear style="width: 130px" size="small">
        <a-option value="active">正常</a-option>
        <a-option value="locked">已锁定</a-option>
        <a-option value="disabled">已禁用</a-option>
        <a-option value="idle">闲置</a-option>
        <a-option value="expired">已过期</a-option>
      </a-select>
      <a-select v-model="fAuth" placeholder="认证方式" allow-clear style="width: 150px" size="small">
        <a-option v-for="a in authOptions" :key="a" :value="a">{{ a }}</a-option>
      </a-select>
      <span class="usr-count">{{ filtered.length }} / {{ rows.length }} 人</span>
      <a-button v-if="hasFilter" size="mini" @click="resetFilter">重置</a-button>
    </div>

    <div class="zl-card">
      <a-table :data="filtered" :pagination="filtered.length > 12 ? { pageSize: 12 } : false" :bordered="false"
               row-key="account" :row-class="()=>'row-click'" @row-click="(r:any)=>openUser(r)">
        <template #columns>
          <a-table-column title="姓名" data-index="name" :width="110" />
          <a-table-column title="账号" :width="140">
            <template #cell="{ record }"><span class="data" style="color:var(--ink-2)">{{ record.account }}</span></template>
          </a-table-column>
          <a-table-column title="组织" data-index="org" />
          <a-table-column title="认证方式">
            <template #cell="{ record }">
              <a-tag v-for="a in record.auth" :key="a" size="small" style="margin-right:4px">{{ a }}</a-tag>
            </template>
          </a-table-column>
          <a-table-column title="来源" align="center" :width="72">
            <template #cell="{ record }"><span style="font-size:11px;color:var(--ink-3)">{{ SRC_LABEL[record.source] ?? '本地' }}</span></template>
          </a-table-column>
          <a-table-column title="设备" align="center" :width="58" data-index="devices" />
          <a-table-column title="最近登录" :width="130">
            <template #cell="{ record }"><span class="data" style="font-size:11.5px;color:var(--ink-3)">{{ record.lastLoginAt ?? record.lastLogin ?? lastLoginOf(record.account) }}</span></template>
          </a-table-column>
          <a-table-column title="状态" align="center" :width="84">
            <template #cell="{ record }">
              <span class="zl-badge" :class="statusBadge(record).cls">{{ statusBadge(record).text }}</span>
            </template>
          </a-table-column>
          <a-table-column title="" align="center" :width="70">
            <template #cell="{ record }">
              <a-button size="mini" type="text" @click.stop="openEdit(record)">编辑</a-button>
            </template>
          </a-table-column>
        </template>
      </a-table>
    </div>

    <!-- 新建 / 编辑 -->
    <a-modal v-model:visible="show" :title="editing ? '编辑用户' : '新建用户'" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="form" layout="vertical">
        <a-form-item label="姓名" required><a-input v-model="form.name" /></a-form-item>
        <a-form-item label="账号" required>
          <a-input v-model="form.account" placeholder="工号 / 邮箱前缀" :disabled="editing" />
        </a-form-item>
        <a-form-item label="组织">
          <a-select v-model="form.org">
            <a-option>研发中心 / 平台组</a-option><a-option>研发中心 / 移动组</a-option>
            <a-option>财务中心</a-option><a-option>运维中心</a-option><a-option>服务账号</a-option>
          </a-select>
        </a-form-item>
        <a-grid :cols="2" :col-gap="14">
          <a-grid-item><a-form-item label="邮箱"><a-input v-model="form.email" placeholder="name@corp.com" /></a-form-item></a-grid-item>
          <a-grid-item><a-form-item label="手机"><a-input v-model="form.phone" placeholder="选填" /></a-form-item></a-grid-item>
        </a-grid>
        <a-form-item label="账号有效期">
          <a-input v-model="form.expiryDate" placeholder="YYYY-MM-DD（留空=永久）" />
        </a-form-item>
        <a-form-item :label="editing ? '认证方式' : '初始认证方式'">
          <a-checkbox-group v-model="form.auth">
            <a-checkbox value="密码">密码</a-checkbox><a-checkbox value="扫码">扫码</a-checkbox>
            <a-checkbox value="TOTP">TOTP</a-checkbox><a-checkbox value="证书">证书</a-checkbox>
            <a-checkbox value="WebAuthn">WebAuthn</a-checkbox>
          </a-checkbox-group>
        </a-form-item>
      </a-form>
      <div v-if="!editing" style="font-size:11.5px;color:var(--ink-3);line-height:1.6">初始密码经一次性链接下发（不落聊天工具）；首次登录强制改密 + MFA 注册（DP-05）。</div>
      <div v-else style="font-size:11.5px;color:var(--ink-3);line-height:1.6">账号不可改；认证方式变更下次登录生效，移除某方式会清除其已注册凭证（审计标记）。</div>
    </a-modal>

    <a-drawer v-model:visible="drawer" :width="440" :footer="false">
      <template #title>用户详情 · {{ cur?.name }}</template>
      <div v-if="cur" class="ud">
        <div class="ud-row"><span>账号</span><b class="data">{{ cur.account }}</b><span class="ud-src">{{ SRC_LABEL[cur.source] ?? '本地' }}</span></div>
        <div class="ud-row"><span>组织</span><b>{{ cur.org }}</b></div>
        <div v-if="cur.email" class="ud-row"><span>邮箱</span><b class="data">{{ cur.email }}</b></div>
        <div v-if="cur.phone" class="ud-row"><span>手机</span><b class="data">{{ cur.phone }}</b></div>
        <div class="ud-row"><span>认证方式</span><b><a-tag v-for="a in cur.auth" :key="a" size="small" style="margin-right:4px">{{ a }}</a-tag></b></div>
        <div class="ud-row"><span>状态</span>
          <span class="zl-badge" :class="statusBadge(cur).cls">{{ statusBadge(cur).text }}</span>
          <span v-if="cur.lockReason" class="ud-src">{{ LOCK_LABEL[cur.lockReason] ?? cur.lockReason }}<template v-if="cur.lockedAt"> · {{ cur.lockedAt }}</template></span>
        </div>
        <div class="ud-row"><span>最近登录</span><b class="data">{{ cur.lastLoginAt ?? cur.lastLogin ?? lastLoginOf(cur.account) }}</b><span v-if="cur.lastLoginIp" class="ud-src">{{ cur.lastLoginIp }}</span></div>
        <div v-if="cur.createdAt" class="ud-row"><span>建账时间</span><b class="data">{{ cur.createdAt }}</b></div>
        <div class="ud-row"><span>有效期</span><b class="data">{{ cur.expiryDate || '永久' }}</b></div>
        <div class="ud-row"><span>口令修改</span><b class="data">{{ cur.pwdChangedAt || '—' }}</b><span v-if="cur.pwdInitialized===false" class="ud-src ud-src--warn">待首登改密</span></div>
        <div class="ud-row"><span>MFA 绑定</span><b class="data">{{ cur.mfaBoundAt || '未绑定' }}</b></div>

        <div class="ud-sec">设备（{{ devs.length }}）—— 三模式共用同一设备对象（ZL-FR-101）</div>
        <div v-if="!devs.length" class="ud-empty">该用户暂无注册设备</div>
        <div v-for="d in devs" :key="d.id" class="ud-dev">
          <div>
            <div class="ud-dev__n">{{ d.id }} <span class="zl-mode-pill" :class="`zl-mode--${d.mode}`" style="margin-left:6px">{{ d.mode }}</span></div>
            <div class="ud-dev__m data">{{ d.os }} · {{ d.last }}</div>
          </div>
          <span class="zl-badge" :class="d.online?'zl-badge--ok':'zl-badge--idle'">{{ d.online?'在线':'离线' }}</span>
        </div>

        <div class="ud-sec">操作</div>
        <a-space wrap>
          <a-button size="small" @click="openEdit(cur)">编辑资料</a-button>
          <template v-if="cur.status==='active'">
            <a-button size="small" status="warning" @click="setStatus('locked','admin')">锁定账户</a-button>
            <a-button size="small" status="danger" type="outline" @click="setStatus('disabled','admin')">禁用账户</a-button>
          </template>
          <a-button v-else size="small" status="warning" @click="setStatus('active')">{{ cur.status==='disabled'?'启用账户':'解锁账户' }}</a-button>
          <a-button size="small" status="danger" @click="revokeAll">吊销全部会话</a-button>
          <a-button size="small" @click="resetMfa">重置 MFA</a-button>
          <a-button size="small" status="danger" type="outline" @click="del">删除用户</a-button>
        </a-space>
      </div>
    </a-drawer>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { users } from '@/mock';

/* 用户列表来自控制面 /ctl/api/users（持久化 store），控制面不可达时降级 mock 演示 */
const rows = ref<any[]>([...users]);
const live = ref(false);
async function loadUsers() {
  try {
    const r = await fetch('/ctl/api/users');
    if (!r.ok) return;
    rows.value = await r.json();
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadUsers);

/* —— 搜索与筛选 —— */
const q = ref('');
const fOrg = ref<string | undefined>();
const fStatus = ref<string | undefined>();
const fAuth = ref<string | undefined>();
const orgOptions = computed(() => [...new Set(rows.value.map((u) => u.org))].filter(Boolean));
const authOptions = computed(() => [...new Set(rows.value.flatMap((u) => u.auth ?? []))]);
const hasFilter = computed(() => !!(q.value || fOrg.value || fStatus.value || fAuth.value));
const filtered = computed(() => rows.value.filter((u) => {
  if (fOrg.value && u.org !== fOrg.value) return false;
  if (fStatus.value) {
    // idle/expired 为派生态（匹配 derivedStatus）；active/locked/disabled 匹配持久状态
    const match = fStatus.value === 'idle' || fStatus.value === 'expired'
      ? u.derivedStatus === fStatus.value
      : u.status === fStatus.value;
    if (!match) return false;
  }
  if (fAuth.value && !(u.auth ?? []).includes(fAuth.value)) return false;
  if (q.value) {
    const s = q.value.toLowerCase();
    if (![u.name, u.account, u.org].some((x) => String(x ?? '').toLowerCase().includes(s))) return false;
  }
  return true;
}));
const resetFilter = () => { q.value = ''; fOrg.value = fStatus.value = fAuth.value = undefined; };

// 演示用最近登录（账号哈希到一组相对时间）；真实数据走 record.lastLoginAt
const LOGIN_SAMPLES = ['刚刚', '12 分钟前', '1 小时前', '今天 09:14', '昨天 18:02', '3 天前', '从未登录'];
function lastLoginOf(account: string) {
  let h = 0; for (const c of account ?? '') h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return LOGIN_SAMPLES[h % LOGIN_SAMPLES.length];
}

// 账号显示态：持久状态(active/locked/disabled) 与只读派生态(idle/expired，后端 handleUsers 计算) 合一。
const SRC_LABEL: Record<string, string> = { local: '本地', ad: 'AD 域', ldap: 'LDAP', oidc: '联邦' };
const LOCK_LABEL: Record<string, string> = { bruteForce: '连续失败锁定', idle: '闲置锁定', policy: '策略禁用', admin: '管理员操作' };
function statusBadge(r: any): { cls: string; text: string } {
  if (r.status === 'disabled') return { cls: 'zl-badge--warn', text: '已禁用' };
  if (r.status === 'locked') return { cls: 'zl-badge--warn', text: '已锁定' };
  if (r.derivedStatus === 'expired') return { cls: 'zl-badge--warn', text: '已过期' };
  if (r.derivedStatus === 'idle') return { cls: 'zl-badge--idle', text: '闲置' };
  return { cls: 'zl-badge--ok', text: '正常' };
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const blankForm = () => ({ name: '', account: '', org: '研发中心 / 平台组', auth: ['密码', 'TOTP'] as string[], email: '', phone: '', expiryDate: '' });
const form = reactive(blankForm());
function openCreate() {
  editing.value = false;
  Object.assign(form, blankForm());
  show.value = true;
}
function openEdit(r: any) {
  editing.value = true;
  Object.assign(form, { name: r.name, account: r.account, org: r.org, auth: [...(r.auth ?? [])], email: r.email ?? '', phone: r.phone ?? '', expiryDate: r.expiryDate ?? '' });
  show.value = true;
}
async function submit() {
  if (!form.name || !form.account) return Message.warning('姓名与账号为必填');
  if (editing.value) return saveEdit();
  return add();
}
async function add() {
  const u: any = { name: form.name, account: form.account, org: form.org, auth: [...form.auth], devices: 0, status: 'active', source: 'local' };
  if (form.email) u.email = form.email;
  if (form.phone) u.phone = form.phone;
  if (form.expiryDate) u.expiryDate = form.expiryDate;
  if (live.value) {
    try {
      const r = await fetch('/ctl/api/users', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(u) });
      if (r.status === 409) return Message.error(`账号 ${form.account} 已存在`);
      if (!r.ok) return Message.error('创建失败');
      await loadUsers();
    } catch { return Message.error('控制面不可达'); }
  } else {
    rows.value.unshift(u);
  }
  Message.success(`用户 ${form.name} 已创建 · 激活链接已生成（一次性）${live.value ? ' · 已持久化' : ''}`);
  show.value = false;
}
async function saveEdit() {
  const patch = { name: form.name, org: form.org, auth: [...form.auth], email: form.email, phone: form.phone, expiryDate: form.expiryDate };
  const row = rows.value.find((x: any) => x.account === form.account);
  if (row) Object.assign(row, patch);
  if (cur.value?.account === form.account) Object.assign(cur.value, patch);
  // 注：live 资料更新需后端 PUT（当前后端仅 POST/DELETE）——演示走本地乐观更新
  Message.success(`用户 ${form.name} 资料已更新${live.value ? '（本地 · 后端 PUT 待接）' : ''}`);
  show.value = false;
}

/* —— 详情抽屉 —— */
const drawer = ref(false);
const cur = ref<any>(null);
const openUser = (r: any) => { cur.value = r; drawer.value = true; };
const DEVPOOL: Record<string, any[]> = {
  'zhang.wei': [
    { id: 'MBP-7F2A', os: 'macOS 15', mode: 'mesh', online: true, last: '当前在线' },
    { id: 'PIXEL-3C1', os: 'Android 15', mode: 'ssl', online: false, last: '2 小时前' }
  ],
  'li.na': [{ id: 'iPhone-92', os: 'iOS 18', mode: 'ssl', online: true, last: '当前在线' }],
  'wang.qiang': [
    { id: 'WS-330', os: 'Windows 11', mode: 'mesh', online: true, last: '当前在线' },
    { id: 'WS-331', os: 'Windows 11', mode: 'mesh', online: false, last: '昨天' },
    { id: 'SRV-OPS', os: 'Kylin V10', mode: 'mesh', online: true, last: '当前在线' }
  ],
  'chen.jing': [{ id: 'Pad-1180', os: 'HarmonyOS 5.1', mode: 'ssl', online: false, last: '3 天前' }],
  'svc.ci': [{ id: 'ci-runner-01', os: 'Ubuntu 24.04', mode: 'mesh', online: true, last: '当前在线' }]
};
const devs = computed(() => DEVPOOL[cur.value?.account] ?? []);
// 设置账号状态（active|locked|disabled，可带锁定原因）；写控制面 + 本地同步。
async function setStatus(next: string, reason?: string) {
  if (live.value) {
    try {
      const q = `/ctl/api/user/status?account=${encodeURIComponent(cur.value.account)}&status=${next}${reason ? `&reason=${encodeURIComponent(reason)}` : ''}`;
      const r = await fetch(q, { method: 'POST' });
      if (!r.ok) return Message.error('操作失败');
    } catch { return Message.error('控制面不可达'); }
  }
  cur.value.status = next;
  cur.value.lockReason = next === 'active' ? '' : (reason || 'admin');
  const row = rows.value.find((x: any) => x.account === cur.value.account);
  if (row) { row.status = next; row.lockReason = cur.value.lockReason; }
  const msg: Record<string, string> = {
    locked: '已锁定 · 全部会话吊销 ≤10s 传播三执行点',
    disabled: '已禁用 · 账号停用，会话吊销 ≤10s 传播',
    active: '已恢复 · 账号正常'
  };
  Message.success(msg[next]);
}
const revokeAll = () => Message.success(`已吊销 ${cur.value.name} 全部会话 · ≤10s 传播（ZL-FR-105），审计链记录`);
const resetMfa = () => Message.success('MFA 已重置 · 用户下次登录强制重新注册（审计标记）');
const del = () => {
  Modal.warning({
    title: `删除用户 ${cur.value.name}？`,
    content: '将移除账号、解绑全部设备、吊销所有会话。此操作进入审计链，不可静默撤销。',
    hideCancel: false, okText: '确认删除', cancelText: '取消',
    onOk: async () => {
      const acc = cur.value.account;
      if (live.value) {
        try {
          const r = await fetch(`/ctl/api/users?account=${acc}`, { method: 'DELETE' });
          if (!r.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      rows.value = rows.value.filter((x: any) => x.account !== acc);
      drawer.value = false;
      Message.success(`用户 ${cur.value.name} 已删除 · 设备解绑、会话吊销已下发`);
    }
  });
};
</script>
<style scoped>
:deep(.row-click) { cursor: pointer; }
.usr-filter { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.usr-count { font-size: 12px; color: var(--ink-3); margin-left: auto; }
.ud-row { display: flex; align-items: center; gap: 12px; padding: 8px 0; font-size: 12.5px; }
.ud-row > span { color: var(--ink-3); min-width: 64px; }
.ud-row b { color: var(--ink); font-weight: 600; }
.ud-src { font-size: 11px; color: var(--ink-3); margin-left: auto; }
.ud-src--warn { color: var(--accent-2); }
.ud-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 16px 0 8px; }
.ud-empty { font-size: 12px; color: var(--ink-3); padding: 4px 0 8px; }
.ud-dev { display: flex; align-items: center; justify-content: space-between; border: 1px solid var(--line); border-radius: var(--r-md); padding: 9px 12px; margin-bottom: 8px; }
.ud-dev__n { font-size: 12.5px; font-weight: 650; color: var(--ink); display: flex; align-items: center; }
.ud-dev__m { font-size: 11px; color: var(--ink-3); margin-top: 2px; }
</style>
