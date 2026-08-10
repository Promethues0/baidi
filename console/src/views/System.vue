<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">系统管理</div>
        <div class="bd-page__sub">三权分立 · 分级分权 · 集群</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '未连控制中心' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'admin' }" @click="tab = 'admin'">管理员与三权分立</span>
      <span class="bd-tab" :class="{ on: tab === 'cluster' }" @click="tab = 'cluster'">集群</span>
    </div>

    <!-- ============ 管理员与三权分立 ============ -->
    <div v-show="tab === 'admin'">
      <!-- ① 角色卡片行 -->
      <div class="bd-section-title">管理员角色 · 三权分立</div>
      <div class="bd-sep__note">
        <icon-safe />
        <span>
          <b>系统 / 安全 / 审计</b> 三组互不越权，权限由后端 <i class="bd-mono">requirePerm</i> 逐端点执行：
          审计管理员只读全量日志（改不了用户与策略）、安全管理员定策略但读不到审计、系统管理员管配置。
          卡片上的权限键就是判定用的那份，不是文案。
        </span>
      </div>
      <div v-if="err" class="bd-warn"><icon-exclamation-circle-fill />{{ err }}</div>
      <div class="bd-groups">
        <div
          v-for="g in roles"
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
          <div class="bd-gcard__perms">
            <span v-for="p in g.perms" :key="p" class="bd-perm bd-mono">{{ p }}</span>
          </div>
          <div class="bd-gcard__scope">{{ g.scope }}</div>
          <div v-if="!g.builtin" class="bd-gcard__ops">
            <span class="bd-link bd-link--danger" @click="removeRole(g)">删除角色</span>
          </div>
        </div>
      </div>
      <div class="bd-rolebar">
        <button class="bd-btn bd-btn--ghost" @click="openRole"><icon-plus />新建自定义角色</button>
        <span class="bd-hint">自定义角色只能在 system / security / audit 三权内收缩，不能自造超管。</span>
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
            <button class="bd-btn" @click="openAdmin"><icon-plus />新建管理员</button>
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>账号</th>
              <th>角色</th>
              <th>认证方式</th>
              <th>二次认证</th>
              <th>状态</th>
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
                  <span class="d" :style="{ background: powerColor(a.power) }" />{{ a.roleName }}
                </span>
              </td>
              <td>{{ a.auth }}</td>
              <td>
                <span v-if="a.twoFa" class="bd-tg" :style="tagStyle('#00B42A')">已注册 passkey</span>
                <span v-else class="bd-tg" :style="tagStyle('#86909C')">未注册</span>
              </td>
              <td>{{ statusText(a.status) }}</td>
              <td class="bd-mono">{{ a.lastLogin || '—' }}</td>
              <td class="r">
                <span class="bd-link" @click="openRoleChange(a)">改派角色</span>
                <span class="bd-link bd-link--danger" style="margin-left: 14px" @click="removeAdmin(a)">撤销管理员</span>
              </td>
            </tr>
            <tr v-if="!filteredAdmins.length">
              <td colspan="7" class="bd-empty">{{ kw ? '无匹配管理员' : '暂无管理员账号' }}</td>
            </tr>
          </tbody>
        </table>
        <div class="bd-pager">
          共 {{ filteredAdmins.length }} 名管理员 · 系统至少保留一名超级管理员（最后一名不可降权/撤销/禁用）
        </div>
      </div>
    </div>

    <!-- ============ 集群（未部署的诚实空态）============ -->
    <div v-show="tab === 'cluster'">
      <div class="bd-card bd-empty bd-empty--lg">
        <icon-storage />
        <div class="bd-empty__t">集群未部署</div>
        <div class="bd-empty__d">{{ cluster.note || '白帝当前为单机形态（1 进程 + SQLite），无节点发现 / 选主 / 主备同步机制。' }}</div>
        <div class="bd-empty__d">
          本版本没有 HA 能力；如需冗余请依赖外部手段（备份恢复 / 冷备），不要按「集群健康」规划容量。
          运维体检（/diag）里这一项同样记为 <i class="bd-mono">skip</i>。
        </div>
      </div>
    </div>

    <!-- 新建 / 提升管理员 -->
    <a-modal v-model:visible="adminOpen" title="新建管理员" :confirm-loading="saving" @ok="submitAdmin" @cancel="adminOpen = false">
      <a-form :model="adminForm" layout="vertical">
        <a-form-item label="账号" help="账号已存在时只改其角色，不会重置口令">
          <a-input v-model="adminForm.account" placeholder="如 sec.zhang" />
        </a-form-item>
        <a-form-item label="姓名">
          <a-input v-model="adminForm.name" placeholder="新建账号时的显示名" />
        </a-form-item>
        <a-form-item label="角色">
          <a-select v-model="adminForm.roleKey" placeholder="选择管理员角色">
            <a-option v-for="g in roles" :key="g.key" :value="g.key">{{ g.name }}（{{ g.perms.join('/') }}）</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="初始口令" help="留空用演示默认口令；新账号一律置首登强制改密">
          <a-input-password v-model="adminForm.password" placeholder="至少 6 位" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 改派角色 -->
    <a-modal v-model:visible="roleChangeOpen" title="改派管理员角色" :confirm-loading="saving" @ok="submitRoleChange" @cancel="roleChangeOpen = false">
      <a-form :model="roleChangeForm" layout="vertical">
        <a-form-item label="账号"><a-input v-model="roleChangeForm.account" disabled /></a-form-item>
        <a-form-item label="新角色">
          <a-select v-model="roleChangeForm.roleKey">
            <a-option v-for="g in roles" :key="g.key" :value="g.key">{{ g.name }}（{{ g.perms.join('/') }}）</a-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 新建自定义角色 -->
    <a-modal v-model:visible="roleOpen" title="新建自定义角色" :confirm-loading="saving" @ok="submitRole" @cancel="roleOpen = false">
      <a-form :model="roleForm" layout="vertical">
        <a-form-item label="角色标识" help="小写字母/数字/短横，落库后不可改">
          <a-input v-model="roleForm.key" placeholder="如 east-op" />
        </a-form-item>
        <a-form-item label="角色名称"><a-input v-model="roleForm.name" placeholder="如 华东运维组" /></a-form-item>
        <a-form-item label="权限键" help="只能在三权内收缩；* 与 admins 不可选（那等于自造超管）">
          <a-checkbox-group v-model="roleForm.perms">
            <a-checkbox value="system">system · 系统配置</a-checkbox>
            <a-checkbox value="security">security · 安全策略</a-checkbox>
            <a-checkbox value="audit">audit · 审计只读</a-checkbox>
          </a-checkbox-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type SystemBundle, type AdminRole, type AdminAccount, type ClusterInfo } from '@/lib/api';

const tab = ref<'admin' | 'cluster'>('admin');
const live = ref(false);
const err = ref('');
const kw = ref('');
const saving = ref(false);

/* 全部数据来自 GET /api/v1/system（admin_roles 表 + users 表）。
 * 此前这里有 MOCK_GROUPS / MOCK_ADMINS / MOCK_CLUSTER 三份编造数据，
 * 后端不可达时页面照样显示"五个管理组八个管理员三个集群节点"——那是全项目
 * 最容易被误读成"已实现"的地方。现在拉不到就空着并显式报错。 */
const roles = ref<AdminRole[]>([]);
const admins = ref<AdminAccount[]>([]);
const cluster = ref<ClusterInfo>({ deployed: false, note: '', localNodes: [], distNodes: [] });

const filteredAdmins = computed(() => {
  const q = kw.value.trim().toLowerCase();
  if (!q) return admins.value;
  return admins.value.filter((a) => a.name.toLowerCase().includes(q) || a.account.toLowerCase().includes(q));
});

/* ── 颜色 / 文案 ── */
function powerColor(power: string) {
  switch (power) {
    case 'root': return '#F53F3F';
    case 'system': return '#165DFF';
    case 'security': return '#FF7D00';
    case 'audit': return '#00B42A';
    default: return '#722ED1'; // custom / 未分配
  }
}
function powerText(power: string) {
  switch (power) {
    case 'root': return '超级权限（含角色分配）';
    case 'system': return '系统配置权';
    case 'security': return '安全策略权';
    case 'audit': return '审计只读权';
    default: return '自定义收缩权';
  }
}
function statusText(status: string) {
  switch (status) {
    case 'active': return '启用';
    case 'disabled': return '禁用';
    case 'locked': return '锁定';
    case 'idle': return '挂起';
    default: return status || '—';
  }
}
function tagStyle(color: string) { return { color, background: color + '14', border: 'none' }; }
function avatarBg(name: string) {
  const palette = ['#165DFF', '#722ED1', '#00B42A', '#FF7D00', '#F53F3F'];
  let h = 0;
  for (const ch of name) h = (h + ch.charCodeAt(0)) % palette.length;
  return palette[h];
}

/* ── 读取 ── */
async function load(toast = false) {
  try {
    const b = await api<SystemBundle>('/system');
    roles.value = b.roles ?? [];
    admins.value = b.admins ?? [];
    cluster.value = b.cluster ?? cluster.value;
    live.value = true;
    err.value = '';
    if (toast) Message.success('已刷新');
  } catch (e) {
    live.value = false;
    roles.value = [];
    admins.value = [];
    err.value = '未连控制中心，管理员与角色数据不可用：' + (e instanceof Error ? e.message : String(e));
    if (toast) Message.error('刷新失败');
  }
}
function reload() { void load(true); }
onMounted(() => { void load(); });

/* ── 写操作 ── */
function opError(e: unknown, fallback: string) {
  const msg = e instanceof Error ? e.message : String(e);
  if (msg.includes('409')) { Message.warning('操作被拒：系统必须保留至少一名超级管理员，或该角色仍有成员'); return; }
  if (msg.includes('403')) { Message.warning('当前角色无权执行该操作（分配管理员权限仅超级管理员持有）'); return; }
  Message.error(fallback);
}

const adminOpen = ref(false);
const adminForm = reactive({ account: '', name: '', roleKey: '', password: '' });
function openAdmin() {
  adminForm.account = ''; adminForm.name = ''; adminForm.password = '';
  adminForm.roleKey = roles.value[0]?.key ?? '';
  adminOpen.value = true;
}
async function submitAdmin() {
  if (!adminForm.account.trim() || !adminForm.roleKey) { Message.warning('账号与角色不能为空'); return; }
  saving.value = true;
  try {
    await api('/admins', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account: adminForm.account.trim(), name: adminForm.name.trim(),
        roleKey: adminForm.roleKey, password: adminForm.password
      })
    });
    Message.success(`管理员「${adminForm.account.trim()}」已落库`);
    adminOpen.value = false;
    await load();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

const roleChangeOpen = ref(false);
const roleChangeForm = reactive({ account: '', roleKey: '' });
function openRoleChange(a: AdminAccount) {
  roleChangeForm.account = a.account;
  roleChangeForm.roleKey = a.roleKey || (roles.value[0]?.key ?? '');
  roleChangeOpen.value = true;
}
async function submitRoleChange() {
  saving.value = true;
  try {
    await api(`/admins/${encodeURIComponent(roleChangeForm.account)}/role`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ roleKey: roleChangeForm.roleKey })
    });
    Message.success('角色已改派');
    roleChangeOpen.value = false;
    await load();
  } catch (e) { opError(e, '改派失败'); } finally { saving.value = false; }
}

function removeAdmin(a: AdminAccount) {
  Modal.warning({
    title: '撤销管理员身份',
    content: `将「${a.name}（${a.account}）」降为普通用户并清空角色。账号本身保留（删号会让审计里的历史行为人对不上）。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/admins/${encodeURIComponent(a.account)}`, { method: 'DELETE' });
        Message.success('已撤销管理员身份');
        await load();
      } catch (e) { opError(e, '撤销失败'); }
    }
  });
}

const roleOpen = ref(false);
const roleForm = reactive<{ key: string; name: string; perms: string[] }>({ key: '', name: '', perms: [] });
function openRole() {
  roleForm.key = ''; roleForm.name = ''; roleForm.perms = [];
  roleOpen.value = true;
}
async function submitRole() {
  if (!roleForm.key.trim() || !roleForm.name.trim() || !roleForm.perms.length) {
    Message.warning('标识、名称与至少一个权限键都必填');
    return;
  }
  saving.value = true;
  try {
    await api('/admin-roles', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: roleForm.key.trim(), name: roleForm.name.trim(), perms: roleForm.perms })
    });
    Message.success('自定义角色已落库');
    roleOpen.value = false;
    await load();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

function removeRole(g: AdminRole) {
  Modal.warning({
    title: '删除自定义角色',
    content: `删除「${g.name}」。仍有成员时后端会拒绝——请先把这 ${g.members} 名管理员改派到其他角色。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/admin-roles/${encodeURIComponent(g.key)}`, { method: 'DELETE' });
        Message.success('角色已删除');
        await load();
      } catch (e) { opError(e, '删除失败'); }
    }
  });
}
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

.bd-warn {
  display: flex; align-items: center; gap: 8px; margin-bottom: 14px; padding: 10px 14px;
  border-radius: var(--bd-radius); background: #fff3e8; color: #ad4b00; font-size: 12.5px;
}

/* 角色卡片行 */
.bd-groups { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 14px; }
.bd-gcard { position: relative; padding: 16px 16px 16px 20px; overflow: hidden; }
.bd-gcard__bar { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--pc); }
.bd-gcard__top { display: flex; align-items: center; gap: 8px; }
.bd-gcard__dot { width: 9px; height: 9px; border-radius: 50%; background: var(--pc); flex: none; }
.bd-gcard__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-gcard__meta { display: flex; align-items: center; gap: 10px; margin: 12px 0 8px; }
.bd-gcard__power { font-size: 12px; font-weight: 600; }
.bd-gcard__members { margin-left: auto; font-size: 12px; color: var(--bd-t3); }
.bd-gcard__members b { font-size: 16px; font-weight: 700; color: var(--bd-t1); margin-right: 2px; }
.bd-gcard__perms { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
.bd-perm { font-size: 11px; padding: 1px 7px; border-radius: 5px; background: var(--bd-fill-2); color: var(--bd-t2); }
.bd-gcard__scope { font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-gcard__ops { margin-top: 10px; font-size: 12px; }

.bd-rolebar { display: flex; align-items: center; gap: 12px; margin-top: 14px; }
.bd-hint { font-size: 12px; color: var(--bd-t3); }

/* 搜索框内 input 复位 */
.bd-searchbox input { border: none; background: transparent; outline: none; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-btn--ghost :deep(svg), .bd-btn :deep(svg) { font-size: 14px; }

/* 空态 */
.bd-empty { text-align: center; color: var(--bd-t3); padding: 28px 0; }
.bd-empty--lg {
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px;
  min-height: 300px; padding: 32px 24px;
}
.bd-empty--lg :deep(svg) { font-size: 30px; color: var(--bd-t4); }
.bd-empty__t { font-size: 15px; font-weight: 600; color: var(--bd-t2); }
.bd-empty__d { font-size: 12.5px; color: var(--bd-t3); line-height: 1.8; max-width: 620px; }
</style>
